// Package protocol defines authenticated Punt control and data messages.
package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
)

const (
	Version        = 1
	ControlSize    = 56
	DataHeaderSize = 32
	MaxPayload     = 1400

	controlMACOffset = 48
	dataMACOffset    = 24
	macSize          = 8
)

var (
	controlMagic = [4]byte{'P', 'U', 'W', 'C'}
	dataMagic    = [4]byte{'P', 'U', 'W', 'G'}

	errKey            = errors.New("key must be exactly 16 bytes")
	errInvalidControl = errors.New("invalid control message or key")
	errControlEnv     = errors.New("invalid control envelope")
	errControlType    = errors.New("invalid control type")
	errControlMAC     = errors.New("invalid control mac")
	errInvalidData    = errors.New("invalid data message or key")
	errDataEnv        = errors.New("invalid data envelope")
	errDataType       = errors.New("invalid data type")
	errDataLength     = errors.New("invalid data length")
	errDataMAC        = errors.New("invalid data mac")
	errSealBuffer     = errors.New("seal buffer too small")
)

type EnvelopeType uint8

const (
	UnknownEnvelope EnvelopeType = iota
	ControlEnvelope
	DataEnvelope
)

func hasMagic(b []byte, magic [4]byte) bool {
	return len(b) >= 4 && [4]byte(b[:4]) == magic
}

// ClassifyEnvelope identifies the authenticated Punt envelope carried by UDP.
// Full validation remains the responsibility of ParseControl or ParseData.
func ClassifyEnvelope(b []byte) EnvelopeType {
	switch {
	case hasMagic(b, controlMagic):
		return ControlEnvelope
	case hasMagic(b, dataMagic):
		return DataEnvelope
	default:
		return UnknownEnvelope
	}
}

type ControlType uint8

const (
	Hello    ControlType = 1
	HelloAck ControlType = 2
)

type DataType uint8

const (
	Probe        DataType = 1
	ProbeAck     DataType = 2
	ProbeConfirm DataType = 3
	Packet       DataType = 4
)

type Control struct {
	Type          ControlType
	ClientSession uint64
	ServerSession uint64
	Nonce         uint64
	Timestamp     uint64
	ObservedPort  uint16
}

type Data struct {
	Type     DataType
	Session  uint64
	Sequence uint32
	Payload  []byte
}

// Verifier owns a reusable keyed HMAC-SHA256 state. It is not safe for
// concurrent use; give every concurrent reader/writer its own instance.
type Verifier struct {
	h   hash.Hash
	sum [sha256.Size]byte
}

func NewVerifier(key []byte) (*Verifier, error) {
	if len(key) != 16 {
		return nil, errKey
	}
	return &Verifier{h: hmac.New(sha256.New, key)}, nil
}

func (v *Verifier) tag(packet []byte) []byte {
	v.h.Reset()
	_, _ = v.h.Write(packet)
	return v.h.Sum(v.sum[:0])[:macSize]
}

func (v *Verifier) verifyInPlace(b []byte, off int) bool {
	var received [macSize]byte
	copy(received[:], b[off:off+macSize])
	clear(b[off : off+macSize])
	return subtle.ConstantTimeCompare(received[:], v.tag(b)) == 1
}

func validControlType(t ControlType) bool { return t == Hello || t == HelloAck }

func validDataType(t DataType) bool { return t >= Probe && t <= Packet }

// SealControl encodes m into dst without allocating.
func (v *Verifier) SealControl(dst []byte, m Control) ([]byte, error) {
	if !validControlType(m.Type) {
		return nil, errInvalidControl
	}
	if cap(dst) < ControlSize {
		return nil, errSealBuffer
	}
	b := dst[:ControlSize]
	clear(b)
	copy(b, controlMagic[:])
	b[4] = Version
	b[5] = byte(m.Type)
	binary.BigEndian.PutUint16(b[6:8], ControlSize)
	binary.BigEndian.PutUint64(b[8:16], m.ClientSession)
	binary.BigEndian.PutUint64(b[16:24], m.ServerSession)
	binary.BigEndian.PutUint64(b[24:32], m.Nonce)
	binary.BigEndian.PutUint64(b[32:40], m.Timestamp)
	binary.BigEndian.PutUint16(b[40:42], m.ObservedPort)
	copy(b[controlMACOffset:], v.tag(b))
	return b, nil
}

// ParseControlInPlace validates b, decodes it, and zeroes its MAC field.
func (v *Verifier) ParseControlInPlace(b []byte) (Control, error) {
	var m Control
	if len(b) != ControlSize || !hasMagic(b, controlMagic) || b[4] != Version ||
		binary.BigEndian.Uint16(b[6:8]) != ControlSize || !allZero(b[42:48]) {
		return m, errControlEnv
	}
	m.Type = ControlType(b[5])
	if !validControlType(m.Type) {
		return m, errControlType
	}
	if !v.verifyInPlace(b, controlMACOffset) {
		return m, errControlMAC
	}
	m.ClientSession = binary.BigEndian.Uint64(b[8:16])
	m.ServerSession = binary.BigEndian.Uint64(b[16:24])
	m.Nonce = binary.BigEndian.Uint64(b[24:32])
	m.Timestamp = binary.BigEndian.Uint64(b[32:40])
	m.ObservedPort = binary.BigEndian.Uint16(b[40:42])
	return m, nil
}

// SealData encodes m into dst. Payload may already be at dst[DataHeaderSize:].
func (v *Verifier) SealData(dst []byte, m Data) ([]byte, error) {
	if !validDataType(m.Type) || len(m.Payload) > MaxPayload {
		return nil, errInvalidData
	}
	need := DataHeaderSize + len(m.Payload)
	if cap(dst) < need {
		return nil, errSealBuffer
	}
	b := dst[:need]
	copy(b[DataHeaderSize:], m.Payload)
	copy(b, dataMagic[:])
	b[4] = Version
	b[5] = byte(m.Type)
	binary.BigEndian.PutUint16(b[6:8], DataHeaderSize)
	binary.BigEndian.PutUint64(b[8:16], m.Session)
	binary.BigEndian.PutUint32(b[16:20], m.Sequence)
	binary.BigEndian.PutUint16(b[20:22], uint16(len(m.Payload)))
	clear(b[22:DataHeaderSize])
	copy(b[dataMACOffset:], v.tag(b))
	return b, nil
}

// ParseDataInPlace validates b and returns a payload aliasing b. The MAC field
// is zeroed before returning.
func (v *Verifier) ParseDataInPlace(b []byte) (Data, error) {
	var m Data
	if len(b) < DataHeaderSize || !hasMagic(b, dataMagic) || b[4] != Version ||
		binary.BigEndian.Uint16(b[6:8]) != DataHeaderSize || !allZero(b[22:24]) {
		return m, errDataEnv
	}
	m.Type = DataType(b[5])
	if !validDataType(m.Type) {
		return m, errDataType
	}
	payloadLen := int(binary.BigEndian.Uint16(b[20:22]))
	if payloadLen > MaxPayload || len(b) != DataHeaderSize+payloadLen {
		return m, errDataLength
	}
	if !v.verifyInPlace(b, dataMACOffset) {
		return m, errDataMAC
	}
	m.Session = binary.BigEndian.Uint64(b[8:16])
	m.Sequence = binary.BigEndian.Uint32(b[16:20])
	m.Payload = b[DataHeaderSize:]
	return m, nil
}

// Marshal and Parse* retain their original copy semantics for callers outside
// the hot path.
func (m Control) Marshal(key []byte) ([]byte, error) {
	v, err := NewVerifier(key)
	if err != nil {
		return nil, errInvalidControl
	}
	return v.SealControl(make([]byte, ControlSize), m)
}

func ParseControl(b, key []byte) (Control, error) {
	v, err := NewVerifier(key)
	if err != nil {
		return Control{}, errControlEnv
	}
	return v.ParseControlInPlace(append([]byte(nil), b...))
}

func (m Data) Marshal(key []byte) ([]byte, error) {
	v, err := NewVerifier(key)
	if err != nil {
		return nil, errInvalidData
	}
	return v.SealData(make([]byte, DataHeaderSize+len(m.Payload)), m)
}

func ParseData(b, key []byte) (Data, error) {
	v, err := NewVerifier(key)
	if err != nil {
		return Data{}, errDataEnv
	}
	return v.ParseDataInPlace(append([]byte(nil), b...))
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
