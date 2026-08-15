// Package protocol defines authenticated Punt control and data messages.
package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	Version        = 1
	ControlSize    = 56
	DataHeaderSize = 32
	MaxPayload     = 1400
)

var (
	controlMagic = [4]byte{'P', 'U', 'W', 'C'}
	dataMagic    = [4]byte{'P', 'U', 'W', 'G'}
)

type EnvelopeType uint8

const (
	UnknownEnvelope EnvelopeType = iota
	ControlEnvelope
	DataEnvelope
)

// ClassifyEnvelope identifies the authenticated Punt envelope carried by UDP.
// Full validation remains the responsibility of ParseControl or ParseData.
func ClassifyEnvelope(b []byte) EnvelopeType {
	if len(b) < 4 {
		return UnknownEnvelope
	}
	switch string(b[:4]) {
	case string(controlMagic[:]):
		return ControlEnvelope
	case string(dataMagic[:]):
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

func mac(key []byte, packet []byte) [8]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(packet)
	full := h.Sum(nil)
	var out [8]byte
	copy(out[:], full[:len(out)])
	return out
}

func validControlType(t ControlType) bool {
	return t == Hello || t == HelloAck
}

func validDataType(t DataType) bool {
	return t >= Probe && t <= Packet
}

func (m Control) Marshal(key []byte) ([]byte, error) {
	if len(key) != 16 || !validControlType(m.Type) {
		return nil, errors.New("invalid control message or key")
	}
	b := make([]byte, ControlSize)
	copy(b, controlMagic[:])
	b[4] = Version
	b[5] = byte(m.Type)
	binary.BigEndian.PutUint16(b[6:8], ControlSize)
	binary.BigEndian.PutUint64(b[8:16], m.ClientSession)
	binary.BigEndian.PutUint64(b[16:24], m.ServerSession)
	binary.BigEndian.PutUint64(b[24:32], m.Nonce)
	binary.BigEndian.PutUint64(b[32:40], m.Timestamp)
	binary.BigEndian.PutUint16(b[40:42], m.ObservedPort)
	tag := mac(key, b)
	copy(b[48:56], tag[:])
	return b, nil
}

func ParseControl(b, key []byte) (Control, error) {
	var m Control
	if len(key) != 16 || len(b) != ControlSize || string(b[:4]) != string(controlMagic[:]) ||
		b[4] != Version || binary.BigEndian.Uint16(b[6:8]) != ControlSize || !allZero(b[42:48]) {
		return m, errors.New("invalid control envelope")
	}
	m.Type = ControlType(b[5])
	if !validControlType(m.Type) {
		return m, errors.New("invalid control type")
	}
	copyB := append([]byte(nil), b...)
	received := append([]byte(nil), copyB[48:56]...)
	clear(copyB[48:56])
	expected := mac(key, copyB)
	if subtle.ConstantTimeCompare(received, expected[:]) != 1 {
		return m, errors.New("invalid control mac")
	}
	m.ClientSession = binary.BigEndian.Uint64(b[8:16])
	m.ServerSession = binary.BigEndian.Uint64(b[16:24])
	m.Nonce = binary.BigEndian.Uint64(b[24:32])
	m.Timestamp = binary.BigEndian.Uint64(b[32:40])
	m.ObservedPort = binary.BigEndian.Uint16(b[40:42])
	return m, nil
}

func (m Data) Marshal(key []byte) ([]byte, error) {
	if len(key) != 16 || !validDataType(m.Type) || len(m.Payload) > MaxPayload {
		return nil, errors.New("invalid data message or key")
	}
	b := make([]byte, DataHeaderSize+len(m.Payload))
	copy(b, dataMagic[:])
	b[4] = Version
	b[5] = byte(m.Type)
	binary.BigEndian.PutUint16(b[6:8], DataHeaderSize)
	binary.BigEndian.PutUint64(b[8:16], m.Session)
	binary.BigEndian.PutUint32(b[16:20], m.Sequence)
	binary.BigEndian.PutUint16(b[20:22], uint16(len(m.Payload)))
	copy(b[DataHeaderSize:], m.Payload)
	tag := mac(key, b)
	copy(b[24:32], tag[:])
	return b, nil
}

func ParseData(b, key []byte) (Data, error) {
	var m Data
	if len(key) != 16 || len(b) < DataHeaderSize || string(b[:4]) != string(dataMagic[:]) ||
		b[4] != Version || binary.BigEndian.Uint16(b[6:8]) != DataHeaderSize || !allZero(b[22:24]) {
		return m, errors.New("invalid data envelope")
	}
	m.Type = DataType(b[5])
	if !validDataType(m.Type) {
		return m, errors.New("invalid data type")
	}
	payloadLen := int(binary.BigEndian.Uint16(b[20:22]))
	if payloadLen > MaxPayload || len(b) != DataHeaderSize+payloadLen {
		return m, errors.New("invalid data length")
	}
	copyB := append([]byte(nil), b...)
	received := append([]byte(nil), copyB[24:32]...)
	clear(copyB[24:32])
	expected := mac(key, copyB)
	if subtle.ConstantTimeCompare(received, expected[:]) != 1 {
		return m, errors.New("invalid data mac")
	}
	m.Session = binary.BigEndian.Uint64(b[8:16])
	m.Sequence = binary.BigEndian.Uint32(b[16:20])
	m.Payload = append([]byte(nil), b[DataHeaderSize:]...)
	return m, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
