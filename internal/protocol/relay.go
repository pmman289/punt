package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	RelayHeaderSize = 16
	relayVersion    = 1
	MaxRelayPayload = MaxPayload - RelayHeaderSize
)

var relayMagic = [4]byte{'P', 'R', 'L', 'Y'}

// RelayType identifies an application-facing relay frame carried by Data.Packet.
type RelayType uint8

const (
	RelayUDP        RelayType = 1
	RelayTCPOpen    RelayType = 2
	RelayTCPOpenAck RelayType = 3
	RelayTCPPacket  RelayType = 4
	RelayTCPReject  RelayType = 5
)

type RelayFrame struct {
	Type    RelayType
	FlowID  uint32
	Payload []byte
}

var (
	errRelayFrame    = errors.New("invalid relay frame")
	errRelayEnvelope = errors.New("invalid relay envelope")
	errRelayLength   = errors.New("invalid relay frame length")
)

// EncodeRelayFrame writes a frame into dst without allocating.
func EncodeRelayFrame(dst []byte, f RelayFrame) ([]byte, error) {
	if f.FlowID == 0 || !validRelayType(f.Type) || len(f.Payload) > MaxRelayPayload {
		return nil, errRelayFrame
	}
	need := RelayHeaderSize + len(f.Payload)
	if cap(dst) < need {
		return nil, errRelayFrame
	}
	b := dst[:need]
	copy(b[RelayHeaderSize:], f.Payload)
	copy(b[:4], relayMagic[:])
	b[4] = relayVersion
	b[5] = byte(f.Type)
	binary.BigEndian.PutUint16(b[6:8], RelayHeaderSize)
	binary.BigEndian.PutUint32(b[8:12], f.FlowID)
	binary.BigEndian.PutUint16(b[12:14], uint16(len(f.Payload)))
	b[14], b[15] = 0, 0
	return b, nil
}

func (f RelayFrame) Marshal() ([]byte, error) {
	return EncodeRelayFrame(make([]byte, RelayHeaderSize+len(f.Payload)), f)
}

func ParseRelayFrameInPlace(b []byte) (RelayFrame, error) {
	var f RelayFrame
	if len(b) < RelayHeaderSize || [4]byte(b[:4]) != relayMagic || b[4] != relayVersion ||
		binary.BigEndian.Uint16(b[6:8]) != RelayHeaderSize || b[14] != 0 || b[15] != 0 {
		return f, errRelayEnvelope
	}
	f.Type = RelayType(b[5])
	f.FlowID = binary.BigEndian.Uint32(b[8:12])
	payloadLen := int(binary.BigEndian.Uint16(b[12:14]))
	if f.FlowID == 0 || !validRelayType(f.Type) || len(b) != RelayHeaderSize+payloadLen {
		return f, errRelayLength
	}
	f.Payload = b[RelayHeaderSize:]
	return f, nil
}

func ParseRelayFrame(b []byte) (RelayFrame, error) {
	f, err := ParseRelayFrameInPlace(b)
	if err != nil {
		return f, err
	}
	f.Payload = append([]byte(nil), f.Payload...)
	return f, nil
}

func validRelayType(t RelayType) bool {
	return t == RelayUDP || t == RelayTCPOpen || t == RelayTCPOpenAck || t == RelayTCPPacket || t == RelayTCPReject
}
