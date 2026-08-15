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

// RelayFrame multiplexes application flows inside an authenticated Punt data
// packet. It has no MAC of its own: Data.Marshal authenticates the complete
// encoded frame.
type RelayFrame struct {
	Type    RelayType
	FlowID  uint32
	Payload []byte
}

func (f RelayFrame) Marshal() ([]byte, error) {
	if f.FlowID == 0 || !validRelayType(f.Type) || len(f.Payload) > MaxRelayPayload {
		return nil, errors.New("invalid relay frame")
	}
	b := make([]byte, RelayHeaderSize+len(f.Payload))
	copy(b[:4], relayMagic[:])
	b[4] = relayVersion
	b[5] = byte(f.Type)
	binary.BigEndian.PutUint16(b[6:8], RelayHeaderSize)
	binary.BigEndian.PutUint32(b[8:12], f.FlowID)
	binary.BigEndian.PutUint16(b[12:14], uint16(len(f.Payload)))
	copy(b[RelayHeaderSize:], f.Payload)
	return b, nil
}

func ParseRelayFrame(b []byte) (RelayFrame, error) {
	var f RelayFrame
	if len(b) < RelayHeaderSize || string(b[:4]) != string(relayMagic[:]) || b[4] != relayVersion ||
		binary.BigEndian.Uint16(b[6:8]) != RelayHeaderSize || b[14] != 0 || b[15] != 0 {
		return f, errors.New("invalid relay envelope")
	}
	f.Type = RelayType(b[5])
	f.FlowID = binary.BigEndian.Uint32(b[8:12])
	payloadLen := int(binary.BigEndian.Uint16(b[12:14]))
	if f.FlowID == 0 || !validRelayType(f.Type) || len(b) != RelayHeaderSize+payloadLen {
		return f, errors.New("invalid relay frame length")
	}
	f.Payload = append([]byte(nil), b[RelayHeaderSize:]...)
	return f, nil
}

func validRelayType(t RelayType) bool {
	return t == RelayUDP || t == RelayTCPOpen || t == RelayTCPOpenAck || t == RelayTCPPacket || t == RelayTCPReject
}
