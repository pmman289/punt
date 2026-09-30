// Package tunnel implements the Linux control-plane and data carriers.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ipv4HeaderLen = 20
	icmpHeaderLen = 8
	udpHeaderLen  = 8
	maxIPPacket   = 1500

	// icmpPayloadOffset is where the quoted UDP payload starts in a generated
	// Port Unreachable packet.
	icmpPayloadOffset = ipv4HeaderLen + icmpHeaderLen + ipv4HeaderLen + udpHeaderLen
)

var (
	errIPv4Only    = errors.New("only IPv4 tuples are supported")
	errInvalidPort = errors.New("invalid UDP port")
)

type Tuple struct {
	IP   net.IP
	Port int
}

func (t Tuple) String() string { return net.JoinHostPort(t.IP.String(), fmt.Sprint(t.Port)) }

func validTuples(tuples ...Tuple) error {
	for _, t := range tuples {
		if t.IP.To4() == nil {
			return errIPv4Only
		}
	}
	for _, t := range tuples {
		if t.Port < 1 || t.Port > 65535 {
			return errInvalidPort
		}
	}
	return nil
}

// checksum returns the RFC 1071 Internet checksum using wide accumulators.
func checksum(b []byte) uint16 {
	var sum uint64
	for len(b) >= 8 {
		sum += uint64(binary.BigEndian.Uint32(b[:4])) + uint64(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
	}
	if len(b) >= 4 {
		sum += uint64(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
	}
	if len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func BuildPortUnreachable(source, destination, quotedSource, quotedDestination Tuple, payload []byte, id uint16) ([]byte, error) {
	if icmpPayloadOffset+len(payload) > maxIPPacket {
		return nil, fmt.Errorf("packet is %d bytes, exceeds IPv4 MTU limit %d", icmpPayloadOffset+len(payload), maxIPPacket)
	}
	p := make([]byte, icmpPayloadOffset+len(payload))
	copy(p[icmpPayloadOffset:], payload)
	return finishPortUnreachable(p, source, destination, quotedSource, quotedDestination, len(payload), id)
}

// finishPortUnreachable writes headers into a buffer whose payload is already
// at icmpPayloadOffset. It is used by the hot transmit path.
func finishPortUnreachable(p []byte, source, destination, quotedSource, quotedDestination Tuple, payloadLen int, id uint16) ([]byte, error) {
	if err := validTuples(source, destination, quotedSource, quotedDestination); err != nil {
		return nil, err
	}
	quotedLen := ipv4HeaderLen + udpHeaderLen + payloadLen
	totalLen := ipv4HeaderLen + icmpHeaderLen + quotedLen
	if totalLen > maxIPPacket {
		return nil, fmt.Errorf("packet is %d bytes, exceeds IPv4 MTU limit %d", totalLen, maxIPPacket)
	}
	if cap(p) < totalLen {
		return nil, errors.New("ICMP build buffer too small")
	}
	p = p[:totalLen]
	writeIPv4Header(p[:ipv4HeaderLen], source.IP, destination.IP, uint16(totalLen), id, 1, true)
	icmp := p[ipv4HeaderLen : ipv4HeaderLen+icmpHeaderLen]
	icmp[0], icmp[1] = 3, 3
	clear(icmp[2:])
	quoted := p[ipv4HeaderLen+icmpHeaderLen:]
	writeIPv4Header(quoted[:ipv4HeaderLen], quotedSource.IP, quotedDestination.IP, uint16(quotedLen), id, 17, false)
	udp := quoted[ipv4HeaderLen : ipv4HeaderLen+udpHeaderLen]
	binary.BigEndian.PutUint16(udp[:2], uint16(quotedSource.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(quotedDestination.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen+payloadLen))
	udp[6], udp[7] = 0, 0
	binary.BigEndian.PutUint16(p[22:24], checksum(p[ipv4HeaderLen:]))
	return p, nil
}

func writeIPv4Header(b []byte, source, destination net.IP, totalLen, id uint16, protocol uint8, df bool) {
	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], totalLen)
	binary.BigEndian.PutUint16(b[4:6], id)
	flags := uint16(0)
	if df {
		flags = 0x4000
	}
	binary.BigEndian.PutUint16(b[6:8], flags)
	b[8] = 64
	b[9] = protocol
	b[10], b[11] = 0, 0
	copy(b[12:16], source.To4())
	copy(b[16:20], destination.To4())
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:ipv4HeaderLen]))
}

func ParsePortUnreachable(packet []byte, expectedOuterSource, expectedOuterDestination, expectedQuotedSource, expectedQuotedDestination Tuple) ([]byte, error) {
	payload, err := parsePortUnreachableInPlace(packet, expectedOuterSource, expectedOuterDestination, expectedQuotedSource, expectedQuotedDestination)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), payload...), nil
}

func parsePortUnreachableInPlace(packet []byte, expectedOuterSource, expectedOuterDestination, expectedQuotedSource, expectedQuotedDestination Tuple) ([]byte, error) {
	if len(packet) < ipv4HeaderLen+icmpHeaderLen+ipv4HeaderLen+udpHeaderLen {
		return nil, errors.New("packet too short")
	}
	outerLen := int(packet[0]&0x0f) * 4
	if packet[0]>>4 != 4 || outerLen < ipv4HeaderLen || outerLen > len(packet) || packet[9] != 1 {
		return nil, errors.New("invalid outer IPv4 header")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < outerLen+icmpHeaderLen || totalLen > len(packet) {
		return nil, errors.New("invalid outer IPv4 length")
	}
	if !packetIPMatches(packet[12:16], expectedOuterSource.IP) || !packetIPMatches(packet[16:20], expectedOuterDestination.IP) {
		return nil, errors.New("unexpected outer tuple")
	}
	if packet[outerLen] != 3 || packet[outerLen+1] != 3 {
		return nil, errors.New("not ICMP port unreachable")
	}
	quoted := packet[outerLen+icmpHeaderLen : totalLen]
	if len(quoted) < ipv4HeaderLen+udpHeaderLen {
		return nil, errors.New("invalid quoted IPv4 header")
	}
	quotedLen := int(quoted[0]&0x0f) * 4
	if quoted[0]>>4 != 4 || quotedLen < ipv4HeaderLen || quotedLen+udpHeaderLen > len(quoted) || quoted[9] != 17 {
		return nil, errors.New("invalid quoted IPv4 header")
	}
	quotedTotal := int(binary.BigEndian.Uint16(quoted[2:4]))
	if quotedTotal < quotedLen+udpHeaderLen || quotedTotal > len(quoted) {
		return nil, errors.New("invalid quoted IPv4 length")
	}
	if !packetIPMatches(quoted[12:16], expectedQuotedSource.IP) || !packetIPMatches(quoted[16:20], expectedQuotedDestination.IP) {
		return nil, errors.New("unexpected quoted IP tuple")
	}
	udp := quoted[quotedLen : quotedLen+udpHeaderLen]
	if int(binary.BigEndian.Uint16(udp[:2])) != expectedQuotedSource.Port || int(binary.BigEndian.Uint16(udp[2:4])) != expectedQuotedDestination.Port {
		return nil, errors.New("unexpected quoted UDP tuple")
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < udpHeaderLen || udpLen != quotedTotal-quotedLen {
		return nil, errors.New("invalid quoted UDP length")
	}
	return quoted[quotedLen+udpHeaderLen : quotedTotal], nil
}

func packetIPMatches(b []byte, expected net.IP) bool {
	e := expected.To4()
	return e != nil && len(b) == 4 && [4]byte(b) == [4]byte(e)
}
