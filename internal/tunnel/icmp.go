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
)

type Tuple struct {
	IP   net.IP
	Port int
}

func (t Tuple) String() string { return net.JoinHostPort(t.IP.String(), fmt.Sprint(t.Port)) }

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// BuildPortUnreachable builds an IPv4/ICMP Type 3 Code 3 packet. The quoted
// UDP packet direction is intentionally the reverse of the outer ICMP packet.
func BuildPortUnreachable(source, destination, quotedSource, quotedDestination Tuple, payload []byte, id uint16) ([]byte, error) {
	if source.IP.To4() == nil || destination.IP.To4() == nil || quotedSource.IP.To4() == nil || quotedDestination.IP.To4() == nil {
		return nil, errors.New("only IPv4 tuples are supported")
	}
	if source.Port < 1 || source.Port > 65535 || destination.Port < 1 || destination.Port > 65535 ||
		quotedSource.Port < 1 || quotedSource.Port > 65535 || quotedDestination.Port < 1 || quotedDestination.Port > 65535 {
		return nil, errors.New("invalid UDP port")
	}
	quotedLen := ipv4HeaderLen + udpHeaderLen + len(payload)
	totalLen := ipv4HeaderLen + icmpHeaderLen + quotedLen
	if totalLen > maxIPPacket {
		return nil, fmt.Errorf("packet is %d bytes, exceeds IPv4 MTU limit %d", totalLen, maxIPPacket)
	}
	p := make([]byte, totalLen)
	writeIPv4Header(p[:ipv4HeaderLen], source.IP, destination.IP, uint16(totalLen), id, 1, true)
	p[20] = 3
	p[21] = 3

	quoted := p[ipv4HeaderLen+icmpHeaderLen:]
	writeIPv4Header(quoted[:ipv4HeaderLen], quotedSource.IP, quotedDestination.IP, uint16(quotedLen), id, 17, false)
	udp := quoted[ipv4HeaderLen : ipv4HeaderLen+udpHeaderLen]
	binary.BigEndian.PutUint16(udp[:2], uint16(quotedSource.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(quotedDestination.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen+len(payload)))
	// A zero quoted UDP checksum is valid IPv4 and avoids a checksum that NAT
	// would otherwise need to update after rewriting the quoted tuple.
	copy(quoted[ipv4HeaderLen+udpHeaderLen:], payload)
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
	copy(b[12:16], source.To4())
	copy(b[16:20], destination.To4())
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:ipv4HeaderLen]))
}

// ParsePortUnreachable accepts only packets matching the complete expected
// outer and quoted tuples and returns the quoted UDP payload.
func ParsePortUnreachable(packet []byte, expectedOuterSource, expectedOuterDestination, expectedQuotedSource, expectedQuotedDestination Tuple) ([]byte, error) {
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
	payload := quoted[quotedLen+udpHeaderLen : quotedTotal]
	return append([]byte(nil), payload...), nil
}

func packetIPMatches(b []byte, expected net.IP) bool {
	return expected.To4() != nil && len(b) == 4 && string(b) == string(expected.To4())
}
