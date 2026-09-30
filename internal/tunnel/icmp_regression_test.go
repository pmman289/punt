package tunnel

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParsePortUnreachableShortQuotedDoesNotPanic(t *testing.T) {
	a := Tuple{IP: net.ParseIP("10.0.0.1").To4(), Port: 1}
	b := Tuple{IP: net.ParseIP("10.0.0.2").To4(), Port: 2}
	p := make([]byte, 64)
	p[0] = 0x46 // outer IHL=6; no quoted datagram follows the ICMP header
	binary.BigEndian.PutUint16(p[2:4], 24+8)
	p[9] = 1
	copy(p[12:16], a.IP)
	copy(p[16:20], b.IP)
	p[24], p[25] = 3, 3
	if _, err := ParsePortUnreachable(p, a, b, b, a); err == nil {
		t.Fatal("accepted a packet with an empty quoted datagram")
	}
}
