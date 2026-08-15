package tunnel

import (
	"net"
	"testing"
)

func tuple(ip string, port int) Tuple { return Tuple{IP: net.ParseIP(ip), Port: port} }

func TestPortUnreachableRoundTrip(t *testing.T) {
	local := tuple("192.0.2.2", 42487)
	remote := tuple("198.51.100.9", 23086)
	payload := []byte("PUWG authenticated payload")
	p, err := BuildPortUnreachable(remote, local, local, remote, payload, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePortUnreachable(p, remote, local, local, remote)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("got %q, err %v", got, err)
	}
	if _, err := ParsePortUnreachable(p, local, remote, remote, local); err == nil {
		t.Fatal("accepted packet with reversed tuples")
	}
}

func TestPortUnreachableRejectsTruncation(t *testing.T) {
	a, b := tuple("192.0.2.2", 1), tuple("198.51.100.9", 2)
	p, err := BuildPortUnreachable(b, a, a, b, []byte("x"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePortUnreachable(p[:len(p)-1], b, a, a, b); err == nil {
		t.Fatal("accepted a truncated ICMP packet")
	}
}
