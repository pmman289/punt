package tunnel

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/pmman289/punt/internal/protocol"
)

func TestTCPControlHelloLearnsClaimedUDPPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan event, 4)
	listener, err := startTCPControlListener(ctx, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, events)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	control, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	e := &engine{
		cfg:     Config{Mode: Server, Network: control.LocalAddr().(*net.UDPAddr), Key: carrierTestKey, Logger: log.New(io.Discard, "", 0)},
		control: control,
	}

	conn, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hello, err := (protocol.Control{Type: protocol.Hello, ClientSession: 42, Nonce: 99, ObservedPort: 42493}).Marshal(carrierTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-events:
		if ev.type_ != tcpControlEvent {
			t.Fatalf("event type = %d, want TCP control", ev.type_)
		}
		e.handleTCPControl(ev.data, ev.addr, ev.conn)
	case <-time.After(time.Second):
		t.Fatal("did not receive TCP control event")
	}
	if e.remote == nil || e.remote.Port != 42493 || !e.remote.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("learned remote = %#v", e.remote)
	}
	if e.controlTransport != "tcp" {
		t.Fatalf("control transport = %q", e.controlTransport)
	}

	ack := make([]byte, protocol.ControlSize)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, ack); err != nil {
		t.Fatal(err)
	}
	parsed, err := protocol.ParseControl(ack, carrierTestKey)
	if err != nil || parsed.Type != protocol.HelloAck || parsed.Nonce != 99 {
		t.Fatalf("TCP HELLO_ACK = %#v, err=%v", parsed, err)
	}
}
