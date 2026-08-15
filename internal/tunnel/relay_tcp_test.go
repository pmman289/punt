package tunnel

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pmman289/punt/internal/protocol"
	"github.com/xtaci/kcp-go/v5"
)

func TestTCPRelayRoundTrip(t *testing.T) {
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.AcceptTCP()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan event, 128)
	serverCfg := RelayConfig{Protocol: RelayTCP, Target: udpAddr(target.Addr().String()), IdleTimeout: time.Minute}
	clientCfg := RelayConfig{Protocol: RelayTCP, Listen: udpAddr("127.0.0.1:0"), IdleTimeout: time.Minute}
	var client, server *tcpRelay
	var dropped atomic.Bool
	server, err = startTCPRelay(ctx, Server, serverCfg, events, func(frame protocol.RelayFrame) {
		if err := client.handleFrame(frame, time.Now()); err != nil {
			t.Errorf("server -> client frame: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err = startTCPRelay(ctx, Client, clientCfg, events, func(frame protocol.RelayFrame) {
		if frame.Type == protocol.RelayTCPPacket && !dropped.Swap(true) {
			return // Verify the KCP sub-session retransmits an ICMP-frame loss.
		}
		if err := server.handleFrame(frame, time.Now()); err != nil {
			t.Errorf("client -> server frame: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case ev := <-events:
				switch ev.type_ {
				case relayTCPAcceptEvent:
					client.acceptLocal(ev.conn, time.Now())
				case relayTCPClientEvent:
					client.localData(ev.flowID, ev.data, ev.eof, ev.ready, time.Now())
				case relayTCPTargetEvent:
					server.localData(ev.flowID, ev.data, ev.eof, ev.ready, time.Now())
				case relayTCPConnectedEvent:
					server.targetConnected(ev.flowID, ev.conn, ev.err, time.Now())
				}
			case now := <-ticker.C:
				client.update(now)
				server.update(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel()
		<-done
		_ = client.Close()
		_ = server.Close()
	}()

	conn, err := net.DialTimeout("tcp4", client.listen.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("punt reliable TCP relay")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if !dropped.Load() {
		t.Fatal("test did not drop a TCP relay packet")
	}
}

func TestTCPRelayRejectClosesLocalConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan event, 8)
	r, err := startTCPRelay(ctx, Client, RelayConfig{
		Protocol: RelayTCP, Listen: udpAddr("127.0.0.1:0"), IdleTimeout: time.Minute,
	}, events, func(protocol.RelayFrame) {})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	conn, err := net.DialTimeout("tcp4", r.listen.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ev := <-events
	r.acceptLocal(ev.conn, time.Now())
	var id uint32
	for id = range r.flows {
		break
	}
	if err := r.handleFrame(protocol.RelayFrame{Type: protocol.RelayTCPReject, FlowID: id}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("local TCP connection remained open after target rejection")
	}
}

func TestTCPRelayServerListenSideRoundTrip(t *testing.T) {
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.AcceptTCP()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan event, 128)
	serverCfg := RelayConfig{Protocol: RelayTCP, ListenSide: Server, Listen: udpAddr("127.0.0.1:0"), IdleTimeout: time.Minute}
	clientCfg := RelayConfig{Protocol: RelayTCP, ListenSide: Server, Target: udpAddr(target.Addr().String()), IdleTimeout: time.Minute}
	var client, server *tcpRelay
	server, err = startTCPRelay(ctx, Server, serverCfg, events, func(frame protocol.RelayFrame) { _ = client.handleFrame(frame, time.Now()) })
	if err != nil {
		t.Fatal(err)
	}
	client, err = startTCPRelay(ctx, Client, clientCfg, events, func(frame protocol.RelayFrame) { _ = server.handleFrame(frame, time.Now()) })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case ev := <-events:
				switch ev.type_ {
				case relayTCPAcceptEvent:
					server.acceptLocal(ev.conn, time.Now())
				case relayTCPClientEvent:
					server.localData(ev.flowID, ev.data, ev.eof, ev.ready, time.Now())
				case relayTCPTargetEvent:
					client.localData(ev.flowID, ev.data, ev.eof, ev.ready, time.Now())
				case relayTCPConnectedEvent:
					client.targetConnected(ev.flowID, ev.conn, ev.err, time.Now())
				}
			case now := <-ticker.C:
				client.update(now)
				server.update(now)
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel()
		<-done
		_ = client.Close()
		_ = server.Close()
	}()

	conn, err := net.DialTimeout("tcp4", server.listen.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("server-side listener")
	_, _ = conn.Write(payload)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != string(payload) {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestTCPRelayFramesApplicationDataAtMSS(t *testing.T) {
	r := &tcpRelay{cfg: RelayConfig{MaxPayload: protocol.MaxRelayPayload}}
	payload := make([]byte, 32*1024)
	frames := r.frameApplicationData(payload)
	if len(frames) < 2 {
		t.Fatal("application read was not split into MSS-sized messages")
	}
	got := 0
	for _, frame := range frames {
		if len(frame) > protocol.MaxRelayPayload-kcp.IKCP_OVERHEAD {
			t.Fatalf("frame length %d exceeds one KCP segment", len(frame))
		}
		if frame[0] != 0 {
			t.Fatal("missing TCP data marker")
		}
		got += len(frame) - 1
	}
	if got != len(payload) {
		t.Fatalf("framed %d bytes, want %d", got, len(payload))
	}
}

func udpAddr(value string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp4", value)
	if err != nil {
		panic(err)
	}
	return addr
}
