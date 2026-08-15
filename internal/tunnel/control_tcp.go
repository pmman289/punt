package tunnel

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/pmman289/punt/internal/protocol"
)

func startTCPControlListener(ctx context.Context, addr *net.UDPAddr, out chan<- event) (*net.TCPListener, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, acceptErr := listener.AcceptTCP()
			if acceptErr != nil {
				return
			}
			go readTCPControl(ctx, conn, out)
		}
	}()
	return listener, nil
}

func readTCPControl(ctx context.Context, conn *net.TCPConn, out chan<- event) {
	defer func() {
		select {
		case out <- event{type_: tcpControlClosedEvent, conn: conn}:
		case <-ctx.Done():
		}
		_ = conn.Close()
	}()
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.To4() == nil {
		return
	}
	sender := &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: remote.Port}
	for {
		packet := make([]byte, protocol.ControlSize)
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}
		select {
		case out <- event{type_: tcpControlEvent, data: packet, addr: sender, conn: conn, viaTCP: true}:
		case <-ctx.Done():
			return
		}
	}
}

func (e *engine) startTCPControlDial() {
	e.tcpDialing = true
	e.lastTCPDial = time.Now()
	local := &net.TCPAddr{IP: append(net.IP(nil), e.cfg.Network.IP...), Port: e.cfg.Network.Port}
	peer := &net.TCPAddr{IP: append(net.IP(nil), e.cfg.Peer.IP...), Port: e.cfg.Peer.Port}
	timeout := e.cfg.TCPFallback
	go func() {
		dialer := net.Dialer{LocalAddr: local, Timeout: timeout}
		rawConn, err := dialer.DialContext(e.ctx, "tcp4", peer.String())
		var conn *net.TCPConn
		if err == nil {
			conn = rawConn.(*net.TCPConn)
			_ = conn.SetKeepAlive(true)
		}
		event := event{type_: tcpControlConnectedEvent, conn: conn, err: err}
		// The engine owns the connection after this send. If it is shutting down,
		// close the speculative dial instead of leaking it.
		select {
		case e.events <- event:
		case <-e.ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
}

func (e *engine) handleTCPControlConnected(conn *net.TCPConn, err error) {
	e.tcpDialing = false
	if err != nil {
		e.logf("TCP control fallback dial: %v", err)
		return
	}
	if e.cfg.Mode != Client || e.state == established {
		_ = conn.Close()
		return
	}
	e.replaceTCPControl(conn)
	e.controlTransport = "tcp"
	go readTCPControl(e.ctx, conn, e.events)
	e.sendTCPHello(time.Now())
}

func (e *engine) replaceTCPControl(conn *net.TCPConn) {
	if e.tcpControl != nil && e.tcpControl != conn {
		_ = e.tcpControl.Close()
	}
	e.tcpControl = conn
}

func (e *engine) closeTCPControl() {
	if e.tcpControl != nil {
		_ = e.tcpControl.Close()
		e.tcpControl = nil
	}
}
