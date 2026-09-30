package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/pmman289/punt/internal/protocol"
	"github.com/xtaci/kcp-go/v5"
)

const maxPendingTCP = 1 << 20

const (
	tcpSendHighWater   = 512
	tcpSendLowWater    = 256
	tcpReadChunk       = 32 * 1024
	tcpWriteBatch      = 32 * 1024
	tcpWriteQueue      = 64
	defaultKCPInterval = 10
	defaultKCPWindow   = 512
	defaultKCPResend   = 2
)

type tcpFlow struct {
	id        uint32
	conn      *net.TCPConn
	kcp       *kcp.KCP
	opened    bool
	pending   [][]byte
	last      time.Time
	lastOpen  time.Time
	readReady chan struct{}
	outq      chan []byte // nil means CloseWrite
	outClosed bool
	finQueued bool
}

type tcpRelay struct {
	cfg       RelayConfig
	listener  bool
	ctx       context.Context
	listen    *net.TCPListener
	flows     map[uint32]*tcpFlow
	opening   map[uint32]bool
	events    chan<- event
	send      func(protocol.RelayFrame)
	congested func() bool
	recvBuf   []byte
	sendBuf   []byte
}

func startTCPRelay(ctx context.Context, mode Mode, cfg RelayConfig, events chan<- event, send func(protocol.RelayFrame)) (*tcpRelay, error) {
	limit := relayPayloadLimit(cfg)
	r := &tcpRelay{cfg: cfg, listener: mode == relayListenSide(cfg), ctx: ctx,
		flows: make(map[uint32]*tcpFlow), opening: make(map[uint32]bool), events: events,
		send: send, recvBuf: make([]byte, limit), sendBuf: make([]byte, limit)}
	if !r.listener {
		return r, nil
	}
	listener, err := net.ListenTCP("tcp4", tcpAddr(cfg.Listen))
	if err != nil {
		return nil, err
	}
	r.listen = listener
	go r.accept()
	return r, nil
}

func tcpAddr(addr *net.UDPAddr) *net.TCPAddr {
	if addr == nil {
		return nil
	}
	return &net.TCPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func (r *tcpRelay) Close() error {
	if r.listen != nil {
		_ = r.listen.Close()
	}
	r.reset()
	return nil
}

func (r *tcpRelay) reset() {
	for _, flow := range r.flows {
		closeTCPFlow(flow)
	}
	r.flows = make(map[uint32]*tcpFlow)
	r.opening = make(map[uint32]bool)
}

func closeTCPFlow(flow *tcpFlow) {
	releaseTCPReader(flow)
	if !flow.outClosed && flow.outq != nil {
		close(flow.outq)
		flow.outClosed = true
	}
	if flow.conn != nil {
		_ = flow.conn.Close()
	}
}

func (r *tcpRelay) removeFlow(flow *tcpFlow) {
	closeTCPFlow(flow)
	delete(r.flows, flow.id)
}

func (r *tcpRelay) accept() {
	for {
		conn, err := r.listen.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || r.ctx.Err() != nil {
				return
			}
			continue
		}
		_ = conn.SetNoDelay(true)
		select {
		case r.events <- event{type_: relayTCPAcceptEvent, conn: conn}:
		case <-r.ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

func (r *tcpRelay) startReader(id uint32, conn *net.TCPConn, kind eventType) {
	go func() {
		buf := make([]byte, tcpReadChunk)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				ready := make(chan struct{})
				select {
				case r.events <- event{type_: kind, flowID: id, data: buf[:n], ready: ready}:
				case <-r.ctx.Done():
					return
				}
				select {
				case <-ready:
				case <-r.ctx.Done():
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					select {
					case r.events <- event{type_: kind, flowID: id, eof: true}:
					case <-r.ctx.Done():
					}
				}
				return
			}
		}
	}()
}

func startWriter(conn *net.TCPConn, outq <-chan []byte) {
	go func() {
		failed := false
		for b := range outq {
			if failed {
				continue
			}
			if b == nil {
				_ = conn.CloseWrite()
				continue
			}
			if _, err := conn.Write(b); err != nil {
				failed = true
				_ = conn.Close()
			}
		}
	}()
}

func (r *tcpRelay) newFlow(id uint32, conn *net.TCPConn, now time.Time) *tcpFlow {
	flow := &tcpFlow{id: id, conn: conn, last: now, outq: make(chan []byte, tcpWriteQueue)}
	flow.kcp = kcp.NewKCP(id, func(buf []byte, size int) {
		r.send(protocol.RelayFrame{Type: protocol.RelayTCPPacket, FlowID: id, Payload: buf[:size]})
	})
	_ = flow.kcp.SetMtu(relayPayloadLimit(r.cfg))
	interval := r.cfg.KCPInterval
	if interval <= 0 {
		interval = defaultKCPInterval
	}
	resend := r.cfg.KCPFastResend
	if resend < 0 {
		resend = 0
	} else if resend == 0 {
		resend = defaultKCPResend
	}
	noCwnd := 0
	if r.cfg.TCPNoCwnd {
		noCwnd = 1
	}
	_ = flow.kcp.NoDelay(1, interval, resend, noCwnd)
	wnd := r.cfg.KCPWindow
	if wnd <= 0 {
		wnd = defaultKCPWindow
	}
	flow.kcp.WndSize(wnd, wnd)
	_ = conn.SetNoDelay(true)
	startWriter(conn, flow.outq)
	r.flows[id] = flow
	return flow
}

func (r *tcpRelay) acceptLocal(conn *net.TCPConn, now time.Time) {
	id := uint32(randomUint64())
	if id == 0 {
		id = 1
	}
	for r.flows[id] != nil {
		id++
		if id == 0 {
			id = 1
		}
	}
	flow := r.newFlow(id, conn, now)
	flow.lastOpen = now
	r.startReader(id, conn, relayTCPClientEvent)
	r.send(protocol.RelayFrame{Type: protocol.RelayTCPOpen, FlowID: id})
}

func (r *tcpRelay) handleFrame(frame protocol.RelayFrame, now time.Time) error {
	switch frame.Type {
	case protocol.RelayTCPOpen:
		if r.listener {
			return errors.New("TCP open received by relay listener side")
		}
		flow := r.flows[frame.FlowID]
		if flow == nil {
			if !r.opening[frame.FlowID] {
				r.opening[frame.FlowID] = true
				go r.dialTarget(frame.FlowID)
			}
			return nil
		}
		flow.last = now
		r.send(protocol.RelayFrame{Type: protocol.RelayTCPOpenAck, FlowID: frame.FlowID})
		return nil
	case protocol.RelayTCPOpenAck:
		if !r.listener {
			return errors.New("TCP open acknowledgment received by relay target side")
		}
		flow := r.flows[frame.FlowID]
		if flow == nil {
			return errors.New("unknown TCP relay flow")
		}
		if flow.opened {
			return nil
		}
		flow.opened = true
		flow.last = now
		for _, msg := range flow.pending {
			if flow.kcp.Send(msg) < 0 {
				r.removeFlow(flow)
				return nil
			}
		}
		flow.pending = nil
		r.flushKCP(flow)
		r.maybeReleaseReader(flow, r.highWater())
		return nil
	case protocol.RelayTCPReject:
		if !r.listener {
			return errors.New("TCP rejection received by relay target side")
		}
		if flow := r.flows[frame.FlowID]; flow != nil {
			r.removeFlow(flow)
		}
		return nil
	case protocol.RelayTCPPacket:
		flow := r.flows[frame.FlowID]
		if flow == nil || !flow.opened {
			return errors.New("unknown or unopened TCP relay flow")
		}
		flow.last = now
		if flow.kcp.Input(frame.Payload, true, true) < 0 {
			return errors.New("invalid KCP packet")
		}
		r.drain(flow)
		return nil
	default:
		return errors.New("unexpected TCP relay frame")
	}
}

func (r *tcpRelay) dialTarget(id uint32) {
	connRaw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(r.ctx, "tcp4", r.cfg.Target.String())
	if r.ctx.Err() != nil {
		if connRaw != nil {
			_ = connRaw.Close()
		}
		return
	}
	var conn *net.TCPConn
	if connRaw != nil {
		conn = connRaw.(*net.TCPConn)
	}
	select {
	case r.events <- event{type_: relayTCPConnectedEvent, flowID: id, conn: conn, err: err}:
	case <-r.ctx.Done():
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (r *tcpRelay) targetConnected(id uint32, conn *net.TCPConn, dialErr error, now time.Time) {
	if !r.opening[id] {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	delete(r.opening, id)
	if dialErr != nil || conn == nil {
		r.send(protocol.RelayFrame{Type: protocol.RelayTCPReject, FlowID: id})
		return
	}
	if r.flows[id] != nil {
		_ = conn.Close()
		return
	}
	flow := r.newFlow(id, conn, now)
	flow.opened = true
	r.startReader(id, conn, relayTCPTargetEvent)
	r.send(protocol.RelayFrame{Type: protocol.RelayTCPOpenAck, FlowID: id})
}

func (r *tcpRelay) localData(id uint32, payload []byte, eof bool, ready chan struct{}, now time.Time) {
	flow := r.flows[id]
	if flow == nil {
		if ready != nil {
			close(ready)
		}
		return
	}
	flow.last = now
	if len(payload) > 0 {
		if !flow.opened {
			pending := 0
			for _, item := range flow.pending {
				pending += len(item)
			}
			if pending+len(payload) > maxPendingTCP {
				r.removeFlow(flow)
				if ready != nil {
					close(ready)
				}
				return
			}
			flow.pending = append(flow.pending, frameApplicationData(payload, r.chunkSize())...)
		} else if !r.sendApplicationData(flow, payload) {
			r.removeFlow(flow)
			if ready != nil {
				close(ready)
			}
			return
		}
	}
	if eof {
		fin := []byte{1}
		if flow.opened {
			if flow.kcp.Send(fin) < 0 {
				r.removeFlow(flow)
				if ready != nil {
					close(ready)
				}
				return
			}
		} else {
			flow.pending = append(flow.pending, fin)
		}
	}
	if flow.opened {
		r.flushKCP(flow)
	}
	if ready != nil {
		if flow.opened && flow.kcp.WaitSnd() < r.highWater() {
			close(ready)
		} else {
			flow.readReady = ready
		}
	}
}

func (r *tcpRelay) chunkSize() int { return relayPayloadLimit(r.cfg) - kcp.IKCP_OVERHEAD - 1 }

func (r *tcpRelay) highWater() int {
	if r.cfg.KCPWindow > tcpSendHighWater {
		return r.cfg.KCPWindow
	}
	return tcpSendHighWater
}

func (r *tcpRelay) sendApplicationData(flow *tcpFlow, payload []byte) bool {
	chunk := r.chunkSize()
	for len(payload) > 0 {
		n := min(len(payload), chunk)
		r.sendBuf[0] = 0
		copy(r.sendBuf[1:], payload[:n])
		if flow.kcp.Send(r.sendBuf[:n+1]) < 0 {
			return false
		}
		payload = payload[n:]
	}
	return true
}

func frameApplicationData(payload []byte, chunkSize int) [][]byte {
	frames := make([][]byte, 0, (len(payload)+chunkSize-1)/chunkSize)
	for len(payload) > 0 {
		n := min(len(payload), chunkSize)
		frame := make([]byte, n+1)
		copy(frame[1:], payload[:n])
		frames = append(frames, frame)
		payload = payload[n:]
	}
	return frames
}

// Kept for package tests and compatibility with callers that used the helper.
func (r *tcpRelay) frameApplicationData(payload []byte) [][]byte {
	return frameApplicationData(payload, r.chunkSize())
}

func (r *tcpRelay) flushKCP(flow *tcpFlow) {
	if r.congested != nil && r.congested() {
		return
	}
	flow.kcp.Update()
}

func (r *tcpRelay) drain(flow *tcpFlow) {
	if flow.outClosed || flow.finQueued {
		return
	}
	var batch []byte
	for cap(flow.outq)-len(flow.outq) >= 2 {
		n := flow.kcp.Recv(r.recvBuf)
		if n < 0 {
			break
		}
		if n == 0 {
			continue
		}
		msg := r.recvBuf[:n]
		switch msg[0] {
		case 0:
			if batch == nil {
				batch = make([]byte, 0, tcpWriteBatch)
			}
			if len(batch)+n-1 > cap(batch) {
				flow.outq <- batch
				batch = make([]byte, 0, tcpWriteBatch)
			}
			batch = append(batch, msg[1:]...)
		case 1:
			if len(batch) > 0 {
				flow.outq <- batch
			}
			flow.outq <- nil
			flow.finQueued = true
			return
		default:
			r.removeFlow(flow)
			return
		}
	}
	if len(batch) > 0 {
		flow.outq <- batch
	}
}

func (r *tcpRelay) update(now time.Time) {
	for id, flow := range r.flows {
		if r.listener && !flow.opened && now.Sub(flow.lastOpen) >= 500*time.Millisecond {
			r.send(protocol.RelayFrame{Type: protocol.RelayTCPOpen, FlowID: id})
			flow.lastOpen = now
		}
		if !flow.opened {
			continue
		}
		r.flushKCP(flow)
		r.drain(flow)
		r.maybeReleaseReader(flow, r.highWater()/2)
	}
}

func (r *tcpRelay) maybeReleaseReader(flow *tcpFlow, threshold int) {
	if flow.readReady != nil && flow.opened && flow.kcp.WaitSnd() < threshold {
		releaseTCPReader(flow)
	}
}

func releaseTCPReader(flow *tcpFlow) {
	if flow.readReady != nil {
		close(flow.readReady)
		flow.readReady = nil
	}
}

func (r *tcpRelay) expire(now time.Time) {
	for _, flow := range r.flows {
		if now.Sub(flow.last) > r.cfg.IdleTimeout {
			r.removeFlow(flow)
		}
	}
}
