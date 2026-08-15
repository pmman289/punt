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
	tcpSendHighWater = 512
	tcpSendLowWater  = 256
)

type tcpFlow struct {
	conn      *net.TCPConn
	kcp       *kcp.KCP
	opened    bool
	pending   [][]byte
	last      time.Time
	lastOpen  time.Time
	readReady chan struct{}
}

type tcpRelay struct {
	cfg      RelayConfig
	listener bool
	ctx      context.Context
	listen   *net.TCPListener
	flows    map[uint32]*tcpFlow
	opening  map[uint32]bool
	events   chan<- event
	send     func(protocol.RelayFrame)
}

func startTCPRelay(ctx context.Context, mode Mode, cfg RelayConfig, events chan<- event, send func(protocol.RelayFrame)) (*tcpRelay, error) {
	r := &tcpRelay{cfg: cfg, listener: mode == relayListenSide(cfg), ctx: ctx, flows: make(map[uint32]*tcpFlow), opening: make(map[uint32]bool), events: events, send: send}
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
		releaseTCPReader(flow)
		_ = flow.conn.Close()
	}
	r.flows = make(map[uint32]*tcpFlow)
	r.opening = make(map[uint32]bool)
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
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				ready := make(chan struct{})
				select {
				case r.events <- event{type_: kind, flowID: id, data: payload, ready: ready}:
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

func (r *tcpRelay) newFlow(id uint32, conn *net.TCPConn, now time.Time) *tcpFlow {
	flow := &tcpFlow{conn: conn, last: now}
	flow.kcp = kcp.NewKCP(id, func(buf []byte, size int) {
		// KCP owns buf after this callback returns, so retain a copy for the
		// authenticated Punt frame.
		r.send(protocol.RelayFrame{Type: protocol.RelayTCPPacket, FlowID: id, Payload: append([]byte(nil), buf[:size]...)})
	})
	_ = flow.kcp.SetMtu(relayPayloadLimit(r.cfg))
	noCwnd := 0
	if r.cfg.TCPNoCwnd {
		noCwnd = 1
	}
	_ = flow.kcp.NoDelay(1, 10, 2, noCwnd)
	flow.kcp.WndSize(512, 512)
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
		flow.opened = true
		flow.last = now
		for _, payload := range flow.pending {
			r.sendKCP(flow, payload)
		}
		flow.pending = nil
		r.maybeReleaseReader(flow, tcpSendHighWater)
		return nil
	case protocol.RelayTCPReject:
		if !r.listener {
			return errors.New("TCP rejection received by relay target side")
		}
		flow := r.flows[frame.FlowID]
		if flow == nil {
			return nil
		}
		releaseTCPReader(flow)
		_ = flow.conn.Close()
		delete(r.flows, frame.FlowID)
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
		framed := r.frameApplicationData(payload)
		if !flow.opened {
			pending := 0
			for _, item := range flow.pending {
				pending += len(item)
			}
			if pending+len(payload) > maxPendingTCP {
				_ = flow.conn.Close()
				if ready != nil {
					close(ready)
				}
				return
			}
			flow.pending = append(flow.pending, framed...)
		} else {
			for _, item := range framed {
				r.sendKCP(flow, item)
			}
		}
	}
	if eof {
		fin := []byte{1}
		if flow.opened {
			r.sendKCP(flow, fin)
		} else {
			flow.pending = append(flow.pending, fin)
		}
	}
	if ready != nil {
		if flow.opened && flow.kcp.WaitSnd() < tcpSendHighWater {
			close(ready)
		} else {
			flow.readReady = ready
		}
	}
}

func (r *tcpRelay) frameApplicationData(payload []byte) [][]byte {
	chunkSize := relayPayloadLimit(r.cfg) - kcp.IKCP_OVERHEAD - 1
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

func (r *tcpRelay) sendKCP(flow *tcpFlow, payload []byte) {
	if flow.kcp.Send(payload) < 0 {
		_ = flow.conn.Close()
		releaseTCPReader(flow)
		return
	}
	flow.kcp.Update()
}

func (r *tcpRelay) drain(flow *tcpFlow) {
	message := make([]byte, relayPayloadLimit(r.cfg))
	batch := make([]byte, 0, 32*1024)
	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		if _, err := flow.conn.Write(batch); err != nil {
			_ = flow.conn.Close()
			return false
		}
		batch = batch[:0]
		return true
	}
	for {
		n := flow.kcp.Recv(message)
		if n < 0 {
			flush()
			return
		}
		if n == 0 {
			continue
		}
		switch message[0] {
		case 0:
			payload := message[1:n]
			if len(batch)+len(payload) > cap(batch) && !flush() {
				return
			}
			batch = append(batch, payload...)
		case 1:
			if !flush() {
				return
			}
			_ = flow.conn.CloseWrite()
		default:
			flush()
			_ = flow.conn.Close()
			return
		}
	}
}

func (r *tcpRelay) update(now time.Time) {
	for id, flow := range r.flows {
		if r.listener && !flow.opened && now.Sub(flow.lastOpen) >= 500*time.Millisecond {
			r.send(protocol.RelayFrame{Type: protocol.RelayTCPOpen, FlowID: id})
			flow.lastOpen = now
		}
		flow.kcp.Update()
		r.maybeReleaseReader(flow, tcpSendLowWater)
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
	for id, flow := range r.flows {
		if now.Sub(flow.last) <= r.cfg.IdleTimeout {
			continue
		}
		releaseTCPReader(flow)
		_ = flow.conn.Close()
		delete(r.flows, id)
	}
}
