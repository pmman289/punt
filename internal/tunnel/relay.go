package tunnel

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/pmman289/punt/internal/protocol"
)

// RelayProtocol describes the local application protocol accepted by Punt.
// UDP is intentionally datagram-preserving; it does not add retransmission.
type RelayProtocol string

const (
	RelayUDP RelayProtocol = "udp"
	RelayTCP RelayProtocol = "tcp"
)

// RelayConfig is an explicit, single-target port forwarding policy. ListenSide
// selects which underlay role accepts local application traffic; the opposite
// side connects only to Target.
type RelayConfig struct {
	Protocol    RelayProtocol
	ListenSide  Mode
	Listen      *net.UDPAddr
	Target      *net.UDPAddr
	IdleTimeout time.Duration
	MaxPayload  int
	TCPNoCwnd   bool
}

type relayFlow struct {
	local  *net.UDPAddr
	target *net.UDPConn
	last   time.Time
}

type udpRelay struct {
	cfg    RelayConfig
	listen *net.UDPConn
	flows  map[uint32]*relayFlow
	byAddr map[string]uint32
	events chan<- event
}

func validateRelayConfig(mode Mode, cfg *RelayConfig) error {
	if cfg == nil {
		return nil
	}
	if cfg.Protocol != RelayUDP && cfg.Protocol != RelayTCP {
		return errors.New("relay protocol must be udp or tcp")
	}
	if cfg.Protocol != RelayTCP && cfg.TCPNoCwnd {
		return errors.New("tcp_nocwnd is valid only for TCP relay")
	}
	if cfg.ListenSide == "" {
		cfg.ListenSide = Client
	}
	if cfg.ListenSide != Client && cfg.ListenSide != Server {
		return errors.New("relay listen side must be client or server")
	}
	if cfg.IdleTimeout <= 0 {
		return errors.New("relay idle timeout must be positive")
	}
	maxPayload := relayPayloadLimit(*cfg)
	if cfg.Protocol == RelayUDP && maxPayload < 1 {
		return errors.New("UDP relay payload limit must be positive")
	}
	if cfg.Protocol == RelayTCP && maxPayload < 50 {
		return errors.New("TCP relay payload limit must be at least 50 bytes")
	}
	if mode == cfg.ListenSide {
		if cfg.Listen == nil || cfg.Listen.IP.To4() == nil || cfg.Listen.Port < 1 || cfg.Target != nil {
			return errors.New("relay listener side requires IPv4 listen and no target")
		}
	} else if cfg.Target == nil || cfg.Target.IP.To4() == nil || cfg.Target.Port < 1 || cfg.Listen != nil {
		return errors.New("relay target side requires IPv4 target and no listen")
	}
	return nil
}

func relayListenSide(cfg RelayConfig) Mode {
	if cfg.ListenSide == "" {
		return Client
	}
	return cfg.ListenSide
}

func relayPayloadLimit(cfg RelayConfig) int {
	if cfg.MaxPayload <= 0 || cfg.MaxPayload > protocol.MaxRelayPayload {
		return protocol.MaxRelayPayload
	}
	return cfg.MaxPayload
}

func startUDPRelay(ctx context.Context, mode Mode, cfg RelayConfig, events chan<- event) (*udpRelay, error) {
	r := &udpRelay{cfg: cfg, flows: make(map[uint32]*relayFlow), byAddr: make(map[string]uint32), events: events}
	if mode != relayListenSide(cfg) {
		return r, nil
	}
	conn, err := net.ListenUDP("udp4", cfg.Listen)
	if err != nil {
		return nil, err
	}
	r.listen = conn
	go r.readClient(ctx)
	return r, nil
}

func (r *udpRelay) Close() error {
	if r.listen != nil {
		_ = r.listen.Close()
	}
	r.reset()
	return nil
}

func (r *udpRelay) reset() {
	for _, flow := range r.flows {
		if flow.target != nil {
			_ = flow.target.Close()
		}
	}
	r.flows = make(map[uint32]*relayFlow)
	r.byAddr = make(map[string]uint32)
}

func (r *udpRelay) readClient(ctx context.Context) {
	for {
		buf := make([]byte, relayPayloadLimit(r.cfg))
		n, _, flags, addr, err := r.listen.ReadMsgUDP(buf, nil)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}
		if flags&syscall.MSG_TRUNC != 0 {
			select {
			case r.events <- event{type_: relayDropEvent}:
			case <-ctx.Done():
				return
			}
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		select {
		case r.events <- event{type_: relayClientEvent, data: payload, addr: addr}:
		case <-ctx.Done():
			return
		}
	}
}

func (r *udpRelay) readTarget(ctx context.Context, id uint32, conn *net.UDPConn) {
	for {
		buf := make([]byte, relayPayloadLimit(r.cfg))
		n, _, flags, _, err := conn.ReadMsgUDP(buf, nil)
		if err != nil {
			return
		}
		if flags&syscall.MSG_TRUNC != 0 {
			select {
			case r.events <- event{type_: relayDropEvent}:
			case <-ctx.Done():
				return
			}
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		select {
		case r.events <- event{type_: relayTargetEvent, flowID: id, data: payload}:
		case <-ctx.Done():
			return
		}
	}
}

func (r *udpRelay) listenerFrame(payload []byte, sender *net.UDPAddr, now time.Time) (protocol.RelayFrame, error) {
	id, ok := r.byAddr[sender.String()]
	if !ok {
		id = uint32(randomUint64())
		if id == 0 {
			id = 1
		}
		for r.flows[id] != nil {
			id++
			if id == 0 {
				id = 1
			}
		}
		r.byAddr[sender.String()] = id
		r.flows[id] = &relayFlow{local: cloneAddr(sender)}
	}
	r.flows[id].last = now
	return protocol.RelayFrame{Type: protocol.RelayUDP, FlowID: id, Payload: payload}, nil
}

func (r *udpRelay) handleRemote(ctx context.Context, frame protocol.RelayFrame, now time.Time) error {
	if frame.Type != protocol.RelayUDP {
		return errors.New("unexpected UDP relay frame")
	}
	if r.listen != nil {
		flow := r.flows[frame.FlowID]
		if flow == nil || r.listen == nil {
			return errors.New("unknown UDP relay flow")
		}
		flow.last = now
		_, err := r.listen.WriteToUDP(frame.Payload, flow.local)
		return err
	}
	flow := r.flows[frame.FlowID]
	if flow == nil {
		conn, err := net.DialUDP("udp4", nil, r.cfg.Target)
		if err != nil {
			return err
		}
		flow = &relayFlow{target: conn}
		r.flows[frame.FlowID] = flow
		go r.readTarget(ctx, frame.FlowID, conn)
	}
	flow.last = now
	_, err := flow.target.Write(frame.Payload)
	return err
}

func (r *udpRelay) expire(now time.Time) {
	for id, flow := range r.flows {
		if now.Sub(flow.last) <= r.cfg.IdleTimeout {
			continue
		}
		if flow.target != nil {
			_ = flow.target.Close()
		}
		if flow.local != nil {
			delete(r.byAddr, flow.local.String())
		}
		delete(r.flows, id)
	}
}
