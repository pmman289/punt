package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/pmman289/punt/internal/protocol"
)

type Mode string

const (
	Client Mode = "client"
	Server Mode = "server"
)

type DataCarrier string

const (
	CarrierICMP DataCarrier = "icmp"
	CarrierUDP  DataCarrier = "udp"
)

type Config struct {
	Mode         Mode
	Network      *net.UDPAddr // Public-facing local IPv4 address and UDP port.
	Peer         *net.UDPAddr // Required only in client mode.
	Local        *net.UDPAddr // Wrapper endpoint WireGuard sends to.
	WireGuard    *net.UDPAddr // WireGuard ListenPort endpoint.
	Relay        *RelayConfig // Optional explicit local application relay.
	Key          []byte
	Keepalive    time.Duration
	DeadTimeout  time.Duration
	MaxPayload   int
	MaxPPS       int
	MaxMegabits  int
	ClientTX     DataCarrier // Data carrier from underlay client to server.
	ServerTX     DataCarrier // Data carrier from underlay server to client.
	StatusSocket string      // Optional absolute Unix socket path for local status queries.
	Logger       *log.Logger
}

// RuntimeStats contains counters suitable for a local orchestration agent.
// Values are cumulative for the lifetime of the Punt process.
type RuntimeStats struct {
	ControlIn    uint64 `json:"control_in"`
	ControlOut   uint64 `json:"control_out"`
	RawIn        uint64 `json:"raw_in"`
	RawOut       uint64 `json:"raw_out"`
	UDPDataIn    uint64 `json:"udp_data_in"`
	UDPDataOut   uint64 `json:"udp_data_out"`
	WireGuardIn  uint64 `json:"wireguard_in"`
	WireGuardOut uint64 `json:"wireguard_out"`
	Dropped      uint64 `json:"dropped"`
	Invalid      uint64 `json:"invalid"`
}

// RuntimeStatus is returned only through the locally permissioned Unix socket.
// It intentionally excludes the shared key and application payloads.
type RuntimeStatus struct {
	Mode          string       `json:"mode"`
	Transport     string       `json:"transport"`
	ListenSide    string       `json:"listen_side,omitempty"`
	State         string       `json:"state"`
	Network       string       `json:"network"`
	Peer          string       `json:"peer,omitempty"`
	Listen        string       `json:"listen,omitempty"`
	Target        string       `json:"target,omitempty"`
	ActiveFlows   int          `json:"active_flows"`
	QueuedRaw     int          `json:"queued_raw"`
	QueuedUDP     int          `json:"queued_udp"`
	ClientTX      string       `json:"client_to_server"`
	ServerTX      string       `json:"server_to_client"`
	TCPNoCwnd     bool         `json:"tcp_nocwnd,omitempty"`
	LearnedRemote string       `json:"learned_remote,omitempty"`
	StartedAt     time.Time    `json:"started_at"`
	LastHelloAt   *time.Time   `json:"last_hello_at,omitempty"`
	LastAckAt     *time.Time   `json:"last_ack_at,omitempty"`
	LastRawAt     *time.Time   `json:"last_raw_at,omitempty"`
	Stats         RuntimeStats `json:"stats"`
}

type state uint8

const (
	udpProbing state = iota
	icmpProbing
	established
)

func (s state) String() string {
	switch s {
	case udpProbing:
		return "UDP_PROBING"
	case icmpProbing:
		return "ICMP_PROBING"
	case established:
		return "ESTABLISHED"
	default:
		return "UNKNOWN"
	}
}

type stats struct {
	controlIn, controlOut uint64
	rawIn, rawOut         uint64
	udpDataIn, udpDataOut uint64
	wgIn, wgOut           uint64
	dropped, invalid      uint64
}

type eventType uint8

const (
	controlEvent eventType = iota
	rawEvent
	wireGuardEvent
	statusEvent
	relayClientEvent
	relayTargetEvent
	relayTCPAcceptEvent
	relayTCPClientEvent
	relayTCPTargetEvent
	relayTCPConnectedEvent
	relayDropEvent
	errEvent
)

type event struct {
	type_          eventType
	data           []byte
	addr           *net.UDPAddr
	err            error
	statusResponse chan<- RuntimeStatus
	flowID         uint32
	conn           *net.TCPConn
	eof            bool
	ready          chan struct{}
}

type limiter struct {
	packets, bytes float64
	last           time.Time
	packetRate     float64
	byteRate       float64
	packetBurst    float64
	byteBurst      float64
}

func newLimiter(pps, megabits int) limiter {
	packetRate := float64(pps)
	byteRate := float64(megabits) * 1000 * 1000 / 8
	return limiter{
		packets: packetRate / 10, bytes: byteRate / 10, last: time.Now(),
		packetRate: packetRate, byteRate: byteRate,
		packetBurst: maxFloat(1, packetRate/10), byteBurst: maxFloat(float64(maxIPPacket), byteRate/10),
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (l *limiter) allow(now time.Time, size int) bool {
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.packets = minFloat(l.packetBurst, l.packets+elapsed*l.packetRate)
	l.bytes = minFloat(l.byteBurst, l.bytes+elapsed*l.byteRate)
	if l.packets < 1 || l.bytes < float64(size) {
		return false
	}
	l.packets--
	l.bytes -= float64(size)
	return true
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

type engine struct {
	cfg     Config
	control *net.UDPConn
	local   *net.UDPConn
	raw     *rawSocket

	state         state
	remote        *net.UDPAddr
	clientSession uint64
	serverSession uint64
	nonce         uint64
	expectedProbe []byte
	sequence      uint32
	packetID      uint16
	lastHello     time.Time
	lastAck       time.Time
	lastProbe     time.Time
	lastRaw       time.Time
	lastStats     time.Time
	startedAt     time.Time
	limiter       limiter
	stats         stats
	udpRelay      *udpRelay
	tcpRelay      *tcpRelay
	rawQueue      []queuedRaw
	udpQueue      []queuedUDP
}

const maxReliableCarrierQueue = 256

type queuedRaw struct {
	packet      []byte
	destination Tuple
}

type queuedUDP struct {
	packet      []byte
	destination *net.UDPAddr
}

func ValidateConfig(cfg Config) error {
	if cfg.Mode != Client && cfg.Mode != Server {
		return errors.New("mode must be client or server")
	}
	if cfg.Network == nil || cfg.Network.IP.To4() == nil || cfg.Network.Port < 1 {
		return errors.New("network must be an IPv4 address with a UDP port")
	}
	if cfg.Mode == Client && (cfg.Peer == nil || cfg.Peer.IP.To4() == nil || cfg.Peer.Port < 1) {
		return errors.New("client mode requires an IPv4 peer address and UDP port")
	}
	if cfg.Relay == nil && (cfg.Local == nil || !cfg.Local.IP.IsLoopback() || cfg.Local.Port < 1 || cfg.WireGuard == nil || !cfg.WireGuard.IP.IsLoopback() || cfg.WireGuard.Port < 1) {
		return errors.New("local and wireguard endpoints must be loopback UDP addresses with ports")
	}
	if err := validateRelayConfig(cfg.Mode, cfg.Relay); err != nil {
		return err
	}
	if len(cfg.Key) != 16 {
		return errors.New("key must be exactly 16 bytes")
	}
	if cfg.Keepalive <= 0 || cfg.DeadTimeout < cfg.Keepalive*2 {
		return errors.New("dead timeout must be at least twice the keepalive interval")
	}
	if cfg.MaxPayload < 1 || cfg.MaxPayload > protocol.MaxPayload || cfg.MaxPPS < 1 || cfg.MaxMegabits < 1 {
		return errors.New("invalid payload, PPS, or bandwidth limit")
	}
	if !validCarrier(cfg.ClientTX) || !validCarrier(cfg.ServerTX) {
		return errors.New("client and server transmit carriers must be icmp or udp")
	}
	if cfg.Relay != nil && cfg.MaxPayload <= protocol.RelayHeaderSize {
		return errors.New("relay max payload is too small for its frame header")
	}
	if cfg.Relay != nil && cfg.Relay.Protocol == RelayTCP && cfg.MaxPayload-protocol.RelayHeaderSize < 50 {
		return errors.New("TCP relay max payload must leave at least 50 bytes for KCP")
	}
	if cfg.StatusSocket != "" && !filepath.IsAbs(cfg.StatusSocket) {
		return errors.New("status socket path must be absolute")
	}
	return nil
}

func Run(ctx context.Context, cfg Config) error {
	cfg.ClientTX = carrierOrDefault(cfg.ClientTX)
	cfg.ServerTX = carrierOrDefault(cfg.ServerTX)
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	control, err := net.ListenUDP("udp4", cfg.Network)
	if err != nil {
		return fmt.Errorf("bind network UDP %s: %w", cfg.Network, err)
	}
	defer control.Close()
	var local *net.UDPConn
	if cfg.Relay == nil {
		local, err = net.ListenUDP("udp4", cfg.Local)
		if err != nil {
			return fmt.Errorf("bind local WireGuard endpoint %s: %w", cfg.Local, err)
		}
		defer local.Close()
	}
	var raw *rawSocket
	if configUsesICMP(cfg) {
		raw, err = openRawSocket()
		if err != nil {
			return err
		}
		defer raw.Close()
	}

	now := time.Now()
	e := &engine{cfg: cfg, control: control, local: local, raw: raw, state: udpProbing, limiter: newLimiter(cfg.MaxPPS, cfg.MaxMegabits), startedAt: now, lastStats: now}
	if cfg.Mode == Client {
		e.remote = cloneAddr(cfg.Peer)
		e.clientSession = randomUint64()
	}
	e.logf("started mode=%s network=%s", cfg.Mode, cfg.Network)

	events := make(chan event, 1024)
	var statusServer *statusServer
	if cfg.StatusSocket != "" {
		statusServer, err = startStatusServer(ctx, cfg.StatusSocket, events)
		if err != nil {
			return fmt.Errorf("start status socket: %w", err)
		}
		defer statusServer.Close()
	}
	go readUDP(control, controlEvent, events)
	if cfg.Relay == nil {
		go readUDP(local, wireGuardEvent, events)
	} else if cfg.Relay.Protocol == RelayUDP {
		relayCfg := *cfg.Relay
		relayCfg.MaxPayload = cfg.MaxPayload - protocol.RelayHeaderSize
		relay, err := startUDPRelay(ctx, cfg.Mode, relayCfg, events)
		if err != nil {
			return fmt.Errorf("start UDP relay: %w", err)
		}
		e.udpRelay = relay
		defer relay.Close()
	} else {
		relayCfg := *cfg.Relay
		relayCfg.MaxPayload = cfg.MaxPayload - protocol.RelayHeaderSize
		relay, err := startTCPRelay(ctx, cfg.Mode, relayCfg, events, e.sendRelay)
		if err != nil {
			return fmt.Errorf("start TCP relay: %w", err)
		}
		e.tcpRelay = relay
		defer relay.Close()
	}
	if raw != nil {
		go readRaw(raw, events)
	}
	if cfg.Mode == Client {
		e.sendHello(time.Now())
	}

	tickInterval := 250 * time.Millisecond
	if cfg.Relay != nil && cfg.Relay.Protocol == RelayTCP {
		tickInterval = 10 * time.Millisecond
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.logf("stopped: control in/out=%d/%d raw in/out=%d/%d udp data in/out=%d/%d wg in/out=%d/%d dropped=%d invalid=%d", e.stats.controlIn, e.stats.controlOut, e.stats.rawIn, e.stats.rawOut, e.stats.udpDataIn, e.stats.udpDataOut, e.stats.wgIn, e.stats.wgOut, e.stats.dropped, e.stats.invalid)
			return nil
		case ev := <-events:
			e.handleEvent(ev)
		case now := <-ticker.C:
			e.tick(now)
		}
	}
}

func readUDP(conn *net.UDPConn, kind eventType, out chan<- event) {
	for {
		buf := make([]byte, 2048)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A Port Unreachable can be surfaced as ECONNREFUSED by Linux on
			// a UDP socket. The control socket is deliberately unconnected, and
			// that asynchronous error must not tear down its receive loop.
			continue
		}
		out <- event{type_: kind, data: buf[:n], addr: addr}
	}
}

func readRaw(raw *rawSocket, out chan<- event) {
	for {
		buf := make([]byte, maxIPPacket+64)
		n, err := raw.Receive(buf)
		if err != nil {
			out <- event{type_: errEvent, err: err}
			return
		}
		out <- event{type_: rawEvent, data: buf[:n]}
	}
}

func (e *engine) handleEvent(ev event) {
	switch ev.type_ {
	case controlEvent:
		e.handleUDP(ev.data, ev.addr)
	case rawEvent:
		e.handleRaw(ev.data)
	case wireGuardEvent:
		e.handleWireGuard(ev.data, ev.addr)
	case relayClientEvent:
		e.handleRelayClient(ev.data, ev.addr)
	case relayTargetEvent:
		e.handleRelayTarget(ev.flowID, ev.data)
	case relayTCPAcceptEvent:
		e.handleTCPAccept(ev.conn)
	case relayTCPClientEvent:
		e.handleTCPClient(ev.flowID, ev.data, ev.eof, ev.ready)
	case relayTCPTargetEvent:
		e.handleTCPTarget(ev.flowID, ev.data, ev.eof, ev.ready)
	case relayTCPConnectedEvent:
		e.handleTCPConnected(ev.flowID, ev.conn, ev.err)
	case relayDropEvent:
		e.stats.dropped++
	case statusEvent:
		ev.statusResponse <- e.runtimeStatus()
	case errEvent:
		// Closing sockets during shutdown also reaches readers; the context path
		// exits the engine and no state is reset for transient UDP errors.
		if !errors.Is(ev.err, net.ErrClosed) {
			e.logf("socket receive error: %v", ev.err)
		}
	}
}

func (e *engine) runtimeStatus() RuntimeStatus {
	status := RuntimeStatus{
		Mode: string(e.cfg.Mode), State: e.state.String(), Network: e.cfg.Network.String(),
		ClientTX: string(carrierOrDefault(e.cfg.ClientTX)), ServerTX: string(carrierOrDefault(e.cfg.ServerTX)),
		Peer: formatAddr(e.cfg.Peer), LearnedRemote: formatAddr(e.remote), StartedAt: e.startedAt,
		LastHelloAt: timePointer(e.lastHello), LastAckAt: timePointer(e.lastAck), LastRawAt: timePointer(e.lastRaw),
		Stats: RuntimeStats{
			ControlIn: e.stats.controlIn, ControlOut: e.stats.controlOut,
			RawIn: e.stats.rawIn, RawOut: e.stats.rawOut,
			UDPDataIn: e.stats.udpDataIn, UDPDataOut: e.stats.udpDataOut,
			WireGuardIn: e.stats.wgIn, WireGuardOut: e.stats.wgOut,
			Dropped: e.stats.dropped, Invalid: e.stats.invalid,
		},
	}
	status.QueuedRaw = len(e.rawQueue)
	status.QueuedUDP = len(e.udpQueue)
	if e.cfg.Relay == nil {
		status.Transport = "wireguard"
		return status
	}
	status.Transport = string(e.cfg.Relay.Protocol)
	status.ListenSide = string(relayListenSide(*e.cfg.Relay))
	status.TCPNoCwnd = e.cfg.Relay.TCPNoCwnd
	status.Listen = formatAddr(e.cfg.Relay.Listen)
	status.Target = formatAddr(e.cfg.Relay.Target)
	if e.udpRelay != nil {
		status.ActiveFlows = len(e.udpRelay.flows)
	}
	if e.tcpRelay != nil {
		status.ActiveFlows = len(e.tcpRelay.flows)
	}
	return status
}

func (e *engine) handleUDP(packet []byte, sender *net.UDPAddr) {
	switch protocol.ClassifyEnvelope(packet) {
	case protocol.ControlEnvelope:
		e.handleControl(packet, sender)
	case protocol.DataEnvelope:
		e.handleUDPData(packet, sender)
	default:
		e.stats.invalid++
	}
}

func formatAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func (e *engine) handleControl(packet []byte, sender *net.UDPAddr) {
	m, err := protocol.ParseControl(packet, e.cfg.Key)
	if err != nil {
		e.stats.invalid++
		return
	}
	if sender.IP.To4() == nil {
		e.stats.invalid++
		return
	}
	e.stats.controlIn++
	now := time.Now()
	if e.cfg.Mode == Server {
		if m.Type != protocol.Hello || m.ClientSession == 0 {
			e.stats.invalid++
			return
		}
		if e.remote == nil || e.clientSession != m.ClientSession || !sameAddr(e.remote, sender) {
			e.resetRelays()
			e.remote = cloneAddr(sender)
			e.clientSession = m.ClientSession
			e.serverSession = randomUint64()
			e.state = udpProbing
			e.logf("learned UDP NAT tuple %s", e.remote)
		}
		e.lastHello = now
		e.sendHelloAck(m.Nonce)
		return
	}

	if m.Type != protocol.HelloAck || !sameAddr(sender, e.cfg.Peer) || m.ClientSession != e.clientSession || m.Nonce != e.nonce || m.ServerSession == 0 || m.ObservedPort == 0 {
		e.stats.invalid++
		return
	}
	newSession := e.serverSession != m.ServerSession
	if e.serverSession != 0 && newSession {
		e.resetRelays()
	}
	e.serverSession = m.ServerSession
	e.lastAck = now
	if newSession || e.state == udpProbing {
		e.transition(icmpProbing)
		e.sendProbe()
	}
}

func (e *engine) handleRaw(packet []byte) {
	if e.remoteCarrier() != CarrierICMP {
		e.stats.invalid++
		return
	}
	if e.remote == nil || e.serverSession == 0 {
		e.stats.invalid++
		return
	}
	localTuple := Tuple{IP: e.cfg.Network.IP, Port: e.cfg.Network.Port}
	remoteTuple := Tuple{IP: e.remote.IP, Port: e.remote.Port}
	payload, err := ParsePortUnreachable(packet, remoteTuple, localTuple, localTuple, remoteTuple)
	if err != nil {
		e.stats.invalid++
		return
	}
	if !e.handleDataEnvelope(payload) {
		e.stats.invalid++
		return
	}
	e.stats.rawIn++
	e.lastRaw = time.Now()

}

func (e *engine) handleUDPData(packet []byte, sender *net.UDPAddr) {
	if e.remote == nil || e.serverSession == 0 || e.remoteCarrier() != CarrierUDP || !sameAddr(sender, e.remote) {
		e.stats.invalid++
		return
	}
	if !e.handleDataEnvelope(packet) {
		e.stats.invalid++
		return
	}
	e.stats.udpDataIn++
}

func (e *engine) handleDataEnvelope(packet []byte) bool {
	m, err := protocol.ParseData(packet, e.cfg.Key)
	if err != nil || m.Session != e.serverSession {
		return false
	}
	return e.handleDataMessage(m)
}

func (e *engine) handleDataMessage(m protocol.Data) bool {
	switch m.Type {
	case protocol.Probe:
		if e.cfg.Mode == Server && e.validProbePayload(m.Payload) {
			e.sendData(protocol.ProbeAck, m.Payload)
			return true
		}
	case protocol.ProbeAck:
		if e.cfg.Mode == Client && string(m.Payload) == string(e.expectedProbe) {
			e.transition(established)
			e.sendData(protocol.ProbeConfirm, m.Payload)
			return true
		}
	case protocol.ProbeConfirm:
		if e.cfg.Mode == Server && e.validProbePayload(m.Payload) {
			e.transition(established)
			return true
		}
	case protocol.Packet:
		if e.state != established {
			e.stats.dropped++
			return true
		}
		if e.udpRelay != nil || e.tcpRelay != nil {
			frame, err := protocol.ParseRelayFrame(m.Payload)
			if err != nil {
				e.stats.invalid++
				return true
			}
			e.handleRelayFrame(frame)
			return true
		}
		if _, err := e.local.WriteToUDP(m.Payload, e.cfg.WireGuard); err != nil {
			e.logf("deliver to WireGuard: %v", err)
			e.stats.dropped++
			return true
		}
		e.stats.wgOut++
		return true
	}
	return false
}

func (e *engine) handleWireGuard(payload []byte, sender *net.UDPAddr) {
	if !sameAddr(sender, e.cfg.WireGuard) {
		e.stats.invalid++
		return
	}
	e.stats.wgIn++
	if e.state != established || len(payload) > e.cfg.MaxPayload {
		e.stats.dropped++
		return
	}
	e.sendData(protocol.Packet, payload)
}

func (e *engine) handleRelayClient(payload []byte, sender *net.UDPAddr) {
	if e.udpRelay == nil || e.state != established {
		e.stats.dropped++
		return
	}
	frame, err := e.udpRelay.listenerFrame(payload, sender, time.Now())
	if err != nil {
		e.stats.dropped++
		return
	}
	e.sendRelay(frame)
}

func (e *engine) handleRelayTarget(flowID uint32, payload []byte) {
	if e.udpRelay == nil || e.state != established {
		e.stats.dropped++
		return
	}
	e.sendRelay(protocol.RelayFrame{Type: protocol.RelayUDP, FlowID: flowID, Payload: payload})
}

func (e *engine) handleRelayFrame(frame protocol.RelayFrame) {
	if e.state != established {
		e.stats.dropped++
		return
	}
	if e.udpRelay != nil {
		if err := e.udpRelay.handleRemote(context.Background(), frame, time.Now()); err != nil {
			e.stats.invalid++
		}
		return
	}
	if e.tcpRelay != nil {
		if err := e.tcpRelay.handleFrame(frame, time.Now()); err != nil {
			e.stats.invalid++
		}
		return
	}
	e.stats.invalid++
}

func (e *engine) sendRelay(frame protocol.RelayFrame) {
	payload, err := frame.Marshal()
	if err != nil {
		e.stats.dropped++
		return
	}
	if len(payload) > e.cfg.MaxPayload {
		e.stats.dropped++
		return
	}
	reliable := frame.Type != protocol.RelayUDP
	e.sendDataWithQueue(protocol.Packet, payload, reliable)
}

func (e *engine) handleTCPAccept(conn *net.TCPConn) {
	if e.tcpRelay == nil || e.state != established {
		_ = conn.Close()
		return
	}
	e.tcpRelay.acceptLocal(conn, time.Now())
}

func (e *engine) handleTCPClient(flowID uint32, payload []byte, eof bool, ready chan struct{}) {
	if e.tcpRelay == nil {
		if ready != nil {
			close(ready)
		}
		return
	}
	e.tcpRelay.localData(flowID, payload, eof, ready, time.Now())
}

func (e *engine) handleTCPTarget(flowID uint32, payload []byte, eof bool, ready chan struct{}) {
	if e.tcpRelay == nil {
		if ready != nil {
			close(ready)
		}
		return
	}
	e.tcpRelay.localData(flowID, payload, eof, ready, time.Now())
}

func (e *engine) handleTCPConnected(flowID uint32, conn *net.TCPConn, err error) {
	if e.tcpRelay == nil || e.state != established {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	e.tcpRelay.targetConnected(flowID, conn, err, time.Now())
}

func (e *engine) sendHello(now time.Time) {
	if e.cfg.Mode != Client {
		return
	}
	e.nonce = randomUint64()
	m := protocol.Control{Type: protocol.Hello, ClientSession: e.clientSession, Nonce: e.nonce, Timestamp: uint64(now.Unix())}
	b, _ := m.Marshal(e.cfg.Key)
	if _, err := e.control.WriteToUDP(b, e.cfg.Peer); err != nil {
		e.logf("send HELLO: %v", err)
		return
	}
	e.lastHello = now
	e.stats.controlOut++
}

func (e *engine) sendHelloAck(nonce uint64) {
	if e.remote == nil {
		return
	}
	m := protocol.Control{Type: protocol.HelloAck, ClientSession: e.clientSession, ServerSession: e.serverSession, Nonce: nonce, Timestamp: uint64(time.Now().Unix()), ObservedPort: uint16(e.remote.Port)}
	b, _ := m.Marshal(e.cfg.Key)
	if _, err := e.control.WriteToUDP(b, e.remote); err != nil {
		e.logf("send HELLO_ACK: %v", err)
		return
	}
	e.stats.controlOut++
}

func (e *engine) sendProbe() {
	if e.remote == nil || e.serverSession == 0 {
		return
	}
	e.expectedProbe = e.newProbePayload()
	e.lastProbe = time.Now()
	e.sendData(protocol.Probe, e.expectedProbe)
}

func (e *engine) sendData(kind protocol.DataType, payload []byte) {
	e.sendDataWithQueue(kind, payload, false)
}

func (e *engine) sendDataWithQueue(kind protocol.DataType, payload []byte, reliable bool) {
	if e.remote == nil || e.serverSession == 0 {
		return
	}
	e.sequence++
	m := protocol.Data{Type: kind, Session: e.serverSession, Sequence: e.sequence, Payload: payload}
	b, err := m.Marshal(e.cfg.Key)
	if err != nil {
		e.stats.dropped++
		return
	}
	if e.localCarrier() == CarrierUDP {
		e.sendUDPData(b, reliable)
		return
	}
	e.sendICMPData(b, reliable)
}

func (e *engine) sendICMPData(b []byte, reliable bool) {
	e.packetID++
	localTuple := Tuple{IP: e.cfg.Network.IP, Port: e.cfg.Network.Port}
	remoteTuple := Tuple{IP: e.remote.IP, Port: e.remote.Port}
	p, err := BuildPortUnreachable(localTuple, remoteTuple, remoteTuple, localTuple, b, e.packetID)
	if err != nil {
		e.logf("build ICMP: %v", err)
		e.stats.dropped++
		return
	}
	if reliable && len(e.rawQueue) > 0 {
		e.enqueueRaw(p, remoteTuple)
		return
	}
	if !e.limiter.allow(time.Now(), len(p)) {
		if reliable {
			e.enqueueRaw(p, remoteTuple)
			return
		}
		e.stats.dropped++
		return
	}
	if err := e.raw.Send(p, remoteTuple); err != nil {
		e.logf("send ICMP: %v", err)
		e.stats.dropped++
		return
	}
	e.stats.rawOut++
}

func (e *engine) sendUDPData(packet []byte, reliable bool) {
	if reliable && len(e.udpQueue) > 0 {
		e.enqueueUDP(packet, e.remote)
		return
	}
	if !e.limiter.allow(time.Now(), len(packet)+ipv4HeaderLen+udpHeaderLen) {
		if reliable {
			e.enqueueUDP(packet, e.remote)
			return
		}
		e.stats.dropped++
		return
	}
	if _, err := e.control.WriteToUDP(packet, e.remote); err != nil {
		e.logf("send UDP data: %v", err)
		e.stats.dropped++
		return
	}
	e.stats.udpDataOut++
}

func (e *engine) enqueueRaw(packet []byte, destination Tuple) {
	if len(e.rawQueue) >= maxReliableCarrierQueue {
		e.stats.dropped++
		return
	}
	e.rawQueue = append(e.rawQueue, queuedRaw{packet: packet, destination: destination})
}

func (e *engine) enqueueUDP(packet []byte, destination *net.UDPAddr) {
	if len(e.udpQueue) >= maxReliableCarrierQueue {
		e.stats.dropped++
		return
	}
	e.udpQueue = append(e.udpQueue, queuedUDP{packet: packet, destination: cloneAddr(destination)})
}

func (e *engine) flushRawQueue(now time.Time) {
	for len(e.rawQueue) > 0 {
		next := e.rawQueue[0]
		if !e.limiter.allow(now, len(next.packet)) {
			return
		}
		e.rawQueue[0] = queuedRaw{}
		e.rawQueue = e.rawQueue[1:]
		if err := e.raw.Send(next.packet, next.destination); err != nil {
			e.logf("send queued ICMP: %v", err)
			e.stats.dropped++
			continue
		}
		e.stats.rawOut++
	}
}

func (e *engine) flushUDPQueue(now time.Time) {
	for len(e.udpQueue) > 0 {
		next := e.udpQueue[0]
		if !e.limiter.allow(now, len(next.packet)+ipv4HeaderLen+udpHeaderLen) {
			return
		}
		e.udpQueue[0] = queuedUDP{}
		e.udpQueue = e.udpQueue[1:]
		if _, err := e.control.WriteToUDP(next.packet, next.destination); err != nil {
			e.logf("send queued UDP data: %v", err)
			e.stats.dropped++
			continue
		}
		e.stats.udpDataOut++
	}
}

func (e *engine) tick(now time.Time) {
	e.flushRawQueue(now)
	e.flushUDPQueue(now)
	if e.cfg.Mode == Client {
		if now.Sub(e.lastHello) >= e.cfg.Keepalive {
			e.sendHello(now)
		}
		if !e.lastAck.IsZero() && now.Sub(e.lastAck) > e.cfg.DeadTimeout {
			e.resetRelays()
			e.transition(udpProbing)
			e.serverSession = 0
			e.expectedProbe = nil
		}
		if e.state == established && now.Sub(e.lastProbe) >= e.cfg.Keepalive*2 {
			e.sendProbe()
		}
	} else if e.remote != nil && now.Sub(e.lastHello) > e.cfg.DeadTimeout {
		e.logf("UDP NAT tuple expired: %s", e.remote)
		e.remote = nil
		e.serverSession = 0
		e.resetRelays()
		e.transition(udpProbing)
	}
	if now.Sub(e.lastStats) >= 10*time.Second {
		e.logf("state=%s control in/out=%d/%d raw in/out=%d/%d udp data in/out=%d/%d wg in/out=%d/%d dropped=%d invalid=%d", e.state, e.stats.controlIn, e.stats.controlOut, e.stats.rawIn, e.stats.rawOut, e.stats.udpDataIn, e.stats.udpDataOut, e.stats.wgIn, e.stats.wgOut, e.stats.dropped, e.stats.invalid)
		e.lastStats = now
	}
	if e.udpRelay != nil {
		e.udpRelay.expire(now)
	}
	if e.tcpRelay != nil {
		e.tcpRelay.update(now)
		e.tcpRelay.expire(now)
	}
}

func (e *engine) resetRelays() {
	e.rawQueue = nil
	e.udpQueue = nil
	if e.udpRelay != nil {
		e.udpRelay.reset()
	}
	if e.tcpRelay != nil {
		e.tcpRelay.reset()
	}
}

func validCarrier(carrier DataCarrier) bool {
	return carrier == "" || carrier == CarrierICMP || carrier == CarrierUDP
}

func carrierOrDefault(carrier DataCarrier) DataCarrier {
	if carrier == "" {
		return CarrierICMP
	}
	return carrier
}

func configUsesICMP(cfg Config) bool {
	return carrierOrDefault(cfg.ClientTX) == CarrierICMP || carrierOrDefault(cfg.ServerTX) == CarrierICMP
}

func (e *engine) localCarrier() DataCarrier {
	if e.cfg.Mode == Client {
		return carrierOrDefault(e.cfg.ClientTX)
	}
	return carrierOrDefault(e.cfg.ServerTX)
}

func (e *engine) remoteCarrier() DataCarrier {
	if e.cfg.Mode == Client {
		return carrierOrDefault(e.cfg.ServerTX)
	}
	return carrierOrDefault(e.cfg.ClientTX)
}

const carrierProbeMarker = "PUC1"

func carrierCode(carrier DataCarrier) byte {
	if carrierOrDefault(carrier) == CarrierUDP {
		return 2
	}
	return 1
}

func (e *engine) newProbePayload() []byte {
	if carrierOrDefault(e.cfg.ClientTX) == CarrierICMP && carrierOrDefault(e.cfg.ServerTX) == CarrierICMP {
		payload := make([]byte, 8)
		_, _ = rand.Read(payload)
		return payload
	}
	payload := make([]byte, 16)
	copy(payload[:4], carrierProbeMarker)
	payload[4] = carrierCode(e.cfg.ClientTX)
	payload[5] = carrierCode(e.cfg.ServerTX)
	_, _ = rand.Read(payload[8:])
	return payload
}

func (e *engine) validProbePayload(payload []byte) bool {
	if carrierOrDefault(e.cfg.ClientTX) == CarrierICMP && carrierOrDefault(e.cfg.ServerTX) == CarrierICMP {
		return len(payload) == 8
	}
	return len(payload) == 16 && string(payload[:4]) == carrierProbeMarker &&
		payload[4] == carrierCode(e.cfg.ClientTX) && payload[5] == carrierCode(e.cfg.ServerTX) &&
		payload[6] == 0 && payload[7] == 0
}

func (e *engine) transition(next state) {
	if e.state == next {
		return
	}
	e.logf("state %s -> %s", e.state, next)
	e.state = next
}

func (e *engine) logf(format string, args ...any) { e.cfg.Logger.Printf(format, args...) }

func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

func randomUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("cryptographic random source failed: %v", err))
	}
	return binary.BigEndian.Uint64(b[:])
}
