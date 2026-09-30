package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sync"
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
	Mode          Mode
	Network       *net.UDPAddr // Public-facing local IPv4 address and UDP port.
	Peer          *net.UDPAddr // Required only in client mode.
	Local         *net.UDPAddr // Wrapper endpoint WireGuard sends to.
	WireGuard     *net.UDPAddr // WireGuard ListenPort endpoint.
	Relay         *RelayConfig // Optional explicit local application relay.
	Key           []byte
	Keepalive     time.Duration
	DeadTimeout   time.Duration
	TCPFallback   time.Duration // UDP control fallback delay; zero disables TCP control.
	MaxPayload    int
	MaxPPS        int
	MaxMegabits   int
	QueuePackets  int           // reliable carrier queue depth; 0 = 4096
	Burst         time.Duration // token bucket capacity duration; 0 = 100ms
	SocketBuffer  int           // requested UDP/raw socket buffer; 0 = 4 MiB
	ICMPPacingPPS int           // Optional WireGuard-over-ICMP outbound pacing target.
	ClientTX      DataCarrier   // Data carrier from underlay client to server.
	ServerTX      DataCarrier   // Data carrier from underlay server to client.
	StatusSocket  string        // Optional absolute Unix socket path for local status queries.
	Logger        *log.Logger
}

// RuntimeStats contains counters suitable for a local orchestration agent.
// Values are cumulative for the lifetime of the Punt process.
type RuntimeStats struct {
	ControlIn     uint64 `json:"control_in"`
	ControlOut    uint64 `json:"control_out"`
	RawIn         uint64 `json:"raw_in"`
	RawOut        uint64 `json:"raw_out"`
	UDPDataIn     uint64 `json:"udp_data_in"`
	UDPDataOut    uint64 `json:"udp_data_out"`
	WireGuardIn   uint64 `json:"wireguard_in"`
	WireGuardOut  uint64 `json:"wireguard_out"`
	Dropped       uint64 `json:"dropped"`
	Invalid       uint64 `json:"invalid"`
	TxBytes       uint64 `json:"tx_bytes"`
	RxBytes       uint64 `json:"rx_bytes"`
	LimiterQueued uint64 `json:"limiter_queued"`
	LimiterDrops  uint64 `json:"limiter_drops"`
	QueueDrops    uint64 `json:"queue_drops"`
	RelayOversize uint64 `json:"relay_oversize"`
}

// RuntimeStatus is returned only through the locally permissioned Unix socket.
// It intentionally excludes the shared key and application payloads.
type RuntimeStatus struct {
	Mode             string       `json:"mode"`
	Transport        string       `json:"transport"`
	ListenSide       string       `json:"listen_side,omitempty"`
	State            string       `json:"state"`
	Network          string       `json:"network"`
	Peer             string       `json:"peer,omitempty"`
	Listen           string       `json:"listen,omitempty"`
	Target           string       `json:"target,omitempty"`
	ActiveFlows      int          `json:"active_flows"`
	QueuedRaw        int          `json:"queued_raw"`
	QueuedUDP        int          `json:"queued_udp"`
	ClientTX         string       `json:"client_to_server"`
	ServerTX         string       `json:"server_to_client"`
	ICMPPacingPPS    int          `json:"icmp_pacing_pps,omitempty"`
	ControlTransport string       `json:"control_transport,omitempty"`
	TCPNoCwnd        bool         `json:"tcp_nocwnd,omitempty"`
	LearnedRemote    string       `json:"learned_remote,omitempty"`
	StartedAt        time.Time    `json:"started_at"`
	LastHelloAt      *time.Time   `json:"last_hello_at,omitempty"`
	LastAckAt        *time.Time   `json:"last_ack_at,omitempty"`
	LastRawAt        *time.Time   `json:"last_raw_at,omitempty"`
	Stats            RuntimeStats `json:"stats"`
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
	txBytes, rxBytes      uint64
	limiterQueued         uint64
	limiterDrops          uint64
	queueDrops            uint64
	relayOversize         uint64
}

type eventType uint8

const (
	controlEvent eventType = iota
	tcpControlEvent
	tcpControlConnectedEvent
	tcpControlClosedEvent
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
	relayOversizeEvent
	errEvent
)

type event struct {
	type_          eventType
	data           []byte
	addr           *net.UDPAddr
	viaTCP         bool
	err            error
	statusResponse chan<- RuntimeStatus
	flowID         uint32
	conn           *net.TCPConn
	eof            bool
	ready          chan struct{}
	rx             *[]byte
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
	return newLimiterBurst(pps, megabits, 100*time.Millisecond)
}

func newLimiterBurst(pps, megabits int, burst time.Duration) limiter {
	packetRate := float64(pps)
	byteRate := float64(megabits) * 1000 * 1000 / 8
	seconds := burst.Seconds()
	if seconds <= 0 {
		seconds = 0.1
	}
	return limiter{
		packets: packetRate * seconds, bytes: byteRate * seconds, last: time.Now(),
		packetRate: packetRate, byteRate: byteRate,
		packetBurst: maxFloat(1, packetRate*seconds), byteBurst: maxFloat(float64(maxIPPacket), byteRate*seconds),
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
	ctx     context.Context
	events  chan event
	cfg     Config
	control *net.UDPConn
	local   *net.UDPConn
	raw     *rawSocket

	state            state
	remote           *net.UDPAddr
	clientSession    uint64
	serverSession    uint64
	nonce            uint64
	tcpNonce         uint64
	expectedProbe    []byte
	sequence         uint32
	packetID         uint16
	lastHello        time.Time
	lastTCPHello     time.Time
	lastTCPDial      time.Time
	lastAck          time.Time
	lastProbe        time.Time
	lastRaw          time.Time
	lastStats        time.Time
	startedAt        time.Time
	limiter          limiter
	stats            stats
	udpRelay         *udpRelay
	tcpRelay         *tcpRelay
	tcpControl       *net.TCPConn
	tcpDialing       bool
	controlTransport string
	verifier         *protocol.Verifier
	tx               [txBufferSize]byte
	rawQueue         packetQueue
	udpQueue         packetQueue
	queueLimit       int
	highWater        int
}

const maxReliableCarrierQueue = 4096

const maxPacedWireGuardQueue = 4096

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
	if cfg.TCPFallback < 0 {
		return errors.New("TCP fallback delay cannot be negative")
	}
	if cfg.MaxPayload < 1 || cfg.MaxPayload > protocol.MaxPayload || cfg.MaxPPS < 1 || cfg.MaxMegabits < 1 {
		return errors.New("invalid payload, PPS, or bandwidth limit")
	}
	if cfg.QueuePackets < 0 || cfg.SocketBuffer < 0 || cfg.Burst < 0 {
		return errors.New("queue packets, socket buffer, and burst cannot be negative")
	}
	if cfg.ICMPPacingPPS < 0 || cfg.ICMPPacingPPS > cfg.MaxPPS {
		return errors.New("ICMP pacing PPS must be between zero and max PPS")
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
	sockBuf := cfg.SocketBuffer
	if sockBuf <= 0 {
		sockBuf = defaultSocketBuffer
	}
	if got := tuneUDPBuffers(control, sockBuf); got < sockBuf/2 {
		cfg.Logger.Printf("control socket receive buffer is %d bytes (requested %d); raise net.core.rmem_max/wmem_max", got, sockBuf)
	}
	var local *net.UDPConn
	if cfg.Relay == nil {
		local, err = net.ListenUDP("udp4", cfg.Local)
		if err != nil {
			return fmt.Errorf("bind local WireGuard endpoint %s: %w", cfg.Local, err)
		}
		defer local.Close()
		tuneUDPBuffers(local, sockBuf)
	}
	var raw *rawSocket
	if configUsesICMP(cfg) {
		raw, err = openRawSocket()
		if err != nil {
			return err
		}
		defer raw.Close()
		setSocketBuffers(raw.fd, sockBuf)
	}

	now := time.Now()
	e := &engine{cfg: cfg, control: control, local: local, raw: raw, state: udpProbing, limiter: newLimiterBurst(cfg.MaxPPS, cfg.MaxMegabits, cfg.Burst), startedAt: now, lastStats: now}
	e.queueLimit = cfg.QueuePackets
	if e.queueLimit <= 0 {
		e.queueLimit = maxReliableCarrierQueue
	}
	if e.verifier, err = protocol.NewVerifier(cfg.Key); err != nil {
		return err
	}
	pps := cfg.MaxPPS
	if byRate := cfg.MaxMegabits * 1_000_000 / 8 / maxIPPacket; byRate < pps {
		pps = byRate
	}
	e.highWater = pps / 50
	if e.highWater < 64 {
		e.highWater = 64
	}
	if e.highWater > e.queueLimit/2 {
		e.highWater = e.queueLimit / 2
	}
	if e.highWater < 1 {
		e.highWater = 1
	}
	if cfg.Mode == Client {
		e.remote = cloneAddr(cfg.Peer)
		if raw != nil {
			_ = raw.SetPeerFilter(e.remote.IP)
		}
		e.clientSession = randomUint64()
	}
	e.logf("started mode=%s network=%s", cfg.Mode, cfg.Network)

	eventQueueSize := 4096
	if cfg.ICMPPacingPPS > 0 {
		// WireGuard writes to its local UDP socket without carrier backpressure.
		// A deeper event queue absorbs a short scheduler delay while pacing drains
		// packets at a controlled rate.
		eventQueueSize = 16384
	}
	events := make(chan event, eventQueueSize)
	e.ctx = ctx
	e.events = events
	var statusServer *statusServer
	if cfg.StatusSocket != "" {
		statusServer, err = startStatusServer(ctx, cfg.StatusSocket, events)
		if err != nil {
			return fmt.Errorf("start status socket: %w", err)
		}
		defer statusServer.Close()
	}
	if cfg.Mode == Server && cfg.TCPFallback > 0 {
		listener, listenErr := startTCPControlListener(ctx, cfg.Network, events)
		if listenErr != nil {
			e.logf("TCP control fallback unavailable on %s: %v", cfg.Network, listenErr)
		} else {
			defer listener.Close()
		}
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
		relay.congested = func() bool {
			return e.rawQueue.Len()+e.udpQueue.Len() >= e.highWater
		}
		defer relay.Close()
	}
	if raw != nil {
		go readRaw(raw, events)
	}
	if cfg.Mode == Client {
		e.sendUDPHello(time.Now())
	}

	tickInterval := 250 * time.Millisecond
	if cfg.Relay != nil && cfg.Relay.Protocol == RelayTCP {
		tickInterval = 10 * time.Millisecond
	} else if e.pacesWireGuardICMP() {
		// ICMP error paths are frequently policer-sensitive. Millisecond pacing
		// keeps WireGuard data below a large user-space burst while probes remain
		// immediate.
		tickInterval = time.Millisecond
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.closeTCPControl()
			e.logf("stopped: control in/out=%d/%d raw in/out=%d/%d udp data in/out=%d/%d wg in/out=%d/%d dropped=%d invalid=%d", e.stats.controlIn, e.stats.controlOut, e.stats.rawIn, e.stats.rawOut, e.stats.udpDataIn, e.stats.udpDataOut, e.stats.wgIn, e.stats.wgOut, e.stats.dropped, e.stats.invalid)
			return nil
		case ev := <-events:
			e.handleEvent(ev)
		case now := <-ticker.C:
			e.tick(now)
		}
	}
}

const rxBufferSize = maxIPPacket + 64

var rxPool = sync.Pool{New: func() any { b := make([]byte, rxBufferSize); return &b }}

func readUDP(conn *net.UDPConn, kind eventType, out chan<- event) {
	for {
		bp := rxPool.Get().(*[]byte)
		n, addr, err := conn.ReadFromUDP(*bp)
		if err != nil {
			rxPool.Put(bp)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A Port Unreachable can be surfaced as ECONNREFUSED by Linux on
			// a UDP socket. The control socket is deliberately unconnected, and
			// that asynchronous error must not tear down its receive loop.
			continue
		}
		out <- event{type_: kind, data: (*bp)[:n], addr: addr, rx: bp}
	}
}

func readRaw(raw *rawSocket, out chan<- event) {
	for {
		bp := rxPool.Get().(*[]byte)
		n, err := raw.Receive(*bp)
		if err != nil {
			rxPool.Put(bp)
			out <- event{type_: errEvent, err: err}
			return
		}
		out <- event{type_: rawEvent, data: (*bp)[:n], rx: bp}
	}
}

func (e *engine) handleEvent(ev event) {
	if ev.rx != nil {
		defer rxPool.Put(ev.rx)
	}
	switch ev.type_ {
	case controlEvent:
		e.handleUDP(ev.data, ev.addr)
	case tcpControlEvent:
		e.handleTCPControl(ev.data, ev.addr, ev.conn)
	case tcpControlConnectedEvent:
		e.handleTCPControlConnected(ev.conn, ev.err)
	case tcpControlClosedEvent:
		if ev.conn == e.tcpControl {
			e.tcpControl = nil
		}
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
	case relayOversizeEvent:
		e.stats.relayOversize++
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
		ICMPPacingPPS:    e.cfg.ICMPPacingPPS,
		ControlTransport: e.controlTransport,
		Peer:             formatAddr(e.cfg.Peer), LearnedRemote: formatAddr(e.remote), StartedAt: e.startedAt,
		LastHelloAt: timePointer(e.lastHello), LastAckAt: timePointer(e.lastAck), LastRawAt: timePointer(e.lastRaw),
		Stats: RuntimeStats{
			ControlIn: e.stats.controlIn, ControlOut: e.stats.controlOut,
			RawIn: e.stats.rawIn, RawOut: e.stats.rawOut,
			UDPDataIn: e.stats.udpDataIn, UDPDataOut: e.stats.udpDataOut,
			WireGuardIn: e.stats.wgIn, WireGuardOut: e.stats.wgOut,
			Dropped: e.stats.dropped, Invalid: e.stats.invalid,
			TxBytes: e.stats.txBytes, RxBytes: e.stats.rxBytes,
			LimiterQueued: e.stats.limiterQueued, LimiterDrops: e.stats.limiterDrops,
			QueueDrops: e.stats.queueDrops, RelayOversize: e.stats.relayOversize,
		},
	}
	status.QueuedRaw = e.rawQueue.Len()
	status.QueuedUDP = e.udpQueue.Len()
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
		e.handleControl(packet, sender, nil, false)
	case protocol.DataEnvelope:
		e.handleUDPData(packet, sender)
	default:
		e.stats.invalid++
	}
}

func (e *engine) handleTCPControl(packet []byte, sender *net.UDPAddr, conn *net.TCPConn) {
	if protocol.ClassifyEnvelope(packet) != protocol.ControlEnvelope {
		e.stats.invalid++
		return
	}
	e.handleControl(packet, sender, conn, true)
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

func (e *engine) handleControl(packet []byte, sender *net.UDPAddr, conn *net.TCPConn, viaTCP bool) {
	if e.verifier == nil {
		e.verifier, _ = protocol.NewVerifier(e.cfg.Key)
	}
	if e.verifier == nil {
		e.stats.invalid++
		return
	}
	m, err := e.verifier.ParseControlInPlace(packet)
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
		remote := sender
		if viaTCP {
			if m.ObservedPort == 0 {
				e.stats.invalid++
				return
			}
			remote = &net.UDPAddr{IP: append(net.IP(nil), sender.IP...), Port: int(m.ObservedPort)}
		}
		if e.remote == nil || e.clientSession != m.ClientSession || !sameAddr(e.remote, remote) {
			e.resetRelays()
			e.remote = cloneAddr(remote)
			if e.raw != nil {
				_ = e.raw.SetPeerFilter(e.remote.IP)
			}
			e.clientSession = m.ClientSession
			e.serverSession = randomUint64()
			e.state = udpProbing
			if viaTCP {
				e.logf("learned TCP-assisted ICMP tuple %s", e.remote)
			} else {
				e.logf("learned UDP NAT tuple %s", e.remote)
			}
		}
		if viaTCP {
			e.replaceTCPControl(conn)
			e.controlTransport = "tcp"
		} else {
			e.closeTCPControl()
			e.controlTransport = "udp"
		}
		e.lastHello = now
		e.sendHelloAck(m.Nonce, viaTCP)
		return
	}

	expectedNonce := e.nonce
	if viaTCP {
		expectedNonce = e.tcpNonce
	}
	if m.Type != protocol.HelloAck || !sameAddr(sender, e.cfg.Peer) || m.ClientSession != e.clientSession || m.Nonce != expectedNonce || m.ServerSession == 0 || m.ObservedPort == 0 {
		e.stats.invalid++
		return
	}
	newSession := e.serverSession != m.ServerSession
	if e.serverSession != 0 && newSession {
		e.resetRelays()
	}
	e.serverSession = m.ServerSession
	e.lastAck = now
	if viaTCP {
		e.controlTransport = "tcp"
	} else {
		e.closeTCPControl()
		e.controlTransport = "udp"
	}
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
	payload, err := parsePortUnreachableInPlace(packet, remoteTuple, localTuple, localTuple, remoteTuple)
	if err != nil {
		e.stats.invalid++
		return
	}
	if !e.handleDataEnvelope(payload) {
		e.stats.invalid++
		return
	}
	e.stats.rawIn++
	e.stats.rxBytes += uint64(len(packet))
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
	e.stats.rxBytes += uint64(len(packet) + ipv4HeaderLen + udpHeaderLen)
}

func (e *engine) handleDataEnvelope(packet []byte) bool {
	if e.verifier == nil {
		e.verifier, _ = protocol.NewVerifier(e.cfg.Key)
	}
	if e.verifier == nil {
		return false
	}
	m, err := e.verifier.ParseDataInPlace(packet)
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
		if e.cfg.Mode == Client && bytes.Equal(m.Payload, e.expectedProbe) {
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
			frame, err := protocol.ParseRelayFrameInPlace(m.Payload)
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
	e.sendDataWithQueue(protocol.Packet, payload, e.pacesWireGuardICMP())
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
	payload, err := protocol.EncodeRelayFrame(e.tx[icmpPayloadOffset+protocol.DataHeaderSize:], frame)
	if err != nil || len(payload) > e.cfg.MaxPayload {
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

func (e *engine) sendUDPHello(now time.Time) {
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

func (e *engine) sendTCPHello(now time.Time) {
	if e.cfg.Mode != Client || e.tcpControl == nil {
		return
	}
	e.tcpNonce = randomUint64()
	m := protocol.Control{
		Type: protocol.Hello, ClientSession: e.clientSession, Nonce: e.tcpNonce,
		Timestamp: uint64(now.Unix()), ObservedPort: uint16(e.cfg.Network.Port),
	}
	b, _ := m.Marshal(e.cfg.Key)
	if _, err := e.tcpControl.Write(b); err != nil {
		e.logf("send TCP HELLO: %v", err)
		e.closeTCPControl()
		return
	}
	e.lastTCPHello = now
	e.stats.controlOut++
}

func (e *engine) sendHelloAck(nonce uint64, viaTCP bool) {
	if e.remote == nil {
		return
	}
	m := protocol.Control{Type: protocol.HelloAck, ClientSession: e.clientSession, ServerSession: e.serverSession, Nonce: nonce, Timestamp: uint64(time.Now().Unix()), ObservedPort: uint16(e.remote.Port)}
	b, _ := m.Marshal(e.cfg.Key)
	if viaTCP {
		if e.tcpControl == nil {
			return
		}
		if _, err := e.tcpControl.Write(b); err != nil {
			e.logf("send TCP HELLO_ACK: %v", err)
			e.closeTCPControl()
			return
		}
		e.stats.controlOut++
		return
	}
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
	if e.verifier == nil {
		e.verifier, _ = protocol.NewVerifier(e.cfg.Key)
	}
	if e.verifier == nil {
		e.stats.dropped++
		return
	}
	b, err := e.verifier.SealData(e.tx[icmpPayloadOffset:], protocol.Data{Type: kind, Session: e.serverSession, Sequence: e.sequence, Payload: payload})
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
	if e.raw == nil || e.remote == nil {
		return
	}
	e.packetID++
	localTuple := Tuple{IP: e.cfg.Network.IP, Port: e.cfg.Network.Port}
	remoteTuple := Tuple{IP: e.remote.IP, Port: e.remote.Port}
	copy(e.tx[icmpPayloadOffset:], b)
	p, err := finishPortUnreachable(e.tx[:], localTuple, remoteTuple, remoteTuple, localTuple, len(b), e.packetID)
	if err != nil {
		e.logf("build ICMP: %v", err)
		e.stats.dropped++
		return
	}
	e.transmit(&e.rawQueue, p, len(p), reliable)
}

func (e *engine) sendUDPData(packet []byte, reliable bool) {
	e.transmit(&e.udpQueue, packet, len(packet)+ipv4HeaderLen+udpHeaderLen, reliable)
}

func (e *engine) transmit(q *packetQueue, packet []byte, wire int, reliable bool) {
	if q.Len() > 0 || !e.limiter.allow(time.Now(), wire) {
		if !reliable {
			e.stats.limiterDrops++
			e.stats.dropped++
			return
		}
		limit := e.queueLimitFor(q)
		if limit <= 0 {
			limit = maxReliableCarrierQueue
		}
		if !q.push(packet, limit) {
			e.stats.queueDrops++
			e.stats.dropped++
			return
		}
		e.stats.limiterQueued++
		return
	}
	e.writeCarrier(q, packet, wire)
}

// enqueueRaw/enqueueUDP are retained for package-level integrations and tests;
// normal sends go through transmit so limiter counters stay accurate.
func (e *engine) enqueueRaw(packet []byte, _ Tuple) {
	limit := e.queueLimitFor(&e.rawQueue)
	if limit <= 0 {
		limit = maxReliableCarrierQueue
	}
	if !e.rawQueue.push(packet, limit) {
		e.stats.queueDrops++
		e.stats.dropped++
	}
}

func (e *engine) enqueueUDP(packet []byte, _ *net.UDPAddr) {
	limit := e.queueLimitFor(&e.udpQueue)
	if limit <= 0 {
		limit = maxReliableCarrierQueue
	}
	if !e.udpQueue.push(packet, limit) {
		e.stats.queueDrops++
		e.stats.dropped++
	}
}

func (e *engine) queueLimitFor(q *packetQueue) int {
	limit := e.queueLimit
	if q == &e.rawQueue && e.pacesWireGuardICMP() && limit > maxPacedWireGuardQueue {
		return maxPacedWireGuardQueue
	}
	return limit
}

func (e *engine) writeCarrier(q *packetQueue, packet []byte, wire int) {
	var err error
	if q == &e.rawQueue {
		if e.raw == nil || e.remote == nil {
			return
		}
		err = e.raw.Send(packet, Tuple{IP: e.remote.IP, Port: e.remote.Port})
	} else {
		if e.remote == nil {
			return
		}
		_, err = e.control.WriteToUDP(packet, e.remote)
	}
	if err != nil {
		e.logf("send carrier: %v", err)
		e.stats.dropped++
		return
	}
	e.stats.txBytes += uint64(wire)
	if q == &e.rawQueue {
		e.stats.rawOut++
	} else {
		e.stats.udpDataOut++
	}
}

func (e *engine) flushQueue(q *packetQueue, now time.Time, overhead, batch int) {
	for sent := 0; sent < batch; sent++ {
		p := q.peek()
		if p == nil || !e.limiter.allow(now, len(p)+overhead) {
			return
		}
		e.writeCarrier(q, p, len(p)+overhead)
		q.pop()
	}
}

func (e *engine) flushRawQueue(now time.Time) {
	e.flushQueue(&e.rawQueue, now, 0, e.rawQueue.Len())
}

func (e *engine) flushUDPQueue(now time.Time) {
	e.flushQueue(&e.udpQueue, now, ipv4HeaderLen+udpHeaderLen, e.udpQueue.Len())
}

func (e *engine) tick(now time.Time) {
	batch := e.queueLimitFor(&e.rawQueue)
	if batch <= 0 {
		batch = maxReliableCarrierQueue
	}
	if e.pacesWireGuardICMP() {
		batch = (e.cfg.ICMPPacingPPS + 999) / 1000
		if batch < 1 {
			batch = 1
		}
	}
	e.flushQueue(&e.rawQueue, now, 0, batch)
	udpBatch := e.queueLimitFor(&e.udpQueue)
	if udpBatch <= 0 {
		udpBatch = maxReliableCarrierQueue
	}
	e.flushQueue(&e.udpQueue, now, ipv4HeaderLen+udpHeaderLen, udpBatch)
	if e.cfg.Mode == Client {
		if now.Sub(e.lastHello) >= e.cfg.Keepalive {
			e.sendUDPHello(now)
		}
		if e.tcpControl != nil && now.Sub(e.lastTCPHello) >= e.cfg.Keepalive {
			e.sendTCPHello(now)
		}
		if e.cfg.TCPFallback > 0 && e.tcpControl == nil && !e.tcpDialing && e.lastAck.IsZero() && now.Sub(e.startedAt) >= e.cfg.TCPFallback && now.Sub(e.lastTCPDial) >= e.cfg.Keepalive {
			e.startTCPControlDial()
		}
		if !e.lastAck.IsZero() && now.Sub(e.lastAck) > e.cfg.DeadTimeout {
			e.resetRelays()
			e.transition(udpProbing)
			e.serverSession = 0
			e.expectedProbe = nil
			e.closeTCPControl()
			e.controlTransport = ""
		}
		if e.state == established && now.Sub(e.lastProbe) >= e.cfg.Keepalive*2 {
			e.sendProbe()
		}
	} else if e.remote != nil && now.Sub(e.lastHello) > e.cfg.DeadTimeout {
		e.logf("UDP NAT tuple expired: %s", e.remote)
		e.remote = nil
		if e.raw != nil {
			_ = e.raw.SetPeerFilter(nil)
		}
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
	e.rawQueue.reset()
	e.udpQueue.reset()
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

func (e *engine) pacesWireGuardICMP() bool {
	return e.cfg.ICMPPacingPPS > 0 && e.cfg.Relay == nil && (e.cfg.Mode == Client || e.cfg.Mode == Server) && e.localCarrier() == CarrierICMP
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
