package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pmman289/punt/internal/protocol"
	"github.com/pmman289/punt/internal/tunnel"
)

type cliConfig struct {
	configPath   string
	mode         string
	network      string
	peer         string
	local        string
	wireGuard    string
	keyHex       string
	keyFile      string
	statusSocket string
	keepalive    time.Duration
	deadTimeout  time.Duration
	maxPayload   int
	maxPPS       int
	maxMegabits  int
	clientTX     string
	serverTX     string
	relay        string
	listenSide   string
	listen       string
	target       string
	relayIdle    time.Duration
	tcpNoCwnd    bool
}

// managedConfig is the stable file contract consumed by Link42-managed units.
type managedConfig struct {
	Mode         string               `json:"mode"`
	Network      string               `json:"network"`
	Peer         string               `json:"peer,omitempty"`
	Local        string               `json:"local,omitempty"`
	WireGuard    string               `json:"wireguard,omitempty"`
	KeyFile      string               `json:"key_file"`
	StatusSocket string               `json:"status_socket,omitempty"`
	Keepalive    string               `json:"keepalive,omitempty"`
	DeadTimeout  string               `json:"dead_timeout,omitempty"`
	MaxPayload   int                  `json:"max_payload,omitempty"`
	MaxPPS       int                  `json:"max_pps,omitempty"`
	MaxMegabits  int                  `json:"max_mbps,omitempty"`
	Carrier      managedCarrierConfig `json:"carrier,omitempty"`
	Relay        *managedRelayConfig  `json:"relay,omitempty"`
}

type managedCarrierConfig struct {
	ClientToServer string `json:"client_to_server,omitempty"`
	ServerToClient string `json:"server_to_client,omitempty"`
}

type managedRelayConfig struct {
	Protocol    string `json:"protocol"`
	ListenSide  string `json:"listen_side,omitempty"`
	Listen      string `json:"listen,omitempty"`
	Target      string `json:"target,omitempty"`
	IdleTimeout string `json:"idle_timeout,omitempty"`
	TCPNoCwnd   bool   `json:"tcp_nocwnd,omitempty"`
}

func (c cliConfig) tunnelConfig() (tunnel.Config, error) {
	if c.configPath != "" {
		return loadManagedConfig(c.configPath)
	}
	key, err := loadKey(c.keyHex, c.keyFile)
	if err != nil {
		return tunnel.Config{}, err
	}
	relay, err := buildRelayConfig(c.mode, c.relay, c.listenSide, c.listen, c.target, c.relayIdle, c.tcpNoCwnd)
	if err != nil {
		return tunnel.Config{}, err
	}
	return buildTunnelConfig(
		c.mode, c.network, c.peer, c.local, c.wireGuard, c.statusSocket,
		c.clientTX, c.serverTX, key, c.keepalive, c.deadTimeout, c.maxPayload, c.maxPPS, c.maxMegabits, relay,
	)
}

func loadManagedConfig(path string) (tunnel.Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return tunnel.Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64*1024))
	decoder.DisallowUnknownFields()
	var raw managedConfig
	if err := decoder.Decode(&raw); err != nil {
		return tunnel.Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tunnel.Config{}, errors.New("decode config: trailing JSON data")
	}
	key, err := loadKey("", raw.KeyFile)
	if err != nil {
		return tunnel.Config{}, err
	}
	keepalive, err := durationOrDefault(raw.Keepalive, 5*time.Second, "keepalive")
	if err != nil {
		return tunnel.Config{}, err
	}
	deadTimeout, err := durationOrDefault(raw.DeadTimeout, 15*time.Second, "dead_timeout")
	if err != nil {
		return tunnel.Config{}, err
	}
	var relay *tunnel.RelayConfig
	if raw.Relay != nil {
		if raw.Local != "" || raw.WireGuard != "" {
			return tunnel.Config{}, errors.New("relay is mutually exclusive with local and wireguard")
		}
		idle, err := durationOrDefault(raw.Relay.IdleTimeout, 5*time.Minute, "relay.idle_timeout")
		if err != nil {
			return tunnel.Config{}, err
		}
		relay, err = buildRelayConfig(raw.Mode, raw.Relay.Protocol, raw.Relay.ListenSide, raw.Relay.Listen, raw.Relay.Target, idle, raw.Relay.TCPNoCwnd)
		if err != nil {
			return tunnel.Config{}, err
		}
	}
	local := raw.Local
	if local == "" && relay == nil {
		local = "127.0.0.1:51821"
	}
	wireGuard := raw.WireGuard
	if wireGuard == "" && relay == nil {
		wireGuard = "127.0.0.1:51820"
	}
	maxPayload := raw.MaxPayload
	if maxPayload == 0 {
		maxPayload = protocol.MaxPayload
	}
	maxPPS := raw.MaxPPS
	if maxPPS == 0 {
		maxPPS = 10000
	}
	maxMegabits := raw.MaxMegabits
	if maxMegabits == 0 {
		maxMegabits = 100
	}
	return buildTunnelConfig(
		raw.Mode, raw.Network, raw.Peer, local, wireGuard, raw.StatusSocket,
		raw.Carrier.ClientToServer, raw.Carrier.ServerToClient,
		key, keepalive, deadTimeout, maxPayload, maxPPS, maxMegabits, relay,
	)
}

func buildTunnelConfig(mode, networkAddr, peerAddr, localAddr, wireGuardAddr, statusSocket, clientTX, serverTX string, key []byte, keepalive, deadTimeout time.Duration, maxPayload, maxPPS, maxMegabits int, relay *tunnel.RelayConfig) (tunnel.Config, error) {
	if clientTX == "" {
		clientTX = string(tunnel.CarrierICMP)
	}
	if serverTX == "" {
		serverTX = string(tunnel.CarrierICMP)
	}
	network, err := parseIPv4UDP("network", networkAddr)
	if err != nil {
		return tunnel.Config{}, err
	}
	var local, wireGuard *net.UDPAddr
	if relay == nil {
		local, err = parseIPv4UDP("local", localAddr)
		if err != nil {
			return tunnel.Config{}, err
		}
		wireGuard, err = parseIPv4UDP("wireguard", wireGuardAddr)
		if err != nil {
			return tunnel.Config{}, err
		}
	}
	var peer *net.UDPAddr
	if mode == string(tunnel.Client) {
		peer, err = parseIPv4UDP("peer", peerAddr)
		if err != nil {
			return tunnel.Config{}, err
		}
	} else if peerAddr != "" {
		return tunnel.Config{}, errors.New("peer is valid only in client mode")
	}
	cfg := tunnel.Config{
		Mode: tunnel.Mode(mode), Network: network, Peer: peer, Local: local,
		WireGuard: wireGuard, Key: key, StatusSocket: statusSocket,
		ClientTX: tunnel.DataCarrier(clientTX), ServerTX: tunnel.DataCarrier(serverTX),
		Keepalive: keepalive, DeadTimeout: deadTimeout, MaxPayload: maxPayload,
		MaxPPS: maxPPS, MaxMegabits: maxMegabits, Relay: relay,
	}
	if err := tunnel.ValidateConfig(cfg); err != nil {
		return tunnel.Config{}, err
	}
	return cfg, nil
}

func buildRelayConfig(mode, protocolName, listenSide, listen, target string, idle time.Duration, tcpNoCwnd bool) (*tunnel.RelayConfig, error) {
	if protocolName == "" {
		if listen != "" || target != "" {
			return nil, errors.New("relay protocol is required when relay listen or target is set")
		}
		return nil, nil
	}
	if listenSide == "" {
		listenSide = string(tunnel.Client)
	}
	cfg := &tunnel.RelayConfig{Protocol: tunnel.RelayProtocol(protocolName), ListenSide: tunnel.Mode(listenSide), IdleTimeout: idle, TCPNoCwnd: tcpNoCwnd}
	var err error
	if listen != "" {
		cfg.Listen, err = parseIPv4UDP("relay listen", listen)
		if err != nil {
			return nil, err
		}
	}
	if target != "" {
		cfg.Target, err = parseIPv4UDP("relay target", target)
		if err != nil {
			return nil, err
		}
	}
	if mode != string(tunnel.Client) && mode != string(tunnel.Server) {
		return nil, errors.New("mode must be client or server")
	}
	return cfg, nil
}

func parseIPv4UDP(name, value string) (*net.UDPAddr, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	addr, err := net.ResolveUDPAddr("udp4", value)
	if err != nil || addr.IP.To4() == nil || addr.Port < 1 || strings.Contains(value, "[") {
		return nil, fmt.Errorf("%s must be an IPv4 address and UDP port", name)
	}
	return addr, nil
}

func loadKey(keyHex, keyFile string) ([]byte, error) {
	if keyHex != "" && keyFile != "" {
		return nil, errors.New("key and key-file are mutually exclusive")
	}
	if keyFile != "" {
		info, err := os.Stat(keyFile)
		if err != nil {
			return nil, fmt.Errorf("stat key file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("key file must be a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("key file permissions must not grant group or other access")
		}
		contents, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		keyHex = strings.TrimSpace(string(contents))
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 16 {
		return nil, errors.New("key must be exactly 32 hexadecimal characters")
	}
	return key, nil
}

func durationOrDefault(value string, fallback time.Duration, name string) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration: %w", name, err)
	}
	return duration, nil
}
