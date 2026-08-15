package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pmman289/punt/internal/protocol"
	"github.com/pmman289/punt/internal/tunnel"
)

var version = "dev"

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "punt:", err)
		os.Exit(2)
	}
}

func execute(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "status" {
		return queryStatus(args[1:], stdout, stderr)
	}

	values := cliConfig{
		local:       "127.0.0.1:51821",
		wireGuard:   "127.0.0.1:51820",
		keepalive:   5 * time.Second,
		deadTimeout: 15 * time.Second,
		tcpFallback: 3 * time.Second,
		maxPayload:  protocol.MaxPayload,
		maxPPS:      10000,
		maxMegabits: 100,
		clientTX:    string(tunnel.CarrierICMP),
		serverTX:    string(tunnel.CarrierICMP),
		relayIdle:   5 * time.Minute,
	}
	flags := flag.NewFlagSet("punt", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&values.configPath, "config", "", "Link42-managed JSON configuration file")
	flags.StringVar(&values.mode, "mode", "", "required: client or server")
	flags.StringVar(&values.network, "network", "", "required: public-facing local IPv4 UDP address")
	flags.StringVar(&values.peer, "peer", "", "client only: public server IPv4 UDP address")
	flags.StringVar(&values.local, "local", values.local, "wrapper localhost UDP address")
	flags.StringVar(&values.wireGuard, "wireguard", values.wireGuard, "WireGuard localhost UDP ListenPort")
	flags.StringVar(&values.keyHex, "key", "", "32 hex characters; use -key-file for managed services")
	flags.StringVar(&values.keyFile, "key-file", "", "0600 file containing the 16-byte key as hexadecimal")
	flags.StringVar(&values.statusSocket, "status-socket", "", "absolute Unix socket path for local status queries")
	flags.DurationVar(&values.keepalive, "keepalive", values.keepalive, "real UDP HELLO keepalive interval")
	flags.DurationVar(&values.deadTimeout, "dead-timeout", values.deadTimeout, "UDP control timeout before reprobe")
	flags.DurationVar(&values.tcpFallback, "tcp-fallback", values.tcpFallback, "delay before falling back from UDP to TCP control; 0 disables")
	flags.IntVar(&values.maxPayload, "max-payload", values.maxPayload, "maximum authenticated data payload bytes")
	flags.IntVar(&values.maxPPS, "max-pps", values.maxPPS, "maximum data carrier packets per second")
	flags.IntVar(&values.maxMegabits, "max-mbps", values.maxMegabits, "maximum data carrier megabits per second")
	flags.IntVar(&values.icmpPacingPPS, "icmp-pacing-pps", 0, "WireGuard-over-ICMP outbound pacing target; 0 disables pacing")
	flags.StringVar(&values.clientTX, "client-tx", values.clientTX, "client-to-server data carrier: icmp or udp")
	flags.StringVar(&values.serverTX, "server-tx", values.serverTX, "server-to-client data carrier: icmp or udp")
	flags.StringVar(&values.relay, "relay", "", "application relay protocol: udp or tcp")
	flags.StringVar(&values.listenSide, "listen-side", "client", "underlay side accepting applications: client or server")
	flags.StringVar(&values.listen, "listen", "", "listener-side relay IPv4 address")
	flags.StringVar(&values.target, "target", "", "target-side application IPv4 address")
	flags.DurationVar(&values.relayIdle, "relay-idle-timeout", values.relayIdle, "application relay flow idle timeout")
	flags.BoolVar(&values.tcpNoCwnd, "tcp-nocwnd", false, "disable KCP congestion window; use only with an explicit Punt rate limit")
	showVersion := flags.Bool("version", false, "print Punt version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *showVersion {
		fmt.Fprintf(stdout, "punt %s\n", version)
		return nil
	}

	cfg, err := values.tunnelConfig()
	if err != nil {
		return err
	}
	cfg.Logger = log.New(stderr, "punt: ", log.LstdFlags|log.Lmicroseconds)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return tunnel.Run(ctx, cfg)
}

func queryStatus(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("punt status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	socketPath := flags.String("socket", "", "required: Punt status Unix socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *socketPath == "" {
		return errors.New("status requires -socket")
	}
	conn, err := net.DialTimeout("unix", *socketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect status socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var status tunnel.RuntimeStatus
	if err := json.NewDecoder(conn).Decode(&status); err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}
