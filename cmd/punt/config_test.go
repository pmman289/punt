package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pmman289/punt/internal/tunnel"
)

const managedTestKey = "00112233445566778899aabbccddeeff"

func TestLoadManagedConfig(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "punt.json")
	config := `{
  "mode": "client",
  "network": "192.0.2.2:42487",
  "peer": "198.51.100.9:23086",
  "key_file": "` + keyPath + `",
  "status_socket": "` + filepath.Join(dir, "punt.sock") + `"
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadManagedConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "client" || cfg.Network.String() != "192.0.2.2:42487" || cfg.Peer == nil || cfg.Peer.String() != "198.51.100.9:23086" {
		t.Fatalf("unexpected network config: %#v", cfg)
	}
	if cfg.Local.String() != "127.0.0.1:51821" || cfg.WireGuard.String() != "127.0.0.1:51820" || cfg.MaxPPS != 10000 || cfg.MaxMegabits != 100 || cfg.ClientTX != tunnel.CarrierICMP || cfg.ServerTX != tunnel.CarrierICMP {
		t.Fatalf("managed defaults not applied: %#v", cfg)
	}
}

func TestLoadManagedCarrierConfig(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "punt.json")
	config := `{"mode":"client","network":"192.0.2.2:42487","peer":"198.51.100.9:23086","key_file":"` + keyPath + `","carrier":{"client_to_server":"udp","server_to_client":"icmp"}}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadManagedConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientTX != tunnel.CarrierUDP || cfg.ServerTX != tunnel.CarrierICMP {
		t.Fatalf("unexpected carrier config: %#v", cfg)
	}
}

func TestManagedConfigRejectsUnknownCarrier(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "punt.json")
	config := `{"mode":"server","network":"192.0.2.2:23086","key_file":"` + keyPath + `","carrier":{"client_to_server":"tcp"}}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedConfig(configPath); err == nil {
		t.Fatal("accepted an unknown managed carrier")
	}
}

func TestKeyFileRejectsGroupReadablePermissions(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKey("", keyPath); err == nil {
		t.Fatal("accepted a group-readable key file")
	}
}

func TestManagedConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "punt.json")
	config := `{"mode":"server","network":"192.0.2.2:23086","key_file":"` + keyPath + `","unknown":true}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagedConfig(configPath); err == nil {
		t.Fatal("accepted an unknown managed configuration field")
	}
}

func TestLoadManagedUDPRelayConfig(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "punt.json")
	config := `{"mode":"client","network":"192.0.2.2:42487","peer":"198.51.100.9:23086","key_file":"` + keyPath + `","relay":{"protocol":"udp","listen":"127.0.0.1:8080","idle_timeout":"2m"}}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadManagedConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay == nil || cfg.Relay.Protocol != tunnel.RelayUDP || cfg.Relay.Listen.String() != "127.0.0.1:8080" || cfg.Relay.IdleTimeout != 2*time.Minute {
		t.Fatalf("unexpected relay config: %#v", cfg.Relay)
	}
	if cfg.Local != nil || cfg.WireGuard != nil {
		t.Fatalf("relay config unexpectedly created WireGuard endpoints: %#v", cfg)
	}
}

func TestLoadManagedServerListenSide(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte(managedTestKey), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "punt.json")
	config := `{"mode":"server","network":"192.0.2.2:23086","key_file":"` + keyPath + `","relay":{"protocol":"tcp","listen_side":"server","listen":"127.0.0.1:8080","tcp_nocwnd":true}}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadManagedConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Relay == nil || cfg.Relay.ListenSide != tunnel.Server || cfg.Relay.Listen.String() != "127.0.0.1:8080" || !cfg.Relay.TCPNoCwnd {
		t.Fatalf("unexpected server listener config: %#v", cfg.Relay)
	}
}
