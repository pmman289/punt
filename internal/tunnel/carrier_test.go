package tunnel

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/pmman289/punt/internal/protocol"
)

var carrierTestKey = []byte("0123456789abcdef")

func TestCarrierProbePayloadCompatibilityAndConsistency(t *testing.T) {
	legacy := &engine{cfg: Config{ClientTX: CarrierICMP, ServerTX: CarrierICMP}}
	legacyPayload := legacy.newProbePayload()
	if len(legacyPayload) != 8 || !legacy.validProbePayload(legacyPayload) {
		t.Fatalf("legacy probe payload is invalid: %x", legacyPayload)
	}

	mixed := &engine{cfg: Config{ClientTX: CarrierUDP, ServerTX: CarrierICMP}}
	mixedPayload := mixed.newProbePayload()
	if len(mixedPayload) != 16 || !mixed.validProbePayload(mixedPayload) {
		t.Fatalf("mixed probe payload is invalid: %x", mixedPayload)
	}
	mismatch := &engine{cfg: Config{ClientTX: CarrierICMP, ServerTX: CarrierUDP}}
	if mismatch.validProbePayload(mixedPayload) {
		t.Fatal("accepted probe payload for a different carrier configuration")
	}
}

func TestCarrierDirectionsFollowUnderlayRole(t *testing.T) {
	client := &engine{cfg: Config{Mode: Client, ClientTX: CarrierUDP, ServerTX: CarrierICMP}}
	server := &engine{cfg: Config{Mode: Server, ClientTX: CarrierUDP, ServerTX: CarrierICMP}}
	if client.localCarrier() != CarrierUDP || client.remoteCarrier() != CarrierICMP {
		t.Fatalf("client carriers local=%s remote=%s", client.localCarrier(), client.remoteCarrier())
	}
	if server.localCarrier() != CarrierICMP || server.remoteCarrier() != CarrierUDP {
		t.Fatalf("server carriers local=%s remote=%s", server.localCarrier(), server.remoteCarrier())
	}
}

func TestConfigUsesRawSocketOnlyForICMP(t *testing.T) {
	if configUsesICMP(Config{ClientTX: CarrierUDP, ServerTX: CarrierUDP}) {
		t.Fatal("UDP-only carrier configuration unexpectedly requires a raw socket")
	}
	if !configUsesICMP(Config{ClientTX: CarrierUDP, ServerTX: CarrierICMP}) {
		t.Fatal("mixed carrier configuration did not require a raw socket")
	}
}

func TestUDPDataValidatesSourceSessionAndDelivers(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	delivery, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Close()
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	e := &engine{
		cfg: Config{
			Mode: Client, ServerTX: CarrierUDP, Key: carrierTestKey,
			WireGuard: target.LocalAddr().(*net.UDPAddr), Logger: log.New(io.Discard, "", 0),
		},
		local: delivery, remote: remote.LocalAddr().(*net.UDPAddr), serverSession: 42, state: established,
	}
	packet, err := (protocol.Data{Type: protocol.Packet, Session: 42, Payload: []byte("payload")}).Marshal(carrierTestKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongSource := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: e.remote.Port + 1}
	e.handleUDPData(packet, wrongSource)
	if e.stats.invalid != 1 || e.stats.udpDataIn != 0 {
		t.Fatalf("wrong source counters: %#v", e.stats)
	}

	wrongSession, err := (protocol.Data{Type: protocol.Packet, Session: 43, Payload: []byte("payload")}).Marshal(carrierTestKey)
	if err != nil {
		t.Fatal(err)
	}
	e.handleUDPData(wrongSession, e.remote)
	if e.stats.invalid != 2 || e.stats.udpDataIn != 0 {
		t.Fatalf("wrong session counters: %#v", e.stats)
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	e.handleUDPData(tampered, e.remote)
	if e.stats.invalid != 3 || e.stats.udpDataIn != 0 {
		t.Fatalf("tampered MAC counters: %#v", e.stats)
	}

	e.handleUDPData(packet, e.remote)
	if e.stats.udpDataIn != 1 || e.stats.wgOut != 1 {
		t.Fatalf("valid UDP data counters: %#v", e.stats)
	}
	_ = target.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := target.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "payload" {
		t.Fatalf("delivered payload = %q", buf[:n])
	}
}

func TestReliableUDPQueueIsBoundedAndFlushes(t *testing.T) {
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	now := time.Now()
	e := &engine{
		cfg:     Config{Mode: Client, ClientTX: CarrierUDP, Key: carrierTestKey, Logger: log.New(io.Discard, "", 0)},
		control: sender, remote: receiver.LocalAddr().(*net.UDPAddr), serverSession: 9,
		limiter: newLimiter(1, 1),
	}
	e.limiter.packets = 0
	e.limiter.bytes = 0
	e.limiter.last = now
	e.sendDataWithQueue(protocol.Packet, []byte("queued"), true)
	if len(e.udpQueue) != 1 || e.stats.udpDataOut != 0 {
		t.Fatalf("UDP queue was not used: queue=%d stats=%#v", len(e.udpQueue), e.stats)
	}
	e.flushUDPQueue(now.Add(2 * time.Second))
	if len(e.udpQueue) != 0 || e.stats.udpDataOut != 1 {
		t.Fatalf("UDP queue was not flushed: queue=%d stats=%#v", len(e.udpQueue), e.stats)
	}
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := protocol.ParseData(buf[:n], carrierTestKey)
	if err != nil || string(m.Payload) != "queued" {
		t.Fatalf("queued packet = %#v, err=%v", m, err)
	}

	for i := 0; i < maxReliableCarrierQueue+10; i++ {
		e.enqueueUDP([]byte{byte(i)}, e.remote)
	}
	if len(e.udpQueue) != maxReliableCarrierQueue || e.stats.dropped != 10 {
		t.Fatalf("bounded queue=%d dropped=%d", len(e.udpQueue), e.stats.dropped)
	}
	e.resetRelays()
	if len(e.udpQueue) != 0 {
		t.Fatal("session reset retained reliable UDP packets")
	}
}

func TestValidateConfigRejectsUnknownCarrier(t *testing.T) {
	cfg := Config{
		Mode: Server, Network: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		Relay: &RelayConfig{Protocol: RelayUDP, Target: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}, IdleTimeout: time.Minute},
		Key:   carrierTestKey, Keepalive: time.Second, DeadTimeout: 2 * time.Second,
		MaxPayload: protocol.MaxPayload, MaxPPS: 1, MaxMegabits: 1, ClientTX: "tcp",
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("accepted an unknown data carrier")
	}
}
