package tunnel

import (
	"net"
	"testing"
	"time"
)

func TestUDPRelayUsesStableDistinctFlowIDs(t *testing.T) {
	r := &udpRelay{flows: make(map[uint32]*relayFlow), byAddr: make(map[string]uint32)}
	a := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	b := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10002}
	first, err := r.listenerFrame([]byte("a"), a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.listenerFrame([]byte("again"), a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.listenerFrame([]byte("b"), b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.FlowID != again.FlowID {
		t.Fatal("same UDP source received a different flow ID")
	}
	if first.FlowID == second.FlowID {
		t.Fatal("different UDP sources received the same flow ID")
	}
}

func TestReliableRawQueueIsBoundedAndReset(t *testing.T) {
	e := &engine{}
	for i := 0; i < maxReliableCarrierQueue+10; i++ {
		e.enqueueRaw([]byte{byte(i)}, Tuple{})
	}
	if len(e.rawQueue) != maxReliableCarrierQueue || e.stats.dropped != 10 {
		t.Fatalf("queue=%d dropped=%d", len(e.rawQueue), e.stats.dropped)
	}
	e.resetRelays()
	if len(e.rawQueue) != 0 {
		t.Fatal("session reset retained reliable raw packets")
	}
}

func TestValidateRelayServerListenSide(t *testing.T) {
	server := &RelayConfig{Protocol: RelayTCP, ListenSide: Server, Listen: udpAddr("127.0.0.1:8080"), IdleTimeout: time.Minute}
	client := &RelayConfig{Protocol: RelayTCP, ListenSide: Server, Target: udpAddr("127.0.0.1:80"), IdleTimeout: time.Minute}
	if err := validateRelayConfig(Server, server); err != nil {
		t.Fatal(err)
	}
	if err := validateRelayConfig(Client, client); err != nil {
		t.Fatal(err)
	}
}
