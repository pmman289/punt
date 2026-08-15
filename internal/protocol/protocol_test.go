package protocol

import "testing"

var testKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func TestControlRoundTripAndMAC(t *testing.T) {
	want := Control{Type: HelloAck, ClientSession: 1, ServerSession: 2, Nonce: 3, Timestamp: 4, ObservedPort: 23086}
	b, err := want.Marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseControl(b, testKey)
	if err != nil || got != want {
		t.Fatalf("got %#v, err %v", got, err)
	}
	b[21] ^= 1
	if _, err := ParseControl(b, testKey); err == nil {
		t.Fatal("accepted a modified authenticated control packet")
	}
}

func TestDataRoundTripAndLength(t *testing.T) {
	want := Data{Type: Packet, Session: 99, Sequence: 7, Payload: []byte("wireguard")}
	b, err := want.Marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseData(b, testKey)
	if err != nil || got.Type != want.Type || got.Session != want.Session || got.Sequence != want.Sequence || string(got.Payload) != string(want.Payload) {
		t.Fatalf("got %#v, err %v", got, err)
	}
	if _, err := ParseData(b[:len(b)-1], testKey); err == nil {
		t.Fatal("accepted truncated packet")
	}
}

func TestReservedFieldsMustBeZero(t *testing.T) {
	control, err := (Control{Type: Hello, ClientSession: 1}).Marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	control[42] = 1
	if _, err := ParseControl(control, testKey); err == nil {
		t.Fatal("accepted a non-zero control reserved field")
	}

	data, err := (Data{Type: Probe, Session: 1}).Marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	data[22] = 1
	if _, err := ParseData(data, testKey); err == nil {
		t.Fatal("accepted a non-zero data reserved field")
	}
}

func TestClassifyEnvelope(t *testing.T) {
	control, err := (Control{Type: Hello, ClientSession: 1}).Marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := (Data{Type: Probe, Session: 1}).Marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if ClassifyEnvelope(control) != ControlEnvelope || ClassifyEnvelope(data) != DataEnvelope || ClassifyEnvelope([]byte("nope")) != UnknownEnvelope {
		t.Fatal("envelope classifier returned an unexpected type")
	}
}

func TestRelayFrameRoundTripAndRejectsReservedBytes(t *testing.T) {
	want := RelayFrame{Type: RelayUDP, FlowID: 42, Payload: []byte("datagram")}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRelayFrame(b)
	if err != nil || got.Type != want.Type || got.FlowID != want.FlowID || string(got.Payload) != string(want.Payload) {
		t.Fatalf("got %#v, err %v", got, err)
	}
	b[14] = 1
	if _, err := ParseRelayFrame(b); err == nil {
		t.Fatal("accepted non-zero relay reserved byte")
	}
}
