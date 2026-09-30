package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func legacyDataMarshal(key []byte, m Data) []byte {
	b := make([]byte, DataHeaderSize+len(m.Payload))
	copy(b, dataMagic[:])
	b[4], b[5] = Version, byte(m.Type)
	binary.BigEndian.PutUint16(b[6:8], DataHeaderSize)
	binary.BigEndian.PutUint64(b[8:16], m.Session)
	binary.BigEndian.PutUint32(b[16:20], m.Sequence)
	binary.BigEndian.PutUint16(b[20:22], uint16(len(m.Payload)))
	copy(b[DataHeaderSize:], m.Payload)
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(b)
	copy(b[dataMACOffset:], h.Sum(nil)[:macSize])
	return b
}

func TestSealAndParseRemainWireCompatible(t *testing.T) {
	key := []byte("0123456789abcdef")
	v, err := NewVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	dirty := bytes.Repeat([]byte{0xaa}, DataHeaderSize+MaxPayload)
	for _, n := range []int{0, 1, 17, 1384, MaxPayload} {
		m := Data{Type: Packet, Session: 0x1122334455667788, Sequence: uint32(n), Payload: bytes.Repeat([]byte{byte(n)}, n)}
		got, err := v.SealData(dirty, m)
		if err != nil {
			t.Fatal(err)
		}
		if want := legacyDataMarshal(key, m); !bytes.Equal(got, want) {
			t.Fatalf("payload %d changed the wire format", n)
		}
	}
}

func TestParseDataInPlaceAliasesAndRejectsTamper(t *testing.T) {
	key := []byte("0123456789abcdef")
	v, _ := NewVerifier(key)
	packet := legacyDataMarshal(key, Data{Type: Packet, Session: 3, Sequence: 4, Payload: []byte("abc")})
	m, err := v.ParseDataInPlace(packet)
	if err != nil || string(m.Payload) != "abc" || &m.Payload[0] != &packet[DataHeaderSize] {
		t.Fatalf("in-place parse failed: %#v, %v", m, err)
	}
	tampered := append([]byte(nil), legacyDataMarshal(key, Data{Type: Packet, Session: 3, Payload: []byte("abc")})...)
	tampered[len(tampered)-1] ^= 1
	if _, err := v.ParseDataInPlace(tampered); err == nil {
		t.Fatal("accepted a tampered packet")
	}
}

func TestRelayInPlaceRoundTrip(t *testing.T) {
	f := RelayFrame{Type: RelayTCPPacket, FlowID: 7, Payload: []byte("segment")}
	want, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeRelayFrame(bytes.Repeat([]byte{0xff}, 64), f)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encode mismatch: %v", err)
	}
	parsed, err := ParseRelayFrameInPlace(got)
	if err != nil || &parsed.Payload[0] != &got[RelayHeaderSize] {
		t.Fatalf("in-place relay parse failed: %v", err)
	}
}
