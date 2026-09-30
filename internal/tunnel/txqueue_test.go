package tunnel

import "testing"

func TestPacketQueueRingAndReset(t *testing.T) {
	var q packetQueue
	for i := 0; i < 100; i++ {
		if !q.push([]byte{byte(i)}, 8) {
			t.Fatalf("push %d failed", i)
		}
		if got := q.peek(); len(got) != 1 || got[0] != byte(i) {
			t.Fatalf("peek after push %d = %v", i, got)
		}
		q.pop()
	}
	for i := 0; i < 8; i++ {
		if !q.push([]byte{byte(i)}, 8) {
			t.Fatalf("fill push %d failed", i)
		}
	}
	if q.push([]byte("overflow"), 8) {
		t.Fatal("queue accepted a packet past its limit")
	}
	for i := 0; i < 8; i++ {
		got := q.peek()
		if len(got) != 1 || got[0] != byte(i) {
			t.Fatalf("FIFO item %d = %v", i, got)
		}
		q.pop()
	}
	if q.Len() != 0 || q.peek() != nil {
		t.Fatalf("queue not empty after drain: len=%d peek=%v", q.Len(), q.peek())
	}
	q.reset()
}
