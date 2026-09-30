package tunnel

import "sync"

const txBufferSize = maxIPPacket

var txPool = sync.Pool{New: func() any { b := make([]byte, txBufferSize); return &b }}

type queuedPacket struct {
	buf *[]byte
	n   int
}

// packetQueue is a bounded FIFO ring. It reuses packet storage across limiter
// stalls, avoiding the old slice reallocation and per-packet copies.
type packetQueue struct {
	items []queuedPacket
	head  int
	count int
}

func (q *packetQueue) Len() int { return q.count }

func (q *packetQueue) push(packet []byte, limit int) bool {
	if q.count >= limit || len(packet) > txBufferSize || limit <= 0 {
		return false
	}
	if q.count == len(q.items) {
		q.grow(limit)
	}
	buf := txPool.Get().(*[]byte)
	n := copy(*buf, packet)
	q.items[(q.head+q.count)%len(q.items)] = queuedPacket{buf: buf, n: n}
	q.count++
	return true
}

func (q *packetQueue) grow(limit int) {
	size := len(q.items) * 2
	if size < 64 {
		size = 64
	}
	if size > limit {
		size = limit
	}
	items := make([]queuedPacket, size)
	for i := 0; i < q.count; i++ {
		items[i] = q.items[(q.head+i)%len(q.items)]
	}
	q.items, q.head = items, 0
}

func (q *packetQueue) peek() []byte {
	if q.count == 0 {
		return nil
	}
	item := q.items[q.head]
	return (*item.buf)[:item.n]
}

func (q *packetQueue) pop() {
	if q.count == 0 {
		return
	}
	txPool.Put(q.items[q.head].buf)
	q.items[q.head] = queuedPacket{}
	q.head = (q.head + 1) % len(q.items)
	q.count--
}

func (q *packetQueue) reset() {
	for q.count > 0 {
		q.pop()
	}
	q.head = 0
}
