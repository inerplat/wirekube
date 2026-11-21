package relay

import (
	"net"
	"testing"
	"time"
)

func queuedBySource(cc *clientConn, src [PubKeySize]byte) int {
	cc.srcMu.Lock()
	defer cc.srcMu.Unlock()
	return cc.srcQueued[src]
}

// One source that filled a destination's queue while alone must give slots
// back once another source is being dropped: as the writer drains, the
// flooding source is held at sourceQueueCap and the rest goes to the peer
// that had none.
func TestSourceCapYieldsToStarvedSource(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	cc := newClientConn(pubkey(60), server) // no writer: the queue only moves when the test drains it
	flooder, starved := pubkey(61), pubkey(62)

	for i := 0; i < sendQueueDepth+8; i++ {
		if err := cc.writeFrame(MakeDataFrame(flooder, seqDataPacket(i))); err != nil {
			t.Fatalf("flood %d: %v", i, err)
		}
	}
	if got := queuedBySource(cc, flooder); got != sendQueueDepth {
		t.Fatalf("a lone source holds %d slots, want the whole queue (%d)", got, sendQueueDepth)
	}

	// The second source arrives to a full queue and is tail-dropped.
	if err := cc.writeFrame(MakeDataFrame(starved, seqDataPacket(0))); err != nil {
		t.Fatalf("starved write: %v", err)
	}
	if got := queuedBySource(cc, starved); got != 0 {
		t.Fatalf("starved source holds %d slots in a full queue, want 0", got)
	}

	// The writer frees 100 slots; both sources then compete for them.
	for i := 0; i < 100; i++ {
		if _, _, ok := cc.nextQueued(); !ok {
			t.Fatalf("queue empty after %d dequeues", i)
		}
	}
	for i := 0; i < 100; i++ {
		_ = cc.writeFrame(MakeDataFrame(flooder, seqDataPacket(i)))
	}
	if got := queuedBySource(cc, flooder); got != sourceQueueCap {
		t.Fatalf("flooder holds %d slots while another source is starved, want the cap (%d)", got, sourceQueueCap)
	}
	for i := 0; i < sendQueueDepth; i++ {
		_ = cc.writeFrame(MakeDataFrame(starved, seqDataPacket(i)))
	}
	if got, want := queuedBySource(cc, starved), sendQueueDepth-sourceQueueCap; got != want {
		t.Fatalf("starved source holds %d slots, want the reserved %d", got, want)
	}
	if got := len(cc.dataQ); got != sendQueueDepth {
		t.Fatalf("dataQ len = %d, want %d", got, sendQueueDepth)
	}

	// Draining everything returns every reservation.
	cc.drainQueues()
	if a, b := queuedBySource(cc, flooder), queuedBySource(cc, starved); a != 0 || b != 0 {
		t.Fatalf("reservations left after drain: flooder=%d starved=%d", a, b)
	}
}

// The relay echoes keepalives so a client can tell a dead inbound direction
// from an idle connection, and the echo is not held behind a data backlog.
func TestServerEchoesKeepalive(t *testing.T) {
	s := NewServer()
	conn := connectPeer(t, s, pubkey(63))
	if err := WriteFrame(conn, MakeKeepaliveFrame()); err != nil {
		t.Fatalf("write keepalive: %v", err)
	}
	if frame := readFrameWithin(t, conn, 5*time.Second); frame.Type != MsgKeepalive {
		t.Fatalf("got frame type %d, want keepalive echo", frame.Type)
	}
}
