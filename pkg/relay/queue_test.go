package relay

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// wgPacket fakes a WireGuard message: a little-endian uint32 type followed by
// enough bytes to reach that type's fixed size. Handshake messages are
// recognised by type and length together, so a plausible length matters.
func wgPacket(msgType byte) []byte {
	size := 64
	switch msgType {
	case wgMessageInitiation:
		size = wgInitiationLen
	case wgMessageResponse:
		size = wgResponseLen
	case wgMessageCookie:
		size = wgCookieReplyLen
	}
	p := make([]byte, size)
	p[0] = msgType
	return p
}

// wgPacketSized builds a message of an arbitrary length, for the cases where
// the length is the thing under test.
func wgPacketSized(msgType byte, size int) []byte {
	p := make([]byte, size)
	if size > 0 {
		p[0] = msgType
	}
	return p
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name  string
		frame Frame
		want  frameClass
	}{
		{"data: handshake initiation", MakeDataFrame(pubkey(1), wgPacket(1)), classCtrl},
		{"data: handshake response", MakeDataFrame(pubkey(1), wgPacket(2)), classCtrl},
		{"data: cookie reply", MakeDataFrame(pubkey(1), wgPacket(3)), classCtrl},
		{"data: transport data", MakeDataFrame(pubkey(1), wgPacket(4)), classData},
		{"data: empty payload", MakeDataFrame(pubkey(1), nil), classData},
		{"data: body shorter than a key", Frame{Type: MsgData, Body: []byte{1, 2, 3}}, classData},
		// The class is a scheduling lever and the payload comes from a
		// remote peer, so a frame that merely starts with a handshake type
		// is not one: the length and the upper type bytes must agree too.
		{"data: initiation type, wrong length", MakeDataFrame(pubkey(1), wgPacketSized(1, 200)), classData},
		{"data: initiation type, truncated", MakeDataFrame(pubkey(1), []byte{1}), classData},
		{"data: response type at initiation length", MakeDataFrame(pubkey(1), wgPacketSized(2, wgInitiationLen)), classData},
		{"data: nonzero upper type bytes", MakeDataFrame(pubkey(1), func() []byte {
			p := wgPacket(1)
			p[3] = 1
			return p
		}()), classData},
		{"external: handshake initiation", MakeExternalDataFrame(7, "203.0.113.1:51820", wgPacket(1)), classCtrl},
		{"external: cookie reply", MakeExternalDataFrame(7, "", wgPacket(3)), classCtrl},
		{"external: transport data", MakeExternalDataFrame(7, "203.0.113.1:51820", wgPacket(4)), classData},
		{"external: empty payload", MakeExternalDataFrame(7, "203.0.113.1:51820", nil), classData},
		{"external: malformed body", Frame{Type: MsgExternalData, Body: []byte{1}}, classData},
		{"bimodal hint", MakeBimodalHintFrame(pubkey(2)), classCtrl},
		{"nat probe", MakeNATProbeFrame(net.IPv4(203, 0, 113, 7), 3478), classCtrl},
		{"relay probe", MakeRelayProbeFrame(9), classCtrl},
		{"keepalive", MakeKeepaliveFrame(), classData},
		{"error", MakeErrorFrame("x"), classData},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.frame); got != tc.want {
				t.Fatalf("classify = %s, want %s", got, tc.want)
			}
		})
	}
}

// fillDataQueue enqueues past the data capacity on a connection with no
// writer, so dataQ is full and the overflow has been tail-dropped.
func fillDataQueue(t *testing.T, cc *clientConn) {
	t.Helper()
	for i := 0; i < sendQueueDepth+8; i++ {
		if err := cc.writeFrame(MakeKeepaliveFrame()); err != nil {
			t.Fatalf("writeFrame data %d: %v", i, err)
		}
	}
	if got := len(cc.dataQ); got != sendQueueDepth {
		t.Fatalf("dataQ len = %d, want full (%d)", got, sendQueueDepth)
	}
}

// A full data queue must not cost the destination its control frames: they
// have their own queue and the writer takes them first.
func TestClientConnCtrlFramesBypassFullDataQueue(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	cc := newClientConn(pubkey(1), serverSide)
	fillDataQueue(t, cc)
	droppedBefore := cc.dropped.Load()

	probe := MakeRelayProbeFrame(42)
	if err := cc.writeFrame(probe); err != nil {
		t.Fatalf("writeFrame ctrl: %v", err)
	}
	if got := len(cc.ctrlQ); got != 1 {
		t.Fatalf("ctrlQ len = %d, want 1", got)
	}
	if got := cc.dropped.Load(); got != droppedBefore {
		t.Fatalf("ctrl frame counted as dropped (%d -> %d); want ctrl queue untouched by data overflow", droppedBefore, got)
	}

	// Now let the writer run: the control frame must come out ahead of the
	// 256 data frames that were queued before it.
	go cc.writeLoop()
	defer cc.close()
	if err := clientSide.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	first, err := ReadFrame(bufio.NewReader(clientSide))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if first.Type != MsgRelayProbe {
		t.Fatalf("first delivered frame type = %#x, want MsgRelayProbe ahead of queued data", first.Type)
	}
}

// The control queue is bounded and tail-drops like the data queue; a stalled
// destination must not grow memory or block the sender through either queue.
func TestClientConnCtrlQueueTailDrops(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	cc := newClientConn(pubkey(1), serverSide)
	start := time.Now()
	for i := 0; i < ctrlQueueDepth*2; i++ {
		if err := cc.writeFrame(MakeBimodalHintFrame(pubkey(2))); err != nil {
			t.Fatalf("writeFrame ctrl %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("writeFrame blocked for %s on a full ctrl queue", elapsed)
	}
	if got := len(cc.ctrlQ); got != ctrlQueueDepth {
		t.Fatalf("ctrlQ len = %d, want %d", got, ctrlQueueDepth)
	}
	if got := cc.dropped.Load(); got != uint64(ctrlQueueDepth) {
		t.Fatalf("dropped = %d, want %d (tail drop past ctrl capacity)", got, ctrlQueueDepth)
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// readDataFrom reads one MsgData frame from src and returns its WireGuard
// payload.
func readDataFrom(t *testing.T, conn net.Conn, src [PubKeySize]byte) []byte {
	t.Helper()
	frame := readFrameWithin(t, conn, 5*time.Second)
	if frame.Type != MsgData {
		t.Fatalf("frame type = %#x, want MsgData", frame.Type)
	}
	from, payload, err := ParseDataFrame(frame.Body)
	if err != nil {
		t.Fatalf("ParseDataFrame: %v", err)
	}
	if from != src {
		t.Fatalf("src = %x, want %x", from[:4], src[:4])
	}
	return payload
}

// seqDataPacket is a transport-data packet carrying a sequence number just
// after the 4-byte type field, so the test can assert delivery order.
func seqDataPacket(i int) []byte {
	p := wgPacket(4)
	p[4], p[5] = byte(i>>8), byte(i)
	return p
}

func packetSeq(payload []byte) int {
	return int(payload[4])<<8 | int(payload[5])
}

// End to end through the MsgData handler: peer A floods B with transport data
// that B is not reading, then sends a handshake initiation. B's writer takes
// one batch into its bufio buffer and blocks on the pipe; everything after
// that fills dataQ (256) and then tail-drops, so by the time the handshake is
// enqueued the data queue is provably full. With one FIFO queue the handshake
// would be dropped or come out last; with the split it must arrive and be
// followed by the 256 data frames that were already waiting.
func TestServerHandshakeNotStarvedByDataBacklog(t *testing.T) {
	s := NewServer()
	keyA, keyB := pubkey(21), pubkey(22)
	connA := connectPeer(t, s, keyA)
	connB := connectPeer(t, s, keyB)

	s.mu.RLock()
	ccB := s.peers[keyB]
	s.mu.RUnlock()

	// Larger than one maximal batch plus the queue, so the queue fills no
	// matter how much of the flood the first batch absorbed.
	const flood = (ctrlQueueDepth + sendQueueDepth) + sendQueueDepth + 16
	for i := 0; i < flood; i++ {
		payload := seqDataPacket(i)
		if err := WriteFrame(connA, MakeDataFrame(keyB, payload)); err != nil {
			t.Fatalf("send data %d: %v", i, err)
		}
	}
	waitFor(t, "B's data queue to fill", func() bool { return len(ccB.dataQ) == sendQueueDepth })

	if err := WriteFrame(connA, MakeDataFrame(keyB, wgPacket(1))); err != nil {
		t.Fatalf("send handshake: %v", err)
	}
	waitFor(t, "handshake to be queued as ctrl", func() bool { return len(ccB.ctrlQ) == 1 })

	// Drain the first batch (whatever the writer buffered before blocking),
	// then the handshake must be next.
	dataBefore := 0
	for {
		payload := readDataFrom(t, connB, keyA)
		if payload[0] == wgMessageInitiation {
			break
		}
		dataBefore++
		if dataBefore > ctrlQueueDepth+sendQueueDepth {
			t.Fatalf("read %d data frames and no handshake; ctrl is being starved by data", dataBefore)
		}
	}
	// The 256 frames that were queued when the handshake arrived come after
	// it, in order.
	for i := 0; i < sendQueueDepth; i++ {
		payload := readDataFrom(t, connB, keyA)
		seq := packetSeq(payload)
		if payload[0] != 4 || seq != dataBefore+i {
			t.Fatalf("frame after handshake #%d: type %d seq %d, want data seq %d", i, payload[0], seq, dataBefore+i)
		}
	}

	destB := destLabel(keyB)
	dropped := ccB.dropped.Load()
	if dropped == 0 {
		t.Fatal("no tail drops recorded although the flood exceeded queue capacity")
	}
	if got := testutil.ToFloat64(relayFramesDropped.WithLabelValues("queue_tail", "data", destB)); got != float64(dropped) {
		t.Fatalf("dropped{queue_tail,data} = %v, want %d (same as the in-memory counter)", got, dropped)
	}
	if got := testutil.ToFloat64(relayFramesDropped.WithLabelValues("queue_tail", "ctrl", destB)); got != 0 {
		t.Fatalf("dropped{queue_tail,ctrl} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(relayFramesForwarded.WithLabelValues("ctrl", destB)); got != 1 {
		t.Fatalf("forwarded{ctrl} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(relayFramesForwarded.WithLabelValues("data", destB)); got+float64(dropped) != flood {
		t.Fatalf("forwarded{data} + dropped = %v + %d, want every flood frame (%d) accounted once", got, dropped, flood)
	}
}

// destSeries reports whether any series on the per-destination vectors
// carries dest. It gathers through a private registry so the check does not
// create the series it is looking for.
func destSeries(t *testing.T, dest string) bool {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	for _, c := range []prometheus.Collector{relayFramesDropped, relayFramesForwarded, relayQueueDepth} {
		if err := reg.Register(c); err != nil {
			t.Fatalf("register collector: %v", err)
		}
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "dest" && lp.GetValue() == dest {
					return true
				}
			}
		}
	}
	return false
}

// The dest label exists only for registered local peers: a key that a sender
// merely names never becomes a label, and a peer's series go away when it
// disconnects.
func TestRelayMetricsDestLabelLifecycle(t *testing.T) {
	s := NewServer()
	keyA, keyB, unknown := pubkey(31), pubkey(32), pubkey(33)
	connA := connectPeer(t, s, keyA)

	missesBefore := testutil.ToFloat64(relayFramesDroppedUnknownDest)
	if err := WriteFrame(connA, MakeDataFrame(unknown, wgPacket(4))); err != nil {
		t.Fatalf("send to unknown: %v", err)
	}
	if err := WriteFrame(connA, MakeBimodalHintFrame(unknown)); err != nil {
		t.Fatalf("hint to unknown: %v", err)
	}
	waitFor(t, "unknown-dest drops to be counted", func() bool {
		return testutil.ToFloat64(relayFramesDroppedUnknownDest)-missesBefore == 2
	})
	if destSeries(t, destLabel(unknown)) {
		t.Fatalf("series with dest=%s exist for a key that never registered", destLabel(unknown))
	}

	connB := connectPeer(t, s, keyB)
	destB := destLabel(keyB)
	if !destSeries(t, destB) {
		t.Fatalf("no series with dest=%s after B registered", destB)
	}

	if err := WriteFrame(connA, MakeDataFrame(keyB, wgPacket(4))); err != nil {
		t.Fatalf("send to B: %v", err)
	}
	if frame := readFrameWithin(t, connB, 5*time.Second); frame.Type != MsgData {
		t.Fatalf("B got frame type %#x, want MsgData", frame.Type)
	}
	if got := testutil.ToFloat64(relayFramesForwarded.WithLabelValues("data", destB)); got != 1 {
		t.Fatalf("forwarded{data,%s} = %v, want 1", destB, got)
	}

	_ = connB.Close()
	waitFor(t, "B to deregister", func() bool { return s.ConnectedPeers() == 1 })
	if destSeries(t, destB) {
		t.Fatalf("series with dest=%s survived B's disconnect", destB)
	}
	if !destSeries(t, destLabel(keyA)) {
		t.Fatalf("A's series were removed along with B's")
	}
}

// Drops on the two non-overflow paths carry their own reason so an operator
// can tell "queue full" from "peer already gone" from "socket refused bytes".
func TestClientConnDropReasons(t *testing.T) {
	t.Run("gone", func(t *testing.T) {
		serverSide, clientSide := net.Pipe()
		defer clientSide.Close()
		cc := newClientConn(pubkey(41), serverSide)
		cc.metrics = newConnMetrics(destLabel(cc.pubKey))
		defer deleteDestMetrics(destLabel(cc.pubKey))
		cc.close()

		if err := cc.writeFrame(MakeBimodalHintFrame(pubkey(1))); err == nil {
			t.Fatal("writeFrame on closed conn returned nil")
		}
		if got := testutil.ToFloat64(cc.metrics.dropped[classCtrl][dropGone]); got != 1 {
			t.Fatalf("dropped{gone,ctrl} = %v, want 1", got)
		}
	})

	t.Run("write_error", func(t *testing.T) {
		serverSide, clientSide := net.Pipe()
		cc := newClientConn(pubkey(42), serverSide)
		cc.metrics = newConnMetrics(destLabel(cc.pubKey))
		defer deleteDestMetrics(destLabel(cc.pubKey))
		// Closing the reader makes the next pipe write fail outright.
		_ = clientSide.Close()
		go cc.writeLoop()
		defer cc.close()

		if err := cc.writeFrame(MakeKeepaliveFrame()); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
		waitFor(t, "write error to be counted", func() bool {
			return testutil.ToFloat64(cc.metrics.dropped[classData][dropWriteError]) == 1
		})
	})
}

// Series naming and label conventions stay lint-clean so the endpoint is
// safe to hand to promtool.
func TestRelayMetricsLint(t *testing.T) {
	for _, c := range []prometheus.Collector{relayFramesDropped, relayFramesDroppedUnknownDest, relayFramesForwarded, relayClients, relayQueueDepth} {
		problems, err := testutil.CollectAndLint(c)
		if err != nil {
			t.Fatalf("lint: %v", err)
		}
		for _, p := range problems {
			t.Errorf("%s: %s", p.Metric, p.Text)
		}
	}
}

// The client gauge counts peers, not connections: a reconnect that displaces a
// live session leaves the count alone and must not take the peer's series with
// it when the displaced connection tears down. register/unregister are driven
// directly here so no other test's asynchronous teardown can move the
// process-global gauge underneath the assertions.
func TestRelayClientsGaugeAndReplace(t *testing.T) {
	s := NewServer()
	key := pubkey(41)
	before := testutil.ToFloat64(relayClients)

	firstSrv, firstCli := net.Pipe()
	defer firstCli.Close()
	first := newClientConn(key, firstSrv)
	if _, replaced := s.register(first); replaced {
		t.Fatal("first registration reported a replacement")
	}
	if got := testutil.ToFloat64(relayClients) - before; got != 1 {
		t.Fatalf("clients delta after first register = %v, want 1", got)
	}

	secondSrv, secondCli := net.Pipe()
	defer secondCli.Close()
	second := newClientConn(key, secondSrv)
	old, replaced := s.register(second)
	if !replaced || old != first {
		t.Fatalf("second registration replaced=%v old=%p, want true and the first conn (%p)", replaced, old, first)
	}
	if got := testutil.ToFloat64(relayClients) - before; got != 1 {
		t.Fatalf("clients delta after replace = %v, want 1 (same peer, not two)", got)
	}

	// The displaced connection tears down; the live one keeps its series.
	if s.unregister(first) {
		t.Fatal("unregister of the displaced conn removed the live registration")
	}
	if got := testutil.ToFloat64(relayClients) - before; got != 1 {
		t.Fatalf("clients delta after displaced teardown = %v, want 1", got)
	}
	if !destSeries(t, destLabel(key)) {
		t.Fatal("the live connection's series were removed by the displaced conn's teardown")
	}

	if !s.unregister(second) {
		t.Fatal("unregister of the live conn reported no change")
	}
	if got := testutil.ToFloat64(relayClients) - before; got != 0 {
		t.Fatalf("clients delta after the peer left = %v, want 0", got)
	}
	if destSeries(t, destLabel(key)) {
		t.Fatal("series survived the peer's last connection")
	}
}

// Control priority must be bounded, not absolute. The class is decided from
// payload bytes a remote peer chose and relay registration is unauthenticated,
// so with strict priority one peer could hold a destination's data throughput
// at exactly zero by sending frames shaped like handshakes faster than the
// destination drains.
func TestClientConnCtrlDoesNotStarveData(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	cc := newClientConn(pubkey(51), serverSide)
	// Both queues full: control is the flood, data is the victim's traffic.
	for i := 0; i < ctrlQueueDepth; i++ {
		if err := cc.writeFrame(MakeDataFrame(pubkey(52), wgPacket(1))); err != nil {
			t.Fatalf("writeFrame ctrl %d: %v", i, err)
		}
	}
	for i := 0; i < sendQueueDepth; i++ {
		if err := cc.writeFrame(MakeDataFrame(pubkey(52), seqDataPacket(i))); err != nil {
			t.Fatalf("writeFrame data %d: %v", i, err)
		}
	}
	if len(cc.ctrlQ) != ctrlQueueDepth || len(cc.dataQ) != sendQueueDepth {
		t.Fatalf("setup: ctrlQ=%d dataQ=%d, want both full", len(cc.ctrlQ), len(cc.dataQ))
	}

	go cc.writeLoop()
	defer cc.close()
	if err := clientSide.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	r := bufio.NewReader(clientSide)

	// Read enough frames that strict priority would have produced control
	// only, and require the bound to have let data through.
	const reads = maxCtrlStreak * 4
	streak, maxSeen, dataSeen := 0, 0, 0
	for i := 0; i < reads; i++ {
		frame, err := ReadFrame(r)
		if err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if classify(frame) == classCtrl {
			streak++
			if streak > maxSeen {
				maxSeen = streak
			}
			continue
		}
		streak = 0
		dataSeen++
	}
	if dataSeen == 0 {
		t.Fatalf("no data frame in %d writes while control was saturated; data throughput is zero", reads)
	}
	if maxSeen > maxCtrlStreak {
		t.Fatalf("control ran %d frames back to back, want at most %d", maxSeen, maxCtrlStreak)
	}
}

// Frames still queued when the writer goes away are accounted, so the dropped
// total stays an answer to "frames this relay accepted and did not deliver".
func TestClientConnTeardownCountsQueuedFrames(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	s := NewServer()
	key := pubkey(61)
	cc := newClientConn(key, serverSide)
	if _, replaced := s.register(cc); replaced {
		t.Fatal("unexpected replacement")
	}
	defer s.unregister(cc)
	dest := destLabel(key)

	const ctrlQueued, dataQueued = 3, 5
	for i := 0; i < ctrlQueued; i++ {
		if err := cc.writeFrame(MakeBimodalHintFrame(pubkey(62))); err != nil {
			t.Fatalf("writeFrame ctrl %d: %v", i, err)
		}
	}
	for i := 0; i < dataQueued; i++ {
		if err := cc.writeFrame(MakeKeepaliveFrame()); err != nil {
			t.Fatalf("writeFrame data %d: %v", i, err)
		}
	}

	cc.close()

	if got := testutil.ToFloat64(relayFramesDropped.WithLabelValues("shutdown", "ctrl", dest)); got != ctrlQueued {
		t.Fatalf("dropped{shutdown,ctrl} = %v, want %d", got, ctrlQueued)
	}
	if got := testutil.ToFloat64(relayFramesDropped.WithLabelValues("shutdown", "data", dest)); got != dataQueued {
		t.Fatalf("dropped{shutdown,data} = %v, want %d", got, dataQueued)
	}
	// The depth gauges follow the drain rather than latching at the peak.
	if got := testutil.ToFloat64(relayQueueDepth.WithLabelValues("ctrl", dest)); got != 0 {
		t.Fatalf("queue_depth{ctrl} = %v after teardown, want 0", got)
	}
	if got := testutil.ToFloat64(relayQueueDepth.WithLabelValues("data", dest)); got != 0 {
		t.Fatalf("queue_depth{data} = %v after teardown, want 0", got)
	}
}
