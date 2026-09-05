package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/inerplat/wirekube/pkg/relay/portalloc"
)

var relayDebug = os.Getenv("WIREKUBE_RELAY_DEBUG") == "1"

// NAT probe rate limiting. Legitimate probing is rare (startup plus periodic
// re-classification), so a modest global cap keeps the relay from being abused
// as a UDP reflector while never throttling real traffic. Each allowed probe
// emits two ~19-byte datagrams, so even at the sustained cap the reflected
// volume is negligible.
//
// The cap is global, not per-peer: it bounds a mesh of up to ~100 agents
// probing simultaneously at startup. Beyond that, some legitimate probes are
// dropped and the affected agents fall back to conservative NAT classification
// until the next re-classification cycle (a slow degradation, not a failure).
// Per-peer fairness — so one peer cannot starve others — requires trusted peer
// identity and is deferred to control-plane authentication.
const (
	probeRateLimit = 100 // probes per second, sustained
	probeRateBurst = 100
)

// Server is a WireKube relay server that forwards WireGuard UDP packets
// between agents connected over TCP. Agents register with their WireGuard
// public key; the server routes Data frames by destination public key.
//
// External-peer support includes a shared raw-WireGuard UDP listener for
// official clients and a legacy per-peer UDP Forwarder for older allocations.
// The Server itself implements IngressDispatcher.
type Server struct {
	mu    sync.RWMutex
	peers map[[PubKeySize]byte]*clientConn

	// probeConn is a UDP socket bound to the relay's listen port for sending
	// NAT verification probes. Agents open their NAT filter for this port,
	// so a probe from here distinguishes "firewall blocked" from "NAT blocked".
	probeConn *net.UDPConn

	// probeSem limits concurrent NAT probe goroutines to prevent unbounded
	// goroutine creation from rapid probe requests.
	probeSem chan struct{}

	// probeLimiter caps the sustained NAT-probe rate across all peers so the
	// relay cannot be driven as a UDP reflector by an unauthenticated flood of
	// probe frames on the public control port.
	probeLimiter *rate.Limiter

	// forwarder + alloc handle external-peer traffic. Both may be nil if
	// the operator opted out of external-peer support; in that case the
	// server replies with MsgError on 0x10/0x11 control frames so the
	// reconciler reports a clear failure.
	forwarder *Forwarder
	alloc     *portalloc.Allocator

	externalWG *ExternalWGListener
	probeSeq   atomic.Uint64

	// cluster, when non-nil, forwards frames for peers whose TCP session
	// lives on another relay replica. Nil on single-replica deployments.
	cluster *Cluster

	// destMissLog throttles the dest-not-found line. Dead peers attract
	// warm-relay traffic from the entire mesh, and logging every miss at
	// mesh scale (hundreds/sec) once starved this process through the
	// global log mutex.
	destMissLog *suppressedLogger
}

// sendQueueDepth bounds how many data frames may be waiting for one
// destination. Frames are WireGuard packets, which the transport layer above
// already treats as lossy, so overflow drops the newest frame rather than
// stalling the sender. The depth only needs to cover a short scheduling
// hiccup; a destination that stays behind for longer is genuinely broken and
// dropping is the correct answer.
const sendQueueDepth = 256

// ctrlQueueDepth bounds the separate control queue. Control frames are rare
// (handshakes, hints, probes) but each one gates the peer's ability to move
// traffic at all, so they must not wait behind a data backlog that is mostly
// duplicates the receiver would discard anyway. Same tail-drop policy: a
// destination whose control queue overflows is not draining at all.
const ctrlQueueDepth = 64

// dropLogInterval rate-limits the overflow warning. Without it a single
// wedged destination would reproduce the log flood this queue exists to
// prevent.
const dropLogInterval = 10 * time.Second

// frameClass decides which of a destination's two queues a frame joins.
type frameClass uint8

const (
	classData frameClass = iota
	classCtrl
	frameClassCount
)

func (c frameClass) String() string {
	if c == classCtrl {
		return "ctrl"
	}
	return "data"
}

// WireGuard message types occupy the first byte of every packet (the type is
// a little-endian uint32 with values 1..4). Handshake initiation, response
// and cookie reply are control; transport data is everything a queue can
// afford to lose.
const (
	wgMessageInitiation byte = 1
	wgMessageResponse   byte = 2
	wgMessageCookie     byte = 3

	// Fixed sizes of the three handshake messages, from wireguard-go's
	// device/noise-protocol.go (MessageInitiationSize, MessageResponseSize,
	// MessageCookieReplySize). A handshake is never any other length, so the
	// length is part of recognising one.
	wgInitiationLen  = 148
	wgResponseLen    = 92
	wgCookieReplyLen = 64
)

// classify is the single point that decides a frame's queue. writeFrame calls
// it, so every enqueue path is covered without each call site knowing about
// the split. Relay control messages are control by type; Data and
// ExternalData are control only when the WireGuard payload they carry is a
// handshake message. Anything malformed or empty is data: the split exists to
// protect control frames, not to reject traffic.
func classify(frame Frame) frameClass {
	switch frame.Type {
	case MsgBimodalHint, MsgNATProbe, MsgRelayProbe:
		// MsgNATProbe never reaches a queue in practice (the relay answers
		// NAT probes over UDP), but the class belongs with the other control
		// types rather than as a gap a future caller has to notice.
		return classCtrl
	case MsgData:
		if len(frame.Body) > PubKeySize {
			return classifyWGPayload(frame.Body[PubKeySize:])
		}
	case MsgExternalData:
		if _, _, payload, err := ParseExternalDataFrame(frame.Body); err == nil {
			return classifyWGPayload(payload)
		}
	}
	return classData
}

// classifyWGPayload recognises a WireGuard handshake message. The class is a
// scheduling decision made from bytes a remote peer chose, and relay
// registration is unauthenticated, so the check is as narrow as the wire
// format allows: the message type is a 4-byte little-endian field (the upper
// three bytes are always zero), and each handshake type has one fixed length.
// A transport data frame (type 4) or anything malformed is data. This does not
// make the class unforgeable, which is why the writer also bounds how many
// control frames may run back to back.
func classifyWGPayload(payload []byte) frameClass {
	if len(payload) < 4 || payload[1]|payload[2]|payload[3] != 0 {
		return classData
	}
	switch payload[0] {
	case wgMessageInitiation:
		if len(payload) == wgInitiationLen {
			return classCtrl
		}
	case wgMessageResponse:
		if len(payload) == wgResponseLen {
			return classCtrl
		}
	case wgMessageCookie:
		if len(payload) == wgCookieReplyLen {
			return classCtrl
		}
	}
	return classData
}

type clientConn struct {
	pubKey [PubKeySize]byte
	conn   net.Conn
	writer *bufio.Writer

	// The queues decouple "a peer wants to send to this destination" from
	// "this destination's socket accepts bytes". Before they existed,
	// writeFrame ran synchronously inside the *sending* peer's read loop
	// while holding this connection's write mutex, so one slow destination
	// blocked every peer trying to reach it, and those peers then could not
	// forward to any other destination either. A single stalled socket froze
	// the whole relay for as long as the write deadline allowed.
	//
	// ctrlQ is drained before dataQ. A destination that cannot keep up with
	// mirrored data traffic used to lose its handshakes and probes in the
	// same tail drop, which turned a congested link into a dead session.
	ctrlQ     chan Frame
	dataQ     chan Frame
	done      chan struct{}
	closeOnce sync.Once

	// ctrlStreak counts control frames written back to back. Owned by the
	// writer goroutine alone, so it needs no synchronisation.
	ctrlStreak int

	dropped     atomic.Uint64
	dropLogMu   sync.Mutex
	lastDropLog time.Time

	// metrics is set under Server.mu when the peer registers and stays nil
	// for connections that never register (tests, one-shot control
	// sessions). The per-frame path tolerates nil.
	metrics *connMetrics

	probeMu sync.Mutex
	probes  map[uint64]chan struct{}
}

var relayClientWriteTimeout = 2 * time.Second

func newClientConn(pubKey [PubKeySize]byte, conn net.Conn) *clientConn {
	return &clientConn{
		pubKey: pubKey,
		conn:   conn,
		writer: bufio.NewWriterSize(conn, 64*1024),
		ctrlQ:  make(chan Frame, ctrlQueueDepth),
		dataQ:  make(chan Frame, sendQueueDepth),
		done:   make(chan struct{}),
	}
}

func (c *clientConn) queueFor(class frameClass) chan Frame {
	if class == classCtrl {
		return c.ctrlQ
	}
	return c.dataQ
}

// writeFrame hands a frame to this connection's writer goroutine. It never
// blocks and never reports a full queue as an error: the caller is another
// peer's read loop, and making it wait here is exactly the head-of-line
// blocking this design removes. A closed connection is still an error so
// callers can drop the peer.
func (c *clientConn) writeFrame(frame Frame) error {
	class := classify(frame)

	select {
	case <-c.done:
		c.countDrop(class, dropGone)
		return net.ErrClosed
	default:
	}

	q := c.queueFor(class)
	select {
	case q <- frame:
		if m := c.metrics; m != nil {
			m.forwarded[class].Inc()
			m.depth[class].Set(float64(len(q)))
		}
		return nil
	default:
		c.noteDrop(class)
		return nil
	}
}

func (c *clientConn) countDrop(class frameClass, reason dropReason) {
	if m := c.metrics; m != nil {
		m.dropped[class][reason].Inc()
	}
}

func (c *clientConn) noteDrop(class frameClass) {
	total := c.dropped.Add(1)
	c.countDrop(class, dropQueueTail)

	c.dropLogMu.Lock()
	defer c.dropLogMu.Unlock()
	now := time.Now()
	if now.Sub(c.lastDropLog) < dropLogInterval {
		return
	}
	c.lastDropLog = now
	log.Printf("relay: send queue full for %x, dropping frames (total dropped %d, class %s)", c.pubKey[:8], total, class)
}

// writeLoop is the only goroutine that touches the socket's write side, so
// the per-connection write mutex is gone along with the contention it caused.
// Control frames are taken first whenever one is waiting; data is only
// considered when the control queue is empty.
func (c *clientConn) writeLoop() {
	defer c.close()
	for {
		select {
		case <-c.done:
			return
		default:
		}
		if frame, class, ok := c.nextQueued(); ok {
			if err := c.writeBatch(frame, class); err != nil {
				return
			}
			continue
		}
		// Both queues are empty, so there is nothing to prioritise between.
		select {
		case <-c.done:
			return
		case frame := <-c.ctrlQ:
			c.noteDequeued(classCtrl)
			if err := c.writeBatch(frame, classCtrl); err != nil {
				return
			}
		case frame := <-c.dataQ:
			c.noteDequeued(classData)
			if err := c.writeBatch(frame, classData); err != nil {
				return
			}
		}
	}
}

// maxCtrlStreak bounds how many control frames the writer may send back to
// back before it forces one data frame through. Control still wins every
// honest burst, which is a handful of handshake retries and never approaches
// this many. The bound exists because the class is decided from bytes a
// remote peer chose and relay registration is unauthenticated: with strict
// priority, one peer sending frames shaped like handshakes faster than a
// destination drains would hold that destination's data throughput at exactly
// zero while its handshakes kept flowing, which looks healthy from both ends.
const maxCtrlStreak = 8

// nextQueued pops the next frame to write without blocking: control before
// data, except when control has already had maxCtrlStreak frames in a row and
// data is waiting.
func (c *clientConn) nextQueued() (Frame, frameClass, bool) {
	if c.ctrlStreak < maxCtrlStreak {
		select {
		case frame := <-c.ctrlQ:
			c.ctrlStreak++
			c.noteDequeued(classCtrl)
			return frame, classCtrl, true
		default:
		}
	}
	select {
	case frame := <-c.dataQ:
		c.ctrlStreak = 0
		c.noteDequeued(classData)
		return frame, classData, true
	default:
	}
	// No data to be fair to, so a held-back control frame goes now.
	select {
	case frame := <-c.ctrlQ:
		c.ctrlStreak++
		c.noteDequeued(classCtrl)
		return frame, classCtrl, true
	default:
	}
	return Frame{}, classData, false
}

// noteDequeued resamples the depth gauge as the queue drains. Sampling only on
// enqueue leaves a peer that took one burst and went idle reporting that
// burst's depth forever, which is the reading an operator would alert on.
func (c *clientConn) noteDequeued(class frameClass) {
	if m := c.metrics; m != nil {
		m.depth[class].Set(float64(len(c.queueFor(class))))
	}
}

// writeBatch writes the frame plus whatever else is already queued, then
// flushes once. Coalescing matters here: warm-bimodal peers deliver frames in
// bursts, and one flush per burst keeps the syscall count off the critical
// path.
func (c *clientConn) writeBatch(first Frame, firstClass frameClass) error {
	// Frames sit in the bufio buffer until Flush, so a dead socket usually
	// surfaces there (or already at SetWriteDeadline) rather than at the
	// write that filled the buffer. Every frame handed to the writer in this
	// batch is charged to write_error when any step fails; the batch is
	// bounded, so the overcount when bufio flushed part of it on its own is
	// bounded too.
	var buffered [frameClassCount]uint64
	failBatch := func(err error) error {
		for class, n := range buffered {
			for ; n > 0; n-- {
				c.countDrop(frameClass(class), dropWriteError)
			}
		}
		return err
	}
	buffered[firstClass]++

	if relayClientWriteTimeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(relayClientWriteTimeout)); err != nil {
			return failBatch(err)
		}
		defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	}

	if err := WriteFrame(c.writer, first); err != nil {
		return failBatch(err)
	}
	// Bounded by the combined queue capacity so the deadline above stays
	// meaningful: producers can refill the queues while we drain them, and an
	// unbounded loop would let one batch run arbitrarily long under a single
	// deadline.
	for i := 1; i < ctrlQueueDepth+sendQueueDepth; i++ {
		next, class, ok := c.nextQueued()
		if !ok {
			break
		}
		buffered[class]++
		if err := WriteFrame(c.writer, next); err != nil {
			return failBatch(err)
		}
	}
	if err := c.writer.Flush(); err != nil {
		return failBatch(err)
	}
	return nil
}

func (c *clientConn) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close()
		// Whatever the writer had not reached is gone with the socket.
		// Counting it keeps the dropped total an accurate answer to "frames
		// this relay accepted and did not deliver"; producers that enqueue
		// after this point still race the writer and are charged when their
		// own send sees the closed connection.
		c.drainQueues()
	})
}

// drainQueues empties both queues and charges the remainder to shutdown. Safe
// to run concurrently with a producer's enqueue: a frame that lands after the
// drain sits in a buffered channel nobody reads, and the channel is garbage
// once the connection is dropped.
func (c *clientConn) drainQueues() {
	for _, class := range []frameClass{classCtrl, classData} {
		q := c.queueFor(class)
		for {
			select {
			case <-q:
				c.countDrop(class, dropShutdown)
			default:
				c.noteDequeued(class)
				goto next
			}
		}
	next:
	}
}

func (s *Server) dropPeer(c *clientConn) {
	c.close()
	s.unregister(c)
}

// register makes cc the connection for its key and returns the connection it
// replaced, if any. The metric children are created under the same lock that
// unregister deletes them under, so a reconnect cannot lose its series to the
// old connection's teardown.
func (s *Server) register(cc *clientConn) (old *clientConn, replaced bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, replaced = s.peers[cc.pubKey]
	s.peers[cc.pubKey] = cc
	cc.metrics = newConnMetrics(destLabel(cc.pubKey))
	// Delta rather than Set(len(s.peers)): the gauge is process-global while
	// the count is one Server's, so setting it makes two Servers in one
	// process (the test binary) overwrite each other. A reconnect that
	// replaces a live connection leaves the peer count unchanged.
	if !replaced {
		relayClients.Inc()
	}
	return old, replaced
}

// unregister removes c from the peer table if it is still the registered
// connection for its key, and reports whether it was. A connection that was
// already replaced by a reconnect leaves the table, the registry entry and
// the metrics of the new connection alone.
func (s *Server) unregister(c *clientConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peers[c.pubKey] != c {
		return false
	}
	delete(s.peers, c.pubKey)
	deleteDestMetrics(destLabel(c.pubKey))
	relayClients.Dec()
	return true
}

func NewServer() *Server {
	return &Server{
		peers:        make(map[[PubKeySize]byte]*clientConn),
		probeSem:     make(chan struct{}, 16),
		probeLimiter: rate.NewLimiter(probeRateLimit, probeRateBurst),
		destMissLog:  newSuppressedLogger(time.Second),
	}
}

// EnableCluster joins this server to the replica mesh. Frames for peers not
// connected here are forwarded to the owning replica, and envelopes arriving
// from sibling replicas are delivered to local peers. Must be called before
// ListenAndServe.
func (s *Server) EnableCluster(c *Cluster) {
	s.cluster = c
	c.deliver = s.deliverLocal
	c.deliverExtReply = func(token uint64, ingress [PubKeySize]byte, payload []byte) {
		if s.externalWG == nil {
			return
		}
		// This replica issued the token, so it owns the UDP flow. Pin the
		// flow to the agent that answered — later packets skip the fanout
		// and travel a single cluster hop straight to it.
		s.externalWG.BindTokenIngress(token, ingress)
		if err := s.externalWG.SendToExternal(token, payload); err != nil {
			s.destMissLog.Logf("relay cluster: external reply token=%d: %v", token, err)
		}
	}
	// Fanout needs only this replica's peer table, not its UDP listener, so
	// it works on replicas that run without --external-wg-addr too.
	c.deliverExtFanout = s.fanoutExternalLocal
}

// fanoutExternalLocal delivers a sibling replica's external fanout to LOCAL
// peers only. The cluster hop already happened; fanning out again would loop.
func (s *Server) fanoutExternalLocal(token uint64, srcAddr string, payload []byte) {
	s.mu.RLock()
	conns := make([]*clientConn, 0, len(s.peers))
	for _, cc := range s.peers {
		conns = append(conns, cc)
	}
	s.mu.RUnlock()
	frame := MakeExternalDataFrame(token, srcAddr, payload)
	for _, cc := range conns {
		if err := cc.writeFrame(frame); err != nil {
			s.dropPeer(cc)
		}
	}
}

// deliverLocal is the terminal hop for cluster envelopes: local delivery or
// drop, never another forward.
func (s *Server) deliverLocal(dest [PubKeySize]byte, inner Frame) bool {
	s.mu.RLock()
	peer, ok := s.peers[dest]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if err := peer.writeFrame(inner); err != nil {
		s.dropPeer(peer)
	}
	return true
}

// EnableForwarder wires a per-replica port allocator and a UDP forwarder
// for external-peer support. The Server implements IngressDispatcher so
// inbound external-peer datagrams are framed as Data and pushed to the
// selected ingress peer's TCP connection.
//
// Must be called before ListenAndServe. The portRangeLow/High pair bounds
// the allocator; pick a small dedicated range so it does not collide with
// ephemeral ports the host kernel may select for outbound connections.
func (s *Server) EnableForwarder(portRangeLow, portRangeHigh uint16) error {
	if s.forwarder != nil {
		return errors.New("relay: forwarder already enabled")
	}
	alloc, err := portalloc.New(portRangeLow, portRangeHigh)
	if err != nil {
		return fmt.Errorf("relay: portalloc: %w", err)
	}
	s.alloc = alloc
	s.forwarder = NewForwarder(s)
	return nil
}

// Dispatch implements IngressDispatcher. The relay framing for external
// → ingress places the EXTERNAL peer's pubkey in the Data frame's sender
// slot so the ingress peer's bind keys its peer table by external pubkey
// (matching the pubkey it learned from the WireKubeExternalPeer.status).
func (s *Server) Dispatch(ingress, external [PubKeySize]byte, payload []byte, _ netip.AddrPort) error {
	s.mu.RLock()
	dest, ok := s.peers[ingress]
	s.mu.RUnlock()
	if !ok {
		// The ingress agent may be connected to a sibling replica while the
		// external client's UDP landed here via the shared load balancer.
		if s.cluster != nil && s.cluster.ForwardToPeer(ingress, MakeDataFrame(external, payload)) {
			return nil
		}
		return fmt.Errorf("ingress %x not connected", ingress[:8])
	}
	out := MakeDataFrame(external, payload)
	if err := dest.writeFrame(out); err != nil {
		s.dropPeer(dest)
		return err
	}
	return nil
}

func (s *Server) ListenAndServe(addr string) error {
	lc := net.ListenConfig{
		Control: listenControl,
	}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	// Bind a UDP socket on the same port for NAT verification probes.
	// Agents send a UDP packet to this port to open their NAT filter,
	// then we probe back from THIS socket as a verification that the
	// path is reachable (distinguishes firewall from NAT restriction).
	tcpAddr := ln.Addr().(*net.TCPAddr)
	udpAddr := &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port}
	if s.externalWG != nil && sameUDPListenAddr(s.externalWG.conn.LocalAddr().(*net.UDPAddr), udpAddr) {
		s.probeConn = s.externalWG.conn
		log.Printf("relay: UDP probe listener reusing external WG socket on %s", udpAddr)
	} else {
		s.probeConn, err = net.ListenUDP("udp4", udpAddr)
		if err != nil {
			log.Printf("relay: warning: UDP probe listener on %s failed: %v (verification probes disabled)", udpAddr, err)
		} else {
			log.Printf("relay: UDP probe listener on %s", udpAddr)
			defer s.probeConn.Close()
		}
	}

	log.Printf("relay: listening on %s", addr)

	var acceptBackoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("relay: accept error: %v", err)
			if acceptBackoff == 0 {
				acceptBackoff = 5 * time.Millisecond
			} else {
				acceptBackoff *= 2
				if acceptBackoff > time.Second {
					acceptBackoff = time.Second
				}
			}
			time.Sleep(acceptBackoff)
			continue
		}
		acceptBackoff = 0
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	// Set fwmark on the accepted connection so reply packets bypass the
	// WireKube routing table. Linux does not inherit SO_MARK from the
	// listener socket to accepted connections.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) //nolint:errcheck
		if sc, err := tc.SyscallConn(); err == nil {
			_ = listenControl("", "", sc)
		}
	}
	reader := bufio.NewReader(conn)

	frame, err := ReadFrame(reader)
	if err != nil {
		// TCP health probes (kubelet liveness/readiness) connect and immediately
		// close without sending data — suppress the noisy EOF log for these.
		if err.Error() != "EOF" {
			log.Printf("relay: read register frame: %v", err)
		}
		return
	}
	// Legacy forwarder control frames open a one-shot session: the connection
	// carries a single request and a single response, then closes. The shared
	// raw-WireGuard external listener does not require these frames.
	if frame.Type == MsgForwarderRegister {
		s.handleForwarderRegister(conn, frame)
		return
	}
	if frame.Type == MsgForwarderUnregister {
		s.handleForwarderUnregister(conn, frame)
		return
	}
	if frame.Type == MsgIngressProbe {
		if s.forwarder == nil || s.alloc == nil {
			writer := bufio.NewWriter(conn)
			_ = WriteFrame(writer, MakeErrorFrame("relay control disabled"))
			_ = writer.Flush()
			return
		}
		s.handleIngressProbe(conn, frame)
		return
	}
	if frame.Type != MsgRegister {
		log.Printf("relay: expected register, got type %d", frame.Type)
		return
	}
	if len(frame.Body) != PubKeySize {
		log.Printf("relay: invalid pubkey length %d", len(frame.Body))
		return
	}

	var pubKey [PubKeySize]byte
	copy(pubKey[:], frame.Body)

	cc := newClientConn(pubKey, conn)
	old, exists := s.register(cc)
	go cc.writeLoop()

	if exists {
		old.close()
	}
	if s.cluster != nil {
		s.cluster.registry.PublishPeer(pubKey)
	}

	log.Printf("relay: peer registered: %x", pubKey[:8])
	defer func() {
		// Stop the writer goroutine too: the read loop exiting is what tells
		// us this peer is gone, and without this the goroutine would sit on
		// the queues until the next write error.
		cc.close()
		stillOwner := s.unregister(cc)
		// Withdraw only when this connection was still the registered one:
		// if a reconnect already replaced it, the peer is still local and
		// the registry entry must survive.
		if stillOwner && s.cluster != nil {
			s.cluster.registry.WithdrawPeer(pubKey)
		}
		if dropped := cc.dropped.Load(); dropped > 0 {
			log.Printf("relay: peer disconnected: %x (dropped %d frames)", pubKey[:8], dropped)
			return
		}
		log.Printf("relay: peer disconnected: %x", pubKey[:8])
	}()

	for {
		frame, err := ReadFrame(reader)
		if err != nil {
			return
		}

		switch frame.Type {
		case MsgData:
			destKey, payload, err := ParseDataFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad data frame: %v", err)
				continue
			}

			s.mu.RLock()
			dest, ok := s.peers[destKey]
			s.mu.RUnlock()

			if !ok {
				// External peers don't have a TCP relay session — they only
				// have a UDP forwarder mapping. Try to deliver the payload
				// over UDP to the last source addr observed for that
				// external pubkey. ErrUnknownPort means the dest really is
				// unknown (no TCP peer AND no forwarder mapping); anything
				// else is an unexpected I/O error worth logging.
				if s.forwarder != nil {
					if err := s.forwarder.SendToExternal(destKey, payload); err == nil {
						continue
					} else if !errors.Is(err, ErrUnknownPort) {
						log.Printf("relay: forwarder send to %x: %v", destKey[:8], err)
						continue
					}
				}
				// The dest may hold its TCP session on a sibling replica.
				if s.cluster != nil && s.cluster.ForwardToPeer(destKey, MakeDataFrame(pubKey, payload)) {
					continue
				}
				relayFramesDroppedUnknownDest.Inc()
				s.destMissLog.Logf("relay: data from %x to %x: dest not found", pubKey[:8], destKey[:8])
				continue
			}

			outFrame := MakeDataFrame(pubKey, payload)
			if err := dest.writeFrame(outFrame); err != nil {
				log.Printf("relay: forward error to %x: %v", destKey[:8], err)
				s.dropPeer(dest)
			}
			// Successful forwards intentionally not logged: a busy relay
			// (RelayModeAlways / warm-bimodal) can push tens of frames per
			// second per peer, which would dominate the log without adding
			// operational signal. Prometheus counters on the agent side
			// cover byte/packet accounting.

		case MsgExternalData:
			token, _, payload, err := ParseExternalDataFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad external data frame from %x: %v", pubKey[:8], err)
				continue
			}
			if s.externalWG == nil {
				// No local flow table, but the token names its issuer: a
				// replica that runs without the external listener can still
				// route an agent's reply home.
				if s.cluster != nil && s.cluster.RouteExternalReply(token, pubKey, payload) {
					continue
				}
				log.Printf("relay: external data from %x dropped: shared external listener disabled", pubKey[:8])
				continue
			}
			if !s.externalWG.AllowsIngress(pubKey) {
				log.Printf("relay: external data from non-ingress peer %x dropped", pubKey[:8])
				continue
			}
			// A token minted by another replica means the external client's
			// UDP flow lives there; send the response home instead of
			// consulting the local (tokenless) flow table.
			if s.cluster != nil && s.externalWG.foreignToken(token) {
				if !s.cluster.RouteExternalReply(token, pubKey, payload) {
					s.destMissLog.Logf("relay: external reply token=%d: issuing replica unknown", token)
				}
				continue
			}
			s.externalWG.BindTokenIngress(token, pubKey)
			if err := s.externalWG.SendToExternal(token, payload); err != nil {
				log.Printf("relay: external data response from %x token=%d failed: %v", pubKey[:8], token, err)
			} else if relayDebug {
				log.Printf("relay: external data response from %x token=%d len=%d sent", pubKey[:8], token, len(payload))
			}

		case MsgBimodalHint:
			destKey, err := ParseBimodalHintFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad bimodal hint frame from %x: %v", pubKey[:8], err)
				continue
			}
			// Forward with sender pubkey so the destination can key the hint
			// by peer; body carries the sender (not the dest) on the wire.
			outFrame := Frame{Type: MsgBimodalHint, Body: pubKey[:]}

			s.mu.RLock()
			dest, ok := s.peers[destKey]
			s.mu.RUnlock()
			if !ok {
				// Hints matter for convergence speed, so chase the peer to
				// its owning replica like data frames do. A miss is fine:
				// the sender's FSM falls back on its slower demote path.
				if s.cluster != nil && s.cluster.ForwardToPeer(destKey, outFrame) {
					continue
				}
				relayFramesDroppedUnknownDest.Inc()
				continue
			}
			if err := dest.writeFrame(outFrame); err != nil {
				log.Printf("relay: forward bimodal hint to %x: %v", destKey[:8], err)
				s.dropPeer(dest)
			}

		case MsgNATProbe:
			ip, port, err := ParseNATProbeFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad NAT probe frame from %x: %v", pubKey[:8], err)
				continue
			}
			if err := validateProbeTarget(ip, port); err != nil {
				log.Printf("relay: rejecting NAT probe from %x to %s: %v", pubKey[:8], ip, err)
				continue
			}
			if !s.probeLimiter.Allow() {
				log.Printf("relay: NAT probe rate-limited (from %x to %s)", pubKey[:8], ip)
				continue
			}
			select {
			case s.probeSem <- struct{}{}:
				go func() {
					defer func() { <-s.probeSem }()
					s.sendNATProbe(ip, port, pubKey)
				}()
			default:
				log.Printf("relay: NAT probe dropped for %x (concurrency limit reached)", pubKey[:8])
			}

		case MsgKeepalive:
			// no-op

		case MsgRelayProbe:
			token, err := ParseRelayProbeFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad relay probe response from %x: %v", pubKey[:8], err)
				continue
			}
			cc.completeProbe(token)

		default:
			log.Printf("relay: unknown frame type %d from %x", frame.Type, pubKey[:8])
		}
	}
}

func sameUDPListenAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil || a.Port != b.Port {
		return false
	}
	if a.IP.IsUnspecified() && b.IP.IsUnspecified() {
		return true
	}
	if a.IP.IsUnspecified() || b.IP.IsUnspecified() {
		return false
	}
	return a.IP.Equal(b.IP)
}

const ingressProbeTimeout = 750 * time.Millisecond

func (s *Server) handleIngressProbe(conn net.Conn, frame Frame) {
	writer := bufio.NewWriter(conn)
	pubKeys, err := ParseIngressProbeRequestFrame(frame.Body)
	if err != nil {
		_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("parse ingress probe: %v", err)))
		_ = writer.Flush()
		return
	}
	results := s.probeIngressLatencies(context.Background(), pubKeys, ingressProbeTimeout)
	_ = WriteFrame(writer, MakeIngressProbeResponseFrame(results))
	_ = writer.Flush()
}

func (s *Server) probeIngressLatencies(ctx context.Context, pubKeys [][PubKeySize]byte, timeout time.Duration) []IngressProbeResult {
	results := make([]IngressProbeResult, len(pubKeys))
	ok := make([]bool, len(pubKeys))

	var wg sync.WaitGroup
	for i, pubKey := range pubKeys {
		s.mu.RLock()
		peer := s.peers[pubKey]
		s.mu.RUnlock()
		if peer == nil {
			continue
		}

		wg.Add(1)
		go func(i int, pubKey [PubKeySize]byte, peer *clientConn) {
			defer wg.Done()
			rtt, err := peer.probe(ctx, s.probeSeq.Add(1), timeout)
			if err != nil {
				return
			}
			results[i] = IngressProbeResult{PubKey: pubKey, RTT: rtt}
			ok[i] = true
		}(i, pubKey, peer)
	}
	wg.Wait()

	out := make([]IngressProbeResult, 0, len(pubKeys))
	for i := range results {
		if ok[i] {
			out = append(out, results[i])
		}
	}
	return out
}

func (c *clientConn) probe(ctx context.Context, token uint64, timeout time.Duration) (time.Duration, error) {
	done := make(chan struct{}, 1)
	c.probeMu.Lock()
	if c.probes == nil {
		c.probes = make(map[uint64]chan struct{})
	}
	c.probes[token] = done
	c.probeMu.Unlock()
	defer func() {
		c.probeMu.Lock()
		delete(c.probes, token)
		c.probeMu.Unlock()
	}()

	start := time.Now()
	if err := c.writeFrame(MakeRelayProbeFrame(token)); err != nil {
		return 0, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return time.Since(start), nil
	case <-timer.C:
		return 0, fmt.Errorf("relay probe timeout")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (c *clientConn) completeProbe(token uint64) {
	c.probeMu.Lock()
	ch := c.probes[token]
	c.probeMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// handleForwarderRegister processes a single 0x10 control request and
// writes either a 0x10 echo (with the allocated port) or an 0xFF error
// frame. The connection is closed by the caller (handleConn defer).
//
// The wire format permits the client to either pre-select a port (rare;
// useful for tests/migrations) or pass 0 to request server-side
// allocation from the configured port pool.
func (s *Server) handleForwarderRegister(conn net.Conn, frame Frame) {
	writer := bufio.NewWriter(conn)
	if s.forwarder == nil || s.alloc == nil {
		_ = WriteFrame(writer, MakeErrorFrame("forwarder not enabled on this relay"))
		_ = writer.Flush()
		return
	}
	port, ingress, ext, err := ParseForwarderRegisterFrame(frame.Body)
	if err != nil {
		_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("parse forwarder register: %v", err)))
		_ = writer.Flush()
		return
	}
	reserved := false
	if port == 0 {
		allocated, err := s.alloc.Allocate()
		if err != nil {
			_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("alloc port: %v", err)))
			_ = writer.Flush()
			return
		}
		port = allocated
		reserved = true
	} else if err := s.alloc.Reserve(port); err != nil {
		if !errors.Is(err, portalloc.ErrInUse) {
			_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("reserve port: %v", err)))
			_ = writer.Flush()
			return
		}
	} else {
		reserved = true
	}
	if err := s.forwarder.Register(port, ingress, ext); err != nil {
		// Release only reservations made by this request. If the port was
		// already in use, keeping it reserved matches the live forwarder state.
		if reserved && !errors.Is(err, ErrPortInUse) {
			s.alloc.Release(port)
		}
		_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("register forwarder: %v", err)))
		_ = writer.Flush()
		return
	}
	_ = WriteFrame(writer, MakeForwarderRegisterFrame(port, ingress, ext))
	_ = writer.Flush()
	log.Printf("relay: forwarder registered: port=%d ingress=%x ext=%x", port, ingress[:8], ext[:8])
}

// handleForwarderUnregister processes a single 0x11 control request and
// writes either a 0x11 echo or an 0xFF error frame. Releasing an unknown
// port is treated as success so cleanup paths can be safely retried.
func (s *Server) handleForwarderUnregister(conn net.Conn, frame Frame) {
	writer := bufio.NewWriter(conn)
	if s.forwarder == nil || s.alloc == nil {
		_ = WriteFrame(writer, MakeErrorFrame("forwarder not enabled on this relay"))
		_ = writer.Flush()
		return
	}
	port, err := ParseForwarderUnregisterFrame(frame.Body)
	if err != nil {
		_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("parse forwarder unregister: %v", err)))
		_ = writer.Flush()
		return
	}
	if err := s.forwarder.Unregister(port); err != nil && !errors.Is(err, ErrUnknownPort) {
		_ = WriteFrame(writer, MakeErrorFrame(fmt.Sprintf("unregister forwarder: %v", err)))
		_ = writer.Flush()
		return
	}
	s.alloc.Release(port)
	_ = WriteFrame(writer, MakeForwarderUnregisterFrame(port))
	_ = writer.Flush()
	log.Printf("relay: forwarder unregistered: port=%d", port)
}

// validateProbeTarget guards the relay's NAT-probe primitive from being aimed
// at internal infrastructure. It rejects addresses that can never be a real
// external NAT endpoint — loopback, link-local (including the cloud metadata
// range 169.254.169.254), multicast, the unspecified address and the limited
// broadcast address — so the relay cannot be used to reach a node's own network
// or a metadata service. Private (RFC1918) and CGNAT (100.64.0.0/10) targets
// are deliberately ALLOWED: intra-VPC / intra-cluster peers (e.g. EKS/GKE node
// ranges) legitimately probe such endpoints, so treating them like public
// targets (rate-limited, not blocked) is consistent. The rate limiter bounds
// abuse of the allowed paths; per-peer fairness is deferred to control-plane
// authentication.
func validateProbeTarget(target net.IP, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid target port %d", port)
	}
	if target == nil || target.IsUnspecified() || target.IsLoopback() ||
		target.IsLinkLocalUnicast() || target.IsLinkLocalMulticast() ||
		target.IsMulticast() || target.Equal(net.IPv4bcast) {
		return fmt.Errorf("non-routable target")
	}
	return nil
}

// sendNATProbe sends two UDP probes to the specified endpoint:
//
//  1. Verification probe from the relay's bound UDP port (same port the agent
//     sent its NAT-opening packet to). This tests basic reachability.
//  2. Test probe from a random ephemeral port. This tests port restriction.
//
// The agent evaluates the combination:
//   - Both received   → cone (address-restricted or full)
//   - Only verify     → port-restricted cone
//   - Neither         → firewall blocking (not NAT) → remains cone
func (s *Server) sendNATProbe(ip net.IP, port int, requester [PubKeySize]byte) {
	addr := &net.UDPAddr{IP: ip, Port: port}

	// Probe 1: verification from the bound UDP port (agent opened NAT for this).
	if s.probeConn != nil {
		verify := []byte("WIREKUBE_NAT_VERIFY")
		if _, err := s.probeConn.WriteToUDP(verify, addr); err != nil {
			log.Printf("relay: NAT verify probe to %s failed: %v", addr, err)
		} else {
			log.Printf("relay: NAT verify probe sent to %s for %x (from bound port)", addr, requester[:8])
		}
	}

	// Probe 2: test from a random ephemeral port.
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		log.Printf("relay: NAT test probe dial %s failed: %v", addr, err)
		return
	}
	defer conn.Close()

	probe := []byte("WIREKUBE_NAT_PROBE")
	if _, err := conn.Write(probe); err != nil {
		log.Printf("relay: NAT test probe send to %s failed: %v", addr, err)
		return
	}
	log.Printf("relay: NAT test probe sent to %s for %x (from ephemeral port)", addr, requester[:8])
}

// ConnectedPeers returns the number of currently connected peers.
func (s *Server) ConnectedPeers() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}
