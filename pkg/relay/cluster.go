package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Relay clustering (data plane).
//
// A multi-replica relay sits behind one load balancer, so the TCP sessions of
// two peers that want to talk routinely land on different replicas. Each
// replica publishes "I hold this peer" into a shared registry; on a local
// lookup miss the data path asks the registry, wraps the frame in a
// ClusterEnvelope, and ships it to the owning replica over a dedicated
// replica-to-replica listener (--cluster-addr). The receiving replica unwraps
// and delivers locally — never forwards again — so a stale registry entry can
// misdeliver a frame but can never create a loop.
//
// Links between replicas use the same bounded-queue discipline as client
// connections: enqueue never blocks the sender's read loop, overflow drops
// the newest frame, and WireGuard's own retransmit/replay machinery absorbs
// the loss. A wedged sibling replica therefore costs its own frames only.

// PeerRegistry is the shared "which replica holds which peer" directory.
// Implementations must keep LookupPeer cheap and non-blocking: it sits on the
// data path, so it must be served from a local cache, never from a network
// round trip.
type PeerRegistry interface {
	// PublishPeer records that this replica now holds the peer's session.
	PublishPeer(pubKey [PubKeySize]byte)
	// WithdrawPeer removes the record. Best effort: a missed withdraw ages
	// out via the registry's own staleness horizon.
	WithdrawPeer(pubKey [PubKeySize]byte)
	// LookupPeer returns the cluster address of the replica holding the
	// peer, from local cache.
	LookupPeer(pubKey [PubKeySize]byte) (addr string, ok bool)
	// Replicas returns the cluster addresses of every live replica,
	// including this one, from local cache.
	Replicas() []string
	// SelfAddr is this replica's advertised cluster address.
	SelfAddr() string
}

// External-flow token tagging.
//
// The shared external WG listener keys each client flow by an opaque uint64
// token, but the token table is replica-local state: the UDP flow, its
// conntrack entry at the load balancer, and the reply socket all live on the
// replica that received the datagram. When the ingress agent's TCP session is
// on a different replica, its reply arrives there — carrying a token that
// replica has never seen. The top 16 bits of every token therefore encode a
// stable hash of the issuing replica's cluster address, so any replica can
// route a foreign-tagged reply home without shared state.
const clusterTokenTagShift = 48

func clusterAddrTag(addr string) uint16 {
	// FNV-1a, inlined to keep this file dependency-free.
	const offset32, prime32 = 2166136261, 16777619
	h := uint32(offset32)
	for i := 0; i < len(addr); i++ {
		h ^= uint32(addr[i])
		h *= prime32
	}
	return uint16(h>>16) ^ uint16(h)
}

func clusterTokenTag(token uint64) uint16 {
	return uint16(token >> clusterTokenTagShift)
}

// clusterLinkQueueDepth mirrors sendQueueDepth: enough to ride out a
// scheduling hiccup, small enough that a dead sibling doesn't hoard memory.
const clusterLinkQueueDepth = 256

const clusterDialTimeout = 3 * time.Second

// Cluster wires a Server into the replica mesh.
type Cluster struct {
	registry PeerRegistry

	mu    sync.Mutex
	links map[string]*clusterLink

	// deliver hands an unwrapped inner frame to the local peer. Installed by
	// the Server when the cluster is enabled.
	deliver func(dest [PubKeySize]byte, inner Frame) bool
	// deliverExtReply hands a returned external-flow response to the local
	// external WG listener (this replica issued the token).
	deliverExtReply func(token uint64, ingress [PubKeySize]byte, payload []byte)
	// deliverExtFanout fans a new external source's packet out to LOCAL
	// peers only — the cluster hop already happened.
	deliverExtFanout func(token uint64, srcAddr string, payload []byte)

	dropLog *suppressedLogger
}

func NewCluster(registry PeerRegistry) *Cluster {
	return &Cluster{
		registry: registry,
		links:    make(map[string]*clusterLink),
		dropLog:  newSuppressedLogger(time.Second),
	}
}

// ForwardToPeer routes an inner frame toward whichever replica holds dest.
// Returns false when the registry has no fresh owner (or the owner is this
// replica itself, meaning the peer just disconnected) — the caller keeps its
// existing miss handling. Never blocks.
func (c *Cluster) ForwardToPeer(dest [PubKeySize]byte, inner Frame) bool {
	addr, ok := c.registry.LookupPeer(dest)
	if !ok || addr == "" || addr == c.registry.SelfAddr() {
		return false
	}
	c.linkTo(addr).enqueue(makeClusterEnvelope(dest, inner), c.dropLog)
	return true
}

// RouteExternalReply sends an ingress agent's response for a foreign-tagged
// external-flow token back to the replica that issued it. Returns false when
// no live replica matches the tag (the issuer restarted or is gone) — the
// reply is then dropped and the external client's own retry recovers.
func (c *Cluster) RouteExternalReply(token uint64, ingress [PubKeySize]byte, payload []byte) bool {
	tag := clusterTokenTag(token)
	for _, addr := range c.registry.Replicas() {
		if addr == c.registry.SelfAddr() || clusterAddrTag(addr) != tag {
			continue
		}
		c.linkTo(addr).enqueue(makeClusterExtReply(token, ingress, payload), c.dropLog)
		return true
	}
	return false
}

// FanoutExternal extends a dynamic-ingress fanout to every sibling replica,
// so agents connected elsewhere also see a new external source's first
// packets. Receivers fan out to their local peers only.
func (c *Cluster) FanoutExternal(token uint64, srcAddr string, payload []byte) {
	for _, addr := range c.registry.Replicas() {
		if addr == c.registry.SelfAddr() {
			continue
		}
		c.linkTo(addr).enqueue(makeClusterExtFanout(token, srcAddr, payload), c.dropLog)
	}
}

func (c *Cluster) linkTo(addr string) *clusterLink {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.links[addr]; ok {
		return l
	}
	l := newClusterLink(addr, func() {
		c.mu.Lock()
		if c.links[addr] != nil && c.links[addr].closed() {
			delete(c.links, addr)
		}
		c.mu.Unlock()
	})
	c.links[addr] = l
	go l.run()
	return l
}

// ServeListener accepts replica-to-replica connections and delivers each
// envelope's inner frame to the local peer. Inner frames are terminal here:
// a peer that is not local is a drop, not another forward.
func (c *Cluster) ServeListener(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go c.serveConn(conn)
	}
}

func (c *Cluster) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		frame, err := ReadFrame(conn)
		if err != nil {
			return
		}
		switch frame.Type {
		case MsgClusterEnvelope:
			dest, inner, err := parseClusterEnvelope(frame.Body)
			if err != nil {
				log.Printf("relay cluster: bad envelope: %v", err)
				return
			}
			if c.deliver == nil || !c.deliver(dest, inner) {
				c.dropLog.Logf("relay cluster: envelope for %x: peer not local, dropping", dest[:8])
			}
		case MsgClusterExtReply:
			token, ingress, payload, err := parseClusterExtReply(frame.Body)
			if err != nil {
				log.Printf("relay cluster: bad external reply: %v", err)
				return
			}
			if c.deliverExtReply != nil {
				c.deliverExtReply(token, ingress, payload)
			}
		case MsgClusterExtFanout:
			token, srcAddr, payload, err := parseClusterExtFanout(frame.Body)
			if err != nil {
				log.Printf("relay cluster: bad external fanout: %v", err)
				return
			}
			if c.deliverExtFanout != nil {
				c.deliverExtFanout(token, srcAddr, payload)
			}
		default:
			log.Printf("relay cluster: unexpected frame type %#x on cluster listener", frame.Type)
			return
		}
	}
}

// Close tears down every outbound link. Safe to call more than once.
func (c *Cluster) Close() {
	c.mu.Lock()
	links := make([]*clusterLink, 0, len(c.links))
	for _, l := range c.links {
		links = append(links, l)
	}
	c.links = make(map[string]*clusterLink)
	c.mu.Unlock()
	for _, l := range links {
		l.close()
	}
}

// clusterLink is one outbound replica-to-replica connection. It shares the
// clientConn philosophy: a single writer goroutine owns the socket, senders
// enqueue without blocking, and any error closes the link — the next forward
// to that address dials fresh.
type clusterLink struct {
	addr      string
	sendQ     chan Frame
	done      chan struct{}
	closeOnce sync.Once
	onClose   func()
	dropped   atomic.Uint64
}

func newClusterLink(addr string, onClose func()) *clusterLink {
	return &clusterLink{
		addr:    addr,
		sendQ:   make(chan Frame, clusterLinkQueueDepth),
		done:    make(chan struct{}),
		onClose: onClose,
	}
}

func (l *clusterLink) enqueue(frame Frame, dropLog *suppressedLogger) {
	select {
	case <-l.done:
		return
	default:
	}
	select {
	case l.sendQ <- frame:
	default:
		l.dropped.Add(1)
		dropLog.Logf("relay cluster: link to %s congested, dropping frames", l.addr)
	}
}

func (l *clusterLink) run() {
	defer l.close()
	conn, err := net.DialTimeout("tcp", l.addr, clusterDialTimeout)
	if err != nil {
		log.Printf("relay cluster: dial %s: %v", l.addr, err)
		return
	}
	defer conn.Close()
	for {
		select {
		case <-l.done:
			return
		case frame := <-l.sendQ:
			if err := l.writeBatch(conn, frame); err != nil {
				log.Printf("relay cluster: write to %s: %v", l.addr, err)
				return
			}
		}
	}
}

// writeBatch coalesces whatever is already queued behind one deadline, same
// as clientConn.writeBatch and for the same reason: warm-bimodal traffic
// arrives in bursts.
func (l *clusterLink) writeBatch(conn net.Conn, first Frame) error {
	if relayClientWriteTimeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(relayClientWriteTimeout)); err != nil {
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	if err := WriteFrame(conn, first); err != nil {
		return err
	}
	for i := 1; i < clusterLinkQueueDepth; i++ {
		select {
		case next := <-l.sendQ:
			if err := WriteFrame(conn, next); err != nil {
				return err
			}
		default:
			return nil
		}
	}
	return nil
}

func (l *clusterLink) close() {
	l.closeOnce.Do(func() {
		close(l.done)
		if l.onClose != nil {
			l.onClose()
		}
	})
}

func (l *clusterLink) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func makeClusterEnvelope(dest [PubKeySize]byte, inner Frame) Frame {
	body := make([]byte, 0, PubKeySize+1+len(inner.Body))
	body = append(body, dest[:]...)
	body = append(body, inner.Type)
	body = append(body, inner.Body...)
	return Frame{Type: MsgClusterEnvelope, Body: body}
}

func parseClusterEnvelope(body []byte) (dest [PubKeySize]byte, inner Frame, err error) {
	if len(body) < PubKeySize+1 {
		return dest, inner, fmt.Errorf("cluster envelope too short: %d", len(body))
	}
	copy(dest[:], body[:PubKeySize])
	inner.Type = body[PubKeySize]
	if len(body) > PubKeySize+1 {
		inner.Body = body[PubKeySize+1:]
	}
	return dest, inner, nil
}

func makeClusterExtReply(token uint64, ingress [PubKeySize]byte, payload []byte) Frame {
	body := make([]byte, 0, 8+PubKeySize+len(payload))
	body = binary.BigEndian.AppendUint64(body, token)
	body = append(body, ingress[:]...)
	body = append(body, payload...)
	return Frame{Type: MsgClusterExtReply, Body: body}
}

func parseClusterExtReply(body []byte) (token uint64, ingress [PubKeySize]byte, payload []byte, err error) {
	if len(body) < 8+PubKeySize {
		return 0, ingress, nil, fmt.Errorf("cluster external reply too short: %d", len(body))
	}
	token = binary.BigEndian.Uint64(body[:8])
	copy(ingress[:], body[8:8+PubKeySize])
	payload = body[8+PubKeySize:]
	return token, ingress, payload, nil
}

func makeClusterExtFanout(token uint64, srcAddr string, payload []byte) Frame {
	body := make([]byte, 0, 8+2+len(srcAddr)+len(payload))
	body = binary.BigEndian.AppendUint64(body, token)
	body = binary.BigEndian.AppendUint16(body, uint16(len(srcAddr)))
	body = append(body, srcAddr...)
	body = append(body, payload...)
	return Frame{Type: MsgClusterExtFanout, Body: body}
}

func parseClusterExtFanout(body []byte) (token uint64, srcAddr string, payload []byte, err error) {
	if len(body) < 10 {
		return 0, "", nil, fmt.Errorf("cluster external fanout too short: %d", len(body))
	}
	token = binary.BigEndian.Uint64(body[:8])
	addrLen := int(binary.BigEndian.Uint16(body[8:10]))
	if len(body) < 10+addrLen {
		return 0, "", nil, fmt.Errorf("cluster external fanout addr overruns body")
	}
	srcAddr = string(body[10 : 10+addrLen])
	payload = body[10+addrLen:]
	return token, srcAddr, payload, nil
}

// suppressedLogger rate-limits a hot-path log line. The relay learned this
// lesson the hard way: an unthrottled miss log at hundreds of lines per
// second serialized every goroutine through the global log mutex and starved
// the rest of the process (including its apiserver lease client).
type suppressedLogger struct {
	limiter    *rate.Limiter
	suppressed atomic.Uint64
}

func newSuppressedLogger(every time.Duration) *suppressedLogger {
	return &suppressedLogger{limiter: rate.NewLimiter(rate.Every(every), 1)}
}

func (s *suppressedLogger) Logf(format string, args ...any) {
	if !s.limiter.Allow() {
		s.suppressed.Add(1)
		return
	}
	if n := s.suppressed.Swap(0); n > 0 {
		format += fmt.Sprintf(" (%d similar suppressed)", n)
	}
	log.Printf(format, args...)
}

// clusterListenAndServe binds the replica-to-replica listener and serves it
// until the context is cancelled.
func (c *Cluster) ListenAndServe(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("cluster listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	c.ServeListener(ln)
	return nil
}
