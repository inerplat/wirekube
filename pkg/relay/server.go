package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wirekube/wirekube/pkg/relay/portalloc"
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

	// forwarder + alloc handle external-peer traffic. Both may be nil if
	// the operator opted out of external-peer support; in that case the
	// server replies with MsgError on 0x10/0x11 control frames so the
	// reconciler reports a clear failure.
	forwarder *Forwarder
	alloc     *portalloc.Allocator

	externalWG *ExternalWGListener
	probeSeq   atomic.Uint64
}

type clientConn struct {
	pubKey  [PubKeySize]byte
	conn    net.Conn
	writer  *bufio.Writer
	mu      sync.Mutex
	probeMu sync.Mutex
	probes  map[uint64]chan struct{}
}

func NewServer() *Server {
	return &Server{
		peers:    make(map[[PubKeySize]byte]*clientConn),
		probeSem: make(chan struct{}, 16),
	}
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
		return fmt.Errorf("ingress %x not connected", ingress[:8])
	}
	out := MakeDataFrame(external, payload)
	dest.mu.Lock()
	defer dest.mu.Unlock()
	if err := WriteFrame(dest.writer, out); err != nil {
		return err
	}
	return dest.writer.Flush()
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

	cc := &clientConn{
		pubKey: pubKey,
		conn:   conn,
		writer: bufio.NewWriterSize(conn, 64*1024),
	}

	s.mu.Lock()
	old, exists := s.peers[pubKey]
	s.peers[pubKey] = cc
	s.mu.Unlock()

	if exists {
		old.conn.Close()
	}

	log.Printf("relay: peer registered: %x", pubKey[:8])
	defer func() {
		s.mu.Lock()
		if s.peers[pubKey] == cc {
			delete(s.peers, pubKey)
		}
		s.mu.Unlock()
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
				log.Printf("relay: data from %x to %x: dest not found", pubKey[:8], destKey[:8])
				continue
			}

			outFrame := MakeDataFrame(pubKey, payload)
			dest.mu.Lock()
			err = WriteFrame(dest.writer, outFrame)
			if err == nil {
				err = dest.writer.Flush()
			}
			dest.mu.Unlock()

			if err != nil {
				log.Printf("relay: forward error to %x: %v", destKey[:8], err)
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
				log.Printf("relay: external data from %x dropped: shared external listener disabled", pubKey[:8])
				continue
			}
			if !s.externalWG.AllowsIngress(pubKey) {
				log.Printf("relay: external data from non-ingress peer %x dropped", pubKey[:8])
				continue
			}
			s.externalWG.BindTokenIngress(token, pubKey)
			if err := s.externalWG.SendToExternal(token, payload); err != nil {
				log.Printf("relay: external data response from %x token=%d failed: %v", pubKey[:8], token, err)
			}

		case MsgBimodalHint:
			destKey, err := ParseBimodalHintFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad bimodal hint frame from %x: %v", pubKey[:8], err)
				continue
			}
			s.mu.RLock()
			dest, ok := s.peers[destKey]
			s.mu.RUnlock()
			if !ok {
				continue
			}
			// Forward with sender pubkey so the destination can key the hint
			// by peer; body carries the sender (not the dest) on the wire.
			outFrame := Frame{Type: MsgBimodalHint, Body: pubKey[:]}
			dest.mu.Lock()
			err = WriteFrame(dest.writer, outFrame)
			if err == nil {
				err = dest.writer.Flush()
			}
			dest.mu.Unlock()
			if err != nil {
				log.Printf("relay: forward bimodal hint to %x: %v", destKey[:8], err)
			}

		case MsgNATProbe:
			ip, port, err := ParseNATProbeFrame(frame.Body)
			if err != nil {
				log.Printf("relay: bad NAT probe frame from %x: %v", pubKey[:8], err)
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
	c.mu.Lock()
	err := WriteFrame(c.writer, MakeRelayProbeFrame(token))
	if err == nil {
		err = c.writer.Flush()
	}
	c.mu.Unlock()
	if err != nil {
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
