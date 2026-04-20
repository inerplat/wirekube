//go:build linux

package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// Compile-time check: WireKubeBind implements conn.Bind.
var _ conn.Bind = (*WireKubeBind)(nil)

// Path constants for PeerPath.Mode. These mirror wireguard.PathMode but are
// stored as int32 so they can live in a lock-free atomic.
const (
	PathModeDirect int32 = 0 // UDP only (auto-upgrades to dual-send if direct stalls — see directTrustWindow)
	PathModeWarm   int32 = 1 // UDP + relay duplicate send
	PathModeRelay  int32 = 2 // relay only
)

// directTrustWindow is how long PathModeDirect trusts the direct leg on its
// own. After this many nanoseconds without a direct receive, Send() behaves
// as if the peer were in PathModeWarm for the current packet — duplicating
// to the relay leg so the receiver is reachable regardless of which side of
// the direct path is currently broken.
//
// This is Tailscale's trustBestAddrUntil mechanism (wgengine/magicsock):
// the direct-vs-bimodal decision lives in the datapath, not in a control
// loop, so failover blackout is bounded by this window rather than by the
// agent's sync cadence.
const directTrustWindowNs = int64(3 * time.Second)

// bimodalHintWindowNs is how long an inbound hint forces dual-send on the
// receiving side. Long enough for the remote peer to re-converge on direct
// traffic (or fully demote to relay) without the hinted side flapping.
const bimodalHintWindowNs = int64(10 * time.Second)

// bimodalHintSendIntervalNs rate-limits outbound hints to at most one per
// interval per peer. Short enough that a lost hint is retried several times
// within the trust window (3s / 250ms = 12 attempts), tolerant of TCP relay
// reconnect jitter without flooding the control channel.
const bimodalHintSendIntervalNs = int64(250 * time.Millisecond)

// PathHealth tracks observed health metrics for a single path (direct or relay).
// All fields are lock-free atomics to allow concurrent reads from Send/Receive.
//
// LastSeen is updated only on successful RECEIVE. A send returning nil proves
// the local socket accepted the buffer, not that the peer received it (e.g.
// when inbound WG UDP is firewalled, outgoing writes keep succeeding while the
// return path is dead). Using send success as receive evidence would suppress
// direct→relay failover whenever only the ingress direction is broken.
type PathHealth struct {
	LastSeen atomic.Int64  // unix nano timestamp of last packet received on this path
	RTT      atomic.Uint32 // round-trip time in milliseconds (0 = not measured)
	Loss     atomic.Uint32 // packet loss percentage (0-100)
}

// IsHealthy returns true if the path has seen recent traffic (within 1.5s).
func (ph *PathHealth) IsHealthy() bool {
	lastSeen := ph.LastSeen.Load()
	if lastSeen == 0 {
		return false
	}
	return time.Now().UnixNano()-lastSeen < int64(1500*time.Millisecond)
}

// PeerPath tracks direct and relay transport state for a single peer. All
// mutable fields are lock-free atomics so Send and receive paths can read
// them without coordination.
//
// Mode controls per-packet dispatch in Send (see PathMode* constants).
// DirectHealth.LastSeen / RelayHealth.LastSeen are the watermarks the agent
// uses to detect a stalled leg and demote the mode.
type PeerPath struct {
	DirectAddr   netip.AddrPort
	DirectHealth PathHealth   // observed health of the direct UDP path
	RelayHealth  PathHealth   // observed health of the relay TCP path
	Mode         atomic.Int32 // one of PathModeDirect | PathModeWarm | PathModeRelay

	// hintedUntilNs, when set to a future unix-nano, forces Send to dual-path
	// this peer's packets regardless of Mode. Set on inbound BimodalHint
	// reception; cleared by time. Lets the remote side pull us into bimodal
	// mode when it observes an asymmetric blackhole that we cannot detect
	// locally (our direct receive watermark is still fresh).
	hintedUntilNs atomic.Int64

	// lastHintSentNs rate-limits outbound hints this node sends about this
	// peer. Send updates it when firing a hint so a sustained stall does not
	// flood the relay control channel.
	lastHintSentNs atomic.Int64
}

// WireKubeBind implements conn.Bind using a single UDP socket for direct P2P
// communication, with optional relay transport for NAT-blocked peers.
type WireKubeBind struct {
	mu   sync.Mutex
	udp4 *net.UDPConn
	port uint16

	// pathTable maps peer public key (base64 string) to *PeerPath.
	// Consulted by Send to route via direct UDP or relay.
	pathTable sync.Map

	// addrToPeer maps netip.AddrPort string to peer public key (base64).
	// Updated by SetPeerPath; used by Send to look up the peer key from
	// the endpoint's destination address.
	addrToPeer sync.Map

	// Relay transport fields. relay is nil when no relay is configured.
	relay      RelayTransport
	relayCh    chan RelayPacket
	relayClose chan struct{}
}

// NewWireKubeBind creates a new unbound WireKubeBind.
func NewWireKubeBind() *WireKubeBind {
	return &WireKubeBind{}
}

// SetRelayTransport injects a relay transport into the bind. Must be called
// before Open. The agent calls this to connect the relay pool to the bind.
func (b *WireKubeBind) SetRelayTransport(rt RelayTransport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.relay = rt
}

// Open puts the Bind into a listening state on the given port. Passing zero
// results in a random port selection. Returns one or two ReceiveFuncs:
//   - fns[0]: direct UDP receive (always present)
//   - fns[1]: relay receive (present only when relay transport is set)
func (b *WireKubeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.udp4 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if opErr != nil {
					return
				}
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, 0, err
	}

	udpConn := pc.(*net.UDPConn)
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)

	b.udp4 = udpConn
	b.port = uint16(localAddr.Port)

	fns := []conn.ReceiveFunc{b.makeReceiveFunc(udpConn)}

	if b.relay != nil {
		b.relayCh = make(chan RelayPacket, 256)
		b.relayClose = make(chan struct{})
		fns = append(fns, b.makeRelayReceiveFunc())
		log.Printf("[bind] Open: relay ReceiveFunc created (port=%d, fns=%d)", b.port, len(fns))
	} else {
		log.Printf("[bind] Open: no relay, direct only (port=%d)", b.port)
	}

	return fns, b.port, nil
}

// makeReceiveFunc creates a ReceiveFunc that reads from the given UDP
// connection and populates the provided packet/size/endpoint slices.
func (b *WireKubeBind) makeReceiveFunc(udpConn *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := udpConn.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}

		// Record direct receive evidence for any known peer. In dual-path mode,
		// we accept packets from all paths and let the agent decide preference.
		// Direct evidence is always valuable even when relay is preferred.
		// Per-packet match log intentionally silenced: at N peers × M pps
		// this is the loudest line in the agent log and has no operational
		// value (LastSeen watermark is observable via Prometheus). Only
		// flag unmatched control frames, which is genuinely abnormal.
		if _, path, ok := b.lookupPeerByDirectAddr(addr); ok {
			path.DirectHealth.LastSeen.Store(time.Now().UnixNano())
		} else if isWireGuardControlPacket(packets[0][:n]) {
			log.Printf("[bind] direct receive unmatched control src=%s len=%d", addr.String(), n)
		}

		// Conditional endpoint virtualization for relay mode:
		// When PathModeRelay is active, virtualize direct packets as 127.0.0.1:0
		// with peerKey set so that Send() routes them via relay only.
		// For other modes, deliver with real address to enable endpoint learning.
		sizes[0] = n
		// Always deliver direct packets with real endpoints, even in relay mode.
		// This enables WireGuard to learn actual peer addresses and supports seamless
		// dual-path switching. The bind's Send() method handles routing to relay via
		// pathTable lookup, independent of the receive-side endpoint.
		eps[0] = &WireKubeEndpoint{dst: addr}
		return 1, nil
	}
}

func (b *WireKubeBind) lookupPeerByDirectAddr(addr netip.AddrPort) (string, *PeerPath, bool) {
	if v, ok := b.addrToPeer.Load(addr.String()); ok {
		pubKeyB64 := v.(string)
		if pp := b.GetPeerPath(pubKeyB64); pp != nil {
			return pubKeyB64, pp, true
		}
	}

	// Some environments can preserve the peer's source IP but rebind the
	// source port across restart/reprobe windows. Fall back to a unique IP-only
	// match so direct receive evidence is not lost purely because the port
	// changed underneath the userspace bind.
	var matchedKey string
	var matchedPP *PeerPath
	ambiguous := false
	b.pathTable.Range(func(key, value any) bool {
		pp := value.(*PeerPath)
		if !pp.DirectAddr.IsValid() || pp.DirectAddr.Addr() != addr.Addr() {
			return true
		}
		if matchedPP != nil {
			ambiguous = true
			return false
		}
		matchedKey = key.(string)
		matchedPP = pp
		return true
	})
	if ambiguous || matchedPP == nil {
		return "", nil, false
	}
	b.addrToPeer.Store(addr.String(), matchedKey)
	log.Printf("[bind] learned rebound direct addr peer=%s src=%s expected=%s",
		shortKey(matchedKey), addr.String(), matchedPP.DirectAddr.String())
	return matchedKey, matchedPP, true
}

// Close closes the UDP socket and relay channel. After Close, all ReceiveFuncs
// returned by Open will return net.ErrClosed.
func (b *WireKubeBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.udp4 == nil {
		return nil
	}

	if b.relayClose != nil {
		close(b.relayClose)
		b.relayClose = nil
		b.relayCh = nil
	}

	err := b.udp4.Close()
	b.udp4 = nil
	b.port = 0
	return err
}

// SetMark sets SO_MARK on the UDP socket for policy routing (fwmark).
func (b *WireKubeBind) SetMark(mark uint32) error {
	b.mu.Lock()
	c := b.udp4
	b.mu.Unlock()

	if c == nil {
		return nil
	}

	sc, err := c.SyscallConn()
	if err != nil {
		return err
	}

	var opErr error
	err = sc.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	})
	if err != nil {
		return err
	}
	return opErr
}

// Send writes one or more encrypted WireGuard packets to the endpoint's
// destination address(es). Path selection is driven by PeerPath.Mode:
//
//   - PathModeDirect: write to UDP only.
//   - PathModeWarm:   write to BOTH UDP and relay on every packet. This is
//     the Tailscale DERP-style bimodal send; WireGuard's replay counter on
//     the receiver deduplicates transparently, so duplicate transport is
//     free from a correctness standpoint and gives the receiver the earlier
//     copy regardless of which leg happens to be working right now.
//   - PathModeRelay:  write to relay only.
//
// The synthetic-endpoint case (peerKey set, dst port == 0) arises when
// wireguard-go is replying to a packet we delivered via the relay receive
// function. There is no usable UDP destination in that case, so the packet
// must go via relay regardless of mode.
//
// NOTE: this function intentionally has no error-based path switching.
// UDP WriteToUDP only errors on local socket failures (ENOBUFS, EMSGSIZE,
// socket closed) which carry no information about peer reachability; using
// it as a failover signal is actively harmful because it masks the loss of
// reverse-path connectivity the agent FSM needs to see. Path demotion is
// done by the agent (see pkg/agent/path_monitor) based on receive-side
// evidence (PathHealth.LastSeen).
func (b *WireKubeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.udp4
	relay := b.relay
	b.mu.Unlock()

	if c == nil {
		return syscall.ENOTCONN
	}

	wkep, ok := ep.(*WireKubeEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	// Resolve peer by either the endpoint's peerKey (set on packets we
	// delivered from relay) or by the reverse map on the destination addr.
	// Grab the PeerPath too so we can consult DirectHealth.LastSeen below.
	mode := PathModeDirect
	var pp *PeerPath
	var peerKeyBytes [32]byte
	var hasPeerKey bool

	var zeroKey [32]byte
	if wkep.peerKey != zeroKey {
		peerKeyBytes = wkep.peerKey
		hasPeerKey = true
		pubKeyB64 := base64.StdEncoding.EncodeToString(peerKeyBytes[:])
		if pp = b.GetPeerPath(pubKeyB64); pp != nil {
			mode = pp.Mode.Load()
		}
	} else if v, ok := b.addrToPeer.Load(wkep.dst.String()); ok {
		pubKeyB64 := v.(string)
		if pp = b.GetPeerPath(pubKeyB64); pp != nil {
			mode = pp.Mode.Load()
		}
		if raw, err := base64.StdEncoding.DecodeString(pubKeyB64); err == nil && len(raw) == 32 {
			copy(peerKeyBytes[:], raw)
			hasPeerKey = true
		}
	}

	// Decide which legs to send on.
	sendDirect := mode == PathModeDirect || mode == PathModeWarm
	sendRelay := mode == PathModeRelay || mode == PathModeWarm

	// Datapath trust check: if the direct receive watermark is stale and
	// we have not given up on direct (mode != Relay), we should assume the
	// remote peer cannot reach our direct leg either — they just don't
	// know it yet because their outbound direct keeps succeeding. Mark
	// this as stale so a hint gets fired below, and in PathModeDirect also
	// dual-send this packet so we stay reachable while the remote
	// converges.
	//
	// This condition must NOT gate on PathModeDirect alone: once the agent
	// FSM demotes us to Warm, we still need to keep pulling the remote
	// peer into bimodal via hints for the entire outage window. Without
	// that, a peer that re-entered direct-only mode (hint expired, local
	// LastSeen was refreshed by our direct traffic) would stop forwarding
	// our replies over relay the moment we demoted — triggering a second
	// blackout that lasts until the next FSM cycle.
	nowNs := time.Now().UnixNano()
	directStale := false
	if mode != PathModeRelay && pp != nil {
		lastRX := pp.DirectHealth.LastSeen.Load()
		if lastRX == 0 || nowNs-lastRX > directTrustWindowNs {
			directStale = true
			if mode == PathModeDirect {
				sendRelay = true
			}
		}
	}

	// Bimodal hint: if the remote peer recently told us it cannot reach our
	// direct leg, duplicate this packet to the relay even though our local
	// view of the path may still look healthy. This is the asymmetric
	// blackhole case: they observe stale RX, we don't, so without their
	// hint we'd keep sending direct-only until the control plane demotes us
	// many seconds later.
	if pp != nil {
		if until := pp.hintedUntilNs.Load(); until > nowNs {
			sendRelay = true
		}
	}

	// Synthetic endpoint → relay only (no usable UDP destination).
	if wkep.peerKey != zeroKey && wkep.dst.Port() == 0 {
		sendDirect = false
		sendRelay = true
	}

	relayAvailable := relay != nil && hasPeerKey
	if sendRelay && !relayAvailable {
		sendRelay = false
	}

	// Fire a bimodal hint to the remote when our receive watermark has
	// stalled but we still have a relay to forward through. This pulls the
	// remote into dual-send mode so its replies reach us over relay while
	// direct is blackholed one-way. Rate-limited by pp.lastHintSentNs.
	if directStale && relayAvailable && pp != nil {
		last := pp.lastHintSentNs.Load()
		if nowNs-last > bimodalHintSendIntervalNs {
			if pp.lastHintSentNs.CompareAndSwap(last, nowNs) {
				if err := relay.SendBimodalHint(peerKeyBytes); err != nil {
					log.Printf("[bind] SendBimodalHint peer=%s err=%v",
						shortKey(base64.StdEncoding.EncodeToString(peerKeyBytes[:])), err)
				}
			}
		}
	}

	if !sendDirect && !sendRelay {
		// Nothing we can do — caller selected a mode that has no leg available.
		// In practice this happens only when the agent sets PathRelay on a peer
		// before the relay pool has connected; surface as ENOTCONN so caller
		// can retry on the next reconfigure.
		return syscall.ENOTCONN
	}

	addr := net.UDPAddrFromAddrPort(wkep.dst)

	for _, buf := range bufs {
		// Send on every enabled leg. Errors on one leg do NOT suppress the other;
		// any success satisfies delivery (the receiver dedupes via replay window).
		var directErr, relayErr error

		if sendDirect {
			if _, err := c.WriteToUDP(buf, addr); err != nil {
				directErr = err
			}
		}
		if sendRelay {
			if err := relay.SendToPeer(peerKeyBytes, buf); err != nil {
				relayErr = err
			}
		}

		switch {
		case sendDirect && sendRelay:
			// Warm: success iff at least one leg succeeded.
			if directErr != nil && relayErr != nil {
				log.Printf("[bind] warm send: both legs failed dest=%x directErr=%v relayErr=%v",
					peerKeyBytes[:8], directErr, relayErr)
				return directErr
			}
		case sendDirect:
			if directErr != nil {
				return directErr
			}
		case sendRelay:
			if relayErr != nil {
				log.Printf("[bind] relay send FAILED: dest=%x len=%d err=%v", peerKeyBytes[:8], len(buf), relayErr)
				return relayErr
			}
		}
	}

	return nil
}

// ParseEndpoint parses a "host:port" string into a WireKubeEndpoint.
func (b *WireKubeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &WireKubeEndpoint{dst: ap}, nil
}

// BatchSize returns 1. GSO/GRO batching is not yet implemented.
func (b *WireKubeBind) BatchSize() int {
	return 1
}

// SetPeerPath updates the path table entry for a peer identified by its base64
// public key. Also maintains the addrToPeer reverse map used by Send().
func (b *WireKubeBind) SetPeerPath(pubKeyB64 string, mode int32, directAddr netip.AddrPort) {
	v, loaded := b.pathTable.LoadOrStore(pubKeyB64, &PeerPath{
		DirectAddr: directAddr,
	})
	pp := v.(*PeerPath)
	pp.Mode.Store(mode)
	if loaded {
		// Remove old address mapping if the direct address changed.
		if pp.DirectAddr != directAddr {
			b.addrToPeer.Delete(pp.DirectAddr.String())
		}
		pp.DirectAddr = directAddr
	}
	if directAddr.IsValid() {
		b.addrToPeer.Store(directAddr.String(), pubKeyB64)
	}
	// Only log the *initial* registration of a new peer path, not every
	// sync cycle's reconfirmation. driveTransportMode commits SetPeerPath
	// on every sync tick per peer, which would flood the log otherwise.
	if !loaded {
		log.Printf("[bind] SetPeerPath peer=%s mode=%d direct=%s (new)", shortKey(pubKeyB64), mode, directAddr.String())
	}
}

// GetPeerPath returns the current path for a peer, or nil if not tracked.
func (b *WireKubeBind) GetPeerPath(pubKeyB64 string) *PeerPath {
	v, ok := b.pathTable.Load(pubKeyB64)
	if !ok {
		return nil
	}
	return v.(*PeerPath)
}

// MarkBimodalHint arms the dual-send window for a peer identified by its raw
// public key bytes. Called by the relay pool when the remote peer relays a
// BimodalHint naming itself as the sender. The bind will dual-path all sends
// to that peer until the window expires.
func (b *WireKubeBind) MarkBimodalHint(srcPubKey [32]byte) {
	pubKeyB64 := base64.StdEncoding.EncodeToString(srcPubKey[:])
	pp := b.GetPeerPath(pubKeyB64)
	if pp == nil {
		// Create a stub entry so the hint is remembered until SyncPeers wires
		// up the real path. Without this, first-packet-after-hint would miss
		// the dual-send because the peer has not yet been registered.
		pp = &PeerPath{}
		actual, _ := b.pathTable.LoadOrStore(pubKeyB64, pp)
		pp = actual.(*PeerPath)
	}
	pp.hintedUntilNs.Store(time.Now().UnixNano() + bimodalHintWindowNs)
	log.Printf("[bind] bimodal hint received peer=%s window=%s",
		shortKey(pubKeyB64), time.Duration(bimodalHintWindowNs))
}

// DeliverRelayPacket pushes a packet received from the relay network into the
// bind's relay channel. Called by the relay pool's handleData callback.
// Non-blocking: drops the packet if the channel is full.
func (b *WireKubeBind) DeliverRelayPacket(pkt RelayPacket) {
	b.mu.Lock()
	ch := b.relayCh
	b.mu.Unlock()

	if ch == nil {
		return
	}

	select {
	case ch <- pkt:
	default:
	}
}

// makeRelayReceiveFunc creates a ReceiveFunc that reads packets from the relay
// channel. wireguard-go identifies peers by public key in the WireGuard crypto
// header, not by source endpoint, so we use a synthetic loopback endpoint.
func (b *WireKubeBind) makeRelayReceiveFunc() conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-b.relayCh:
			n := copy(packets[0], pkt.Payload)
			sizes[0] = n
			pubKeyB64 := base64.StdEncoding.EncodeToString(pkt.SrcKey[:])
			if pp := b.GetPeerPath(pubKeyB64); pp != nil {
				pp.RelayHealth.LastSeen.Store(time.Now().UnixNano())
			}
			eps[0] = &WireKubeEndpoint{
				dst:     netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0),
				peerKey: pkt.SrcKey,
			}
			return 1, nil
		case <-b.relayClose:
			return 0, net.ErrClosed
		}
	}
}

func isWireGuardControlPacket(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	switch buf[0] {
	case 1, 2, 3:
		return true
	default:
		return false
	}
}

func shortKey(pubKeyB64 string) string {
	if len(pubKeyB64) <= 8 {
		return pubKeyB64
	}
	return pubKeyB64[:8]
}
