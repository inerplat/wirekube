//go:build linux

package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
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
// interval per peer. The relay is TCP and the receiver arms a 10s window, so
// second-scale retries are enough to survive transient reconnect jitter without
// turning a persistent direct-path stall into control-plane log noise.
const bimodalHintSendIntervalNs = int64(2 * time.Second)

const sendDiagLogIntervalNs = int64(1 * time.Second)

var bindDebug = os.Getenv("WIREKUBE_BIND_DEBUG") == "1"

var (
	lastLogNoPeerNs             atomic.Int64
	lastLogDirectStaleNoRelayNs atomic.Int64
)

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
	// directAddr is the bootstrap address the agent supplies through
	// SetPeerPath. Both datapath directions read it — receive attribution and
	// Send — while the sync goroutine rewrites it every cycle, hence the
	// atomic.
	directAddr   atomic.Pointer[netip.AddrPort]
	DirectHealth PathHealth   // observed health of the direct UDP path
	RelayHealth  PathHealth   // observed health of the relay TCP path
	Mode         atomic.Int32 // one of PathModeDirect | PathModeWarm | PathModeRelay

	// authAddr is where the peer's last authenticated packet came from, fed
	// back from the device's own roamed endpoint. The device moves that
	// endpoint only for packets that pass the crypto, so unlike learnedAddr
	// this address cannot be steered by an unauthenticated sender. Send
	// prefers it for that reason.
	authAddr atomic.Pointer[netip.AddrPort]

	// learnedAddrMu serializes updates to learnedAddr and the corresponding
	// address claim so the reverse map cannot leak stale keys.
	learnedAddrMu sync.Mutex
	// learnedAddr is the NAT-mapped source we have observed for this peer
	// (updated on direct UDP receive and from UAPI stats). DirectAddr stays
	// the SetPeerPath-supplied bootstrap value; for symmetric peers the two
	// diverge as the NAT port drifts.
	learnedAddr netip.AddrPort

	hintedUntilNs  atomic.Int64
	lastHintSentNs atomic.Int64

	// forgotten marks a peer whose claims ForgetPeer is releasing, so that a
	// receive already holding this PeerPath cannot record a new claim behind
	// the teardown. Such a claim would have no path entry to release it later
	// and would leave the address permanently contested for its next holder.
	forgotten atomic.Bool
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

	// addrOwners maps an addr:port to the set of peer public keys (base64)
	// claiming it. An address resolves to a peer only while exactly one peer
	// claims it.
	//
	// A set rather than a single owner because peers behind one NAT advertise
	// the same public addr:port. With one owner per address the last writer
	// wins, which attributes packets to the wrong peer and lets one peer's
	// address change delete an entry the others still rely on. A contested
	// address instead resolves to nothing and takes the same path as an
	// address that was never registered.
	addrMu     sync.Mutex
	addrOwners map[string]map[string]struct{}

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
		var srcKey [32]byte
		if pubKey, path, ok, exact := b.lookupPeerByDirectAddr(addr); ok {
			path.DirectHealth.LastSeen.Store(time.Now().UnixNano())
			b.updateLearnedAddr(path, pubKey, addr)
			// Only an exact addr:port match puts a key on the endpoint. An
			// IP-only match is a guess between peers that share a NAT
			// address, and wireguard-go keeps this endpoint object after
			// authenticating the packet as the real peer: a wrong key here
			// would misdirect every later Send for that peer, whose relay
			// copies the recipient then drops on the MAC1 check.
			if exact {
				if raw, err := base64.StdEncoding.DecodeString(pubKey); err == nil && len(raw) == 32 {
					copy(srcKey[:], raw)
				}
			}
		} else if isWireGuardControlPacket(packets[0][:n]) {
			log.Printf("[bind] direct receive unmatched control src=%s len=%d", addr.String(), n)
		}

		sizes[0] = n
		// Direct packets keep their real source address in every mode. Since
		// wireguard-go roams a peer's endpoint to whatever the bind surfaces,
		// that address is what makes the device endpoint a truthful record of
		// which leg the peer's last authenticated packet arrived on. The relay
		// side surfaces a synthetic instead, for the same reason
		// (makeRelayReceiveFunc).
		//
		// The peer key rides along so that Send can resolve the peer from the
		// endpoint directly, rather than reverse-resolving an address that
		// several peers behind one NAT may share.
		eps[0] = &WireKubeEndpoint{dst: addr, relayPeerKey: relayPeerKey{peerKey: srcKey}}
		return 1, nil
	}
}

// DirectAddr returns the bootstrap address for this peer, or the zero value.
func (p *PeerPath) DirectAddr() netip.AddrPort {
	if v := p.directAddr.Load(); v != nil {
		return *v
	}
	return netip.AddrPort{}
}

func (p *PeerPath) setDirectAddr(addr netip.AddrPort) {
	p.directAddr.Store(&addr)
}

// AuthAddr returns the address the peer last authenticated from, or the zero
// value if nothing has been confirmed by the device yet.
func (p *PeerPath) AuthAddr() netip.AddrPort {
	if v := p.authAddr.Load(); v != nil {
		return *v
	}
	return netip.AddrPort{}
}

// NoteAuthenticatedAddr records an address the device roamed a peer to. The
// device roams only on packets that authenticate, making this the one address
// the datapath can follow without corroboration.
func (b *WireKubeBind) NoteAuthenticatedAddr(pubKeyB64 string, addr netip.AddrPort) {
	if !addr.IsValid() || addr.Port() == 0 || addr.Addr().IsLoopback() {
		return
	}
	if pp := b.GetPeerPath(pubKeyB64); pp != nil {
		pp.authAddr.Store(&addr)
	}
}

// lookupPeerByDirectAddr resolves a source address to a peer, falling back to
// an IP-only match when no peer claims the exact addr:port — which is how a
// peer whose NAT rebound its source port is recognised again.
//
// The final result separates the two: it is true only for an exact match by a
// single claimant. An IP-only match identifies the peer well enough to update
// its health watermark, but not well enough to stamp a key onto the endpoint.
func (b *WireKubeBind) lookupPeerByDirectAddr(addr netip.AddrPort) (string, *PeerPath, bool, bool) {
	if pubKeyB64, ok := b.peerForAddr(addr.String()); ok {
		if pp := b.GetPeerPath(pubKeyB64); pp != nil {
			return pubKeyB64, pp, true, true
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
		direct := pp.DirectAddr()
		if !direct.IsValid() || direct.Addr() != addr.Addr() {
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
		return "", nil, false, false
	}
	if b.claimAddrFor(matchedPP, addr.String(), matchedKey) {
		log.Printf("[bind] learned rebound direct addr peer=%s src=%s expected=%s",
			shortKey(matchedKey), addr.String(), matchedPP.DirectAddr().String())
	}
	return matchedKey, matchedPP, true, false
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

	if wkep.externalSource.Valid {
		if relay == nil {
			return syscall.ENOTCONN
		}
		for _, buf := range bufs {
			if bindDebug {
				log.Printf("[bind] external send relay=%s token=%d len=%d",
					wkep.externalSource.RelayAddr, wkep.externalSource.Token, len(buf))
			}
			if err := relay.SendToExternal(wkep.externalSource.RelayAddr, wkep.externalSource.Token, buf); err != nil {
				return err
			}
		}
		return nil
	}

	// Resolve peer by either the endpoint's peerKey (set on packets we
	// delivered from relay) or by the reverse map on the destination addr.
	// Grab the PeerPath too so we can consult DirectHealth.LastSeen below.
	mode := PathModeDirect
	var pp *PeerPath
	var peerKeyBytes [32]byte
	var hasPeerKey bool
	// contestedKeys is populated only when several peers claim the
	// destination address, and holds the ones the relay leg fans out to.
	var contestedKeys [][32]byte

	var zeroKey [32]byte
	if wkep.peerKey != zeroKey {
		// A keyed endpoint keeps its key regardless of what the address says.
		// The relay leg is addressed by key, and relay-delivered packets carry
		// a loopback synthetic that resolves to no peer, so the key is the
		// only handle those frames have.
		peerKeyBytes = wkep.peerKey
		hasPeerKey = true
		pubKeyB64 := base64.StdEncoding.EncodeToString(peerKeyBytes[:])
		if pp = b.GetPeerPath(pubKeyB64); pp != nil {
			mode = pp.Mode.Load()
		} else if addrKey, unique := b.peerForAddr(wkep.dst.String()); unique {
			// No path entry under that key: the peer was removed and re-added,
			// or the endpoint predates a resync. The destination's own claim
			// still describes the mode, which keeps a relay-only peer from
			// being sent direct-only.
			if p := b.GetPeerPath(addrKey); p != nil {
				pp = p
				mode = p.Mode.Load()
			}
		}
	} else if pubKeyB64, unique := b.peerForAddr(wkep.dst.String()); unique {
		if pp = b.GetPeerPath(pubKeyB64); pp != nil {
			mode = pp.Mode.Load()
		}
		if raw, err := base64.StdEncoding.DecodeString(pubKeyB64); err == nil && len(raw) == 32 {
			copy(peerKeyBytes[:], raw)
			hasPeerKey = true
		}
	} else if owners := b.peersForAddr(wkep.dst.String()); len(owners) > 1 {
		// Several peers claim this destination, as happens when they sit
		// behind one NAT and share its public addr:port. Picking one would
		// apply another peer's mode and address relay copies to the wrong
		// key, and dropping the relay leg would strand whoever depends on it.
		// The frame therefore goes out under the most conservative mode among
		// the claimants, duplicated to each of them; MAC1 sorts out which one
		// it was for.
		for _, k := range owners {
			if p := b.GetPeerPath(k); p != nil {
				if m := p.Mode.Load(); m > mode {
					mode = m
				}
			}
		}
		// Warm, not Relay, is the conservative choice: it keeps both legs
		// open, so one relay-only claimant cannot close the direct leg for
		// every healthy peer sharing the address. Both legs also compensate
		// for the per-peer safety nets that cannot run while no single
		// PeerPath is resolved.
		if mode == PathModeRelay {
			mode = PathModeWarm
		}
		// Fan out to the claimants that need the relay, which is everyone
		// except peers already committed to direct. The filter is by
		// recipient rather than by frame type so that a co-resident peer
		// reachable only over the relay receives its transport data and not
		// just handshakes. Amplification is bounded by the number of
		// relay-needing claimants on one address.
		contestedKeys = make([][32]byte, 0, len(owners))
		for _, k := range owners {
			p := b.GetPeerPath(k)
			if p != nil && p.Mode.Load() == PathModeDirect {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(raw) != 32 {
				continue
			}
			var kb [32]byte
			copy(kb[:], raw)
			contestedKeys = append(contestedKeys, kb)
		}
	}

	// A destination that resolves to no peer leaves the frame direct-only:
	// without a key there is no relay leg to fall back on, whatever mode the
	// agent chose. It means the device roamed to an address the bind never
	// claimed, which is worth reporting outside debug builds — rate-limited,
	// since this is the send path.
	if pp == nil && !hasPeerKey {
		nowNsLog := time.Now().UnixNano()
		last := lastLogNoPeerNs.Load()
		if nowNsLog-last > sendDiagLogIntervalNs &&
			lastLogNoPeerNs.CompareAndSwap(last, nowNsLog) {
			log.Printf("[bind] send resolved no peer, relay leg unavailable dst=%s", wkep.dst.String())
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

	if bindDebug && directStale && !(relay != nil && hasPeerKey) {
		last := lastLogDirectStaleNoRelayNs.Load()
		if nowNs-last > sendDiagLogIntervalNs &&
			lastLogDirectStaleNoRelayNs.CompareAndSwap(last, nowNs) {
			log.Printf("[bind] debug direct-stale no-relay dst=%s hasPeerKey=%v relayNil=%v",
				wkep.dst.String(), hasPeerKey, relay == nil)
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

	// The direct leg's destination comes from the agent-owned path table
	// rather than from the endpoint wireguard-go handed back. That endpoint
	// follows the last packet received, which for a peer in Warm mode is as
	// likely to have been the relay copy; taking it literally would drop the
	// direct leg until the next sync rewrote it.
	dst := wkep.dst
	if dst.Port() == 0 && pp != nil {
		// authAddr first: it comes from the device's roamed endpoint, which
		// only an authenticated packet can move. learnedAddr is stamped on
		// the receive path before any crypto and can rest on an IP-only
		// match, so a host spoofing the peer's source IP could steer the
		// direct leg with it.
		if auth := pp.AuthAddr(); auth.IsValid() && auth.Port() != 0 {
			dst = auth
		} else if direct := pp.DirectAddr(); direct.IsValid() && direct.Port() != 0 {
			dst = direct
		}
	}

	// Still no usable UDP destination → relay only.
	if wkep.peerKey != zeroKey && dst.Port() == 0 {
		sendDirect = false
		sendRelay = true
	}

	relayAvailable := relay != nil && (hasPeerKey || len(contestedKeys) > 0)
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

	addr := net.UDPAddrFromAddrPort(dst)

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
			switch {
			case len(contestedKeys) > 0:
				// Success means the relay accepted the frame for at least one
				// claimant, not that any of them received it. That is the same
				// guarantee the single-key path gives: neither can see the far
				// side.
				relayErr = syscall.ENOTCONN
				for _, k := range contestedKeys {
					if err := relay.SendToPeer(k, buf); err == nil {
						relayErr = nil
					}
				}
			default:
				if err := relay.SendToPeer(peerKeyBytes, buf); err != nil {
					relayErr = err
				}
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

// LearnedAddr returns the most recently observed source address for this peer,
// or the zero value if nothing has been learned yet.
func (pp *PeerPath) LearnedAddr() netip.AddrPort {
	pp.learnedAddrMu.Lock()
	defer pp.learnedAddrMu.Unlock()
	return pp.learnedAddr
}

// learnedAddrSnapshot reads learnedAddr under its mutex.
func (pp *PeerPath) learnedAddrSnapshot() netip.AddrPort {
	pp.learnedAddrMu.Lock()
	defer pp.learnedAddrMu.Unlock()
	return pp.learnedAddr
}

// claimAddr records that pubKeyB64 expects traffic from addr. An address held
// by more than one peer stops resolving until the extra claims are released.
//
// The return value reports whether the claim is new, which lets a caller on the
// datapath log a newly learned address once rather than on every packet.
func (b *WireKubeBind) claimAddr(addr, pubKeyB64 string) bool {
	return b.claimAddrFor(nil, addr, pubKeyB64)
}

// claimAddrFor is claimAddr with the peer's path entry in hand, so that the
// forgotten check and the claim happen under one mutex. Checked separately,
// a claim could land just after ForgetPeer released the peer's others and
// strand an owner that no longer has a path entry to release it.
func (b *WireKubeBind) claimAddrFor(pp *PeerPath, addr, pubKeyB64 string) bool {
	if addr == "" || pubKeyB64 == "" {
		return false
	}
	b.addrMu.Lock()
	defer b.addrMu.Unlock()
	if pp != nil && pp.forgotten.Load() {
		return false
	}
	if b.addrOwners == nil {
		b.addrOwners = make(map[string]map[string]struct{})
	}
	owners := b.addrOwners[addr]
	if owners == nil {
		owners = make(map[string]struct{}, 1)
		b.addrOwners[addr] = owners
	}
	if _, dup := owners[pubKeyB64]; dup {
		return false
	}
	owners[pubKeyB64] = struct{}{}
	return true
}

// releaseAddr drops one peer's claim on addr and leaves the others intact.
// Dropping the second-to-last claim leaves a single owner, so the address
// starts resolving again for the peer that remains.
func (b *WireKubeBind) releaseAddr(addr, pubKeyB64 string) {
	if addr == "" {
		return
	}
	b.addrMu.Lock()
	defer b.addrMu.Unlock()
	owners := b.addrOwners[addr]
	if owners == nil {
		return
	}
	delete(owners, pubKeyB64)
	if len(owners) == 0 {
		delete(b.addrOwners, addr)
	}
}

// peerForAddr resolves addr to a peer public key while exactly one peer claims
// it, and to nothing otherwise. A shared address attributed to whichever peer
// registered last would be worse than no attribution: it names a specific wrong
// peer, and the callers act on that name.
func (b *WireKubeBind) peerForAddr(addr string) (string, bool) {
	b.addrMu.Lock()
	defer b.addrMu.Unlock()
	owners := b.addrOwners[addr]
	if len(owners) != 1 {
		return "", false
	}
	for k := range owners {
		return k, true
	}
	return "", false
}

// peersForAddr returns every peer claiming addr. Send needs the full set
// because a contested address still has to carry the relay leg, and which
// claimant a frame belongs to is settled by the receiver's MAC1 check rather
// than here.
func (b *WireKubeBind) peersForAddr(addr string) []string {
	b.addrMu.Lock()
	defer b.addrMu.Unlock()
	owners := b.addrOwners[addr]
	if len(owners) == 0 {
		return nil
	}
	keys := make([]string, 0, len(owners))
	for k := range owners {
		keys = append(keys, k)
	}
	return keys
}

// ForgetPeer drops a peer's path entry along with every address it claimed.
// Claims outlive the device's peer list otherwise, and a departed peer holding
// its last address forever would leave the next legitimate holder of that
// addr:port permanently contested — ordinary LAN address reuse on a segment is
// enough to hit it.
func (b *WireKubeBind) ForgetPeer(pubKeyB64 string) {
	v, ok := b.pathTable.Load(pubKeyB64)
	if !ok {
		return
	}
	pp := v.(*PeerPath)
	pp.forgotten.Store(true)
	pp.learnedAddrMu.Lock()
	learned := pp.learnedAddr
	pp.learnedAddr = netip.AddrPort{}
	pp.learnedAddrMu.Unlock()
	if learned.IsValid() {
		b.releaseAddr(learned.String(), pubKeyB64)
	}
	if direct := pp.DirectAddr(); direct.IsValid() {
		b.releaseAddr(direct.String(), pubKeyB64)
	}
	// A claim the receive path published between reading the two addresses
	// above and this point is on neither of them, so sweep every owner set.
	// The forgotten flag closes the window going forward; this closes it
	// backwards.
	b.addrMu.Lock()
	for addr, owners := range b.addrOwners {
		if _, ok := owners[pubKeyB64]; ok {
			delete(owners, pubKeyB64)
			if len(owners) == 0 {
				delete(b.addrOwners, addr)
			}
		}
	}
	b.addrMu.Unlock()
	b.pathTable.Delete(pubKeyB64)
}

// updateLearnedAddr records a NAT-mapped source address for a peer and moves
// its address claim to match, so that claims do not accumulate as the peer's
// source port drifts.
func (b *WireKubeBind) updateLearnedAddr(pp *PeerPath, pubKeyB64 string, newAddr netip.AddrPort) {
	if !newAddr.IsValid() {
		return
	}
	pp.learnedAddrMu.Lock()
	defer pp.learnedAddrMu.Unlock()
	if pp.learnedAddr == newAddr {
		return
	}
	if pp.forgotten.Load() {
		return
	}
	// The old address is left claimed when it is also the configured
	// DirectAddr. Claims are a set rather than a refcount, so one release
	// would drop the SetPeerPath claim along with this one and hand the
	// address to a co-resident peer until the next sync re-claimed it.
	if pp.learnedAddr.IsValid() && pp.learnedAddr != pp.DirectAddr() {
		b.releaseAddr(pp.learnedAddr.String(), pubKeyB64)
	}
	pp.learnedAddr = newAddr
	b.claimAddrFor(pp, newAddr.String(), pubKeyB64)
}

// SetPeerPath updates the path table entry for a peer identified by its base64
// public key. Also maintains the address claims used by Send().
func (b *WireKubeBind) SetPeerPath(pubKeyB64 string, mode int32, directAddr netip.AddrPort) {
	v, loaded := b.pathTable.LoadOrStore(pubKeyB64, &PeerPath{})
	pp := v.(*PeerPath)
	pp.Mode.Store(mode)
	if loaded {
		if prev := pp.DirectAddr(); prev != directAddr {
			// Release the previous direct address, unless the learned address
			// still points at it. Symmetric to updateLearnedAddr: claims are a
			// set rather than a refcount, so releasing it there would drop the
			// claim this peer is actively receiving on.
			if prev.IsValid() && prev != pp.learnedAddrSnapshot() {
				b.releaseAddr(prev.String(), pubKeyB64)
			}
			// Drop the confirmed address along with it. It records where the
			// peer authenticated under the endpoint the agent chose before,
			// and says nothing about the one it is choosing now. Kept, it
			// would outrank the new address in Send from the first relay copy
			// onwards — the device endpoint roams to the synthetic, Send falls
			// back to the confirmed address, and the address the agent moved
			// to never carries the traffic that would confirm it.
			pp.authAddr.Store(nil)
		}
	}
	// Stored for a new entry too, not only on change: the datapath resolves a
	// peer's direct destination from this field, so a peer skipped on first
	// registration would be addressable only from the second call onwards.
	pp.setDirectAddr(directAddr)
	if directAddr.IsValid() {
		b.claimAddr(directAddr.String(), pubKeyB64)
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
	nowNs := time.Now().UnixNano()
	prevUntil := pp.hintedUntilNs.Load()
	pp.hintedUntilNs.Store(nowNs + bimodalHintWindowNs)
	if prevUntil <= nowNs {
		log.Printf("[bind] bimodal hint received peer=%s window=%s",
			shortKey(pubKeyB64), time.Duration(bimodalHintWindowNs))
	}
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

// relaySyntheticAddr is the endpoint an unattributed relay delivery is surfaced
// at. The zero port marks it as having no UDP destination, and the loopback
// address carries no claim about where the peer might be.
func relaySyntheticAddr() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)
}

// relaySyntheticAddrFor derives a per-peer address inside 127.0.0.0/8 from the
// peer's public key.
//
// The address is per-peer because wireguard-go keys two things on it alone,
// ignoring the peer identity the endpoint also carries: the mac2 cookie
// (blake2s(secret, DstToBytes)) and the handshake rate limiter
// (limiter.Allow(DstIP())). One shared loopback address would make a single
// cookie valid for every relay-delivered peer and put them all in one
// 20-per-second bucket, which is exactly the wrong behaviour during the mass
// re-handshake that follows a relay restart.
//
// The last octet is forced non-zero so the result is never 127.x.y.0, and the
// port stays zero so Send still treats it as having no UDP destination.
func relaySyntheticAddrFor(peerKey [32]byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, peerKey[0], peerKey[1], peerKey[2] | 0x01}), 0)
}

// makeRelayReceiveFunc creates a ReceiveFunc that reads packets from the relay
// channel and surfaces each one at a synthetic loopback address.
//
// wireguard-go roams a peer's endpoint to whatever address the bind surfaces on
// receive, so surfacing a real address here would make the device endpoint
// assert a direct path on the strength of a packet that arrived over the relay.
// The local-subnet bypass and the transport FSM both read that endpoint, so the
// synthetic is what keeps it an honest record of which leg the peer's last
// authenticated packet came in on.
//
// Nothing is lost on the send side: Send takes the direct destination from the
// agent-owned path table, so a peer sitting at the synthetic still sends on both
// legs while in Warm.
func (b *WireKubeBind) makeRelayReceiveFunc() conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-b.relayCh:
			n := copy(packets[0], pkt.Payload)
			sizes[0] = n
			if pkt.ExternalSource.Valid {
				// The address in the frame is only what the relay claims it
				// is, so it is dropped rather than surfaced: honouring it
				// would let a relay nominate any endpoint it liked for a
				// peer. Replies do not need it, being routed by the
				// RelayAddr and Token carried in externalSource.
				eps[0] = &WireKubeEndpoint{
					dst:            relaySyntheticAddr(),
					externalSource: pkt.ExternalSource,
				}
				if bindDebug {
					log.Printf("[bind] external receive relay=%s token=%d source=%s len=%d",
						pkt.ExternalSource.RelayAddr, pkt.ExternalSource.Token, pkt.ExternalSource.Addr, n)
				}
				return 1, nil
			}
			pubKeyB64 := base64.StdEncoding.EncodeToString(pkt.SrcKey[:])
			if pp := b.GetPeerPath(pubKeyB64); pp != nil {
				pp.RelayHealth.LastSeen.Store(time.Now().UnixNano())
			}
			eps[0] = &WireKubeEndpoint{
				dst:          relaySyntheticAddrFor(pkt.SrcKey),
				relayPeerKey: relayPeerKey{peerKey: pkt.SrcKey},
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
