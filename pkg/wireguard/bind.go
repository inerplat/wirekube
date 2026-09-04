//go:build linux

package wireguard

import (
	"context"
	"crypto/rand"
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
	PathModeWarm   int32 = 1 // UDP, plus relay while direct evidence is missing or stale
	PathModeRelay  int32 = 2 // relay only
)

// directTrustWindow is how long Send trusts the direct leg on the strength of
// its last evidence. Evidence is the newer of the direct data watermark
// (DirectHealth.LastSeen) and the last heartbeat pong (lastPongNs). After this
// many nanoseconds without either, Send duplicates the packet to the relay leg
// so the receiver is reachable regardless of which side of the direct path is
// currently broken.
//
// This is Tailscale's trustBestAddrUntil mechanism (wgengine/magicsock):
// the direct-vs-bimodal decision lives in the datapath, not in a control
// loop, so failover blackout is bounded by this window rather than by the
// agent's sync cadence. The heartbeat (heartbeatTickNs) refreshes trust on a
// healthy path well inside the window, so an idle pair no longer lapses.
const directTrustWindowNs = int64(3 * time.Second)

// Heartbeat scheduler parameters (see runHeartbeat).
const (
	// heartbeatTickNs is the scheduler period: one small ping per active
	// direct peer per tick.
	heartbeatTickNs = int64(1 * time.Second)
	// heartbeatMTUProbeEvery makes every Nth tick an MTU-sized probe.
	heartbeatMTUProbeEvery = 10
	// heartbeatSessionActiveNs is how recently Send must have written to a
	// peer for the scheduler to keep probing it (Tailscale's sessionActiveTimeout).
	heartbeatSessionActiveNs = int64(45 * time.Second)
	// heartbeatSendDstMaxAgeNs bounds how long the address of the last direct
	// write is preferred over AuthAddr/DirectAddr as the probe target.
	heartbeatSendDstMaxAgeNs = int64(60 * time.Second)
	// heartbeatPendingTTLNs is how long a ping's txid stays answerable. A pong
	// arriving later is counted as a replay drop, not as evidence.
	heartbeatPendingTTLNs = int64(3 * time.Second)
	// heartbeatSentAtSkewNs is the tolerated |now - sent_at| on an inbound
	// ping; ordinary clock skew fits, a replayed capture does not.
	heartbeatSentAtSkewNs = int64(60 * time.Second)
	// heartbeatMTUMissLimit consecutive unanswered MTU probes (while small
	// pongs stay fresh) set the mtuStale veto.
	heartbeatMTUMissLimit = 3
	// heartbeatPendingRing is the number of outstanding pings kept per peer.
	heartbeatPendingRing = 4

	// Pong reply rate limits: per peer and for the whole bind.
	heartbeatPongPeerRate  = 4.0
	heartbeatPongPeerBurst = 8.0
	heartbeatPongGlobalCap = 1000.0
)

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

	// hbKey is the heartbeat pair key (k_pair), derived once from the static
	// keys in SetPeerPath / MarkBimodalHint and never on the receive path.
	// nil while the bind has no key pair or the peer key is not a valid
	// X25519 point; heartbeats are then disabled for this peer.
	hbKey atomic.Pointer[[32]byte]

	// Per-peer send accounting. Leg counters are incremented by len(bufs)
	// after every override in Send, so they reflect the legs actually used.
	sentDirectOnly atomic.Uint64
	sentDual       atomic.Uint64
	sentRelayOnly  atomic.Uint64
	pingsSent      atomic.Uint64
	pongsRecv      atomic.Uint64
	authFail       atomic.Uint64
	replayDrop     atomic.Uint64

	// lastSendNs is the last Send for this peer on any leg; it gates the
	// heartbeat (session active within heartbeatSessionActiveNs). Heartbeat
	// frames themselves never touch it.
	lastSendNs atomic.Int64
	// lastPongNs is the second trust watermark next to DirectHealth.LastSeen:
	// the last heartbeat pong, proving a UDP round trip to the probed address.
	// Inbound pings do not refresh it (they prove peer→us only).
	lastPongNs    atomic.Int64
	lastMTUPongNs atomic.Int64
	rttNs         atomic.Int64
	// lastSendDst is the address the last direct write actually went to, i.e.
	// the device's current roamed endpoint. The heartbeat probes it so the
	// probed address equals the sending address even for symmetric-NAT peers
	// whose port drifts ahead of AuthAddr.
	lastSendDst   atomic.Pointer[netip.AddrPort]
	lastSendDstNs atomic.Int64
	// mtuStale is the MTU-probe veto: heartbeatMTUMissLimit MTU probes went
	// unanswered while small pongs stayed fresh, so the path is passing small
	// frames and blackholing large ones. Send treats it as directStale.
	mtuStale atomic.Bool

	// pendingMu guards the outstanding-ping ring and the MTU miss counter.
	pendingMu sync.Mutex
	pending   [heartbeatPendingRing]pendingPing
	// mtuMissed counts consecutive MTU probes that expired unanswered.
	mtuMissed int

	// pongBucket rate-limits pong replies to this peer.
	pongBucket tokenBucket
}

// pendingPing is one outstanding heartbeat ping awaiting its pong.
type pendingPing struct {
	valid    bool
	mtuProbe bool
	txid     [12]byte
	sentAtNs int64
	frameLen uint16
}

// tokenBucket is a small rate limiter for pong replies. Callers pass the
// rate and burst so one type serves the per-peer and global limits.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	lastNs int64
}

// allow takes one token if available, refilling at rate tokens/s up to burst.
func (tb *tokenBucket) allow(nowNs int64, rate, burst float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.lastNs == 0 {
		tb.tokens = burst
	} else if elapsed := nowNs - tb.lastNs; elapsed > 0 {
		tb.tokens += float64(elapsed) / float64(time.Second) * rate
		if tb.tokens > burst {
			tb.tokens = burst
		}
	}
	tb.lastNs = nowNs
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// heartbeatConfig is the local identity and mesh MTU the heartbeat needs,
// installed once by SetHeartbeatConfig.
type heartbeatConfig struct {
	kp  *KeyPair
	mtu int
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

	// Heartbeat state. hbConfig is read lock-free by the receive path and the
	// scheduler; hbStop/hbDone belong to the current socket generation and
	// are handed off under b.mu, but the scheduler itself never takes b.mu
	// because Close holds it while closing the socket.
	hbConfig atomic.Pointer[heartbeatConfig]
	hbStop   chan struct{}
	hbDone   chan struct{}
	hbTicks  atomic.Uint64
	// pongGlobal caps pong replies across all peers.
	pongGlobal tokenBucket

	// nowNs is the clock; nil means time.Now. Tests inject one so trust
	// windows and the pending TTL can be driven without sleeping.
	nowNs func() int64
	// hbTickOverride, when set before Open, replaces the 1s ticker so tests
	// drive ticks by hand through heartbeatTick.
	hbTickOverride <-chan time.Time
}

// NewWireKubeBind creates a new unbound WireKubeBind.
func NewWireKubeBind() *WireKubeBind {
	return &WireKubeBind{}
}

// clockNs returns the current unix time in nanoseconds from the injected
// clock, or the wall clock when none is set.
func (b *WireKubeBind) clockNs() int64 {
	if b.nowNs != nil {
		return b.nowNs()
	}
	return time.Now().UnixNano()
}

// SetRelayTransport injects a relay transport into the bind. Must be called
// before Open. The agent calls this to connect the relay pool to the bind.
func (b *WireKubeBind) SetRelayTransport(rt RelayTransport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.relay = rt
}

// SetHeartbeatConfig gives the bind the local key pair and mesh MTU the
// heartbeat needs: the key pair to derive per-peer heartbeat keys, the MTU to
// size the MTU probe. The engine calls it right after constructing the bind.
// Without it no heartbeat frames are sent or answered and Send falls back to
// data-only evidence. Peers already registered get their key derived here so
// call order against SetPeerPath does not matter.
func (b *WireKubeBind) SetHeartbeatConfig(kp *KeyPair, mtu int) {
	if kp == nil {
		b.hbConfig.Store(nil)
		return
	}
	cfg := &heartbeatConfig{kp: kp, mtu: mtu}
	b.hbConfig.Store(cfg)
	b.pathTable.Range(func(key, value any) bool {
		b.deriveHeartbeatKey(cfg, key.(string), value.(*PeerPath))
		return true
	})
}

// deriveHeartbeatKey computes and caches k_pair for one peer if it is not set
// yet. Called from SetPeerPath and MarkBimodalHint only, never on the receive
// path.
func (b *WireKubeBind) deriveHeartbeatKey(cfg *heartbeatConfig, pubKeyB64 string, pp *PeerPath) {
	if cfg == nil || pp.hbKey.Load() != nil {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(raw) != 32 {
		return
	}
	var peerPub [32]byte
	copy(peerPub[:], raw)
	key, err := deriveHeartbeatKey(cfg.kp.Private, cfg.kp.Public, peerPub)
	if err != nil {
		log.Printf("[bind] heartbeat key derivation failed peer=%s: %v", shortKey(pubKeyB64), err)
		return
	}
	pp.hbKey.Store(key)
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

	// Each socket generation starts with an empty pending-txid table, so a
	// pong addressed to a previous socket cannot refresh trust on this one.
	b.pathTable.Range(func(_, value any) bool {
		value.(*PeerPath).clearPendingPings()
		return true
	})
	b.hbTicks.Store(0)
	b.hbStop = make(chan struct{})
	b.hbDone = make(chan struct{})
	go b.runHeartbeat(udpConn, b.hbTickOverride, b.hbStop, b.hbDone)

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

		// Heartbeat control frames are consumed here, before the peer lookup,
		// and never reach wireguard-go: (0, nil) is "no packets" to
		// RoutineReceiveIncoming. They refresh no data watermark and no
		// learned address; the pong path writes lastPongNs only.
		if hasHeartbeatMagic(packets[0][:n]) {
			b.handleHeartbeat(udpConn, packets[0][:n], addr)
			return 0, nil
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

	if b.udp4 == nil {
		b.mu.Unlock()
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
	stop, done := b.hbStop, b.hbDone
	b.hbStop, b.hbDone = nil, nil
	b.mu.Unlock()

	// Join the scheduler outside b.mu: it never takes the mutex itself, but
	// joining under it would still serialize Close behind a tick in progress
	// for no reason. Writes to the closed socket in that tick are expected
	// and logged once.
	if stop != nil {
		close(stop)
		<-done
	}
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
//   - PathModeDirect / PathModeWarm: write to UDP, and also to the relay
//     while the direct path is unproven (no evidence within
//     directTrustWindow, or the MTU-probe veto). This is the Tailscale
//     DERP-style bimodal send; WireGuard's replay counter on the receiver
//     deduplicates transparently, so duplicate transport is free from a
//     correctness standpoint and gives the receiver the earlier copy
//     regardless of which leg happens to be working right now.
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

	// Decide which legs to send on. Evidence-based (Tailscale's
	// addrForSendLocked): the direct leg is used unless the agent gave up on
	// it, and the relay leg is added whenever the direct path is not
	// currently proven.
	//
	//	evidence    := max(LastSeen, lastPongNs)
	//	directStale := evidence == 0 || now - evidence > directTrustWindowNs || mtuStale
	//	sendDirect  := mode != Relay
	//	sendRelay   := mode == Relay || directStale || hintActive || contested
	//
	// Warm therefore no longer dual-sends unconditionally: it dual-sends while
	// evidence is missing or stale, which for a healthy pair means until the
	// first pong. Direct and Warm still differ in the contested fan-out
	// filter above, in status publication and in the agent's Warm → Relay
	// countdown.
	//
	// The stale check must NOT gate on PathModeDirect alone: once the agent
	// FSM demotes us to Warm, we still need to keep pulling the remote peer
	// into bimodal via hints for the entire outage window. Without that, a
	// peer that re-entered direct-only mode (hint expired, local evidence
	// refreshed by our direct traffic) would stop forwarding our replies over
	// relay the moment we demoted — triggering a second blackout that lasts
	// until the next FSM cycle.
	nowNs := b.clockNs()
	directStale := false
	if mode != PathModeRelay && pp != nil {
		evidence := pp.DirectHealth.LastSeen.Load()
		if pong := pp.lastPongNs.Load(); pong > evidence {
			evidence = pong
		}
		if evidence == 0 || nowNs-evidence > directTrustWindowNs || pp.mtuStale.Load() {
			directStale = true
		}
	}
	sendDirect := mode != PathModeRelay
	// The contested-address branch resolves no pp, so it contributes its own
	// term: without it a contested destination would lose the relay leg that
	// its relay-only claimants depend on.
	sendRelay := mode == PathModeRelay || directStale || len(contestedKeys) > 0

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

	// Accounting, after every override above so the counters describe the
	// legs actually written: counting at the mode decision would ignore the
	// port-0 and relayAvailable flips and over-report dual-send. lastSendNs
	// keeps the heartbeat session alive; lastSendDst is what it probes.
	if pp != nil {
		n := uint64(len(bufs))
		switch {
		case sendDirect && sendRelay:
			pp.sentDual.Add(n)
		case sendDirect:
			pp.sentDirectOnly.Add(n)
		default:
			pp.sentRelayOnly.Add(n)
		}
		pp.lastSendNs.Store(nowNs)
		if sendDirect {
			d := dst
			pp.lastSendDst.Store(&d)
			pp.lastSendDstNs.Store(nowNs)
		}
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
	// The heartbeat key depends only on the two static keys, so it is derived
	// here once (a no-op on every later sync tick) and never on the receive path.
	b.deriveHeartbeatKey(b.hbConfig.Load(), pubKeyB64, pp)
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
	b.deriveHeartbeatKey(b.hbConfig.Load(), pubKeyB64, pp)
	nowNs := b.clockNs()
	prevUntil := pp.hintedUntilNs.Load()
	pp.hintedUntilNs.Store(nowNs + bimodalHintWindowNs)
	if prevUntil <= nowNs {
		log.Printf("[bind] bimodal hint received peer=%s window=%s",
			shortKey(pubKeyB64), time.Duration(bimodalHintWindowNs))
	}
}

// LastDirectPong returns the unix nano timestamp of the last heartbeat pong
// from a peer, or 0 if none has arrived. Kept separate from
// DirectHealth.LastSeen so callers can apply their own liveness gate.
func (b *WireKubeBind) LastDirectPong(pubKeyB64 string) int64 {
	pp := b.GetPeerPath(pubKeyB64)
	if pp == nil {
		return 0
	}
	return pp.lastPongNs.Load()
}

// PeerPathStats returns a snapshot of the peer's send and heartbeat
// accounting, and false if the peer has no path entry.
func (b *WireKubeBind) PeerPathStats(pubKeyB64 string) (PathStats, bool) {
	pp := b.GetPeerPath(pubKeyB64)
	if pp == nil {
		return PathStats{}, false
	}
	return PathStats{
		SentDirectOnly: pp.sentDirectOnly.Load(),
		SentDual:       pp.sentDual.Load(),
		SentRelayOnly:  pp.sentRelayOnly.Load(),
		PingsSent:      pp.pingsSent.Load(),
		PongsRecv:      pp.pongsRecv.Load(),
		AuthFail:       pp.authFail.Load(),
		ReplayDrop:     pp.replayDrop.Load(),
		LastSendNs:     pp.lastSendNs.Load(),
		LastPongNs:     pp.lastPongNs.Load(),
		LastMTUPongNs:  pp.lastMTUPongNs.Load(),
		RTTNs:          pp.rttNs.Load(),
		MTUStale:       pp.mtuStale.Load(),
	}, true
}

// pongStatus is the outcome of matching an inbound pong against the pending
// ping ring.
type pongStatus int

const (
	pongMatched      pongStatus = iota
	pongUnknown                 // no pending entry with that txid (or already consumed)
	pongStale                   // entry older than heartbeatPendingTTLNs
	pongSizeMismatch            // frame_len differs from the ping's
)

// recordPing stores an outstanding ping in the ring, overwriting the oldest
// slot. Four slots outlast the 3s TTL at one ping per second.
func (pp *PeerPath) recordPing(txid [12]byte, sentAtNs int64, frameLen uint16, mtuProbe bool) {
	pp.pendingMu.Lock()
	defer pp.pendingMu.Unlock()
	slot := -1
	var oldest int64
	for i := range pp.pending {
		if !pp.pending[i].valid {
			slot = i
			break
		}
		if slot == -1 || pp.pending[i].sentAtNs < oldest {
			slot, oldest = i, pp.pending[i].sentAtNs
		}
	}
	pp.pending[slot] = pendingPing{valid: true, mtuProbe: mtuProbe, txid: txid, sentAtNs: sentAtNs, frameLen: frameLen}
}

// completePing consumes the pending entry matching txid. The entry is consumed
// on match and on staleness, so a replayed or late pong cannot be accepted
// later; a size mismatch leaves it in place for the genuine pong.
func (pp *PeerPath) completePing(txid [12]byte, frameLen uint16, nowNs int64) (rttNs int64, mtuProbe bool, st pongStatus) {
	pp.pendingMu.Lock()
	defer pp.pendingMu.Unlock()
	for i := range pp.pending {
		e := &pp.pending[i]
		if !e.valid || e.txid != txid {
			continue
		}
		if nowNs-e.sentAtNs > heartbeatPendingTTLNs {
			e.valid = false
			return 0, false, pongStale
		}
		if e.frameLen != frameLen {
			return 0, false, pongSizeMismatch
		}
		e.valid = false
		if e.mtuProbe {
			pp.mtuMissed = 0
		}
		return nowNs - e.sentAtNs, e.mtuProbe, pongMatched
	}
	return 0, false, pongUnknown
}

// expirePendingPings drops entries past the TTL. An expired MTU probe counts
// as a miss only while small pongs are fresh: that is the "small frames pass,
// large frames vanish" signature the veto exists for. A path that answers
// nothing is already handled by the trust window, and would otherwise carry
// a stale miss count into its recovery. Returns the consecutive miss count.
func (pp *PeerPath) expirePendingPings(nowNs int64, smallFresh bool) int {
	pp.pendingMu.Lock()
	defer pp.pendingMu.Unlock()
	for i := range pp.pending {
		e := &pp.pending[i]
		if !e.valid || nowNs-e.sentAtNs <= heartbeatPendingTTLNs {
			continue
		}
		e.valid = false
		if e.mtuProbe {
			if smallFresh {
				pp.mtuMissed++
			} else {
				pp.mtuMissed = 0
			}
		}
	}
	return pp.mtuMissed
}

// clearPendingPings empties the ring for a new socket generation.
func (pp *PeerPath) clearPendingPings() {
	pp.pendingMu.Lock()
	defer pp.pendingMu.Unlock()
	pp.pending = [heartbeatPendingRing]pendingPing{}
	pp.mtuMissed = 0
}

// heartbeatAddr is the address the scheduler probes: the address of the last
// direct write while it is recent (the device's current roamed endpoint),
// then the authenticated address, then the bootstrap address. LearnedAddr is
// excluded on purpose: it is set before crypto from an IP-only match.
func (pp *PeerPath) heartbeatAddr(nowNs int64) netip.AddrPort {
	if d := pp.lastSendDst.Load(); d != nil && d.IsValid() && d.Port() != 0 &&
		nowNs-pp.lastSendDstNs.Load() <= heartbeatSendDstMaxAgeNs {
		return *d
	}
	if a := pp.AuthAddr(); a.IsValid() && a.Port() != 0 {
		return a
	}
	if d := pp.DirectAddr(); d.IsValid() && d.Port() != 0 {
		return d
	}
	return netip.AddrPort{}
}

// handleHeartbeat processes one heartbeat datagram from the direct socket.
// Rules, in order: unsupported version, frame_len ≠ datagram length, and MAC
// mismatch are authFail; a sender without a path entry (or without a derived
// key) is dropped before any crypto and without a counter, since there is
// nowhere to count it. A ping must have one of the two scheduler sizes and a
// sent_at within the skew window; it is answered with a pong of the same
// frame_len to the datagram's source, under a per-peer and a global rate
// limit, and refreshes nothing (it proves peer→us only). A pong is matched
// against the pending ring; only a match writes lastPongNs and RTT.
func (b *WireKubeBind) handleHeartbeat(udpConn *net.UDPConn, frame []byte, src netip.AddrPort) {
	hdr, versionOK := decodeHeartbeatHeader(frame)
	pubKeyB64 := base64.StdEncoding.EncodeToString(hdr.Sender[:])
	pp := b.GetPeerPath(pubKeyB64)
	if pp == nil {
		return
	}
	key := pp.hbKey.Load()
	if key == nil {
		return
	}
	if !versionOK || int(hdr.FrameLen) != len(frame) || !verifyHeartbeatMAC(frame, key[:]) {
		pp.authFail.Add(1)
		return
	}
	nowNs := b.clockNs()

	switch hdr.Type {
	case heartbeatTypePing:
		cfg := b.hbConfig.Load()
		if cfg == nil {
			return
		}
		if !heartbeatPingSizeAllowed(len(frame), cfg.mtu) {
			pp.authFail.Add(1)
			return
		}
		if skew := nowNs - hdr.SentAt; skew > heartbeatSentAtSkewNs || skew < -heartbeatSentAtSkewNs {
			pp.replayDrop.Add(1)
			return
		}
		// Global cap first: consuming the per-peer token before checking it
		// would let a saturated global drain every peer's bucket, so the
		// backlog would outlive the flood that caused it.
		if !b.pongGlobal.allow(nowNs, heartbeatPongGlobalCap, heartbeatPongGlobalCap) ||
			!pp.pongBucket.allow(nowNs, heartbeatPongPeerRate, heartbeatPongPeerBurst) {
			return
		}
		pong := encodeHeartbeat(heartbeatFrame{
			Type:     heartbeatTypePong,
			FrameLen: hdr.FrameLen,
			TxID:     hdr.TxID,
			SentAt:   hdr.SentAt,
			Sender:   cfg.kp.Public,
		}, key[:])
		if _, err := udpConn.WriteToUDPAddrPort(pong, src); err != nil && bindDebug {
			log.Printf("[bind] heartbeat pong write peer=%s dst=%s err=%v", shortKey(pubKeyB64), src, err)
		}

	case heartbeatTypePong:
		rtt, mtuProbe, st := pp.completePing(hdr.TxID, hdr.FrameLen, nowNs)
		switch st {
		case pongMatched:
			pp.lastPongNs.Store(nowNs)
			pp.rttNs.Store(rtt)
			pp.pongsRecv.Add(1)
			if mtuProbe {
				pp.lastMTUPongNs.Store(nowNs)
				if pp.mtuStale.Swap(false) {
					log.Printf("[bind] heartbeat MTU probe answered again peer=%s, veto cleared", shortKey(pubKeyB64))
				}
			}
		case pongSizeMismatch:
			pp.authFail.Add(1)
		default: // unknown, consumed, or stale txid
			pp.replayDrop.Add(1)
		}

	default:
		pp.authFail.Add(1)
	}
}

// runHeartbeat is the scheduler goroutine, one per socket generation. It
// receives the socket as an argument and never takes b.mu, because Close
// holds b.mu while closing that socket and then joins this goroutine.
func (b *WireKubeBind) runHeartbeat(udpConn *net.UDPConn, tickOverride <-chan time.Time, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	tick := tickOverride
	if tick == nil {
		t := time.NewTicker(time.Duration(heartbeatTickNs))
		defer t.Stop()
		tick = t.C
	}
	logged := false
	for {
		select {
		case <-stop:
			return
		case <-tick:
			if err := b.heartbeatTick(udpConn); err != nil && !logged {
				// Expected once per generation when a tick races Close.
				logged = true
				log.Printf("[bind] heartbeat ping write err=%v (logged once)", err)
			}
		}
	}
}

// heartbeatTick sends one ping to every peer that qualifies: Mode is Direct
// or Warm, a usable address exists (stub entries from MarkBimodalHint have
// Mode 0 and no address and are skipped), and the session is active (Send
// wrote to the peer within heartbeatSessionActiveNs). Every
// heartbeatMTUProbeEvery-th tick sends the MTU probe instead of the small
// ping. Heartbeat frames bypass Send and do not touch lastSendNs. Returns the
// first write error, for the caller's once-per-generation log.
func (b *WireKubeBind) heartbeatTick(udpConn *net.UDPConn) error {
	cfg := b.hbConfig.Load()
	if cfg == nil {
		return nil
	}
	tickNo := b.hbTicks.Add(1)
	mtuProbe := tickNo%heartbeatMTUProbeEvery == 0
	frameLen := heartbeatMinLen
	if mtuProbe {
		if l := heartbeatMTUProbeLen(cfg.mtu); l > heartbeatMinLen && l <= 0xFFFF {
			frameLen = l
		}
	}
	nowNs := b.clockNs()
	var firstErr error
	b.pathTable.Range(func(key, value any) bool {
		pp := value.(*PeerPath)
		if pp.Mode.Load() == PathModeRelay {
			return true
		}
		k := pp.hbKey.Load()
		if k == nil {
			return true
		}
		dst := pp.heartbeatAddr(nowNs)
		if !dst.IsValid() {
			return true
		}
		if last := pp.lastSendNs.Load(); last == 0 || nowNs-last > heartbeatSessionActiveNs {
			return true
		}

		lastPong := pp.lastPongNs.Load()
		smallFresh := lastPong != 0 && nowNs-lastPong <= directTrustWindowNs
		if pp.expirePendingPings(nowNs, smallFresh) >= heartbeatMTUMissLimit && smallFresh {
			if !pp.mtuStale.Swap(true) {
				log.Printf("[bind] heartbeat MTU probes unanswered while small pongs are fresh peer=%s, dual-send until the next MTU pong",
					shortKey(key.(string)))
			}
		}

		var txid [12]byte
		if _, err := rand.Read(txid[:]); err != nil {
			return true
		}
		ping := encodeHeartbeat(heartbeatFrame{
			Type:     heartbeatTypePing,
			FrameLen: uint16(frameLen),
			TxID:     txid,
			SentAt:   nowNs,
			Sender:   cfg.kp.Public,
		}, k[:])
		if _, err := udpConn.WriteToUDPAddrPort(ping, dst); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return true
		}
		// Only a ping that left the socket is pending. Recording before the
		// write would let a local send error age out as a missed MTU probe
		// and latch the veto on a path that was never tested.
		pp.recordPing(txid, nowNs, uint16(frameLen), mtuProbe)
		pp.pingsSent.Add(1)
		return true
	})
	return firstErr
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
