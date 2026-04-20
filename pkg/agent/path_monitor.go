package agent

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/wirekube/wirekube/pkg/wireguard"
)

// PathMode is the agent-owned transport mode for a single peer. It mirrors
// wireguard.PathMode but is the single source of truth: the agent decides
// the mode, the Bind faithfully executes whatever it is told, and the
// status publication reads from here. The two other representations
// (wireguard.PathMode in the engine API, and PathMode* int32 in the Bind)
// exist only because they cross package / atomic boundaries.
type PathMode int

const (
	// PathUnknown means the monitor has not yet observed this peer.
	PathUnknown PathMode = iota
	// PathModeRelay: relay-only. Used as the safe default for new peers and
	// as the terminal state for peers whose direct path has proven unusable.
	PathModeRelay
	// PathModeWarm: packets go on BOTH the direct UDP leg and the relay leg.
	// This is the transitional state used when promoting from Relay toward
	// Direct (we do not know yet whether direct works), and when demoting
	// from Direct toward Relay (we have lost confidence in direct but want
	// zero blackout). WireGuard's replay counter deduplicates on the receiver.
	PathModeWarm
	// PathModeDirect: UDP-only. Entered only after direct receive evidence
	// has been observed, and left as soon as that evidence goes stale.
	PathModeDirect
)

func (m PathMode) String() string {
	switch m {
	case PathUnknown:
		return "unknown"
	case PathModeDirect:
		return "direct"
	case PathModeWarm:
		return "warm"
	case PathModeRelay:
		return "relay"
	default:
		return fmt.Sprintf("PathMode(%d)", int(m))
	}
}

// toWireguardPathMode maps the agent-level mode onto the engine's external
// enum. PathUnknown is treated as Relay (the safe default).
func (m PathMode) toWireguardPathMode() wireguard.PathMode {
	switch m {
	case PathModeDirect:
		return wireguard.PathDirect
	case PathModeWarm:
		return wireguard.PathWarm
	default:
		return wireguard.PathRelay
	}
}

// directReceiver is the subset of the engine interface PathMonitor needs.
// Abstracted so unit tests can drive the FSM with deterministic timestamps.
type directReceiver interface {
	LastDirectReceive(pubKey string) int64
}

// PathMonitor is a per-mesh finite state machine that chooses the transport
// mode (Direct / Warm / Relay) for every peer based purely on receive-side
// evidence. All per-peer state lives in entries; there are no global flags.
//
// The design intent — borrowed directly from Tailscale's addrForSendLocked
// + trustBestAddrUntil (wgengine/magicsock/endpoint.go) — is:
//
//  1. Relay is always hot. The relay pool maintains a persistent TCP
//     connection at all times; that is a property of pkg/agent/relay,
//     not of this FSM. From this FSM's perspective, relay is "free".
//  2. Direct is an opportunistic overlay on top of relay. Whenever the
//     direct path is unproven or unreliable, we run in Warm (bimodal
//     send) so the receiver has already accepted the relay copy of
//     whatever would have been lost if direct broke.
//  3. We commit to Direct (UDP-only) only after fresh direct receive
//     evidence, and we revert to Warm the instant that evidence goes
//     stale. Direct → Warm is therefore aggressive; Warm → Direct is
//     conservative; Warm → Relay is slow.
//
// All transitions are driven off a single signal:
// engine.LastDirectReceive(pubKey) — the unix-nano timestamp of the most
// recent direct UDP packet the Bind observed from that peer. Handshake
// success is NOT a valid signal: in Warm mode the handshake may complete
// via the relay leg, masking a dead direct path.
type PathMonitor struct {
	log logr.Logger
	rx  directReceiver

	// thresholds — read under no lock; PathMonitor assumes they do not
	// change after NewPathMonitor returns.
	warmStall  time.Duration // Direct → Warm: LastDirectReceive stale by this much
	relayStall time.Duration // Warm   → Relay: direct still absent this long after Warm entry
	promoteAge time.Duration // Warm   → Direct: LastDirectReceive fresher than this AND newer than warmEnteredAt
	relayRetry time.Duration // Relay  → Warm: minimum interval between opportunistic probes

	now func() time.Time

	mu      sync.Mutex
	entries map[string]*pathEntry
}

type pathEntry struct {
	pubKey        string
	mode          PathMode
	modeEnteredAt time.Time
	// lastDirectSeen is the nanosecond watermark cached from the engine
	// the last time this entry was evaluated. We use it as the baseline
	// for "direct RX observed since the current mode was entered".
	lastDirectSeen int64
	// lastProbeAt records the wallclock time of the most recent Relay→Warm
	// attempt, so the Relay backoff loop does not fire every sync cycle.
	lastProbeAt time.Time
}

// PathMonitorConfig bundles the thresholds. Defaults are applied for any
// zero-valued field, so the caller can set just what it wants to override.
type PathMonitorConfig struct {
	// WarmStall is how long the direct receive watermark is allowed to go
	// without updating before Direct is demoted to Warm. Default: 3s.
	WarmStall time.Duration
	// RelayStall is the additional time the entry can stay in Warm without
	// any direct receive before being demoted to Relay. Default: 30s.
	RelayStall time.Duration
	// PromoteAge is the maximum age of a direct receive watermark for it
	// to count as "fresh evidence" when considering Warm → Direct. Default: 1.5s.
	PromoteAge time.Duration
	// RelayRetry is the minimum wallclock gap between successive
	// Relay → Warm opportunistic probes. Default: 30s.
	RelayRetry time.Duration
}

// NewPathMonitor constructs a PathMonitor with the given engine for
// receive-watermark queries. The `now` argument is a clock function so
// unit tests can drive the FSM deterministically; pass time.Now in prod.
func NewPathMonitor(log logr.Logger, rx directReceiver, cfg PathMonitorConfig, now func() time.Time) *PathMonitor {
	if cfg.WarmStall == 0 {
		cfg.WarmStall = 3 * time.Second
	}
	if cfg.RelayStall == 0 {
		cfg.RelayStall = 30 * time.Second
	}
	if cfg.PromoteAge == 0 {
		cfg.PromoteAge = 1500 * time.Millisecond
	}
	if cfg.RelayRetry == 0 {
		cfg.RelayRetry = 30 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &PathMonitor{
		log:        log,
		rx:         rx,
		warmStall:  cfg.WarmStall,
		relayStall: cfg.RelayStall,
		promoteAge: cfg.PromoteAge,
		relayRetry: cfg.RelayRetry,
		now:        now,
		entries:    make(map[string]*pathEntry),
	}
}

// ModeFor returns the current transport mode for a peer. Returns
// PathUnknown if the peer has never been evaluated.
func (m *PathMonitor) ModeFor(peerName string) PathMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[peerName]; ok {
		return e.mode
	}
	return PathUnknown
}

// Forget removes all state for a peer. Call when a WireKubePeer is deleted.
func (m *PathMonitor) Forget(peerName string) {
	m.mu.Lock()
	delete(m.entries, peerName)
	m.mu.Unlock()
}

// ForgetMissing removes entries for any peers not present in `alive`. Call
// from the sync loop after listing the current peer set so the monitor's
// map does not accumulate stale entries across CRD churn.
func (m *PathMonitor) ForgetMissing(alive []string) {
	if len(m.entries) == 0 {
		return
	}
	keep := make(map[string]struct{}, len(alive))
	for _, n := range alive {
		keep[n] = struct{}{}
	}
	m.mu.Lock()
	for name := range m.entries {
		if _, ok := keep[name]; !ok {
			delete(m.entries, name)
		}
	}
	m.mu.Unlock()
}

// Evaluate advances the FSM for one peer and returns the (possibly new)
// mode. The caller is responsible for translating the result into a
// SetPeerPath call on the engine — PathMonitor intentionally does no I/O.
//
// `forceProbe`, when true, shortcuts the Relay→Warm backoff check so a
// caller (e.g. the ICE layer detecting a new direct handshake attempt)
// can request an opportunistic probe out of band.
func (m *PathMonitor) Evaluate(peerName, pubKey string, forceProbe bool) PathMode {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	lastDirect := m.rx.LastDirectReceive(pubKey)

	e, ok := m.entries[peerName]
	if !ok {
		// First sight of a peer: start on Relay and treat the first backoff
		// window (relayRetry) as elapsed from *now*, not from epoch zero.
		// That ensures a fresh peer does not auto-probe before the backoff
		// deadline — the sync loop may call Evaluate many times per second,
		// and we do not want every one of those calls to fire a new probe.
		// Out-of-band signals from the ICE layer still get through via the
		// forceProbe argument.
		e = &pathEntry{
			pubKey:         pubKey,
			mode:           PathModeRelay,
			modeEnteredAt:  now,
			lastDirectSeen: lastDirect,
			lastProbeAt:    now,
		}
		m.entries[peerName] = e
		m.log.V(1).Info("path monitor: new peer, starting on relay", "peer", peerName)
		// Fall through into the switch: force-probe should take effect on
		// first sight too (and for non-force calls, the backoff we just
		// set to `now` suppresses an accidental probe).
	}

	// pubKey can change if the peer CRD is recreated; refresh it so
	// subsequent LastDirectReceive lookups use the current key.
	e.pubKey = pubKey

	// directFresh = a direct packet arrived within promoteAge wall-time
	// AND that packet is strictly newer than the packet we had seen when
	// the current mode was entered. Both conditions matter: the first
	// prevents ancient evidence from counting; the second prevents the
	// same packet from repeatedly re-promoting a flapping peer.
	directFresh := false
	if lastDirect > 0 {
		age := now.Sub(time.Unix(0, lastDirect))
		if age >= 0 && age <= m.promoteAge && lastDirect > e.lastDirectSeen {
			directFresh = true
		}
	}
	e.lastDirectSeen = lastDirect

	prev := e.mode
	switch e.mode {
	case PathModeDirect:
		// Direct → Warm: any stall of the direct receive watermark beyond
		// warmStall. Even a short stall is treated as uncertainty because
		// the cost of switching to Warm is free (duplicate send, receiver
		// dedupes) and the cost of staying Direct on a dead path is
		// measured in dropped packets per second.
		if !directFresh && !hasDirect(lastDirect, now, m.warmStall) {
			e.setMode(PathModeWarm, now)
		}

	case PathModeWarm:
		// Warm → Direct: fresh direct evidence promotes immediately.
		// Warm → Relay: direct has been absent for relayStall since the
		// entry went Warm. This is the only slow transition in the FSM;
		// everything else is datapath-fast.
		if directFresh {
			e.setMode(PathModeDirect, now)
		} else if now.Sub(e.modeEnteredAt) >= m.relayStall {
			e.setMode(PathModeRelay, now)
		}

	case PathModeRelay:
		// Relay → Warm: opportunistically probe whenever forced (ICE says
		// now) or whenever the backoff interval has elapsed. Note that we
		// enter Warm, not Direct — a probe that cannot prove direct
		// connectivity stays bimodal and will drift back to Relay after
		// relayStall.
		if forceProbe || now.Sub(e.lastProbeAt) >= m.relayRetry {
			e.lastProbeAt = now
			e.setMode(PathModeWarm, now)
		}
	}

	if e.mode != prev {
		m.log.Info("path monitor: transition",
			"peer", peerName,
			"from", prev,
			"to", e.mode,
			"lastDirectAge", ageString(lastDirect, now),
		)
	}
	return e.mode
}

// hasDirect reports whether lastDirect is non-zero AND within maxAge of now.
func hasDirect(lastDirect int64, now time.Time, maxAge time.Duration) bool {
	if lastDirect <= 0 {
		return false
	}
	return now.Sub(time.Unix(0, lastDirect)) < maxAge
}

func ageString(lastDirect int64, now time.Time) string {
	if lastDirect <= 0 {
		return "never"
	}
	return now.Sub(time.Unix(0, lastDirect)).String()
}

func (e *pathEntry) setMode(m PathMode, now time.Time) {
	e.mode = m
	e.modeEnteredAt = now
}
