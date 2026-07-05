package agent

import (
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
)

// fakeRX implements directReceiver with a per-peer map of last-direct-rx
// nanosecond timestamps. Tests manipulate the map directly between
// Evaluate calls to simulate packet arrivals.
type fakeRX struct {
	last map[string]int64
}

func (f *fakeRX) LastDirectReceive(pubKey string) int64 {
	return f.last[pubKey]
}

// fakeClock returns a time.Time that the test can advance between
// Evaluate calls, giving deterministic control over the FSM's wallclock.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func (c *fakeClock) now() time.Time          { return c.t }

// newMonitor builds a PathMonitor with test-friendly short thresholds:
// warmStall=100ms, relayStall=500ms, promoteAge=50ms, relayRetry=200ms.
// These values keep transition boundaries well-separated in nanoseconds
// so the tests don't need to think about clock resolution, and let
// individual tests advance the clock in obvious units.
func newMonitor(t *testing.T) (*PathMonitor, *fakeRX, *fakeClock) {
	t.Helper()
	rx := &fakeRX{last: map[string]int64{}}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	pm := NewPathMonitor(testr.New(t), rx, PathMonitorConfig{
		WarmStall:  100 * time.Millisecond,
		RelayStall: 500 * time.Millisecond,
		PromoteAge: 50 * time.Millisecond,
		RelayRetry: 200 * time.Millisecond,
	}, clk.now)
	return pm, rx, clk
}

// TestFirstSightStartsOnRelay asserts the safe default: a peer that has
// never been evaluated enters the FSM in Relay.
func TestFirstSightStartsOnRelay(t *testing.T) {
	pm, _, _ := newMonitor(t)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("first Evaluate = %v, want PathModeRelay", got)
	}
}

// TestRelayToWarmOnForceProbe asserts that a caller-driven probe request
// (e.g. ICE saw a NAT-matched candidate) skips the backoff check.
func TestRelayToWarmOnForceProbe(t *testing.T) {
	pm, _, _ := newMonitor(t)
	pm.Evaluate("p1", "key1", false) // entry exists, mode=Relay
	if got := pm.Evaluate("p1", "key1", true); got != PathModeWarm {
		t.Fatalf("force-probe from Relay = %v, want PathModeWarm", got)
	}
}

// TestRelayToWarmHonoursBackoff asserts that without a force flag the
// monitor waits relayRetry before re-entering Warm, so a fast sync loop
// does not fire a probe every cycle.
func TestRelayToWarmHonoursBackoff(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", false) // Relay, lastProbeAt=now

	clk.advance(100 * time.Millisecond) // < relayRetry (200ms)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("Evaluate before backoff elapsed = %v, want PathModeRelay", got)
	}

	clk.advance(150 * time.Millisecond) // total 250ms > 200ms
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("Evaluate after backoff elapsed = %v, want PathModeWarm", got)
	}
}

// TestWarmToDirectOnFreshReceive asserts the promotion path: once the
// receive-watermark advances during the Warm window, the FSM commits
// to Direct on the next Evaluate.
func TestWarmToDirectOnFreshReceive(t *testing.T) {
	pm, rx, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", true) // Warm

	// Simulate a direct packet arriving 10ms later.
	clk.advance(10 * time.Millisecond)
	rx.last["key1"] = clk.now().UnixNano()

	if got := pm.Evaluate("p1", "key1", false); got != PathModeDirect {
		t.Fatalf("Evaluate with fresh RX = %v, want PathModeDirect", got)
	}
}

// TestWarmToRelayAfterStallTimeout asserts the slow-demote path: if the
// direct leg never produces evidence during the Warm window, we give
// up and go back to Relay-only. relayStall is intentionally the only
// slow transition in the FSM.
func TestWarmToRelayAfterStallTimeout(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", true) // Warm at t=0

	clk.advance(400 * time.Millisecond) // < relayStall
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("Evaluate before relayStall = %v, want PathModeWarm", got)
	}

	clk.advance(200 * time.Millisecond) // total 600ms > relayStall=500ms
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("Evaluate after relayStall = %v, want PathModeRelay", got)
	}
}

// TestDirectToWarmOnStall asserts the aggressive demotion path that makes
// "immediate" failover possible: as soon as the direct receive watermark
// ages past warmStall, the FSM drops to Warm so both legs carry the next
// packet. This is the transition that eliminates the blackout window.
func TestDirectToWarmOnStall(t *testing.T) {
	pm, rx, clk := newMonitor(t)
	// Drive the peer to Direct first.
	pm.Evaluate("p1", "key1", true) // Warm
	clk.advance(10 * time.Millisecond)
	rx.last["key1"] = clk.now().UnixNano()
	if got := pm.Evaluate("p1", "key1", false); got != PathModeDirect {
		t.Fatalf("setup: want Direct, got %v", got)
	}

	// Advance past warmStall without updating the RX watermark — simulates
	// the remote's return path being dropped (iptables INPUT DROP in e2e).
	clk.advance(200 * time.Millisecond) // > warmStall (100ms)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("Evaluate after direct stall = %v, want PathModeWarm", got)
	}
}

// TestDirectStaysDirectOnContinuousReceive is the negative complement of
// the stall test: if direct packets keep arriving, the FSM does not flap
// back to Warm.
func TestDirectStaysDirectOnContinuousReceive(t *testing.T) {
	pm, rx, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", true)
	clk.advance(10 * time.Millisecond)
	rx.last["key1"] = clk.now().UnixNano()
	if got := pm.Evaluate("p1", "key1", false); got != PathModeDirect {
		t.Fatalf("setup: want Direct, got %v", got)
	}

	// Simulate steady direct traffic: advance the clock and the RX
	// watermark together a few times.
	for i := 0; i < 5; i++ {
		clk.advance(30 * time.Millisecond)
		rx.last["key1"] = clk.now().UnixNano()
		if got := pm.Evaluate("p1", "key1", false); got != PathModeDirect {
			t.Fatalf("iteration %d: want Direct, got %v", i, got)
		}
	}
}

// TestForgetClearsEntry asserts that Forget completely drops the peer's
// state so re-adding the same name rebuilds the FSM from scratch.
func TestForgetClearsEntry(t *testing.T) {
	pm, _, _ := newMonitor(t)
	pm.Evaluate("p1", "key1", true) // Warm
	pm.Forget("p1")
	if got := pm.ModeFor("p1"); got != PathUnknown {
		t.Fatalf("ModeFor after Forget = %v, want PathUnknown", got)
	}
	// Next Evaluate should restart on Relay.
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("first Evaluate after Forget = %v, want PathModeRelay", got)
	}
}

// TestStaleWatermarkIsNotFreshEvidence asserts that an RX watermark
// captured before the peer entered Warm (e.g. from a previous Direct
// session whose evidence the monitor already consumed) does not promote.
// Without this guard, a peer that flaps Direct → Warm → Direct would
// promote immediately on every Warm entry using the same cached packet.
func TestStaleWatermarkIsNotFreshEvidence(t *testing.T) {
	pm, rx, clk := newMonitor(t)
	// Put a non-zero RX watermark from before Evaluate ever runs.
	rx.last["key1"] = clk.now().UnixNano()
	pm.Evaluate("p1", "key1", false) // Relay; lastDirectSeen captured

	clk.advance(250 * time.Millisecond) // past relayRetry
	// No new RX packet has arrived; watermark is identical to the one
	// captured on the first Evaluate.
	got := pm.Evaluate("p1", "key1", false)
	if got != PathModeWarm {
		t.Fatalf("second Evaluate = %v, want PathModeWarm (probe triggered)", got)
	}
	// Third Evaluate: still no new RX. Stays in Warm, does NOT promote.
	clk.advance(10 * time.Millisecond)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("stale watermark promoted to Direct (should not): got %v", got)
	}
}

// TestMarkNeverDirectSuppressesProbe asserts that pinning a peer with
// MarkNeverDirect prevents both the timer-based and forced Relay→Warm
// transitions, so symmetric ↔ symmetric NAT pairs (with birthday attack
// disabled or already failed) stop oscillating between modes.
func TestMarkNeverDirectSuppressesProbe(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", false) // Relay
	pm.MarkNeverDirect("p1", "key1")

	// Backoff timer elapsed: would normally probe Relay→Warm.
	clk.advance(300 * time.Millisecond) // > relayRetry (200ms)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("Evaluate after timer with neverDirect = %v, want PathModeRelay", got)
	}

	// forceProbe must not override neverDirect: this is the contract
	// that lets the agent durably pin a peer to relay even if other
	// signals (e.g. ICE detected an inbound direct packet via relay
	// keepalive proxying) would normally trigger a probe.
	if got := pm.Evaluate("p1", "key1", true); got != PathModeRelay {
		t.Fatalf("Evaluate with forceProbe and neverDirect = %v, want PathModeRelay", got)
	}
}

// TestMarkNeverDirectFromWarmDemotes asserts that calling MarkNeverDirect
// while the peer is already in Warm (e.g. an in-flight probe just before
// the agent decides this pair is impossible) demotes immediately back to
// Relay rather than waiting out relayStall.
func TestMarkNeverDirectFromWarmDemotes(t *testing.T) {
	pm, _, _ := newMonitor(t)
	pm.Evaluate("p1", "key1", true) // Warm
	pm.MarkNeverDirect("p1", "key1")
	if got := pm.ModeFor("p1"); got != PathModeRelay {
		t.Fatalf("ModeFor after MarkNeverDirect from Warm = %v, want PathModeRelay", got)
	}
}

// TestMarkNeverDirectCreatesEntry asserts that MarkNeverDirect is safe to
// call before the peer has ever been Evaluate-d. The agent's ICE loop and
// the data-plane sync loop are independent goroutines, so the marking can
// land first.
func TestMarkNeverDirectCreatesEntry(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.MarkNeverDirect("p1", "key1")
	if got := pm.ModeFor("p1"); got != PathModeRelay {
		t.Fatalf("ModeFor after MarkNeverDirect on missing entry = %v, want PathModeRelay", got)
	}
	clk.advance(time.Hour) // way past any timer
	if got := pm.Evaluate("p1", "key1", true); got != PathModeRelay {
		t.Fatalf("Evaluate after MarkNeverDirect on missing entry = %v, want PathModeRelay", got)
	}
}

// TestClearNeverDirectRestoresProbing asserts the symmetric undo path:
// once the agent decides direct may now work (e.g. NAT type re-discovered
// as cone, or birthday attack flipped on), ClearNeverDirect lets the
// timer fire again on the next backoff window.
func TestClearNeverDirectRestoresProbing(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", false) // Relay, lastProbeAt = now
	pm.MarkNeverDirect("p1", "key1")

	clk.advance(300 * time.Millisecond)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("setup: still pinned, got %v", got)
	}

	pm.ClearNeverDirect("p1")
	// neverDirect is cleared but lastProbeAt was anchored when the entry
	// was created, and the clock has already moved past relayRetry. The
	// next Evaluate should now fire the deferred probe.
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("Evaluate after ClearNeverDirect = %v, want PathModeWarm", got)
	}
}

func TestBackoffDirectProbeUntilSuppressesTimerProbe(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", false) // Relay, lastProbeAt = now

	pm.BackoffDirectProbeUntil("p1", "key1", clk.now().Add(time.Second))
	clk.advance(300 * time.Millisecond) // > relayRetry (200ms)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeRelay {
		t.Fatalf("Evaluate during probe backoff = %v, want PathModeRelay", got)
	}

	clk.advance(time.Second)
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("Evaluate after probe backoff = %v, want PathModeWarm", got)
	}
}

func TestForceProbeOverridesTemporaryBackoff(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", false)
	pm.BackoffDirectProbeUntil("p1", "key1", clk.now().Add(time.Second))

	if got := pm.Evaluate("p1", "key1", true); got != PathModeWarm {
		t.Fatalf("forced Evaluate during probe backoff = %v, want PathModeWarm", got)
	}
}

func TestClearProbeBackoffRestoresTimerProbe(t *testing.T) {
	pm, _, clk := newMonitor(t)
	pm.Evaluate("p1", "key1", false)
	pm.BackoffDirectProbeUntil("p1", "key1", clk.now().Add(time.Second))

	clk.advance(300 * time.Millisecond) // > relayRetry (200ms)
	pm.ClearProbeBackoff("p1")
	if got := pm.Evaluate("p1", "key1", false); got != PathModeWarm {
		t.Fatalf("Evaluate after ClearProbeBackoff = %v, want PathModeWarm", got)
	}
}
