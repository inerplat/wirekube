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
