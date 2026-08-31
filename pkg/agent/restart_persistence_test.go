package agent

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
)

// Graceful shutdown must leave the dataplane for the next agent: no route
// flush, no interface deletion. Only process-owned resources close. This is
// what lets a rolling update pass without route churn; tearing down here was
// the regression that kept every restart cold.
func TestCleanupLeavesDataplaneInPlace(t *testing.T) {
	fake := &fakeWGEngine{}
	a := &Agent{wgMgr: fake, log: logr.Discard()}

	a.cleanup()

	if fake.deleteCalls != 0 {
		t.Errorf("cleanup deleted the interface %d times, want 0", fake.deleteCalls)
	}
	if fake.routeFlushes != 0 {
		t.Errorf("cleanup flushed routes %d times, want 0", fake.routeFlushes)
	}
	if fake.closeCalls != 1 {
		t.Errorf("cleanup closed the device %d times, want 1", fake.closeCalls)
	}
}

func TestAdoptSurvivingInterface(t *testing.T) {
	t.Run("existing interface is adopted without teardown", func(t *testing.T) {
		fake := &fakeWGEngine{}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		a.adoptSurvivingInterface()
		if !a.wasInterfacePreserved {
			t.Error("surviving interface was not marked preserved")
		}
		// The first sync runs before any handshake; replacing routes there
		// would empty the set adoption just preserved.
		if !a.keepRoutesUntilHandshakes {
			t.Error("first-sync route replacement was not deferred")
		}
		// Preservation must never be the mismatch-teardown of the old gate.
		if fake.deleteCalls != 0 || fake.routeFlushes != 0 {
			t.Errorf("adoption touched the dataplane: deletes=%d flushes=%d", fake.deleteCalls, fake.routeFlushes)
		}
	})

	t.Run("no interface means a cold start", func(t *testing.T) {
		fake := &fakeWGEngine{ifaceGone: true}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		a.adoptSurvivingInterface()
		if a.wasInterfacePreserved {
			t.Error("preserved was set with no interface present")
		}
	})
}

func TestResetDataplaneIfRequested(t *testing.T) {
	t.Run("unset env is a no-op", func(t *testing.T) {
		fake := &fakeWGEngine{}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		if err := a.resetDataplaneIfRequested(); err != nil {
			t.Fatal(err)
		}
		if fake.deleteCalls != 0 || fake.routeFlushes != 0 {
			t.Errorf("reset ran without the env: deletes=%d flushes=%d", fake.deleteCalls, fake.routeFlushes)
		}
	})

	t.Run("WIREKUBE_CLEAN_STATE=true tears the interface down", func(t *testing.T) {
		t.Setenv("WIREKUBE_CLEAN_STATE", "true")
		fake := &fakeWGEngine{}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		if err := a.resetDataplaneIfRequested(); err != nil {
			t.Fatal(err)
		}
		if fake.deleteCalls != 1 {
			t.Errorf("deletes=%d, want 1", fake.deleteCalls)
		}
		// Deleting the link drops its routes; a separate flush would run
		// before the engine has a link index and match nothing.
		if fake.routeFlushes != 0 {
			t.Errorf("flushes=%d, want 0", fake.routeFlushes)
		}
	})

	t.Run("boolean spellings are accepted", func(t *testing.T) {
		t.Setenv("WIREKUBE_CLEAN_STATE", "1")
		fake := &fakeWGEngine{}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		if err := a.resetDataplaneIfRequested(); err != nil {
			t.Fatal(err)
		}
		if fake.deleteCalls != 1 {
			t.Errorf("deletes=%d, want 1", fake.deleteCalls)
		}
	})

	t.Run("unparseable values are ignored", func(t *testing.T) {
		t.Setenv("WIREKUBE_CLEAN_STATE", "yes")
		fake := &fakeWGEngine{}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		if err := a.resetDataplaneIfRequested(); err != nil {
			t.Fatal(err)
		}
		if fake.deleteCalls != 0 {
			t.Errorf("deletes=%d, want 0", fake.deleteCalls)
		}
	})

	t.Run("teardown failure surfaces to the caller", func(t *testing.T) {
		t.Setenv("WIREKUBE_CLEAN_STATE", "true")
		wantErr := errors.New("link busy")
		fake := &fakeWGEngine{deleteErr: wantErr}
		a := &Agent{wgMgr: fake, log: logr.Discard()}
		err := a.resetDataplaneIfRequested()
		if err == nil || !errors.Is(err, wantErr) {
			t.Fatalf("error=%v, want wrap of %v", err, wantErr)
		}
	})
}

// Two idle peers with equal keepalive intervals ping-pong: WireGuard re-arms
// the timer on receive too, so each side hears from the other only every
// 2×interval. The default must keep that below PathMonitor's 30s warm-stall
// threshold, and CRs still carrying the old 25s default (or nothing) migrate,
// while operator-chosen values survive.
func TestMigrateDefaultKeepalive(t *testing.T) {
	if got := 2 * defaultPeerKeepaliveSeconds; got >= 30 {
		t.Fatalf("2×default keepalive = %ds reaches the 30s warm-stall threshold", got)
	}
	cases := map[int32]int32{0: 10, 25: 10, 10: 10, 7: 7, 60: 60}
	for in, want := range cases {
		if got := migrateDefaultKeepalive(in); got != want {
			t.Errorf("migrate(%d) = %d, want %d", in, got, want)
		}
	}
}
