package agent

import (
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/wireguard"
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

// After a restart the FSM is empty (it lives in process memory), so the
// first driveTransportMode of the new process is every peer's first sight.
// This is the incident contract: no peer may come out of that call pinned
// to Relay — the old Relay-first default hairpinned all traffic through the
// relay (or, with no relay, blackholed TX) for a full relayRetry window.
func TestDriveTransportModeAfterRestartPinsNoPeerToRelay(t *testing.T) {
	fake := &fakeWGEngine{lastDirect: map[string]int64{}}
	pm := NewPathMonitor(logr.Discard(), fake, PathMonitorConfig{}, time.Now)
	a := &Agent{
		wgMgr:           fake,
		log:             logr.Discard(),
		pathMonitor:     pm,
		directEndpoints: map[string]string{},
		relayedPeers:    map[string]bool{},
		startedAt:       time.Now(),
	}
	now := metav1.Now()
	peers := map[string]*wirekubev1alpha1.WireKubePeer{}
	names := []string{"peer-a", "peer-b"}
	for _, name := range names {
		p := &wirekubev1alpha1.WireKubePeer{}
		p.Name = name
		p.Spec.PublicKey = name + "-key"
		p.Spec.Endpoint = "192.0.2.1:51820"
		p.Status.LastReportedAt = &now
		peers[name] = p
	}

	a.driveTransportMode(names, peers, nil)

	for i, mode := range fake.setPaths {
		if mode == wireguard.PathRelay {
			t.Errorf("SetPeerPath call %d pinned a peer to Relay on first sight", i)
		}
	}
	if len(fake.setPaths) != len(names) {
		t.Fatalf("SetPeerPath calls = %d, want %d", len(fake.setPaths), len(names))
	}
	for _, name := range names {
		if a.relayedPeers[name] {
			t.Errorf("peer %s marked relayed after first sight", name)
		}
	}
}

// probeDirectEndpoint's Warm decision must reach PathMonitor, not only the
// Bind: driveTransportMode re-commits PathMonitor's mode at the end of the
// same sync tick, so a Bind-only write is reverted before the next packet.
func TestProbeDirectEndpointForcesPathMonitorWarm(t *testing.T) {
	fake := &fakeWGEngine{lastDirect: map[string]int64{}}
	pm := NewPathMonitor(logr.Discard(), fake, PathMonitorConfig{}, time.Now)
	a := &Agent{
		wgMgr:           fake,
		log:             logr.Discard(),
		pathMonitor:     pm,
		directEndpoints: map[string]string{},
		directProbing:   map[string]bool{},
	}
	seedRelay(t, pm, "p1", "p1-key")

	peer := &wirekubev1alpha1.WireKubePeer{}
	peer.Name = "p1"
	peer.Spec.PublicKey = "p1-key"
	peer.Spec.Endpoint = "192.0.2.1:51820"
	a.probeDirectEndpoint(peer)

	if got := pm.ModeFor("p1"); got != PathModeWarm {
		t.Fatalf("PathMonitor mode after probe = %v, want PathModeWarm", got)
	}
	if n := len(fake.setPaths); n == 0 || fake.setPaths[n-1] != wireguard.PathWarm {
		t.Fatalf("Bind path after probe = %v, want trailing PathWarm", fake.setPaths)
	}

	// The incident's failure mode end to end: driveTransportMode runs after
	// the ICE layer in the same sync tick and re-commits PathMonitor's mode
	// to the Bind. Before the Evaluate(force) notification it re-pinned the
	// peer to Relay here, reverting the probe's Warm before the next packet.
	a.relayedPeers = map[string]bool{}
	a.startedAt = time.Now()
	now := metav1.Now()
	peer.Status.LastReportedAt = &now
	a.driveTransportMode([]string{"p1"}, map[string]*wirekubev1alpha1.WireKubePeer{"p1": peer}, nil)
	if n := len(fake.setPaths); fake.setPaths[n-1] != wireguard.PathWarm {
		t.Fatalf("Bind path after same-tick driveTransportMode = %v, want trailing PathWarm", fake.setPaths)
	}
}

// A peer whose stats are missing must not be gated: GetStats failing leaves an
// empty map, and demoting the whole mesh on a transient UAPI error is far
// worse than trusting a pong for one cycle.
func TestDriveTransportModeFailsOpenWithoutStats(t *testing.T) {
	now := time.Now()
	fake := &fakeWGEngine{
		lastDirect: map[string]int64{},
		lastPong:   map[string]int64{"p1-key": now.UnixNano()},
	}
	pm := NewPathMonitor(logr.Discard(), fake, PathMonitorConfig{}, time.Now)
	a := &Agent{
		wgMgr:           fake,
		log:             logr.Discard(),
		pathMonitor:     pm,
		directEndpoints: map[string]string{},
		relayedPeers:    map[string]bool{},
		startedAt:       now,
	}
	reported := metav1.Now()
	peer := &wirekubev1alpha1.WireKubePeer{}
	peer.Name = "p1"
	peer.Spec.PublicKey = "p1-key"
	peer.Spec.Endpoint = "192.0.2.1:51820"
	peer.Status.LastReportedAt = &reported
	peers := map[string]*wirekubev1alpha1.WireKubePeer{"p1": peer}

	// First sight is Warm and seeds the watermark; the next pong is what
	// promotes, and only if the gate let it through.
	a.driveTransportMode([]string{"p1"}, peers, nil)
	fake.lastPong["p1-key"] = time.Now().UnixNano()
	a.driveTransportMode([]string{"p1"}, peers, nil)

	if got := pm.ModeFor("p1"); got != PathModeDirect {
		t.Fatalf("mode with no stats entry = %v, want PathModeDirect (gate must fail open)", got)
	}
}

// A handshake older than the reject window means the session is gone, so the
// pong that the Bind still answers must not hold the peer in Direct.
func TestDriveTransportModeGatesStaleHandshake(t *testing.T) {
	now := time.Now()
	fake := &fakeWGEngine{
		lastDirect: map[string]int64{},
		lastPong:   map[string]int64{"p1-key": now.UnixNano()},
	}
	pm := NewPathMonitor(logr.Discard(), fake, PathMonitorConfig{}, time.Now)
	a := &Agent{
		wgMgr:           fake,
		log:             logr.Discard(),
		pathMonitor:     pm,
		directEndpoints: map[string]string{},
		relayedPeers:    map[string]bool{},
		startedAt:       now,
	}
	reported := metav1.Now()
	peer := &wirekubev1alpha1.WireKubePeer{}
	peer.Name = "p1"
	peer.Spec.PublicKey = "p1-key"
	peer.Spec.Endpoint = "192.0.2.1:51820"
	peer.Status.LastReportedAt = &reported
	peers := map[string]*wirekubev1alpha1.WireKubePeer{"p1": peer}
	stats := map[string]wireguard.PeerStats{
		"p1-key": {LastHandshake: now.Add(-wgSessionAliveWindow - time.Minute)},
	}

	a.driveTransportMode([]string{"p1"}, peers, stats)
	fake.lastPong["p1-key"] = time.Now().UnixNano()
	a.driveTransportMode([]string{"p1"}, peers, stats)

	if got := pm.ModeFor("p1"); got == PathModeDirect {
		t.Fatal("a pong held the peer in Direct although its handshake is past the reject window")
	}
}

// A stats entry that exists with no handshake at all is not the same as a
// missing entry: the device knows the peer and has never completed a session
// with it. Treating that as alive let a peer whose key no longer matches
// answer pongs and be published as direct forever, which is the zombie the
// gate exists to catch.
func TestDriveTransportModeGatesZeroHandshake(t *testing.T) {
	now := time.Now()
	fake := &fakeWGEngine{
		lastDirect: map[string]int64{},
		lastPong:   map[string]int64{"p1-key": now.UnixNano()},
	}
	pm := NewPathMonitor(logr.Discard(), fake, PathMonitorConfig{}, time.Now)
	a := &Agent{
		wgMgr:           fake,
		log:             logr.Discard(),
		pathMonitor:     pm,
		directEndpoints: map[string]string{},
		relayedPeers:    map[string]bool{},
		startedAt:       now,
	}
	reported := metav1.Now()
	peer := &wirekubev1alpha1.WireKubePeer{}
	peer.Name = "p1"
	peer.Spec.PublicKey = "p1-key"
	peer.Spec.Endpoint = "192.0.2.1:51820"
	peer.Status.LastReportedAt = &reported
	peers := map[string]*wirekubev1alpha1.WireKubePeer{"p1": peer}
	// Entry present, handshake never completed.
	stats := map[string]wireguard.PeerStats{"p1-key": {}}

	a.driveTransportMode([]string{"p1"}, peers, stats)
	fake.lastPong["p1-key"] = time.Now().UnixNano()
	a.driveTransportMode([]string{"p1"}, peers, stats)

	if got := pm.ModeFor("p1"); got == PathModeDirect {
		t.Fatal("pongs promoted a peer whose WireGuard session has never formed")
	}
}
