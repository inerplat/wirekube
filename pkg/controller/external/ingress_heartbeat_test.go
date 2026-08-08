package external

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func reportedAt(peer *wirekubev1alpha1.WireKubePeer, t time.Time) *wirekubev1alpha1.WireKubePeer {
	ts := metav1.NewTime(t)
	peer.Status.LastReportedAt = &ts
	return peer
}

// The production failure this guards against: a node goes NotReady, its agent
// stops writing status, but the WireKubePeer CR survives because ownerReference
// GC only fires on Node deletion. With no relay latency known every candidate
// scores identically, so selection fell through to name ordering and picked the
// dead node purely because it sorted first. Clients bound to it pin its public
// key and never hand shake.
func TestReconcile_AutoIngressSkipsPeerWithStaleHeartbeat(t *testing.T) {
	now := time.Now()

	cr := newExternalPeer(testExternalName)
	dead := reportedAt(newIngressPeerWith("aaa-dead", ingressPubKey()), now.Add(-24*time.Hour))
	live := reportedAt(newIngressPeerWith("zzz-live", alternateIngressPubKey()), now.Add(-time.Second))

	c := newFakeClient(t, cr, newReadyMesh(), dead, live)
	relayCtl := newProbeRelay(testRelayHost, nil)
	relayCtl.probeErr = ErrIngressProbeDisabled
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: relayCtl,
		Now: func() time.Time { return now },
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != "zzz-live" {
		t.Fatalf("ingressPeerName = %q, want zzz-live (the dead peer sorts first by name)", got.Status.IngressPeerName)
	}
}

// A peer that never publishes a heartbeat is as unusable as one whose
// heartbeat went stale, and it is the shape the field takes on a CR written
// before the heartbeat existed.
func TestReconcile_AutoIngressSkipsPeerWithNoHeartbeat(t *testing.T) {
	now := time.Now()

	cr := newExternalPeer(testExternalName)
	silent := newIngressPeerWith("aaa-silent", ingressPubKey())
	live := reportedAt(newIngressPeerWith("zzz-live", alternateIngressPubKey()), now.Add(-time.Second))

	c := newFakeClient(t, cr, newReadyMesh(), silent, live)
	relayCtl := newProbeRelay(testRelayHost, nil)
	relayCtl.probeErr = ErrIngressProbeDisabled
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: relayCtl,
		Now: func() time.Time { return now },
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != "zzz-live" {
		t.Fatalf("ingressPeerName = %q, want zzz-live", got.Status.IngressPeerName)
	}
}

// Rolling upgrade safety: a fleet whose agents all predate the heartbeat
// reports nothing at all. Treating that as "everyone is dead" would strand
// external peers that work today, so selection must fall back to the previous
// behaviour rather than reject every candidate.
func TestReconcile_AutoIngressIgnoresHeartbeatWhenNoPeerPublishesOne(t *testing.T) {
	now := time.Now()

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newProbeRelay(testRelayHost, nil)
	relayCtl.probeErr = ErrIngressProbeDisabled
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: relayCtl,
		Now: func() time.Time { return now },
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if got.Status.IngressPeerName != testIngressPeer {
		t.Fatalf("ingressPeerName = %q, want %q", got.Status.IngressPeerName, testIngressPeer)
	}
}

func TestFreshlyReportedPeers(t *testing.T) {
	now := time.Now()
	list := &wirekubev1alpha1.WireKubePeerList{
		Items: []wirekubev1alpha1.WireKubePeer{
			*reportedAt(newIngressPeerWith("fresh", ingressPubKey()), now.Add(-time.Second)),
			*reportedAt(newIngressPeerWith("edge", ingressPubKey()), now.Add(-ingressHeartbeatThreshold)),
			*reportedAt(newIngressPeerWith("stale", ingressPubKey()), now.Add(-time.Hour)),
			*newIngressPeerWith("silent", ingressPubKey()),
		},
	}

	live := freshlyReportedPeers(list, now)

	if !live["fresh"] {
		t.Error("fresh peer missing from live set")
	}
	for _, name := range []string{"edge", "stale", "silent"} {
		if live[name] {
			t.Errorf("%q counted as live", name)
		}
	}
}
