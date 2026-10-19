package external

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func TestReconcile_HeartbeatExpiry(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Annotations = map[string]string{wirekubev1alpha1.ExternalPeerHeartbeatAnnotation: "1"}
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	now := time.Now()
	r := &Reconciler{
		Client: c,
		Scheme: testScheme(t),
		Relay:  newMockRelay(testRelayHost),
		Now:    func() time.Time { return now },
	}
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}

	res := reconcileTwice(t, r, testExternalName)
	if res.RequeueAfter <= 0 || res.RequeueAfter > wirekubev1alpha1.ExternalPeerHeartbeatTimeout {
		t.Fatalf("an active heartbeating peer must requeue by its deadline, got %+v", res)
	}

	// A fresh value just short of the deadline resets the clock.
	now = now.Add(wirekubev1alpha1.ExternalPeerHeartbeatTimeout - time.Second)
	got := getCR(t, c, testExternalName)
	got.Annotations[wirekubev1alpha1.ExternalPeerHeartbeatAnnotation] = "2"
	if err := c.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(wirekubev1alpha1.ExternalPeerHeartbeatTimeout - time.Second)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := getCR(t, c, testExternalName); got.DeletionTimestamp != nil {
		t.Fatal("peer expired although its heartbeat advanced within the timeout")
	}

	// Silence past the timeout deletes it.
	now = now.Add(2 * time.Second)
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	after := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(ctx, req.NamespacedName, after)
	if err == nil && after.DeletionTimestamp == nil {
		t.Fatal("peer survived a stale heartbeat")
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}

func TestReconcile_NoHeartbeatNeverExpires(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	now := time.Now()
	r := &Reconciler{
		Client: c,
		Scheme: testScheme(t),
		Relay:  newMockRelay(testRelayHost),
		Now:    func() time.Time { return now },
	}
	reconcileTwice(t, r, testExternalName)
	now = now.Add(24 * time.Hour)
	reconcileTwice(t, r, testExternalName)
	if got := getCR(t, c, testExternalName); got.DeletionTimestamp != nil {
		t.Fatal("a peer without a heartbeat was expired")
	}
}

func TestHeartbeatTrackerTimesOnItsOwnClock(t *testing.T) {
	var tr heartbeatTracker
	t0 := time.Unix(1000, 0)
	if got := tr.observe("u", "client-says-1999", t0); !got.Equal(t0) {
		t.Fatalf("first sighting = %v", got)
	}
	if got := tr.observe("u", "client-says-1999", t0.Add(time.Minute)); !got.Equal(t0) {
		t.Fatalf("unchanged value moved its time to %v", got)
	}
	if got := tr.observe("u", "client-says-1998", t0.Add(2*time.Minute)); !got.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("a changed value, even an older-looking one, must count as a beat; got %v", got)
	}
}
