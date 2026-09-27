package e2e

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	reaperpkg "github.com/inerplat/wirekube/pkg/controller/meshalloc"
	"github.com/inerplat/wirekube/pkg/meshalloc"
)

// reaperFixture wires a Reaper over a fresh namespace and a fresh mesh, with a
// clock the test drives.
type reaperFixture struct {
	t         *testing.T
	allocator *meshalloc.Allocator
	reaper    *reaperpkg.Reaper
	mesh      string
	now       time.Time
}

func newReaperFixture(t *testing.T, cidr string) *reaperFixture {
	t.Helper()
	namespace := allocNamespace(t)
	meshName := sanitize(t.Name())
	if len(meshName) > 60 {
		meshName = meshName[:60]
	}
	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: meshName},
		Spec:       wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: cidr},
	}
	if err := k8sClient.Create(context.Background(), mesh); err != nil {
		t.Fatalf("create mesh: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), mesh) })

	f := &reaperFixture{t: t, mesh: meshName, now: time.Now()}
	f.allocator = &meshalloc.Allocator{
		Client:    k8sClient,
		Namespace: namespace,
		MeshName:  meshName,
		MeshCIDR:  cidr,
	}
	f.reaper = &reaperpkg.Reaper{
		Client:    k8sClient,
		Namespace: namespace,
		Log:       zap.New(zap.UseDevMode(true)),
		Grace:     10 * time.Minute,
		Now:       func() time.Time { return f.now },
	}
	return f
}

func (f *reaperFixture) sweep() {
	f.t.Helper()
	if err := f.reaper.Sweep(context.Background()); err != nil {
		f.t.Fatalf("sweep: %v", err)
	}
}

func (f *reaperFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *reaperFixture) claims() int { return countClaims(f.t, f.allocator.Namespace) }

func (f *reaperFixture) addPeer(name string) *wirekubev1alpha1.WireKubePeer {
	f.t.Helper()
	peer := &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(context.Background(), peer); err != nil {
		f.t.Fatalf("create peer %s: %v", name, err)
	}
	f.t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), peer) })
	return peer
}

// TestReaperKeepsAClaimWhosePeerExists is the case that must never go wrong:
// reclaiming a live peer's address would hand it to somebody else while the
// peer is still using it.
func TestReaperKeepsAClaimWhosePeerExists(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	f.addPeer("worker1")
	if _, err := f.allocator.Allocate(context.Background(), "worker1", ""); err != nil {
		t.Fatal(err)
	}
	f.advance(72 * time.Hour)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Errorf("%d claims after a long sweep, want the live peer's to survive", n)
	}
}

// TestReaperGivesAnEnrolmentItsGrace covers the reason claims carry no
// ownerReference: the tool claims the address first and the peer appears
// minutes later, so an eager reaper would pull the address out from under a
// machine that is still booting.
func TestReaperGivesAnEnrolmentItsGrace(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	if _, err := f.allocator.Allocate(context.Background(), "enrolling", ""); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Fatalf("%d claims immediately after claiming, want it left alone", n)
	}
	f.advance(9 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Fatalf("%d claims inside the grace period, want it left alone", n)
	}
	// The machine finishes booting and registers its peer.
	f.addPeer("enrolling")
	f.advance(48 * time.Hour)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Errorf("%d claims after the peer appeared, want it kept", n)
	}
}

func TestReaperReclaimsAnOrphanAfterTheGrace(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	if _, err := f.allocator.Allocate(context.Background(), "abandoned", ""); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(11 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims after the grace expired, want the orphan reclaimed", n)
	}
}

// TestReaperGraceRunsFromTheDisappearance, not from when the claim was made.
// A peer that ran for months and then went away gets the same grace as a fresh
// enrolment, because the reaper cannot tell a deletion from a slow restart.
func TestReaperGraceRunsFromTheDisappearance(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	peer := f.addPeer("long-lived")
	if _, err := f.allocator.Allocate(context.Background(), "long-lived", ""); err != nil {
		t.Fatal(err)
	}
	f.advance(30 * 24 * time.Hour)
	f.sweep()
	if err := k8sClient.Delete(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(9 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Fatalf("%d claims, want the full grace to start at the disappearance", n)
	}
	f.advance(2 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want the orphan reclaimed once its grace expired", n)
	}
}

// TestReaperHonoursAClaimsOwnGrace: a creator that knows its enrolment is slow
// says so in spec.leaseDurationSeconds rather than forcing everyone onto a
// long default.
func TestReaperHonoursAClaimsOwnGrace(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	if _, err := f.allocator.Allocate(context.Background(), "slow-enrolment", ""); err != nil {
		t.Fatal(err)
	}
	setLeaseDuration(t, f.allocator.Namespace, "slow-enrolment", 3600)

	f.sweep()
	f.advance(30 * time.Minute) // well past the reaper's 10-minute default
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Fatalf("%d claims, want the claim's own 1h grace honoured", n)
	}
	f.advance(31 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want it reclaimed once its own grace expired", n)
	}
}

// TestReaperReclaimsAnAddressOutsideTheCIDR immediately: the allocator has
// already renumbered the peer, and the address can never be handed out again,
// so waiting out a grace period only keeps a dead entry in the pool.
func TestReaperReclaimsAnAddressOutsideTheCIDR(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	f.addPeer("resident")
	if _, err := f.allocator.Allocate(context.Background(), "resident", ""); err != nil {
		t.Fatal(err)
	}
	// The operator moves the mesh to a different range.
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: f.mesh}, mesh); err != nil {
		t.Fatal(err)
	}
	mesh.Spec.MeshCIDR = "198.18.19.0/24"
	if err := k8sClient.Update(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want the out-of-range claim reclaimed at once", n)
	}
}

// TestReaperKeepsAnExternalPeersClaim: external peers hold their address under
// the display name the address is derived from, not under the resource name.
func TestReaperKeepsAnExternalPeersClaim(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	external := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop-cr"},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			DisplayName: "someones-laptop",
			PublicKey:   "0000000000000000000000000000000000000000000=",
		},
	}
	if err := k8sClient.Create(context.Background(), external); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), external) })

	if _, err := f.allocator.Allocate(context.Background(), "someones-laptop", ""); err != nil {
		t.Fatal(err)
	}
	f.advance(48 * time.Hour)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Errorf("%d claims, want the external peer's kept", n)
	}
}

func TestReaperReclaimsAClaimWithNoMesh(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	f.addPeer("worker1")
	if _, err := f.allocator.Allocate(context.Background(), "worker1", ""); err != nil {
		t.Fatal(err)
	}
	mesh := &wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: f.mesh}}
	if err := k8sClient.Delete(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want claims for a deleted mesh reclaimed", n)
	}
}

// TestReaperReclaimedAddressIsReusable closes the loop: the point of
// reclaiming is that the address goes back into the pool.
func TestReaperReclaimedAddressIsReusable(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	held, err := f.allocator.Allocate(context.Background(), "abandoned", "")
	if err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(11 * time.Minute)
	f.sweep()
	got, err := f.allocator.Allocate(context.Background(), "successor", held.Address)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != held.Address {
		t.Errorf("successor got %s, want the reclaimed %s", got.Address, held.Address)
	}
}

// TestReaperSurvivesALeaderChange: the grace timer lives in memory, so a new
// leader restarts it. That is safe — it delays a reclaim, it never causes an
// early one.
func TestReaperSurvivesALeaderChange(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	if _, err := f.allocator.Allocate(context.Background(), "abandoned", ""); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(9 * time.Minute)

	successor := &reaperpkg.Reaper{
		Client:    k8sClient,
		Namespace: f.allocator.Namespace,
		Log:       zap.New(zap.UseDevMode(true)),
		Grace:     10 * time.Minute,
		Now:       func() time.Time { return f.now },
	}
	f.reaper = successor
	f.sweep()
	f.advance(2 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Fatalf("%d claims, want the new leader to restart the grace rather than reclaim early", n)
	}
	f.advance(9 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want the orphan reclaimed once the new leader's grace expired", n)
	}
}

func setLeaseDuration(t *testing.T, namespace, peer string, seconds int32) {
	t.Helper()
	claims := &coordinationv1.LeaseList{}
	if err := k8sClient.List(context.Background(), claims,
		client.InNamespace(namespace),
		client.MatchingLabels{meshalloc.ClaimLabel: meshalloc.ClaimAddress, meshalloc.PeerLabel: peer}); err != nil {
		t.Fatal(err)
	}
	if len(claims.Items) != 1 {
		t.Fatalf("found %d claims for %s, want 1", len(claims.Items), peer)
	}
	lease := &claims.Items[0]
	lease.Spec.LeaseDurationSeconds = &seconds
	if err := k8sClient.Update(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
}
