package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
	return newReaperFixtureWith(t, cidr, wirekubev1alpha1.AddressAllocationAllocator)
}

func newReaperFixtureWith(t *testing.T, cidr, allocation string) *reaperFixture {
	t.Helper()
	namespace := allocNamespace(t)
	meshName := sanitize(t.Name())
	if len(meshName) > 60 {
		meshName = meshName[:60]
	}
	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: meshName},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			MeshCIDR:          cidr,
			AddressAllocation: allocation,
		},
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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("worker1"), Name: "worker1"}); err != nil {
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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("enrolling"), Name: "enrolling"}); err != nil {
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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("abandoned"), Name: "abandoned"}); err != nil {
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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("long-lived"), Name: "long-lived"}); err != nil {
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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("slow-enrolment"), Name: "slow-enrolment"}); err != nil {
		t.Fatal(err)
	}
	setLeaseDuration(t, f.allocator.Namespace, meshalloc.HolderForPeer("slow-enrolment"), 3600)

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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("resident"), Name: "resident"}); err != nil {
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

// TestReaperKeepsAnExternalPeersClaim. An external peer's address derives from
// its display name but the claim is held under the resource name, which is
// what the reaper looks up.
func TestReaperKeepsAnExternalPeersClaim(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	external := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "laptop-cr"},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			DisplayName: "Someone's Laptop",
			PublicKey:   "0000000000000000000000000000000000000000000=",
		},
	}
	if err := k8sClient.Create(context.Background(), external); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), external) })

	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{
		Holder: meshalloc.HolderForExternalPeer(external.Name),
		Name:   external.Spec.DisplayName,
	}); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(48 * time.Hour)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Errorf("%d claims, want the external peer's kept", n)
	}
}

// TestReaperReclaimedAddressIsReusable closes the loop: the point of
// reclaiming is that the address goes back into the pool.
func TestReaperReclaimedAddressIsReusable(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	held, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("abandoned"), Name: "abandoned"})
	if err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(11 * time.Minute)
	f.sweep()
	got, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: "successor", Preferred: held.Address})
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
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("abandoned"), Name: "abandoned"}); err != nil {
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

// labelSafe mirrors the allocator's own reduction, because the peer label is
// lossy and a test selecting on the raw holder would find nothing.
func labelSafe(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
		if len(out) == 63 {
			break
		}
	}
	return strings.Trim(string(out), "-_.")
}

func setLeaseDuration(t *testing.T, namespace, peer string, seconds int32) {
	t.Helper()
	claims := &coordinationv1.LeaseList{}
	if err := k8sClient.List(context.Background(), claims,
		client.InNamespace(namespace),
		client.MatchingLabels{meshalloc.ClaimLabel: meshalloc.ClaimAddress, meshalloc.PeerLabel: labelSafe(peer)}); err != nil {
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

// TestReaperWithdrawsTheSeriesOfADeletedMesh. A frozen gauge is worse than no
// gauge: an alert on free addresses would sit quietly on a pool that no longer
// exists.
func TestReaperWithdrawsTheSeriesOfADeletedMesh(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	f.addPeer("worker1")
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("worker1"), Name: "worker1"}); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if got := gaugeValue(t, "wirekube_mesh_addresses_allocated", f.mesh); got != 1 {
		t.Fatalf("allocated = %v, want 1", got)
	}

	mesh := &wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: f.mesh}}
	if err := k8sClient.Delete(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if metricExists(t, "wirekube_mesh_addresses_allocated", f.mesh) {
		t.Error("the deleted mesh still reports a pool")
	}
}

func gaugeValue(t *testing.T, name, mesh string) float64 {
	t.Helper()
	// promauto registers into the default registry, which is what the agent
	// serves at /metrics via promhttp.Handler.
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "mesh" && label.GetValue() == mesh {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("no %s series for mesh %q", name, mesh)
	return 0
}

func metricExists(t *testing.T, name, mesh string) bool {
	t.Helper()
	// promauto registers into the default registry, which is what the agent
	// serves at /metrics via promhttp.Handler.
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "mesh" && label.GetValue() == mesh {
					return true
				}
			}
		}
	}
	return false
}

// TestReaperWaitsOutAMissingMesh. A mesh absent from one list is not proof it
// was deleted: the list comes from an informer, and re-applying the chart
// deletes and recreates the object. Without a grace here, a sweep landing in
// that window would reclaim every claim in the namespace while every peer was
// still up and advertising its address.
func TestReaperWaitsOutAMissingMesh(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	f.addPeer("worker1")
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("worker1"), Name: "worker1"}); err != nil {
		t.Fatal(err)
	}
	f.sweep()

	mesh := &wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: f.mesh}}
	if err := k8sClient.Delete(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Fatalf("%d claims, want the claim to survive a mesh that has only just gone", n)
	}
	// Recreating it inside the grace leaves the claim untouched.
	mesh = &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: f.mesh},
		Spec:       wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: "198.18.18.0/24"},
	}
	if err := k8sClient.Create(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.advance(48 * time.Hour)
	f.sweep()
	if n := f.claims(); n != 1 {
		t.Errorf("%d claims, want the claim kept once the mesh came back", n)
	}
}

// TestReaperReclaimsAfterTheMeshStaysGone keeps the other half honest: the
// grace delays the reclaim, it does not cancel it.
func TestReaperReclaimsAfterTheMeshStaysGone(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	f.addPeer("worker1")
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("worker1"), Name: "worker1"}); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	mesh := &wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: f.mesh}}
	if err := k8sClient.Delete(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	f.advance(11 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want them reclaimed once the mesh stayed gone", n)
	}
}

// TestReaperDoesNotTreatADisplayNameAsAHolder. Claims are held under resource
// names. Counting free-form display names as live holders would keep the
// orphaned claim of a decommissioned node alive forever whenever somebody
// invited an external peer under that node's name.
func TestReaperDoesNotTreatADisplayNameAsAHolder(t *testing.T) {
	f := newReaperFixture(t, "198.18.18.0/24")
	if _, err := f.allocator.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer("worker1"), Name: "worker1"}); err != nil {
		t.Fatal(err)
	}
	external := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "someones-laptop"},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			DisplayName: "worker1",
			PublicKey:   "0000000000000000000000000000000000000000000=",
		},
	}
	if err := k8sClient.Create(context.Background(), external); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(context.Background(), external) })

	f.sweep()
	f.advance(11 * time.Minute)
	f.sweep()
	if n := f.claims(); n != 0 {
		t.Errorf("%d claims, want the orphan reclaimed despite a display name that matches it", n)
	}
}

// TestReaperReportsNoPoolForAHashMesh. A mesh that does not arbitrate has no
// claims to count, so publishing a pool for it would read as every address
// free while every peer is using one.
func TestReaperReportsNoPoolForAHashMesh(t *testing.T) {
	f := newReaperFixtureWith(t, "198.18.18.0/24", wirekubev1alpha1.AddressAllocationHash)
	f.sweep()
	if metricExists(t, "wirekube_mesh_addresses_capacity", f.mesh) {
		t.Error("a hash mesh reported a pool")
	}

	mesh := &wirekubev1alpha1.WireKubeMesh{}
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Name: f.mesh}, mesh); err != nil {
		t.Fatal(err)
	}
	mesh.Spec.AddressAllocation = wirekubev1alpha1.AddressAllocationAllocator
	if err := k8sClient.Update(context.Background(), mesh); err != nil {
		t.Fatal(err)
	}
	f.sweep()
	if got := gaugeValue(t, "wirekube_mesh_addresses_capacity", f.mesh); got != 254 {
		t.Errorf("capacity = %v, want 254 once the mesh arbitrates", got)
	}
}
