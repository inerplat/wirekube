package external

import (
	"context"
	"fmt"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	coordinationv1 "k8s.io/api/coordination/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/meshalloc"
	"github.com/inerplat/wirekube/pkg/meship"
)

func newAllocatorMesh() *wirekubev1alpha1.WireKubeMesh {
	mesh := newReadyMesh()
	mesh.Spec.AddressAllocation = wirekubev1alpha1.AddressAllocationAllocator
	return mesh
}

// TestReconcileHashModeIsUnchanged: until an operator opts in, the address is
// the display-name hash written straight to status, exactly as before.
func TestReconcileHashModeIsUnchanged(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	reconcileTwice(t, r, testExternalName)

	want, err := meship.IPForName(getCR(t, c, testExternalName).Spec.DisplayName, testMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if got := getCR(t, c, testExternalName).Status.AssignedMeshIP; got != want {
		t.Errorf("assignedMeshIP = %s, want the hashed %s", got, want)
	}
	if n := len(listClaims(t, c)); n != 0 {
		t.Errorf("hash mode created %d claims, want none", n)
	}
}

// TestReconcileAllocatorModeClaimsTheAddress: with the allocator on, the same
// address is chosen but it is now backed by a claim, so nothing else can take
// it.
func TestReconcileAllocatorModeClaimsTheAddress(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newAllocatorMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	want, err := meship.IPForName(got.Spec.DisplayName, testMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.AssignedMeshIP != want {
		t.Errorf("assignedMeshIP = %s, want the hashed %s", got.Status.AssignedMeshIP, want)
	}
	claims := listClaims(t, c)
	if len(claims) != 1 {
		t.Fatalf("%d claims, want exactly one", len(claims))
	}
	claim := claims[0]
	if addr := claim.Annotations[meshalloc.AddressAnnotation]; addr != want {
		t.Errorf("claim covers %s, want %s", addr, want)
	}
	// Held under the resource name, prefixed by its kind. The display name is
	// only what the address derives from; using it as the holder would let a
	// node of the same name adopt this claim.
	wantHolder := meshalloc.HolderForExternalPeer(got.Name)
	if holder := *claim.Spec.HolderIdentity; holder != wantHolder {
		t.Errorf("claim holder = %q, want %q", holder, wantHolder)
	}
}

// TestReconcileAllocatorModeMovesOffAHeldAddress is the bug the allocator
// fixes: status.assignedMeshIP used to be written with no check at all, so an
// external peer whose display name hashed onto an address somebody already
// held was simply handed a duplicate.
func TestReconcileAllocatorModeMovesOffAHeldAddress(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newAllocatorMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	displayName := getCR(t, c, testExternalName).Spec.DisplayName
	contested, err := meship.IPForName(displayName, testMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	// A node got there first.
	incumbent := &meshalloc.Allocator{Client: c, Namespace: "wirekube-system", MeshName: "default", MeshCIDR: testMeshCIDR}
	if _, err := incumbent.Allocate(context.Background(), meshalloc.Request{
		Holder: meshalloc.HolderForPeer("some-node"), Name: "some-node", Preferred: contested,
	}); err != nil {
		t.Fatal(err)
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AssignedMeshIP
	if got == contested {
		t.Fatalf("assignedMeshIP = %s, which some-node already holds", got)
	}
	if got == "" {
		t.Fatal("assignedMeshIP empty")
	}
	if !meship.Contains(got, testMeshCIDR) {
		t.Errorf("assignedMeshIP = %s, outside the mesh CIDR %s", got, testMeshCIDR)
	}
}

// TestReconcileAllocatorModeKeepsAPublishedAddress: turning the allocator on
// must not renumber an external peer that is already up and connected.
func TestReconcileAllocatorModeKeepsAPublishedAddress(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newAllocatorMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	// The peer was issued a non-hashed address before the allocator existed.
	const published = "100.127.255.222/32"
	live := getCR(t, c, testExternalName)
	hashed, err := meship.IPForName(live.Spec.DisplayName, testMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if hashed == published {
		t.Fatal("test vector is useless: the display name already hashes to the published address")
	}
	live.Status.AssignedMeshIP = published
	if err := c.Status().Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}

	reconcileTwice(t, r, testExternalName)

	if got := getCR(t, c, testExternalName).Status.AssignedMeshIP; got != published {
		t.Errorf("assignedMeshIP = %s, want the already-published %s", got, published)
	}
}

func listClaims(t *testing.T, c client.Client) []coordinationv1.Lease {
	t.Helper()
	claims := &coordinationv1.LeaseList{}
	if err := c.List(context.Background(), claims,
		client.MatchingLabels{meshalloc.ClaimLabel: meshalloc.ClaimAddress}); err != nil {
		t.Fatalf("list claims: %v", err)
	}
	return claims.Items
}

// TestReconcileHashModeKeepsAnAllocatedAddress. Turning the allocator off must
// not renumber a peer it had moved: the client is connected on the issued
// address, and putting it back on the hash recreates the collision that moved
// it off in the first place. Cluster peers keep theirs via status.meshIP, and
// external peers have to behave the same way.
func TestReconcileHashModeKeepsAnAllocatedAddress(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	const allocated = "100.127.255.222/32"
	live := getCR(t, c, testExternalName)
	hashed, err := meship.IPForName(live.Spec.DisplayName, testMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if hashed == allocated {
		t.Fatal("test vector is useless")
	}
	live.Status.AssignedMeshIP = allocated
	if err := c.Status().Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}

	reconcileTwice(t, r, testExternalName)

	if got := getCR(t, c, testExternalName).Status.AssignedMeshIP; got != allocated {
		t.Errorf("assignedMeshIP = %s, want the already-issued %s", got, allocated)
	}
}

// TestReconcileHashModeRederivesAnUnroutableAddress keeps the other half
// honest: an address the mesh CIDR no longer covers is not worth keeping.
func TestReconcileHashModeRederivesAnUnroutableAddress(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	live := getCR(t, c, testExternalName)
	live.Status.AssignedMeshIP = "10.9.9.9/32"
	if err := c.Status().Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}
	reconcileTwice(t, r, testExternalName)

	want, err := meship.IPForName(live.Spec.DisplayName, testMeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if got := getCR(t, c, testExternalName).Status.AssignedMeshIP; got != want {
		t.Errorf("assignedMeshIP = %s, want the re-derived %s", got, want)
	}
}

// TestReconcileRequeuesATransientAllocatorFailure. Marking the peer Failed
// settles its status, and nothing is guaranteed to reconcile it again once the
// API server recovers — the enrollment would stay broken until an unrelated
// watched object happened to change.
func TestReconcileRequeuesATransientAllocatorFailure(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newAllocatorMesh(), newIngressPeer())
	r := &Reconciler{
		Client:         unavailableCreates{c},
		Scheme:         testScheme(t),
		Relay:          newMockRelay(testRelayHost),
		ClaimNamespace: "wirekube-system",
	}

	// The first pass adds the finalizer; allocation happens on the next one.
	ctx := context.Background()
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}
	var err error
	for range 2 {
		if _, err = r.Reconcile(ctx, request); err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("a transient allocator failure did not requeue")
	}
	if got := getCR(t, c, testExternalName).Status.Phase; got == wirekubev1alpha1.ExternalPeerPhaseFailed {
		t.Error("a transient allocator failure parked the peer in Failed")
	}
}

// TestReconcileFailsTerminallyOnExhaustion is the other side: nothing frees up
// on its own, so retrying forever would say nothing an operator can act on.
func TestReconcileFailsTerminallyOnExhaustion(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	mesh := newAllocatorMesh()
	mesh.Spec.MeshCIDR = "198.18.18.0/30"
	c := newFakeClient(t, cr, mesh, newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	filler := &meshalloc.Allocator{Client: c, Namespace: "wirekube-system", MeshName: "default", MeshCIDR: mesh.Spec.MeshCIDR}
	for i := range 2 {
		if _, err := filler.Allocate(context.Background(), meshalloc.Request{Holder: meshalloc.HolderForPeer(fmt.Sprintf("filler-%d", i))}); err != nil {
			t.Fatal(err)
		}
	}

	result := reconcileTwice(t, r, testExternalName)
	// Pending, not Failed: the pool fills and empties, and the reaper frees
	// addresses as peers go away, so this has to come back on its own.
	if got := getCR(t, c, testExternalName).Status.Phase; got != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Errorf("phase = %q, want Pending on an exhausted mesh", got)
	}
	if result.RequeueAfter == 0 {
		t.Error("an exhausted mesh was left with nothing to bring it back")
	}
	if cond := findCondition(getCR(t, c, testExternalName).Status.Conditions, conditionReady); !strings.Contains(cond.Message, "widen") {
		t.Errorf("the condition does not say what to do: %q", cond.Message)
	}
}

// TestReconcileFailsTerminallyOnAnUnusableCIDR is the other half: a mesh the
// allocator cannot work with at all is a spec problem, and retrying it forever
// would say nothing an operator can act on.
func TestReconcileFailsTerminallyOnAnUnusableCIDR(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	mesh := newAllocatorMesh()
	// Syntactically valid for the CRD's regex, and unusable: a /31 has no
	// assignable host range.
	mesh.Spec.MeshCIDR = "198.18.18.0/31"
	c := newFakeClient(t, cr, mesh, newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), ClaimNamespace: "wirekube-system"}

	reconcileTwice(t, r, testExternalName)
	if got := getCR(t, c, testExternalName).Status.Phase; got != wirekubev1alpha1.ExternalPeerPhaseFailed {
		t.Errorf("phase = %q, want Failed on a CIDR the allocator cannot use", got)
	}
}

// unavailableCreates is the API server briefly refusing writes.
type unavailableCreates struct {
	client.Client
}

func (c unavailableCreates) Create(context.Context, client.Object, ...client.CreateOption) error {
	return apierrors.NewServiceUnavailable("the server is currently unable to handle the request")
}
