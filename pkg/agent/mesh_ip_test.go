package agent

import (
	"context"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/meshalloc"
	"github.com/inerplat/wirekube/pkg/meship"
)

func meshWithCIDR(cidr string) *wirekubev1alpha1.WireKubeMesh {
	return &wirekubev1alpha1.WireKubeMesh{Spec: wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: cidr}}
}

func TestApplyMeshIPDerivesWhenNothingRecorded(t *testing.T) {
	want, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	spec := &wirekubev1alpha1.WireKubePeerSpec{}
	got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", "", spec)
	if got != want {
		t.Errorf("returned %q, want %q", got, want)
	}
	if !slices.Equal(spec.AllowedIPs, []string{want}) {
		t.Errorf("AllowedIPs = %v, want [%s]", spec.AllowedIPs, want)
	}
}

// TestApplyMeshIPHonoursTheRecordedAddress is the whole point of the recorded
// field: an allocator moved this peer off its hashed address, and the agent
// must not drag it back on the next upsert.
func TestApplyMeshIPHonoursTheRecordedAddress(t *testing.T) {
	const recorded = "198.18.18.200/32"
	hashed, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if hashed == recorded {
		t.Fatalf("test vector is useless: worker1 already hashes to %s", recorded)
	}
	spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{recorded, "10.42.0.0/24"}}
	got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", recorded, spec)
	if got != recorded {
		t.Errorf("returned %q, want the recorded %q", got, recorded)
	}
	if !slices.Equal(spec.AllowedIPs, []string{recorded, "10.42.0.0/24"}) {
		t.Errorf("AllowedIPs = %v, want the recorded address first and the gateway route kept", spec.AllowedIPs)
	}
}

// TestApplyMeshIPRestoresTheRecordedAddressToTheFront covers the peer whose
// AllowedIPs were reordered or cleared out of band.
func TestApplyMeshIPRestoresTheRecordedAddressToTheFront(t *testing.T) {
	const recorded = "198.18.18.200/32"
	spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{"10.42.0.0/24", recorded}}
	got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", recorded, spec)
	if got != recorded {
		t.Errorf("returned %q, want %q", got, recorded)
	}
	if !slices.Equal(spec.AllowedIPs, []string{recorded, "10.42.0.0/24"}) {
		t.Errorf("AllowedIPs = %v, want the recorded address moved to the front without duplicating it", spec.AllowedIPs)
	}
}

// TestApplyMeshIPRejectsAStaleRecord covers a record left behind by a mesh
// whose CIDR has since moved or shrunk. Honouring it would put the peer on an
// address the mesh does not route.
func TestApplyMeshIPRejectsAStaleRecord(t *testing.T) {
	want, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, recorded := range []string{
		"10.9.9.9/32",       // outside the mesh CIDR
		"198.18.18.0/32",    // the network address
		"198.18.18.255/32",  // the broadcast address
		"198.18.18.0/24",    // not a host address
		"198.18.18.200",     // missing the prefix length
		"not-an-address",    //
		"fd00::1/128",       // IPv6
		"198.18.18.200/31",  // wrong prefix length
		"198.18.18.200/32 ", // trailing space
	} {
		spec := &wirekubev1alpha1.WireKubePeerSpec{}
		got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", recorded, spec)
		if got != want {
			t.Errorf("recorded %q: returned %q, want the re-derived %q", recorded, got, want)
		}
		if !slices.Equal(spec.AllowedIPs, []string{want}) {
			t.Errorf("recorded %q: AllowedIPs = %v, want [%s]", recorded, spec.AllowedIPs, want)
		}
	}
}

func TestApplyMeshIPLeavesManualPeersAloneWithoutAMeshCIDR(t *testing.T) {
	for _, mesh := range []*wirekubev1alpha1.WireKubeMesh{nil, meshWithCIDR("")} {
		spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{"192.168.1.0/24"}}
		if got := applyMeshIP(logr.Discard(), mesh, "worker1", "198.18.18.200/32", spec); got != "" {
			t.Errorf("returned %q, want no address", got)
		}
		if !slices.Equal(spec.AllowedIPs, []string{"192.168.1.0/24"}) {
			t.Errorf("AllowedIPs = %v, want the manual entry untouched", spec.AllowedIPs)
		}
	}
}

func TestApplyMeshIPReportsNothingForAnUnusableMeshCIDR(t *testing.T) {
	spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{"192.168.1.0/24"}}
	if got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/31"), "worker1", "", spec); got != "" {
		t.Errorf("returned %q, want no address", got)
	}
	if !slices.Equal(spec.AllowedIPs, []string{"192.168.1.0/24"}) {
		t.Errorf("AllowedIPs = %v, want them untouched", spec.AllowedIPs)
	}
}

func allocatorTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return ctrlclientfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&wirekubev1alpha1.WireKubePeer{}).
		Build()
}

func allocatorMesh(cidr string) *wirekubev1alpha1.WireKubeMesh {
	return &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			MeshCIDR:          cidr,
			AddressAllocation: wirekubev1alpha1.AddressAllocationAllocator,
		},
	}
}

// TestAllocateMeshIPIsInertUntilTheMeshOptsIn. The rollout gate exists because
// an agent that has not yet learned to honour status.meshIP would keep forcing
// the hash back; until every agent has, the allocator must write nothing.
func TestAllocateMeshIPIsInertUntilTheMeshOptsIn(t *testing.T) {
	c := allocatorTestClient(t)
	a := &Agent{log: testr.New(t), client: c, nodeName: "worker1", podNamespace: "wirekube-system"}
	for _, mesh := range []*wirekubev1alpha1.WireKubeMesh{
		nil,
		{Spec: wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: "198.18.18.0/24"}},
		{Spec: wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: "198.18.18.0/24", AddressAllocation: wirekubev1alpha1.AddressAllocationHash}},
	} {
		if got := a.allocateMeshIP(context.Background(), mesh, "worker1", "198.18.18.9/32"); got != "198.18.18.9/32" {
			t.Errorf("returned %q, want the recorded address passed straight through", got)
		}
	}
	claims := &coordinationv1.LeaseList{}
	if err := c.List(context.Background(), claims); err != nil {
		t.Fatal(err)
	}
	if len(claims.Items) != 0 {
		t.Errorf("hash mode wrote %d claims, want none", len(claims.Items))
	}
}

func TestAllocateMeshIPClaimsWhenTheMeshOptsIn(t *testing.T) {
	c := allocatorTestClient(t)
	a := &Agent{log: testr.New(t), client: c, nodeName: "worker1", podNamespace: "wirekube-system"}
	want, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	got := a.allocateMeshIP(context.Background(), allocatorMesh("198.18.18.0/24"), "worker1", "")
	if got != want {
		t.Errorf("returned %q, want the hashed %q", got, want)
	}
	claims := &coordinationv1.LeaseList{}
	if err := c.List(context.Background(), claims, client.InNamespace("wirekube-system")); err != nil {
		t.Fatal(err)
	}
	if len(claims.Items) != 1 {
		t.Fatalf("%d claims, want one", len(claims.Items))
	}
}

// TestAllocateMeshIPAdoptsAPreClaimedAddress is the enrolment handshake: a tool
// claims the address under this node's name before the node exists, and the
// agent must pick that address up rather than claim a second one.
func TestAllocateMeshIPAdoptsAPreClaimedAddress(t *testing.T) {
	c := allocatorTestClient(t)
	mesh := allocatorMesh("198.18.18.0/24")
	const preClaimed = "198.18.18.177/32"
	enroller := &meshalloc.Allocator{Client: c, Namespace: "wirekube-system", MeshName: "default", MeshCIDR: mesh.Spec.MeshCIDR}
	if _, err := enroller.Allocate(context.Background(), "worker1", preClaimed); err != nil {
		t.Fatal(err)
	}

	a := &Agent{log: testr.New(t), client: c, nodeName: "worker1", podNamespace: "wirekube-system"}
	if got := a.allocateMeshIP(context.Background(), mesh, "worker1", ""); got != preClaimed {
		t.Errorf("returned %q, want the pre-claimed %q", got, preClaimed)
	}
	claims := &coordinationv1.LeaseList{}
	if err := c.List(context.Background(), claims, client.InNamespace("wirekube-system")); err != nil {
		t.Fatal(err)
	}
	if len(claims.Items) != 1 {
		t.Errorf("%d claims, want the pre-claim adopted rather than a second one made", len(claims.Items))
	}
}

// TestAllocateMeshIPKeepsTheRecordWhenTheAPIFails. Falling back to the hash
// would put this peer back on the address a collision would have moved it off,
// which is the one outcome worse than not allocating at all.
func TestAllocateMeshIPKeepsTheRecordWhenTheAPIFails(t *testing.T) {
	a := &Agent{log: testr.New(t), client: nil, nodeName: "worker1", podNamespace: "wirekube-system"}
	const recorded = "198.18.18.177/32"
	if got := a.allocateMeshIP(context.Background(), allocatorMesh("198.18.18.0/24"), "worker1", recorded); got != recorded {
		t.Errorf("returned %q, want the recorded %q kept", got, recorded)
	}
}

// TestUpsertOwnPeerRecordsTheAllocatedAddress ties the two halves together:
// the address the allocator picked ends up in both allowedIPs[0] and the
// status record that stops the next upsert re-deriving the hash.
func TestUpsertOwnPeerRecordsTheAllocatedAddress(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker1", UID: "node-uid-1"}}
	c := allocatorTestClient(t, node)
	mesh := allocatorMesh("198.18.18.0/24")

	// Somebody already holds worker1's hashed address, so worker1 has to move.
	contested, err := meship.IPForName("worker1", mesh.Spec.MeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	incumbent := &meshalloc.Allocator{Client: c, Namespace: "wirekube-system", MeshName: "default", MeshCIDR: mesh.Spec.MeshCIDR}
	if _, err := incumbent.Allocate(context.Background(), "squatter", contested); err != nil {
		t.Fatal(err)
	}

	a := &Agent{log: testr.New(t), client: c, nodeName: "worker1", podNamespace: "wirekube-system"}
	if err := a.upsertOwnPeer(context.Background(), mesh, node, "worker1", "pubkey", nil); err != nil {
		t.Fatalf("upsertOwnPeer: %v", err)
	}

	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "worker1"}, peer); err != nil {
		t.Fatal(err)
	}
	if len(peer.Spec.AllowedIPs) == 0 {
		t.Fatal("no allowedIPs")
	}
	if peer.Spec.AllowedIPs[0] == contested {
		t.Fatalf("worker1 took %s, which squatter holds", contested)
	}
	if peer.Status.MeshIP != peer.Spec.AllowedIPs[0] {
		t.Errorf("status.meshIP = %q but allowedIPs[0] = %q; they must agree or the next upsert re-derives the hash",
			peer.Status.MeshIP, peer.Spec.AllowedIPs[0])
	}

	// And a second pass is a no-op rather than a second move.
	settled := peer.Spec.AllowedIPs[0]
	if err := a.upsertOwnPeer(context.Background(), mesh, node, "worker1", "pubkey", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "worker1"}, peer); err != nil {
		t.Fatal(err)
	}
	if peer.Spec.AllowedIPs[0] != settled {
		t.Errorf("second upsert moved worker1 from %s to %s", settled, peer.Spec.AllowedIPs[0])
	}
}
