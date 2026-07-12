package agent

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func cleanupTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(core): %v", err)
	}
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(wirekube): %v", err)
	}
	return scheme
}

// TestNodeOwnerReferences covers the two inputs that need to behave
// gracefully: a nil node (e.g. caller hasn't fetched the Node yet, which
// happens during early setup races) and a node missing its UID (e.g.
// constructed by a test). In both cases the helper must return an empty
// slice so callers can append it unconditionally.
func TestNodeOwnerReferences(t *testing.T) {
	if refs := nodeOwnerReferences(nil); refs != nil {
		t.Fatalf("nodeOwnerReferences(nil) = %v, want nil", refs)
	}
	if refs := nodeOwnerReferences(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n"}}); refs != nil {
		t.Fatalf("nodeOwnerReferences(no-UID) = %v, want nil", refs)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker1", UID: types.UID("abc")}}
	refs := nodeOwnerReferences(node)
	if len(refs) != 1 {
		t.Fatalf("len = %d, want 1", len(refs))
	}
	if refs[0].Kind != "Node" || refs[0].Name != "worker1" || refs[0].UID != types.UID("abc") || refs[0].APIVersion != "v1" {
		t.Fatalf("unexpected ref: %+v", refs[0])
	}
}

// TestHasNodeOwnerReference asserts that the matcher rejects mismatched
// UIDs even when names happen to coincide: K8s nodes can be deleted and
// recreated with the same name but a fresh UID, and ownerReferences must
// be re-emitted in that case so K8s GC tracks the current owner.
func TestHasNodeOwnerReference(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n", UID: types.UID("uid-1")}}
	if hasNodeOwnerReference(nil, node) {
		t.Fatal("nil refs should return false")
	}
	refs := []metav1.OwnerReference{{Kind: "Node", Name: "n", UID: types.UID("uid-2")}}
	if hasNodeOwnerReference(refs, node) {
		t.Fatal("stale UID should be treated as missing")
	}
	refs = append(refs, metav1.OwnerReference{Kind: "Node", Name: "n", UID: types.UID("uid-1")})
	if !hasNodeOwnerReference(refs, node) {
		t.Fatal("matching UID should be detected")
	}
}

// peerWithAge produces an agent-managed WireKubePeer fixture (carrying
// agentManagedPeerLabel) whose CreationTimestamp is rewound by `age`.
// Used to exercise the grace-period gate in cleanupOrphanedPeers —
// tests need both "young enough to be spared" and "old enough to be
// reaped" fixtures.
func peerWithAge(name string, age time.Duration) *wirekubev1alpha1.WireKubePeer {
	return &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Labels:            map[string]string{agentManagedPeerLabel: name},
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
	}
}

// externalPeer produces an external (manually-created) WireKubePeer
// fixture without the agent-managed label. Used to confirm cleanup
// leaves user-curated peers untouched even when they have no matching
// K8s Node.
func externalPeer(name string, age time.Duration) *wirekubev1alpha1.WireKubePeer {
	return &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now().Add(-age)),
		},
	}
}

// TestCleanupOrphanedPeersDeletesOrphans is the happy path: a CR whose
// underlying Node is gone and which has outlived the grace period must
// be deleted, while peers with a matching Node must be preserved.
func TestCleanupOrphanedPeersDeletesOrphans(t *testing.T) {
	scheme := cleanupTestScheme(t)
	orphan := peerWithAge("gpu-bm", orphanGracePeriod+time.Minute)
	live := peerWithAge("worker1", 2*orphanGracePeriod)
	worker1Node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker1", UID: "uid-1"}}
	myNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "self", UID: "uid-self"}}
	myPeer := peerWithAge("self", time.Hour)
	c := ctrlclientfake.NewClientBuilder().WithScheme(scheme).
		WithObjects(orphan, live, myPeer, worker1Node, myNode).Build()

	a := &Agent{log: testr.New(t), client: c, nodeName: "self"}
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := c.List(context.Background(), peerList); err != nil {
		t.Fatalf("list: %v", err)
	}
	a.cleanupOrphanedPeers(context.Background(), peerList)

	if err := c.Get(context.Background(), client.ObjectKey{Name: "gpu-bm"}, &wirekubev1alpha1.WireKubePeer{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected orphan to be deleted, got err=%v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "worker1"}, &wirekubev1alpha1.WireKubePeer{}); err != nil {
		t.Fatalf("expected live peer to survive: %v", err)
	}
}

// TestCleanupOrphanedPeersHonoursGracePeriod guards against deleting a
// brand-new peer whose Node has not yet propagated into this agent's
// local cache (control-plane scale-up race or transient API server
// hiccup). The cleanup must wait for the grace period before considering
// the peer abandoned.
func TestCleanupOrphanedPeersHonoursGracePeriod(t *testing.T) {
	scheme := cleanupTestScheme(t)
	freshOrphan := peerWithAge("brand-new", orphanGracePeriod/2)
	c := ctrlclientfake.NewClientBuilder().WithScheme(scheme).WithObjects(freshOrphan).Build()

	a := &Agent{log: testr.New(t), client: c, nodeName: "self"}
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := c.List(context.Background(), peerList); err != nil {
		t.Fatalf("list: %v", err)
	}
	a.cleanupOrphanedPeers(context.Background(), peerList)

	if err := c.Get(context.Background(), client.ObjectKey{Name: "brand-new"}, &wirekubev1alpha1.WireKubePeer{}); err != nil {
		t.Fatalf("fresh peer was incorrectly deleted: %v", err)
	}
}

// TestCleanupOrphanedPeersIgnoresSelf protects the local agent's own
// peer record. This row is the agent's published identity; deleting it
// would break the cluster's view of this node until the next sync. The
// agent's own cleanup() path (graceful shutdown) is the only legitimate
// way to remove this record.
func TestCleanupOrphanedPeersIgnoresSelf(t *testing.T) {
	scheme := cleanupTestScheme(t)
	selfPeer := peerWithAge("self", 2*orphanGracePeriod)
	c := ctrlclientfake.NewClientBuilder().WithScheme(scheme).WithObjects(selfPeer).Build()

	a := &Agent{log: testr.New(t), client: c, nodeName: "self"}
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := c.List(context.Background(), peerList); err != nil {
		t.Fatalf("list: %v", err)
	}
	a.cleanupOrphanedPeers(context.Background(), peerList)

	if err := c.Get(context.Background(), client.ObjectKey{Name: "self"}, &wirekubev1alpha1.WireKubePeer{}); err != nil {
		t.Fatalf("own peer was deleted: %v", err)
	}
}

// TestCleanupOrphanedPeersIgnoresExternalPeers protects manually-created
// external peers (home PCs, remote VMs — per WireKubePeer type doc) from
// being mistaken for orphans. They lack the wirekube.io/node label that
// upsertOwnPeer sets, so the cleanup must skip them even when no Node
// matches and the grace period has long elapsed.
func TestCleanupOrphanedPeersIgnoresExternalPeers(t *testing.T) {
	scheme := cleanupTestScheme(t)
	external := externalPeer("my-laptop", 30*orphanGracePeriod)
	c := ctrlclientfake.NewClientBuilder().WithScheme(scheme).WithObjects(external).Build()

	a := &Agent{log: testr.New(t), client: c, nodeName: "self"}
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := c.List(context.Background(), peerList); err != nil {
		t.Fatalf("list: %v", err)
	}
	a.cleanupOrphanedPeers(context.Background(), peerList)

	if err := c.Get(context.Background(), client.ObjectKey{Name: "my-laptop"}, &wirekubev1alpha1.WireKubePeer{}); err != nil {
		t.Fatalf("external peer was deleted: %v", err)
	}
}

// TestDropStaleMetricLabelsRemovesVanished asserts the diff-based label
// cleanup. After emitting a sample for "gone", advancing the peer set to
// only contain "alive", the gauge must drop the "gone" label so /metrics
// stops advertising the vanished peer.
func TestDropStaleMetricLabelsRemovesVanished(t *testing.T) {
	peerTransport.Reset()
	peerTransport.WithLabelValues("me", "gone").Set(2)
	peerTransport.WithLabelValues("me", "alive").Set(1)

	if before := testutil.CollectAndCount(peerTransport); before != 2 {
		t.Fatalf("setup: peerTransport count = %d, want 2", before)
	}

	a := &Agent{
		nodeName:         "self",
		peerMetricLabels: map[string]struct{}{"gone": {}, "alive": {}},
	}
	a.dropStaleMetricLabels(map[string]struct{}{"alive": {}})

	if after := testutil.CollectAndCount(peerTransport); after != 1 {
		t.Fatalf("peerTransport count after cleanup = %d, want 1", after)
	}
	if _, tracked := a.peerMetricLabels["gone"]; tracked {
		t.Fatal("peerMetricLabels still contains vanished peer")
	}
}

// TestDropStaleMetricLabelsKeepsSelf is the defensive invariant: a label
// matching the local node name must never be dropped, even if it slipped
// into peerMetricLabels via a future bug. Per-peer metrics are not
// supposed to be emitted for self, but if they are, removing them on
// every cycle would cause oscillation.
func TestDropStaleMetricLabelsKeepsSelf(t *testing.T) {
	peerTransport.Reset()
	peerTransport.WithLabelValues("self", "self").Set(1)

	a := &Agent{
		nodeName:         "self",
		peerMetricLabels: map[string]struct{}{"self": {}},
	}
	a.dropStaleMetricLabels(map[string]struct{}{})

	if count := testutil.CollectAndCount(peerTransport); count != 1 {
		t.Fatalf("self metric was dropped (count=%d)", count)
	}
}

// TestUpsertOwnPeerCreateAttachesOwnerReference asserts the create path
// installs a Node ownerReference so K8s GC cascade-deletes the peer on
// node removal — the load-bearing invariant of this fix.
func TestUpsertOwnPeerCreateAttachesOwnerReference(t *testing.T) {
	scheme := cleanupTestScheme(t)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker1", UID: "node-uid-1"}}
	c := ctrlclientfake.NewClientBuilder().WithScheme(scheme).WithObjects(node).Build()

	a := &Agent{log: testr.New(t), client: c, nodeName: "worker1"}
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	if err := a.upsertOwnPeer(context.Background(), mesh, node, "worker1", "pubkey", nil); err != nil {
		t.Fatalf("upsertOwnPeer: %v", err)
	}
	got := &wirekubev1alpha1.WireKubePeer{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "worker1"}, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("OwnerReferences len = %d, want 1", len(got.OwnerReferences))
	}
	if got.OwnerReferences[0].UID != types.UID("node-uid-1") {
		t.Fatalf("OwnerReferences UID mismatch: got %s", got.OwnerReferences[0].UID)
	}
	if got.Labels[agentManagedPeerLabel] != "worker1" {
		t.Fatalf("agent-managed label missing: %v", got.Labels)
	}
}

// TestUpsertOwnPeerPatchBackfillsOwnerReference covers the migration
// path: pre-existing CRs (created before this fix) get the ownerRef
// retroactively attached during the next sync, so K8s GC starts
// tracking them without requiring manual intervention.
func TestUpsertOwnPeerPatchBackfillsOwnerReference(t *testing.T) {
	scheme := cleanupTestScheme(t)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker1", UID: "node-uid-1"}}
	legacy := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "worker1",
			Labels: map[string]string{agentManagedPeerLabel: "worker1"},
			// No OwnerReferences — pre-fix CR.
		},
		Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "oldkey"},
	}
	c := ctrlclientfake.NewClientBuilder().WithScheme(scheme).WithObjects(node, legacy).Build()

	a := &Agent{log: testr.New(t), client: c, nodeName: "worker1"}
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	if err := a.upsertOwnPeer(context.Background(), mesh, node, "worker1", "newkey", nil); err != nil {
		t.Fatalf("upsertOwnPeer: %v", err)
	}
	got := &wirekubev1alpha1.WireKubePeer{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "worker1"}, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].UID != types.UID("node-uid-1") {
		t.Fatalf("OwnerReferences not backfilled: %+v", got.OwnerReferences)
	}
}
