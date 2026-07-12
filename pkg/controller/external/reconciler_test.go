package external

import (
	"context"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const (
	testMeshCIDR     = "100.64.0.0/10"
	testIngressPeer  = "node-a"
	testRelayHost    = "relay.example.com:3478"
	testExternalName = "alice"
)

// validPubKey returns a deterministic 32-byte base64 WG pubkey for the
// external peer.
func validPubKey() string {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// ingressPubKey returns a different deterministic 32-byte base64 WG
// pubkey for the ingress-side WireKubePeer.
func ingressPubKey() string {
	var k [32]byte
	for i := range k {
		k[i] = byte(0xA0 + i)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

func alternateIngressPubKey() string {
	var k [32]byte
	for i := range k {
		k[i] = byte(0xC0 + i)
	}
	return base64.StdEncoding.EncodeToString(k[:])
}

// mockRelay is a counting RelayController. nextPort increments on each
// successful Register so tests can observe deterministic allocation;
// .registerErr injects a synthetic failure (e.g. ErrNotImplemented).
type mockRelay struct {
	endpoint string

	registerErr error
	registerN   atomic.Int32
	ensureN     atomic.Int32
	unregisterN atomic.Int32
	lastUnreg   atomic.Uint32

	mu       sync.Mutex
	nextPort uint16
	mappings map[uint16][2][32]byte // [0]=ingress, [1]=external
}

type probeRelay struct {
	*mockRelay

	probeErr       error
	probeN         atomic.Int32
	probeLatencies map[[32]byte]time.Duration
}

func newMockRelay(endpoint string) *mockRelay {
	return &mockRelay{
		endpoint: endpoint,
		nextPort: 33000,
		mappings: make(map[uint16][2][32]byte),
	}
}

func (m *mockRelay) RelayEndpoint() string { return m.endpoint }

func (m *mockRelay) RegisterForwarder(_ context.Context, ingress, ext [32]byte) (uint16, error) {
	m.registerN.Add(1)
	if m.registerErr != nil {
		return 0, m.registerErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	port := m.nextPort
	m.nextPort++
	m.mappings[port] = [2][32]byte{ingress, ext}
	return port, nil
}

func (m *mockRelay) UnregisterForwarder(_ context.Context, port uint16) error {
	m.unregisterN.Add(1)
	m.lastUnreg.Store(uint32(port))
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.mappings, port)
	return nil
}

func (m *mockRelay) EnsureForwarder(_ context.Context, port uint16, ingress, ext [32]byte) error {
	m.ensureN.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mappings[port] = [2][32]byte{ingress, ext}
	return nil
}

func newProbeRelay(endpoint string, latencies map[[32]byte]time.Duration) *probeRelay {
	return &probeRelay{
		mockRelay:      newMockRelay(endpoint),
		probeLatencies: latencies,
	}
}

func (m *probeRelay) ProbeIngressLatency(_ context.Context, ingressPubKeys [][32]byte) (map[[32]byte]time.Duration, error) {
	m.probeN.Add(1)
	if m.probeErr != nil {
		return nil, m.probeErr
	}
	out := make(map[[32]byte]time.Duration, len(ingressPubKeys))
	for _, key := range ingressPubKeys {
		if rtt, ok := m.probeLatencies[key]; ok {
			out[key] = rtt
		}
	}
	return out, nil
}

// testScheme returns a runtime.Scheme with both core/v1 and
// wirekube.io/v1alpha1 registered. The reconciler uses Status() patches
// so the fake client builder needs an explicit StatusSubresource list.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme(core): %v", err)
	}
	if err := wirekubev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme(wirekube): %v", err)
	}
	return s
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := testScheme(t)
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(
			&wirekubev1alpha1.WireKubeExternalPeer{},
			&wirekubev1alpha1.WireKubeMesh{},
			&wirekubev1alpha1.WireKubePeer{},
		).
		Build()
}

func newReadyMesh() *wirekubev1alpha1.WireKubeMesh {
	return &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			MeshCIDR: testMeshCIDR,
		},
	}
}

func newIngressPeer() *wirekubev1alpha1.WireKubePeer {
	return newIngressPeerWith(testIngressPeer, ingressPubKey())
}

func newIngressPeerWith(name, pubKey string) *wirekubev1alpha1.WireKubePeer {
	return &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: pubKey,
		},
	}
}

func newExternalPeer(name string, mods ...func(*wirekubev1alpha1.WireKubeExternalPeer)) *wirekubev1alpha1.WireKubeExternalPeer {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now()),
		},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			DisplayName: name,
			PublicKey:   validPubKey(),
		},
	}
	for _, m := range mods {
		m(cr)
	}
	return cr
}

func activeExternalPeer(name, ingressPeer string) *wirekubev1alpha1.WireKubeExternalPeer {
	cr := newExternalPeer(name)
	cr.Status.Phase = wirekubev1alpha1.ExternalPeerPhaseActive
	cr.Status.IngressPeerName = ingressPeer
	return cr
}

// reconcileTwice runs Reconcile twice: the first pass adds the
// finalizer + requeues, the second pass performs the actual allocation
// and writes status. Tests that want to assert on Active state should
// use this helper.
func reconcileTwice(t *testing.T, r *Reconciler, name string) ctrl.Result {
	t.Helper()
	ctx := context.Background()
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	return res
}

func getCR(t *testing.T, c client.Client, name string) *wirekubev1alpha1.WireKubeExternalPeer {
	t.Helper()
	got := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: name}, got); err != nil {
		t.Fatalf("get %q: %v", name, err)
	}
	return got
}

// findCondition returns the named condition or a zero value with an
// empty Type if absent.
func findCondition(conds []metav1.Condition, condType string) metav1.Condition {
	for _, c := range conds {
		if c.Type == condType {
			return c
		}
	}
	return metav1.Condition{}
}

// ---------------------------------------------------------------------------
// happy path
// ---------------------------------------------------------------------------

func TestReconcile_HappyPath(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)

	r := &Reconciler{
		Client: c,
		Scheme: testScheme(t),
		Relay:  relayCtl,
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if got.Status.AssignedMeshIP == "" {
		t.Fatal("assignedMeshIP empty")
	}
	if got.Status.RelayPort != 0 {
		t.Fatalf("relayPort = %d, want 0 for shared endpoint", got.Status.RelayPort)
	}
	if got.Status.IngressPeerName != testIngressPeer {
		t.Fatalf("ingressPeerName = %q, want %q", got.Status.IngressPeerName, testIngressPeer)
	}
	if got.Status.PublicKey != validPubKey() {
		t.Fatal("publicKey not mirrored from spec")
	}
	if got.Status.RelayEndpoint != testRelayHost {
		t.Fatalf("relayEndpoint = %q, want %q", got.Status.RelayEndpoint, testRelayHost)
	}
	if got.Status.MTU != wirekubev1alpha1.DefaultExternalPeerMTU {
		t.Fatalf("mtu = %d, want %d", got.Status.MTU, wirekubev1alpha1.DefaultExternalPeerMTU)
	}
	cond := findCondition(got.Status.Conditions, conditionReady)
	if cond.Status != metav1.ConditionTrue || cond.Reason != reasonReconciled {
		t.Fatalf("Ready condition = %+v", cond)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder calls = %d, want 0 for shared endpoint", relayCtl.registerN.Load())
	}
}

func TestReconcile_ExplicitMTU(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.MTU = 1200
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.MTU != 1200 {
		t.Fatalf("mtu = %d, want 1200", got.Status.MTU)
	}
}

func TestReconcile_ExplicitIngressPeer(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.IngressPeer = "node-z"
	})
	c := newFakeClient(t, cr, newReadyMesh(),
		newIngressPeerWith("node-a", ingressPubKey()),
		newIngressPeerWith("node-z", alternateIngressPubKey()),
	)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != "node-z" {
		t.Fatalf("ingressPeerName = %q, want node-z", got.Status.IngressPeerName)
	}
	if got.Status.IngressPublicKey != alternateIngressPubKey() {
		t.Fatalf("ingressPublicKey = %q, want explicit peer key", got.Status.IngressPublicKey)
	}
}

func TestReconcile_StatusIngressPeerIsStable(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)
	if err := c.Create(context.Background(), newIngressPeerWith("aaa-earlier", alternateIngressPubKey())); err != nil {
		t.Fatalf("create earlier peer: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}); err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != testIngressPeer {
		t.Fatalf("ingressPeerName changed to %q, want stable %q", got.Status.IngressPeerName, testIngressPeer)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder calls = %d, want 0 for shared endpoint", relayCtl.registerN.Load())
	}
}

func TestReconcile_AutoIngressPrefersLowerLoadWhenRelayRTTIsClose(t *testing.T) {
	nodeAKey := ingressPubKey()
	nodeBKey := alternateIngressPubKey()
	nodeA, err := decodeWGKey(nodeAKey)
	if err != nil {
		t.Fatalf("decode node-a key: %v", err)
	}
	nodeB, err := decodeWGKey(nodeBKey)
	if err != nil {
		t.Fatalf("decode node-b key: %v", err)
	}

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(),
		newIngressPeerWith("node-a", nodeAKey),
		newIngressPeerWith("node-b", nodeBKey),
		activeExternalPeer("bob", "node-a"),
		activeExternalPeer("carol", "node-a"),
	)
	relayCtl := newProbeRelay(testRelayHost, map[[32]byte]time.Duration{
		nodeA: 5 * time.Millisecond,
		nodeB: 40 * time.Millisecond,
	})
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != "node-b" {
		t.Fatalf("ingressPeerName = %q, want node-b", got.Status.IngressPeerName)
	}
	if relayCtl.probeN.Load() != 1 {
		t.Fatalf("ProbeIngressLatency calls = %d, want 1", relayCtl.probeN.Load())
	}
}

func TestReconcile_AutoIngressKeepsFastPeerWhenLoadPenaltyIsSmallerThanRTTGap(t *testing.T) {
	nodeAKey := ingressPubKey()
	nodeBKey := alternateIngressPubKey()
	nodeA, err := decodeWGKey(nodeAKey)
	if err != nil {
		t.Fatalf("decode node-a key: %v", err)
	}
	nodeB, err := decodeWGKey(nodeBKey)
	if err != nil {
		t.Fatalf("decode node-b key: %v", err)
	}

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(),
		newIngressPeerWith("node-a", nodeAKey),
		newIngressPeerWith("node-b", nodeBKey),
		activeExternalPeer("bob", "node-a"),
	)
	relayCtl := newProbeRelay(testRelayHost, map[[32]byte]time.Duration{
		nodeA: 5 * time.Millisecond,
		nodeB: 100 * time.Millisecond,
	})
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != "node-a" {
		t.Fatalf("ingressPeerName = %q, want node-a", got.Status.IngressPeerName)
	}
}

func TestReconcile_AutoIngressFallsBackWhenIngressProbeDisabled(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newProbeRelay(testRelayHost, nil)
	relayCtl.probeErr = ErrIngressProbeDisabled
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if got.Status.IngressPeerName != testIngressPeer {
		t.Fatalf("ingressPeerName = %q, want %q", got.Status.IngressPeerName, testIngressPeer)
	}
	if relayCtl.probeN.Load() != 1 {
		t.Fatalf("ProbeIngressLatency calls = %d, want 1", relayCtl.probeN.Load())
	}
}

func TestReconcile_ExplicitIngressPeerFallsBackWhenIngressProbeDisabled(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.IngressPeer = "node-a"
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newProbeRelay(testRelayHost, nil)
	relayCtl.probeErr = ErrIngressProbeDisabled
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if got.Status.IngressPeerName != "node-a" {
		t.Fatalf("ingressPeerName = %q, want node-a", got.Status.IngressPeerName)
	}
}

func TestReconcile_ExplicitIngressPeerMustBeReachableFromRelay(t *testing.T) {
	nodeAKey := ingressPubKey()
	if _, err := decodeWGKey(nodeAKey); err != nil {
		t.Fatalf("decode node-a key: %v", err)
	}
	nodeB, err := decodeWGKey(alternateIngressPubKey())
	if err != nil {
		t.Fatalf("decode unrelated key: %v", err)
	}
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.IngressPeer = "node-a"
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeerWith("node-a", nodeAKey))
	relayCtl := newProbeRelay(testRelayHost, map[[32]byte]time.Duration{
		// An unrelated result proves the controller does not accept a
		// successful probe response unless the requested ingress key is present.
		nodeB: time.Millisecond,
	})
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	res := reconcileTwice(t, r, testExternalName)
	if res.RequeueAfter == 0 {
		t.Fatal("expected RequeueAfter > 0")
	}
	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Fatalf("phase = %q, want Pending", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonIngressPeerNotReady {
		t.Fatalf("Reason = %q, want %q", cond.Reason, reasonIngressPeerNotReady)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder calls = %d, want 0", relayCtl.registerN.Load())
	}
}

// ---------------------------------------------------------------------------
// idempotency: re-reconciling an Active CR must NOT call RegisterForwarder.
// ---------------------------------------------------------------------------

func TestReconcile_IdempotentReReconcile(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("first pass register count = %d, want 0 for shared endpoint", relayCtl.registerN.Load())
	}
	firstPort := getCR(t, c, testExternalName).Status.RelayPort

	// Third reconcile: must be a no-op for the relay controller.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}); err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder called again on idempotent reconcile (got %d calls)", relayCtl.registerN.Load())
	}
	if relayCtl.unregisterN.Load() != 0 {
		t.Fatalf("UnregisterForwarder unexpectedly called (got %d)", relayCtl.unregisterN.Load())
	}
	if relayCtl.ensureN.Load() != 0 {
		t.Fatalf("EnsureForwarder calls after idempotent reconcile = %d, want 0 for shared endpoint", relayCtl.ensureN.Load())
	}
	if got := getCR(t, c, testExternalName).Status.RelayPort; got != firstPort {
		t.Fatalf("relayPort changed from %d to %d on idempotent reconcile", firstPort, got)
	}
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

func TestReconcile_MissingDisplayName(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.DisplayName = ""
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseFailed {
		t.Fatalf("phase = %q, want Failed", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonValidationFailed {
		t.Fatalf("Reason = %q, want %q", cond.Reason, reasonValidationFailed)
	}
}

func TestReconcile_MissingPublicKey(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.PublicKey = ""
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseFailed {
		t.Fatalf("phase = %q, want Failed", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonValidationFailed {
		t.Fatalf("Reason = %q, want %q", cond.Reason, reasonValidationFailed)
	}
}

func TestReconcile_InvalidPublicKey(t *testing.T) {
	cases := []struct{ name, key string }{
		{"non-base64", "not===base64==="},
		{"too-short", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"too-long", base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
				p.Spec.PublicKey = tc.key
			})
			c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
			r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

			reconcileTwice(t, r, testExternalName)

			got := getCR(t, c, testExternalName)
			if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseFailed {
				t.Fatalf("phase = %q, want Failed", got.Status.Phase)
			}
			cond := findCondition(got.Status.Conditions, conditionReady)
			if cond.Reason != reasonInvalidPublicKey {
				t.Fatalf("Reason = %q, want %q", cond.Reason, reasonInvalidPublicKey)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// dependency-not-ready paths
// ---------------------------------------------------------------------------

func TestReconcile_NoMesh(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newIngressPeer()) // no mesh
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	res := reconcileTwice(t, r, testExternalName)
	if res.RequeueAfter == 0 {
		t.Fatal("expected RequeueAfter > 0")
	}
	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Fatalf("phase = %q, want Pending", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonMeshNotFound {
		t.Fatalf("Reason = %q, want %q", cond.Reason, reasonMeshNotFound)
	}
}

func TestReconcile_NoReadyIngressPeer(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh())
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	res := reconcileTwice(t, r, testExternalName)
	if res.RequeueAfter == 0 {
		t.Fatal("expected RequeueAfter > 0")
	}
	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Fatalf("phase = %q, want Pending", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonNoReadyIngressPeer {
		t.Fatalf("Reason = %q, want %q", cond.Reason, reasonNoReadyIngressPeer)
	}
}

func TestReconcile_DoesNotRequireForwarderController(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)
	relayCtl.registerErr = ErrNotImplemented
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	reconcileTwice(t, r, testExternalName)
	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder calls = %d, want 0 for shared endpoint", relayCtl.registerN.Load())
	}
}

func TestReconcile_RelayResolverReevaluatesAfterEndpointReady(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)
	ready := false
	r := &Reconciler{
		Client: c,
		Scheme: testScheme(t),
		Relay:  NewNoopRelayController(""),
		RelayResolver: func(_ context.Context, _ *wirekubev1alpha1.WireKubeMesh) RelayController {
			if ready {
				return relayCtl
			}
			return newMockRelay("")
		},
	}

	res := reconcileTwice(t, r, testExternalName)
	if res.RequeueAfter == 0 {
		t.Fatal("expected RequeueAfter > 0 while relay endpoint is not ready")
	}
	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Fatalf("phase = %q, want Pending", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonRelayEndpointNotReady {
		t.Fatalf("Reason = %q, want %q", cond.Reason, reasonRelayEndpointNotReady)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder calls before endpoint ready = %d, want 0", relayCtl.registerN.Load())
	}

	ready = true
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}); err != nil {
		t.Fatalf("Reconcile after endpoint ready: %v", err)
	}
	got = getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if relayCtl.registerN.Load() != 0 {
		t.Fatalf("RegisterForwarder calls after endpoint ready = %d, want 0 for shared endpoint", relayCtl.registerN.Load())
	}
}

// ---------------------------------------------------------------------------
// deletion
// ---------------------------------------------------------------------------

func TestReconcile_Deletion(t *testing.T) {
	now := metav1.NewTime(time.Now())
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Finalizers = []string{FinalizerName}
		p.DeletionTimestamp = &now
		p.Status.RelayPort = 42
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: relayCtl}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if relayCtl.unregisterN.Load() != 1 {
		t.Fatalf("UnregisterForwarder called %d times, want 1", relayCtl.unregisterN.Load())
	}
	if relayCtl.lastUnreg.Load() != 42 {
		t.Fatalf("UnregisterForwarder port = %d, want 42", relayCtl.lastUnreg.Load())
	}
	// CR should be gone (finalizer removed → fake client deletes object).
	got := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(context.Background(), types.NamespacedName{Name: testExternalName}, got)
	if !apierrors.IsNotFound(err) {
		// Some fake clients keep the object around with the finalizer
		// removed but no DeletionTimestamp resolution; accept either.
		if err == nil {
			for _, f := range got.Finalizers {
				if f == FinalizerName {
					t.Fatalf("finalizer %q not removed", FinalizerName)
				}
			}
		} else {
			t.Fatalf("Get after deletion: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// TTL expiry
// ---------------------------------------------------------------------------

func TestReconcile_TTLExpiry(t *testing.T) {
	creation := metav1.NewTime(time.Now().Add(-2 * time.Hour))
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.CreationTimestamp = creation
		p.Spec.TTL = &metav1.Duration{Duration: time.Hour}
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	relayCtl := newMockRelay(testRelayHost)
	// Pin Now() so the TTL math is deterministic.
	r := &Reconciler{
		Client: c,
		Scheme: testScheme(t),
		Relay:  relayCtl,
		Now:    func() time.Time { return creation.Time.Add(2 * time.Hour) },
	}

	reconcileTwice(t, r, testExternalName)

	got := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(context.Background(), types.NamespacedName{Name: testExternalName}, got)
	if err == nil {
		// fake client: a Delete on a CR with finalizers sets a
		// DeletionTimestamp instead of removing — that is the
		// observable signal we want.
		if got.DeletionTimestamp == nil {
			t.Fatalf("expected CR to be deleted or marked for deletion (DT=%v, finalizers=%v)",
				got.DeletionTimestamp, got.Finalizers)
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("Get after TTL: %v", err)
	}
}
