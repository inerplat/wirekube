package external

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// serviceCIDRReader stands in for the uncached APIReader. It serves
// unstructured ServiceCIDR lists for exactly one API group/version and
// answers every other one the way a RESTMapper answers a kind the server
// does not serve, so tests can pin which graduation stage a cluster is at.
type serviceCIDRReader struct {
	client.Reader

	apiVersion string
	items      []unstructured.Unstructured
	listErr    error

	tried []string
}

func (s *serviceCIDRReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	typed, ok := list.(*unstructured.UnstructuredList)
	if !ok {
		return s.Reader.List(ctx, list, opts...)
	}
	s.tried = append(s.tried, typed.GetAPIVersion())
	if s.listErr != nil {
		return s.listErr
	}
	if typed.GetAPIVersion() != s.apiVersion {
		return &meta.NoKindMatchError{
			GroupKind:        schema.GroupKind{Group: "networking.k8s.io", Kind: "ServiceCIDR"},
			SearchedVersions: []string{typed.GetAPIVersion()},
		}
	}
	typed.Items = append([]unstructured.Unstructured(nil), s.items...)
	return nil
}

func newServiceCIDRObject(apiVersion, name string, ready *bool, cidrs ...string) unstructured.Unstructured {
	values := make([]any, 0, len(cidrs))
	for _, c := range cidrs {
		values = append(values, c)
	}
	obj := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiVersion,
		"kind":       "ServiceCIDR",
		"metadata":   map[string]any{"name": name},
		"spec":       map[string]any{"cidrs": values},
	}}
	if ready != nil {
		status := "False"
		if *ready {
			status = "True"
		}
		obj.Object["status"] = map[string]any{
			"conditions": []any{
				map[string]any{"type": "Ready", "status": status},
			},
		}
	}
	return obj
}

func boolPtr(b bool) *bool { return &b }

func newNode(name, podCIDR string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{PodCIDR: podCIDR, PodCIDRs: []string{podCIDR}},
	}
}

func newGateway(name string, cidrs ...string) *wirekubev1alpha1.WireKubeGateway {
	routes := make([]wirekubev1alpha1.GatewayRoute, 0, len(cidrs))
	for _, c := range cidrs {
		routes = append(routes, wirekubev1alpha1.GatewayRoute{CIDR: c})
	}
	return &wirekubev1alpha1.WireKubeGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: wirekubev1alpha1.WireKubeGatewaySpec{
			PeerRefs: []string{testIngressPeer},
			Routes:   routes,
		},
	}
}

// ---------------------------------------------------------------------------
// defaulting
// ---------------------------------------------------------------------------

func TestAllowedDestinations_DefaultsToEveryClusterRange(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(),
		newNode("node-a", "10.244.1.0/24"),
		newNode("node-b", "10.244.2.0/24"),
		newGateway("ncp", "172.20.0.0/16"),
	)
	r := &Reconciler{
		Client: c,
		Scheme: testScheme(t),
		Relay:  newMockRelay(testRelayHost),
		APIReader: &serviceCIDRReader{
			Reader:     c,
			apiVersion: "networking.k8s.io/v1",
			items: []unstructured.Unstructured{
				newServiceCIDRObject("networking.k8s.io/v1", "kubernetes", boolPtr(true), "10.96.0.0/12"),
			},
		},
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	want := []string{
		"10.244.1.0/24",
		"10.244.2.0/24",
		"10.96.0.0/12",
		"100.64.0.0/10",
		"172.20.0.0/16",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("allowedDestinations = %v, want %v", got, want)
	}
}

func TestAllowedDestinations_IsSortedForStableStatus(t *testing.T) {
	// Nodes are listed in arbitrary order; status is compared with
	// slices.Equal, so an unsorted result would rewrite status forever.
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(),
		newNode("node-z", "10.244.9.0/24"),
		newNode("node-a", "10.244.1.0/24"),
	)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)
	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.IsSorted(got) {
		t.Fatalf("allowedDestinations not sorted: %v", got)
	}

	// A further reconcile must not rewrite an already-correct status.
	before := getCR(t, c, testExternalName).ResourceVersion
	reconcileTwice(t, r, testExternalName)
	if after := getCR(t, c, testExternalName).ResourceVersion; after != before {
		t.Fatalf("status rewritten on steady-state reconcile: %s -> %s", before, after)
	}
}

func TestAllowedDestinations_ExplicitSpecWinsVerbatim(t *testing.T) {
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.AllowedDestinations = []string{"192.168.5.0/24", "10.0.0.0/8"}
	})
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(),
		newNode("node-a", "10.244.1.0/24"),
		newGateway("ncp", "172.20.0.0/16"),
	)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	want := []string{"192.168.5.0/24", "10.0.0.0/8"}
	if !slices.Equal(got, want) {
		t.Fatalf("allowedDestinations = %v, want operator order %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// service CIDR resolution
// ---------------------------------------------------------------------------

func TestServiceCIDRs_MeshOverrideBeatsDiscovery(t *testing.T) {
	mesh := newReadyMesh()
	mesh.Spec.ServiceCIDRs = []string{"10.43.0.0/16"}
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, mesh, newIngressPeer())
	reader := &serviceCIDRReader{
		Reader:     c,
		apiVersion: "networking.k8s.io/v1",
		items: []unstructured.Unstructured{
			newServiceCIDRObject("networking.k8s.io/v1", "kubernetes", boolPtr(true), "10.96.0.0/12"),
		},
	}
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), APIReader: reader}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Contains(got, "10.43.0.0/16") {
		t.Fatalf("mesh override missing from %v", got)
	}
	if slices.Contains(got, "10.96.0.0/12") {
		t.Fatalf("discovered range used despite explicit override: %v", got)
	}
	if len(reader.tried) != 0 {
		t.Fatalf("discovery attempted despite override: %v", reader.tried)
	}
}

func TestServiceCIDRs_FallsThroughToServedGroupVersion(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	reader := &serviceCIDRReader{
		Reader:     c,
		apiVersion: "networking.k8s.io/v1beta1",
		items: []unstructured.Unstructured{
			newServiceCIDRObject("networking.k8s.io/v1beta1", "kubernetes", boolPtr(true), "10.96.0.0/12"),
		},
	}
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost), APIReader: reader}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Contains(got, "10.96.0.0/12") {
		t.Fatalf("v1beta1 range missing from %v", got)
	}
	if len(reader.tried) == 0 || reader.tried[0] != "networking.k8s.io/v1" {
		t.Fatalf("expected v1 to be tried first, got %v", reader.tried)
	}
}

func TestServiceCIDRs_SkipsTerminatingRange(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost),
		APIReader: &serviceCIDRReader{
			Reader:     c,
			apiVersion: "networking.k8s.io/v1",
			items: []unstructured.Unstructured{
				newServiceCIDRObject("networking.k8s.io/v1", "kubernetes", boolPtr(true), "10.96.0.0/12"),
				newServiceCIDRObject("networking.k8s.io/v1", "retiring", boolPtr(false), "10.112.0.0/12"),
			},
		},
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Contains(got, "10.96.0.0/12") {
		t.Fatalf("ready range missing from %v", got)
	}
	if slices.Contains(got, "10.112.0.0/12") {
		t.Fatalf("terminating range advertised: %v", got)
	}
}

func TestServiceCIDRs_ConditionlessObjectIsUsed(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer())
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost),
		APIReader: &serviceCIDRReader{
			Reader:     c,
			apiVersion: "networking.k8s.io/v1alpha1",
			items: []unstructured.Unstructured{
				newServiceCIDRObject("networking.k8s.io/v1alpha1", "kubernetes", nil, "10.96.0.0/12"),
			},
		},
	}

	reconcileTwice(t, r, testExternalName)

	if got := getCR(t, c, testExternalName).Status.AllowedDestinations; !slices.Contains(got, "10.96.0.0/12") {
		t.Fatalf("conditionless range dropped: %v", got)
	}
}

func TestServiceCIDRs_UnservedClusterStillIssuesPeer(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(),
		newNode("node-a", "10.244.1.0/24"),
		newGateway("ncp", "172.20.0.0/16"),
	)
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost),
		APIReader: &serviceCIDRReader{Reader: c, apiVersion: "served/by/nothing"},
	}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active despite absent ServiceCIDR API", got.Status.Phase)
	}
	want := []string{"10.244.1.0/24", "100.64.0.0/10", "172.20.0.0/16"}
	if !slices.Equal(got.Status.AllowedDestinations, want) {
		t.Fatalf("allowedDestinations = %v, want %v", got.Status.AllowedDestinations, want)
	}
}

// ---------------------------------------------------------------------------
// gateway routes
// ---------------------------------------------------------------------------

func TestAllowedDestinations_IncludesEveryGatewayRoute(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(),
		newGateway("ncp", "172.20.0.0/16", "172.21.0.0/16"),
		newGateway("onprem", "192.168.0.0/16"),
	)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	for _, want := range []string{"172.20.0.0/16", "172.21.0.0/16", "192.168.0.0/16"} {
		if !slices.Contains(got, want) {
			t.Fatalf("gateway route %s missing from %v", want, got)
		}
	}
}

func TestAllowedDestinations_DeduplicatesOverlappingSources(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(),
		newNode("node-a", "10.244.1.0/24"),
		// A gateway that re-advertises a pod CIDR must not double it up.
		newGateway("dup", "10.244.1.0/24"),
	)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	count := 0
	for _, c := range got {
		if c == "10.244.1.0/24" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("10.244.1.0/24 appears %d times in %v", count, got)
	}
}

// ---------------------------------------------------------------------------
// degraded reads
// ---------------------------------------------------------------------------

// TestAllowedDestinations_DegradedReadKeepsExistingStatus pins the rule that a
// failed read must never shrink a peer that already has destinations: the
// rendered conf is read back from status, so a momentary apiserver failure
// would otherwise hand the next downloader a conf that stops routing a range.
func TestAllowedDestinations_DegradedReadKeepsExistingStatus(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	scheme := testScheme(t)
	failGateways := false
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, newReadyMesh(), newIngressPeer(),
			newNode("node-a", "10.244.1.0/24"),
			newGateway("ncp", "172.20.0.0/16"),
		).
		WithStatusSubresource(
			&wirekubev1alpha1.WireKubeExternalPeer{},
			&wirekubev1alpha1.WireKubeMesh{},
			&wirekubev1alpha1.WireKubePeer{},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*wirekubev1alpha1.WireKubeGatewayList); ok && failGateways {
					return apierrors.NewServiceUnavailable("synthetic outage")
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &Reconciler{
		Client: c,
		Scheme: scheme,
		Relay:  newMockRelay(testRelayHost),
		APIReader: &serviceCIDRReader{
			Reader:     c,
			apiVersion: "networking.k8s.io/v1",
			items: []unstructured.Unstructured{
				newServiceCIDRObject("networking.k8s.io/v1", "kubernetes", boolPtr(true), "10.96.0.0/12"),
			},
		},
	}

	reconcileTwice(t, r, testExternalName)
	want := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Contains(want, "172.20.0.0/16") {
		t.Fatalf("precondition: gateway route missing from %v", want)
	}

	failGateways = true
	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Equal(got, want) {
		t.Fatalf("degraded reconcile narrowed destinations: %v, want %v", got, want)
	}
}

// TestAllowedDestinations_DegradedFirstIssuanceStillProceeds is the other half
// of the rule: with nothing to preserve, a partial list beats no conf at all.
func TestAllowedDestinations_DegradedFirstIssuanceStillProceeds(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	scheme := testScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, newReadyMesh(), newIngressPeer(), newNode("node-a", "10.244.1.0/24")).
		WithStatusSubresource(
			&wirekubev1alpha1.WireKubeExternalPeer{},
			&wirekubev1alpha1.WireKubeMesh{},
			&wirekubev1alpha1.WireKubePeer{},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*wirekubev1alpha1.WireKubeGatewayList); ok {
					return apierrors.NewServiceUnavailable("synthetic outage")
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &Reconciler{Client: c, Scheme: scheme, Relay: newMockRelay(testRelayHost)}
	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("phase = %q, want Active", got.Status.Phase)
	}
	if !slices.Contains(got.Status.AllowedDestinations, "10.244.1.0/24") {
		t.Fatalf("readable sources missing from %v", got.Status.AllowedDestinations)
	}
}

// ---------------------------------------------------------------------------
// gateway client scoping
// ---------------------------------------------------------------------------

func TestAllowedDestinations_SkipsGatewayThatExcludesTheIngressPeer(t *testing.T) {
	// The agent refuses to install a gateway route on a node outside a
	// non-empty clientRefs, so advertising it would blackhole the client.
	gateway := newGateway("ncp", "172.20.0.0/16")
	gateway.Spec.PeerRefs = []string{"gateway-node"}
	gateway.Spec.ClientRefs = []string{"some-other-node"}

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(), gateway)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName)
	if got.Status.IngressPeerName != testIngressPeer {
		t.Fatalf("ingressPeerName = %q, want %q", got.Status.IngressPeerName, testIngressPeer)
	}
	if slices.Contains(got.Status.AllowedDestinations, "172.20.0.0/16") {
		t.Fatalf("route advertised despite ingress peer being outside clientRefs: %v", got.Status.AllowedDestinations)
	}
}

func TestAllowedDestinations_KeepsGatewayThatListsTheIngressPeer(t *testing.T) {
	gateway := newGateway("ncp", "172.20.0.0/16")
	gateway.Spec.ClientRefs = []string{"some-other-node", testIngressPeer}

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(), gateway)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Contains(got, "172.20.0.0/16") {
		t.Fatalf("route missing though ingress peer is a gateway client: %v", got)
	}
}

// TestAllowedDestinations_KeepsGatewayForItsElectedPeer covers the shape real
// clusters use: clientRefs lists every node except the gateway itself, because
// the elected gateway peer carries the routes natively rather than as a client.
// An external peer entering through that node must not lose the route.
func TestAllowedDestinations_KeepsGatewayForItsElectedPeer(t *testing.T) {
	gateway := newGateway("ncp", "172.20.0.0/16")
	gateway.Spec.PeerRefs = []string{testIngressPeer}
	gateway.Spec.ClientRefs = []string{"worker1", "worker2"}
	gateway.Status.ActivePeer = testIngressPeer

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(), gateway)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if !slices.Contains(got, "172.20.0.0/16") {
		t.Fatalf("route dropped for the gateway's own peer: %v", got)
	}
}

// TestAllowedDestinations_SkipsGatewayStandbyPeer is the counterpart: only the
// elected peer has the routes injected, so a standby named in peerRefs but
// excluded by clientRefs would blackhole until it happens to be elected.
func TestAllowedDestinations_SkipsGatewayStandbyPeer(t *testing.T) {
	gateway := newGateway("ncp", "172.20.0.0/16")
	gateway.Spec.PeerRefs = []string{"gateway-primary", testIngressPeer}
	gateway.Spec.ClientRefs = []string{"worker1", "worker2"}
	gateway.Status.ActivePeer = "gateway-primary"

	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(), gateway)
	r := &Reconciler{Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost)}

	reconcileTwice(t, r, testExternalName)

	got := getCR(t, c, testExternalName).Status.AllowedDestinations
	if slices.Contains(got, "172.20.0.0/16") {
		t.Fatalf("route advertised through an unelected standby: %v", got)
	}
}

// TestAllowedDestinations_DegradedReadRequeues pins that a preserved list is
// retried: a failed read raises no watch event of its own, so without a
// requeue the peer would hold the stale list indefinitely.
func TestAllowedDestinations_DegradedReadRequeues(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	scheme := testScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cr, newReadyMesh(), newIngressPeer(), newNode("node-a", "10.244.1.0/24")).
		WithStatusSubresource(
			&wirekubev1alpha1.WireKubeExternalPeer{},
			&wirekubev1alpha1.WireKubeMesh{},
			&wirekubev1alpha1.WireKubePeer{},
		).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*wirekubev1alpha1.WireKubeGatewayList); ok {
					return apierrors.NewServiceUnavailable("synthetic outage")
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &Reconciler{Client: c, Scheme: scheme, Relay: newMockRelay(testRelayHost)}
	res := reconcileTwice(t, r, testExternalName)

	if res.RequeueAfter == 0 {
		t.Fatal("degraded reconcile returned no requeue; the stale list would never be retried")
	}
}

// TestAllowedDestinations_HealthyReadDoesNotRequeue keeps the retry scoped to
// actual failures rather than becoming an unconditional poll.
func TestAllowedDestinations_HealthyReadDoesNotRequeue(t *testing.T) {
	cr := newExternalPeer(testExternalName)
	c := newFakeClient(t, cr, newReadyMesh(), newIngressPeer(), newNode("node-a", "10.244.1.0/24"))
	r := &Reconciler{
		Client: c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost),
		APIReader: &serviceCIDRReader{
			Reader:     c,
			apiVersion: "networking.k8s.io/v1",
			items: []unstructured.Unstructured{
				newServiceCIDRObject("networking.k8s.io/v1", "kubernetes", boolPtr(true), "10.96.0.0/12"),
			},
		},
	}

	if res := reconcileTwice(t, r, testExternalName); res.RequeueAfter != 0 {
		t.Fatalf("healthy reconcile requeued after %s", res.RequeueAfter)
	}
}
