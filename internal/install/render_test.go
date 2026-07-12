package install

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

const testImage = "registry.example.test/wirekube@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestOptionsRequireExplicitRelayForNonInteractiveInstall(t *testing.T) {
	options := Options{Image: testImage, Yes: true}
	if err := options.Normalize(); err == nil || !strings.Contains(err.Error(), "--relay must be specified") {
		t.Fatalf("error=%v", err)
	}
}

func TestOptionsRequireImageDigest(t *testing.T) {
	options := Options{Image: "registry.example.test/wirekube:v1", Relay: RelayNone}
	if err := options.Normalize(); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Fatalf("error=%v", err)
	}
}

func TestOptionsRejectNonNumericRelayEndpointPort(t *testing.T) {
	options := Options{Image: testImage, Relay: RelayExternal, RelayEndpoint: "relay.example.test:https"}
	if err := options.Normalize(); err == nil || !strings.Contains(err.Error(), "port must be between 1 and 65535") {
		t.Fatalf("error=%v", err)
	}
}

func TestRenderUsesPortableDefaultsAndSeparateRelayServices(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Manifest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	for _, forbidden := range []string{"eks.amazonaws.com/nodegroup", "admin-web", ":v0.0."} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("manifest contains %q", forbidden)
		}
	}
	if !strings.Contains(text, testImage) {
		t.Fatal("manifest does not contain the pinned image")
	}
	services := map[string][]corev1.ServicePort{}
	for _, object := range bundle.Objects {
		if service, ok := object.(*corev1.Service); ok {
			services[service.Name] = service.Spec.Ports
		}
	}
	if len(services["wirekube-relay"]) != 1 || services["wirekube-relay"][0].Protocol != corev1.ProtocolTCP {
		t.Fatalf("TCP relay service=%v", services["wirekube-relay"])
	}
	if len(services["wirekube-relay-udp"]) != 1 || services["wirekube-relay-udp"][0].Protocol != corev1.ProtocolUDP {
		t.Fatalf("UDP relay service=%v", services["wirekube-relay-udp"])
	}
}

func TestNodePortUDPUsesSeparateDataAndControlEndpoints(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNodePort, RelayEndpoint: "[2001:db8::10]:30478", RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	for _, object := range bundle.Objects {
		if typed, ok := object.(*wirekubev1alpha1.WireKubeMesh); ok {
			mesh = typed
			break
		}
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if mesh.Spec.Relay.External.ControlEndpoint != "[2001:db8::10]:30478" {
		t.Fatalf("controlEndpoint=%q", mesh.Spec.Relay.External.ControlEndpoint)
	}
	if mesh.Spec.Relay.External.Endpoint != "[2001:db8::10]:30479" {
		t.Fatalf("endpoint=%q", mesh.Spec.Relay.External.Endpoint)
	}
}

func TestNodePortTCPOnlyDoesNotAdvertiseRawWireGuardEndpoint(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNodePort, RelayEndpoint: "203.0.113.10:30478", MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	for _, object := range bundle.Objects {
		if typed, ok := object.(*wirekubev1alpha1.WireKubeMesh); ok {
			mesh = typed
			break
		}
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if got := mesh.Spec.Relay.External.ControlEndpoint; got != "203.0.113.10:30478" {
		t.Fatalf("controlEndpoint=%q", got)
	}
	if got := mesh.Spec.Relay.External.Endpoint; got != "" {
		t.Fatalf("endpoint=%q, want empty without UDP", got)
	}
}

func TestExternalRelaySeparatesControlAndUDPEndpoints(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayExternal, RelayEndpoint: "relay.example.test:443", RelayUDPEndpoint: "wg.example.test:51820", MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	for _, object := range bundle.Objects {
		if typed, ok := object.(*wirekubev1alpha1.WireKubeMesh); ok {
			mesh = typed
			break
		}
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if got := mesh.Spec.Relay.External.ControlEndpoint; got != "relay.example.test:443" {
		t.Fatalf("controlEndpoint=%q", got)
	}
	if got := mesh.Spec.Relay.External.Endpoint; got != "wg.example.test:51820" {
		t.Fatalf("endpoint=%q", got)
	}
}

func TestDefaultAgentRBACDoesNotGrantAdministrativeCreate(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var role *rbacv1.ClusterRole
	for _, object := range bundle.Objects {
		if typed, ok := object.(*rbacv1.ClusterRole); ok && typed.Name == "wirekube-agent" {
			role = typed
			break
		}
	}
	if role == nil {
		t.Fatal("agent ClusterRole was not rendered")
	}
	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource != "wirekubemeshes" && resource != "wirekubegateways" && resource != "wirekubeexternalpeers" {
				continue
			}
			for _, verb := range rule.Verbs {
				if verb == "create" {
					t.Fatalf("default agent role grants create on %s: %v", resource, rule.Verbs)
				}
			}
		}
	}
}

func TestPlannerAvoidsOccupiedCIDRsWithoutMutation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}, Spec: corev1.NodeSpec{PodCIDR: "100.96.0.0/11", PodCIDRs: []string{"100.96.0.0/11"}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.1", ClusterIPs: []string{"10.96.0.1"}}},
	).Build()
	plan, normalized, err := (Planner{Client: client}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "auto", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.MeshCIDR == "100.96.0.0/11" || plan.MeshCIDR == "100.96.0.0/11" {
		t.Fatalf("selected occupied CIDR: %s", normalized.MeshCIDR)
	}
	var namespaces corev1.NamespaceList
	if err := client.List(context.Background(), &namespaces); err != nil {
		t.Fatal(err)
	}
	if len(namespaces.Items) != 0 {
		t.Fatalf("planning mutated the cluster: %v", namespaces.Items)
	}
}

func TestPlannerRequiresExplicitMeshCIDRForNonInteractiveInstall(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	_, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "auto", Yes: true, WireKubeVersion: "v1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "--mesh-cidr must be explicit") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlannerAllowsAutoMeshCIDRForNonMutatingDryRunWithWarning(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	plan, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "auto", Yes: true, DryRun: true, WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "best effort") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings=%v", plan.Warnings)
	}
}

func TestPlannerRejectsExplicitMeshCIDROverlap(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}, Spec: corev1.NodeSpec{PodCIDR: "198.18.0.0/24", PodCIDRs: []string{"198.18.0.0/24"}}},
	).Build()

	_, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "198.18.0.0/16", WireKubeVersion: "v1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "overlaps observed cluster or local network") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlannerWarnsAboutPublicLoadBalancerCost(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	plan, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayLoadBalancer, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Warnings) == 0 || !strings.Contains(plan.Warnings[0], "provider charges") {
		t.Fatalf("warnings=%v", plan.Warnings)
	}
}

func TestPlannerFailsWhenAccessPreflightIsDenied(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reviewer := &testAccessReviewer{err: fmt.Errorf("insufficient Kubernetes permissions: patch deployments.apps")}
	_, _, err := (Planner{Client: c, AccessReviewer: reviewer}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "insufficient Kubernetes permissions") {
		t.Fatalf("error=%v", err)
	}
	if !reviewer.called {
		t.Fatal("access reviewer was not called")
	}
}

type testAccessReviewer struct {
	called bool
	err    error
}

func (r *testAccessReviewer) Review(_ context.Context, requirements []AccessRequirement) error {
	r.called = true
	if len(requirements) == 0 {
		return fmt.Errorf("no access requirements were provided")
	}
	return r.err
}
