package relayendpoint

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

const testNamespace = "wirekube-system"

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(scheme))
	return scheme
}

func managedMesh(statusEndpoint string) *wirekubev1alpha1.WireKubeMesh {
	return &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			Relay: &wirekubev1alpha1.RelaySpec{
				Mode:     "auto",
				Provider: "managed",
				Managed:  &wirekubev1alpha1.ManagedRelaySpec{Replicas: 1},
			},
		},
		Status: wirekubev1alpha1.WireKubeMeshStatus{RelayEndpoint: statusEndpoint},
	}
}

func relayService(ingress ...corev1.LoadBalancerIngress) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: relayServiceName, Namespace: testNamespace},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{Ingress: ingress},
		},
	}
}

func reconcileMesh(t *testing.T, mesh *wirekubev1alpha1.WireKubeMesh, svc *corev1.Service) *wirekubev1alpha1.WireKubeMesh {
	t.Helper()
	builder := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeMesh{}).
		WithObjects(mesh)
	if svc != nil {
		builder = builder.WithObjects(svc)
	}
	c := builder.Build()

	r := &Reconciler{Client: c, RelayNamespace: testNamespace}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: mesh.Name}}); err != nil {
		t.Fatal(err)
	}

	got := &wirekubev1alpha1.WireKubeMesh{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: mesh.Name}, got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReconcileSyncsIngressHostname(t *testing.T) {
	got := reconcileMesh(t, managedMesh(""), relayService(corev1.LoadBalancerIngress{Hostname: "lb.example.com", IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "lb.example.com:3478" {
		t.Fatalf("status.relayEndpoint=%q, want lb.example.com:3478 (hostname preferred over IP)", got.Status.RelayEndpoint)
	}
}

func TestReconcileSyncsIngressIP(t *testing.T) {
	got := reconcileMesh(t, managedMesh(""), relayService(corev1.LoadBalancerIngress{IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "203.0.113.10:3478" {
		t.Fatalf("status.relayEndpoint=%q, want 203.0.113.10:3478", got.Status.RelayEndpoint)
	}
}

func TestReconcileHonoursManagedPort(t *testing.T) {
	mesh := managedMesh("")
	mesh.Spec.Relay.Managed.Port = 3479
	got := reconcileMesh(t, mesh, relayService(corev1.LoadBalancerIngress{IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "203.0.113.10:3479" {
		t.Fatalf("status.relayEndpoint=%q, want 203.0.113.10:3479", got.Status.RelayEndpoint)
	}
}

func TestReconcileKeepsLastKnownGoodWithoutIngress(t *testing.T) {
	// LoadBalancer recreation window: the ingress list is briefly empty and
	// the previously synced endpoint must NOT be cleared — agents keep the
	// last-known-good address.
	got := reconcileMesh(t, managedMesh("203.0.113.10:3478"), relayService())
	if got.Status.RelayEndpoint != "203.0.113.10:3478" {
		t.Fatalf("status.relayEndpoint=%q, want unchanged 203.0.113.10:3478", got.Status.RelayEndpoint)
	}
}

func TestReconcileUpdatesChangedEndpoint(t *testing.T) {
	got := reconcileMesh(t, managedMesh("198.51.100.7:3478"), relayService(corev1.LoadBalancerIngress{IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "203.0.113.10:3478" {
		t.Fatalf("status.relayEndpoint=%q, want updated 203.0.113.10:3478", got.Status.RelayEndpoint)
	}
}

func TestReconcileNoOpForExternalProvider(t *testing.T) {
	mesh := managedMesh("")
	mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{
		Mode:     "auto",
		Provider: "external",
		External: &wirekubev1alpha1.ExternalRelaySpec{Endpoint: "relay.example.com:3478"},
	}
	got := reconcileMesh(t, mesh, relayService(corev1.LoadBalancerIngress{IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "" {
		t.Fatalf("status.relayEndpoint=%q, want empty for external provider", got.Status.RelayEndpoint)
	}
}

func TestReconcileNoOpForNodePortServiceType(t *testing.T) {
	mesh := managedMesh("")
	mesh.Spec.Relay.Managed.ServiceType = string(corev1.ServiceTypeNodePort)
	got := reconcileMesh(t, mesh, relayService(corev1.LoadBalancerIngress{IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "" {
		t.Fatalf("status.relayEndpoint=%q, want empty for NodePort", got.Status.RelayEndpoint)
	}
}

func TestReconcileNoOpForWSSTransport(t *testing.T) {
	mesh := managedMesh("")
	mesh.Spec.Relay.Managed.Transport = "wss"
	mesh.Spec.Relay.Managed.ControlEndpoint = "wss://relay.example.com/relay"
	got := reconcileMesh(t, mesh, relayService(corev1.LoadBalancerIngress{IP: "203.0.113.10"}))
	if got.Status.RelayEndpoint != "" {
		t.Fatalf("status.relayEndpoint=%q, want empty for wss transport", got.Status.RelayEndpoint)
	}
}

func TestReconcileNoOpWhenServiceMissing(t *testing.T) {
	got := reconcileMesh(t, managedMesh("203.0.113.10:3478"), nil)
	if got.Status.RelayEndpoint != "203.0.113.10:3478" {
		t.Fatalf("status.relayEndpoint=%q, want unchanged when the Service is missing", got.Status.RelayEndpoint)
	}
}
