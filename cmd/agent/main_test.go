package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func TestRelayControlAddrFromMeshPrefersControlEndpoint(t *testing.T) {
	mesh := &wirekubev1alpha1.WireKubeMesh{
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			Relay: &wirekubev1alpha1.RelaySpec{
				External: &wirekubev1alpha1.ExternalRelaySpec{
					Endpoint:        "relay.example.com:3478",
					ControlEndpoint: "wirekube-relay-control.wirekube-system.svc.cluster.local:3478",
				},
			},
		},
	}

	got := relayControlAddrFromMesh(mesh, "wirekube-system")
	want := "wirekube-relay-control.wirekube-system.svc.cluster.local:3478"
	if got != want {
		t.Fatalf("relayControlAddrFromMesh = %q, want %q", got, want)
	}
}

func TestRelayControlAddrFromMeshDoesNotUsePublicEndpoint(t *testing.T) {
	mesh := &wirekubev1alpha1.WireKubeMesh{
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			Relay: &wirekubev1alpha1.RelaySpec{
				External: &wirekubev1alpha1.ExternalRelaySpec{
					Endpoint: "relay.example.com:3478",
				},
			},
		},
	}

	got := relayControlAddrFromMesh(mesh, "wirekube-system")
	if got != "" {
		t.Fatalf("relayControlAddrFromMesh = %q, want empty", got)
	}
}

func TestRelayEndpointFromMeshExternalKeepsPort(t *testing.T) {
	mesh := &wirekubev1alpha1.WireKubeMesh{
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			Relay: &wirekubev1alpha1.RelaySpec{
				External: &wirekubev1alpha1.ExternalRelaySpec{
					Endpoint: "relay.example.com:3478",
				},
			},
		},
	}

	got := relayEndpointFromMesh(context.Background(), nil, mesh, "wirekube-system")
	want := "relay.example.com:3478"
	if got != want {
		t.Fatalf("relayEndpointFromMesh = %q, want %q", got, want)
	}
}

func TestRelayControlAddrFromMeshManagedDoesNotEnableControlByDefault(t *testing.T) {
	mesh := &wirekubev1alpha1.WireKubeMesh{
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			Relay: &wirekubev1alpha1.RelaySpec{
				Managed: &wirekubev1alpha1.ManagedRelaySpec{Port: 3478},
			},
		},
	}

	got := relayControlAddrFromMesh(mesh, "wirekube-system")
	if got != "" {
		t.Fatalf("relayControlAddrFromMesh = %q, want empty", got)
	}
}

func TestRelayEndpointFromMeshManagedDoesNotUseTCPServiceAsUDPEndpoint(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wirekube-relay",
				Namespace: "wirekube-system",
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: []corev1.LoadBalancerIngress{{Hostname: "relay.example.com"}},
				},
			},
		}).
		Build()
	mesh := &wirekubev1alpha1.WireKubeMesh{
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			Relay: &wirekubev1alpha1.RelaySpec{
				Managed: &wirekubev1alpha1.ManagedRelaySpec{Port: 3478},
			},
		},
	}

	if got := relayEndpointFromMesh(context.Background(), c, mesh, "wirekube-system"); got != "" {
		t.Fatalf("relayEndpointFromMesh = %q, want empty without a UDP Service", got)
	}
}

func TestRelayEndpointFromMeshManagedPrefersSeparateUDPService(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Namespace: "wirekube-system"},
				Status:     corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{Hostname: "tcp-relay.example.com"}}}},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay-udp", Namespace: "wirekube-system"},
				Status:     corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{Hostname: "udp-relay.example.com"}}}},
			},
		).
		Build()
	mesh := &wirekubev1alpha1.WireKubeMesh{Spec: wirekubev1alpha1.WireKubeMeshSpec{Relay: &wirekubev1alpha1.RelaySpec{Managed: &wirekubev1alpha1.ManagedRelaySpec{Port: 3478}}}}

	got := relayEndpointFromMesh(context.Background(), c, mesh, "wirekube-system")
	if got != "udp-relay.example.com:3478" {
		t.Fatalf("relayEndpointFromMesh = %q", got)
	}
}

func TestRelayEndpointFromMeshManagedWaitsForSeparateUDPService(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Namespace: "wirekube-system"},
				Status:     corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{{Hostname: "tcp-relay.example.com"}}}},
			},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay-udp", Namespace: "wirekube-system"}},
		).
		Build()
	mesh := &wirekubev1alpha1.WireKubeMesh{Spec: wirekubev1alpha1.WireKubeMeshSpec{Relay: &wirekubev1alpha1.RelaySpec{Managed: &wirekubev1alpha1.ManagedRelaySpec{Port: 3478}}}}

	if got := relayEndpointFromMesh(context.Background(), c, mesh, "wirekube-system"); got != "" {
		t.Fatalf("relayEndpointFromMesh = %q, want empty while UDP LoadBalancer is pending", got)
	}
}
