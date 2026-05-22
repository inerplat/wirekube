package agent

import "testing"

func TestManagedRelayControlEndpoint(t *testing.T) {
	got := managedRelayControlEndpoint("wirekube-system", 3478)
	want := "wirekube-relay-control.wirekube-system.svc.cluster.local:3478"
	if got != want {
		t.Fatalf("managedRelayControlEndpoint = %q, want %q", got, want)
	}
}

func TestManagedRelayControlEndpointDefaultNamespace(t *testing.T) {
	got := managedRelayControlEndpoint("", 3478)
	want := "wirekube-relay-control.wirekube-system.svc.cluster.local:3478"
	if got != want {
		t.Fatalf("managedRelayControlEndpoint = %q, want %q", got, want)
	}
}
