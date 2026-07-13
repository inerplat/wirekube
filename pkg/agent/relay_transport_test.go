package agent

import (
	"testing"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func TestExternalRelayDialConfigDefaultsToTCP(t *testing.T) {
	config, err := externalRelayDialConfig(&wirekubev1alpha1.ExternalRelaySpec{
		Endpoint:        "relay.example.com:3478",
		ControlEndpoint: "relay-control.example.com:443",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "tcp" || config.endpoint != "relay-control.example.com:443" || config.probeAddr != "relay.example.com:3478" || config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestExternalRelayDialConfigSelectsWSSFromMesh(t *testing.T) {
	config, err := externalRelayDialConfig(&wirekubev1alpha1.ExternalRelaySpec{
		Endpoint:        "203.0.113.10:3478",
		ControlEndpoint: "wss://relay.example.com/relay",
		Transport:       "wss",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "wss" || config.endpoint != "wss://relay.example.com/relay" || config.probeAddr != "203.0.113.10:3478" || !config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestExternalRelayDialConfigAllowsWSSWithoutRawUDPEndpoint(t *testing.T) {
	config, err := externalRelayDialConfig(&wirekubev1alpha1.ExternalRelaySpec{
		ControlEndpoint: "wss://relay.example.com/relay",
		Transport:       "wss",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "wss" || config.endpoint != "wss://relay.example.com/relay" || config.probeAddr != "" || !config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestExternalRelayDialConfigAllowsTCPControlWithoutRawUDPEndpoint(t *testing.T) {
	config, err := externalRelayDialConfig(&wirekubev1alpha1.ExternalRelaySpec{ControlEndpoint: "relay.example.com:3478"})
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "tcp" || config.endpoint != "relay.example.com:3478" || config.probeAddr != "" || config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestManagedRelayDialConfigSelectsWSSFromMesh(t *testing.T) {
	config, err := managedRelayDialConfig(&wirekubev1alpha1.ManagedRelaySpec{ControlEndpoint: "wss://relay.example.com/relay", Transport: "wss"}, "wirekube-system")
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "wss" || config.endpoint != "wss://relay.example.com/relay" || config.probeAddr != "" || !config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestManagedRelayDialConfigDefaultsToClusterLocalTCP(t *testing.T) {
	config, err := managedRelayDialConfig(&wirekubev1alpha1.ManagedRelaySpec{Port: 3479}, "wirekube-system")
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "tcp" || config.endpoint != "wirekube-relay-control.wirekube-system.svc.cluster.local:3479" || config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestExternalRelayDialConfigRejectsTransportEndpointMismatch(t *testing.T) {
	tests := []wirekubev1alpha1.ExternalRelaySpec{
		{Endpoint: "203.0.113.10:3478", ControlEndpoint: "wss://relay.example.com/relay", Transport: "tcp"},
		{Endpoint: "203.0.113.10:3478", ControlEndpoint: "https://relay.example.com/relay", Transport: "tcp"},
		{Endpoint: "203.0.113.10:3478", ControlEndpoint: "ws://relay.example.com/relay", Transport: "wss"},
		{Endpoint: "203.0.113.10:3478", Transport: "wss"},
	}
	for _, external := range tests {
		if _, err := externalRelayDialConfig(&external); err == nil {
			t.Fatalf("expected config to fail: %+v", external)
		}
	}
}
