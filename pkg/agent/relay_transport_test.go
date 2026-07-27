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
	config, err := managedRelayDialConfig(&wirekubev1alpha1.ManagedRelaySpec{ControlEndpoint: "wss://relay.example.com/relay", Transport: "wss"}, "", "wirekube-system")
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "wss" || config.endpoint != "wss://relay.example.com/relay" || config.probeAddr != "" || !config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestManagedRelayDialConfigDefaultsToClusterLocalTCP(t *testing.T) {
	config, err := managedRelayDialConfig(&wirekubev1alpha1.ManagedRelaySpec{Port: 3479}, "", "wirekube-system")
	if err != nil {
		t.Fatal(err)
	}
	if config.transport != "tcp" || config.endpoint != "wirekube-relay-control.wirekube-system.svc.cluster.local:3479" || config.tokenRequired {
		t.Fatalf("unexpected config: %+v", config)
	}
}

// TestManagedRelayDialConfigTCPEndpointPriority pins the managed TCP dial
// priority: spec.controlEndpoint > status.relayEndpoint > cluster-local
// control Service DNS name. WebSocket URLs are rejected under tcp transport,
// mirroring the external provider's validation.
func TestManagedRelayDialConfigTCPEndpointPriority(t *testing.T) {
	tests := []struct {
		name           string
		managed        *wirekubev1alpha1.ManagedRelaySpec
		statusEndpoint string
		wantEndpoint   string
		wantErr        bool
	}{
		{
			name:           "spec controlEndpoint wins over status",
			managed:        &wirekubev1alpha1.ManagedRelaySpec{ControlEndpoint: "relay.example.com:3478"},
			statusEndpoint: "203.0.113.10:3478",
			wantEndpoint:   "relay.example.com:3478",
		},
		{
			name:           "status relayEndpoint used when spec is empty",
			managed:        &wirekubev1alpha1.ManagedRelaySpec{},
			statusEndpoint: "203.0.113.10:3478",
			wantEndpoint:   "203.0.113.10:3478",
		},
		{
			name:         "cluster-local Service DNS fallback when both are empty",
			managed:      &wirekubev1alpha1.ManagedRelaySpec{},
			wantEndpoint: "wirekube-relay-control.wirekube-system.svc.cluster.local:3478",
		},
		{
			name:           "nil managed spec still honours status",
			managed:        nil,
			statusEndpoint: "lb.example.com:3478",
			wantEndpoint:   "lb.example.com:3478",
		},
		{
			name:    "ws URL in spec rejected under tcp transport",
			managed: &wirekubev1alpha1.ManagedRelaySpec{ControlEndpoint: "ws://relay.example.com/relay"},
			wantErr: true,
		},
		{
			name:    "wss URL in spec rejected under tcp transport",
			managed: &wirekubev1alpha1.ManagedRelaySpec{ControlEndpoint: "wss://relay.example.com/relay", Transport: "tcp"},
			wantErr: true,
		},
		{
			name:           "status endpoint without a port rejected",
			managed:        &wirekubev1alpha1.ManagedRelaySpec{},
			statusEndpoint: "203.0.113.10",
			wantErr:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := managedRelayDialConfig(tt.managed, tt.statusEndpoint, "wirekube-system")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected config to fail, got %+v", config)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.transport != "tcp" || config.endpoint != tt.wantEndpoint || config.tokenRequired {
				t.Fatalf("unexpected config: %+v, want endpoint %q", config, tt.wantEndpoint)
			}
		})
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

func TestRelayRebuildDecision(t *testing.T) {
	cases := []struct {
		name          string
		poolExists    bool
		poolConnected bool
		current       string
		resolved      string
		want          bool
	}{
		{"connected pool is never disturbed", true, true, "a:3478", "b:3478", false},
		{"disconnected with unchanged endpoint stays put", true, false, "a:3478", "a:3478", false},
		{"disconnected with changed endpoint rebuilds", true, false, "a:3478", "b:3478", true},
		{"missing pool retries even when unchanged", false, false, "a:3478", "a:3478", true},
		{"missing pool retries on change", false, false, "a:3478", "b:3478", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayRebuildDecision(tc.poolExists, tc.poolConnected, tc.current, tc.resolved); got != tc.want {
				t.Fatalf("relayRebuildDecision(%t, %t, %q, %q) = %t, want %t",
					tc.poolExists, tc.poolConnected, tc.current, tc.resolved, got, tc.want)
			}
		})
	}
}
