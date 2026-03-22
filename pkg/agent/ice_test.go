package agent

import (
	"net"
	"testing"

	"github.com/wirekube/wirekube/pkg/agent/nat"
)

func TestIsPortRestrictedSymmetricPair(t *testing.T) {
	prc := string(nat.NATPortRestrictedCone)
	sym := string(nat.NATSymmetric)

	tests := []struct {
		name     string
		myNAT    string
		peerNAT  string
		expected bool
	}{
		{"prc↔sym", prc, sym, true},
		{"sym↔prc", sym, prc, true},
		{"cone↔sym", "cone", sym, false},
		{"sym↔cone", sym, "cone", false},
		{"cone↔cone", "cone", "cone", false},
		{"sym↔sym", sym, sym, false},
		{"prc↔prc", prc, prc, false},
		{"prc↔cone", prc, "cone", false},
		{"empty↔sym", "", sym, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPortRestrictedSymmetricPair(tt.myNAT, tt.peerNAT)
			if got != tt.expected {
				t.Errorf("isPortRestrictedSymmetricPair(%q, %q) = %v, want %v",
					tt.myNAT, tt.peerNAT, got, tt.expected)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		endpoint string
		expected string
	}{
		{"1.2.3.4:51820", "1.2.3.4"},
		{"[::1]:51820", "::1"},
		{"", ""},
		{"no-port", ""},
		{"192.168.1.1:0", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			got := extractIP(tt.endpoint)
			if got != tt.expected {
				t.Errorf("extractIP(%q) = %q, want %q", tt.endpoint, got, tt.expected)
			}
		})
	}
}

func TestIsLocalhostEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		expected bool
	}{
		{"127.0.0.1:51820", true},
		{"127.0.0.2:1234", true},
		{"[::1]:51820", true},
		{"192.168.1.1:51820", false},
		{"10.0.0.1:51820", false},
		{"", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			got := isLocalhostEndpoint(tt.endpoint)
			if got != tt.expected {
				t.Errorf("isLocalhostEndpoint(%q) = %v, want %v", tt.endpoint, got, tt.expected)
			}
		})
	}
}

func TestIsVirtualInterface(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"docker0", true},
		{"veth1234", true},
		{"cilium_host", true},
		{"cni0", true},
		{"flannel.1", true},
		{"br-abc", true},
		{"wg0", true},
		{"wire_kube", true},
		{"eth0", false},
		{"ens5", false},
		{"enp0s3", false},
		{"bond0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVirtualInterface(tt.name)
			if got != tt.expected {
				t.Errorf("isVirtualInterface(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestFirstNonLoopbackIPv4(t *testing.T) {
	ip := firstNonLoopbackIPv4()
	// In any test environment, there should be at least one non-loopback interface
	if ip == "" {
		t.Skip("no non-loopback IPv4 address found (CI without network)")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("returned IP %q is not parseable", ip)
	}
	if parsed.IsLoopback() {
		t.Errorf("returned IP %q is loopback", ip)
	}
	if parsed.To4() == nil {
		t.Errorf("returned IP %q is not IPv4", ip)
	}
}

func TestPortPrediction_GenerateCandidates(t *testing.T) {
	tests := []struct {
		name string
		pp   nat.PortPrediction
		n    int
		minN int // minimum expected candidates
	}{
		{
			name: "sequential increment",
			pp:   nat.PortPrediction{BasePort: 10000, Increment: 2, Jitter: 1, SamplePorts: []int{9996, 9998, 10000}},
			n:    10,
			minN: 10,
		},
		{
			name: "random allocation",
			pp:   nat.PortPrediction{BasePort: 40000, Increment: 0, Jitter: 100, SamplePorts: []int{39900, 40100}},
			n:    256,
			minN: 256,
		},
		{
			name: "zero count",
			pp:   nat.PortPrediction{BasePort: 10000, Increment: 1},
			n:    0,
			minN: 0,
		},
		{
			name: "negative count",
			pp:   nat.PortPrediction{BasePort: 10000, Increment: 1},
			n:    -1,
			minN: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pp.GenerateCandidates(tt.n)
			if len(got) < tt.minN {
				t.Errorf("GenerateCandidates(%d) returned %d ports, want at least %d",
					tt.n, len(got), tt.minN)
			}
			for _, p := range got {
				if p <= 0 || p >= 65536 {
					t.Errorf("invalid port: %d", p)
				}
			}
		})
	}
}

func TestProbeToken_Deterministic(t *testing.T) {
	keyA := [32]byte{1}
	keyB := [32]byte{2}

	token1 := nat.ProbeToken(keyA, keyB)
	token2 := nat.ProbeToken(keyA, keyB)
	if token1 != token2 {
		t.Error("ProbeToken should be deterministic")
	}

	// Order should not matter
	token3 := nat.ProbeToken(keyB, keyA)
	if token1 != token3 {
		t.Error("ProbeToken should be commutative")
	}
}

func TestProbeToken_DifferentKeys(t *testing.T) {
	keyA := [32]byte{1}
	keyB := [32]byte{2}
	keyC := [32]byte{3}

	tokenAB := nat.ProbeToken(keyA, keyB)
	tokenAC := nat.ProbeToken(keyA, keyC)
	if tokenAB == tokenAC {
		t.Error("different key pairs should (almost certainly) produce different tokens")
	}
}
