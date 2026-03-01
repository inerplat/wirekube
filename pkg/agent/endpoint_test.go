package agent

import (
	"context"
	"net"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeNode(annotations map[string]string, addresses []corev1.NodeAddress) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-node",
			Annotations: annotations,
		},
		Status: corev1.NodeStatus{
			Addresses: addresses,
		},
	}
}

// requireNoNetwork skips the test if the environment allows outbound network
// (i.e., STUN or UPnP might succeed, making fallback tests non-deterministic).
// Set WIREKUBE_NETWORK_TESTS=1 to run these as integration tests.
func requireNetworkTestsDisabled(t *testing.T) {
	t.Helper()
	if os.Getenv("WIREKUBE_NETWORK_TESTS") == "1" {
		t.Skip("skipping: WIREKUBE_NETWORK_TESTS=1 enables network-dependent tests separately")
	}
}

// ─── Pure-logic tests (no network) ────────────────────────────────────────────

func TestDiscoverEndpoint_ManualAnnotation(t *testing.T) {
	node := makeNode(
		map[string]string{AnnotationEndpoint: "1.2.3.4:51820"},
		nil,
	)

	res, err := DiscoverEndpoint(context.Background(), node, 51820, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Endpoint != "1.2.3.4:51820" {
		t.Errorf("Endpoint = %q, want %q", res.Endpoint, "1.2.3.4:51820")
	}
	if res.Method != MethodManual {
		t.Errorf("Method = %q, want %q", res.Method, MethodManual)
	}
}

func TestDiscoverEndpoint_ManualOverrides_All(t *testing.T) {
	// Annotation takes precedence over all other methods (no network calls)
	node := makeNode(
		map[string]string{AnnotationEndpoint: "9.9.9.9:12345"},
		[]corev1.NodeAddress{
			{Type: corev1.NodeExternalIP, Address: "1.1.1.1"},
			{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
		},
	)

	res, err := DiscoverEndpoint(context.Background(), node, 51820, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Endpoint != "9.9.9.9:12345" {
		t.Errorf("Endpoint = %q, want %q", res.Endpoint, "9.9.9.9:12345")
	}
	if res.Method != MethodManual {
		t.Errorf("Method = %q, want %q", res.Method, MethodManual)
	}
}

func TestIsPublicIPv6(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"::1", false},      // loopback
		{"fe80::1", false},  // link-local
		{"fc00::1", false},  // unique local (private)
		{"fd00::1", false},  // unique local (private)
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.addr)
		if ip == nil {
			t.Fatalf("ParseIP(%q) returned nil", tc.addr)
		}
		got := isPublicIPv6(ip)
		if got != tc.want {
			t.Errorf("isPublicIPv6(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// ─── Integration tests (require network to be blocked) ────────────────────────
// Run with: WIREKUBE_NETWORK_TESTS=skip go test ./pkg/agent/ -run Integration
// (or ensure outbound STUN/UPnP is blocked in CI)

func TestIntegration_DiscoverEndpoint_ExternalIP_Fallback(t *testing.T) {
	if os.Getenv("WIREKUBE_NETWORK_TESTS") != "skip" {
		t.Skip("skipping fallback test: STUN/UPnP may succeed on this network; " +
			"set WIREKUBE_NETWORK_TESTS=skip and block outbound UDP to run")
	}

	node := makeNode(nil, []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.5"},
		{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
	})

	res, err := DiscoverEndpoint(context.Background(), node, 51820, []string{"stun:127.0.0.1:65534"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Endpoint != "5.6.7.8:51820" {
		t.Errorf("Endpoint = %q, want %q", res.Endpoint, "5.6.7.8:51820")
	}
}

func TestIntegration_DiscoverEndpoint_InternalIP_LastResort(t *testing.T) {
	if os.Getenv("WIREKUBE_NETWORK_TESTS") != "skip" {
		t.Skip("skipping fallback test: STUN/UPnP may succeed on this network; " +
			"set WIREKUBE_NETWORK_TESTS=skip and block outbound UDP to run")
	}

	node := makeNode(nil, []corev1.NodeAddress{
		{Type: corev1.NodeInternalIP, Address: "10.0.0.5"},
	})

	res, err := DiscoverEndpoint(context.Background(), node, 51820, []string{"stun:127.0.0.1:65534"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Endpoint != "10.0.0.5:51820" {
		t.Errorf("Endpoint = %q, want %q", res.Endpoint, "10.0.0.5:51820")
	}
	if res.Method != MethodInternalIP {
		t.Errorf("Method = %q, want %q", res.Method, MethodInternalIP)
	}
}

func TestIntegration_DiscoverEndpoint_NoAddresses(t *testing.T) {
	if os.Getenv("WIREKUBE_NETWORK_TESTS") != "skip" {
		t.Skip("skipping: depends on STUN/UPnP failing")
	}

	node := makeNode(nil, nil)

	_, err := DiscoverEndpoint(context.Background(), node, 51820, []string{"stun:127.0.0.1:65534"})
	if err == nil {
		t.Error("expected error when no addresses available, got nil")
	}
}
