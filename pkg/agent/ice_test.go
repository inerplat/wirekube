package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/wirekube/wirekube/pkg/agent/nat"
	agentrelay "github.com/wirekube/wirekube/pkg/agent/relay"
	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/wireguard"
)

type fakeWGEngine struct {
	lastDirect map[string]int64
	lastRelay  map[string]int64
	stats      []wireguard.PeerStats
	setPaths   []wireguard.PathMode
	poked      []string
}

func (f *fakeWGEngine) EnsureInterface() error                   { return nil }
func (f *fakeWGEngine) Configure() error                         { return nil }
func (f *fakeWGEngine) DeleteInterface() error                   { return nil }
func (f *fakeWGEngine) Close() error                             { return nil }
func (f *fakeWGEngine) InterfaceName() string                    { return "" }
func (f *fakeWGEngine) ListenPort() int                          { return 0 }
func (f *fakeWGEngine) InterfaceExists() bool                    { return true }
func (f *fakeWGEngine) ConfigMatchesKey(*wireguard.KeyPair) bool { return true }
func (f *fakeWGEngine) SyncPeers([]wireguard.PeerConfig) error   { return nil }
func (f *fakeWGEngine) ForceEndpoint(string, string) error       { return nil }
func (f *fakeWGEngine) PokeKeepalive(pubKey string) error {
	f.poked = append(f.poked, pubKey)
	return nil
}
func (f *fakeWGEngine) GetStats() ([]wireguard.PeerStats, error) { return f.stats, nil }
func (f *fakeWGEngine) SetAddress(string) error                  { return nil }
func (f *fakeWGEngine) SetPreferredSrc(string)                   {}
func (f *fakeWGEngine) SyncRoutes([]string) error                { return nil }
func (f *fakeWGEngine) AddRoute(string) error                    { return nil }
func (f *fakeWGEngine) DelRoute(string) error                    { return nil }
func (f *fakeWGEngine) SetPeerPath(_ string, mode wireguard.PathMode, _ string) error {
	f.setPaths = append(f.setPaths, mode)
	return nil
}
func (f *fakeWGEngine) SetRelayTransport(wireguard.RelayTransport) {}
func (f *fakeWGEngine) LastDirectReceive(pubKey string) int64      { return f.lastDirect[pubKey] }
func (f *fakeWGEngine) LastRelayReceive(pubKey string) int64       { return f.lastRelay[pubKey] }
func (f *fakeWGEngine) MarkBimodalHint([32]byte)                   {}

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

func TestPreferredTransportForPeer(t *testing.T) {
	a := &Agent{
		relayedPeers: map[string]bool{
			"relay-peer": true,
		},
	}

	if got := a.preferredTransportForPeer("relay-peer"); got != "relay" {
		t.Fatalf("preferredTransportForPeer(relay-peer) = %q, want relay", got)
	}
	if got := a.preferredTransportForPeer("direct-peer"); got != "direct" {
		t.Fatalf("preferredTransportForPeer(direct-peer) = %q, want direct", got)
	}
}

func TestPublishedTransportForPeerPrefersObservedDirectPath(t *testing.T) {
	wg := &fakeWGEngine{lastDirect: map[string]int64{
		"pub-a": time.Now().Add(-500 * time.Millisecond).UnixNano(),
	}}
	a := &Agent{
		wgMgr:                 wg,
		relayedPeers:          map[string]bool{"peer-a": true},
		handshakeValidWindow:  45 * time.Second,
		directConnectedWindow: 3 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "pub-a",
		},
	}
	stats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  time.Now().Add(-5 * time.Second),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if got := a.publishedTransportForPeer(peer, stats); got != "direct" {
		t.Fatalf("publishedTransportForPeer() = %q, want direct for observed direct dataplane", got)
	}
}

// TestPublishedTransportForPeerReadsPathMonitor asserts the new status
// contract: publishedTransportForPeer reflects whatever PathMonitor
// currently says the peer's mode is. Direct and Warm both surface as
// "direct" (we are using, or trying, the direct leg); only PathModeRelay
// surfaces as "relay" (direct has been given up on). The legacy path —
// inspecting WG's ActualEndpoint for "127.0.0.1:..." (the old UDPProxy
// signal) — is gone along with UDPProxy itself.
func TestPublishedTransportForPeerReadsPathMonitor(t *testing.T) {
	// Drive a PathMonitor into PathModeRelay by setting its backoff
	// deadline into the past and never feeding a direct RX.
	rx := &fakeRX{last: map[string]int64{}}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	pm := NewPathMonitor(logr.Discard(), rx, PathMonitorConfig{
		WarmStall:  100 * time.Millisecond,
		RelayStall: 100 * time.Millisecond, // short so the transition to Relay happens fast
		PromoteAge: 50 * time.Millisecond,
		RelayRetry: 5 * time.Second, // long so we stay in Relay
	}, clk.now)
	// Drive: Relay (first Evaluate) → Warm (forced probe) → Relay (stall).
	pm.Evaluate("peer-a", "pub-a", true) // → Warm
	clk.advance(200 * time.Millisecond)
	pm.Evaluate("peer-a", "pub-a", false) // Warm → Relay

	a := &Agent{pathMonitor: pm}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: "pub-a"},
	}
	if got := a.publishedTransportForPeer(peer, nil); got != "relay" {
		t.Fatalf("publishedTransportForPeer() = %q, want relay", got)
	}

	// A second peer the monitor has never seen → "direct" (safe default;
	// the sync loop will catch up on the next tick and place the peer on
	// Relay if appropriate).
	other := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-b"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: "pub-b"},
	}
	if got := a.publishedTransportForPeer(other, nil); got != "direct" {
		t.Fatalf("publishedTransportForPeer(new peer) = %q, want direct (unknown)", got)
	}
}

func TestHasPendingRestartRelayRecovery(t *testing.T) {
	a := &Agent{
		relayedPeers: map[string]bool{
			"relay-peer": true,
		},
		iceStates: map[string]*peerICEState{
			"checking-peer": {State: iceStateChecking},
			"direct-peer":   {State: iceStateConnected},
		},
	}

	if !a.hasPendingRestartRelayRecovery([]string{"relay-peer"}) {
		t.Fatal("hasPendingRestartRelayRecovery() = false, want true for relay-preferred peer")
	}
	if !a.hasPendingRestartRelayRecovery([]string{"checking-peer"}) {
		t.Fatal("hasPendingRestartRelayRecovery() = false, want true for checking peer")
	}
	if a.hasPendingRestartRelayRecovery([]string{"direct-peer"}) {
		t.Fatal("hasPendingRestartRelayRecovery() = true, want false for fully recovered direct peer")
	}
}

func TestPeerTransportUsableForDirectPeer(t *testing.T) {
	wg := &fakeWGEngine{lastDirect: map[string]int64{
		"pub-a": time.Now().Add(-2 * time.Second).UnixNano(),
	}}
	a := &Agent{
		relayedPeers:          map[string]bool{},
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "pub-a",
		},
	}

	directStats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  time.Now().Add(-30 * time.Second),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}
	if !a.peerTransportUsable(peer, directStats) {
		t.Fatal("peerTransportUsable() = false, want true for healthy direct path")
	}

	delete(wg.lastDirect, "pub-a")

	relayEndpointStats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  time.Now().Add(-30 * time.Second),
			ActualEndpoint: "127.0.0.1:51820",
		},
	}
	if !a.peerTransportUsable(peer, relayEndpointStats) {
		t.Fatal("peerTransportUsable() = false, want true when relay-assisted handshake is still fresh")
	}

	staleRelayEndpointStats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  time.Now().Add(-10 * time.Minute),
			ActualEndpoint: "127.0.0.1:51820",
		},
	}
	if a.peerTransportUsable(peer, staleRelayEndpointStats) {
		t.Fatal("peerTransportUsable() = true, want false when relay-assisted handshake is stale")
	}
}

func TestIsDirectConnectedFalseForRelayAssistedHandshakeWithoutDirectTraffic(t *testing.T) {
	wg := &fakeWGEngine{lastDirect: map[string]int64{"pub-a": -1}}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: "pub-a"},
	}
	stats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  time.Now().Add(-30 * time.Second),
			ActualEndpoint: "127.0.0.1:51820",
		},
	}

	if a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = true, want false when only relay-assisted traffic is fresh")
	}
}

func TestIsDirectConnectedUsesRecentDirectReceive(t *testing.T) {
	pubKey := "pub-a"
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: time.Now().Add(-500 * time.Millisecond).UnixNano(),
		},
	}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-4 * time.Minute),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if !a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = false, want true when direct traffic is still flowing")
	}
}

func TestIsDirectConnectedUsesDirectReceiveSeenThisSync(t *testing.T) {
	pubKey := "pub-a"
	now := time.Now()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: now.Add(-4 * time.Second).UnixNano(),
		},
	}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			pubKey: {
				bytesSent:     100,
				bytesReceived: 100,
				lastDirectRX:  now.Add(-10 * time.Second).UnixNano(),
			},
		},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  now.Add(-30 * time.Second),
			BytesReceived:  200,
			BytesSent:      200,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if !a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = false, want true when direct receive advanced during this sync interval")
	}
}

func TestIsDirectConnectedUsesHandshakeFallbackDuringPreservedRestartRecovery(t *testing.T) {
	pubKey := "pub-a"
	a := &Agent{
		handshakeValidWindow:  10 * time.Second,
		directConnectedWindow: 45 * time.Second,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates: map[string]*peerICEState{
			"peer-a": {State: iceStateConnected},
		},
		wgMgr:                 &fakeWGEngine{lastDirect: map[string]int64{}},
		wasInterfacePreserved: true,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if !a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = false, want true while preserved restart recovery awaits first direct receive")
	}
}

func TestIsDirectConnectedFailsDuringPreservedRestartRecoveryWithTrafficButNoDirectReceive(t *testing.T) {
	pubKey := "pub-a"
	a := &Agent{
		handshakeValidWindow:  10 * time.Second,
		directConnectedWindow: 45 * time.Second,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates: map[string]*peerICEState{
			"peer-a": {State: iceStateConnected},
		},
		wgMgr:                 &fakeWGEngine{lastDirect: map[string]int64{}},
		wasInterfacePreserved: true,
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			pubKey: {bytesSent: 100, bytesReceived: 100},
		},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			BytesReceived:  900,
			BytesSent:      900,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = true, want false when restart recovery still sees no direct receive under traffic")
	}
}

func TestIsDirectConnectedWithoutDirectReceiveFailsAfterRestartRecoveryEnds(t *testing.T) {
	pubKey := "pub-a"
	a := &Agent{
		handshakeValidWindow:  10 * time.Second,
		directConnectedWindow: 45 * time.Second,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates: map[string]*peerICEState{
			"peer-a": {State: iceStateConnected},
		},
		wgMgr: &fakeWGEngine{lastDirect: map[string]int64{}},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-4 * time.Minute),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = true, want false once preserved restart recovery is no longer active")
	}
}

func TestPeerTransportUsableUsesRecoveryHandshakeWindowAfterPreservedRestart(t *testing.T) {
	pubKey := "pub-a"
	a := &Agent{
		handshakeValidWindow:  10 * time.Second,
		directConnectedWindow: 45 * time.Second,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates: map[string]*peerICEState{
			"peer-a": {State: iceStateConnected},
		},
		wgMgr:                 &fakeWGEngine{lastDirect: map[string]int64{}},
		wasInterfacePreserved: true,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if !a.peerTransportUsable(peer, stats) {
		t.Fatal("peerTransportUsable() = false, want true while preserved restart recovery keeps the direct session usable")
	}
}

func TestIsDirectConnectedUsesHandshakeFallbackForIdlePeer(t *testing.T) {
	pubKey := "pub-a"
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: time.Now().Add(-10 * time.Second).UnixNano(),
		},
	}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			pubKey: {bytesSent: 100, bytesReceived: 100},
		},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			BytesReceived:  100,
			BytesSent:      100,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if !a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = false, want true for idle peer with fresh handshake")
	}
}

func TestIsDirectConnectedDoesNotUseHandshakeGraceForBusyPeerWithoutDirectTraffic(t *testing.T) {
	pubKey := "pub-a"
	lastDirect := time.Now().Add(-10 * time.Second).UnixNano()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: lastDirect,
		},
	}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates: map[string]*peerICEState{
			"peer-a": {
				State:      iceStateConnected,
				UpgradedAt: time.Now(),
			},
		},
		wgMgr: wg,
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			pubKey: {bytesSent: 100, bytesReceived: 100, lastDirectRX: lastDirect},
		},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			BytesReceived:  900,
			BytesSent:      900,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = true, want false for busy peer missing recent direct traffic even within upgrade grace")
	}
}

func TestIsDirectConnectedKeepsQuietEstablishedPeerOnDirect(t *testing.T) {
	pubKey := "pub-a"
	lastDirect := time.Now().Add(-10 * time.Second).UnixNano()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: lastDirect,
		},
	}
	a := &Agent{
		handshakeValidWindow:  10 * time.Second,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates: map[string]*peerICEState{
			"peer-a": {
				State: iceStateConnected,
			},
		},
		wgMgr: wg,
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			pubKey: {bytesSent: 100, bytesReceived: 100, lastDirectRX: lastDirect},
		},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}
	stats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			BytesReceived:  220,
			BytesSent:      220,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if !a.isDirectConnected(peer, stats) {
		t.Fatal("isDirectConnected() = false, want true for quiet established peer with direct endpoint")
	}
}

func TestResolveEndpointForPeerDoesNotReclassifyRelayAssistedHandshakeAsDirect(t *testing.T) {
	wg := &fakeWGEngine{lastDirect: map[string]int64{}}
	a := &Agent{
		relayedPeers:          map[string]bool{},
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "pub-a",
			Endpoint:  "203.0.113.10:51820",
		},
	}
	stats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  time.Now().Add(-30 * time.Second),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if got := a.resolveEndpointForPeer(peer, stats); got != peer.Spec.Endpoint {
		t.Fatalf("resolveEndpointForPeer() = %q, want peer endpoint when relay is unavailable", got)
	}

	if state := a.getICEState(peer.Name).State; state == iceStateConnected {
		t.Fatal("resolveEndpointForPeer() incorrectly marked peer direct-connected without direct traffic")
	}
}

func TestResolveEndpointForPeerPromotesObservedDirectPathEvenIfRelayPreferred(t *testing.T) {
	now := time.Now()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			"pub-a": now.UnixNano(),
		},
	}
	a := &Agent{
		relayPool:             &agentrelay.Pool{},
		relayMode:             "auto",
		relayedPeers:          map[string]bool{"peer-a": true},
		directEndpoints:       map[string]string{"peer-a": "203.0.113.10:51820"},
		relayGracePeers:       map[string]bool{},
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		iceStates:             map[string]*peerICEState{},
		wgMgr:                 wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "pub-a",
			Endpoint:  "203.0.113.10:51820",
		},
	}
	stats := map[string]wireguard.PeerStats{
		"pub-a": {
			PublicKeyB64:   "pub-a",
			LastHandshake:  now.Add(-30 * time.Second),
			ActualEndpoint: "203.0.113.10:51820",
		},
	}

	if got := a.resolveEndpointForPeer(peer, stats); got != peer.Spec.Endpoint {
		t.Fatalf("resolveEndpointForPeer() = %q, want %q", got, peer.Spec.Endpoint)
	}
	if a.relayedPeers[peer.Name] {
		t.Fatal("resolveEndpointForPeer() left peer relay-preferred despite healthy direct dataplane")
	}
	if state := a.getICEState(peer.Name).State; state != iceStateConnected {
		t.Fatalf("ICE state = %s, want %s", state, iceStateConnected)
	}
	if len(wg.setPaths) == 0 || wg.setPaths[len(wg.setPaths)-1] != wireguard.PathDirect {
		t.Fatalf("SetPeerPath calls = %v, want final PathDirect promotion", wg.setPaths)
	}
}

func TestProbeDirectHealthRejectsRelayOnlyHandshakeInUserspace(t *testing.T) {
	pubKey := "pub-a"
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{},
		stats: []wireguard.PeerStats{
			{
				PublicKeyB64:   pubKey,
				LastHandshake:  time.Now(),
				ActualEndpoint: "127.0.0.1:51820",
			},
		},
	}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    time.Millisecond,
		syncEvery:             time.Millisecond,
		directEndpoints: map[string]string{
			"peer-a": "203.0.113.10:51820",
		},
		iceStates: map[string]*peerICEState{},
		wgMgr:     wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}

	if a.probeDirectHealth(peer) {
		t.Fatal("probeDirectHealth() = true, want false when only relay-assisted handshake is observed")
	}
}

func TestProbeDirectHealthAcceptsRecentDirectTraffic(t *testing.T) {
	pubKey := "pub-a"
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: time.Now().UnixNano(),
		},
		stats: []wireguard.PeerStats{
			{
				PublicKeyB64:   pubKey,
				LastHandshake:  time.Now(),
				ActualEndpoint: "203.0.113.10:51820",
			},
		},
	}
	a := &Agent{
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    time.Millisecond,
		syncEvery:             time.Millisecond,
		directEndpoints: map[string]string{
			"peer-a": "203.0.113.10:51820",
		},
		iceStates: map[string]*peerICEState{},
		wgMgr:     wg,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}

	if !a.probeDirectHealth(peer) {
		t.Fatal("probeDirectHealth() = false, want true when direct traffic was observed")
	}
	if len(wg.setPaths) < 2 || wg.setPaths[len(wg.setPaths)-1] != wireguard.PathDirect {
		t.Fatal("probeDirectHealth() did not restore direct path after a successful health probe")
	}
}

func TestRecentDirectReceiveWindowCoversOneSyncInterval(t *testing.T) {
	a := &Agent{
		healthProbeTimeout: 5 * time.Second,
		syncEvery:          5 * time.Second,
	}

	if got := a.recentDirectReceiveWindow(); got != 5*time.Second {
		t.Fatalf("recentDirectReceiveWindow() = %v, want 5s to span one sync interval", got)
	}
}

func TestRecentDirectReceiveWindowKeepsSmallDefaultWithoutSyncInterval(t *testing.T) {
	a := &Agent{
		healthProbeTimeout: 5 * time.Second,
	}

	if got := a.recentDirectReceiveWindow(); got != 1500*time.Millisecond {
		t.Fatalf("recentDirectReceiveWindow() = %v, want 1.5s when sync interval is unset", got)
	}
}

func TestPeerHadTrafficSinceLastSync(t *testing.T) {
	a := &Agent{
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			"pub-a": {bytesSent: 10, bytesReceived: 20},
		},
	}

	if !a.peerHadTrafficSinceLastSync("pub-a", wireguard.PeerStats{BytesSent: 10, BytesReceived: 21}) {
		t.Fatal("peerHadTrafficSinceLastSync() = false, want true when bytes increased")
	}
	if a.peerHadTrafficSinceLastSync("pub-a", wireguard.PeerStats{BytesSent: 10, BytesReceived: 20}) {
		t.Fatal("peerHadTrafficSinceLastSync() = true, want false when peer is idle")
	}
}

func TestPeerHadMeaningfulTrafficSinceLastSync(t *testing.T) {
	a := &Agent{
		peerTrafficSnapshots: map[string]peerTrafficSnapshot{
			"pub-a": {bytesSent: 10, bytesReceived: 20},
		},
	}

	if a.peerHadMeaningfulTrafficSinceLastSync("pub-a", wireguard.PeerStats{BytesSent: 60, BytesReceived: 70}) {
		t.Fatal("peerHadMeaningfulTrafficSinceLastSync() = true, want false for keepalive-sized deltas")
	}
	if !a.peerHadMeaningfulTrafficSinceLastSync("pub-a", wireguard.PeerStats{BytesSent: 400, BytesReceived: 300}) {
		t.Fatal("peerHadMeaningfulTrafficSinceLastSync() = false, want true for data-plane sized deltas")
	}
}

func TestDeferDirectReprobeSetsCooldown(t *testing.T) {
	a := &Agent{
		iceStates: map[string]*peerICEState{
			"peer-a": {State: iceStateRelay},
		},
	}

	before := time.Now()
	a.deferDirectReprobe("peer-a", 10*time.Second)
	state := a.getICEState("peer-a")
	if state.NextProbeAfter.Before(before.Add(9 * time.Second)) {
		t.Fatal("deferDirectReprobe() did not set a future cooldown")
	}
}

func TestShouldFastFailToRelayRequiresActiveTraffic(t *testing.T) {
	pubKey := "pub-a"
	lastDirect := time.Now().Add(-10 * time.Second).UnixNano()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: lastDirect,
		},
	}
	a := &Agent{
		wgMgr:                 wg,
		relayedPeers:          map[string]bool{},
		iceStates:             map[string]*peerICEState{"peer-a": {State: iceStateConnected}},
		peerTrafficSnapshots:  map[string]peerTrafficSnapshot{pubKey: {bytesSent: 10, bytesReceived: 10, lastDirectRX: lastDirect}},
		handshakeValidWindow:  3 * time.Minute,
		directConnectedWindow: 5 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		syncEvery:             5 * time.Second,
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
	}

	idleStats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			BytesSent:      10,
			BytesReceived:  10,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}
	if a.shouldFastFailToRelay(peer, idleStats) {
		t.Fatal("shouldFastFailToRelay() = true, want false for idle peer")
	}

	busyStats := map[string]wireguard.PeerStats{
		pubKey: {
			PublicKeyB64:   pubKey,
			LastHandshake:  time.Now().Add(-30 * time.Second),
			BytesSent:      900,
			BytesReceived:  900,
			ActualEndpoint: "203.0.113.10:51820",
		},
	}
	if !a.shouldFastFailToRelay(peer, busyStats) {
		t.Fatal("shouldFastFailToRelay() = false, want true for active peer with stale direct traffic")
	}
}

func TestRevertToRelayPokesKeepalive(t *testing.T) {
	const pubKey = "peer-key"
	wg := &fakeWGEngine{}
	a := &Agent{
		wgMgr:           wg,
		iceStates:       map[string]*peerICEState{"peer-1": {State: iceStateConnected}},
		relayedPeers:    map[string]bool{},
		directEndpoints: map[string]string{"peer-1": "10.0.0.2:51820"},
		relayPrewarmed:  map[string]bool{"peer-1": true},
	}
	peer := &wirekubev1alpha1.WireKubePeer{}
	peer.Name = "peer-1"
	peer.Spec.PublicKey = pubKey
	peer.Spec.Endpoint = "10.0.0.2:51820"

	a.revertToRelay(peer)

	if len(wg.poked) != 1 || wg.poked[0] != pubKey {
		t.Fatalf("PokeKeepalive calls = %v, want [%s]", wg.poked, pubKey)
	}
	if len(wg.setPaths) == 0 || wg.setPaths[0] != wireguard.PathRelay {
		t.Fatalf("SetPeerPath calls = %v, want first call PathRelay", wg.setPaths)
	}
}

func TestEvaluateICECheckUsesDirectReceiveWatermark(t *testing.T) {
	const pubKey = "pub-a"
	now := time.Now()

	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			pubKey: now.Add(-2 * time.Second).UnixNano(),
		},
		stats: []wireguard.PeerStats{
			{
				PublicKeyB64:   pubKey,
				LastHandshake:  now.Add(-1 * time.Second),
				ActualEndpoint: "203.0.113.10:51820",
			},
		},
	}
	a := &Agent{
		wgMgr:           wg,
		directProbing:   map[string]bool{"peer-a": true},
		probeForced:     map[string]bool{"peer-a": true},
		directEndpoints: map[string]string{"peer-a": "203.0.113.10:51820"},
		iceStates: map[string]*peerICEState{
			"peer-a": {
				State:                   iceStateChecking,
				LastCheck:               now.Add(-activeProbeWait - time.Second),
				ProbeStartHandshake:     now.Add(-3 * time.Second),
				ProbeStartDirectReceive: now.Add(-3 * time.Second).UnixNano(),
			},
		},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: pubKey,
			Endpoint:  "203.0.113.10:51820",
		},
	}

	a.evaluateICECheck(context.TODO(), peer, map[string]wireguard.PeerStats{
		pubKey: wg.stats[0],
	})

	state := a.getICEState("peer-a")
	if state.State != iceStateConnected {
		t.Fatalf("ICE state = %s, want %s after fresh direct RX", state.State, iceStateConnected)
	}
	if len(wg.setPaths) == 0 || wg.setPaths[len(wg.setPaths)-1] != wireguard.PathDirect {
		t.Fatalf("SetPeerPath calls = %v, want final PathDirect upgrade", wg.setPaths)
	}
}

func TestRecoverICEStateFromWGUsesPreservedDirectEndpointInUserspace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(core): %v", err)
	}
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(wirekube): %v", err)
	}

	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "pub-a",
			Endpoint:  "203.0.113.10:51820",
		},
	}
	k8sClient := ctrlclientfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(peer).
		Build()

	now := time.Now()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			"pub-a": 0,
		},
		stats: []wireguard.PeerStats{
			{
				PublicKeyB64:   "pub-a",
				LastHandshake:  now.Add(-1 * time.Second),
				ActualEndpoint: "203.0.113.10:51820",
			},
		},
	}

	a := &Agent{
		client:                k8sClient,
		wgMgr:                 wg,
		iceStates:             map[string]*peerICEState{},
		directEndpoints:       map[string]string{},
		relayedPeers:          map[string]bool{"peer-a": true},
		handshakeValidWindow:  3 * time.Minute,
		healthProbeTimeout:    5 * time.Second,
		wasInterfacePreserved: true,
	}

	a.recoverICEStateFromWG()

	state := a.getICEState("peer-a")
	if state.State != iceStateConnected {
		t.Fatalf("ICE state = %s, want %s with preserved direct endpoint", state.State, iceStateConnected)
	}
	if !state.UpgradedAt.IsZero() {
		t.Fatalf("UpgradedAt = %v, want zero for restart recovery", state.UpgradedAt)
	}
	if got := a.directEndpoints["peer-a"]; got != "203.0.113.10:51820" {
		t.Fatalf("directEndpoints[peer-a] = %q, want preserved WG endpoint", got)
	}
	if a.relayedPeers["peer-a"] {
		t.Fatal("peer-a remained marked relayed after direct recovery")
	}
}

func TestRecoverICEStateFromWGWithoutPreservedInterfaceFallsBackToRelay(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(core): %v", err)
	}
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(wirekube): %v", err)
	}

	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "peer-a"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "pub-a",
			Endpoint:  "203.0.113.10:51820",
		},
	}
	k8sClient := ctrlclientfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(peer).
		Build()

	now := time.Now()
	wg := &fakeWGEngine{
		lastDirect: map[string]int64{
			"pub-a": 0,
		},
		stats: []wireguard.PeerStats{
			{
				PublicKeyB64:   "pub-a",
				LastHandshake:  now.Add(-1 * time.Second),
				ActualEndpoint: "203.0.113.10:51820",
			},
		},
	}

	a := &Agent{
		client:               k8sClient,
		wgMgr:                wg,
		iceStates:            map[string]*peerICEState{},
		handshakeValidWindow: 3 * time.Minute,
		healthProbeTimeout:   5 * time.Second,
	}

	a.recoverICEStateFromWG()

	state := a.getICEState("peer-a")
	if state.State != iceStateRelay {
		t.Fatalf("ICE state = %s, want %s without preserved interface", state.State, iceStateRelay)
	}
	if !state.LastCheck.IsZero() {
		t.Fatalf("LastCheck = %v, want zero for immediate reprobe", state.LastCheck)
	}
}
