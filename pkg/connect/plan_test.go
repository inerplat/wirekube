package connect

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

var testIngressKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func activePeer(allowed ...string) *wirekubev1alpha1.WireKubeExternalPeer {
	return &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "p"},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			Phase:               wirekubev1alpha1.ExternalPeerPhaseActive,
			AssignedMeshIP:      "100.64.0.9/32",
			RelayEndpoint:       "relay.example.test:30479",
			IngressPublicKey:    testIngressKey,
			AllowedDestinations: allowed,
		},
	}
}

func TestConfigFromStatusNormalizesRoutes(t *testing.T) {
	cfg, err := ConfigFromStatus(activePeer("10.96.0.0/12", "100.64.0.0/10", "10.244.1.7/16", "10.244.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(cfg.Routes))
	for i, r := range cfg.Routes {
		got[i] = r.String()
	}
	want := "10.96.0.0/12,10.244.0.0/16,100.64.0.0/10"
	if strings.Join(got, ",") != want {
		t.Fatalf("routes = %v, want %s", got, want)
	}
	if cfg.Address != netip.MustParsePrefix("100.64.0.9/32") {
		t.Fatalf("address = %s", cfg.Address)
	}
	if cfg.MTU != int(wirekubev1alpha1.DefaultExternalPeerMTU) {
		t.Fatalf("mtu = %d", cfg.MTU)
	}
}

func TestConfigFromStatusFallsBackToOwnAddress(t *testing.T) {
	cfg, err := ConfigFromStatus(activePeer())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0] != netip.MustParsePrefix("100.64.0.9/32") {
		t.Fatalf("routes = %v", cfg.Routes)
	}
}

func TestConfigFromStatusRejectsIncompleteStatus(t *testing.T) {
	cr := activePeer("10.0.0.0/8")
	cr.Status.IngressPublicKey = ""
	if _, err := ConfigFromStatus(cr); err == nil {
		t.Fatal("expected an error for a status without an ingress key")
	}
}

func TestCheckEndpointReachable(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if err := CheckEndpointReachable(netip.MustParseAddrPort("10.1.2.3:30479"), routes); err == nil {
		t.Fatal("an endpoint inside a routed range must be refused")
	}
	if err := CheckEndpointReachable(netip.MustParseAddrPort("192.0.2.1:30479"), routes); err != nil {
		t.Fatal(err)
	}
}

func TestLocalOverlaps(t *testing.T) {
	routes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12")}
	local := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("192.168.1.0/24")}
	got := LocalOverlaps(routes, local)
	if len(got) != 1 || !strings.Contains(got[0], "10.1.0.0/16") {
		t.Fatalf("overlaps = %v", got)
	}
}

func TestUAPIConfig(t *testing.T) {
	cfg, err := ConfigFromStatus(activePeer("10.96.0.0/12", "10.244.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	var priv [32]byte
	priv[0] = 1
	out, err := uapiConfig(priv, cfg, netip.MustParseAddrPort("192.0.2.1:30479"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"private_key=01" + strings.Repeat("00", 31),
		"replace_peers=true",
		"public_key=" + strings.Repeat("00", 32),
		"endpoint=192.0.2.1:30479",
		"replace_allowed_ips=true",
		"allowed_ip=10.96.0.0/12",
		"allowed_ip=10.244.0.0/16",
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("uapi config lacks %q:\n%s", line, out)
		}
	}
	cfg.PeerPublicKey = "not-a-key"
	if _, err := uapiConfig(priv, cfg, netip.MustParseAddrPort("192.0.2.1:30479")); err == nil {
		t.Fatal("expected an error for a malformed ingress key")
	}
}

func TestDefaultName(t *testing.T) {
	for _, tc := range []struct{ user, host, want string }{
		{"alice", "Alice-MacBook.local", "connect-alice-alice-macbook-local"},
		{"Bob Smith", "WIN_PC", "connect-bob-smith-win-pc"},
		{"x", strings.Repeat("h", 80), ("connect-x-" + strings.Repeat("h", 80))[:63]},
	} {
		if got := DefaultName(tc.user, tc.host); got != tc.want {
			t.Errorf("DefaultName(%q, %q) = %q, want %q", tc.user, tc.host, got, tc.want)
		}
	}
}

func TestParseLastHandshake(t *testing.T) {
	if got := parseLastHandshake("public_key=aa\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n"); !got.IsZero() {
		t.Fatalf("no handshake parsed as %v", got)
	}
	got := parseLastHandshake("public_key=aa\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n")
	if !got.Equal(time.Unix(1700000000, 5)) {
		t.Fatalf("handshake = %v", got)
	}
}

// TestConfigFromStatusUsesTheIssuedKey covers an older controller writing a
// node key into status mid-upgrade: the tunnel must keep authenticating the
// key the peer was issued under, which the agents keep serving.
func TestConfigFromStatusUsesTheIssuedKey(t *testing.T) {
	cr := activePeer("10.96.0.0/12")
	issued := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 7))
	cr.Annotations = map[string]string{wirekubev1alpha1.ExternalPeerIssuedIngressKeyAnnotation: issued}
	cfg, err := ConfigFromStatus(cr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeerPublicKey != issued {
		t.Fatalf("peer key = %q, want the issued key over status", cfg.PeerPublicKey)
	}
}
