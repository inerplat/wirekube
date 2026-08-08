package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

const refreshTestPrivateKey = "c3RvcmVkLXByaXZhdGUta2V5LXBhZGRpbmc9PT0="

func storedConfigSecret(name, ingressKey string) *corev1.Secret {
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + refreshTestPrivateKey,
		"Address = 100.64.0.10/32",
		"MTU = 1248",
		"",
		"[Peer]",
		"PublicKey = " + ingressKey,
		"AllowedIPs = 100.64.0.0/16",
		"Endpoint = vpn.example.com:3478",
		"PersistentKeepalive = 25",
	}, "\n")
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        peerConfigSecretName(name),
			Namespace:   "wirekube-system",
			Annotations: map[string]string{peerConfigPeerAnnotation: name},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{peerConfigDataKey: []byte(conf)},
	}
}

// The production incident this covers: a peer was issued while a dead node
// was still selectable as ingress. The CR was later re-pinned to a live
// ingress, but the download kept serving the issuance-time render, so the
// client kept handshaking against a public key nobody held.
func TestViewPeerConfigRendersFromCurrentStatus(t *testing.T) {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", CreationTimestamp: metav1.NewTime(time.Now())},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:      "100.64.0.10/32",
			RelayEndpoint:       "vpn.example.com:3478",
			IngressPublicKey:    "live-ingress-key",
			AllowedDestinations: []string{"100.64.0.0/16"},
			MTU:                 1248,
			Phase:               wirekubev1alpha1.ExternalPeerPhaseActive,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(cr, storedConfigSecret("alice", "dead-ingress-key")).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/peers/alice/config", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "live-ingress-key") {
		t.Fatalf("download does not carry the current ingress key:\n%s", body)
	}
	if strings.Contains(body, "dead-ingress-key") {
		t.Fatalf("download still carries the issuance-time ingress key:\n%s", body)
	}
	if !strings.Contains(body, refreshTestPrivateKey) {
		t.Fatal("download lost the stored private key")
	}

	// The stored secret is refreshed too, so out-of-band readers see the
	// same config the web serves.
	secret := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "wirekube-system", Name: peerConfigSecretName("alice")}, secret); err != nil {
		t.Fatalf("stored secret: %v", err)
	}
	stored := string(secret.Data[peerConfigDataKey])
	if !strings.Contains(stored, "live-ingress-key") || strings.Contains(stored, "dead-ingress-key") {
		t.Fatalf("stored secret not refreshed:\n%s", stored)
	}
	if !strings.Contains(stored, refreshTestPrivateKey) {
		t.Fatal("stored secret lost the private key")
	}
}

// A peer knocked back to Pending has an incomplete status; rendering from it
// would produce a config with empty fields. The last known-good render is the
// right thing to serve until the allocation settles.
func TestViewPeerConfigKeepsStoredRenderWhilePending(t *testing.T) {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", CreationTimestamp: metav1.NewTime(time.Now())},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			Phase: wirekubev1alpha1.ExternalPeerPhasePending,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(cr, storedConfigSecret("alice", "issued-ingress-key")).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/peers/alice/config", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "issued-ingress-key") {
		t.Fatal("pending peer no longer serves the stored render")
	}
}

func TestPrivateKeyFromConfigKeepsPadding(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + refreshTestPrivateKey + "\nAddress = 1.2.3.4/32\n"
	if got := privateKeyFromConfig(conf); got != refreshTestPrivateKey {
		t.Fatalf("privateKeyFromConfig = %q, want %q", got, refreshTestPrivateKey)
	}
	if got := privateKeyFromConfig("[Interface]\nAddress = 1.2.3.4/32\n"); got != "" {
		t.Fatalf("privateKeyFromConfig on keyless conf = %q, want empty", got)
	}
}
