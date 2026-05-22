package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestIssuePeerCreatesCRAndReturnsConfig(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second)
	s.waitForActive = func(_ context.Context, _ client.Client, name string, _ time.Duration) (*wirekubev1alpha1.WireKubeExternalPeer, error) {
		return &wirekubev1alpha1.WireKubeExternalPeer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
				AssignedMeshIP:      "100.64.0.10/32",
				RelayEndpoint:       "vpn.example.com:3478",
				IngressPublicKey:    "ingress-public-key",
				AllowedDestinations: []string{"100.64.0.0/16"},
				MTU:                 1248,
				Phase:               wirekubev1alpha1.ExternalPeerPhaseActive,
			},
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader("name=alice&displayName=Alice&ttl=24h&mtu=1248&allowed=10.0.0.0/24&ingressPeer=worker1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Issued: alice", "[Interface]", "Endpoint = vpn.example.com:3478"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q:\n%s", want, body)
		}
	}

	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "alice"}, cr); err != nil {
		t.Fatalf("created CR not found: %v", err)
	}
	if cr.Spec.DisplayName != "Alice" || cr.Spec.IngressPeer != "worker1" {
		t.Fatalf("unexpected spec: %#v", cr.Spec)
	}
	if len(cr.Spec.PublicKey) != 44 {
		t.Fatalf("publicKey length = %d, want 44", len(cr.Spec.PublicKey))
	}
	if cr.Spec.TTL == nil || cr.Spec.TTL.Duration != 24*time.Hour {
		t.Fatalf("ttl = %#v, want 24h", cr.Spec.TTL)
	}
	if got := strings.Join(cr.Spec.AllowedDestinations, ","); got != "10.0.0.0/24" {
		t.Fatalf("allowedDestinations = %q", got)
	}
}

func TestDeletePeerRemovesCR(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "alice"}}).
		Build()
	s := newServer(c, time.Second)

	req := httptest.NewRequest(http.MethodPost, "/peers/alice/delete", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(context.Background(), client.ObjectKey{Name: "alice"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("get after delete = %v, want not found", err)
	}
}
