package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestIssuePeerCreatesCRAndReturnsConfig(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")
	s.waitForActive = activePeer

	form := url.Values{
		"csrf_token":  {s.csrfToken},
		"name":        {"alice"},
		"displayName": {"Alice"},
		"ttl":         {"24h"},
		"mtu":         {"1248"},
		"allowed":     {"10.0.0.0/24"},
		"ingressPeer": {"worker1"},
	}
	req := formRequest(http.MethodPost, "/peers", form)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Peer config", "[Interface]", "Endpoint = vpn.example.com:3478"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q:\n%s", want, body)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
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

	secret := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "wirekube-system", Name: peerConfigSecretName("alice")}, secret); err != nil {
		t.Fatalf("stored config secret not found: %v", err)
	}
	conf := string(secret.Data[peerConfigDataKey])
	for _, want := range []string{"PrivateKey = ", "Endpoint = vpn.example.com:3478"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("stored config missing %q:\n%s", want, conf)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/peers/alice/config", nil)
	rec = httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("config status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if !strings.Contains(body, "[Interface]") || !strings.Contains(body, "WireGuard QR code") {
		t.Fatalf("config response missing conf/qr:\n%s", body)
	}
}

func TestBasicAuth(t *testing.T) {
	// bcrypt hash of "s3cret" (cost 10).
	const hash = "$2a$10$QUOTjZgtTKnkj9pwIJZOoOCoKP8dWi8dbZ9.wto6FrQNdVFZx1HkO"
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")
	s.auth = &basicAuthConfig{username: "admin", passwordHash: []byte(hash)}

	cases := []struct {
		name       string
		setAuth    func(*http.Request)
		wantStatus int
	}{
		{"no credentials", func(*http.Request) {}, http.StatusUnauthorized},
		{"wrong password", func(r *http.Request) { r.SetBasicAuth("admin", "nope") }, http.StatusUnauthorized},
		{"wrong username", func(r *http.Request) { r.SetBasicAuth("root", "s3cret") }, http.StatusUnauthorized},
		{"correct", func(r *http.Request) { r.SetBasicAuth("admin", "s3cret") }, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/peers", nil)
			tc.setAuth(req)
			rec := httptest.NewRecorder()
			s.routes().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
					t.Fatalf("WWW-Authenticate = %q, want Basic challenge", got)
				}
			}
		})
	}
}

func TestBasicAuthDisabledAllowsAccess(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system") // s.auth == nil

	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (auth disabled)", rec.Code, http.StatusOK)
	}
}

func TestHealthzSkipsAuth(t *testing.T) {
	const hash = "$2a$10$QUOTjZgtTKnkj9pwIJZOoOCoKP8dWi8dbZ9.wto6FrQNdVFZx1HkO"
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")
	s.auth = &basicAuthConfig{username: "admin", passwordHash: []byte(hash)}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestLoadBasicAuth(t *testing.T) {
	const hash = "$2a$10$QUOTjZgtTKnkj9pwIJZOoOCoKP8dWi8dbZ9.wto6FrQNdVFZx1HkO"
	cases := []struct {
		name        string
		user, hash  string
		wantEnabled bool
		wantErr     bool
	}{
		{"both empty disables", "", "", false, false},
		{"username only errors", "admin", "", false, true},
		{"hash only errors", "", hash, false, true},
		{"invalid hash errors", "admin", "not-a-bcrypt-hash", false, true},
		{"valid enables", "admin", hash, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WIREKUBE_ADMIN_WEB_USERNAME", tc.user)
			t.Setenv("WIREKUBE_ADMIN_WEB_PASSWORD_HASH", tc.hash)
			auth, err := loadBasicAuth()
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && tc.wantEnabled != (auth != nil) {
				t.Fatalf("enabled = %v, want %v", auth != nil, tc.wantEnabled)
			}
		})
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{":8080", false},        // wildcard: all interfaces
		{"0.0.0.0:8080", false}, // all interfaces
		{"10.0.0.5:8080", false},
		{"garbage", false},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := isLoopbackAddr(tc.addr); got != tc.want {
				t.Fatalf("isLoopbackAddr(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIssuePeerRejectsMissingCSRF(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := formRequest(http.MethodPost, "/peers", url.Values{"name": {"alice"}})
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(context.Background(), client.ObjectKey{Name: "alice"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("created CR after csrf rejection: %v", err)
	}
}

func TestIssuePeerRejectsCrossOrigin(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := formRequest(http.MethodPost, "/peers", url.Values{
		"csrf_token": {s.csrfToken},
		"name":       {"alice"},
	})
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestIssuePeerRejectsInvalidAllowedCIDR(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := formRequest(http.MethodPost, "/peers", url.Values{
		"csrf_token": {s.csrfToken},
		"name":       {"alice"},
		"allowed":    {"not-a-cidr"},
	})
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "invalid allowed IPs CIDR") {
		t.Fatalf("body missing cidr error:\n%s", rec.Body.String())
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(context.Background(), client.ObjectKey{Name: "alice"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("created CR after invalid cidr: %v", err)
	}
}

func TestIssuePeerDeletesCRWhenWaitFails(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Millisecond, "wirekube-system")
	s.waitForActive = func(context.Context, client.Client, string, time.Duration) (*wirekubev1alpha1.WireKubeExternalPeer, error) {
		return nil, fmt.Errorf("timeout")
	}

	req := formRequest(http.MethodPost, "/peers", url.Values{
		"csrf_token": {s.csrfToken},
		"name":       {"alice"},
	})
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusGatewayTimeout)
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(context.Background(), client.ObjectKey{Name: "alice"}, cr)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("created CR was not cleaned up: %v", err)
	}
}

func TestDeletePeerRemovesCR(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("alice"),
			Namespace: "wirekube-system",
		},
		Data: map[string][]byte{peerConfigDataKey: []byte("stored config")},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "alice"}}, secret).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := formRequest(http.MethodPost, "/peers/alice/delete", url.Values{"csrf_token": {s.csrfToken}})
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
	secret = &corev1.Secret{}
	err = c.Get(context.Background(), client.ObjectKey{Namespace: "wirekube-system", Name: peerConfigSecretName("alice")}, secret)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("secret after delete = %v, want not found", err)
	}
}

func TestViewPeerConfigRequiresStoredSecret(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "alice"}}).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/peers/alice/config", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), "stored config unavailable") {
		t.Fatalf("body missing unavailable message:\n%s", rec.Body.String())
	}
}

func TestIndexShowsConfigActionOnlyWhenStoredConfigExists(t *testing.T) {
	aliceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("alice"),
			Namespace: "wirekube-system",
			Annotations: map[string]string{
				peerConfigPeerAnnotation: "alice",
			},
		},
		Data: map[string][]byte{peerConfigDataKey: []byte("[Interface]\nPrivateKey = private\n")},
	}
	bobSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("bob"),
			Namespace: "wirekube-system",
			Annotations: map[string]string{
				peerConfigPeerAnnotation: "mallory",
			},
		},
		Data: map[string][]byte{peerConfigDataKey: []byte("[Interface]\nPrivateKey = wrong-peer\n")},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&wirekubev1alpha1.WireKubeExternalPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec:       wirekubev1alpha1.WireKubeExternalPeerSpec{DisplayName: "Alice"},
			},
			&wirekubev1alpha1.WireKubeExternalPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "bob"},
				Spec:       wirekubev1alpha1.WireKubeExternalPeerSpec{DisplayName: "Bob"},
			},
			aliceSecret,
			bobSecret,
		).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/peers/alice/config"`) {
		t.Fatalf("body missing alice config link:\n%s", body)
	}
	if strings.Contains(body, `href="/peers/bob/config"`) {
		t.Fatalf("body unexpectedly links bob config:\n%s", body)
	}
	if !strings.Contains(body, "No stored config for this peer") {
		t.Fatalf("body missing disabled config affordance:\n%s", body)
	}
}

func TestIndexWiresBulkPeerActions(t *testing.T) {
	aliceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("alice"),
			Namespace: "wirekube-system",
			Annotations: map[string]string{
				peerConfigPeerAnnotation: "alice",
			},
		},
		Data: map[string][]byte{peerConfigDataKey: []byte("[Interface]\nPrivateKey = private\n")},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&wirekubev1alpha1.WireKubeExternalPeer{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec:       wirekubev1alpha1.WireKubeExternalPeerSpec{DisplayName: "Alice"},
			},
			aliceSecret,
		).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`id="bulk-delete-form"`,
		`id="select-all"`,
		`id="select-visible"`,
		`class="peer-select" form="bulk-delete-form" name="peers" value="alice"`,
		`Revoke selected`,
		`Actions`,
		`data-detail-kind="External peer"`,
		`aria-label="Open details for alice"`,
		`id="detail-modal"`,
		`href="/peers/alice/config"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
}

func TestBulkDeletePeersRemovesCRsAndSecrets(t *testing.T) {
	aliceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("alice"),
			Namespace: "wirekube-system",
		},
		Data: map[string][]byte{peerConfigDataKey: []byte("alice config")},
	}
	bobSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("bob"),
			Namespace: "wirekube-system",
		},
		Data: map[string][]byte{peerConfigDataKey: []byte("bob config")},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "alice"}},
			&wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "bob"}},
			aliceSecret,
			bobSecret,
		).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := formRequest(http.MethodPost, "/peers/delete", url.Values{
		"csrf_token": {s.csrfToken},
		"peers":      {"alice", "bob"},
	})
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d; body:\n%s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}
	for _, name := range []string{"alice", "bob"} {
		cr := &wirekubev1alpha1.WireKubeExternalPeer{}
		err := c.Get(context.Background(), client.ObjectKey{Name: name}, cr)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("peer %s after delete = %v, want not found", name, err)
		}
		secret := &corev1.Secret{}
		err = c.Get(context.Background(), client.ObjectKey{Namespace: "wirekube-system", Name: peerConfigSecretName(name)}, secret)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("secret %s after delete = %v, want not found", name, err)
		}
	}
}

func TestRelaysPageRendersKubernetesResources(t *testing.T) {
	replicas := int32(1)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wirekube-relay",
					Namespace: "wirekube-system",
					Labels:    map[string]string{"app.kubernetes.io/name": "wirekube-relay"},
				},
				Spec: appsv1.DeploymentSpec{Replicas: &replicas},
				Status: appsv1.DeploymentStatus{
					ReadyReplicas:     1,
					UpdatedReplicas:   1,
					AvailableReplicas: 1,
				},
			},
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wirekube-relay-abc",
					Namespace: "wirekube-system",
					Labels:    map[string]string{"app.kubernetes.io/name": "wirekube-relay"},
				},
				Spec: corev1.PodSpec{
					NodeName:   "worker1",
					Containers: []corev1.Container{{Name: "relay"}, {Name: "admin-web"}},
				},
				Status: corev1.PodStatus{
					Phase:  corev1.PodRunning,
					PodIP:  "10.0.0.10",
					HostIP: "10.0.0.1",
					ContainerStatuses: []corev1.ContainerStatus{
						{Name: "relay", Ready: true},
						{Name: "admin-web", Ready: true},
					},
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wirekube-relay",
					Namespace: "wirekube-system",
					Labels:    map[string]string{"app.kubernetes.io/name": "wirekube-relay"},
				},
				Spec: corev1.ServiceSpec{
					Type:      corev1.ServiceTypeLoadBalancer,
					ClusterIP: "10.96.0.10",
					Ports: []corev1.ServicePort{{
						Name:     "relay-udp",
						Port:     3478,
						Protocol: corev1.ProtocolUDP,
					}},
				},
			},
		).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/relays", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Relays",
		"wirekube-relay-abc",
		"worker1",
		"relay-udp:3478/UDP",
		"wirekube-relay",
		`data-detail-kind="Relay deployment"`,
		`data-detail-kind="Relay pod"`,
		`data-detail-kind="Relay service"`,
		`Details`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `class="disabled"`) {
		t.Fatalf("relays page still renders disabled nav:\n%s", body)
	}
}

func TestMeshNodesPageRendersWireKubeResources(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&wirekubev1alpha1.WireKubeMesh{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: wirekubev1alpha1.WireKubeMeshSpec{
					ListenPort:    51820,
					InterfaceName: "wire_kube",
					MTU:           1248,
					MeshCIDR:      "100.64.0.0/10",
				},
				Status: wirekubev1alpha1.WireKubeMeshStatus{
					ReadyPeers: 1,
					TotalPeers: 1,
				},
			},
			&wirekubev1alpha1.WireKubePeer{
				ObjectMeta: metav1.ObjectMeta{Name: "worker1"},
				Spec: wirekubev1alpha1.WireKubePeerSpec{
					Endpoint:   "worker1.example.com:51820",
					AllowedIPs: []string{"100.64.0.1/32"},
				},
				Status: wirekubev1alpha1.WireKubePeerStatus{
					Connected:   true,
					NATType:     "cone",
					ICEState:    "connected",
					Connections: map[string]string{"worker2": "direct"},
				},
			},
		).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/mesh-nodes", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Mesh nodes",
		"Mesh configuration",
		"default",
		"worker1",
		"Ready",
		"1 total (direct: 1)",
		`data-detail-kind="Mesh configuration"`,
		`data-detail-kind="Mesh node"`,
		`data-detail-connections-url="/mesh-nodes/worker1/connections"`,
		`Details`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "worker2:direct") {
		t.Fatalf("mesh page should not inline every connection in the table:\n%s", body)
	}
}

func TestMeshNodeConnectionsEndpointReturnsConnections(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&wirekubev1alpha1.WireKubePeer{
				ObjectMeta: metav1.ObjectMeta{Name: "worker1"},
				Status: wirekubev1alpha1.WireKubePeerStatus{
					Connections: map[string]string{
						"worker3": "relay",
						"worker2": "direct",
					},
				},
			},
		).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := httptest.NewRequest(http.MethodGet, "/mesh-nodes/worker1/connections", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body:\n%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var resp meshConnectionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v\n%s", err, rec.Body.String())
	}
	if resp.Node != "worker1" || resp.Total != 2 {
		t.Fatalf("response summary = node %q total %d, want worker1/2", resp.Node, resp.Total)
	}
	if resp.Summary != "2 total (direct: 1, relay: 1)" {
		t.Fatalf("summary = %q", resp.Summary)
	}
	if len(resp.Connections) != 2 {
		t.Fatalf("connections len = %d, want 2", len(resp.Connections))
	}
	if resp.Connections[0].Peer != "worker2" || resp.Connections[0].Status != "direct" {
		t.Fatalf("first connection = %#v, want sorted worker2/direct", resp.Connections[0])
	}
	if resp.Connections[1].Peer != "worker3" || resp.Connections[1].Status != "relay" {
		t.Fatalf("second connection = %#v, want worker3/relay", resp.Connections[1])
	}
}

func TestLoadPeerConfigPreservesStoredBytes(t *testing.T) {
	const raw = "[Interface]\nPrivateKey = private\n"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName("alice"),
			Namespace: "wirekube-system",
			Annotations: map[string]string{
				peerConfigPeerAnnotation: "alice",
			},
		},
		Data: map[string][]byte{peerConfigDataKey: []byte(raw)},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	s := newServer(c, time.Second, "wirekube-system")

	got, err := s.loadPeerConfig(context.Background(), "alice")
	if err != nil {
		t.Fatalf("loadPeerConfig: %v", err)
	}
	if got != raw {
		t.Fatalf("config = %q, want exact stored bytes %q", got, raw)
	}
}

func TestSavePeerConfigSetsOwnerReference(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := newServer(c, time.Second, "wirekube-system")
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice",
			UID:  types.UID("uid-alice"),
		},
	}

	if err := s.savePeerConfig(context.Background(), cr, "[Interface]\nPrivateKey = private\n"); err != nil {
		t.Fatalf("savePeerConfig: %v", err)
	}
	secret := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "wirekube-system", Name: peerConfigSecretName("alice")}, secret); err != nil {
		t.Fatalf("stored config secret not found: %v", err)
	}
	if len(secret.OwnerReferences) != 1 {
		t.Fatalf("ownerReferences = %#v, want one owner", secret.OwnerReferences)
	}
	owner := secret.OwnerReferences[0]
	if owner.Kind != "WireKubeExternalPeer" || owner.Name != "alice" || owner.UID != types.UID("uid-alice") {
		t.Fatalf("ownerReference = %#v", owner)
	}
}

func TestDeletePeerRejectsMissingCSRF(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "alice"}}).
		Build()
	s := newServer(c, time.Second, "wirekube-system")

	req := formRequest(http.MethodPost, "/peers/alice/delete", nil)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "alice"}, cr); err != nil {
		t.Fatalf("peer deleted after csrf rejection: %v", err)
	}
}

func activePeer(ctx context.Context, c client.Client, name string, _ time.Duration) (*wirekubev1alpha1.WireKubeExternalPeer, error) {
	active := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Now()),
		},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			TTL: &metav1.Duration{Duration: 24 * time.Hour},
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:      "100.64.0.10/32",
			RelayEndpoint:       "vpn.example.com:3478",
			IngressPublicKey:    "ingress-public-key",
			AllowedDestinations: []string{"100.64.0.0/16"},
			MTU:                 1248,
			Phase:               wirekubev1alpha1.ExternalPeerPhaseActive,
		},
	}
	current := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, current); err == nil {
		current.Status = active.Status
		if current.Spec.TTL == nil {
			current.Spec.TTL = active.Spec.TTL
		}
		if current.CreationTimestamp.IsZero() {
			current.CreationTimestamp = active.CreationTimestamp
		}
		if updateErr := c.Update(ctx, current); updateErr == nil {
			return current, nil
		}
	}
	return active, nil
}

func formRequest(method, target string, values url.Values) *http.Request {
	body := ""
	if values != nil {
		body = values.Encode()
	}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}
