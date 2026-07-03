package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/externalpeer"
	"github.com/wirekube/wirekube/pkg/wireguard"
)

const (
	csrfFieldName = "csrf_token"

	peerConfigDataKey        = "config"
	peerConfigLabelKey       = "wirekube.io/external-peer-config"
	peerConfigPeerAnnotation = "wirekube.io/external-peer-name"
	defaultSecretNamespace   = "wirekube-system"
)

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = wirekubev1alpha1.AddToScheme(scheme)
}

func main() {
	addr := flag.String("addr", envOrDefault("WIREKUBE_ADMIN_WEB_ADDR", "127.0.0.1:8080"), "HTTP listen address")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "optional kubeconfig path for local development")
	waitFor := flag.Duration("wait", envDuration("WIREKUBE_ADMIN_WEB_WAIT", 60*time.Second), "how long to wait for issued peers to become Active")
	secretNamespace := flag.String("secret-namespace", envOrDefault("WIREKUBE_ADMIN_WEB_SECRET_NAMESPACE", serviceAccountNamespace()), "namespace for stored WireGuard client configs")
	flag.Parse()

	cfg, err := restConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("kubernetes config: %v", err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	auth, err := loadBasicAuth()
	if err != nil {
		log.Fatalf("admin-web auth: %v", err)
	}

	// Enforce the safe invariant: the console can download private keys, so it
	// may only run without authentication when bound to loopback. A non-loopback
	// bind with auth disabled is refused rather than silently exposed.
	if auth == nil && !isLoopbackAddr(*addr) {
		log.Fatalf("refusing to start: admin-web is bound to non-loopback address %q with authentication disabled; set WIREKUBE_ADMIN_WEB_USERNAME and WIREKUBE_ADMIN_WEB_PASSWORD_HASH", *addr)
	}

	s := newServer(c, *waitFor, *secretNamespace)
	s.auth = auth
	if auth == nil {
		log.Printf("WARNING: admin-web authentication is DISABLED; set WIREKUBE_ADMIN_WEB_USERNAME and WIREKUBE_ADMIN_WEB_PASSWORD_HASH to require login")
	} else {
		log.Printf("admin-web authentication enabled for user %q", auth.username)
	}
	log.Printf("wirekube-admin-web listening on %s", *addr)
	if err := http.ListenAndServe(*addr, s.routes()); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// basicAuthConfig holds HTTP Basic Auth credentials sourced from the
// environment (injected from a Kubernetes Secret). A nil *basicAuthConfig
// means authentication is disabled.
type basicAuthConfig struct {
	username     string
	passwordHash []byte // bcrypt hash of the password
}

// isLoopbackAddr reports whether a listen address binds only the loopback
// interface. An empty or wildcard host (":8080", "0.0.0.0:8080") is not
// loopback — it binds all interfaces — so it returns false.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loadBasicAuth reads credentials from the environment. Authentication is
// enabled only when both the username and the bcrypt password hash are set;
// setting exactly one is treated as a misconfiguration and is rejected so a
// deploy that intends to require auth never silently runs open.
func loadBasicAuth() (*basicAuthConfig, error) {
	user := os.Getenv("WIREKUBE_ADMIN_WEB_USERNAME")
	hash := os.Getenv("WIREKUBE_ADMIN_WEB_PASSWORD_HASH")
	if user == "" && hash == "" {
		return nil, nil
	}
	if user == "" || hash == "" {
		return nil, fmt.Errorf("both WIREKUBE_ADMIN_WEB_USERNAME and WIREKUBE_ADMIN_WEB_PASSWORD_HASH must be set to enable authentication")
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return nil, fmt.Errorf("WIREKUBE_ADMIN_WEB_PASSWORD_HASH is not a valid bcrypt hash: %w", err)
	}
	return &basicAuthConfig{username: user, passwordHash: []byte(hash)}, nil
}

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func serviceAccountNamespace() string {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return defaultSecretNamespace
	}
	ns := strings.TrimSpace(string(b))
	if ns == "" {
		return defaultSecretNamespace
	}
	return ns
}

type server struct {
	client          client.Client
	waitFor         time.Duration
	secretNamespace string
	auth            *basicAuthConfig
	csrfToken       string
	waitForActive   func(context.Context, client.Client, string, time.Duration) (*wirekubev1alpha1.WireKubeExternalPeer, error)
}

func newServer(c client.Client, waitFor time.Duration, secretNamespace string) *server {
	if secretNamespace == "" {
		secretNamespace = defaultSecretNamespace
	}
	return &server{
		client:          c,
		waitFor:         waitFor,
		secretNamespace: secretNamespace,
		csrfToken:       mustRandomToken(),
		waitForActive:   externalpeer.WaitForActive,
	}
}

func mustRandomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("generate csrf token: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	mux.HandleFunc("/relays", s.requireAuth(s.handleRelays))
	mux.HandleFunc("/mesh-nodes", s.requireAuth(s.handleMeshNodes))
	mux.HandleFunc("/mesh-nodes/", s.requireAuth(s.handleMeshNodeAction))
	mux.HandleFunc("/peers", s.requireAuth(s.handlePeers))
	mux.HandleFunc("/peers/delete", s.requireAuth(s.handleBulkDelete))
	mux.HandleFunc("/peers/", s.requireAuth(s.handlePeerAction))
	return mux
}

// requireAuth wraps a handler with HTTP Basic Auth when credentials are
// configured. When s.auth is nil, authentication is disabled and the handler
// runs unguarded (the operator was warned at startup). The bcrypt password
// comparison is run on every request regardless of whether the username
// matched, so its fixed cost dominates response timing and hides whether the
// username was correct.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil {
			next(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok {
			s.challengeAuth(w)
			return
		}
		userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.auth.username)) == 1
		passMatch := bcrypt.CompareHashAndPassword(s.auth.passwordHash, []byte(pass)) == nil
		if !userMatch || !passMatch {
			s.challengeAuth(w)
			return
		}
		next(w, r)
	}
}

func (s *server) challengeAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="wirekube-admin", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, r, http.StatusOK, pageData{
		ActiveView: "peers",
		Notice:     r.URL.Query().Get("notice"),
	})
}

func (s *server) handleRelays(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, r, http.StatusOK, pageData{
		ActiveView: "relays",
		Notice:     r.URL.Query().Get("notice"),
	})
}

func (s *server) handleMeshNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, r, http.StatusOK, pageData{
		ActiveView: "mesh",
		Notice:     r.URL.Query().Get("notice"),
	})
}

func (s *server) handleMeshNodeAction(w http.ResponseWriter, r *http.Request) {
	name, action := meshNodePathAction(r.URL.Path)
	if name == "" || action == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch action {
	case "connections":
		s.viewMeshNodeConnections(w, r, name)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.render(w, r, http.StatusOK, pageData{ActiveView: "peers"})
	case http.MethodPost:
		s.issuePeer(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePeerAction(w http.ResponseWriter, r *http.Request) {
	name, action := peerPathAction(r.URL.Path)
	if name == "" || action == "" {
		http.NotFound(w, r)
		return
	}

	switch action {
	case "config":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.viewPeerConfig(w, r, name)
	case "delete":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !s.verifyMutation(w, r) {
			return
		}
		if err := externalpeer.Delete(r.Context(), s.client, name); err != nil {
			s.render(w, r, http.StatusInternalServerError, pageData{Error: err.Error()})
			return
		}
		if err := s.deletePeerConfig(r.Context(), name); err != nil {
			s.render(w, r, http.StatusInternalServerError, pageData{Error: fmt.Sprintf("revoked %s; deleting stored config failed: %v", name, err)})
			return
		}
		http.Redirect(w, r, "/?notice="+url.QueryEscape("revoked "+name), http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) handleBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.verifyMutation(w, r) {
		return
	}
	names := uniquePeerNames(r.Form["peers"])
	if len(names) == 0 {
		s.render(w, r, http.StatusBadRequest, pageData{
			ActiveView: "peers",
			Error:      "select at least one peer to revoke",
		})
		return
	}

	var errs []string
	for _, name := range names {
		if err := validatePeerName(name); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := externalpeer.Delete(r.Context(), s.client, name); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if err := s.deletePeerConfig(r.Context(), name); err != nil {
			errs = append(errs, fmt.Sprintf("%s config: %v", name, err))
		}
	}
	if len(errs) > 0 {
		s.render(w, r, http.StatusInternalServerError, pageData{
			ActiveView: "peers",
			Error:      "bulk revoke failed: " + strings.Join(errs, "; "),
		})
		return
	}
	http.Redirect(w, r, "/?notice="+url.QueryEscape(fmt.Sprintf("revoked %d peer(s)", len(names))), http.StatusSeeOther)
}

func peerPathAction(path string) (string, string) {
	rest := strings.Trim(strings.TrimPrefix(path, "/peers/"), "/")
	for _, action := range []string{"config", "delete"} {
		suffix := "/" + action
		if strings.HasSuffix(rest, suffix) {
			name := strings.Trim(strings.TrimSuffix(rest, suffix), "/")
			return name, action
		}
	}
	return "", ""
}

func meshNodePathAction(path string) (string, string) {
	rest := strings.Trim(strings.TrimPrefix(path, "/mesh-nodes/"), "/")
	if strings.HasSuffix(rest, "/connections") {
		name := strings.Trim(strings.TrimSuffix(rest, "/connections"), "/")
		return name, "connections"
	}
	return "", ""
}

func (s *server) viewMeshNodeConnections(w http.ResponseWriter, r *http.Request, name string) {
	if err := validatePeerName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := s.client.Get(r.Context(), client.ObjectKey{Name: name}, peer); err != nil {
		status := http.StatusInternalServerError
		if apierrors.IsNotFound(err) {
			status = http.StatusNotFound
		}
		http.Error(w, fmt.Sprintf("get mesh node: %v", err), status)
		return
	}
	items := sortedConnectionItems(peer.Status.Connections)
	resp := meshConnectionsResponse{
		Node:        name,
		Total:       len(items),
		Summary:     summarizeConnections(peer.Status.Connections),
		Counts:      connectionCounts(items),
		Connections: items,
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("encode mesh node connections: %v", err)
	}
}

func (s *server) viewPeerConfig(w http.ResponseWriter, r *http.Request, name string) {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := s.client.Get(r.Context(), client.ObjectKey{Name: name}, cr); err != nil {
		status := http.StatusInternalServerError
		if apierrors.IsNotFound(err) {
			status = http.StatusNotFound
		}
		s.render(w, r, status, pageData{Error: fmt.Sprintf("get external peer: %v", err)})
		return
	}
	conf, err := s.loadPeerConfig(r.Context(), name)
	if err != nil {
		status := http.StatusInternalServerError
		if apierrors.IsNotFound(err) {
			status = http.StatusNotFound
		}
		s.render(w, r, status, pageData{Error: fmt.Sprintf("stored config unavailable for %s: %v", name, err)})
		return
	}
	qr, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		s.render(w, r, http.StatusInternalServerError, pageData{Error: fmt.Sprintf("encode QR: %v", err)})
		return
	}
	s.render(w, r, http.StatusOK, pageData{
		Issued: issuedPeerFromCR(name, conf, qr, cr),
	})
}

func (s *server) issuePeer(w http.ResponseWriter, r *http.Request) {
	if !s.verifyMutation(w, r) {
		return
	}
	spec, err := issueSpecFromForm(r)
	if err != nil {
		s.render(w, r, http.StatusBadRequest, pageData{Error: err.Error()})
		return
	}
	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		s.render(w, r, http.StatusInternalServerError, pageData{Error: fmt.Sprintf("generate keypair: %v", err)})
		return
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: wirekubev1alpha1.GroupVersion.String(),
			Kind:       "WireKubeExternalPeer",
		},
		ObjectMeta: metav1.ObjectMeta{Name: spec.Name},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			DisplayName:         spec.DisplayName,
			PublicKey:           kp.PublicKeyBase64(),
			AllowedDestinations: spec.AllowedDestinations,
			IngressPeer:         spec.IngressPeer,
			MTU:                 spec.MTU,
		},
	}
	if spec.TTL > 0 {
		cr.Spec.TTL = &metav1.Duration{Duration: spec.TTL}
	}
	if err := s.client.Create(r.Context(), cr); err != nil {
		s.render(w, r, http.StatusInternalServerError, pageData{Error: fmt.Sprintf("create external peer: %v", err)})
		return
	}
	active, err := s.waitForActive(r.Context(), s.client, spec.Name, s.waitFor)
	if err != nil {
		cleanupErr := s.cleanupCreatedPeer(r.Context(), spec.Name)
		msg := fmt.Sprintf("peer did not become Active: %v", err)
		if cleanupErr != nil {
			msg = fmt.Sprintf("%s; cleanup failed: %v", msg, cleanupErr)
		}
		s.render(w, r, http.StatusGatewayTimeout, pageData{Error: msg})
		return
	}
	conf := externalpeer.RenderConfig(kp.PrivateKeyBase64(), active)
	if err := s.savePeerConfig(r.Context(), active, conf); err != nil {
		cleanupErr := s.cleanupCreatedPeer(r.Context(), spec.Name)
		msg := fmt.Sprintf("store peer config: %v", err)
		if cleanupErr != nil {
			msg = fmt.Sprintf("%s; cleanup failed: %v", msg, cleanupErr)
		}
		s.render(w, r, http.StatusInternalServerError, pageData{Error: msg})
		return
	}
	qr, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		cleanupErr := s.cleanupCreatedPeer(r.Context(), spec.Name)
		msg := fmt.Sprintf("encode QR: %v", err)
		if cleanupErr != nil {
			msg = fmt.Sprintf("%s; cleanup failed: %v", msg, cleanupErr)
		}
		s.render(w, r, http.StatusInternalServerError, pageData{Error: msg})
		return
	}
	s.render(w, r, http.StatusOK, pageData{
		Issued: issuedPeerFromCR(spec.Name, conf, qr, active),
	})
}

func (s *server) cleanupCreatedPeer(ctx context.Context, name string) error {
	if err := s.deletePeerConfig(ctx, name); err != nil {
		return err
	}
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := s.client.Get(ctx, client.ObjectKey{Name: name}, cr); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	if err := s.client.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (s *server) savePeerConfig(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, conf string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName(cr.Name),
			Namespace: s.secretNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/part-of":   "wirekube",
				"app.kubernetes.io/component": "admin-web",
				peerConfigLabelKey:            "true",
			},
			Annotations: map[string]string{
				peerConfigPeerAnnotation: cr.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			peerConfigDataKey: []byte(conf),
		},
	}
	if cr.UID != "" {
		secret.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: wirekubev1alpha1.GroupVersion.String(),
			Kind:       "WireKubeExternalPeer",
			Name:       cr.Name,
			UID:        cr.UID,
		}}
	}
	if err := s.client.Create(ctx, secret); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		current := &corev1.Secret{}
		key := client.ObjectKey{Namespace: s.secretNamespace, Name: secret.Name}
		if getErr := s.client.Get(ctx, key, current); getErr != nil {
			return getErr
		}
		if current.Labels == nil {
			current.Labels = map[string]string{}
		}
		for k, v := range secret.Labels {
			current.Labels[k] = v
		}
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		for k, v := range secret.Annotations {
			current.Annotations[k] = v
		}
		if len(secret.OwnerReferences) > 0 {
			current.OwnerReferences = secret.OwnerReferences
		}
		current.Type = corev1.SecretTypeOpaque
		current.Data = map[string][]byte{
			peerConfigDataKey: []byte(conf),
		}
		return s.client.Update(ctx, current)
	}
	return nil
}

func (s *server) loadPeerConfig(ctx context.Context, name string) (string, error) {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Namespace: s.secretNamespace, Name: peerConfigSecretName(name)}
	if err := s.client.Get(ctx, key, secret); err != nil {
		return "", err
	}
	conf, err := peerConfigFromSecret(secret, name)
	if err != nil {
		return "", err
	}
	return conf, nil
}

func peerConfigFromSecret(secret *corev1.Secret, name string) (string, error) {
	if owner := secret.Annotations[peerConfigPeerAnnotation]; owner != "" && owner != name {
		return "", fmt.Errorf("secret %s/%s is not recorded for peer %s", secret.Namespace, secret.Name, name)
	}
	conf := string(secret.Data[peerConfigDataKey])
	if strings.TrimSpace(conf) == "" {
		return "", fmt.Errorf("secret %s/%s has no %q data", secret.Namespace, secret.Name, peerConfigDataKey)
	}
	return conf, nil
}

func (s *server) deletePeerConfig(ctx context.Context, name string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      peerConfigSecretName(name),
			Namespace: s.secretNamespace,
		},
	}
	if err := s.client.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (s *server) peerConfigAvailable(ctx context.Context, name string) (bool, error) {
	secret := &corev1.Secret{}
	key := client.ObjectKey{Namespace: s.secretNamespace, Name: peerConfigSecretName(name)}
	if err := s.client.Get(ctx, key, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if _, err := peerConfigFromSecret(secret, name); err != nil {
		return false, nil
	}
	return true, nil
}

func peerConfigSecretName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "wkep-config-" + hex.EncodeToString(sum[:])[:16]
}

func (s *server) verifyMutation(w http.ResponseWriter, r *http.Request) bool {
	if !sameOrigin(r) {
		s.render(w, r, http.StatusForbidden, pageData{Error: "forbidden origin"})
		return false
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, r, http.StatusBadRequest, pageData{Error: fmt.Sprintf("parse form: %v", err)})
		return false
	}
	token := r.FormValue(csrfFieldName)
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.csrfToken)) != 1 {
		s.render(w, r, http.StatusForbidden, pageData{Error: "invalid csrf token"})
		return false
	}
	return true
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

type issueSpec struct {
	Name                string
	DisplayName         string
	AllowedDestinations []string
	IngressPeer         string
	TTL                 time.Duration
	MTU                 int32
}

func issueSpecFromForm(r *http.Request) (issueSpec, error) {
	name := strings.TrimSpace(r.FormValue("name"))
	if err := validatePeerName(name); err != nil {
		return issueSpec{}, err
	}
	displayName := strings.TrimSpace(r.FormValue("displayName"))
	if displayName == "" {
		displayName = name
	}
	ttl, err := parseOptionalDuration(r.FormValue("ttl"))
	if err != nil {
		return issueSpec{}, err
	}
	mtu, err := parseOptionalMTU(r.FormValue("mtu"))
	if err != nil {
		return issueSpec{}, err
	}
	allowed, err := parseOptionalCIDRs(r.FormValue("allowed"))
	if err != nil {
		return issueSpec{}, err
	}
	return issueSpec{
		Name:                name,
		DisplayName:         displayName,
		AllowedDestinations: allowed,
		IngressPeer:         strings.TrimSpace(r.FormValue("ingressPeer")),
		TTL:                 ttl,
		MTU:                 mtu,
	}, nil
}

func validatePeerName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("invalid name: %s", strings.Join(errs, "; "))
	}
	return nil
}

func uniquePeerNames(raw []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, name := range raw {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func parseOptionalDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl: %w", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("ttl must be >= 0")
	}
	return d, nil
}

func parseOptionalMTU(raw string) (int32, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid mtu: %w", err)
	}
	if n < 576 || n > 1420 {
		return 0, fmt.Errorf("mtu must be between 576 and 1420")
	}
	return int32(n), nil
}

func parseOptionalCIDRs(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, err := netip.ParsePrefix(f); err != nil {
			return nil, fmt.Errorf("invalid allowed IPs CIDR %q: %w", f, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, data pageData) {
	if data.ActiveView == "" {
		data.ActiveView = "peers"
	}
	rows, err := s.peerRows(r.Context())
	if err != nil && data.Error == "" {
		data.Error = err.Error()
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
	}
	data.Peers = rows
	data.CSRFToken = s.csrfToken
	data.Counts = phaseCounts(rows)
	data.TotalPeers = len(rows)
	data.ViewTitle, data.ViewDescription = viewCopy(data.ActiveView)
	data.RefreshPath = refreshPath(data.ActiveView)

	switch data.ActiveView {
	case "relays":
		pods, services, deployments, relayErr := s.relayRows(r.Context())
		if relayErr != nil && data.Error == "" {
			data.Error = relayErr.Error()
			if status == http.StatusOK {
				status = http.StatusInternalServerError
			}
		}
		data.RelayPods = pods
		data.RelayServices = services
		data.RelayDeployments = deployments
		data.TotalRelays = len(pods)
	case "mesh":
		meshes, meshNodes, meshErr := s.meshRows(r.Context())
		if meshErr != nil && data.Error == "" {
			data.Error = meshErr.Error()
			if status == http.StatusOK {
				status = http.StatusInternalServerError
			}
		}
		data.Meshes = meshes
		data.MeshNodes = meshNodes
		data.TotalMeshNodes = len(meshNodes)
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, data); err != nil {
		log.Printf("render: %v", err)
	}
}

func (s *server) peerRows(ctx context.Context) ([]peerRow, error) {
	list := &wirekubev1alpha1.WireKubeExternalPeerList{}
	if err := s.client.List(ctx, list); err != nil {
		return nil, fmt.Errorf("list external peers: %w", err)
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].Name < list.Items[j].Name
	})
	now := time.Now()
	rows := make([]peerRow, 0, len(list.Items))
	for i := range list.Items {
		p := &list.Items[i]
		hasConfig, err := s.peerConfigAvailable(ctx, p.Name)
		if err != nil {
			return nil, fmt.Errorf("check stored config for %s: %w", p.Name, err)
		}
		phase := string(p.Status.Phase)
		if phase == "" {
			phase = string(wirekubev1alpha1.ExternalPeerPhasePending)
		}
		allowed := p.Status.AllowedDestinations
		if len(allowed) == 0 {
			allowed = p.Spec.AllowedDestinations
		}
		rows = append(rows, peerRow{
			Name:        p.Name,
			DisplayName: dash(p.Spec.DisplayName),
			Phase:       phase,
			PhaseClass:  strings.ToLower(phase),
			MeshIP:      dash(p.Status.AssignedMeshIP),
			Endpoint:    dash(p.Status.RelayEndpoint),
			Ingress:     dash(p.Status.IngressPeerName),
			Allowed:     dash(strings.Join(allowed, ", ")),
			MTU:         externalpeer.EffectiveMTU(p),
			Age:         formatAge(now.Sub(p.CreationTimestamp.Time), !p.CreationTimestamp.IsZero()),
			Message:     externalpeer.LastConditionMessage(p.Status.Conditions),
			HasConfig:   hasConfig,
		})
	}
	return rows, nil
}

func (s *server) relayRows(ctx context.Context) ([]relayPodRow, []relayServiceRow, []relayDeploymentRow, error) {
	ns := s.secretNamespace
	podList := &corev1.PodList{}
	if err := s.client.List(ctx, podList,
		client.InNamespace(ns),
		client.MatchingLabels{"app.kubernetes.io/name": "wirekube-relay"},
	); err != nil {
		return nil, nil, nil, fmt.Errorf("list relay pods: %w", err)
	}
	serviceList := &corev1.ServiceList{}
	if err := s.client.List(ctx, serviceList,
		client.InNamespace(ns),
		client.MatchingLabels{"app.kubernetes.io/name": "wirekube-relay"},
	); err != nil {
		return nil, nil, nil, fmt.Errorf("list relay services: %w", err)
	}
	deploymentList := &appsv1.DeploymentList{}
	if err := s.client.List(ctx, deploymentList,
		client.InNamespace(ns),
		client.MatchingLabels{"app.kubernetes.io/name": "wirekube-relay"},
	); err != nil {
		return nil, nil, nil, fmt.Errorf("list relay deployments: %w", err)
	}

	now := time.Now()
	sort.Slice(podList.Items, func(i, j int) bool { return podList.Items[i].Name < podList.Items[j].Name })
	sort.Slice(serviceList.Items, func(i, j int) bool { return serviceList.Items[i].Name < serviceList.Items[j].Name })
	sort.Slice(deploymentList.Items, func(i, j int) bool { return deploymentList.Items[i].Name < deploymentList.Items[j].Name })

	pods := make([]relayPodRow, 0, len(podList.Items))
	for i := range podList.Items {
		p := &podList.Items[i]
		ready, restarts := podReadySummary(p)
		status := string(p.Status.Phase)
		if status == "" {
			status = "Unknown"
		}
		pods = append(pods, relayPodRow{
			Name:        p.Name,
			Status:      status,
			StatusClass: statusClass(status),
			Ready:       ready,
			Restarts:    restarts,
			Node:        dash(p.Spec.NodeName),
			PodIP:       dash(p.Status.PodIP),
			HostIP:      dash(p.Status.HostIP),
			Age:         formatAge(now.Sub(p.CreationTimestamp.Time), !p.CreationTimestamp.IsZero()),
		})
	}

	services := make([]relayServiceRow, 0, len(serviceList.Items))
	for i := range serviceList.Items {
		svc := &serviceList.Items[i]
		services = append(services, relayServiceRow{
			Name:      svc.Name,
			Type:      string(svc.Spec.Type),
			ClusterIP: dash(svc.Spec.ClusterIP),
			External:  serviceExternal(svc),
			Ports:     servicePorts(svc),
			Age:       formatAge(now.Sub(svc.CreationTimestamp.Time), !svc.CreationTimestamp.IsZero()),
		})
	}

	deployments := make([]relayDeploymentRow, 0, len(deploymentList.Items))
	for i := range deploymentList.Items {
		d := &deploymentList.Items[i]
		deployments = append(deployments, relayDeploymentRow{
			Name:      d.Name,
			Ready:     fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, replicasOrZero(d.Spec.Replicas)),
			Updated:   fmt.Sprintf("%d", d.Status.UpdatedReplicas),
			Available: fmt.Sprintf("%d", d.Status.AvailableReplicas),
			Age:       formatAge(now.Sub(d.CreationTimestamp.Time), !d.CreationTimestamp.IsZero()),
		})
	}

	return pods, services, deployments, nil
}

func (s *server) meshRows(ctx context.Context) ([]meshRow, []meshNodeRow, error) {
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if err := s.client.List(ctx, meshList); err != nil {
		return nil, nil, fmt.Errorf("list meshes: %w", err)
	}
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := s.client.List(ctx, peerList); err != nil {
		return nil, nil, fmt.Errorf("list mesh nodes: %w", err)
	}

	now := time.Now()
	sort.Slice(meshList.Items, func(i, j int) bool { return meshList.Items[i].Name < meshList.Items[j].Name })
	sort.Slice(peerList.Items, func(i, j int) bool { return peerList.Items[i].Name < peerList.Items[j].Name })

	meshes := make([]meshRow, 0, len(meshList.Items))
	for i := range meshList.Items {
		m := &meshList.Items[i]
		meshes = append(meshes, meshRow{
			Name:      m.Name,
			Listen:    formatInt32(m.Spec.ListenPort),
			Interface: dash(m.Spec.InterfaceName),
			MTU:       formatInt32(m.Spec.MTU),
			MeshCIDR:  dash(m.Spec.MeshCIDR),
			Relay:     relaySummary(m.Spec.Relay),
			Ready:     fmt.Sprintf("%d/%d", m.Status.ReadyPeers, m.Status.TotalPeers),
			Age:       formatAge(now.Sub(m.CreationTimestamp.Time), !m.CreationTimestamp.IsZero()),
		})
	}

	nodes := make([]meshNodeRow, 0, len(peerList.Items))
	for i := range peerList.Items {
		p := &peerList.Items[i]
		status := "NotReady"
		if p.Status.Connected {
			status = "Ready"
		} else if len(p.Status.Connections) > 0 {
			status = "Degraded"
		}
		nodes = append(nodes, meshNodeRow{
			Name:               p.Name,
			Status:             status,
			StatusClass:        status,
			Endpoint:           dash(p.Spec.Endpoint),
			Allowed:            dash(strings.Join(p.Spec.AllowedIPs, ", ")),
			NAT:                dash(p.Status.NATType),
			ICE:                dash(p.Status.ICEState),
			ConnectionsSummary: summarizeConnections(p.Status.Connections),
			Age:                formatAge(now.Sub(p.CreationTimestamp.Time), !p.CreationTimestamp.IsZero()),
		})
	}

	return meshes, nodes, nil
}

type pageData struct {
	ActiveView       string
	ViewTitle        string
	ViewDescription  string
	RefreshPath      string
	Peers            []peerRow
	Issued           *issuedPeer
	Error            string
	Notice           string
	CSRFToken        string
	Counts           map[string]int
	TotalPeers       int
	RelayPods        []relayPodRow
	RelayServices    []relayServiceRow
	RelayDeployments []relayDeploymentRow
	TotalRelays      int
	Meshes           []meshRow
	MeshNodes        []meshNodeRow
	TotalMeshNodes   int
}

type peerRow struct {
	Name        string
	DisplayName string
	Phase       string
	PhaseClass  string
	MeshIP      string
	Endpoint    string
	Ingress     string
	Allowed     string
	MTU         int32
	Age         string
	Message     string
	HasConfig   bool
}

type relayPodRow struct {
	Name        string
	Status      string
	StatusClass string
	Ready       string
	Restarts    string
	Node        string
	PodIP       string
	HostIP      string
	Age         string
}

type relayServiceRow struct {
	Name      string
	Type      string
	ClusterIP string
	External  string
	Ports     string
	Age       string
}

type relayDeploymentRow struct {
	Name      string
	Ready     string
	Updated   string
	Available string
	Age       string
}

type meshRow struct {
	Name      string
	Listen    string
	Interface string
	MTU       string
	MeshCIDR  string
	Relay     string
	Ready     string
	Age       string
}

type meshNodeRow struct {
	Name               string
	Status             string
	StatusClass        string
	Endpoint           string
	Allowed            string
	NAT                string
	ICE                string
	ConnectionsSummary string
	Age                string
}

type meshConnectionItem struct {
	Peer   string `json:"peer"`
	Status string `json:"status"`
}

type meshConnectionsResponse struct {
	Node        string               `json:"node"`
	Total       int                  `json:"total"`
	Summary     string               `json:"summary"`
	Counts      map[string]int       `json:"counts"`
	Connections []meshConnectionItem `json:"connections"`
}

type issuedPeer struct {
	Name     string
	Config   string
	QR       template.URL
	MeshIP   string
	Endpoint string
	MTU      int32
	Allowed  string
	TTL      string
	Expires  string
	FileName string
}

func viewCopy(activeView string) (string, string) {
	switch activeView {
	case "relays":
		return "Relays", "Relay deployment, pod, and service state visible to the admin-web sidecar."
	case "mesh":
		return "Mesh nodes", "WireKube mesh resources and node peer state reported by the cluster."
	default:
		return "External peers", "WireGuard client peers issued by this relay. Configs are stored in Kubernetes Secrets so they can be reopened later."
	}
}

func refreshPath(activeView string) string {
	switch activeView {
	case "relays":
		return "/relays"
	case "mesh":
		return "/mesh-nodes"
	default:
		return "/"
	}
}

func issuedPeerFromCR(name, conf string, qr []byte, cr *wirekubev1alpha1.WireKubeExternalPeer) *issuedPeer {
	allowed := cr.Status.AllowedDestinations
	if len(allowed) == 0 {
		allowed = []string{cr.Status.AssignedMeshIP}
	}
	ttl := "-"
	expires := "-"
	if cr.Spec.TTL != nil && cr.Spec.TTL.Duration > 0 {
		ttl = cr.Spec.TTL.Duration.String()
		if !cr.CreationTimestamp.IsZero() {
			expires = cr.CreationTimestamp.Time.Add(cr.Spec.TTL.Duration).UTC().Format(time.RFC3339)
		}
	}
	return &issuedPeer{
		Name:     name,
		Config:   conf,
		QR:       template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(qr)), //nolint:gosec
		MeshIP:   dash(cr.Status.AssignedMeshIP),
		Endpoint: dash(cr.Status.RelayEndpoint),
		MTU:      externalpeer.EffectiveMTU(cr),
		Allowed:  strings.Join(allowed, ", "),
		TTL:      ttl,
		Expires:  expires,
		FileName: name + ".conf",
	}
}

func phaseCounts(rows []peerRow) map[string]int {
	counts := map[string]int{
		"Active":  0,
		"Pending": 0,
		"Failed":  0,
		"Revoked": 0,
	}
	for _, row := range rows {
		counts[row.Phase]++
	}
	return counts
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatAge(d time.Duration, ok bool) string {
	if !ok {
		return "-"
	}
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func statusClass(status string) string {
	switch status {
	case "Running", "Ready", "Active":
		return "Active"
	case "Pending", "Degraded":
		return "Pending"
	case "Succeeded":
		return "Expired"
	default:
		return "Failed"
	}
}

func podReadySummary(p *corev1.Pod) (string, string) {
	total := len(p.Status.ContainerStatuses)
	ready := 0
	restarts := int32(0)
	for _, st := range p.Status.ContainerStatuses {
		if st.Ready {
			ready++
		}
		restarts += st.RestartCount
	}
	if total == 0 {
		total = len(p.Spec.Containers)
	}
	return fmt.Sprintf("%d/%d", ready, total), fmt.Sprintf("%d", restarts)
}

func serviceExternal(svc *corev1.Service) string {
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			return "pending"
		}
		return "-"
	}
	out := make([]string, 0, len(svc.Status.LoadBalancer.Ingress))
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.Hostname != "" {
			out = append(out, ing.Hostname)
			continue
		}
		if ing.IP != "" {
			out = append(out, ing.IP)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ", ")
}

func servicePorts(svc *corev1.Service) string {
	if len(svc.Spec.Ports) == 0 {
		return "-"
	}
	ports := make([]string, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		name := p.Name
		if name == "" {
			name = strings.ToLower(string(p.Protocol))
		}
		ports = append(ports, fmt.Sprintf("%s:%d/%s", name, p.Port, p.Protocol))
	}
	return strings.Join(ports, ", ")
}

func replicasOrZero(replicas *int32) int32 {
	if replicas == nil {
		return 0
	}
	return *replicas
}

func formatInt32(v int32) string {
	if v == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", v)
}

func relaySummary(relay *wirekubev1alpha1.RelaySpec) string {
	if relay == nil {
		return "-"
	}
	provider := dash(relay.Provider)
	mode := dash(relay.Mode)
	if relay.External != nil && relay.External.Endpoint != "" {
		return fmt.Sprintf("%s/%s %s", provider, mode, relay.External.Endpoint)
	}
	if relay.Managed != nil {
		port := relay.Managed.Port
		if port == 0 {
			port = 3478
		}
		return fmt.Sprintf("%s/%s :%d", provider, mode, port)
	}
	return fmt.Sprintf("%s/%s", provider, mode)
}

func sortedConnectionItems(connections map[string]string) []meshConnectionItem {
	if len(connections) == 0 {
		return nil
	}
	keys := make([]string, 0, len(connections))
	for k := range connections {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]meshConnectionItem, 0, len(keys))
	for _, k := range keys {
		out = append(out, meshConnectionItem{Peer: k, Status: connectionStatus(connections[k])})
	}
	return out
}

func connectionStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "unknown"
	}
	return status
}

func connectionCounts(items []meshConnectionItem) map[string]int {
	out := make(map[string]int)
	for _, item := range items {
		out[item.Status]++
	}
	return out
}

func summarizeConnections(connections map[string]string) string {
	items := sortedConnectionItems(connections)
	if len(items) == 0 {
		return "-"
	}
	counts := connectionCounts(items)
	statuses := make([]string, 0, len(counts))
	for status := range counts {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%s: %d", status, counts[status]))
	}
	return fmt.Sprintf("%d total (%s)", len(items), strings.Join(parts, ", "))
}

var pageTemplate = template.Must(template.New("page").Parse(pageHTML))

const pageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WireKube</title>
  <style>

  /* ─── tokens ─────────────────────────────────────────────────────── */
  :root{
    /* surfaces */
    --page:        #f6f8fb;
    --surface:     #ffffff;
    --surface-sub: #f9fafb;
    --surface-alt: #f3f6fa;

    /* text */
    --fg:          #111827;
    --fg-muted:    #4b5563;
    --fg-subtle:   #6b7280;
    --fg-faint:    #9ca3af;

    /* lines */
    --line:        #e5e7eb;
    --line-strong: #d8dee8;
    --line-soft:   #eef1f5;

    /* table + interaction */
    --table-head:  #f8fafc;
    --row-bg:      #ffffff;
    --row-hover:   #f5f8fc;
    --row-selected:#eef4ff;
    --row-active:  #e8f1ff;
    --accent:      #1f2937;
    --accent-fg:   #ffffff;
    --focus-ring:  rgba(37, 99, 235, 0.22);

    /* status */
    --ok:          #15803d;
    --ok-bg:       #f0fdf4;
    --ok-line:     #bbf7d0;
    --warn:        #a16207;
    --warn-bg:     #fffbeb;
    --warn-line:   #fde68a;
    --danger:      #b91c1c;
    --danger-bg:   #fef2f2;
    --danger-line: #fecaca;
    --info:        #2563eb;
    --info-bg:     #eff6ff;
    --info-line:   #bfdbfe;

    /* legacy aliases used by the existing template */
    --bg:        var(--surface);
    --bg-sub:    var(--surface-sub);
    --bg-side:   var(--surface-alt);
    --hover:     var(--row-hover);
    --selected:  var(--row-selected);
    --fg-2:      var(--fg);
    --fg-3:      var(--fg-muted);
    --mute:      var(--fg-subtle);
    --faint:     var(--fg-faint);
    --line-2:    var(--line-strong);
    --line-3:    #c8d0dc;
    --row-line:  var(--line-soft);
    --acc:       var(--accent);
    --acc-fg:    var(--accent-fg);
    --acc-hov:   #111827;
    --acc-bg:    var(--row-selected);
    --acc-line:  var(--line-strong);

    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", Helvetica, Arial, sans-serif;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;

    --r: 6px;
    --r-sm: 4px;
  }
  html[data-theme="dark"]{
    --page:        #0f141b;
    --surface:     #151b23;
    --surface-sub: #1a212b;
    --surface-alt: #202936;

    --fg:          #e5e7eb;
    --fg-muted:    #cbd5e1;
    --fg-subtle:   #94a3b8;
    --fg-faint:    #64748b;

    --line:        #293241;
    --line-strong: #364152;
    --line-soft:   #232b38;

    --table-head:  #1a212b;
    --row-bg:      #151b23;
    --row-hover:   #1d2633;
    --row-selected:#1e3150;
    --row-active:  #243b61;
    --accent:      #e5e7eb;
    --accent-fg:   #111827;
    --focus-ring:  rgba(96, 165, 250, 0.28);

    --ok:          #4ade80;
    --ok-bg:       #0f2a1a;
    --ok-line:     #22543d;
    --warn:        #facc15;
    --warn-bg:     #2a2108;
    --warn-line:   #6b4e16;
    --danger:      #f87171;
    --danger-bg:   #2a1111;
    --danger-line: #7f1d1d;
    --info:        #60a5fa;
    --info-bg:     #10233f;
    --info-line:   #1d4ed8;

    --bg:        var(--surface);
    --bg-sub:    var(--surface-sub);
    --bg-side:   var(--surface-alt);
    --hover:     var(--row-hover);
    --selected:  var(--row-selected);
    --fg-2:      var(--fg);
    --fg-3:      var(--fg-muted);
    --mute:      var(--fg-subtle);
    --faint:     var(--fg-faint);
    --line-2:    var(--line-strong);
    --line-3:    #475569;
    --row-line:  var(--line-soft);
    --acc:       var(--accent);
    --acc-fg:    var(--accent-fg);
    --acc-hov:   #ffffff;
    --acc-bg:    var(--row-selected);
    --acc-line:  var(--line-strong);
  }

  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{
    background:var(--page);color:var(--fg);
    font:13px/1.45 var(--sans);
    -webkit-font-smoothing:antialiased;
    text-rendering:geometricPrecision;
    display:flex;
  }
  ::selection{background:var(--acc-bg);color:var(--fg)}

  /* ─── sidebar ────────────────────────────────────────────────────── */
  aside.side{
    flex:0 0 232px;
    height:100vh;position:sticky;top:0;
    background:var(--bg-side);
    border-right:1px solid var(--line);
    display:flex;flex-direction:column;
    overflow:hidden;
  }
  .side-brand{
    display:flex;align-items:center;
    padding:15px 14px 13px;
    border-bottom:1px solid var(--line);
  }
  .side-brand .name{
    font:600 14px/1 var(--sans);
    letter-spacing:-0.01em;color:var(--fg);
  }

  .side-cluster{
    padding:10px 12px;border-bottom:1px solid var(--line);
    font:11.5px/1.4 var(--sans);
  }
  .side-cluster .lbl{
    font:10px/1 var(--mono);color:var(--mute);
    letter-spacing:0.1em;text-transform:uppercase;
  }
  .side-cluster .ctx{
    margin-top:6px;
    display:flex;align-items:center;gap:8px;
    padding:7px 9px;border:1px solid var(--line-2);border-radius:var(--r-sm);
    background:var(--bg);
    cursor:pointer;width:100%;text-align:left;
    min-width:0;
  }
  .side-cluster .ctx:hover{border-color:var(--line-3)}
  .side-cluster .ctx .dot{
    width:6px;height:6px;border-radius:50%;background:var(--ok);
    flex:0 0 6px;
  }
  .side-cluster .ctx .info{
    flex:1;min-width:0;display:flex;flex-direction:column;gap:1px;
  }
  .side-cluster .ctx .info .nm{
    font:500 12.5px/1.2 var(--sans);color:var(--fg);
    letter-spacing:-0.005em;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  }
  .side-cluster .ctx .info .ns{
    font:11px/1.2 var(--mono);color:var(--mute);
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  }
  .side-cluster .ctx .chev{margin-left:auto;color:var(--faint);flex:0 0 10px}

  .side-nav{padding:8px 6px 6px;display:flex;flex-direction:column;gap:1px;flex:1;overflow:auto}
  .side-nav .group{
    padding:10px 8px 4px;
    font:10px/1 var(--mono);color:var(--mute);
    letter-spacing:0.12em;text-transform:uppercase;
  }
  .side-nav a{
    display:flex;align-items:center;gap:9px;
    padding:6px 8px;border-radius:var(--r-sm);
    color:var(--fg-3);text-decoration:none;
    font:500 12.5px/1 var(--sans);letter-spacing:-0.005em;
    cursor:pointer;
  }
  .side-nav a:hover{background:var(--hover);color:var(--fg)}
  .side-nav a.active{
    background:var(--selected);color:var(--fg);
    font-weight:600;
    box-shadow:inset 2px 0 0 var(--fg);
  }
  html[data-theme="dark"] .side-nav a.active{color:var(--fg);box-shadow:inset 2px 0 0 var(--fg)}
  .side-nav a svg{width:14px;height:14px;flex:0 0 14px;color:currentColor}
  .side-nav a .badge{
    margin-left:auto;
    font:10px/1 var(--mono);color:var(--mute);
    background:var(--bg);border:1px solid var(--line);
    border-radius:3px;padding:2px 5px;
  }
  .side-nav a.active .badge{
    background:var(--bg);color:var(--fg);border-color:var(--line-2);
  }

  .side-foot{
    border-top:1px solid var(--line);
    padding:10px 12px;
    font:11px/1.4 var(--mono);color:var(--mute);
    display:flex;align-items:center;gap:8px;
  }
  .side-foot .pf{
    display:inline-flex;align-items:center;gap:5px;
    color:var(--fg-3);
  }
  .side-foot .pf::before{
    content:"";width:5px;height:5px;border-radius:50%;background:var(--ok);
  }
  .side-foot .sep{color:var(--faint)}

  /* ─── main ──────────────────────────────────────────────────────── */
  main.main{flex:1;min-width:0;display:flex;flex-direction:column}

  .topbar{
    display:flex;align-items:center;gap:12px;
    height:48px;padding:0 18px;
    border-bottom:1px solid var(--line);
    background:var(--bg);
    flex:0 0 auto;
  }
  .crumbs{
    display:flex;align-items:center;gap:6px;
    font:13px/1 var(--sans);color:var(--fg-3);
  }
  .crumbs .sep{color:var(--faint);font-weight:400}
  .crumbs .cur{color:var(--fg);font-weight:600}
  .topbar .spacer{flex:1}

  /* ─── page header ───────────────────────────────────────────────── */
  .page{
    padding:18px 20px;
    border:1px solid var(--line);
    border-radius:var(--r);
    background:var(--bg);
  }
  .page-title{
    display:flex;align-items:flex-start;gap:14px;
  }
  .page-title h1{
    margin:0;font:600 20px/1.25 var(--sans);
    letter-spacing:-0.015em;color:var(--fg);
  }
  .page-title .desc{
    margin-top:4px;color:var(--mute);font-size:13px;max-width:60ch;
  }
  .page-title .actions{margin-left:auto;display:flex;align-items:center;gap:8px}

  /* ─── buttons ───────────────────────────────────────────────────── */
  .btn{
    display:inline-flex;align-items:center;justify-content:center;gap:6px;
    height:32px;padding:0 12px;
    background:var(--bg);color:var(--fg-2);
    border:1px solid var(--line-2);border-radius:var(--r-sm);
    font:500 12.5px/1 var(--sans);letter-spacing:-0.005em;
    cursor:pointer;
    transition:background .12s,border-color .12s,box-shadow .12s;
    white-space:nowrap;
  }
  .btn:hover{background:var(--bg-sub);border-color:var(--line-3);color:var(--fg)}
  .btn:focus-visible{outline:none;box-shadow:0 0 0 3px var(--focus-ring);border-color:var(--acc)}

  .btn-primary{
    background:var(--acc);color:var(--acc-fg);
    border-color:var(--acc);
    box-shadow:0 1px 0 rgba(0,0,0,.04);
    font-weight:600;
  }
  .btn-primary:hover{background:var(--acc-hov);border-color:var(--acc-hov);color:var(--acc-fg)}

  .btn-ghost{background:transparent;border-color:transparent;color:var(--fg-3)}
  .btn-ghost:hover{background:var(--hover);color:var(--fg);border-color:transparent}

  .btn-danger{color:var(--danger);background:var(--bg);border-color:var(--line-2)}
  .btn-danger:hover{background:var(--danger-bg);border-color:var(--danger-line);color:var(--danger)}
  .btn-danger.solid{background:var(--danger);color:#fff;border-color:var(--danger)}
  .btn-danger.solid:hover{background:#991b1b;border-color:#991b1b}

  .btn-sm{height:26px;padding:0 9px;font-size:12px}
  .btn-icon{padding:0;width:28px;height:28px;flex:0 0 28px}
  .btn-icon svg{width:13px;height:13px}

  /* ─── filter row above table ────────────────────────────────────── */
  .toolbar{
    display:flex;align-items:center;gap:10px;
    padding:10px 14px;background:var(--bg);
    border:1px solid var(--line);
    border-radius:var(--r);
  }
  .filter-chips{display:flex;align-items:center;gap:0;border:1px solid var(--line);border-radius:var(--r-sm);overflow:hidden;background:var(--bg-sub)}
  .filter-chips button{
    background:transparent;border:0;cursor:pointer;
    height:26px;padding:0 11px;
    font:500 12px/1 var(--sans);color:var(--fg-3);
    border-right:1px solid var(--line);
    display:inline-flex;align-items:center;gap:6px;
  }
  .filter-chips button:last-child{border-right:0}
  .filter-chips button:hover{color:var(--fg);background:var(--hover)}
  .filter-chips button.on{background:var(--bg);color:var(--fg);font-weight:600}
  .filter-chips .c{
    font:10.5px/1 var(--mono);color:var(--mute);
    padding:1px 5px;border-radius:3px;background:var(--bg);
    border:1px solid var(--line);
  }
  .filter-chips button.on .c{color:var(--fg-2);border-color:var(--line-2)}

  .toolbar .ts-search{
    flex:1;max-width:340px;
    display:flex;align-items:center;gap:7px;
    height:28px;padding:0 9px;
    background:var(--bg);border:1px solid var(--line);border-radius:var(--r-sm);
    color:var(--mute);
  }
  .toolbar .ts-search input{
    flex:1;border:0;background:transparent;outline:none;
    color:var(--fg);font:13px var(--sans);min-width:0;
  }
  .toolbar .spacer{flex:1}
  .toolbar .res-count{font:11.5px/1 var(--mono);color:var(--mute)}
  .toolbar form{margin:0;display:inline-flex;align-items:center}
  .bulk-check{
    display:inline-flex;
    align-items:center;
    gap:6px;
    font:12px/1 var(--sans);
    color:var(--fg-3);
    white-space:nowrap;
  }
  .section-label{
    padding:14px 24px 8px;
    font:600 12px/1 var(--sans);
    color:var(--fg);
    background:var(--surface-sub);
    border-top:1px solid var(--line);
    border-bottom:1px solid var(--line);
  }

  /* ─── table ─────────────────────────────────────────────────────── */
  .tbl-host{
    background:var(--bg);
    overflow:auto;flex:1;
    border:1px solid var(--line);
    border-radius:var(--r);
  }
  table.peers{
    width:100%;border-collapse:collapse;
    font-size:13px;
    table-layout:fixed;
  }
  table.peers th{
    text-align:left;
    font:500 11px/1 var(--sans);color:var(--mute);
    letter-spacing:0.02em;
    padding:9px 14px;
    background:var(--table-head);
    border-bottom:1px solid var(--row-line);
    position:sticky;top:0;z-index:1;
    white-space:nowrap;
    user-select:none;
  }
  table.peers th:first-child{padding-left:18px;padding-right:0}
  table.peers th:last-child{padding-right:24px}
  table.peers th.right{text-align:right}
  table.peers th .sortable{
    display:inline-flex;align-items:center;gap:4px;cursor:pointer;
  }
  table.peers th .sortable:hover{color:var(--fg-2)}
  table.peers th .sortable.on{color:var(--fg-2)}
  table.peers th .sortable .arr{opacity:.5;font-size:9px}

  table.peers td{
    padding:9px 14px;
    border-bottom:1px solid var(--row-line);
    vertical-align:middle;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
    color:var(--fg-2);
  }
  table.peers td:first-child{padding-left:18px;padding-right:0}
  table.peers td:last-child{padding-right:24px}
  body[data-density="compact"] table.peers td{padding:6px 14px}
  body[data-density="comfy"]    table.peers td{padding:13px 14px}

  table.peers tbody tr{background:var(--row-bg);transition:background .08s}
  table.peers tbody tr:hover{background:var(--row-hover)}
  table.peers tbody tr.clickable-row{cursor:pointer}
  table.peers tbody tr.clickable-row:focus-visible{
    outline:none;
    box-shadow:inset 0 0 0 2px var(--acc);
  }
  table.peers tr.armed{background:var(--danger-bg) !important}

  .col-sel{width:40px}
  .col-name{width:auto;min-width:200px}
  .col-phase{width:110px}
  .col-ip{width:140px}
  .col-endpoint{width:auto;min-width:200px}
  .col-age{width:80px}
  .col-act{width:220px}

  td.sel input{margin:0;cursor:pointer}

  /* ─── custom checkboxes (theme-aware) ──────────────────────────── */
  input[type="checkbox"]{
    appearance:none;-webkit-appearance:none;
    width:14px;height:14px;margin:0;
    border:1px solid var(--line-2);
    background:var(--bg);
    border-radius:3px;cursor:pointer;
    display:inline-block;vertical-align:middle;
    position:relative;flex:0 0 14px;
    transition:background .1s, border-color .1s, box-shadow .1s;
  }
  input[type="checkbox"]:hover{border-color:var(--line-3)}
  input[type="checkbox"]:focus-visible{
    outline:none;
    box-shadow:0 0 0 3px var(--focus-ring);
    border-color:var(--fg);
  }
  input[type="checkbox"]:checked{
    background:var(--fg);border-color:var(--fg);
  }
  input[type="checkbox"]:checked::after{
    content:"";position:absolute;left:3px;top:0;
    width:5px;height:9px;
    border:solid var(--bg);
    border-width:0 1.6px 1.6px 0;
    transform:rotate(45deg);
  }
  input[type="checkbox"]:disabled{opacity:.45;cursor:not-allowed}
  input[type="checkbox"]:indeterminate{background:var(--fg);border-color:var(--fg)}
  input[type="checkbox"]:indeterminate::after{
    content:"";position:absolute;left:2.5px;top:5.5px;
    width:7px;height:1.5px;background:var(--bg);
  }

  /* ─── view switching ────────────────────────────────────────────────────── */
  .view{display:none;flex-direction:column;flex:1;min-height:0}
  .view.active{display:flex}

  /* ─── relays grid ──────────────────────────────────────────────────────── */
  .relays-grid{
    padding:18px 24px;
    display:grid;
    grid-template-columns:repeat(auto-fit, minmax(360px, 1fr));
    gap:14px;
  }
  .relay-card{
    background:var(--bg);border:1px solid var(--line);border-radius:var(--r);
    overflow:hidden;display:flex;flex-direction:column;min-width:0;
  }
  .relay-card .rc-hd{
    display:flex;align-items:flex-start;gap:10px;
    padding:13px 16px 11px;border-bottom:1px solid var(--line);
    background:var(--page);
  }
  .relay-card .rc-hd .nm{
    font:600 13.5px/1.2 var(--sans);color:var(--fg);letter-spacing:-0.005em;
  }
  .relay-card .rc-hd .id{
    font:11px/1.2 var(--mono);color:var(--mute);margin-top:3px;
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:230px;
  }
  .relay-card .rc-hd .right{margin-left:auto;display:flex;align-items:center;gap:6px}

  .relay-card .rc-body{padding:14px 16px;display:flex;flex-direction:column;gap:12px}
  .relay-card .row{display:flex;align-items:baseline;gap:8px;font-size:12.5px;min-width:0}
  .relay-card .row .lbl{
    flex:0 0 110px;
    font:11px/1.4 var(--mono);color:var(--mute);
    letter-spacing:0.02em;
  }
  .relay-card .row .val{
    flex:1;font:12.5px/1.4 var(--mono);color:var(--fg-2);
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;
  }
  .relay-card .row .val.big{font:500 14px var(--sans);color:var(--fg)}

  .relay-card .metrics{
    display:grid;grid-template-columns:repeat(3, 1fr);
    gap:0;border-top:1px solid var(--line);
    margin:4px -16px -14px;
  }
  .relay-card .metrics .m{
    padding:10px 14px;border-right:1px solid var(--line);
    display:flex;flex-direction:column;gap:3px;
    min-width:0;
  }
  .relay-card .metrics .m:last-child{border-right:0}
  .relay-card .metrics .m .lbl{
    font:10px/1 var(--mono);color:var(--mute);
    letter-spacing:0.08em;text-transform:uppercase;
  }
  .relay-card .metrics .m .v{
    font:500 14px/1.2 var(--sans);color:var(--fg);
    letter-spacing:-0.01em;
    display:flex;align-items:baseline;gap:4px;
  }
  .relay-card .metrics .m .v .u{
    font:400 10.5px/1 var(--mono);color:var(--mute);
  }
  .relay-card .metrics .m .v .delta{
    font:500 11px var(--mono);
  }
  .relay-card .metrics .m .v .delta.up{color:var(--ok)}
  .relay-card .metrics .m .v .delta.dn{color:var(--danger)}

  .spark{
    height:34px;width:100%;
    border-top:1px solid var(--line);
    background:linear-gradient(to bottom, var(--bg) 0%, var(--bg-sub) 100%);
    position:relative;
  }
  .spark svg{display:block;width:100%;height:100%}
  .spark .stroke{fill:none;stroke:var(--fg-3);stroke-width:1.2}
  .spark .fill{fill:var(--hover);stroke:none}

  /* ─── mesh nodes (uses .peers table, just override col widths) ────── */
  .col-role{width:120px}
  .col-relay{width:160px}
  .col-ver{width:90px}
  .col-status{width:110px}

  /* status dot for mesh nodes */
  .nstat{
    display:inline-flex;align-items:center;gap:6px;
    font:12px/1 var(--sans);color:var(--fg-2);
  }
  .nstat::before{
    content:"";width:6px;height:6px;border-radius:50%;flex:0 0 6px;
    background:currentColor;
  }
  .nstat.Ready{color:var(--ok)}
  .nstat.NotReady{color:var(--danger)}
  .nstat.Degraded{color:var(--warn)}

  .role{
    display:inline-block;padding:1px 7px;border-radius:3px;
    font:500 10.5px/1.5 var(--mono);letter-spacing:0.02em;
    background:var(--bg-sub);color:var(--fg-3);
    border:1px solid var(--line);
  }
  .role.cp{color:var(--fg);border-color:var(--line-2);background:var(--bg)}

  td.name{min-width:0}
  td.name .disp{
    font:500 13px/1.2 var(--sans);color:var(--fg);
    display:block;
    overflow:hidden;text-overflow:ellipsis;
  }
  td.name .id{
    margin-top:2px;display:block;
    font:11.5px/1.2 var(--mono);color:var(--mute);
    overflow:hidden;text-overflow:ellipsis;
  }

  /* status markers */
  .pill{
    display:inline-flex;align-items:center;gap:6px;
    padding:0;
    border:0;border-radius:0;
    font:500 11.5px/1.4 var(--sans);
    background:transparent;
    color:var(--fg-3);
  }
  .pill::before{
    content:"";width:6px;height:6px;border-radius:50%;background:currentColor;
    flex:0 0 6px;
  }
  .pill.Active  {color:var(--ok);    background:transparent;    border-color:transparent}
  .pill.Pending {color:var(--warn);  background:transparent;  border-color:transparent}
  .pill.Pending::before{animation:pulse 1.3s ease-in-out infinite}
  .pill.Failed  {color:var(--danger);background:transparent;border-color:transparent}
  .pill.Expired {color:var(--mute);  background:transparent;   border-color:transparent}
  @keyframes pulse{50%{opacity:.35}}

  .mono{font:12.5px/1.35 var(--mono);color:var(--fg-2)}
  .mono.dim{color:var(--faint)}
  .age{font:12px/1 var(--mono);color:var(--mute);text-align:right}

  td.actions{text-align:right}
  td.actions .row-acts{
    display:inline-flex;align-items:center;gap:2px;
    opacity:1;transition:opacity .08s;
  }
  table.peers tr:hover td.actions .row-acts,
  td.actions .row-acts:focus-within,
  table.peers tr.armed td.actions .row-acts{opacity:1}
  td.actions .btn-icon{color:var(--mute)}
  td.actions .btn-icon:hover{color:var(--fg)}
  .row-detail-link{
    margin-top:3px;
    display:inline-flex;
    align-items:center;
    padding:0;
    background:transparent;
    border:0;
    color:var(--mute);
    font:11px/1.2 var(--sans);
    cursor:pointer;
  }
  .row-detail-link:hover{color:var(--fg)}

  tr.armed .confirm{
    display:inline-flex;align-items:center;gap:10px;justify-content:flex-end;
    font:12px/1 var(--sans);color:var(--danger);font-weight:500;
    white-space:nowrap;
  }
  tr.armed .confirm .what{color:var(--fg-2);font-weight:400}

  /* ─── empty ─────────────────────────────────────────────────────── */
  .empty{
    padding:64px 24px;
    text-align:center;
    display:flex;flex-direction:column;align-items:center;gap:14px;
    background:var(--bg);
  }
  .empty .ic{
    width:40px;height:40px;border-radius:50%;
    background:var(--bg-sub);border:1px solid var(--line);
    display:flex;align-items:center;justify-content:center;
    color:var(--mute);
  }
  .empty h3{margin:0;font:600 14px/1.3 var(--sans);color:var(--fg)}
  .empty p{margin:0;color:var(--mute);max-width:380px;font-size:13px}

  /* ─── banner ────────────────────────────────────────────────────── */
  .banner-row{padding:10px 24px 0;background:var(--bg)}
  .banner{
    display:flex;align-items:flex-start;gap:10px;
    padding:9px 12px;
    background:var(--info-bg);border:1px solid var(--acc-line);
    border-radius:var(--r-sm);
    color:var(--fg-2);font-size:12.5px;
  }
  .banner.err{background:var(--danger-bg);border-color:var(--danger-line);color:#7f1d1d}
  html[data-theme="dark"] .banner.err{color:var(--danger)}
  .banner.ok{background:var(--ok-bg);border-color:var(--ok-line);color:var(--ok)}
  .banner .ic{
    flex:0 0 16px;width:16px;height:16px;border-radius:50%;
    color:var(--acc);margin-top:1px;
    display:flex;align-items:center;justify-content:center;
    background:var(--bg);border:1px solid var(--acc-line);
    font:600 10px/1 var(--mono);
  }
  .banner.err .ic{color:var(--danger);border-color:var(--danger-line)}
  .banner.ok .ic{color:var(--ok);border-color:var(--ok-line)}
  .banner .msg{flex:1;min-width:0}
  .banner .msg code{font:12px var(--mono);color:var(--fg)}
  .banner .x{
    background:transparent;border:0;color:inherit;opacity:.5;cursor:pointer;
    font-size:14px;line-height:1;padding:2px 4px;
  }
  .banner .x:hover{opacity:1}

  /* ─── modal ─────────────────────────────────────────────────────── */
  .modal{
    position:fixed;inset:0;z-index:100;
    display:none;align-items:flex-start;justify-content:center;
    padding:80px 20px 40px;
    background:rgba(15,23,42,0.45);
    backdrop-filter:blur(2px);
    overflow-y:auto;
  }
  html[data-theme="dark"] .modal{background:rgba(0,0,0,0.65)}
  .modal[open]{display:flex;animation:fade .14s ease}
  @keyframes fade{from{opacity:0}to{opacity:1}}

  .sheet{
    background:var(--bg);
    border:1px solid var(--line);
    border-radius:8px;
    width:100%;max-width:520px;
    box-shadow:0 24px 48px -16px rgba(15,23,42,0.22), 0 4px 12px rgba(15,23,42,0.06);
    animation:rise .16s cubic-bezier(.2,.7,.2,1);
    overflow:hidden;
  }
  .sheet.wide{max-width:680px}
  @keyframes rise{from{transform:translateY(8px);opacity:0}to{transform:none;opacity:1}}

  .sheet-hd{
    display:flex;align-items:center;gap:12px;
    padding:14px 18px;border-bottom:1px solid var(--line);
  }
  .sheet-hd h3{
    margin:0;font:600 14.5px/1.2 var(--sans);letter-spacing:-0.01em;color:var(--fg);
  }
  .sheet-hd .x{
    margin-left:auto;background:transparent;border:0;cursor:pointer;
    color:var(--mute);width:26px;height:26px;border-radius:var(--r-sm);
    display:flex;align-items:center;justify-content:center;
  }
  .sheet-hd .x:hover{background:var(--hover);color:var(--fg)}

  .sheet-body{padding:18px;max-height:calc(100vh - 220px);overflow:auto}
  .sheet-foot{
    display:flex;align-items:center;gap:8px;
    padding:12px 18px;border-top:1px solid var(--line);
    background:var(--bg-sub);
  }
  .sheet-foot .spacer{flex:1}
  .sheet-foot .hint{font:11.5px/1.3 var(--sans);color:var(--mute)}

  .form{display:flex;flex-direction:column;gap:14px}
  .form .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .field{display:flex;flex-direction:column;gap:5px;min-width:0}
  .field > label{
    font:500 12px/1 var(--sans);
    color:var(--fg-2);
    display:flex;align-items:baseline;gap:6px;
  }
  .field > label .opt{
    color:var(--mute);font:400 11px/1 var(--sans);
    text-transform:lowercase;
  }
  .field input{
    height:32px;padding:0 10px;
    background:var(--bg);
    border:1px solid var(--line-2);border-radius:var(--r-sm);
    color:var(--fg);font:13px var(--sans);
    width:100%;
    transition:border-color .1s, box-shadow .1s;
  }
  .field input.mono{font:12.5px var(--mono)}
  .field input::placeholder{color:var(--faint)}
  .field input:hover{border-color:var(--line-3)}
  .field input:focus{
    outline:none;border-color:var(--acc);
    box-shadow:0 0 0 3px var(--focus-ring);
  }
  .field .help{font:11.5px/1.3 var(--sans);color:var(--mute)}

  details.advanced{border-top:1px dashed var(--line);padding-top:12px;margin-top:4px}
  details.advanced summary{
    cursor:pointer;list-style:none;
    font:500 11.5px/1 var(--sans);color:var(--mute);
    letter-spacing:0.04em;
    display:inline-flex;align-items:center;gap:6px;
  }
  details.advanced summary::-webkit-details-marker{display:none}
  details.advanced summary::before{
    content:"";width:0;height:0;
    border:3px solid transparent;border-left-color:var(--faint);
    margin-right:2px;transition:transform .12s;
  }
  details.advanced[open] summary::before{transform:rotate(90deg)}
  details.advanced[open] .grid-2{margin-top:10px}
  details.advanced[open] summary{color:var(--fg-2)}

  /* ─── issued result ─────────────────────────────────────────────── */
  .issued{display:flex;flex-direction:column;gap:12px}
  .issued .note{
    display:flex;align-items:flex-start;gap:9px;
    padding:9px 11px;
    background:var(--warn-bg);border:1px solid var(--warn-line);
    border-radius:var(--r-sm);
    color:#78350f;font-size:12.5px;line-height:1.4;
  }
  html[data-theme="dark"] .issued .note{color:var(--warn)}
  .issued .note .ic{
    flex:0 0 16px;width:16px;height:16px;border-radius:50%;
    background:var(--bg);border:1px solid var(--warn-line);color:var(--warn);
    display:flex;align-items:center;justify-content:center;
    font:600 11px/1 var(--mono);
  }
  .issued .note b{color:inherit;font-weight:600}

  .qr-row{display:grid;grid-template-columns:160px 1fr;gap:14px;align-items:start}
  .qr{
    width:160px;height:160px;background:#fff;padding:8px;
    border:1px solid var(--line);border-radius:var(--r-sm);
    image-rendering:pixelated;
  }
  .summary{font:12.5px/1.5 var(--sans);color:var(--fg-3)}
  .summary dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:4px 12px}
  .summary dt{font:11.5px/1.5 var(--mono);color:var(--mute);text-transform:none}
  .summary dd{margin:0;font:12.5px var(--mono);color:var(--fg-2);word-break:break-all}

  #detail-modal .sheet{max-width:760px}
  #detail-modal .sheet-body{overflow:hidden}
  .detail-panel{
    display:flex;
    flex-direction:column;
    gap:14px;
    max-height:calc(100vh - 220px);
    min-height:0;
  }
  .detail-head{
    display:flex;align-items:flex-start;gap:12px;
    padding:11px 12px;
    border:1px solid var(--line);
    border-radius:var(--r-sm);
    background:var(--bg-sub);
  }
  .detail-head .kind{
    flex:0 0 auto;
    font:10.5px/1 var(--mono);
    letter-spacing:.08em;
    text-transform:uppercase;
    color:var(--mute);
    border:1px solid var(--line-2);
    background:var(--bg);
    border-radius:3px;
    padding:4px 6px;
  }
  .detail-head .title{
    min-width:0;
    font:600 14px/1.25 var(--sans);
    color:var(--fg);
    overflow-wrap:anywhere;
  }
  .detail-head .subtitle{
    margin-top:3px;
    font:12px/1.35 var(--mono);
    color:var(--mute);
    overflow-wrap:anywhere;
  }
  .detail-list{
    margin:0;
    display:grid;
    grid-template-columns:150px minmax(0, 1fr);
    gap:8px 14px;
  }
  .detail-list dt{
    font:11.5px/1.4 var(--mono);
    color:var(--mute);
  }
  .detail-list dd{
    margin:0;
    font:12.5px/1.45 var(--mono);
    color:var(--fg-2);
    overflow-wrap:anywhere;
    word-break:break-word;
  }
  .detail-extra{
    min-height:0;
    display:flex;
    flex-direction:column;
  }
  .detail-extra[hidden]{display:none}
  .connection-view{
    border:1px solid var(--line);
    border-radius:var(--r-sm);
    overflow:hidden;
    background:var(--bg);
    display:flex;
    flex-direction:column;
    --connection-row-height:36px;
  }
  .connection-toolbar{
    display:flex;
    align-items:center;
    gap:10px;
    padding:10px;
    border-bottom:1px solid var(--line);
    background:var(--bg-sub);
    flex:0 0 auto;
  }
  .connection-toolbar .ts-search{
    flex:1;
    max-width:none;
    display:flex;
    align-items:center;
    height:30px;
    padding:0 9px;
    background:var(--bg);
    border:1px solid var(--line);
    border-radius:var(--r-sm);
  }
  .connection-toolbar input{
    flex:1;
    border:0;
    background:transparent;
    color:var(--fg);
    outline:none;
    font:12.5px var(--sans);
    min-width:0;
  }
  .connection-count{
    flex:0 0 auto;
    font:11.5px/1 var(--mono);
    color:var(--mute);
  }
  .connection-list{
    max-height:calc(var(--connection-row-height) * 5);
    overflow:auto;
    background:var(--bg);
  }
  .connection-item{
    display:grid;
    grid-template-columns:minmax(0, 1fr) auto;
    gap:10px;
    align-items:center;
    min-height:var(--connection-row-height);
    padding:0 10px;
    border-bottom:1px solid var(--line);
  }
  .connection-item:last-child{border-bottom:0}
  .connection-peer{
    font:12.5px/1.35 var(--mono);
    color:var(--fg-2);
    overflow:hidden;
    text-overflow:ellipsis;
    white-space:nowrap;
  }
  .connection-status{
    font:11.5px/1 var(--mono);
    color:var(--fg-3);
    background:var(--bg-sub);
    border:1px solid var(--line);
    border-radius:999px;
    padding:3px 7px;
  }
  .connection-status.direct{
    color:var(--ok);
    background:var(--ok-bg);
    border-color:var(--ok-line);
  }
  .connection-status.relay,
  .connection-status.relayed{
    color:var(--warn);
    background:var(--warn-bg);
    border-color:var(--warn-line);
  }
  .connection-empty{
    padding:24px 12px;
    text-align:center;
    color:var(--mute);
    font:12.5px/1.4 var(--sans);
  }

  .conf{
    border:1px solid var(--line);border-radius:var(--r-sm);
    background:var(--bg-sub);overflow:hidden;
  }
  .conf-hd{
    display:flex;align-items:center;gap:8px;
    padding:7px 10px;border-bottom:1px solid var(--line);
    background:var(--bg);
  }
  .conf-hd .nm{font:11.5px var(--mono);color:var(--mute)}
  .conf-hd .spacer{flex:1}
  .conf pre{
    margin:0;padding:12px 12px;
    font:12px/1.6 var(--mono);color:var(--fg);
    overflow:auto;max-height:240px;white-space:pre;
  }
  .conf pre .c{color:var(--mute);font-style:italic}
  .conf pre .h{color:var(--fg);font-weight:600}
  .conf pre .k{color:var(--fg-3)}
  .conf pre .v{color:var(--fg)}

  /* ─── responsive ────────────────────────────────────────────────── */
  @media (max-width: 1100px){
    table.peers th.col-endpoint, table.peers td.col-endpoint{display:none}
  }
  @media (max-width: 880px){
    aside.side{flex:0 0 60px;width:60px}
    .side-brand .name,.side-cluster,.side-nav .group,.side-nav a span,.side-nav a .badge,.side-foot{display:none}
    .side-nav a{justify-content:center}
    .side-nav a svg{width:16px;height:16px}
    table.peers th.col-ip, table.peers td.col-ip{display:none}
  }
  @media (max-width: 700px){
    table.peer-list colgroup, table.peer-list thead{display:none}
    table.peer-list, table.peer-list tbody, table.peer-list tr, table.peer-list td{
      display:block;width:100%;
    }
    table.peer-list tr{
      position:relative;
      padding:12px 16px 12px 44px;
      border-bottom:1px solid var(--line);
      min-height:78px;
    }
    table.peer-list td{
      padding:0 !important;
      border-bottom:0;
      white-space:normal;
      overflow:visible;
      text-overflow:clip;
    }
    table.peer-list td.sel{
      position:absolute;
      left:16px;
      top:18px;
      width:auto;
    }
    table.peer-list td.name .disp,
    table.peer-list td.name .id{
      white-space:nowrap;
      overflow:hidden;
      text-overflow:ellipsis;
    }
    table.peer-list td.phase-cell{margin-top:7px}
    table.peer-list td.actions{
      margin-top:8px;
      text-align:left;
    }
    table.peer-list th.col-ip,
    table.peer-list td.col-ip,
    table.peer-list th.col-endpoint,
    table.peer-list td.col-endpoint,
    table.peer-list th.col-age,
    table.peer-list td.age{display:none}
    td.actions .row-acts{opacity:1}
    td.actions .row-acts .btn-icon{display:none}
    .page-title .desc{display:none}
    table.resource-table colgroup, table.resource-table thead{display:none}
    table.resource-table, table.resource-table tbody, table.resource-table tr, table.resource-table td{
      display:block;width:100%;
    }
    table.resource-table tr{
      padding:10px 16px;
      border-bottom:1px solid var(--line);
    }
    table.resource-table td{
      padding:4px 0;
      border-bottom:0;
      white-space:normal;
      overflow:visible;
      text-overflow:clip;
      display:grid;
      grid-template-columns:76px minmax(0, 1fr);
      gap:8px;
      text-align:right;
      overflow-wrap:anywhere;
      word-break:break-word;
    }
    table.resource-table td::before{
      content:attr(data-label);
      font:10.5px/1.4 var(--mono);
      color:var(--mute);
      text-align:left;
    }
    table.resource-table td.name{
      display:block;
      padding-bottom:7px;
    }
    table.resource-table td.name::before{display:none}
    table.resource-table td.age{text-align:left}
  }
  @media (max-width: 600px){
    .qr-row{grid-template-columns:1fr}
    .qr{width:120px;height:120px}
    .toolbar{flex-wrap:wrap}
    .page-title{flex-wrap:wrap}
    .page-title .actions{margin-left:0;width:100%;justify-content:flex-start}
    .page{padding:14px 16px}
    .content{padding:12px}
    .toolbar,.banner-row{padding-left:12px;padding-right:12px}
    table.peers th:first-child,table.peers td:first-child{padding-left:16px}
    table.peers th:last-child,table.peers td:last-child{padding-right:16px}
    .topbar{padding:0 14px}
    .crumbs{font-size:12px}
    .crumbs span:not(.cur):not(.sep){display:none}
    .crumbs .sep{display:none}
    .page-title h1{font-size:17px}
    .page-title .actions .btn:not(.btn-primary){display:none}
    .modal{left:0;right:0;width:100vw;max-width:100vw;padding:48px 20px 26px;overflow-x:hidden}
    .sheet,.sheet.wide{width:calc(100vw - 72px);max-width:calc(100vw - 72px)}
    .sheet-body{max-height:calc(100vh - 180px)}
    .issued .note{display:block}
    .issued .note .ic{display:none}
    .issued .note > div{min-width:0;overflow-wrap:anywhere}
    .conf-hd{display:grid;grid-template-columns:1fr 1fr;gap:6px}
    .conf-hd .nm{grid-column:1 / -1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .conf-hd .spacer{display:none}
    .conf-hd .btn{width:100%;min-width:0}
    .sheet-foot{display:grid;grid-template-columns:1fr;gap:10px}
    .sheet-foot .spacer{display:none}
    .sheet-foot .hint{display:none}
    .sheet-foot .btn{width:100%}
    #detail-modal .sheet-body{overflow:auto}
    .detail-panel{max-height:none}
    .detail-list{grid-template-columns:1fr;gap:4px}
    .detail-list dt{margin-top:8px}
  }
  @media (max-width: 460px){
    td.actions .btn-sm{padding:0 7px;font-size:11.5px}
  }
  body.modal-open{overflow:hidden}
  /* server-template compatibility */
  .shell{display:flex;width:100%;min-height:100vh}
  .content{
    display:flex;
    flex-direction:column;
    flex:1;
    min-height:0;
    gap:12px;
    padding:16px 20px 24px;
    background:var(--page);
    overflow:auto;
  }
  .side-nav a.disabled{opacity:.55;cursor:not-allowed;pointer-events:none}
  .modal.open{display:flex;animation:fade .14s ease}
  .banner.error{background:var(--danger-bg);border-color:var(--danger-line);color:var(--danger)}
  .pill.Revoked{color:var(--danger);background:transparent;border-color:transparent}
  .pill.revoked,.pill.active,.pill.pending,.pill.failed{color:inherit}
  .btn[disabled]{opacity:.45;cursor:not-allowed}
  .row-acts form{display:inline-flex;margin:0}
  .confirm{display:none;margin:0}
  @media (max-width: 700px){
    table.peers th.col-sel, table.peers td.sel{display:table-cell}
  }
</style>
</head>
<body data-density="regular">
  <div class="shell">
    <aside class="side">
      <div class="side-brand">
        <span class="name">WireKube</span>
      </div>
      <div class="side-cluster">
        <div class="lbl">Access</div>
        <button class="ctx" type="button">
          <span class="dot"></span>
          <span class="info">
            <span class="nm">relay sidecar</span>
            <span class="ns">localhost only</span>
          </span>
        </button>
      </div>
      <nav class="side-nav" aria-label="Primary">
        <div class="group">Manage</div>
        <a class="{{if eq .ActiveView "peers"}}active{{end}}" href="/">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="4" cy="8" r="2"></circle><circle cx="12" cy="8" r="2"></circle><path d="M6 8h4"></path></svg>
          <span>External peers</span>
          <span class="badge">{{.TotalPeers}}</span>
        </a>
        <a class="{{if eq .ActiveView "relays"}}active{{end}}" href="/relays">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="3.5" width="11" height="9" rx="1.5"></rect><path d="M2.5 7h11"></path></svg>
          <span>Relays</span>
        </a>
        <a class="{{if eq .ActiveView "mesh"}}active{{end}}" href="/mesh-nodes">
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l5 2 5-2v8l-5 2-5-2V3z"></path><path d="M8 5v8"></path></svg>
          <span>Mesh nodes</span>
        </a>
      </nav>
      <div class="side-foot">port-forward / 127.0.0.1</div>
    </aside>
    <main class="main">
      <div class="topbar">
        <div class="crumbs">
          <span>wirekube-system</span>
          <span>/</span>
          <span class="cur">{{.ViewTitle}}</span>
        </div>
        <div class="spacer"></div>
      </div>
      <section class="content">
        {{if .Error}}<div class="banner error">{{.Error}}</div>{{end}}
        {{if .Notice}}<div class="banner ok">{{.Notice}}</div>{{end}}

        <div class="page">
          <div class="page-title">
            <div>
              <h1>{{.ViewTitle}}</h1>
              <div class="desc">{{.ViewDescription}}</div>
            </div>
            <div class="actions">
              <a class="btn btn-ghost" href="{{.RefreshPath}}">
                <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M13 8a5 5 0 1 1-1.5-3.5L13 6"></path><path d="M13 3v3h-3"></path></svg>
                Refresh
              </a>
              {{if eq .ActiveView "peers"}}
              <button class="btn btn-primary" type="button" onclick="openIssue()">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><path d="M8 3v10M3 8h10"></path></svg>
                Issue peer
              </button>
              {{end}}
            </div>
          </div>
        </div>

        {{if eq .ActiveView "peers"}}
          <div class="toolbar">
            <div class="filter-chips" id="phase-chips">
              <button type="button" class="on" data-phase="all" onclick="setPhase(this)">All <span class="c">{{.TotalPeers}}</span></button>
              <button type="button" data-phase="Active" onclick="setPhase(this)">Active <span class="c">{{index .Counts "Active"}}</span></button>
              <button type="button" data-phase="Pending" onclick="setPhase(this)">Pending <span class="c">{{index .Counts "Pending"}}</span></button>
              <button type="button" data-phase="Failed" onclick="setPhase(this)">Failed <span class="c">{{index .Counts "Failed"}}</span></button>
              <button type="button" data-phase="Revoked" onclick="setPhase(this)">Revoked <span class="c">{{index .Counts "Revoked"}}</span></button>
            </div>
            <label class="ts-search">
              <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><circle cx="7" cy="7" r="4.5"></circle><path d="M10.5 10.5L14 14"></path></svg>
              <input id="filter-input" placeholder="Filter by name, IP, endpoint..." oninput="setFilter(this.value)">
            </label>
			<div class="spacer"></div>
			<label class="bulk-check">
				<input id="select-visible" data-select-all-peers type="checkbox" aria-label="Select visible peers" onchange="toggleAllPeers(this)">
				Select visible
			</label>
			<form id="bulk-delete-form" method="post" action="/peers/delete" onsubmit="return confirmBulkDelete()">
				<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
				<button class="btn btn-danger" id="bulk-delete-btn" type="submit" disabled>Revoke selected</button>
            </form>
            <span class="res-count" id="res-count">{{.TotalPeers}} of {{.TotalPeers}}</span>
          </div>

          <div class="tbl-host">
            {{if .Peers}}
			<table class="peers peer-list" id="peer-table">
              <colgroup>
                <col class="col-sel">
                <col class="col-name">
                <col class="col-phase">
                <col class="col-ip">
                <col class="col-endpoint">
                <col class="col-age">
                <col class="col-act">
              </colgroup>
              <thead>
                <tr>
				  <th class="col-sel"><input id="select-all" data-select-all-peers type="checkbox" aria-label="Select visible peers" onchange="toggleAllPeers(this)"></th>
                  <th class="col-name"><span class="sortable on">Peer <span class="arr">↓</span></span></th>
                  <th class="col-phase">Phase</th>
                  <th class="col-ip">Mesh IP</th>
                  <th class="col-endpoint">Endpoint</th>
                  <th class="col-age right">Age</th>
                  <th class="col-act right">Actions</th>
                </tr>
              </thead>
              <tbody id="peer-tbody">
                {{range .Peers}}
                <tr class="clickable-row" tabindex="0" onclick="handleDetailRowClick(event, this)" onkeydown="handleDetailRowKey(event, this)" data-detail-kind="External peer" data-detail-title="{{.DisplayName}}" data-detail-subtitle="{{.Name}}" data-detail-phase="{{.Phase}}" data-detail-mesh-ip="{{.MeshIP}}" data-detail-endpoint="{{.Endpoint}}" data-detail-ingress="{{.Ingress}}" data-detail-allowed="{{.Allowed}}" data-detail-mtu="{{.MTU}}" data-detail-age="{{.Age}}" data-detail-condition="{{.Message}}" data-detail-config="{{if .HasConfig}}stored{{else}}not stored{{end}}" data-phase="{{.Phase}}" data-filter="{{.Name}} {{.DisplayName}} {{.MeshIP}} {{.Endpoint}} {{.Ingress}} {{.Allowed}}">
                  <td class="sel"><input class="peer-select" form="bulk-delete-form" name="peers" value="{{.Name}}" type="checkbox" aria-label="Select {{.Name}}" onchange="syncPeerSelection()"></td>
                  <td class="name">
                    <span class="disp">{{.DisplayName}}</span>
                    <span class="id">{{.Name}}</span>
                  </td>
				<td class="phase-cell"><span class="pill {{.Phase}}">{{.Phase}}</span></td>
                  <td class="col-ip mono">{{.MeshIP}}</td>
                  <td class="col-endpoint mono" title="{{.Endpoint}}">{{.Endpoint}}</td>
                  <td class="age">{{.Age}}</td>
                  <td class="actions">
                    <div class="row-acts default-actions">
                      <button class="btn btn-sm" type="button" aria-label="Open details for {{.Name}}" onclick="openDetailFromRow(this.closest('tr'))">Details</button>
                      {{if .HasConfig}}
                      <a class="btn btn-sm" aria-label="Open config for {{.Name}}" href="/peers/{{.Name}}/config">Config</a>
                      {{else}}
                      <button class="btn btn-sm" type="button" title="No stored config for this peer" disabled>Config</button>
                      {{end}}
                      <button class="btn btn-sm btn-danger" type="button" aria-label="Revoke {{.Name}}" onclick="armRevoke(this)">Revoke</button>
                    </div>
                    <form class="confirm" method="post" action="/peers/{{.Name}}/delete">
                      <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                      <span class="what">Revoke this peer?</span>
                      <button class="btn btn-sm" type="button" onclick="cancelRevoke(this)">Cancel</button>
                      <button class="btn btn-sm btn-danger solid" type="submit">Revoke</button>
                    </form>
                  </td>
                </tr>
                {{end}}
              </tbody>
            </table>
            {{else}}
            <div class="empty" id="empty-state">
              <div>
                <h3>No external peers</h3>
                <p>Issue a peer to generate a WireGuard client config. Stored configs can be reopened while the Kubernetes Secret exists.</p>
                <button class="btn btn-primary" type="button" onclick="openIssue()">Issue peer</button>
              </div>
            </div>
            {{end}}
            <div class="empty" id="filtered-empty" style="display:none">
              <div>
                <h3>No matching peers</h3>
                <p>Adjust the phase or text filter.</p>
              </div>
            </div>
          </div>
        {{else if eq .ActiveView "relays"}}
          <div class="toolbar">
            <span class="res-count">{{len .RelayDeployments}} deployment(s), {{len .RelayPods}} pod(s), {{len .RelayServices}} service(s)</span>
          </div>
          <div class="tbl-host">
            {{if .RelayDeployments}}
            <div class="section-label">Deployments</div>
			<table class="peers resource-table">
              <thead><tr><th>Name</th><th>Ready</th><th>Updated</th><th>Available</th><th class="right">Age</th></tr></thead>
              <tbody>
                {{range .RelayDeployments}}
				<tr class="clickable-row" tabindex="0" onclick="handleDetailRowClick(event, this)" onkeydown="handleDetailRowKey(event, this)" data-detail-kind="Relay deployment" data-detail-title="{{.Name}}" data-detail-ready="{{.Ready}}" data-detail-updated="{{.Updated}}" data-detail-available="{{.Available}}" data-detail-age="{{.Age}}"><td class="name"><span class="disp">{{.Name}}</span><button class="row-detail-link" type="button" onclick="openDetailFromRow(this.closest('tr'))">Details</button></td><td data-label="Ready" class="mono">{{.Ready}}</td><td data-label="Updated" class="mono">{{.Updated}}</td><td data-label="Available" class="mono">{{.Available}}</td><td data-label="Age" class="age">{{.Age}}</td></tr>
                {{end}}
              </tbody>
            </table>
            {{end}}
            <div class="section-label">Pods</div>
            {{if .RelayPods}}
			<table class="peers resource-table">
              <thead><tr><th>Name</th><th>Status</th><th>Ready</th><th>Node</th><th>Pod IP</th><th>Host IP</th><th>Restarts</th><th class="right">Age</th></tr></thead>
              <tbody>
                {{range .RelayPods}}
				<tr class="clickable-row" tabindex="0" onclick="handleDetailRowClick(event, this)" onkeydown="handleDetailRowKey(event, this)" data-detail-kind="Relay pod" data-detail-title="{{.Name}}" data-detail-status="{{.Status}}" data-detail-ready="{{.Ready}}" data-detail-node="{{.Node}}" data-detail-pod-ip="{{.PodIP}}" data-detail-host-ip="{{.HostIP}}" data-detail-restarts="{{.Restarts}}" data-detail-age="{{.Age}}"><td class="name"><span class="disp">{{.Name}}</span><button class="row-detail-link" type="button" onclick="openDetailFromRow(this.closest('tr'))">Details</button></td><td data-label="Status"><span class="pill {{.StatusClass}}">{{.Status}}</span></td><td data-label="Ready" class="mono">{{.Ready}}</td><td data-label="Node" class="mono">{{.Node}}</td><td data-label="Pod IP" class="mono">{{.PodIP}}</td><td data-label="Host IP" class="mono">{{.HostIP}}</td><td data-label="Restarts" class="mono">{{.Restarts}}</td><td data-label="Age" class="age">{{.Age}}</td></tr>
                {{end}}
              </tbody>
            </table>
            {{else}}
            <div class="empty"><div><h3>No relay pods</h3><p>No pods matched app.kubernetes.io/name=wirekube-relay.</p></div></div>
            {{end}}
            {{if .RelayServices}}
            <div class="section-label">Services</div>
			<table class="peers resource-table">
              <thead><tr><th>Name</th><th>Type</th><th>Cluster IP</th><th>External</th><th>Ports</th><th class="right">Age</th></tr></thead>
              <tbody>
                {{range .RelayServices}}
				<tr class="clickable-row" tabindex="0" onclick="handleDetailRowClick(event, this)" onkeydown="handleDetailRowKey(event, this)" data-detail-kind="Relay service" data-detail-title="{{.Name}}" data-detail-type="{{.Type}}" data-detail-cluster-ip="{{.ClusterIP}}" data-detail-external="{{.External}}" data-detail-ports="{{.Ports}}" data-detail-age="{{.Age}}"><td class="name"><span class="disp">{{.Name}}</span><button class="row-detail-link" type="button" onclick="openDetailFromRow(this.closest('tr'))">Details</button></td><td data-label="Type" class="mono">{{.Type}}</td><td data-label="Cluster IP" class="mono">{{.ClusterIP}}</td><td data-label="External" class="mono">{{.External}}</td><td data-label="Ports" class="mono">{{.Ports}}</td><td data-label="Age" class="age">{{.Age}}</td></tr>
                {{end}}
              </tbody>
            </table>
            {{end}}
          </div>
        {{else if eq .ActiveView "mesh"}}
          <div class="toolbar">
            <span class="res-count">{{len .Meshes}} mesh resource(s), {{len .MeshNodes}} node peer(s)</span>
          </div>
          <div class="tbl-host">
            {{if .Meshes}}
            <div class="section-label">Mesh configuration</div>
			<table class="peers resource-table">
              <thead><tr><th>Name</th><th>Listen</th><th>Interface</th><th>MTU</th><th>Mesh CIDR</th><th>Relay</th><th>Ready</th><th class="right">Age</th></tr></thead>
              <tbody>
                {{range .Meshes}}
				<tr class="clickable-row" tabindex="0" onclick="handleDetailRowClick(event, this)" onkeydown="handleDetailRowKey(event, this)" data-detail-kind="Mesh configuration" data-detail-title="{{.Name}}" data-detail-listen="{{.Listen}}" data-detail-interface="{{.Interface}}" data-detail-mtu="{{.MTU}}" data-detail-mesh-cidr="{{.MeshCIDR}}" data-detail-relay="{{.Relay}}" data-detail-ready="{{.Ready}}" data-detail-age="{{.Age}}"><td class="name"><span class="disp">{{.Name}}</span><button class="row-detail-link" type="button" onclick="openDetailFromRow(this.closest('tr'))">Details</button></td><td data-label="Listen" class="mono">{{.Listen}}</td><td data-label="Interface" class="mono">{{.Interface}}</td><td data-label="MTU" class="mono">{{.MTU}}</td><td data-label="Mesh CIDR" class="mono">{{.MeshCIDR}}</td><td data-label="Relay" class="mono">{{.Relay}}</td><td data-label="Ready" class="mono">{{.Ready}}</td><td data-label="Age" class="age">{{.Age}}</td></tr>
                {{end}}
              </tbody>
            </table>
            {{end}}
            <div class="section-label">Mesh nodes</div>
            {{if .MeshNodes}}
			<table class="peers resource-table">
              <thead><tr><th>Name</th><th>Status</th><th>Endpoint</th><th>Allowed IPs</th><th>NAT</th><th>ICE</th><th>Connections</th><th class="right">Age</th></tr></thead>
              <tbody>
                {{range .MeshNodes}}
				<tr class="clickable-row" tabindex="0" onclick="handleDetailRowClick(event, this)" onkeydown="handleDetailRowKey(event, this)" data-detail-kind="Mesh node" data-detail-title="{{.Name}}" data-detail-status="{{.Status}}" data-detail-endpoint="{{.Endpoint}}" data-detail-allowed-ips="{{.Allowed}}" data-detail-nat="{{.NAT}}" data-detail-ice="{{.ICE}}" data-detail-connections-summary="{{.ConnectionsSummary}}" data-detail-connections-url="/mesh-nodes/{{.Name}}/connections" data-detail-age="{{.Age}}"><td class="name"><span class="disp">{{.Name}}</span><button class="row-detail-link" type="button" onclick="openDetailFromRow(this.closest('tr'))">Details</button></td><td data-label="Status"><span class="nstat {{.StatusClass}}">{{.Status}}</span></td><td data-label="Endpoint" class="mono">{{.Endpoint}}</td><td data-label="Allowed IPs" class="mono">{{.Allowed}}</td><td data-label="NAT" class="mono">{{.NAT}}</td><td data-label="ICE" class="mono">{{.ICE}}</td><td data-label="Connections" class="mono">{{.ConnectionsSummary}}</td><td data-label="Age" class="age">{{.Age}}</td></tr>
                {{end}}
              </tbody>
            </table>
            {{else}}
            <div class="empty"><div><h3>No mesh nodes</h3><p>No WireKubePeer resources are visible to admin-web.</p></div></div>
            {{end}}
          </div>
        {{end}}
      </section>
    </main>
  </div>

  <div class="modal" id="detail-modal" role="dialog" aria-modal="true" aria-labelledby="detail-title">
    <div class="sheet wide">
      <div class="sheet-hd">
        <h3 id="detail-title">Resource details</h3>
        <button class="x" type="button" aria-label="Close" onclick="closeDetail()">x</button>
      </div>
      <div class="sheet-body">
        <div class="detail-panel">
          <div class="detail-head">
            <span class="kind" id="detail-kind">resource</span>
            <div>
              <div class="title" id="detail-name">-</div>
              <div class="subtitle" id="detail-subtitle">-</div>
            </div>
          </div>
          <dl class="detail-list" id="detail-list"></dl>
          <div class="detail-extra" id="detail-extra" hidden>
            <div class="connection-view">
              <div class="connection-toolbar">
                <label class="ts-search">
                  <input id="detail-connection-filter" placeholder="Filter connections..." oninput="renderDetailConnections()">
                </label>
                <span class="connection-count" id="detail-connection-count">0 of 0</span>
              </div>
              <div class="connection-list" id="detail-connection-list"></div>
            </div>
          </div>
        </div>
      </div>
      <div class="sheet-foot">
        <span class="hint">Details are read from the currently rendered cluster state.</span>
        <span class="spacer"></span>
        <button class="btn btn-primary" type="button" onclick="closeDetail()">Close</button>
      </div>
    </div>
  </div>

  <div class="modal" id="issue-modal" role="dialog" aria-modal="true" aria-labelledby="issue-title" {{if .Issued}}open{{end}}>
    <div class="sheet {{if .Issued}}wide{{end}}">
      {{if .Issued}}
      <div class="sheet-hd">
        <h3 id="issue-title">Peer config · <span class="mono">{{.Issued.Name}}</span></h3>
        <button class="x" type="button" aria-label="Close" onclick="closeIssue()">x</button>
      </div>
      <div class="sheet-body">
        <div class="issued">
          <div class="note">
            <span class="ic">!</span>
            <div><b>Stored config.</b> This WireGuard config is stored as a Kubernetes Secret and can be reopened while the peer exists.</div>
          </div>
          <div class="qr-row">
            <img class="qr" alt="WireGuard QR code" src="{{.Issued.QR}}">
            <div class="summary">
              <dl>
                <dt>Mesh IP</dt><dd>{{.Issued.MeshIP}}</dd>
                <dt>Endpoint</dt><dd>{{.Issued.Endpoint}}</dd>
                <dt>MTU</dt><dd>{{.Issued.MTU}}</dd>
                <dt>Allowed IPs</dt><dd>{{.Issued.Allowed}}</dd>
                <dt>TTL</dt><dd>{{.Issued.TTL}}</dd>
                <dt>Expires</dt><dd>{{.Issued.Expires}}</dd>
              </dl>
            </div>
          </div>
          <div class="conf">
            <div class="conf-hd">
              <span class="nm mono" id="conf-filename">{{.Issued.FileName}}</span>
              <span class="spacer"></span>
              <button class="btn btn-sm" type="button" onclick="downloadConfig()">Download</button>
              <button class="btn btn-sm btn-primary" type="button" onclick="copyConfig(this)">Copy</button>
            </div>
            <pre id="conf-text">{{.Issued.Config}}</pre>
          </div>
        </div>
      </div>
      <div class="sheet-foot">
        <span class="hint">This config remains available from the peer row while its Secret exists.</span>
        <span class="spacer"></span>
        <button class="btn btn-primary" type="button" onclick="location.href='/'">Done</button>
      </div>
      {{else}}
      <div class="sheet-hd">
        <h3 id="issue-title">Issue external peer</h3>
        <button class="x" type="button" aria-label="Close" onclick="closeIssue()">x</button>
      </div>
      <div class="sheet-body">
        <form class="form" id="issue-form" method="post" action="/peers">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <div class="field">
            <label for="peer-name">Name <span class="opt">required</span></label>
            <input id="peer-name" name="name" class="mono" autocomplete="off" required pattern="[a-z0-9]([-a-z0-9.]*[a-z0-9])?" placeholder="field-laptop-ada">
            <div class="help">DNS-1123 subdomain. Used as the CR name; cannot be changed.</div>
          </div>
          <div class="field">
            <label for="peer-display-name">Display name <span class="opt">optional</span></label>
            <input id="peer-display-name" name="displayName" autocomplete="off" placeholder="Ada's field laptop">
          </div>
          <div class="grid-2">
            <div class="field">
              <label for="peer-ttl">TTL <span class="opt">optional</span></label>
              <input id="peer-ttl" name="ttl" class="mono" autocomplete="off" placeholder="24h">
              <div class="help">Go duration. Empty means no expiry.</div>
            </div>
            <div class="field">
              <label for="peer-mtu">MTU <span class="opt">576-1420</span></label>
              <input id="peer-mtu" name="mtu" class="mono" inputmode="numeric" autocomplete="off" placeholder="1248">
            </div>
          </div>
          <details class="advanced">
            <summary>Advanced</summary>
            <div class="grid-2">
              <div class="field">
                <label for="peer-ingress">Ingress peer <span class="opt">optional</span></label>
                <input id="peer-ingress" name="ingressPeer" class="mono" autocomplete="off" placeholder="auto-selected">
              </div>
              <div class="field">
                <label for="peer-allowed">Allowed IPs <span class="opt">optional CIDRs</span></label>
                <input id="peer-allowed" name="allowed" class="mono" autocomplete="off" placeholder="controller default">
              </div>
            </div>
          </details>
        </form>
      </div>
      <div class="sheet-foot">
        <span class="hint">A keypair is generated server-side and the rendered config is stored in a Kubernetes Secret.</span>
        <span class="spacer"></span>
        <button class="btn" type="button" onclick="closeIssue()">Cancel</button>
        <button class="btn btn-primary" form="issue-form" type="submit">Issue peer</button>
      </div>
      {{end}}
    </div>
  </div>

  <script>
    let phaseFilter = "all";
    let textFilter = "";

    function openIssue() {
      document.getElementById("issue-modal").setAttribute("open", "");
      setTimeout(function() {
        const input = document.querySelector("#issue-form input[name='name']");
        if (input) input.focus();
      }, 30);
    }

    function closeIssue() {
      if (/^\/peers\/[^/]+\/config$/.test(window.location.pathname)) {
        window.location.href = "/";
        return;
      }
      document.getElementById("issue-modal").removeAttribute("open");
    }

    function setPhase(btn) {
      phaseFilter = btn.dataset.phase || "all";
      document.querySelectorAll("#phase-chips button").forEach(function(el) { el.classList.remove("on"); });
      btn.classList.add("on");
      applyFilter();
    }

    function setFilter(value) {
      textFilter = (value || "").toLowerCase().trim();
      const a = document.getElementById("filter-input");
      if (a && a.value !== value) a.value = value;
      applyFilter();
    }

    function applyFilter() {
      const rows = Array.from(document.querySelectorAll("#peer-tbody tr"));
      let visible = 0;
      rows.forEach(function(row) {
        const phaseOK = phaseFilter === "all" || row.dataset.phase === phaseFilter;
        const textOK = !textFilter || (row.dataset.filter || "").toLowerCase().includes(textFilter);
        const show = phaseOK && textOK;
        row.style.display = show ? "" : "none";
        if (show) visible++;
      });
      const res = document.getElementById("res-count");
      if (res) res.textContent = visible + " of " + rows.length;
      const filteredEmpty = document.getElementById("filtered-empty");
      const table = document.getElementById("peer-table");
      if (filteredEmpty && table) {
        filteredEmpty.style.display = rows.length > 0 && visible === 0 ? "grid" : "none";
        table.style.display = visible === 0 ? "none" : "";
      }
      syncPeerSelection();
    }

    function peerCheckboxes() {
      return Array.from(document.querySelectorAll(".peer-select"));
    }

    function visiblePeerCheckboxes() {
      return peerCheckboxes().filter(function(cb) {
        const row = cb.closest("tr");
        return row && row.style.display !== "none";
      });
    }

    function toggleAllPeers(source) {
      visiblePeerCheckboxes().forEach(function(cb) { cb.checked = source.checked; });
      syncPeerSelection();
    }

    function syncPeerSelection() {
      const boxes = peerCheckboxes();
      const visible = visiblePeerCheckboxes();
      const selected = boxes.filter(function(cb) { return cb.checked; });
      const selectedVisible = visible.filter(function(cb) { return cb.checked; });
      document.querySelectorAll("[data-select-all-peers]").forEach(function(selectAll) {
        selectAll.checked = visible.length > 0 && selectedVisible.length === visible.length;
        selectAll.indeterminate = selectedVisible.length > 0 && selectedVisible.length < visible.length;
        selectAll.disabled = visible.length === 0;
      });
      const btn = document.getElementById("bulk-delete-btn");
      if (btn) {
        btn.disabled = selected.length === 0;
        btn.textContent = selected.length > 0 ? "Revoke selected (" + selected.length + ")" : "Revoke selected";
      }
    }

    function confirmBulkDelete() {
      const selected = peerCheckboxes().filter(function(cb) { return cb.checked; });
      if (selected.length === 0) return false;
      return window.confirm("Revoke " + selected.length + " selected peer(s)?");
    }

    function armRevoke(btn) {
      document.querySelectorAll("tr.armed").forEach(function(row) { row.classList.remove("armed"); });
      btn.closest("tr").classList.add("armed");
    }

    function cancelRevoke(btn) {
      btn.closest("tr").classList.remove("armed");
    }

    const detailFields = {
      "External peer": [
        ["Phase", "detailPhase"],
        ["Mesh IP", "detailMeshIp"],
        ["Endpoint", "detailEndpoint"],
        ["Ingress peer", "detailIngress"],
        ["Allowed IPs", "detailAllowed"],
        ["MTU", "detailMtu"],
        ["Config", "detailConfig"],
        ["Age", "detailAge"],
        ["Condition", "detailCondition"]
      ],
      "Relay deployment": [
        ["Ready", "detailReady"],
        ["Updated", "detailUpdated"],
        ["Available", "detailAvailable"],
        ["Age", "detailAge"]
      ],
      "Relay pod": [
        ["Status", "detailStatus"],
        ["Ready", "detailReady"],
        ["Node", "detailNode"],
        ["Pod IP", "detailPodIp"],
        ["Host IP", "detailHostIp"],
        ["Restarts", "detailRestarts"],
        ["Age", "detailAge"]
      ],
      "Relay service": [
        ["Type", "detailType"],
        ["Cluster IP", "detailClusterIp"],
        ["External", "detailExternal"],
        ["Ports", "detailPorts"],
        ["Age", "detailAge"]
      ],
      "Mesh configuration": [
        ["Listen port", "detailListen"],
        ["Interface", "detailInterface"],
        ["MTU", "detailMtu"],
        ["Mesh CIDR", "detailMeshCidr"],
        ["Relay", "detailRelay"],
        ["Ready", "detailReady"],
        ["Age", "detailAge"]
      ],
      "Mesh node": [
        ["Status", "detailStatus"],
        ["Endpoint", "detailEndpoint"],
        ["Allowed IPs", "detailAllowedIps"],
        ["NAT", "detailNat"],
        ["ICE", "detailIce"],
        ["Connections", "detailConnectionsSummary"],
        ["Age", "detailAge"]
      ]
    };
    let detailConnections = [];

    function handleDetailRowClick(event, row) {
      if (event.target.closest("a, button, input, form, label")) return;
      openDetailFromRow(row);
    }

    function handleDetailRowKey(event, row) {
      if (event.key !== "Enter" && event.key !== " ") return;
      if (event.target.closest("a, button, input, form, label")) return;
      event.preventDefault();
      openDetailFromRow(row);
    }

    function openDetailFromRow(row) {
      if (!row) return;
      const kind = row.dataset.detailKind || "Resource";
      document.getElementById("detail-title").textContent = kind + " details";
      document.getElementById("detail-kind").textContent = kind;
      document.getElementById("detail-name").textContent = row.dataset.detailTitle || "-";
      document.getElementById("detail-subtitle").textContent = row.dataset.detailSubtitle || "";

      const dl = document.getElementById("detail-list");
      dl.replaceChildren();
      (detailFields[kind] || []).forEach(function(field) {
        const dt = document.createElement("dt");
        const dd = document.createElement("dd");
        dt.textContent = field[0];
        dd.textContent = row.dataset[field[1]] || "-";
        dl.appendChild(dt);
        dl.appendChild(dd);
      });
      resetDetailConnections();
      if (row.dataset.detailConnectionsUrl) {
        loadDetailConnections(row.dataset.detailConnectionsUrl);
      }
      document.getElementById("detail-modal").setAttribute("open", "");
    }

    function closeDetail() {
      document.getElementById("detail-modal").removeAttribute("open");
    }

    function resetDetailConnections() {
      detailConnections = [];
      const extra = document.getElementById("detail-extra");
      const filter = document.getElementById("detail-connection-filter");
      const list = document.getElementById("detail-connection-list");
      const count = document.getElementById("detail-connection-count");
      if (extra) extra.hidden = true;
      if (filter) filter.value = "";
      if (list) list.replaceChildren();
      if (count) count.textContent = "0 of 0";
    }

    async function loadDetailConnections(url) {
      const extra = document.getElementById("detail-extra");
      const list = document.getElementById("detail-connection-list");
      const count = document.getElementById("detail-connection-count");
      if (!extra || !list || !count) return;
      extra.hidden = false;
      list.innerHTML = '<div class="connection-empty">Loading connections...</div>';
      count.textContent = "loading";
      try {
        const resp = await fetch(url, { headers: { "Accept": "application/json" } });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        detailConnections = Array.isArray(data.connections) ? data.connections : [];
        renderDetailConnections();
      } catch (err) {
        detailConnections = [];
        count.textContent = "failed";
        list.innerHTML = '<div class="connection-empty">Failed to load connections.</div>';
      }
    }

    function renderDetailConnections() {
      const filter = (document.getElementById("detail-connection-filter").value || "").toLowerCase().trim();
      const list = document.getElementById("detail-connection-list");
      const count = document.getElementById("detail-connection-count");
      if (!list || !count) return;
      const matched = detailConnections.filter(function(item) {
        const text = ((item.peer || "") + " " + (item.status || "")).toLowerCase();
        return !filter || text.includes(filter);
      });
      count.textContent = matched.length + " of " + detailConnections.length;
      list.replaceChildren();
      if (matched.length === 0) {
        const empty = document.createElement("div");
        empty.className = "connection-empty";
        empty.textContent = detailConnections.length === 0 ? "No connections reported." : "No matching connections.";
        list.appendChild(empty);
        return;
      }
      matched.forEach(function(item) {
        const row = document.createElement("div");
        const peer = document.createElement("div");
        const status = document.createElement("span");
        row.className = "connection-item";
        peer.className = "connection-peer";
        status.className = "connection-status " + statusClassName(item.status || "unknown");
        peer.textContent = item.peer || "-";
        status.textContent = item.status || "unknown";
        row.appendChild(peer);
        row.appendChild(status);
        list.appendChild(row);
      });
    }

    function statusClassName(status) {
      return String(status || "unknown").toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    }

    async function copyText(text) {
      try { await navigator.clipboard.writeText(text); } catch (_) {}
    }

    async function copyConfig(btn) {
      const text = document.getElementById("conf-text").textContent;
      await navigator.clipboard.writeText(text);
      const old = btn.textContent;
      btn.textContent = "Copied";
      setTimeout(function() { btn.textContent = old; }, 1200);
    }

    function downloadConfig() {
      const text = document.getElementById("conf-text").textContent;
      const filename = document.getElementById("conf-filename").textContent;
      const blob = new Blob([text], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape") {
        if (document.getElementById("detail-modal").hasAttribute("open")) {
          closeDetail();
          return;
        }
        closeIssue();
      }
      if (e.key === "/" && document.activeElement && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
        const search = document.getElementById("filter-input");
        if (search) {
          e.preventDefault();
          search.focus();
        }
      }
    });

    document.getElementById("detail-modal").addEventListener("click", function(e) {
      if (e.target.id === "detail-modal") closeDetail();
    });

    document.getElementById("issue-modal").addEventListener("click", function(e) {
      if (e.target.id === "issue-modal") closeIssue();
    });
    syncPeerSelection();
  </script>
</body>
</html>`
