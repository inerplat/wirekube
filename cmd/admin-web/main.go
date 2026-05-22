package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
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

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = wirekubev1alpha1.AddToScheme(scheme)
}

func main() {
	addr := flag.String("addr", envOrDefault("WIREKUBE_ADMIN_WEB_ADDR", "127.0.0.1:8080"), "HTTP listen address")
	kubeconfig := flag.String("kubeconfig", os.Getenv("KUBECONFIG"), "optional kubeconfig path for local development")
	waitFor := flag.Duration("wait", envDuration("WIREKUBE_ADMIN_WEB_WAIT", 60*time.Second), "how long to wait for issued peers to become Active")
	flag.Parse()

	cfg, err := restConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("kubernetes config: %v", err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	s := newServer(c, *waitFor)
	log.Printf("wirekube-admin-web listening on %s", *addr)
	if err := http.ListenAndServe(*addr, s.routes()); err != nil {
		log.Fatalf("listen: %v", err)
	}
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

type server struct {
	client        client.Client
	waitFor       time.Duration
	waitForActive func(context.Context, client.Client, string, time.Duration) (*wirekubev1alpha1.WireKubeExternalPeer, error)
}

func newServer(c client.Client, waitFor time.Duration) *server {
	return &server{
		client:        c,
		waitFor:       waitFor,
		waitForActive: externalpeer.WaitForActive,
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/peers", s.handlePeers)
	mux.HandleFunc("/peers/", s.handlePeerAction)
	return mux
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
	s.render(w, r, pageData{
		Notice: r.URL.Query().Get("notice"),
	})
}

func (s *server) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.render(w, r, pageData{})
	case http.MethodPost:
		s.issuePeer(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePeerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/peers/"), "/")
	if !strings.HasSuffix(name, "/delete") {
		http.NotFound(w, r)
		return
	}
	name = strings.TrimSuffix(name, "/delete")
	name = strings.Trim(name, "/")
	if name == "" {
		http.Error(w, "missing peer name", http.StatusBadRequest)
		return
	}
	if err := externalpeer.Delete(r.Context(), s.client, name); err != nil {
		s.render(w, r, pageData{Error: err.Error()})
		return
	}
	http.Redirect(w, r, "/?notice="+url.QueryEscape("removed "+name), http.StatusSeeOther)
}

func (s *server) issuePeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, r, pageData{Error: fmt.Sprintf("parse form: %v", err)})
		return
	}
	spec, err := issueSpecFromForm(r)
	if err != nil {
		s.render(w, r, pageData{Error: err.Error()})
		return
	}
	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		s.render(w, r, pageData{Error: fmt.Sprintf("generate keypair: %v", err)})
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
		s.render(w, r, pageData{Error: fmt.Sprintf("create external peer: %v", err)})
		return
	}
	active, err := s.waitForActive(r.Context(), s.client, spec.Name, s.waitFor)
	if err != nil {
		s.render(w, r, pageData{Error: err.Error()})
		return
	}
	conf := externalpeer.RenderConfig(kp.PrivateKeyBase64(), active)
	qr, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		s.render(w, r, pageData{Error: fmt.Sprintf("encode QR: %v", err)})
		return
	}
	s.render(w, r, pageData{
		Issued: &issuedPeer{
			Name:   spec.Name,
			Config: conf,
			QR:     template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(qr)), //nolint:gosec
		},
	})
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
	if name == "" {
		return issueSpec{}, fmt.Errorf("name is required")
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return issueSpec{}, fmt.Errorf("invalid name: %s", strings.Join(errs, "; "))
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
	return issueSpec{
		Name:                name,
		DisplayName:         displayName,
		AllowedDestinations: splitCIDRs(r.FormValue("allowed")),
		IngressPeer:         strings.TrimSpace(r.FormValue("ingressPeer")),
		TTL:                 ttl,
		MTU:                 mtu,
	}, nil
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

func splitCIDRs(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (s *server) render(w http.ResponseWriter, r *http.Request, data pageData) {
	rows, err := s.peerRows(r.Context())
	if err != nil && data.Error == "" {
		data.Error = err.Error()
	}
	data.Peers = rows
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
		rows = append(rows, peerRow{
			Name:        p.Name,
			DisplayName: dash(p.Spec.DisplayName),
			Phase:       dash(string(p.Status.Phase)),
			MeshIP:      dash(p.Status.AssignedMeshIP),
			Endpoint:    dash(p.Status.RelayEndpoint),
			Ingress:     dash(p.Status.IngressPeerName),
			MTU:         externalpeer.EffectiveMTU(p),
			Age:         formatAge(now.Sub(p.CreationTimestamp.Time), !p.CreationTimestamp.IsZero()),
		})
	}
	return rows, nil
}

type pageData struct {
	Peers  []peerRow
	Issued *issuedPeer
	Error  string
	Notice string
}

type peerRow struct {
	Name        string
	DisplayName string
	Phase       string
	MeshIP      string
	Endpoint    string
	Ingress     string
	MTU         int32
	Age         string
}

type issuedPeer struct {
	Name   string
	Config string
	QR     template.URL
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

var pageTemplate = template.Must(template.New("page").Parse(pageHTML))

const pageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WireKube External Peers</title>
  <style>
    :root { color-scheme: light dark; --bg: #f7f8fa; --fg: #18202a; --muted: #667085; --line: #d7dde5; --panel: #ffffff; --accent: #1f7668; --danger: #b42318; }
    @media (prefers-color-scheme: dark) { :root { --bg: #111417; --fg: #edf1f5; --muted: #9aa4b2; --line: #303842; --panel: #181d23; --accent: #43b89f; --danger: #ff746d; } }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    header { padding: 18px 24px; border-bottom: 1px solid var(--line); background: var(--panel); }
    h1 { margin: 0; font-size: 20px; font-weight: 650; letter-spacing: 0; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; display: grid; gap: 22px; }
    section { display: grid; gap: 12px; }
    h2 { margin: 0; font-size: 15px; font-weight: 650; letter-spacing: 0; }
    form.issue { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; align-items: end; padding: 14px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); }
    label { display: grid; gap: 5px; color: var(--muted); font-size: 12px; min-width: 0; }
    input, textarea { width: 100%; border: 1px solid var(--line); border-radius: 5px; padding: 9px 10px; background: var(--bg); color: var(--fg); font: inherit; }
    textarea { min-height: 238px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
    .wide { grid-column: span 2; }
    .full { grid-column: 1 / -1; }
    button { border: 0; border-radius: 5px; padding: 10px 12px; background: var(--accent); color: white; font: inherit; font-weight: 650; cursor: pointer; white-space: nowrap; }
    button.danger { background: var(--danger); padding: 7px 10px; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 6px; overflow: hidden; }
    th, td { padding: 10px 11px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; white-space: nowrap; }
    th { color: var(--muted); font-size: 12px; font-weight: 650; }
    tr:last-child td { border-bottom: 0; }
    .scroll { overflow-x: auto; }
    .message { padding: 10px 12px; border-radius: 6px; border: 1px solid var(--line); background: var(--panel); }
    .error { border-color: var(--danger); color: var(--danger); }
    .issued { display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 16px; align-items: start; padding: 14px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); }
    .issued img { width: 256px; height: 256px; image-rendering: pixelated; border: 1px solid var(--line); border-radius: 5px; background: white; padding: 8px; }
    .empty { color: var(--muted); padding: 14px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); }
    @media (max-width: 880px) {
      main { padding: 16px; }
      form.issue { grid-template-columns: 1fr; }
      .wide, .full { grid-column: auto; }
      .issued { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header><h1>WireKube External Peers</h1></header>
  <main>
    {{if .Error}}<div class="message error">{{.Error}}</div>{{end}}
    {{if .Notice}}<div class="message">{{.Notice}}</div>{{end}}
    {{if .Issued}}
    <section>
      <h2>Issued: {{.Issued.Name}}</h2>
      <div class="issued">
        <img alt="WireGuard QR code" src="{{.Issued.QR}}">
        <textarea readonly spellcheck="false">{{.Issued.Config}}</textarea>
      </div>
    </section>
    {{end}}
    <section>
      <h2>Issue Peer</h2>
      <form class="issue" method="post" action="/peers">
        <label>Name<input name="name" autocomplete="off" required pattern="[a-z0-9]([-a-z0-9.]*[a-z0-9])?"></label>
        <label>Display<input name="displayName" autocomplete="off"></label>
        <label>TTL<input name="ttl" autocomplete="off" placeholder="24h"></label>
        <label>MTU<input name="mtu" inputmode="numeric" autocomplete="off" placeholder="1248"></label>
        <label class="wide">Ingress<input name="ingressPeer" autocomplete="off"></label>
        <label class="full">Allowed IPs<input name="allowed" autocomplete="off" placeholder="empty = controller default"></label>
        <button type="submit">Issue</button>
      </form>
    </section>
    <section>
      <h2>Peers</h2>
      {{if .Peers}}
      <div class="scroll">
        <table>
          <thead><tr><th>Name</th><th>Display</th><th>Phase</th><th>Mesh IP</th><th>Endpoint</th><th>Ingress</th><th>MTU</th><th>Age</th><th></th></tr></thead>
          <tbody>
          {{range .Peers}}
            <tr>
              <td>{{.Name}}</td><td>{{.DisplayName}}</td><td>{{.Phase}}</td><td>{{.MeshIP}}</td><td>{{.Endpoint}}</td><td>{{.Ingress}}</td><td>{{.MTU}}</td><td>{{.Age}}</td>
              <td><form method="post" action="/peers/{{.Name}}/delete"><button class="danger" type="submit">Delete</button></form></td>
            </tr>
          {{end}}
          </tbody>
        </table>
      </div>
      {{else}}
      <div class="empty">No external peers</div>
      {{end}}
    </section>
  </main>
</body>
</html>`
