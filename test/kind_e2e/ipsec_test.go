//go:build kind_e2e

package kind_e2e

// Gateway IPsec end to end. A strongSwan container on its own network plays
// the remote site's IPsec gateway (policy-based responder, like a managed
// cloud VPN), with a server on an internal network behind it. The two
// workers are the gateway's peers and run charon; the control plane is the
// client that reaches the site through the mesh.
//
//	cp ──WireGuard──▶ w1 (active) ──IKEv2/ESP──▶ site-gw ──▶ site-srv
//	                  w2 (standby)                (WAN)       (LAN)
//
// Enable with WIREKUBE_E2E_IPSEC=1. WIREKUBE_CHARON_IMAGE overrides the
// charon image (default: the agent repository + "-charon", same tag), and
// WIREKUBE_E2E_IPSEC_DATAPLANE (XFRMInterface or Policy) pins the dataplane
// and asserts it; unset means Auto.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

const (
	ipsecRunDir       = "/run/wirekube-ipsec"
	ipsecGatewayLabel = "wirekube.io/e2e-ipsec-gateway"
	ipsecGatewayName  = "e2e-site"
	ipsecSecretName   = "e2e-site-psk"
	ipsecPSK          = "e2e-site-pre-shared-key"
	ipsecSiteImage    = "wirekube-e2e-ipsec-site:latest"
	ipsecTimeout      = 3 * time.Minute
	siteVici          = "unix://" + ipsecRunDir + "/charon.vici"
)

func ipsecEnabled() bool { return os.Getenv("WIREKUBE_E2E_IPSEC") == "1" }

func charonImage() string {
	if img := os.Getenv("WIREKUBE_CHARON_IMAGE"); img != "" {
		return img
	}
	img := wireKubeImage()
	if i := strings.LastIndex(img, ":"); i > strings.LastIndex(img, "/") {
		return img[:i] + "-charon" + img[i:]
	}
	return img + "-charon"
}

type siteNet struct {
	network string
	subnet  string
	gwIP    string // the site gateway's address on this network
}

// ipsecSiteOffset separates the site networks of CNI modes that may run on
// one host, like the node networks.
func ipsecSiteOffset() int {
	switch cniMode() {
	case cniModeKubeProxyVxlan:
		return 3
	case cniModeNoKubeProxyVxlan:
		return 6
	case cniModeCalico:
		return 9
	}
	return 0
}

func ipsecPrefix() string { return strings.SplitN(cpNode().name, "-", 2)[0] }

func ipsecSiteWAN() siteNet {
	o := ipsecSiteOffset()
	return siteNet{network: ipsecPrefix() + "-site-wan", subnet: fmt.Sprintf("172.30.%d.0/24", o), gwIP: fmt.Sprintf("172.30.%d.10", o)}
}

func ipsecSiteLAN() siteNet {
	o := ipsecSiteOffset()
	return siteNet{network: ipsecPrefix() + "-site-lan", subnet: fmt.Sprintf("10.88.%d.0/24", o), gwIP: fmt.Sprintf("10.88.%d.254", o)}
}

func siteGW() string  { return ipsecPrefix() + "-site-gw" }
func siteSrv() string { return ipsecPrefix() + "-site-srv" }

func siteServerIP() string {
	o := ipsecSiteOffset()
	return fmt.Sprintf("10.88.%d.10", o)
}

func workers() []nodeConfig {
	var out []nodeConfig
	for _, n := range nodeConfigs {
		if n.role == "worker" {
			out = append(out, n)
		}
	}
	return out
}

// deployIPsecComponents starts the simulated remote site and deploys charon
// on the workers with the agent's Secret access, before the agents start.
func deployIPsecComponents() error {
	if err := startIPsecSite(); err != nil {
		return fmt.Errorf("start remote site: %w", err)
	}
	for _, w := range workers() {
		if _, err := kubectl("label", "node", w.name, ipsecGatewayLabel+"=true", "--overwrite"); err != nil {
			return err
		}
	}
	manifest := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wirekube-agent-ipsec
  namespace: %[1]s
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: wirekube-agent-ipsec
  namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: wirekube-agent-ipsec
subjects:
  - kind: ServiceAccount
    name: wirekube-agent
    namespace: %[1]s
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wirekube-charon
  namespace: %[1]s
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: wirekube-charon
  template:
    metadata:
      labels:
        app.kubernetes.io/name: wirekube-charon
    spec:
      hostNetwork: true
      automountServiceAccountToken: false
      nodeSelector:
        %[2]s: "true"
      tolerations:
        - operator: Exists
      terminationGracePeriodSeconds: 10
      containers:
        - name: charon
          image: %[3]s
          imagePullPolicy: Never
          securityContext:
            capabilities:
              add: [NET_ADMIN, NET_RAW]
          volumeMounts:
            - name: ipsec-run
              mountPath: %[4]s
      volumes:
        - name: ipsec-run
          hostPath:
            path: %[4]s
            type: DirectoryOrCreate
`, agentNamespace, ipsecGatewayLabel, charonImage(), ipsecRunDir)
	tmp, err := os.CreateTemp("", "wk-ipsec-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(manifest); err != nil {
		return err
	}
	tmp.Close()
	return kubectlApply(tmp.Name())
}

// startIPsecSite starts the site gateway and server. The gateway's iptables
// counters tell plaintext from ESP on its WAN side.
func startIPsecSite() error {
	teardownIPsecSite()
	dir, err := os.MkdirTemp("", "wk-ipsec-site-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dockerfile := fmt.Sprintf("FROM %s\nRUN apk add --no-cache iproute2 iptables tcpdump\n", charonImage())
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		return err
	}
	if _, err := ctrExec("build", "-t", ipsecSiteImage, dir); err != nil {
		return err
	}

	wan, lan := ipsecSiteWAN(), ipsecSiteLAN()
	if err := createNetwork(wan.network, wan.subnet); err != nil {
		return err
	}
	if _, err := ctrExec("network", "inspect", lan.network); err != nil {
		if _, err := ctrExec("network", "create", "--internal", "--subnet", lan.subnet, lan.network); err != nil {
			return err
		}
	}
	if _, err := ctrExec("run", "-d", "--name", siteGW(), "--hostname", siteGW(),
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
		"--sysctl", "net.ipv4.ip_forward=1",
		"--sysctl", "net.ipv4.conf.all.rp_filter=0",
		"--network", wan.network, "--ip", wan.gwIP,
		"--entrypoint", "sh", ipsecSiteImage,
		"-c", "mkdir -p "+ipsecRunDir+" && exec /usr/lib/strongswan/charon"); err != nil {
		return err
	}
	if _, err := ctrExec("network", "connect", "--ip", lan.gwIP, lan.network, siteGW()); err != nil {
		return err
	}
	if _, err := ctrExec("run", "-d", "--name", siteSrv(), "--hostname", siteSrv(),
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
		"--network", lan.network, "--ip", siteServerIP(),
		"--entrypoint", "sleep", ipsecSiteImage, "infinity"); err != nil {
		return err
	}
	// The site routes the mesh back through its IPsec gateway.
	if _, err := ctrExec("exec", siteSrv(), "ip", "route", "add", "100.64.0.0/10", "via", lan.gwIP); err != nil {
		return err
	}

	conf := fmt.Sprintf(`connections {
  site {
    version = 2
    local_addrs = %[1]s
    proposals = aes256-sha256-modp2048
    local {
      auth = psk
      id = %[1]s
    }
    remote {
      auth = psk
    }
    children {
      site {
        local_ts = %[2]s
        remote_ts = 100.64.0.0/10
        esp_proposals = aes256-sha256-modp2048
      }
    }
  }
}
secrets {
  ike-site {
    secret = "%[3]s"
  }
}
`, wan.gwIP, lan.subnet, ipsecPSK)
	if _, err := ctrExec("exec", siteGW(), "mkdir", "-p", "/etc/swanctl/conf.d"); err != nil {
		return err
	}
	if err := writeToContainer(siteGW(), "/etc/swanctl/conf.d/site.conf", conf); err != nil {
		return err
	}
	var loadErr error
	for i := 0; i < 20; i++ {
		if _, loadErr = ctrExec("exec", siteGW(), "swanctl", "--load-all", "--uri", siteVici); loadErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if loadErr != nil {
		return loadErr
	}

	wanIf, err := siteInterface(wan.gwIP)
	if err != nil {
		return err
	}
	for _, rule := range [][]string{
		{"-I", "FORWARD", "-i", wanIf, "-p", "icmp", "-m", "policy", "--dir", "in", "--pol", "none", "-m", "comment", "--comment", "e2e-plain", "-j", "ACCEPT"},
		{"-I", "INPUT", "-i", wanIf, "-p", "esp", "-m", "comment", "--comment", "e2e-esp", "-j", "ACCEPT"},
	} {
		if _, err := ctrExec(append([]string{"exec", siteGW(), "iptables"}, rule...)...); err != nil {
			return err
		}
	}
	fmt.Printf("e2e: remote IPsec site up: gateway %s, LAN %s\n", wan.gwIP, lan.subnet)
	return nil
}

func teardownIPsecSite() {
	ctrExec("rm", "-f", siteSrv(), siteGW())         //nolint:errcheck
	ctrExec("network", "rm", ipsecSiteLAN().network) //nolint:errcheck
	ctrExec("network", "rm", ipsecSiteWAN().network) //nolint:errcheck
}

func siteInterface(addr string) (string, error) {
	out, err := ctrExec("exec", siteGW(), "ip", "-o", "-4", "addr", "show")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && strings.HasPrefix(f[3], addr+"/") {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("no interface with %s on %s:\n%s", addr, siteGW(), out)
}

func iptablesCounter(t *testing.T, container, table, chain, comment string) int {
	t.Helper()
	out, err := ctrExec("exec", container, "iptables", "-t", table, "-nvxL", chain)
	if err != nil {
		t.Fatalf("read %s counters on %s: %v", chain, container, err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "/* "+comment+" */") {
			n, _ := strconv.Atoi(strings.Fields(line)[0])
			return n
		}
	}
	t.Fatalf("no rule %q in %s %s on %s:\n%s", comment, table, chain, container, out)
	return 0
}

func zeroCounters(t *testing.T, container, table, chain string) {
	t.Helper()
	if _, err := ctrExec("exec", container, "iptables", "-t", table, "-Z", chain); err != nil {
		t.Fatalf("zero %s counters on %s: %v", chain, container, err)
	}
}

// siteIKESA returns the unique ID of the site's ESTABLISHED IKE_SA, or 0.
func siteIKESA(t *testing.T) int {
	t.Helper()
	out, err := ctrExec("exec", siteGW(), "swanctl", "--list-sas", "--uri", siteVici)
	if err != nil {
		t.Logf("swanctl --list-sas: %v", err)
		return 0
	}
	m := regexp.MustCompile(`(?m)^site: #(\d+), ESTABLISHED`).FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func ipsecGateway(ctx context.Context, t *testing.T) *wirekubev1alpha1.WireKubeGateway {
	t.Helper()
	gw := &wirekubev1alpha1.WireKubeGateway{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: ipsecGatewayName}, gw); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	return gw
}

func tunnelStatus(gw *wirekubev1alpha1.WireKubeGateway) wirekubev1alpha1.GatewayIPsecTunnelStatus {
	for _, st := range gw.Status.IPsec {
		if st.Name == "vpn" {
			return st
		}
	}
	return wirekubev1alpha1.GatewayIPsecTunnelStatus{}
}

func waitForTunnel(ctx context.Context, t *testing.T, node string, phase wirekubev1alpha1.IPsecTunnelPhase, msg string) wirekubev1alpha1.GatewayIPsecTunnelStatus {
	t.Helper()
	var st wirekubev1alpha1.GatewayIPsecTunnelStatus
	eventually(t, func() bool {
		gw := ipsecGateway(ctx, t)
		st = tunnelStatus(gw)
		ok := gw.Status.ActivePeer == node && st.Phase == phase && strings.Contains(st.Message, msg)
		if !ok {
			t.Logf("gateway: activePeer=%s tunnel=%+v", gw.Status.ActivePeer, st)
		}
		return ok
	}, ipsecTimeout, 5*time.Second, fmt.Sprintf("tunnel %s on %s (message containing %q)", phase, node, msg))
	return st
}

func setPSK(ctx context.Context, t *testing.T, psk string) {
	t.Helper()
	s := &corev1.Secret{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: agentNamespace, Name: ipsecSecretName}, s); err != nil {
		t.Fatal(err)
	}
	s.Data = map[string][]byte{"psk": []byte(psk)}
	if err := k8sClient.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
}

func createPSKSecret(ctx context.Context, t *testing.T) {
	t.Helper()
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ipsecSecretName, Namespace: agentNamespace},
		Data: map[string][]byte{"psk": []byte(ipsecPSK)}}
	if err := k8sClient.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
}

func meshIPOf(ctx context.Context, t *testing.T, node string) string {
	t.Helper()
	p := &wirekubev1alpha1.WireKubePeer{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: node}, p); err != nil || len(p.Spec.AllowedIPs) == 0 {
		t.Fatalf("mesh IP of %s: %v %v", node, err, p.Spec.AllowedIPs)
	}
	return strings.SplitN(p.Spec.AllowedIPs[0], "/", 2)[0]
}

func pingSiteFromClient(ctx context.Context, t *testing.T, count int) error {
	t.Helper()
	pod := agentPodForNode(ctx, t, cpNode().name)
	out, err := execInPod(ctx, t, pod, "agent", []string{"ping", "-c", strconv.Itoa(count), "-W", "2", siteServerIP()})
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func agentMetrics(ctx context.Context, t *testing.T, node string) string {
	t.Helper()
	// Through the node's CRI: the API server cannot reach a worker's
	// kubelet across the simulated VPC isolation.
	out, err := execInPodViaCRI(t, agentPodForNode(ctx, t, node), "agent", []string{"wget", "-qO-", "http://127.0.0.1:9090/metrics"})
	if err != nil {
		t.Fatalf("metrics of %s: %v", node, err)
	}
	return out
}

func metricValue(metrics, name string) (float64, bool) {
	total, found := 0.0, false
	for _, line := range strings.Split(metrics, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
			continue
		}
		f := strings.Fields(line)
		v, err := strconv.ParseFloat(f[len(f)-1], 64)
		if err == nil {
			total += v
			found = true
		}
	}
	return total, found
}

func TestIPsecGateway(t *testing.T) {
	if !ipsecEnabled() {
		t.Skip("set WIREKUBE_E2E_IPSEC=1")
	}
	ctx := context.Background()
	waitForPeers(ctx, t, len(nodeConfigs))
	w := workers()
	if len(w) < 2 {
		t.Fatalf("need two workers, have %d", len(w))
	}
	w1, w2 := w[0].name, w[1].name
	dataplane := wirekubev1alpha1.IPsecDataplane(os.Getenv("WIREKUBE_E2E_IPSEC_DATAPLANE"))

	createPSKSecret(ctx, t)
	gw := &wirekubev1alpha1.WireKubeGateway{
		ObjectMeta: metav1.ObjectMeta{Name: ipsecGatewayName},
		Spec: wirekubev1alpha1.WireKubeGatewaySpec{
			PeerRefs: []string{w1, w2},
			Routes:   []wirekubev1alpha1.GatewayRoute{{CIDR: ipsecSiteLAN().subnet}},
			IPsec: []wirekubev1alpha1.GatewayIPsecTunnel{{
				Name: "vpn", RemoteAddress: ipsecSiteWAN().gwIP,
				PreSharedKeyRef: wirekubev1alpha1.IPsecSecretKeyRef{Name: ipsecSecretName},
				Dataplane:       dataplane,
			}},
		},
	}
	if err := k8sClient.Create(ctx, gw); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = k8sClient.Delete(ctx, &wirekubev1alpha1.WireKubeGateway{ObjectMeta: metav1.ObjectMeta{Name: ipsecGatewayName}})
		_ = k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ipsecSecretName, Namespace: agentNamespace}})
	})

	step := func(name string, fn func(t *testing.T)) {
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}

	step("establishes on the elected peer", func(t *testing.T) {
		st := waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseEstablished, "")
		if !st.Carrier || st.InstalledChildSAs < 1 {
			t.Errorf("status = %+v", st)
		}
		if dataplane != "" && st.Dataplane != dataplane {
			t.Errorf("dataplane = %s, want %s", st.Dataplane, dataplane)
		}
		g := ipsecGateway(ctx, t)
		if !g.Status.Ready || !strings.Contains(g.Status.IPsecSummary, "Established") {
			t.Errorf("ready=%v summary=%q", g.Status.Ready, g.Status.IPsecSummary)
		}
		t.Logf("tunnel: %+v", st)
	})

	step("carries traffic both ways with the mesh source", func(t *testing.T) {
		clientIP := meshIPOf(ctx, t, cpNode().name)
		if _, err := ctrExec("exec", siteSrv(), "iptables", "-I", "INPUT", "-s", clientIP, "-p", "icmp",
			"-m", "comment", "--comment", "e2e-from-client", "-j", "ACCEPT"); err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool {
			err := pingSiteFromClient(ctx, t, 3)
			if err != nil {
				t.Logf("client -> site: %v", err)
			}
			return err == nil
		}, time.Minute, 5*time.Second, "client reaches the site server")
		if n := iptablesCounter(t, siteSrv(), "filter", "INPUT", "e2e-from-client"); n < 3 {
			t.Errorf("site server saw %d packets from the client's mesh address %s", n, clientIP)
		}
		if out, err := ctrExec("exec", siteSrv(), "ping", "-c", "3", "-W", "2", clientIP); err != nil {
			t.Errorf("site -> client mesh address: %v\n%s", err, out)
		}
	})

	step("only ESP crosses the WAN", func(t *testing.T) {
		zeroCounters(t, siteGW(), "filter", "FORWARD")
		zeroCounters(t, siteGW(), "filter", "INPUT")
		if err := pingSiteFromClient(ctx, t, 5); err != nil {
			t.Fatal(err)
		}
		plain := iptablesCounter(t, siteGW(), "filter", "FORWARD", "e2e-plain")
		esp := iptablesCounter(t, siteGW(), "filter", "INPUT", "e2e-esp")
		if plain != 0 || esp < 5 {
			t.Errorf("WAN carried %d plaintext ICMP and %d ESP packets; want 0 and >= 5", plain, esp)
		}
	})

	step("drops instead of leaking while no SA covers the traffic", func(t *testing.T) {
		// Count plaintext leaving the gateway node's underlay toward the site.
		leak := []string{"-t", "mangle", "-I", "POSTROUTING", "-o", "eth0", "-d", ipsecSiteLAN().subnet,
			"-m", "policy", "--dir", "out", "--pol", "none", "-m", "comment", "--comment", "e2e-leak", "-j", "ACCEPT"}
		if _, err := ctrExec(append([]string{"exec", w1, "iptables"}, leak...)...); err != nil {
			t.Fatal(err)
		}
		before, _ := metricValue(agentMetrics(ctx, t, w1), "wirekube_ipsec_guard_dropped_packets")

		// Without its key the tunnel is torn down but the gateway keeps
		// pulling the site's traffic to w1.
		if err := k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ipsecSecretName, Namespace: agentNamespace}}); err != nil {
			t.Fatal(err)
		}
		waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseError, ipsecSecretName)
		eventually(t, func() bool { return siteIKESA(t) == 0 }, time.Minute, 2*time.Second, "site IKE_SA closed")

		if err := pingSiteFromClient(ctx, t, 5); err == nil {
			t.Errorf("site reachable without an SA")
		}
		if n := iptablesCounter(t, w1, "mangle", "POSTROUTING", "e2e-leak"); n != 0 {
			t.Errorf("%d plaintext packets left %s toward the site", n, w1)
		}
		eventually(t, func() bool {
			after, _ := metricValue(agentMetrics(ctx, t, w1), "wirekube_ipsec_guard_dropped_packets")
			return after >= before+5
		}, 30*time.Second, 5*time.Second, "guard drop counter rises")

		createPSKSecret(ctx, t)
		waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseEstablished, "")
		if err := pingSiteFromClient(ctx, t, 3); err != nil {
			t.Errorf("site unreachable after the key returned: %v", err)
		}
	})

	step("explains a failed negotiation and applies a key change", func(t *testing.T) {
		setPSK(ctx, t, "wrong-key")
		st := waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseConnecting, "authentication failed")
		t.Logf("message: %s", st.Message)
		setPSK(ctx, t, ipsecPSK)
		waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseEstablished, "")
	})

	step("keeps the SA across an agent restart", func(t *testing.T) {
		eventually(t, func() bool { return siteIKESA(t) != 0 }, time.Minute, 2*time.Second, "site IKE_SA established")
		sa := siteIKESA(t)
		restartAgentOnNode(ctx, t, w1)
		time.Sleep(15 * time.Second) // a few agent syncs
		if got := siteIKESA(t); got != sa {
			t.Errorf("site IKE_SA #%d became #%d: the restart renegotiated", sa, got)
		}
		waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseEstablished, "")
		if err := pingSiteFromClient(ctx, t, 3); err != nil {
			t.Errorf("site unreachable after the restart: %v", err)
		}
	})

	step("renegotiates when a setting changes", func(t *testing.T) {
		sa := siteIKESA(t)
		g := ipsecGateway(ctx, t)
		patch := client.MergeFrom(g.DeepCopy())
		g.Spec.IPsec[0].DPD.DelaySeconds = 10
		if err := k8sClient.Patch(ctx, g, patch); err != nil {
			t.Fatal(err)
		}
		eventually(t, func() bool {
			got := siteIKESA(t)
			return got != 0 && got != sa
		}, ipsecTimeout, 2*time.Second, "a new site IKE_SA after the change")
		waitForTunnel(ctx, t, w1, wirekubev1alpha1.IPsecTunnelPhaseEstablished, "")
	})

	step("fails over to the other peer", func(t *testing.T) {
		g := ipsecGateway(ctx, t)
		patch := client.MergeFrom(g.DeepCopy())
		g.Spec.PeerRefs = []string{w2, w1}
		if err := k8sClient.Patch(ctx, g, patch); err != nil {
			t.Fatal(err)
		}
		waitForTunnel(ctx, t, w2, wirekubev1alpha1.IPsecTunnelPhaseEstablished, "")
		eventually(t, func() bool {
			err := pingSiteFromClient(ctx, t, 3)
			if err != nil {
				t.Logf("client -> site: %v", err)
			}
			return err == nil
		}, time.Minute, 5*time.Second, "client reaches the site through "+w2)

		out, err := execInPodViaCRI(t, agentPodForNode(ctx, t, w1), "agent", []string{"ip", "xfrm", "state"})
		if err != nil || strings.TrimSpace(out) != "" {
			t.Errorf("%s kept XFRM state after handing the tunnel over (%v):\n%s", w1, err, out)
		}
		if _, found := metricValue(agentMetrics(ctx, t, w1), "wirekube_ipsec_tunnel_established"); found {
			t.Errorf("%s still exports tunnel metrics", w1)
		}
		if v, _ := metricValue(agentMetrics(ctx, t, w2), "wirekube_ipsec_tunnel_established"); v != 1 {
			t.Errorf("%s reports wirekube_ipsec_tunnel_established=%v", w2, v)
		}
	})

	step("wirekubectl reports the tunnel", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./cmd/wirekubectl", "--kubeconfig", kubeConfigPath, "--namespace", agentNamespace, "ipsec", "status")
		cmd.Dir = repoRoot()
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Established") || !strings.Contains(string(out), w2) || strings.Contains(string(out), "Warning") {
			t.Errorf("ipsec status (%v):\n%s", err, out)
		}
		cmd = exec.Command("go", "run", "./cmd/wirekubectl", "--kubeconfig", kubeConfigPath, "--namespace", agentNamespace, "ipsec", "remote-config", ipsecGatewayName)
		cmd.Dir = repoRoot()
		out, err = cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), w[0].ip) || !strings.Contains(string(out), w[1].ip) || !strings.Contains(string(out), ipsecSiteLAN().subnet) {
			t.Errorf("ipsec remote-config (%v):\n%s", err, out)
		}
	})
}
