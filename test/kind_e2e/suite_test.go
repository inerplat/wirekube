//go:build kind_e2e

// Package kind_e2e runs end-to-end tests for WireKube on isolated container
// networks. Each node runs in a separate 172.x subnet using kindest/node
// images bootstrapped directly with kubeadm — no kind CLI is required.
//
// Network topology:
//
//	wk-vpc-1 (172.20.0.0/24) ─── wk-cp  (control-plane, 172.20.0.2)
//	wk-vpc-2 (172.21.0.0/24) ─── wk-w1  (worker,        172.21.0.2)
//	wk-vpc-3 (172.22.0.0/24) ─── wk-w2  (worker,        172.22.0.2)
//
//	Nodes reach each other via L3 routing through the container host kernel.
//	STUN servers run as processes inside the CP container.
//	Relay runs as a K8s Pod on the CP (taint removed, hostNetwork).
//	K8s API on wk-cp:6443, port-forwarded to localhost for the test client.
//
// Prerequisites:
//
//	docker or podman
//	kubectl
//	WireKube image built: podman build -t inerplat/wirekube:<ver> .
//	kindest/node pulled:  podman pull kindest/node:v1.31.0
//
// Run:
//
//	make kind-e2e
//
// Environment variables:
//
//	WIREKUBE_IMAGE              override agent/relay image
//	WIREKUBE_KIND_NODE_IMG      override kindest/node image
//	WIREKUBE_E2E_REUSE=1        skip teardown for faster re-runs
//	WIREKUBE_E2E_SKIP_SETUP=1   skip cluster creation (assume running)
//	WIREKUBE_E2E_CNI_MODE       "kube-proxy-vxlan" (default) or "no-kube-proxy-vxlan"
package kind_e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	kruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

const (
	stunPort1 = 13478
	stunPort2 = 13480

	agentNamespace = "wirekube-system"
	meshName       = "default"
	wgPort         = 51822

	relayTimeout  = 3 * time.Minute
	directTimeout = 3 * time.Minute
	pollInterval  = 2 * time.Second

	defaultNodeImage     = "kindest/node:v1.34.0"
	defaultWireKubeImage = "inerplat/wirekube:v0.0.8-dev.15"

	cniModeKubeProxyVxlan   = "kube-proxy-vxlan"
	cniModeNoKubeProxyVxlan = "no-kube-proxy-vxlan"
)

type nodeConfig struct {
	name    string
	network string
	subnet  string
	ip      string
	role    string // "control-plane" or "worker"
}

var nodeConfigs = []nodeConfig{
	{name: "wk-cp", network: "wk-vpc-1", subnet: "172.20.0.0/24", ip: "172.20.0.2", role: "control-plane"},
	{name: "wk-w1", network: "wk-vpc-2", subnet: "172.21.0.0/24", ip: "172.21.0.2", role: "worker"},
	{name: "wk-w2", network: "wk-vpc-3", subnet: "172.22.0.0/24", ip: "172.22.0.2", role: "worker"},
}

var (
	k8sClient      client.Client
	restConfig     *rest.Config
	testScheme     = kruntime.NewScheme()
	kubeConfigPath string
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(testScheme))
}

func cpNode() nodeConfig { return nodeConfigs[0] }

func repoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func nodeImage() string {
	if img := os.Getenv("WIREKUBE_KIND_NODE_IMG"); img != "" {
		return img
	}
	return defaultNodeImage
}

func wireKubeImage() string {
	if img := os.Getenv("WIREKUBE_IMAGE"); img != "" {
		return img
	}
	return defaultWireKubeImage
}

func cniMode() string {
	if mode := os.Getenv("WIREKUBE_E2E_CNI_MODE"); mode != "" {
		return mode
	}
	return cniModeKubeProxyVxlan
}

func skipKubeProxy() bool {
	return cniMode() == cniModeNoKubeProxyVxlan
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	code := 1
	defer func() { os.Exit(code) }()

	if err := os.Chdir(repoRoot()); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: chdir: %v\n", err)
		return
	}

	// ── 1. Bootstrap K8s cluster on isolated networks ────────────────────────
	if err := setupCluster(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: cluster setup: %v\n", err)
		return
	}
	if os.Getenv("WIREKUBE_E2E_REUSE") == "" {
		defer teardownCluster()
	}

	// ── 2. Kubernetes client (via port-forwarded API on localhost:6443) ──────
	var err error
	restConfig, kubeConfigPath, err = extractKubeConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: kubeconfig: %v\n", err)
		return
	}
	k8sClient, err = client.New(restConfig, client.Options{Scheme: testScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: k8s client: %v\n", err)
		return
	}

	// ── 3. Deploy WireKube CRDs + RBAC, then create Mesh CR before agents ──
	if err := deployWireKubeCRDs(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: deploy CRDs: %v\n", err)
		return
	}

	// Mesh CR must exist before agents start so they pick up listenPort.
	cpIP := cpNode().ip
	stunServers := []string{
		fmt.Sprintf("stun:%s:%d", cpIP, stunPort1),
		fmt.Sprintf("stun:%s:%d", cpIP, stunPort2),
	}
	relayEndpoint := fmt.Sprintf("%s:3478", cpIP)
	if err := applyWireKubeMeshCR(ctx, stunServers, relayEndpoint); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: mesh CR: %v\n", err)
		return
	}

	// Now deploy agents + relay (they will read the existing mesh CR)
	if err := deployWireKubeAgents(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: deploy agents: %v\n", err)
		return
	}

	// ── 4. Wait for all agents (CP + workers) ───────────────────────────────
	if err := waitForAgents(ctx, len(nodeConfigs)); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: agents not ready: %v\n", err)
		return
	}

	code = m.Run()
}
