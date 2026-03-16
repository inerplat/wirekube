//go:build kind_e2e

// Package kind_e2e contains end-to-end tests that spin up a local kind cluster
// and verify WireKube relay/direct transport transitions under controlled
// network conditions.
//
// Infrastructure is managed entirely in-process or via CLI tools (kind, kubectl,
// docker) — no external image registry access is required at test runtime
// beyond what is already cached locally.
//
// Prerequisites (run once before this test suite):
//
//  1. kind CLI installed (https://kind.sigs.k8s.io/)
//  2. kubectl installed
//  3. WireKube image built and available in the local Docker daemon:
//     make docker-build   (or: make podman-build && podman push to docker)
//  4. Optionally, pre-pull the kind node image to avoid internet access:
//     docker pull kindest/node:v1.31.0
//
// Run:
//
//	make kind-e2e
//	# or manually:
//	go test -tags kind_e2e -v ./test/kind_e2e/... -timeout 20m
//
// Environment variables:
//
//	WIREKUBE_IMAGE          WireKube agent image to load into kind
//	                        (default: value from config/agent/daemonset.yaml)
//	WIREKUBE_KIND_CLUSTER   kind cluster name to reuse; if set and the cluster
//	                        exists, setup/teardown are skipped (dev iteration)
//	WIREKUBE_KIND_NODE_IMG  kindest/node image tag (default: kindest/node:v1.31.0)
package kind_e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// Ports used by in-process test servers (non-standard to avoid conflicts on the host).
// kind nodes reach these via the Docker bridge gateway IP.
const (
	stunPort1 = 13478 // First STUN listener (UDP)
	stunPort2 = 13480 // Second STUN listener (UDP); NAT detection requires 2+ servers
	relayPort = 13479 // Relay server (TCP + UDP for NAT probes)

	agentNamespace = "wirekube-system"
	meshName       = "default"
	wgPort         = 51822

	// Transport state transition timeouts.
	relayTimeout  = 3 * time.Minute // direct → relay after path block
	directTimeout = 5 * time.Minute // relay → direct after path restored
	pollInterval  = 5 * time.Second
)

var (
	k8sClient     client.Client
	restConfig    *rest.Config
	hostGatewayIP string // host IP as seen from inside kind containers

	testScheme    = runtime.NewScheme()
	clusterName   string
	clusterOwned  bool // true if we created the cluster (responsible for teardown)
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(testScheme))
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	code := 1
	defer func() { os.Exit(code) }()

	// ── 1. Kind cluster ──────────────────────────────────────────────────────
	var err error
	clusterName, clusterOwned, err = ensureKindCluster()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: cluster setup: %v\n", err)
		return
	}
	if clusterOwned {
		defer teardownKindCluster(clusterName)
	}

	// ── 2. kubeconfig ────────────────────────────────────────────────────────
	restConfig, err = kindKubeConfig(clusterName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: kubeconfig: %v\n", err)
		return
	}
	k8sClient, err = client.New(restConfig, client.Options{Scheme: testScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: k8s client: %v\n", err)
		return
	}

	// ── 3. Host gateway IP ──────────────────────────────────────────────────
	hostGatewayIP, err = getHostGatewayIP(clusterName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: host gateway: %v\n", err)
		return
	}
	fmt.Printf("kind_e2e: host gateway IP = %s\n", hostGatewayIP)

	// ── 4. In-process STUN servers ──────────────────────────────────────────
	// Two instances on different ports so agents detect NAT type correctly
	// (NAT detection compares mapped ports from ≥2 STUN servers).
	stunAddr1 := fmt.Sprintf("0.0.0.0:%d", stunPort1)
	stunAddr2 := fmt.Sprintf("0.0.0.0:%d", stunPort2)
	stopSTUN1, err := startSTUNServer(stunAddr1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: STUN server 1: %v\n", err)
		return
	}
	defer stopSTUN1()

	stopSTUN2, err := startSTUNServer(stunAddr2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: STUN server 2: %v\n", err)
		return
	}
	defer stopSTUN2()

	// ── 5. In-process relay server ──────────────────────────────────────────
	relayAddr := fmt.Sprintf("0.0.0.0:%d", relayPort)
	stopRelay, err := startRelayServer(relayAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: relay server: %v\n", err)
		return
	}
	defer stopRelay()

	// ── 6. Deploy WireKube into the cluster ─────────────────────────────────
	// NOTE: requires the WireKube image to be pre-built locally.
	// Run `make docker-build` (or `make podman-build`) first.
	// TODO: consider running `make docker-build` here once internet is available.
	if err := deployWireKube(ctx, clusterName); err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: deploy: %v\n", err)
		return
	}

	// ── 7. WireKubeMesh CR with in-process servers ──────────────────────────
	stunServers := []string{
		fmt.Sprintf("stun:%s:%d", hostGatewayIP, stunPort1),
		fmt.Sprintf("stun:%s:%d", hostGatewayIP, stunPort2),
	}
	relayEndpoint := fmt.Sprintf("%s:%d", hostGatewayIP, relayPort)
	if err := applyWireKubeMeshCR(ctx, stunServers, relayEndpoint); err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: WireKubeMesh CR: %v\n", err)
		return
	}

	// ── 8. Wait for agents ───────────────────────────────────────────────────
	if err := waitForAgents(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: agents not ready: %v\n", err)
		return
	}

	code = m.Run()
}

// startSTUNServer starts an in-process STUN server and returns a stop function.
// kind nodes reach it via hostGatewayIP on the given port.
func startSTUNServer(addr string) (stop func(), err error) {
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP %s: %w", addr, err)
	}
	fmt.Printf("kind_e2e: STUN server listening on %s\n", conn.LocalAddr())

	go serveSTUN(conn)

	return func() { conn.Close() }, nil
}
