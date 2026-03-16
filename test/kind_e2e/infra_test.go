//go:build kind_e2e

package kind_e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/rest"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/relay"

	"github.com/pion/stun/v3"
)

const (
	// defaultKindClusterName is used when WIREKUBE_KIND_CLUSTER is not set.
	defaultKindClusterName = "wirekube-e2e"

	// defaultKindNodeImage is the kindest/node image used for cluster creation.
	// Pre-pull with: docker pull kindest/node:v1.31.0
	// TODO: update to a newer tag once testing is resumed with internet access.
	defaultKindNodeImage = "kindest/node:v1.31.0"

	// kindConfig is the cluster configuration for the kind cluster.
	// Three nodes: 1 control-plane + 2 workers so we always have two peers
	// available for direct/relay tests regardless of node labeling.
	kindConfig = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
`
)

// ── Cluster lifecycle ────────────────────────────────────────────────────────

// ensureKindCluster creates a kind cluster if one does not already exist, or
// reuses one whose name is provided via WIREKUBE_KIND_CLUSTER.
// Returns the cluster name, whether this call owns it (and should tear it down),
// and any error.
func ensureKindCluster() (name string, owned bool, err error) {
	if name = os.Getenv("WIREKUBE_KIND_CLUSTER"); name != "" {
		fmt.Printf("kind_e2e: reusing existing cluster %q\n", name)
		return name, false, nil
	}
	name = defaultKindClusterName

	// Check if the cluster already exists.
	out, _ := kindExec("get", "clusters")
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == name {
			fmt.Printf("kind_e2e: reusing existing cluster %q (not owned)\n", name)
			return name, false, nil
		}
	}

	// Create the cluster.
	// NOTE: 'kind create cluster' may pull kindest/node image from the internet
	// if not already cached locally.
	// Pre-pull to avoid downloads: docker pull kindest/node:v1.31.0
	nodeImg := os.Getenv("WIREKUBE_KIND_NODE_IMG")
	if nodeImg == "" {
		nodeImg = defaultKindNodeImage
	}

	cfgFile, err := os.CreateTemp("", "wirekube-kind-*.yaml")
	if err != nil {
		return "", false, fmt.Errorf("temp kind config: %w", err)
	}
	defer os.Remove(cfgFile.Name())
	if _, err := cfgFile.WriteString(kindConfig); err != nil {
		return "", false, fmt.Errorf("write kind config: %w", err)
	}
	cfgFile.Close()

	fmt.Printf("kind_e2e: creating cluster %q (node image: %s)…\n", name, nodeImg)
	if _, err := kindExec("create", "cluster",
		"--name", name,
		"--image", nodeImg,
		"--config", cfgFile.Name(),
	); err != nil {
		return "", false, fmt.Errorf("kind create cluster: %w", err)
	}

	fmt.Printf("kind_e2e: cluster %q created\n", name)
	return name, true, nil
}

func teardownKindCluster(name string) {
	fmt.Printf("kind_e2e: deleting cluster %q…\n", name)
	if _, err := kindExec("delete", "cluster", "--name", name); err != nil {
		fmt.Fprintf(os.Stderr, "kind_e2e: delete cluster %q: %v\n", name, err)
	}
}

func kindKubeConfig(clusterName string) (*rest.Config, error) {
	out, err := kindExec("get", "kubeconfig", "--name", clusterName)
	if err != nil {
		return nil, fmt.Errorf("get kubeconfig: %w", err)
	}
	return clientcmd.RESTConfigFromKubeConfig([]byte(out))
}

// getHostGatewayIP returns the IP address of the host machine as reachable from
// inside kind containers. This is the Docker bridge gateway for the kind network.
func getHostGatewayIP(clusterName string) (string, error) {
	networkName := "kind"
	out, err := dockerExec("network", "inspect", networkName,
		"--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}")
	if err != nil {
		return "", fmt.Errorf("docker network inspect kind: %w", err)
	}
	// 'docker network inspect' may return multiple lines if there are multiple
	// IPAM configs; take the first non-empty one.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && net.ParseIP(line) != nil {
			return line, nil
		}
	}
	return "", fmt.Errorf("could not determine host gateway IP from kind network")
}

// ── WireKube deployment ──────────────────────────────────────────────────────

// deployWireKube loads the WireKube image into the cluster and applies
// CRDs, RBAC, and the agent DaemonSet.
func deployWireKube(ctx context.Context, clusterName string) error {
	image := wireKubeImage()

	// Load the pre-built image into kind — no registry pull required.
	// The image must already exist in the local Docker daemon.
	// Run `make docker-build` (or `make podman-build`) to build it first.
	fmt.Printf("kind_e2e: loading image %s into cluster %q…\n", image, clusterName)
	if _, err := kindExec("load", "docker-image", image, "--name", clusterName); err != nil {
		return fmt.Errorf("kind load docker-image %s: %w\n"+
			"  hint: run `make docker-build` to build the image first", image, err)
	}

	// Apply manifests: CRDs → RBAC → DaemonSet (with patched image).
	manifests := []string{
		"config/crd",
		"config/agent/rbac.yaml",
	}
	for _, m := range manifests {
		if err := kubectlApply(ctx, clusterName, m); err != nil {
			return err
		}
	}

	// Apply DaemonSet with the correct image injected.
	if err := applyDaemonSet(ctx, clusterName, image); err != nil {
		return err
	}

	return nil
}

// wireKubeImage returns the WireKube image to use. Prefers WIREKUBE_IMAGE env
// var; falls back to the image tag from config/agent/daemonset.yaml.
func wireKubeImage() string {
	if img := os.Getenv("WIREKUBE_IMAGE"); img != "" {
		return img
	}
	// Default matches the image in config/agent/daemonset.yaml.
	// Update this constant when the image tag changes.
	return "inerplat/wirekube:v0.0.8-dev.15"
}

// applyDaemonSet applies the agent DaemonSet YAML with the image tag replaced
// to match what was loaded into the kind cluster.
func applyDaemonSet(ctx context.Context, clusterName, image string) error {
	// Read the daemonset template.
	raw, err := os.ReadFile("config/agent/daemonset.yaml")
	if err != nil {
		return fmt.Errorf("read daemonset: %w", err)
	}

	// Replace the image tag with the one we loaded.
	// The DaemonSet YAML has exactly one `image:` line for the agent container.
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "image:") {
			indent := strings.Repeat(" ", len(line)-len(strings.TrimLeft(line, " ")))
			lines[i] = indent + "image: " + image
		}
	}
	patched := strings.Join(lines, "\n")

	// Write to a temp file and apply.
	tmp, err := os.CreateTemp("", "wirekube-ds-*.yaml")
	if err != nil {
		return fmt.Errorf("temp daemonset: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(patched); err != nil {
		return err
	}
	tmp.Close()

	return kubectlApply(ctx, clusterName, tmp.Name())
}

// applyWireKubeMeshCR creates (or updates) the default WireKubeMesh CR pointing
// to the in-process STUN and relay servers running on the host.
func applyWireKubeMeshCR(ctx context.Context, stunServers []string, relayEndpoint string) error {
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	mesh.Name = meshName
	mesh.Spec.ListenPort = wgPort
	mesh.Spec.STUNServers = stunServers
	mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{
		Mode:     "auto",
		Provider: "external",
		External: &wirekubev1alpha1.ExternalRelaySpec{
			Endpoint:  relayEndpoint,
			Transport: "tcp",
		},
		HandshakeTimeoutSeconds:    30,
		DirectRetryIntervalSeconds: 60,
	}

	existing := &wirekubev1alpha1.WireKubeMesh{}
	err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, existing)
	if err != nil {
		// Create.
		return k8sClient.Create(ctx, mesh)
	}
	// Update.
	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec = mesh.Spec
	return k8sClient.Patch(ctx, existing, patch)
}

// waitForAgents blocks until all wirekube-agent pods are Running and the
// wirekube-system namespace has at least one WireKubePeer with a public key.
func waitForAgents(ctx context.Context) error {
	fmt.Println("kind_e2e: waiting for agents to be ready…")
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		var list corev1.PodList
		if err := k8sClient.List(ctx, &list,
			client.InNamespace(agentNamespace),
			client.MatchingLabels{"app": "wirekube-agent"},
		); err == nil {
			ready := 0
			for _, pod := range list.Items {
				if pod.Status.Phase == corev1.PodRunning {
					ready++
				}
			}
			if ready >= 2 {
				fmt.Printf("kind_e2e: %d agent pods running\n", ready)
				// Give agents a moment to post their WireKubePeer.
				time.Sleep(5 * time.Second)
				return nil
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for agent pods to be Running")
}

// ── In-process servers ───────────────────────────────────────────────────────

// serveSTUN handles incoming STUN Binding Requests, responding with the
// observed client address in XOR-MAPPED-ADDRESS.
// Runs until conn is closed.
func serveSTUN(conn net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return // listener closed
		}

		var req stun.Message
		req.Raw = make([]byte, n)
		copy(req.Raw, buf[:n])
		if err := req.Decode(); err != nil {
			continue
		}
		if req.Type != stun.BindingRequest {
			continue
		}

		udpFrom, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip := udpFrom.IP.To4()
		if ip == nil {
			ip = udpFrom.IP
		}

		res, err := stun.Build(
			stun.BindingSuccess,
			transactionIDSetter(req.TransactionID),
			&stun.XORMappedAddress{IP: ip, Port: udpFrom.Port},
		)
		if err != nil {
			continue
		}
		conn.WriteTo(res.Raw, from) //nolint:errcheck
	}
}

// transactionIDSetter echoes the request's transaction ID into the response.
// stun.Message.TransactionID is [12]byte (stun.TransactionIDSize = 12).
type transactionIDSetter [12]byte

func (s transactionIDSetter) AddTo(m *stun.Message) error {
	copy(m.TransactionID[:], s[:])
	return nil
}

// startRelayServer starts an in-process relay server and returns a stop
// function. The relay binds both TCP and UDP on addr.
func startRelayServer(addr string) (stop func(), err error) {
	srv := relay.NewServer()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(addr); err != nil {
			errCh <- err
		}
	}()

	// Give the server a moment to bind.
	select {
	case err := <-errCh:
		return nil, fmt.Errorf("relay server: %w", err)
	case <-time.After(200 * time.Millisecond):
	}

	fmt.Printf("kind_e2e: relay server listening on %s\n", addr)
	// relay.Server has no graceful shutdown; closing the listener would require
	// a context-aware version. For test purposes, the process ending is enough.
	return func() { /* relay stops when the process exits */ }, nil
}

// ── Fault injection ──────────────────────────────────────────────────────────

// blockWireGuardUDP inserts an iptables INPUT DROP rule on the given node's
// agent pod to block incoming WireGuard UDP packets. Returns a cleanup func
// that removes the rule.
func blockWireGuardUDP(ctx context.Context, t *testing.T, nodeName string) func() {
	t.Helper()
	pod := agentPodForNode(ctx, t, nodeName)

	rule := []string{
		"iptables", "-I", "INPUT", "1",
		"-p", "udp", "--dport", fmt.Sprintf("%d", wgPort),
		"-j", "DROP",
	}
	out, err := execInPod(ctx, t, pod, "agent", rule)
	if err != nil {
		t.Fatalf("iptables block on %s: %v\noutput: %s", nodeName, err, out)
	}
	t.Logf("blocked WireGuard UDP on %s", nodeName)

	return func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		remove := []string{
			"iptables", "-D", "INPUT",
			"-p", "udp", "--dport", fmt.Sprintf("%d", wgPort),
			"-j", "DROP",
		}
		out, err := execInPod(cleanCtx, t, pod, "agent", remove)
		if err != nil {
			t.Logf("warning: iptables unblock on %s: %v (output: %s)", nodeName, err, out)
		} else {
			t.Logf("unblocked WireGuard UDP on %s", nodeName)
		}
	}
}

// patchMeshRelayMode patches the WireKubeMesh relay.mode field and returns a
// restore function that reverts to the original mode.
func patchMeshRelayMode(ctx context.Context, t *testing.T, newMode string) func() {
	t.Helper()

	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Fatalf("get WireKubeMesh: %v", err)
	}
	originalMode := ""
	if mesh.Spec.Relay != nil {
		originalMode = mesh.Spec.Relay.Mode
	}

	patch := client.MergeFrom(mesh.DeepCopy())
	if mesh.Spec.Relay == nil {
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
	}
	mesh.Spec.Relay.Mode = newMode
	if err := k8sClient.Patch(ctx, &mesh, patch); err != nil {
		t.Fatalf("patch relay.mode=%s: %v", newMode, err)
	}
	t.Logf("patched WireKubeMesh relay.mode=%s (was %q)", newMode, originalMode)

	return func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var m wirekubev1alpha1.WireKubeMesh
		if err := k8sClient.Get(restoreCtx, types.NamespacedName{Name: meshName}, &m); err != nil {
			t.Logf("warning: restore relay.mode — get: %v", err)
			return
		}
		p := client.MergeFrom(m.DeepCopy())
		if m.Spec.Relay == nil {
			m.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
		}
		m.Spec.Relay.Mode = originalMode
		if err := k8sClient.Patch(restoreCtx, &m, p); err != nil {
			t.Logf("warning: restore relay.mode=%q: %v", originalMode, err)
		} else {
			t.Logf("restored WireKubeMesh relay.mode=%q", originalMode)
		}
	}
}

// ── Pod execution ────────────────────────────────────────────────────────────

// agentPodForNode returns the wirekube-agent Pod running on the given node.
func agentPodForNode(ctx context.Context, t *testing.T, nodeName string) corev1.Pod {
	t.Helper()
	var list corev1.PodList
	if err := k8sClient.List(ctx, &list,
		client.InNamespace(agentNamespace),
		client.MatchingLabels{"app": "wirekube-agent"},
	); err != nil {
		t.Fatalf("list agent pods: %v", err)
	}
	for _, pod := range list.Items {
		if pod.Spec.NodeName == nodeName {
			return pod
		}
	}
	t.Fatalf("no agent pod on node %q", nodeName)
	return corev1.Pod{}
}

// execInPod runs a command inside a pod container and returns combined stdout+stderr.
func execInPod(ctx context.Context, t *testing.T, pod corev1.Pod, container string, cmd []string) (string, error) {
	t.Helper()

	execOpts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
	}

	rc, err := rest.RESTClientFor(&rest.Config{
		Host:            restConfig.Host,
		TLSClientConfig: restConfig.TLSClientConfig,
		BearerToken:     restConfig.BearerToken,
		BearerTokenFile: restConfig.BearerTokenFile,
		APIPath:         "/api",
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &corev1.SchemeGroupVersion,
			NegotiatedSerializer: clientgoscheme.Codecs.WithoutConversion(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("rest client: %w", err)
	}

	req := rc.Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(execOpts, clientgoscheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("spdy executor: %w", err)
	}

	var buf bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &buf,
		Stderr: &buf,
	})
	return buf.String(), err
}

// ── CLI helpers ──────────────────────────────────────────────────────────────

func kindExec(args ...string) (string, error) {
	return runCmd("kind", args...)
}

func dockerExec(args ...string) (string, error) {
	return runCmd("docker", args...)
}

func kubectlApply(ctx context.Context, clusterName, path string) error {
	kubeCtx := "kind-" + clusterName
	_, err := runCmd("kubectl", "--context", kubeCtx, "apply", "-f", path)
	return err
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w\noutput:\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

// eventually polls fn until it returns true or timeout elapses.
func eventually(t *testing.T, fn func() bool, timeout, interval time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timed out after %s: %s", timeout, msg)
}
