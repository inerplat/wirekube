//go:build cluster_e2e

// Package cluster_e2e contains end-to-end tests that run against a live Kubernetes cluster.
// They inject network failures and verify that WireKube correctly transitions between
// direct and relay transport modes.
//
// Prerequisites:
//
//	A running WireKube cluster with agents deployed in the wirekube-system namespace.
//	KUBECONFIG env var or ~/.kube/config must point to the target cluster.
//
// Run:
//
//	go test -tags cluster_e2e -v ./test/cluster_e2e/... -timeout 15m
package cluster_e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

const (
	agentNamespace = "wirekube-system"
	meshName       = "default"
	wgPort         = 51822

	// Timeouts for transport state transitions.
	relayTimeout  = 3 * time.Minute  // direct → relay after path block
	directTimeout = 5 * time.Minute  // relay → direct after path restored
	pollInterval  = 5 * time.Second
)

var (
	k8sClient  client.Client
	restConfig *rest.Config
	testScheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(testScheme))
}

func TestMain(m *testing.M) {
	cfg, err := loadKubeConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cluster_e2e: failed to load kubeconfig: %v\n", err)
		os.Exit(1)
	}
	restConfig = cfg

	k8sClient, err = client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cluster_e2e: failed to create k8s client: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func loadKubeConfig() (*rest.Config, error) {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}
	home, _ := os.UserHomeDir()
	return clientcmd.BuildConfigFromFlags("", filepath.Join(home, ".kube", "config"))
}

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
	t.Fatalf("no agent pod found on node %q", nodeName)
	return corev1.Pod{}
}

// execInPod runs a command inside a pod container and returns stdout+stderr.
func execInPod(ctx context.Context, t *testing.T, pod corev1.Pod, container string, cmd []string) (string, error) {
	t.Helper()

	execOpts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
	}

	// Build the REST client for exec.
	restClient, err := rest.RESTClientFor(&rest.Config{
		Host:    restConfig.Host,
		TLSClientConfig: restConfig.TLSClientConfig,
		BearerToken: restConfig.BearerToken,
		BearerTokenFile: restConfig.BearerTokenFile,
		APIPath: "/api",
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &corev1.SchemeGroupVersion,
			NegotiatedSerializer: clientgoscheme.Codecs.WithoutConversion(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("rest client: %w", err)
	}

	req := restClient.Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(execOpts, clientgoscheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("spdy executor: %w", err)
	}

	var buf bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &buf,
		Stderr: &buf,
	})
	return buf.String(), err
}

// blockWireGuardUDP adds an iptables INPUT DROP rule on the given node's agent pod
// to drop incoming WireGuard UDP packets from the peer node's public IP.
// Returns a cleanup function that removes the rule.
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
	t.Logf("blocked WireGuard UDP on %s (pod %s)", nodeName, pod.Name)

	return func() {
		unblockCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		remove := []string{
			"iptables", "-D", "INPUT",
			"-p", "udp", "--dport", fmt.Sprintf("%d", wgPort),
			"-j", "DROP",
		}
		out, err := execInPod(unblockCtx, t, pod, "agent", remove)
		if err != nil {
			t.Logf("warning: iptables unblock on %s failed: %v (output: %s)", nodeName, err, out)
		} else {
			t.Logf("unblocked WireGuard UDP on %s", nodeName)
		}
	}
}

// patchMeshRelayMode patches the WireKubeMesh relay.mode field.
// Returns a cleanup function that restores the original mode.
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
		t.Fatalf("patch WireKubeMesh relay.mode=%s: %v", newMode, err)
	}
	t.Logf("patched WireKubeMesh relay.mode=%s (was %q)", newMode, originalMode)

	return func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var m wirekubev1alpha1.WireKubeMesh
		if err := k8sClient.Get(restoreCtx, types.NamespacedName{Name: meshName}, &m); err != nil {
			t.Logf("warning: get WireKubeMesh for restore: %v", err)
			return
		}
		p := client.MergeFrom(m.DeepCopy())
		if m.Spec.Relay == nil {
			m.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
		}
		m.Spec.Relay.Mode = originalMode
		if err := k8sClient.Patch(restoreCtx, &m, p); err != nil {
			t.Logf("warning: restore WireKubeMesh relay.mode=%q: %v", originalMode, err)
		} else {
			t.Logf("restored WireKubeMesh relay.mode=%q", originalMode)
		}
	}
}

// allConnectionsHaveMode returns true if every entry in WireKubePeer.status.connections
// for the given peer matches the expected transport mode.
func allConnectionsHaveMode(ctx context.Context, t *testing.T, peerName, mode string) bool {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
		t.Logf("get WireKubePeer %s: %v", peerName, err)
		return false
	}
	if len(peer.Status.Connections) == 0 {
		return false
	}
	for remote, transport := range peer.Status.Connections {
		if transport != mode {
			t.Logf("peer %s → %s = %q (want %q)", peerName, remote, transport, mode)
			return false
		}
	}
	return true
}

// connectionMode returns the transport mode that peerName uses to reach remoteName.
// Returns "" if not found.
func connectionMode(ctx context.Context, t *testing.T, peerName, remoteName string) string {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
		return ""
	}
	return peer.Status.Connections[remoteName]
}

// allPeerNames returns the names of all WireKubePeer objects in the cluster.
func allPeerNames(ctx context.Context, t *testing.T) []string {
	t.Helper()
	var list wirekubev1alpha1.WireKubePeerList
	if err := k8sClient.List(ctx, &list); err != nil {
		t.Fatalf("list WireKubePeers: %v", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, p := range list.Items {
		names = append(names, p.Name)
	}
	return names
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
	t.Fatalf("timed out after %s waiting for: %s", timeout, msg)
}

// logConnections dumps current connection modes for a peer to test log.
func logConnections(ctx context.Context, t *testing.T, peerName string) {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
		t.Logf("connections(%s): get error: %v", peerName, err)
		return
	}
	parts := make([]string, 0, len(peer.Status.Connections))
	for remote, mode := range peer.Status.Connections {
		parts = append(parts, remote+"="+mode)
	}
	t.Logf("connections(%s): {%s}", peerName, strings.Join(parts, ", "))
}
