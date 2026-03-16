//go:build kind_e2e

package kind_e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// workerPeers returns the names of all WireKubePeer objects that correspond to
// worker nodes (i.e. nodes without the control-plane taint). This replaces the
// old hardcoded "nas" / "worker7" peer names — the test selects peers
// dynamically based on what the cluster actually contains.
func workerPeers(ctx context.Context, t *testing.T) []string {
	t.Helper()

	// Collect control-plane node names to exclude.
	var nodeList corev1.NodeList
	if err := k8sClient.List(ctx, &nodeList); err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	cpNodes := map[string]bool{}
	for _, node := range nodeList.Items {
		for _, taint := range node.Spec.Taints {
			if taint.Key == "node-role.kubernetes.io/control-plane" ||
				taint.Key == "node-role.kubernetes.io/master" {
				cpNodes[node.Name] = true
			}
		}
	}

	var peerList wirekubev1alpha1.WireKubePeerList
	if err := k8sClient.List(ctx, &peerList); err != nil {
		t.Fatalf("list WireKubePeers: %v", err)
	}

	var workers []string
	for _, p := range peerList.Items {
		if !cpNodes[p.Name] {
			workers = append(workers, p.Name)
		}
	}
	return workers
}

// allPeerNames returns all WireKubePeer names in the cluster.
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

// waitForWorkerPeers blocks until at least minCount worker peers exist and each
// has a non-empty PublicKey (meaning the agent has initialised its WireGuard
// interface and written its peer CRD).
func waitForWorkerPeers(ctx context.Context, t *testing.T, minCount int) []string {
	t.Helper()
	var peers []string
	eventually(t, func() bool {
		peers = workerPeers(ctx, t)
		if len(peers) < minCount {
			t.Logf("waiting for %d worker peers, have %d", minCount, len(peers))
			return false
		}
		// Confirm each has a public key.
		for _, name := range peers {
			var p wirekubev1alpha1.WireKubePeer
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, &p); err != nil {
				return false
			}
			if p.Spec.PublicKey == "" {
				t.Logf("peer %s: public key not yet set", name)
				return false
			}
		}
		return true
	}, 2*time.Minute, pollInterval, "worker peers with public keys")
	return peers
}

// waitForNATDetection blocks until the given peer's WireKubePeer status has a
// non-empty NATType, indicating the agent has completed STUN-based NAT detection.
func waitForNATDetection(ctx context.Context, t *testing.T, peerName string) string {
	t.Helper()
	var natType string
	eventually(t, func() bool {
		var p wirekubev1alpha1.WireKubePeer
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &p); err != nil {
			return false
		}
		natType = p.Status.NATType
		if natType == "" {
			t.Logf("peer %s: NAT type not yet detected", peerName)
			return false
		}
		t.Logf("peer %s: NAT type = %s", peerName, natType)
		return true
	}, 2*time.Minute, pollInterval, "NAT type detection for "+peerName)
	return natType
}

// connectionMode returns the transport mode that peerName currently uses to
// reach remoteName ("direct", "relay", or "" if unknown).
func connectionMode(ctx context.Context, t *testing.T, peerName, remoteName string) string {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
		return ""
	}
	return peer.Status.Connections[remoteName]
}

// allConnectionsHaveMode returns true if every entry in
// WireKubePeer.status.connections for peerName matches the expected mode.
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

// logConnections dumps the current connection modes for a peer to the test log.
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
