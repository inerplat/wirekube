//go:build kind_e2e

package kind_e2e

import (
	"context"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func allPeers(ctx context.Context, t *testing.T) []string {
	t.Helper()
	var list wirekubev1alpha1.WireKubePeerList
	if err := k8sClient.List(ctx, &list); err != nil {
		t.Fatalf("list WireKubePeers: %v", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, p := range list.Items {
		names = append(names, p.Name)
	}
	sort.Strings(names) // ensure deterministic order; wk-cp sorts before wk-w*
	return names
}

func waitForPeers(ctx context.Context, t *testing.T, minCount int) []string {
	t.Helper()
	var peers []string
	eventually(t, func() bool {
		peers = allPeers(ctx, t)
		if len(peers) < minCount {
			t.Logf("waiting for %d peers, have %d", minCount, len(peers))
			return false
		}
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
	}, 3*time.Minute, pollInterval, "peers with public keys")
	return peers
}

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

func connectionMode(ctx context.Context, t *testing.T, peerName, remoteName string) string {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
		return ""
	}
	return peer.Status.Connections[remoteName]
}

func allConnectionsHaveMode(ctx context.Context, t *testing.T, peerName, mode string) bool {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
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

func logConnections(ctx context.Context, t *testing.T, peerName string) {
	t.Helper()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err != nil {
		t.Logf("connections(%s): error: %v", peerName, err)
		return
	}
	parts := make([]string, 0, len(peer.Status.Connections))
	for remote, mode := range peer.Status.Connections {
		parts = append(parts, remote+"="+mode)
	}
	t.Logf("connections(%s): {%s}", peerName, strings.Join(parts, ", "))
}

// nodeIPForPeer returns the mesh overlay IP for a peer (AllowedIPs[0] without /32).
// When meshCIDR is configured, peers receive a deterministic overlay IP instead of
// their physical node IP. Tests must ping this address to route through the tunnel.
func nodeIPForPeer(t *testing.T, peerName string) string {
	t.Helper()
	ctx := context.Background()
	var peer wirekubev1alpha1.WireKubePeer
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: peerName}, &peer); err == nil {
		if len(peer.Spec.AllowedIPs) > 0 {
			cidr := peer.Spec.AllowedIPs[0]
			ip, _, _ := net.ParseCIDR(cidr)
			if ip != nil {
				return ip.String()
			}
		}
	}
	// Fallback to physical node IP when meshCIDR is not configured.
	for _, n := range nodeConfigs {
		if n.name == peerName {
			return n.ip
		}
	}
	t.Fatalf("no IP for peer %q", peerName)
	return ""
}
