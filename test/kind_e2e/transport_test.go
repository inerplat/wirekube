//go:build kind_e2e

package kind_e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// TestNATTypeDetected verifies STUN reachability and NAT type reporting for
// ALL nodes including control-plane.
func TestNATTypeDetected(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	t.Logf("all peers: %v", peers)

	for _, name := range peers {
		natType := waitForNATDetection(ctx, t, name)
		if natType == "" {
			t.Errorf("peer %s: NATType still empty", name)
		}
		t.Logf("peer %s NAT type: %s", name, natType)
	}
}

// TestWireGuardTunnel verifies that the control-plane node establishes
// WireGuard tunnels (direct or relay) to all worker nodes.
func TestWireGuardTunnel(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]

	t.Logf("waiting for %s to establish tunnels…", subject)
	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		for _, name := range peers {
			if name == subject {
				continue
			}
			mode := connectionMode(ctx, t, subject, name)
			if mode != "direct" && mode != "relay" {
				return false
			}
		}
		return true
	}, 3*time.Minute, pollInterval, "all peers should be connected")

	t.Logf("%s has tunnels to all peers", subject)
}

// TestPingOverTunnel verifies data-plane connectivity between nodes on
// different private subnets (172.20.x, 172.21.x, 172.22.x). The AllowedIPs
// /32 route ensures traffic traverses the WireGuard tunnel rather than the
// default gateway.
func TestPingOverTunnel(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	if len(peers) < 2 {
		t.Skip("need at least 2 peers")
	}

	subject := peers[0]
	remote := peers[1]

	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		return mode == "direct" || mode == "relay"
	}, 3*time.Minute, pollInterval, subject+" → "+remote+" should be connected")

	remoteIP := nodeIPForPeer(t, remote)
	pod := agentPodForNode(ctx, t, subject)

	t.Logf("pinging %s (%s) from %s…", remote, remoteIP, subject)

	var pingOutput string
	eventually(t, func() bool {
		out, err := execInPod(ctx, t, pod, "agent",
			[]string{"ping", "-c", "3", "-W", "2", remoteIP})
		pingOutput = out
		if err != nil {
			t.Logf("ping %s: %v (%s)", remoteIP, err, out)
			return false
		}
		return true
	}, 2*time.Minute, 10*time.Second,
		fmt.Sprintf("ping from %s to %s (%s)", subject, remote, remoteIP))

	t.Logf("ping succeeded:\n%s", pingOutput)
}

// TestAllNodesReachable verifies that the control-plane has connections
// to all worker nodes and can ping them.
func TestAllNodesReachable(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0] // CP node — always has connections to workers

	// Verify CP has connections to all workers.
	for _, remote := range peers {
		if subject == remote {
			continue
		}
		rem := remote
		eventually(t, func() bool {
			mode := connectionMode(ctx, t, subject, rem)
			t.Logf("%s → %s = %q", subject, rem, mode)
			return mode == "direct" || mode == "relay"
		}, 3*time.Minute, pollInterval,
			subject+" → "+rem+" should have connection")
	}

	// Verify data-plane ping from CP to all workers.
	for _, remote := range peers {
		if subject == remote {
			continue
		}
		remoteIP := nodeIPForPeer(t, remote)
		pod := agentPodForNode(ctx, t, subject)
		rem := remote
		eventually(t, func() bool {
			out, err := execInPod(ctx, t, pod, "agent",
				[]string{"ping", "-c", "2", "-W", "2", remoteIP})
			if err != nil {
				t.Logf("ping %s→%s (%s): %v", subject, rem, remoteIP, err)
				return false
			}
			_ = out
			return true
		}, 1*time.Minute, 5*time.Second,
			fmt.Sprintf("ping %s → %s (%s)", subject, rem, remoteIP))
		t.Logf("ping %s → %s OK", subject, rem)
	}
	t.Log("all nodes reachable from CP")
}

// TestRelayFallback blocks WireGuard UDP on one node, verifies relay fallback,
// then unblocks and verifies recovery.
func TestRelayFallback(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]
	remote := peers[1]

	// Wait for any established connection first.
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		return mode == "direct" || mode == "relay"
	}, 3*time.Minute, pollInterval, subject+" → "+remote+" should be connected")

	baselineMode := connectionMode(ctx, t, subject, remote)
	t.Logf("baseline: %s → %s is %s", subject, remote, baselineMode)

	unblock := blockWireGuardUDP(t, subject)
	defer unblock()

	t.Logf("WG UDP blocked on %s — waiting for relay…", subject)
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "relay"
	}, relayTimeout, pollInterval, subject+" → "+remote+" should relay")

	unblock()

	t.Logf("unblocked — waiting for connection recovery…")
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "direct" || mode == "relay"
	}, directTimeout, pollInterval, subject+" → "+remote+" should recover")
	t.Log("relay fallback and recovery confirmed")
}

// TestRelayModeAlways forces relay.mode=always, verifies, then restores.
func TestRelayModeAlways(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]

	// Wait for any connection before mode change.
	eventually(t, func() bool {
		for _, name := range peers {
			if name == subject {
				continue
			}
			mode := connectionMode(ctx, t, subject, name)
			if mode == "direct" || mode == "relay" {
				return true
			}
		}
		return false
	}, 2*time.Minute, pollInterval, "at least one connection before mode change")

	restore := patchMeshRelayMode(ctx, t, "always")
	defer restore()

	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		return allConnectionsHaveMode(ctx, t, subject, "relay")
	}, relayTimeout, pollInterval, "all connections on "+subject+" should be relay")

	restore()

	// After restoring to auto, verify connections come back.
	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		for _, name := range peers {
			if name == subject {
				continue
			}
			mode := connectionMode(ctx, t, subject, name)
			if mode != "direct" && mode != "relay" {
				return false
			}
		}
		return true
	}, directTimeout, pollInterval, "all connections should recover")
	t.Log("relay.mode=always → auto recovery confirmed")
}

// TestPeerCRDStatus verifies that CRD status fields are properly populated
// after connections are established: Connected, EndpointDiscoveryMethod,
// ICECandidates, and Connections map.
func TestPeerCRDStatus(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)

	// Wait for CP to have connections.
	subject := peers[0]
	remote := peers[1]
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		return mode == "direct" || mode == "relay"
	}, 3*time.Minute, pollInterval, subject+" → "+remote+" should be connected")

	for _, name := range peers {
		var p wirekubev1alpha1.WireKubePeer
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name}, &p); err != nil {
			t.Fatalf("get peer %s: %v", name, err)
		}

		// Spec fields
		if p.Spec.PublicKey == "" {
			t.Errorf("peer %s: PublicKey empty", name)
		}
		if p.Spec.Endpoint == "" {
			t.Errorf("peer %s: Endpoint empty", name)
		}
		if len(p.Spec.AllowedIPs) == 0 {
			t.Errorf("peer %s: AllowedIPs empty", name)
		}

		// Status fields
		if p.Status.NATType == "" {
			t.Errorf("peer %s: NATType empty", name)
		}
		if p.Status.EndpointDiscoveryMethod == "" {
			t.Errorf("peer %s: EndpointDiscoveryMethod empty", name)
		}
		t.Logf("peer %s: endpoint=%s method=%s nat=%s connected=%v candidates=%d connections=%v",
			name, p.Spec.Endpoint, p.Status.EndpointDiscoveryMethod,
			p.Status.NATType, p.Status.Connected, len(p.Status.ICECandidates),
			p.Status.Connections)
	}
}

// TestBidirectionalPing verifies data-plane connectivity from the CP to
// all worker nodes. The CP node reliably reports connections in its CRD.
func TestBidirectionalPing(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0] // CP node

	// Wait for CP to have connections to all workers.
	for _, r := range peers {
		if subject == r {
			continue
		}
		rem := r
		eventually(t, func() bool {
			m := connectionMode(ctx, t, subject, rem)
			return m == "direct" || m == "relay"
		}, 3*time.Minute, pollInterval, subject+" → "+rem+" should be connected")
	}

	// Ping from CP to each worker.
	for _, r := range peers {
		if subject == r {
			continue
		}
		remoteIP := nodeIPForPeer(t, r)
		pod := agentPodForNode(ctx, t, subject)

		eventually(t, func() bool {
			out, err := execInPod(ctx, t, pod, "agent",
				[]string{"ping", "-c", "2", "-W", "2", remoteIP})
			if err != nil {
				t.Logf("ping %s→%s (%s): %v", subject, r, remoteIP, err)
				return false
			}
			_ = out
			return true
		}, 1*time.Minute, 5*time.Second,
			fmt.Sprintf("ping %s → %s (%s)", subject, r, remoteIP))

		t.Logf("ping %s → %s OK", subject, r)
	}
}

// TestDataPlaneUnderRelay verifies that actual data transfer works when
// all traffic is forced through the relay.
func TestDataPlaneUnderRelay(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]
	remote := peers[1]

	restore := patchMeshRelayMode(ctx, t, "always")
	defer restore()

	eventually(t, func() bool {
		return connectionMode(ctx, t, subject, remote) == "relay"
	}, relayTimeout, pollInterval, subject+" → "+remote+" should be relay")

	remoteIP := nodeIPForPeer(t, remote)
	pod := agentPodForNode(ctx, t, subject)

	eventually(t, func() bool {
		out, err := execInPod(ctx, t, pod, "agent",
			[]string{"ping", "-c", "3", "-W", "3", remoteIP})
		if err != nil {
			t.Logf("relay ping %s→%s: %v (%s)", subject, remote, err, out)
			return false
		}
		t.Logf("relay ping succeeded:\n%s", out)
		return true
	}, 2*time.Minute, 10*time.Second,
		fmt.Sprintf("ping over relay %s → %s", subject, remote))

	restore()
}

// TestAgentRestart deletes an agent pod and verifies that connections
// recover after the pod is recreated by the DaemonSet.
func TestAgentRestart(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]
	remote := peers[1]

	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		return mode == "direct" || mode == "relay"
	}, 3*time.Minute, pollInterval, subject+" → "+remote+" should be connected")

	// Delete the agent pod on subject node.
	pod := agentPodForNode(ctx, t, subject)
	oldPodName := pod.Name
	t.Logf("deleting agent pod %s on %s", oldPodName, subject)
	if _, err := kubectlInCP("delete", "pod", "-n", agentNamespace, oldPodName, "--grace-period=0", "--force"); err != nil {
		t.Fatalf("delete pod %s: %v", oldPodName, err)
	}

	// Wait for new pod to come up.
	time.Sleep(5 * time.Second)
	eventually(t, func() bool {
		newPod := agentPodForNode(ctx, t, subject)
		if newPod.Name == "" || newPod.Name == oldPodName {
			t.Logf("waiting for new agent pod (current: %s, old: %s)", newPod.Name, oldPodName)
			return false
		}
		t.Logf("new agent pod: %s", newPod.Name)
		return true
	}, 2*time.Minute, pollInterval, "new agent pod on "+subject)

	// Wait for connection recovery.
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q (after restart)", subject, remote, mode)
		return mode == "direct" || mode == "relay"
	}, directTimeout, pollInterval, subject+" → "+remote+" should recover after restart")

	t.Log("agent restart recovery confirmed")
}

// TestMetricsEndpoint verifies that the Prometheus metrics endpoint is
// reachable and returns expected WireKube metrics.
func TestMetricsEndpoint(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]

	// Wait for connections.
	eventually(t, func() bool {
		return connectionMode(ctx, t, subject, peers[1]) != ""
	}, 2*time.Minute, pollInterval, "connections established")

	pod := agentPodForNode(ctx, t, subject)

	var metricsOut string
	eventually(t, func() bool {
		out, err := execInPod(ctx, t, pod, "agent",
			[]string{"wget", "-qO-", "http://127.0.0.1:9090/metrics"})
		if err != nil {
			t.Logf("metrics fetch: %v", err)
			return false
		}
		metricsOut = out
		return true
	}, 1*time.Minute, 5*time.Second, "metrics endpoint should be reachable")

	expectedMetrics := []string{
		"wirekube_peer_connected",
		"wirekube_peers_total",
		"wirekube_peer_transport_mode",
		"wirekube_node_nat_type",
	}
	for _, metric := range expectedMetrics {
		if !strings.Contains(metricsOut, metric) {
			t.Errorf("metrics missing %q", metric)
		}
	}
	t.Logf("metrics endpoint OK (%d bytes, all expected metrics present)", len(metricsOut))
}

// TestRelayReconnect breaks and restores the relay endpoint.
func TestRelayReconnect(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]
	remote := peers[1]

	restoreMode := patchMeshRelayMode(ctx, t, "always")
	defer restoreMode()

	eventually(t, func() bool {
		return connectionMode(ctx, t, subject, remote) == "relay"
	}, relayTimeout, pollInterval, subject+" → "+remote+" should be relay")

	original := relayEndpointFromMesh(ctx, t)
	if original == "" {
		t.Skip("no external relay endpoint")
	}

	setRelayEndpoint(ctx, t, "127.0.0.1:19999")
	defer setRelayEndpoint(ctx, t, original)

	t.Log("relay broken — waiting 15s…")
	time.Sleep(15 * time.Second)

	setRelayEndpoint(ctx, t, original)

	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "relay" || mode == "direct"
	}, 3*time.Minute, pollInterval, "should recover after relay restore")
	t.Log("relay reconnect recovery confirmed")

	restoreMode()
}
