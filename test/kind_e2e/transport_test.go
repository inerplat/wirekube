//go:build kind_e2e

package kind_e2e

import (
	"context"
	"fmt"
	"testing"
	"time"
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

// TestWireGuardTunnel verifies that all peers (including control-plane)
// establish direct WireGuard tunnels. Because each node is on a separate
// 172.x subnet, the WG tunnel is the only encrypted overlay path.
func TestWireGuardTunnel(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]

	t.Logf("waiting for %s to establish direct tunnels…", subject)
	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		for _, name := range peers {
			if name == subject {
				continue
			}
			if connectionMode(ctx, t, subject, name) != "direct" {
				return false
			}
		}
		return true
	}, 5*time.Minute, pollInterval, "all peers should be direct")

	t.Logf("%s has direct tunnels to all peers", subject)
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
		return connectionMode(ctx, t, subject, remote) == "direct"
	}, 3*time.Minute, pollInterval, subject+" → "+remote+" should be direct")

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

// TestAllNodesReachable verifies that every node pair (including control-plane)
// has at least one active connection.
func TestAllNodesReachable(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)

	for _, subject := range peers {
		for _, remote := range peers {
			if subject == remote {
				continue
			}
			subj, rem := subject, remote
			eventually(t, func() bool {
				mode := connectionMode(ctx, t, subj, rem)
				t.Logf("%s → %s = %q", subj, rem, mode)
				return mode == "direct" || mode == "relay"
			}, 3*time.Minute, pollInterval,
				subj+" → "+rem+" should have connection")
		}
	}
	t.Log("all node pairs reachable")
}

// TestRelayFallback blocks WireGuard UDP on one node, verifies relay fallback,
// then unblocks and verifies recovery to direct.
func TestRelayFallback(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]
	remote := peers[1]

	eventually(t, func() bool {
		return connectionMode(ctx, t, subject, remote) == "direct"
	}, 3*time.Minute, pollInterval, subject+" → "+remote+" should be direct")
	t.Logf("baseline: %s → %s is direct", subject, remote)

	unblock := blockWireGuardUDP(t, subject)
	defer unblock()

	t.Logf("WG UDP blocked on %s — waiting for relay…", subject)
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "relay"
	}, relayTimeout, pollInterval, subject+" → "+remote+" should relay")

	unblock()
	unblock = func() {}

	t.Logf("unblocked — waiting for direct recovery…")
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "direct"
	}, directTimeout, pollInterval, subject+" → "+remote+" should recover")
	t.Log("relay → direct recovery confirmed")
}

// TestRelayModeAlways forces relay.mode=always, verifies, then restores.
func TestRelayModeAlways(t *testing.T) {
	ctx := context.Background()

	peers := waitForPeers(ctx, t, 3)
	subject := peers[0]

	eventually(t, func() bool {
		for _, name := range peers {
			if name == subject {
				continue
			}
			if connectionMode(ctx, t, subject, name) == "direct" {
				return true
			}
		}
		return false
	}, 2*time.Minute, pollInterval, "at least one direct before mode change")

	restore := patchMeshRelayMode(ctx, t, "always")
	defer restore()

	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		return allConnectionsHaveMode(ctx, t, subject, "relay")
	}, relayTimeout, pollInterval, "all connections on "+subject+" should be relay")

	restore()
	restore = func() {}

	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		for _, name := range peers {
			if name == subject {
				continue
			}
			if connectionMode(ctx, t, subject, name) != "direct" {
				return false
			}
		}
		return true
	}, directTimeout, pollInterval, "all connections should recover to direct")
	t.Log("relay.mode=always → auto recovery confirmed")
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
	restoreMode = func() {}
}
