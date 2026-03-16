//go:build kind_e2e

package kind_e2e

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// TestNATTypeDetected verifies that the in-process STUN servers are reachable
// from kind nodes and that each agent reports a non-empty NATType in its
// WireKubePeer status. In a kind cluster (no real NAT), agents query two STUN
// servers and receive the same mapped IP:port from both → NATType = "cone".
//
// This is a baseline check: if STUN is unreachable the rest of the suite would
// be meaningless.
func TestNATTypeDetected(t *testing.T) {
	ctx := context.Background()

	workers := waitForWorkerPeers(ctx, t, 2)
	t.Logf("worker peers: %v", workers)

	for _, name := range workers {
		natType := waitForNATDetection(ctx, t, name)
		if natType == "" {
			t.Errorf("peer %s: NATType still empty after wait", name)
		}
		// In kind (same Docker bridge, no real NAT), both STUN servers return
		// the same IP:port → cone NAT is expected.
		t.Logf("peer %s NAT type: %s", name, natType)
	}
}

// TestDirectP2P verifies that two worker peers can establish direct WireGuard
// connections when they share the same Docker network (kind default). Direct
// connections are expected because there is no NAT or UDP firewall between
// kind nodes.
func TestDirectP2P(t *testing.T) {
	ctx := context.Background()

	workers := waitForWorkerPeers(ctx, t, 2)
	subject := workers[0]

	t.Logf("asserting direct connections from %s…", subject)
	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		for _, name := range workers[1:] {
			if connectionMode(ctx, t, subject, name) != "direct" {
				return false
			}
		}
		return true
	}, 3*time.Minute, pollInterval, "all worker peers should reach direct transport")

	t.Logf("confirmed: %s has direct connections to all other worker peers", subject)
}

// TestRelayFallback injects an iptables DROP rule for WireGuard UDP on one
// worker node, verifies that its connections fall back to relay within
// relayTimeout, then removes the block and verifies that the direct path is
// re-established within directTimeout.
//
// This is the core regression test for the relay ↔ direct transition logic.
// The test selects worker peers dynamically — no node names are hardcoded.
func TestRelayFallback(t *testing.T) {
	ctx := context.Background()

	workers := waitForWorkerPeers(ctx, t, 2)
	subject := workers[0] // node whose UDP we will block
	remote := workers[1]  // peer we expect to transition

	// Step 1: baseline — direct connection must exist first.
	t.Logf("waiting for %s → %s to be direct (baseline)…", subject, remote)
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "direct"
	}, 3*time.Minute, pollInterval, subject+"→"+remote+" should start as direct")
	t.Logf("baseline confirmed: %s → %s is direct", subject, remote)

	// Step 2: block WireGuard UDP ingress on the subject node.
	unblock := blockWireGuardUDP(ctx, t, subject)
	defer unblock()

	// Step 3: expect relay fallback within relayTimeout (30 s handshake timeout
	// + agent sync cycle convergence).
	t.Logf("WireGuard UDP blocked on %s — waiting for relay fallback…", subject)
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "relay"
	}, relayTimeout, pollInterval, subject+"→"+remote+" should fall back to relay")
	t.Logf("confirmed: %s → %s is relay", subject, remote)

	// Step 4: remove the block and wait for direct recovery.
	// The ICE engine retries direct every directRetryIntervalSeconds (60 s in the
	// WireKubeMesh CR applied by TestMain). Once the path is clear the WireGuard
	// handshake succeeds and the connection upgrades back to direct.
	unblock()
	unblock = func() {} // prevent double-call from defer

	t.Logf("path unblocked — waiting for %s → %s to recover direct…", subject, remote)
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "direct"
	}, directTimeout, pollInterval, subject+"→"+remote+" should recover to direct")
	t.Logf("confirmed: relay → direct upgrade succeeded for %s → %s", subject, remote)
}

// TestRelayModeAlways patches WireKubeMesh.spec.relay.mode to "always" and
// verifies that all connections on the subject worker switch to relay, then
// restores "auto" and verifies that direct connections are re-established.
func TestRelayModeAlways(t *testing.T) {
	ctx := context.Background()

	workers := waitForWorkerPeers(ctx, t, 2)
	subject := workers[0]

	// Baseline: at least one direct connection must exist before forcing relay.
	eventually(t, func() bool {
		for _, name := range workers[1:] {
			if connectionMode(ctx, t, subject, name) == "direct" {
				return true
			}
		}
		return false
	}, 2*time.Minute, pollInterval, "at least one direct peer before mode change")

	// Force relay.mode = always.
	restore := patchMeshRelayMode(ctx, t, "always")
	defer restore()

	t.Logf("relay.mode=always — waiting for %s to switch all connections to relay…", subject)
	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		return allConnectionsHaveMode(ctx, t, subject, "relay")
	}, relayTimeout, pollInterval, "all connections on "+subject+" should be relay")
	t.Logf("confirmed: all connections on %s are relay", subject)

	// Restore relay.mode = auto.
	restore()
	restore = func() {}

	t.Logf("relay.mode=auto restored — waiting for %s to recover direct connections…", subject)
	eventually(t, func() bool {
		logConnections(ctx, t, subject)
		for _, name := range workers[1:] {
			if connectionMode(ctx, t, subject, name) != "direct" {
				return false
			}
		}
		return true
	}, directTimeout, pollInterval, "all worker peers should be direct after mode=auto")
	t.Logf("confirmed: %s recovered all direct connections after relay.mode=auto", subject)
}

// TestAllWorkersReachable is a connectivity smoke test: every worker peer must
// have at least one active connection (direct or relay) to every other worker.
func TestAllWorkersReachable(t *testing.T) {
	ctx := context.Background()

	workers := waitForWorkerPeers(ctx, t, 2)

	for _, subject := range workers {
		for _, remote := range workers {
			if subject == remote {
				continue
			}
			subj, rem := subject, remote // capture for closure
			eventually(t, func() bool {
				mode := connectionMode(ctx, t, subj, rem)
				t.Logf("%s → %s = %q", subj, rem, mode)
				return mode == "direct" || mode == "relay"
			}, 3*time.Minute, pollInterval,
				subj+" should have any connection to "+rem)
		}
	}
	t.Log("confirmed: all worker peers are reachable from each other")
}

// TestRelayReconnect simulates a relay outage by patching the relay endpoint
// to an unreachable address, waits for agents to detect the outage, then
// restores the endpoint and verifies that relay connections recover.
func TestRelayReconnect(t *testing.T) {
	ctx := context.Background()

	workers := waitForWorkerPeers(ctx, t, 2)
	subject := workers[0]
	remote := workers[1]

	// Force relay.mode=always to ensure we have a known relay connection.
	restoreMode := patchMeshRelayMode(ctx, t, "always")
	defer restoreMode()

	eventually(t, func() bool {
		return connectionMode(ctx, t, subject, remote) == "relay"
	}, relayTimeout, pollInterval, subject+"→"+remote+" should be relay under mode=always")
	t.Logf("relay connection confirmed: %s → %s", subject, remote)

	// Break the relay endpoint.
	originalEndpoint := relayEndpointFromMesh(ctx, t)
	if originalEndpoint == "" {
		t.Skip("no external relay endpoint in WireKubeMesh — skipping relay reconnect test")
	}

	setRelayEndpoint(ctx, t, "127.0.0.1:19999")
	defer setRelayEndpoint(ctx, t, originalEndpoint)

	// Agents detect the TCP disconnect within one keepalive interval (~30 s).
	t.Log("relay endpoint broken — waiting 60 s for agents to detect disconnect…")
	time.Sleep(60 * time.Second)

	// Restore the relay endpoint.
	setRelayEndpoint(ctx, t, originalEndpoint)

	// Relay reconnects with exponential backoff (1 s–30 s cap).
	t.Log("relay endpoint restored — waiting for connections to recover…")
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, subject, remote)
		t.Logf("%s → %s = %q", subject, remote, mode)
		return mode == "relay" || mode == "direct"
	}, 3*time.Minute, pollInterval, subject+"→"+remote+" should recover after relay restore")
	t.Log("confirmed: connections recovered after relay server restart")

	restoreMode()
	restoreMode = func() {}
}

// relayEndpointFromMesh returns the current relay external endpoint or "".
func relayEndpointFromMesh(ctx context.Context, t *testing.T) string {
	t.Helper()
	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Fatalf("get WireKubeMesh: %v", err)
	}
	if mesh.Spec.Relay != nil && mesh.Spec.Relay.External != nil {
		return mesh.Spec.Relay.External.Endpoint
	}
	return ""
}

// setRelayEndpoint patches WireKubeMesh.spec.relay.external.endpoint.
func setRelayEndpoint(ctx context.Context, t *testing.T, endpoint string) {
	t.Helper()
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(timeoutCtx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Logf("warning: get WireKubeMesh for relay endpoint patch: %v", err)
		return
	}
	p := client.MergeFrom(mesh.DeepCopy())
	if mesh.Spec.Relay == nil {
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
	}
	if mesh.Spec.Relay.External == nil {
		mesh.Spec.Relay.External = &wirekubev1alpha1.ExternalRelaySpec{}
	}
	mesh.Spec.Relay.External.Endpoint = endpoint
	if err := k8sClient.Patch(timeoutCtx, &mesh, p); err != nil {
		t.Logf("warning: patch relay endpoint to %s: %v", endpoint, err)
	} else {
		t.Logf("patched relay endpoint to %s", endpoint)
	}
}
