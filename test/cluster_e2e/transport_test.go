//go:build cluster_e2e

package cluster_e2e

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// TestAllDirectAfterStartup verifies that under normal conditions (relay.mode=auto,
// no path blocks) all peers on the NAS node (cone NAT) reach direct transport.
// This is a smoke test / baseline check before running fault injection tests.
func TestAllDirectAfterStartup(t *testing.T) {
	ctx := context.Background()

	// NAS is a cone NAT node — it should be able to go direct with all other cone peers.
	// worker7 is symmetric, so NAS↔worker7 may be direct (via ICE probe) or relay depending
	// on timing. We only assert cone peers.
	nasPeerName := "nas"

	// Give the mesh 2 minutes to converge before asserting.
	t.Log("waiting for NAS connections to stabilize...")
	eventually(t, func() bool {
		logConnections(ctx, t, nasPeerName)

		var conePeers []string
		for _, name := range allPeerNames(ctx, t) {
			if name == nasPeerName || name == "master" {
				continue
			}
			// worker7 is symmetric — skip deterministic assertion for now
			if name == "worker7" {
				continue
			}
			mode := connectionMode(ctx, t, nasPeerName, name)
			if mode != "direct" {
				t.Logf("nas→%s = %q (not direct yet)", name, mode)
				return false
			}
		}
		_ = conePeers
		return true
	}, 3*time.Minute, pollInterval, "all cone peers on NAS should be direct")

	t.Log("baseline: all cone peers on NAS are direct")
}

// TestRelayModeAlways patches WireKubeMesh.spec.relay.mode to "always" and verifies
// that connections switch to relay, then restores "auto" and verifies direct recovery.
func TestRelayModeAlways(t *testing.T) {
	ctx := context.Background()
	nasPeerName := "nas"

	// Baseline: confirm at least one peer is currently direct.
	eventually(t, func() bool {
		for _, name := range allPeerNames(ctx, t) {
			if name == nasPeerName {
				continue
			}
			if connectionMode(ctx, t, nasPeerName, name) == "direct" {
				return true
			}
		}
		return false
	}, 2*time.Minute, pollInterval, "at least one direct peer on NAS before mode change")

	// Inject: force relay mode for all connections.
	restoreMode := patchMeshRelayMode(ctx, t, "always")
	defer restoreMode()

	// Expect: all NAS connections switch to relay within 3 minutes.
	// The agent reads the mesh config each sync cycle (default ~30s) and forces
	// new endpoints to go through relay. Existing WG sessions expire after ~180s.
	t.Log("waiting for NAS connections to switch to relay...")
	eventually(t, func() bool {
		logConnections(ctx, t, nasPeerName)
		return allConnectionsHaveMode(ctx, t, nasPeerName, "relay")
	}, relayTimeout, pollInterval, "all NAS connections should be relay after mode=always")
	t.Log("confirmed: all NAS connections are relay")

	// Restore: switch back to auto.
	restoreMode()
	// Clear the deferred call so it doesn't run twice.
	restoreMode = func() {}

	// Expect: NAS re-establishes direct paths for cone peers.
	t.Log("waiting for NAS to recover direct connections after mode=auto...")
	eventually(t, func() bool {
		logConnections(ctx, t, nasPeerName)
		// Check that at least the majority of cone peers are direct.
		directCount := 0
		totalCone := 0
		for _, name := range allPeerNames(ctx, t) {
			if name == nasPeerName || name == "worker7" {
				continue
			}
			totalCone++
			if connectionMode(ctx, t, nasPeerName, name) == "direct" {
				directCount++
			}
		}
		t.Logf("direct cone peers: %d/%d", directCount, totalCone)
		return totalCone > 0 && directCount == totalCone
	}, directTimeout, pollInterval, "all cone peers should be direct after mode=auto restored")
	t.Log("confirmed: NAS recovered direct connections")
}

// TestDirectPathBlock_ConeToSymmetric blocks WireGuard UDP on the NAS node (cone NAT)
// and verifies that the NAS↔worker7 (symmetric NAT) connection falls back to relay,
// then removes the block and verifies direct recovery via ICE probe.
//
// This is the critical regression test for the relay↔direct transition logic.
func TestDirectPathBlock_ConeToSymmetric(t *testing.T) {
	ctx := context.Background()
	nasPeerName := "nas"
	symPeerName := "worker7"

	// Step 1: Verify NAS↔worker7 is currently direct (ICE probe should have succeeded).
	t.Log("verifying NAS↔worker7 is direct before injecting fault...")
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, nasPeerName, symPeerName)
		t.Logf("nas→worker7 = %q", mode)
		return mode == "direct"
	}, 3*time.Minute, pollInterval, "NAS↔worker7 should be direct initially")
	t.Log("baseline: NAS↔worker7 is direct")

	// Step 2: Block WireGuard UDP ingress on NAS. This simulates a firewall rule
	// or network partition that prevents direct handshakes.
	unblock := blockWireGuardUDP(ctx, t, "nas")
	defer unblock()

	// Step 3: Verify NAS falls back to relay for worker7.
	// The agent detects the handshake timeout after 30s and switches to relay.
	t.Log("waiting for NAS↔worker7 to fall back to relay...")
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, nasPeerName, symPeerName)
		t.Logf("nas→worker7 = %q", mode)
		return mode == "relay"
	}, relayTimeout, pollInterval, "NAS↔worker7 should fall back to relay after UDP block")
	t.Log("confirmed: NAS↔worker7 is relay")

	// Step 4: Remove the iptables block. The ICE engine retries direct every
	// directRetryIntervalSeconds (default 120s). After the path is clear,
	// the next probe should succeed and upgrade to direct.
	unblock()
	unblock = func() {} // prevent double-call from defer

	t.Log("path unblocked, waiting for NAS↔worker7 to upgrade to direct...")
	eventually(t, func() bool {
		mode := connectionMode(ctx, t, nasPeerName, symPeerName)
		t.Logf("nas→worker7 = %q", mode)
		return mode == "direct"
	}, directTimeout, pollInterval, "NAS↔worker7 should upgrade to direct after unblock")
	t.Log("confirmed: NAS↔worker7 upgraded back to direct — relay↔direct transition works")
}

// TestDirectPathBlock_ConeToAll blocks WireGuard UDP on NAS and verifies that
// ALL peer connections fall back to relay, then verifies full recovery.
// This tests the multi-peer relay fallback path and recovery.
func TestDirectPathBlock_ConeToAll(t *testing.T) {
	ctx := context.Background()
	nasPeerName := "nas"

	// Baseline: all cone peers should be direct.
	t.Log("waiting for NAS to reach all-direct baseline...")
	eventually(t, func() bool {
		allDirect := true
		for _, name := range allPeerNames(ctx, t) {
			if name == nasPeerName || name == "worker7" {
				continue
			}
			mode := connectionMode(ctx, t, nasPeerName, name)
			if mode != "direct" {
				allDirect = false
			}
		}
		logConnections(ctx, t, nasPeerName)
		return allDirect
	}, 3*time.Minute, pollInterval, "all cone peers on NAS should be direct before fault injection")

	// Block UDP ingress on NAS.
	unblock := blockWireGuardUDP(ctx, t, "nas")
	defer unblock()

	// Verify all connections fall back to relay.
	t.Log("waiting for all NAS connections to fall back to relay...")
	eventually(t, func() bool {
		allRelay := true
		for _, name := range allPeerNames(ctx, t) {
			if name == nasPeerName {
				continue
			}
			mode := connectionMode(ctx, t, nasPeerName, name)
			if mode != "relay" {
				t.Logf("nas→%s = %q (not relay yet)", name, mode)
				allRelay = false
			}
		}
		return allRelay
	}, relayTimeout, pollInterval, "all NAS connections should be relay after UDP block")
	t.Log("confirmed: all NAS connections are relay")

	// Remove the block.
	unblock()
	unblock = func() {}

	// Wait for full direct recovery.
	t.Log("waiting for full direct recovery on NAS...")
	eventually(t, func() bool {
		logConnections(ctx, t, nasPeerName)
		for _, name := range allPeerNames(ctx, t) {
			if name == nasPeerName || name == "worker7" {
				continue
			}
			if connectionMode(ctx, t, nasPeerName, name) != "direct" {
				return false
			}
		}
		return true
	}, directTimeout, pollInterval, "all cone NAS connections should recover to direct")
	t.Log("confirmed: NAS fully recovered to direct — multi-peer relay fallback and recovery works")
}

// TestRelayServerDisconnect simulates relay unavailability by patching the relay
// endpoint to a non-existent address, verifying relay peers reconnect when restored.
// Direct-path peers should be unaffected throughout.
func TestRelayServerDisconnect(t *testing.T) {
	ctx := context.Background()
	nasPeerName := "nas"
	symPeerName := "worker7"

	// First, ensure NAS↔worker7 (symmetric) is relay so we have a relay peer to test.
	// Force relay mode temporarily.
	restoreMode := patchMeshRelayMode(ctx, t, "always")
	defer restoreMode()

	t.Log("waiting for NAS↔worker7 to go relay (forced mode=always)...")
	eventually(t, func() bool {
		return connectionMode(ctx, t, nasPeerName, symPeerName) == "relay"
	}, relayTimeout, pollInterval, "NAS↔worker7 should be relay under mode=always")

	// Restore auto mode — keep worker7 on relay via natural conditions.
	// (It's symmetric NAT so it may stay relay or go direct via ICE probe.)
	restoreMode()
	restoreMode = func() {}

	// Now break the relay by patching to a bad endpoint.
	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Fatalf("get WireKubeMesh: %v", err)
	}
	originalEndpoint := ""
	if mesh.Spec.Relay != nil && mesh.Spec.Relay.External != nil {
		originalEndpoint = mesh.Spec.Relay.External.Endpoint
	}
	if originalEndpoint == "" {
		t.Skip("no external relay endpoint configured — skipping relay disconnect test")
	}

	t.Logf("breaking relay endpoint (was %s)...", originalEndpoint)
	patchRelayEndpoint := func(ep string) {
		var m wirekubev1alpha1.WireKubeMesh
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, &m); err != nil {
			t.Fatalf("get WireKubeMesh: %v", err)
		}
		p := client.MergeFrom(m.DeepCopy())
		m.Spec.Relay.External.Endpoint = ep
		if err := k8sClient.Patch(ctx, &m, p); err != nil {
			t.Fatalf("patch relay endpoint to %s: %v", ep, err)
		}
		t.Logf("patched relay endpoint to %s", ep)
	}

	patchRelayEndpoint("127.0.0.1:19999") // unreachable
	defer patchRelayEndpoint(originalEndpoint)

	// Agents should detect relay disconnect and mark relay peers as disconnected/failed.
	// Direct peers should be unaffected.
	t.Log("relay is down — verifying direct peers remain connected...")
	time.Sleep(45 * time.Second) // let agents detect and react

	// Cone peers on NAS should still be direct.
	for _, name := range allPeerNames(ctx, t) {
		if name == nasPeerName || name == "worker7" {
			continue
		}
		mode := connectionMode(ctx, t, nasPeerName, name)
		if mode != "direct" {
			t.Errorf("nas→%s = %q; expected direct peers to be unaffected by relay outage", name, mode)
		}
	}
	t.Log("confirmed: direct peers unaffected by relay outage")

	// Restore relay endpoint.
	patchRelayEndpoint(originalEndpoint)

	// Relay-dependent peers should reconnect via relay within reconnect window.
	// Agent uses exponential backoff 1s–30s for relay reconnect.
	t.Log("relay restored — waiting for relay peers to reconnect...")
	eventually(t, func() bool {
		// At minimum, the relay pool should be re-established (IsConnected).
		// We observe via NAS connections recovering; if worker7 was relay it should
		// come back as relay (or direct if ICE probe happens to succeed).
		mode := connectionMode(ctx, t, nasPeerName, symPeerName)
		t.Logf("nas→worker7 = %q", mode)
		return mode == "relay" || mode == "direct"
	}, 3*time.Minute, pollInterval, "NAS↔worker7 should reconnect after relay restore")
	t.Log("confirmed: relay peers recovered after relay server restored")
}

