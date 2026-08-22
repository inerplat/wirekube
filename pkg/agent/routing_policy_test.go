package agent

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

// policyAgent builds an agent whose local prefixes, peer stats, and gateway
// cache are all synthetic, so every suppression decision is deterministic.
func policyAgent(local []string, stats []wireguard.PeerStats, gatewayCIDRs ...string) *Agent {
	fake := &fakeWGEngine{stats: stats}
	a := &Agent{wgMgr: fake, log: logr.Discard(), handshakeValidWindow: 3 * time.Minute}
	a.localPrefixes = func() []netip.Prefix {
		var out []netip.Prefix
		for _, c := range local {
			out = append(out, netip.MustParsePrefix(c))
		}
		return out
	}
	if len(gatewayCIDRs) > 0 {
		a.gwClientCache = map[string]map[string]bool{}
		for _, c := range gatewayCIDRs {
			a.gwClientCache[c] = map[string]bool{}
		}
	}
	return a
}

func provenPeer(key, endpoint string) wireguard.PeerStats {
	return wireguard.PeerStats{PublicKeyB64: key, ActualEndpoint: endpoint, LastHandshake: time.Now().Add(-10 * time.Second)}
}

const meshCIDR = "198.18.0.0/16"

// The core split: a peer proven on the local segment loses its node-IP route,
// while the mesh overlay route (even a non-/32 inside the overlay) and a
// gateway CIDR inside the same prefix stay tunnelled.
func TestRoutingPolicySuppressesProvenLocalPeer(t *testing.T) {
	a := policyAgent(
		[]string{"10.213.103.64/26"},
		[]wireguard.PeerStats{provenPeer("peerB", "10.213.103.70:51822")},
		"10.213.103.96/27",
	)
	routes := []string{"198.18.18.5/32", "198.18.20.0/30", "10.213.103.70/32", "10.213.103.96/27"}
	owners := map[string]string{"10.213.103.70/32": "peerB"}

	got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil)
	want := []string{"198.18.18.5/32", "198.18.20.0/30", "10.213.103.96/27"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

// Overlapping VPC ranges: every observer's local prefix contains every peer's
// advertised internal IP, but the proven direct endpoints are public
// addresses outside the prefix. Nothing may be suppressed.
func TestRoutingPolicyKeepsRoutesWhenProofIsOffSegment(t *testing.T) {
	a := policyAgent(
		[]string{"10.0.0.0/24"},
		[]wireguard.PeerStats{provenPeer("peerB", "193.123.230.88:51822")},
	)
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	if got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil); !reflect.DeepEqual(got, routes) {
		t.Errorf("suppressed a cross-VPC route: got %v", got)
	}
}

// Containment without any proof at all (no handshake, relay endpoint, or
// unknown owner) keeps the route.
func TestRoutingPolicyRequiresProof(t *testing.T) {
	stale := wireguard.PeerStats{PublicKeyB64: "peerB", ActualEndpoint: "10.0.0.203:51822", LastHandshake: time.Now().Add(-10 * time.Minute)}
	relayed := wireguard.PeerStats{PublicKeyB64: "peerC", ActualEndpoint: "127.0.0.1:40000", LastHandshake: time.Now()}
	a := policyAgent([]string{"10.0.0.0/24"}, []wireguard.PeerStats{stale, relayed})
	routes := []string{"10.0.0.203/32", "10.0.0.204/32", "10.0.0.205/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB", "10.0.0.204/32": "peerC"}

	if got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil); !reflect.DeepEqual(got, routes) {
		t.Errorf("suppressed without proof: got %v", got)
	}
}

// Proof expiry reinstates the route on the next evaluation.
func TestRoutingPolicyReinstatesOnStaleProof(t *testing.T) {
	fresh := provenPeer("peerB", "10.0.0.203:51822")
	a := policyAgent([]string{"10.0.0.0/24"}, []wireguard.PeerStats{fresh})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	if got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil); len(got) != 0 {
		t.Fatalf("fresh proof did not suppress: %v", got)
	}
	stale := fresh
	stale.LastHandshake = time.Now().Add(-10 * time.Minute)
	a.wgMgr.(*fakeWGEngine).stats = []wireguard.PeerStats{stale}
	if got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil); !reflect.DeepEqual(got, routes) {
		t.Errorf("stale proof did not reinstate: got %v", got)
	}
}

func TestRoutingPolicyExcludeCIDRs(t *testing.T) {
	routing := &wirekubev1alpha1.RoutingSpec{ExcludeCIDRs: []string{"172.31.0.0/16", "bogus"}}

	t.Run("exclude beats gateway injection and reachability", func(t *testing.T) {
		a := policyAgent(nil, nil, "172.31.4.0/24")
		routes := []string{"172.31.4.0/24", "172.31.9.9/32", "192.0.2.1/32"}
		got := a.applyRoutingPolicy(routes, map[string]string{}, meshCIDR, routing)
		want := []string{"192.0.2.1/32"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v want %v", got, want)
		}
	})

	t.Run("exclude never suppresses overlay routes", func(t *testing.T) {
		a := policyAgent(nil, nil)
		wide := &wirekubev1alpha1.RoutingSpec{ExcludeCIDRs: []string{"198.18.0.0/15"}}
		routes := []string{"198.18.18.5/32"}
		if got := a.applyRoutingPolicy(routes, map[string]string{}, meshCIDR, wide); !reflect.DeepEqual(got, routes) {
			t.Errorf("overlay route suppressed by exclude: got %v", got)
		}
	})

	t.Run("exclude smaller than a gateway route does not split it", func(t *testing.T) {
		a := policyAgent(nil, nil, "172.16.0.0/12")
		narrow := &wirekubev1alpha1.RoutingSpec{ExcludeCIDRs: []string{"172.31.0.0/16"}}
		routes := []string{"172.16.0.0/12"}
		if got := a.applyRoutingPolicy(routes, map[string]string{}, meshCIDR, narrow); !reflect.DeepEqual(got, routes) {
			t.Errorf("gateway route dropped by a contained exclude: got %v", got)
		}
	})
}

// tunnel restores today's behavior byte for byte, exclusions aside.
func TestRoutingPolicyTunnelKeepsEverything(t *testing.T) {
	a := policyAgent(
		[]string{"10.213.103.64/26"},
		[]wireguard.PeerStats{provenPeer("peerB", "10.213.103.70:51822")},
	)
	routing := &wirekubev1alpha1.RoutingSpec{LocalSubnetPolicy: "tunnel"}
	routes := []string{"198.18.18.5/32", "10.213.103.70/32"}
	owners := map[string]string{"10.213.103.70/32": "peerB"}

	if got := a.applyRoutingPolicy(routes, owners, meshCIDR, routing); !reflect.DeepEqual(got, routes) {
		t.Errorf("tunnel policy altered routes: got %v", got)
	}
}

// A peer on a different segment keeps its node-IP route even when the
// observer has local prefixes and other peers are being suppressed.
func TestRoutingPolicyKeepsOffSegmentPeers(t *testing.T) {
	a := policyAgent(
		[]string{"10.213.103.64/26"},
		[]wireguard.PeerStats{provenPeer("peerB", "10.213.103.70:51822")},
	)
	routes := []string{"10.213.103.70/32", "192.0.2.7/32"}
	owners := map[string]string{"10.213.103.70/32": "peerB", "192.0.2.7/32": "peerFar"}

	got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil)
	want := []string{"192.0.2.7/32"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

// An unparseable (or absent) mesh CIDR disarms overlay detection, so the
// policy must suppress nothing at all.
func TestRoutingPolicyFailsOpenWithoutMeshCIDR(t *testing.T) {
	a := policyAgent(
		[]string{"10.0.0.0/24"},
		[]wireguard.PeerStats{provenPeer("peerB", "10.0.0.203:51822")},
	)
	routing := &wirekubev1alpha1.RoutingSpec{ExcludeCIDRs: []string{"172.31.0.0/16"}}
	routes := []string{"10.0.0.203/32", "172.31.9.9/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	if got := a.applyRoutingPolicy(routes, owners, "", routing); !reflect.DeepEqual(got, routes) {
		t.Errorf("suppressed without a mesh CIDR: got %v", got)
	}
}

// Per-observer decisions: the same mesh state yields a bypass on the node
// that shares the segment and full tunnel routes on the node that does not.
func TestRoutingPolicyIsPerObserver(t *testing.T) {
	routes := []string{"10.213.103.70/32"}
	owners := map[string]string{"10.213.103.70/32": "peerB"}
	stats := []wireguard.PeerStats{provenPeer("peerB", "10.213.103.70:51822")}

	sameSegment := policyAgent([]string{"10.213.103.64/26"}, stats)
	if got := sameSegment.applyRoutingPolicy(routes, owners, meshCIDR, nil); len(got) != 0 {
		t.Errorf("same-segment observer kept %v", got)
	}
	otherVPC := policyAgent([]string{"10.99.0.0/24"}, stats)
	if got := otherVPC.applyRoutingPolicy(routes, owners, meshCIDR, nil); !reflect.DeepEqual(got, routes) {
		t.Errorf("off-segment observer suppressed: got %v", got)
	}
}

// A NAT box on the observer's segment can terminate the peer's session at a
// local address that differs from the advertised host route. The proof must
// be about the destination itself.
func TestRoutingPolicyBindsProofToDestination(t *testing.T) {
	a := policyAgent(
		[]string{"10.0.0.0/24"},
		[]wireguard.PeerStats{provenPeer("peerB", "10.0.0.50:51822")},
	)
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	if got := a.applyRoutingPolicy(routes, owners, meshCIDR, nil); !reflect.DeepEqual(got, routes) {
		t.Errorf("suppressed a route whose proof endpoint differs from the destination: got %v", got)
	}
}

// No routing spec and no local prefixes: output identical to input.
func TestRoutingPolicyNoopWithoutSignals(t *testing.T) {
	a := policyAgent(nil, nil)
	routes := []string{"192.0.2.1/32", "198.18.18.5/32"}
	if got := a.applyRoutingPolicy(routes, map[string]string{}, meshCIDR, nil); !reflect.DeepEqual(got, routes) {
		t.Errorf("noop altered routes: got %v", got)
	}
}
