package agent

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

const meshCIDR = "198.18.0.0/16"

// bypassSpec opts the mesh into the local-subnet bypass. It is not the default:
// the feature trades same-segment encryption for the physical link, so it has
// to be asked for.
func bypassSpec(excludes ...string) *wirekubev1alpha1.RoutingSpec {
	return &wirekubev1alpha1.RoutingSpec{LocalSubnetPolicy: "bypass", ExcludeCIDRs: excludes}
}

// policyAgent builds an agent whose attached prefixes and neighbour table are
// fixed. neighbors maps address -> MAC and every entry is reachable; tests that
// need an unresolved or unreachable entry set a.neighbors themselves.
func policyAgent(local []string, neighbors map[string]string, gatewayCIDRs ...string) *Agent {
	a := &Agent{log: logr.Discard()}
	a.localPrefixes = func() ([]netip.Prefix, error) {
		out := make([]netip.Prefix, 0, len(local))
		for _, c := range local {
			out = append(out, netip.MustParsePrefix(c))
		}
		return out, nil
	}
	a.neighbors = func() ([]wireguard.NeighborEntry, error) {
		out := make([]wireguard.NeighborEntry, 0, len(neighbors))
		for addr, mac := range neighbors {
			out = append(out, wireguard.NeighborEntry{
				Address:   netip.MustParseAddr(addr),
				MAC:       mac,
				Reachable: true,
			})
		}
		return out, nil
	}
	if len(gatewayCIDRs) > 0 {
		a.gwClientCache = map[string]map[string]bool{}
		for _, c := range gatewayCIDRs {
			a.gwClientCache[c] = map[string]bool{}
		}
	}
	return a
}

// links builds what a peer published about its own addresses.
func links(pairs ...string) map[string]map[netip.Addr]string {
	out := map[string]map[netip.Addr]string{}
	for i := 0; i+2 < len(pairs); i += 3 {
		peer, addr, mac := pairs[i], pairs[i+1], pairs[i+2]
		if out[peer] == nil {
			out[peer] = map[netip.Addr]string{}
		}
		out[peer][netip.MustParseAddr(addr)] = mac
	}
	return out
}

// The two sides agree: this node resolved the address on one of its own links,
// and the MAC that answered is the one the keyholder published for itself.
func TestSuppressesWhenBothSidesAgree(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if len(kept) != 0 {
		t.Fatalf("kept %v, want the route suppressed", kept)
	}
	if suppressed["10.0.0.203/32"] != "local 10.0.0.0/24" {
		t.Errorf("reason = %q", suppressed["10.0.0.203/32"])
	}
}

// The reuse case the check exists for: a peer in another VPC advertises an
// address inside this node's range. Something on this segment answers for that
// address, but it is not the peer, so the MACs differ and the route stays.
func TestKeepsRouteWhenMACsDisagree(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "de:ad:be:ef:00:99"))
	if !reflect.DeepEqual(kept, routes) {
		t.Errorf("kept %v, want the tunnel route held", kept)
	}
}

// Nothing on this segment answers for the address, so there is no evidence to
// act on, whatever the peer claims.
func TestKeepsRouteWhenAddressDoesNotAnswerHere(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if !reflect.DeepEqual(kept, routes) {
		t.Errorf("kept %v, want the tunnel route held", kept)
	}
}

// A neighbour entry the kernel has not confirmed carries a MAC that may be
// stale or invented by whatever put it there, so it is not evidence.
func TestKeepsRouteWhenNeighbourIsUnreachable(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, nil)
	a.neighbors = func() ([]wireguard.NeighborEntry, error) {
		return []wireguard.NeighborEntry{{
			Address:   netip.MustParseAddr("10.0.0.203"),
			MAC:       "aa:bb:cc:dd:ee:01",
			Reachable: false,
		}}, nil
	}
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if !reflect.DeepEqual(kept, routes) {
		t.Errorf("kept %v, want the tunnel route held", kept)
	}
}

// A peer that has not published its links yet, which is every peer for the
// first moments after it joins, keeps its tunnel route.
func TestKeepsRouteWhenPeerPublishedNothing(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(), nil)
	if !reflect.DeepEqual(kept, routes) {
		t.Errorf("kept %v, want the tunnel route held", kept)
	}
}

// The option is off by default, and with it off containment means nothing.
func TestDefaultPolicySuppressesNothing(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}
	peers := links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01")

	for _, spec := range []*wirekubev1alpha1.RoutingSpec{
		nil,
		{},
		{LocalSubnetPolicy: "tunnel"},
	} {
		kept, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, spec, peers)
		if !reflect.DeepEqual(kept, routes) || len(suppressed) != 0 {
			t.Errorf("spec %+v: kept %v suppressed %v", spec, kept, suppressed)
		}
	}
}

// Ranks above local suppression: the mesh overlay, static excludes, and
// gateway-injected routes.
func TestRankingAboveLocalSuppression(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24", "198.18.0.0/16"},
		map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01", "198.18.0.7": "aa:bb:cc:dd:ee:01"},
		"10.0.0.208/32")
	routes := []string{"198.18.0.7/32", "10.0.0.203/32", "10.0.0.208/32", "10.0.0.0/25"}
	owners := map[string]string{
		"198.18.0.7/32": "peerB",
		"10.0.0.203/32": "peerB",
		"10.0.0.208/32": "peerC",
		"10.0.0.0/25":   "peerC",
	}
	peers := links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01",
		"peerB", "198.18.0.7", "aa:bb:cc:dd:ee:01")

	kept, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec("10.9.9.0/24"), peers)
	want := []string{"198.18.0.7/32", "10.0.0.208/32", "10.0.0.0/25"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept %v, want %v (overlay, gateway, and non-host routes held)", kept, want)
	}
	if suppressed["10.0.0.203/32"] == "" {
		t.Error("the verified host route was not suppressed")
	}
}

// An excludeCIDRs entry outranks everything droppable.
func TestExcludeWinsOverLocalSuppression(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	_, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec("10.0.0.0/24"),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if suppressed["10.0.0.203/32"] != "excluded" {
		t.Errorf("reason = %q, want excluded", suppressed["10.0.0.203/32"])
	}
}

// The decision is per observing node. Two nodes on one segment suppress each
// other's host routes; a third in another VPC keeps tunnel routes to both,
// because the address does not answer on its own links.
func TestDecisionIsPerObserver(t *testing.T) {
	routes := []string{"10.213.103.70/32"}
	owners := map[string]string{"10.213.103.70/32": "peerB"}
	peers := links("peerB", "10.213.103.70", "aa:bb:cc:dd:ee:01")

	sameSegment := policyAgent([]string{"10.213.103.64/26"},
		map[string]string{"10.213.103.70": "aa:bb:cc:dd:ee:01"})
	if kept, _ := sameSegment.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(), peers); len(kept) != 0 {
		t.Errorf("same-segment observer kept %v", kept)
	}

	otherVPC := policyAgent([]string{"10.99.0.0/24"}, map[string]string{})
	if kept, _ := otherVPC.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(), peers); !reflect.DeepEqual(kept, routes) {
		t.Errorf("other-VPC observer suppressed %v", routes)
	}
}

// A netlink failure is not a topology change. The last set the kernel returned
// is held, so a transient error does not put every suppressed route back for a
// cycle.
func TestHoldsDecisionsWhenPrefixReadFails(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}
	peers := links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01")

	if kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(), peers); len(kept) != 0 {
		t.Fatalf("kept %v on the first pass", kept)
	}
	a.localPrefixes = func() ([]netip.Prefix, error) { return nil, errors.New("netlink: connection refused") }
	if kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(), peers); len(kept) != 0 {
		t.Errorf("suppressed routes came back on a read failure: %v", kept)
	}
}

// With nothing cached yet there is no state to hold, so install the routes and
// try again next sync rather than suppress on a guess.
func TestInstallsRoutesWhenFirstPrefixReadFails(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	a.localPrefixes = func() ([]netip.Prefix, error) { return nil, errors.New("netlink: connection refused") }
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if !reflect.DeepEqual(kept, routes) || len(suppressed) != 0 {
		t.Errorf("kept %v suppressed %v", kept, suppressed)
	}
}

// excludeCIDRs does not depend on the kernel answering. A prefix read that
// fails before anything is cached disables local-segment suppression for that
// cycle, but a destination the operator declared off-limits must still never
// reach the table.
func TestExcludesSurviveFirstPrefixReadFailure(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	a.localPrefixes = func() ([]netip.Prefix, error) { return nil, errors.New("netlink: connection refused") }
	routes := []string{"10.0.0.203/32", "192.168.50.0/24"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec("192.168.50.0/24"),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if suppressed["192.168.50.0/24"] != "excluded" {
		t.Errorf("excluded route reason = %q, want excluded", suppressed["192.168.50.0/24"])
	}
	if !reflect.DeepEqual(kept, []string{"10.0.0.203/32"}) {
		t.Errorf("kept %v, want only the unsuppressed host route", kept)
	}
}

// A neighbour-table read failure leaves the observer with no evidence, so it
// installs the routes rather than acting on a stale in-memory view.
func TestInstallsRoutesWhenNeighbourReadFails(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, nil)
	a.neighbors = func() ([]wireguard.NeighborEntry, error) { return nil, errors.New("netlink: no buffer space") }
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	kept, suppressed := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if !reflect.DeepEqual(kept, routes) || len(suppressed) != 0 {
		t.Errorf("kept %v suppressed %v", kept, suppressed)
	}
}

// A route whose owner is unknown has no peer to compare against.
func TestKeepsRouteWithoutAnOwner(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}

	kept, _ := a.applyRoutingPolicy(routes, map[string]string{}, meshCIDR, bypassSpec(),
		links("peerB", "10.0.0.203", "aa:bb:cc:dd:ee:01"))
	if !reflect.DeepEqual(kept, routes) {
		t.Errorf("kept %v, want the tunnel route held", kept)
	}
}

// MAC comparison must not care about case: the neighbour table and a peer's
// published value can differ in form.
func TestMACComparisonIsCaseInsensitive(t *testing.T) {
	a := policyAgent([]string{"10.0.0.0/24"}, map[string]string{"10.0.0.203": "aa:bb:cc:dd:ee:01"})
	routes := []string{"10.0.0.203/32"}
	owners := map[string]string{"10.0.0.203/32": "peerB"}

	peers := map[string]map[netip.Addr]string{
		"peerB": {netip.MustParseAddr("10.0.0.203"): "AA:BB:CC:DD:EE:01"},
	}
	if kept, _ := a.applyRoutingPolicy(routes, owners, meshCIDR, bypassSpec(), peers); len(kept) != 0 {
		t.Errorf("kept %v; the published MAC differed only in case", kept)
	}
}

// routeOwners records a route's owner by public key, so the published link
// addresses have to be indexed the same way. Keying them by peer name compiled,
// passed every policy test that supplied both halves itself, and suppressed
// nothing at all in the cluster.
func TestPeerLinkAddressesIsKeyedByPublicKey(t *testing.T) {
	const pubKey = "cGVlci1saW5rLWFkZHJlc3MtdGVzdC1rZXk9PQ=="
	peers := map[string]*wirekubev1alpha1.WireKubePeer{
		"abeta-gds-05.ncp3": {
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: pubKey},
			Status: wirekubev1alpha1.WireKubePeerStatus{
				LinkAddresses: []wirekubev1alpha1.LinkAddress{
					{Address: "10.213.103.77", MAC: "22:26:04:AC:25:98", Interface: "bond0"},
					{Address: "192.168.11.145", MAC: "9e:d4:fa:cc:19:9c", Interface: "bond1.13"},
					{Address: "not-an-address", MAC: "9e:d4:fa:cc:19:9c"},
					{Address: "10.0.0.9", MAC: ""},
				},
			},
		},
		"no-key": {Status: wirekubev1alpha1.WireKubePeerStatus{
			LinkAddresses: []wirekubev1alpha1.LinkAddress{{Address: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"}},
		}},
		"no-links": {Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "another-key"}},
	}

	got := peerLinkAddresses(peers)
	if len(got) != 1 {
		t.Fatalf("indexed %d peers, want only the one with both a key and links: %v", len(got), got)
	}
	byAddr, ok := got[pubKey]
	if !ok {
		t.Fatalf("not keyed by public key: %v", got)
	}
	if len(byAddr) != 2 {
		t.Errorf("addresses = %v, want the two parseable entries with a MAC", byAddr)
	}
	if mac := byAddr[netip.MustParseAddr("10.213.103.77")]; mac != "22:26:04:ac:25:98" {
		t.Errorf("MAC = %q, want it normalised to lowercase", mac)
	}
}
