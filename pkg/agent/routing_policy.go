package agent

import (
	"net/netip"
	"strings"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// peerLinkAddresses indexes what every peer publishes about its own links, as
// public key -> address -> MAC. The key is the public key because that is how
// routeOwners identifies the peer a route belongs to.
//
// A peer's link addresses are written by its own agent and by no one else, so
// the map holds each peer's own claim about where it lives. That claim is the
// peer's half of the adjacency check in adjacentOnSegment.
func peerLinkAddresses(peers map[string]*wirekubev1alpha1.WireKubePeer) map[string]map[netip.Addr]string {
	out := make(map[string]map[netip.Addr]string, len(peers))
	for _, p := range peers {
		if p == nil || p.Spec.PublicKey == "" || len(p.Status.LinkAddresses) == 0 {
			continue
		}
		byAddr := make(map[netip.Addr]string, len(p.Status.LinkAddresses))
		for _, la := range p.Status.LinkAddresses {
			addr, err := netip.ParseAddr(la.Address)
			if err != nil || la.MAC == "" {
				continue
			}
			byAddr[addr] = strings.ToLower(la.MAC)
		}
		if len(byAddr) > 0 {
			out[p.Spec.PublicKey] = byAddr
		}
	}
	return out
}

// applyRoutingPolicy drops candidate routes the mesh routing spec says this
// node must not install: static excludes first, then destinations this node
// provably reaches without the tunnel. Every decision is made per observing
// node against its own kernel state, so a mixed-topology mesh (two nodes on
// one segment, a third in another VPC) splits correctly with no configuration.
//
// Precedence, from the local-subnet bypass design:
//  1. overlay routes (contained in meshCIDR) are always installed; they exist
//     only inside the tunnel, so dropping one severs the address instead of
//     falling back to the main table,
//  2. routing.excludeCIDRs,
//  3. gateway-injected routes are operator intent and always installed,
//  4. localSubnetPolicy.
//
// Local suppression needs evidence beyond address containment. Private ranges
// repeat across VPCs, so "the destination is inside one of my attached
// prefixes" says nothing about whether that machine is on this node's segment.
// adjacentOnSegment supplies the evidence.
func (a *Agent) applyRoutingPolicy(routes []string, routeOwners map[string]string, meshCIDR string, routing *wirekubev1alpha1.RoutingSpec, peerLinks map[string]map[netip.Addr]string) ([]string, map[string]string) {
	if len(routes) == 0 {
		return routes, nil
	}

	var excludes []netip.Prefix
	policy := localSubnetPolicyTunnel
	if routing != nil {
		if routing.LocalSubnetPolicy != "" {
			policy = routing.LocalSubnetPolicy
		}
		for _, cidr := range routing.ExcludeCIDRs {
			p, err := netip.ParsePrefix(cidr)
			if err != nil {
				a.log.Info("ignoring unparseable routing.excludeCIDRs entry", "cidr", cidr)
				continue
			}
			// Excludes outrank gateway routes by design, so a very broad
			// entry can drop deliberate cross-VPC paths wholesale. Install it
			// anyway (operator intent), but say so.
			if p.Bits() < 8 {
				a.log.Info("routing.excludeCIDRs entry is very broad; it overrides any gateway route it contains", "cidr", cidr)
			}
			excludes = append(excludes, p.Masked())
		}
	}

	var local []netip.Prefix
	if policy == localSubnetPolicyBypass && a.localPrefixes != nil {
		prefixes, err := a.localPrefixes()
		switch {
		case err == nil:
			local = prefixes
			a.lastLocalPrefixes = prefixes
		case len(a.lastLocalPrefixes) > 0:
			// An unanswered netlink query is a missing observation, not a
			// re-cabling. Holding the last set keeps the suppression decisions
			// stable across a transient failure; treating the failure as "no
			// attached prefixes" would reinstate every suppressed route for a
			// cycle and flap the traffic back into the tunnel. The held set is
			// at most one sync old.
			a.log.Error(err, "reading attached prefixes; holding the last known set",
				"prefixes", len(a.lastLocalPrefixes))
			local = a.lastLocalPrefixes
		default:
			// Nothing observed yet, so there is nothing to hold. Only
			// local-segment suppression is skipped: the static exclusions
			// parsed above are the operator's explicit intent and do not
			// depend on the kernel answering, so they are still applied.
			a.log.Error(err, "reading attached prefixes; no local-segment decisions this cycle")
		}
	}
	if len(excludes) == 0 && len(local) == 0 {
		return routes, nil
	}

	// Without a parseable mesh CIDR there is no mesh-managed overlay to
	// protect (peers run manually managed AllowedIPs), so only the overlay
	// rank is disabled. Static exclusions are the operator's explicit intent
	// and stay enforced, and local suppression stays proof-gated.
	meshPrefix, meshErr := netip.ParsePrefix(meshCIDR)
	meshOK := meshErr == nil
	if meshOK {
		meshPrefix = meshPrefix.Masked()
	}

	var adjacency map[netip.Addr]string
	adjacencyLoaded := false
	kept := routes[:0:0]
	suppressed := map[string]string{}
	for _, cidr := range routes {
		dst, err := netip.ParsePrefix(cidr)
		if err != nil {
			kept = append(kept, cidr)
			continue
		}
		dst = dst.Masked()

		// Overlay routes rank above everything droppable. Containment in the
		// mesh CIDR, not a /32 check: an operator-assigned /30 inside the
		// overlay has no main-table fallback either.
		if meshOK && prefixContains(meshPrefix, dst) {
			kept = append(kept, cidr)
			continue
		}
		if containedInAny(dst, excludes) {
			suppressed[cidr] = "excluded"
			continue
		}
		if _, isGateway := a.gwClientCache[cidr]; isGateway {
			kept = append(kept, cidr)
			continue
		}
		// Host routes only: the adjacency check speaks for a single address,
		// so applying it to a wider route would suppress a whole range on
		// evidence gathered about one machine inside it.
		if !dst.IsSingleIP() {
			kept = append(kept, cidr)
			continue
		}
		containing := containingPrefixes(dst, local)
		if len(containing) == 0 {
			kept = append(kept, cidr)
			continue
		}
		if !adjacencyLoaded {
			adjacency = a.resolvedNeighbors()
			adjacencyLoaded = true
		}
		prefix, ok := a.adjacentOnSegment(dst, routeOwners[cidr], containing, adjacency, peerLinks)
		if !ok {
			kept = append(kept, cidr)
			continue
		}
		suppressed[cidr] = "local " + prefix.String()
	}

	return kept, suppressed
}

// adjacentOnSegment reports whether the peer owning this route sits on the same
// layer-2 segment as this node, and which attached prefix carries it.
//
// It compares two independent observations, neither of which one node can
// produce alone:
//
//   - what answers here. This node resolved the destination in its own
//     neighbour table, so some machine on one of its links answered ARP for
//     that address and the kernel recorded the MAC.
//   - who should be answering. The peer publishes the MAC of the link it owns
//     that address on, in a status only its own agent writes.
//
// Equal MACs mean the machine answering on this wire is the peer itself. When
// another VPC reuses the same private range, the address still resolves here —
// to whatever local machine holds it — and the MACs differ, so the tunnel route
// stays.
//
// Both observations describe wiring rather than traffic, so the result holds
// regardless of WireGuard transport state, of whether the two nodes exchange
// packets, or of whether the peer's agent is running right now. A peer joining
// later is judged on the first sync after it has published its link addresses
// and this node has resolved the address on the wire.
func (a *Agent) adjacentOnSegment(dst netip.Prefix, owner string, containing []netip.Prefix,
	adjacency map[netip.Addr]string, peerLinks map[string]map[netip.Addr]string) (netip.Prefix, bool) {
	if owner == "" || !dst.IsSingleIP() {
		return netip.Prefix{}, false
	}
	localMAC, resolved := adjacency[dst.Addr()]
	if !resolved || localMAC == "" {
		return netip.Prefix{}, false
	}
	claimed, ok := peerLinks[owner][dst.Addr()]
	if !ok || claimed == "" {
		return netip.Prefix{}, false
	}
	// Case-insensitive on top of the normalisation at parse time, because only
	// the peer's claim passes through peerLinkAddresses; the neighbour-table
	// side is formatted by the kernel.
	if !strings.EqualFold(claimed, localMAC) {
		a.log.V(1).Info("address answers on this segment with a MAC the peer does not claim; keeping the tunnel route",
			"address", dst.Addr(), "answered", localMAC, "claimed", claimed, "peer", owner)
		return netip.Prefix{}, false
	}
	for _, p := range containing {
		if p.Contains(dst.Addr()) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// resolvedNeighbors reads this node's neighbour table into address -> MAC, the
// observer's half of the adjacency check.
//
// Entries the kernel has not confirmed are dropped. A neighbour still being
// probed, or one it has given up on, carries no usable answer about who holds
// the address on this wire.
func (a *Agent) resolvedNeighbors() map[netip.Addr]string {
	if a.neighbors == nil {
		return nil
	}
	entries, err := a.neighbors()
	if err != nil {
		a.log.Error(err, "reading the neighbour table; no local-segment decisions this cycle")
		return nil
	}
	out := make(map[netip.Addr]string, len(entries))
	for _, e := range entries {
		if !e.Reachable || e.MAC == "" {
			continue
		}
		out[e.Address] = e.MAC
	}
	return out
}

const (
	localSubnetPolicyBypass = "bypass"
	localSubnetPolicyTunnel = "tunnel"
)

// reportSuppressedRoutes logs suppression changes once per transition and
// keeps the gauge current, so a node that suddenly starts (or stops)
// tunnelling its management segment is visible.
func (a *Agent) reportSuppressedRoutes(current map[string]string) {
	for cidr, reason := range current {
		if a.lastSuppressedRoutes[cidr] != reason {
			a.log.Info("route suppressed", "cidr", cidr, "reason", reason)
		}
	}
	for cidr := range a.lastSuppressedRoutes {
		if _, still := current[cidr]; !still {
			a.log.Info("route reinstated", "cidr", cidr)
		}
	}
	a.lastSuppressedRoutes = current
	setSuppressedRouteMetrics(a.nodeName, current)
}

func containedInAny(dst netip.Prefix, prefixes []netip.Prefix) bool {
	return len(containingPrefixes(dst, prefixes)) > 0
}

func containingPrefixes(dst netip.Prefix, prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range prefixes {
		if prefixContains(p, dst) {
			out = append(out, p)
		}
	}
	return out
}

// prefixContains reports whether outer fully contains inner, in route units:
// routes are never split, so partial overlap does not count.
func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}
