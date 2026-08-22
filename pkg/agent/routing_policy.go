package agent

import (
	"net"
	"net/netip"
	"time"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

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
// Local suppression needs cryptographic proof, not just address containment:
// private ranges repeat across VPCs, so "the destination is inside one of my
// attached prefixes" says nothing about whether that machine is actually on
// my segment. The proof is a live authenticated WireGuard handshake whose
// direct endpoint sits inside the same attached prefix; a stranger holding
// the same address in this node's VPC cannot authenticate. When the proof
// goes stale, the next sync reinstates the route.
func (a *Agent) applyRoutingPolicy(routes []string, routeOwners map[string]string, meshCIDR string, routing *wirekubev1alpha1.RoutingSpec) ([]string, map[string]string) {
	if len(routes) == 0 {
		return routes, nil
	}

	var excludes []netip.Prefix
	policy := "bypass"
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
	if policy == "bypass" && a.localPrefixes != nil {
		local = a.localPrefixes()
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

	var statsByKey map[string]peerDirectProof
	proofsLoaded := false
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
		containing := containingPrefixes(dst, local)
		if len(containing) == 0 {
			kept = append(kept, cidr)
			continue
		}
		if !proofsLoaded {
			statsByKey = a.directProofByKey()
			proofsLoaded = true
		}
		if prefix, ok := a.provenOnSegment(dst, routeOwners[cidr], containing, statsByKey); ok {
			suppressed[cidr] = "local " + prefix.String()
			continue
		}
		kept = append(kept, cidr)
	}

	return kept, suppressed
}

// peerDirectProof is the slice of WireGuard stats the suppression decision
// needs: where the peer's session actually terminates and how fresh it is.
type peerDirectProof struct {
	endpoint      netip.Addr
	lastHandshake time.Time
	lastDirectRX  time.Time
	endpointSetAt time.Time
}

func (a *Agent) directProofByKey() map[string]peerDirectProof {
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		return nil
	}
	proofs := make(map[string]peerDirectProof, len(stats))
	for _, s := range stats {
		if s.ActualEndpoint == "" || isLocalhostEndpoint(s.ActualEndpoint) {
			continue
		}
		host, _, err := net.SplitHostPort(s.ActualEndpoint)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		proof := peerDirectProof{endpoint: addr, lastHandshake: s.LastHandshake, endpointSetAt: a.endpointConfiguredAt[s.PublicKeyB64]}
		if rx := a.wgMgr.LastDirectReceive(s.PublicKeyB64); rx > 0 {
			proof.lastDirectRX = time.Unix(0, rx)
		}
		proofs[s.PublicKeyB64] = proof
	}
	return proofs
}

// provenOnSegment reports whether the peer owning this route has a live
// authenticated handshake terminating inside one of the locally attached
// prefixes that contain the destination, and returns which one.
func (a *Agent) provenOnSegment(dst netip.Prefix, ownerKey string, containing []netip.Prefix, proofs map[string]peerDirectProof) (netip.Prefix, bool) {
	if ownerKey == "" {
		return netip.Prefix{}, false
	}
	proof, ok := proofs[ownerKey]
	if !ok || proof.lastHandshake.IsZero() {
		return netip.Prefix{}, false
	}
	// The proof must be about this destination, not merely about this
	// segment: a NAT box on the observer's segment can terminate the peer's
	// session at a local address while the advertised host route names a
	// different machine in a reused private range. For host routes the
	// endpoint therefore has to be the advertised address itself.
	if dst.IsSingleIP() && proof.endpoint != dst.Addr() {
		return netip.Prefix{}, false
	}
	// Freshness uses the direct-connected window rather than the raw
	// handshake window: the latter equals WireGuard's rekey interval, so a
	// quiet peer sitting at that boundary would flip the route in and out of
	// the table every tick.
	window := a.handshakeValidWindow
	if a.directConnectedWindow > window {
		window = a.directConnectedWindow
	}
	if time.Since(proof.lastHandshake) > window {
		return netip.Prefix{}, false
	}
	// The handshake alone can predate the endpoint: an active direct probe
	// force-sets the WireGuard endpoint to the advertised address before any
	// packet has authenticated over it, while the handshake timestamp still
	// belongs to the relay leg. And the bind's direct-receive watermark
	// updates before wireguard-go authenticates, so junk UDP from a stranger
	// at a reused address can refresh it. The signal that survives both: the
	// handshake must postdate this agent's last endpoint assignment for the
	// peer. WireGuard keeps the endpoint only where authenticated packets
	// come from — a handshake completed via relay roams it to localhost and
	// is filtered above — so endpoint==dst plus a post-assignment handshake
	// means the peer authenticated from that address.
	if proof.endpointSetAt.IsZero() || !proof.lastHandshake.After(proof.endpointSetAt) {
		return netip.Prefix{}, false
	}
	// Direct-socket receive freshness stays as defense in depth.
	if proof.lastDirectRX.IsZero() || time.Since(proof.lastDirectRX) > window {
		return netip.Prefix{}, false
	}
	for _, p := range containing {
		if p.Contains(proof.endpoint) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

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
