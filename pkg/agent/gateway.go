package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// gatewayState tracks gateway configuration applied to this node.
type gatewayState struct {
	// gatewayNames lists WireKubeGateway CRs for which this node is the active gateway.
	gatewayNames []string
	// snatRules tracks iptables MASQUERADE rules we installed, keyed by CIDR.
	snatRules map[string]bool
	// ipForwardEnabled tracks whether we enabled IP forwarding.
	ipForwardEnabled bool
}

// setupGateway checks if this node should act as a gateway and configures
// IP forwarding, SNAT/masquerade, and route injection.
// The agent performs gateway activation directly (no operator required):
// the first peer in PeerRefs that exists and has a public key is elected active.
func (a *Agent) setupGateway(ctx context.Context) error {
	gwList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, gwList); err != nil {
		a.log.Error(err, "gateway list error")
		return nil
	}
	if len(gwList.Items) == 0 {
		// Shutdown no longer removes SNAT rules, so a node that stops being a
		// gateway while its agent is down would keep masquerading forever if
		// this path just returned. Reconcile to the empty set when there is
		// in-process state to clear or when this process has not yet checked
		// the kernel for rules a previous run left behind.
		if a.gwState != nil || !a.gwRetainedRulesChecked {
			a.cleanupGateway()
			a.gwRetainedRulesChecked = true
		}
		// Routes this peer advertised for gateways that no longer exist.
		a.injectGatewayRoutes(ctx, nil, a.nodeName)
		return nil
	}

	myPeerName := a.nodeName
	desiredSNATCIDRs := map[string]bool{}
	allGatewayRouteCIDRs := map[string]bool{}
	activeGateways := []string{}

	for i := range gwList.Items {
		gw := &gwList.Items[i]
		for _, route := range gw.Spec.Routes {
			allGatewayRouteCIDRs[route.CIDR] = true
		}

		activePeer, err := a.electActivePeer(ctx, gw)
		if err != nil {
			// A partial view could elect a second node while the first still
			// serves; change nothing this sync.
			a.log.Error(err, "gateway election skipped this sync", "gateway", gw.Name)
			return nil
		}
		a.log.V(1).Info("gateway election result", "gateway", gw.Name, "elected", activePeer, "me", myPeerName)
		if activePeer == "" {
			continue
		}

		if activePeer != myPeerName {
			continue
		}

		activeGateways = append(activeGateways, gw.Name)

		// Inject gateway routes into our own WireKubePeer AllowedIPs
		a.injectGatewayRoutes(ctx, gw, myPeerName)

		if gw.Spec.SNAT != nil && gw.Spec.SNAT.Enabled {
			for _, route := range gw.Spec.Routes {
				desiredSNATCIDRs[route.CIDR] = true
			}
		}

		// Update gateway status
		a.updateGatewayStatus(ctx, gw, activePeer)
	}

	// A route named by a gateway CR that this node does not currently serve
	// (not elected, or SNAT disabled) may still carry the untagged rule shape
	// an older crashed agent left behind. The CR naming the CIDR is what
	// makes the removal attributable and safe; tagged rules for these CIDRs
	// are handled by the kernel-seeded reconcile in syncSNATRules.
	for cidr := range allGatewayRouteCIDRs {
		if !desiredSNATCIDRs[cidr] {
			removeLegacyMasqueradeRule(cidr)
		}
	}

	if len(activeGateways) == 0 {
		// The loop above only runs on elected peers; a peer that lost the
		// election must still withdraw what it advertised.
		a.injectGatewayRoutes(ctx, nil, myPeerName)
		a.cleanupGateway()
		return nil
	}

	if err := enableIPForwarding(); err != nil {
		a.log.Error(err, "enabling IP forwarding")
	}

	a.syncSNATRules(desiredSNATCIDRs)

	if a.gwState == nil {
		a.gwState = &gatewayState{}
	}
	a.gwState.gatewayNames = activeGateways
	a.gwState.ipForwardEnabled = true

	return nil
}

// electActivePeer returns the first peer in PeerRefs whose WireKubePeer
// exists and has a public key. A lookup error other than NotFound is
// returned, since skipping that peer could elect a second active node.
func (a *Agent) electActivePeer(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway) (string, error) {
	for _, peerName := range gw.Spec.PeerRefs {
		peer := &wirekubev1alpha1.WireKubePeer{}
		if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return "", fmt.Errorf("reading WireKubePeer %s: %w", peerName, err)
		}
		if peer.Spec.PublicKey != "" {
			return peerName, nil
		}
	}
	return "", nil
}

// injectGatewayRoutes reconciles gateway route CIDRs in peerName's AllowedIPs
// against every gateway that currently elects peerName; gw is unused and may
// be nil.
// It adds missing CIDRs and removes stale ones that were previously injected by gateways.
// Gateway-injected CIDRs are tracked in the "wirekube.io/gateway-cidrs" annotation.
func (a *Agent) injectGatewayRoutes(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, peerName string) {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return
	}

	// Without a reliable election, leave the advertised routes as they are.
	desiredGW, err := a.collectGatewayCIDRsForPeer(ctx, peerName)
	if err != nil {
		a.log.Error(err, "gateway route reconcile skipped this sync", "peer", peerName)
		return
	}

	// Parse previously-injected CIDRs from annotation.
	const annKey = "wirekube.io/gateway-cidrs"
	prevInjected := map[string]bool{}
	if ann := peer.Annotations[annKey]; ann != "" {
		for _, c := range strings.Split(ann, ",") {
			if c != "" {
				prevInjected[c] = true
			}
		}
	}

	// Build new AllowedIPs: user CIDRs (not gateway-injected) + desired gateway CIDRs.
	userCIDRs := []string{}
	for _, ip := range peer.Spec.AllowedIPs {
		if !prevInjected[ip] && !desiredGW[ip] {
			userCIDRs = append(userCIDRs, ip)
		}
	}

	newAllowed := make([]string, 0, len(userCIDRs)+len(desiredGW))
	newAllowed = append(newAllowed, userCIDRs...)
	newAllowed = append(newAllowed, sortedKeys(desiredGW)...)

	// Check if anything changed.
	if equalStringSlice(peer.Spec.AllowedIPs, newAllowed) {
		return
	}

	for cidr := range desiredGW {
		if !prevInjected[cidr] {
			a.log.Info("injecting gateway route", "cidr", cidr, "peer", peerName)
		}
	}
	for cidr := range prevInjected {
		if !desiredGW[cidr] {
			a.log.Info("removing stale gateway route", "cidr", cidr, "peer", peerName)
		}
	}

	peer.Spec.AllowedIPs = newAllowed
	if peer.Annotations == nil {
		peer.Annotations = map[string]string{}
	}
	peer.Annotations[annKey] = strings.Join(sortedKeys(desiredGW), ",")

	if err := a.client.Update(ctx, peer); err != nil {
		a.log.Error(err, "updating peer allowedIPs", "peer", peerName)
	}
}

// collectGatewayCIDRsForPeer returns all desired CIDRs from gateways where
// the given peer is the elected active gateway.
func (a *Agent) collectGatewayCIDRsForPeer(ctx context.Context, peerName string) (map[string]bool, error) {
	gwList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, gwList); err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for i := range gwList.Items {
		gw := &gwList.Items[i]
		active, err := a.electActivePeer(ctx, gw)
		if err != nil {
			return nil, err
		}
		if active == peerName {
			for _, route := range gw.Spec.Routes {
				result[route.CIDR] = true
			}
		}
	}
	return result, nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// updateGatewayStatus sets the active peer and ready status on the gateway CR.
// A gateway with IPsec tunnels is ready only when one of them is established,
// which setupIPsec reports; here such a gateway only gets its active peer,
// and is marked not ready when this agent cannot terminate IPsec at all.
func (a *Agent) updateGatewayStatus(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, activePeer string) {
	ready := gw.Status.Ready
	switch {
	case len(gw.Spec.IPsec) == 0:
		ready = true
	case a.ipsec == nil:
		ready = false
	}
	tunnels := gw.Status.IPsec
	if a.ipsec == nil && len(gw.Spec.IPsec) > 0 {
		// Nothing else would overwrite the last report of a node that
		// terminated the tunnels before IPsec was turned off.
		tunnels = make([]wirekubev1alpha1.GatewayIPsecTunnelStatus, 0, len(gw.Spec.IPsec))
		for _, t := range gw.Spec.IPsec {
			st := wirekubev1alpha1.GatewayIPsecTunnelStatus{Name: t.Name, Phase: wirekubev1alpha1.IPsecTunnelPhaseError,
				Message: fmt.Sprintf("the agent on %s runs without IPsec; enable it with the chart value agent.ipsec.enabled=true or wirekubectl upgrade --ipsec", activePeer)}
			for _, old := range gw.Status.IPsec {
				if old.Name == t.Name && old.Phase == st.Phase && old.Message == st.Message {
					st.LastTransitionTime = old.LastTransitionTime
				}
			}
			if st.LastTransitionTime == nil {
				now := metav1.NewTime(time.Now())
				st.LastTransitionTime = &now
			}
			tunnels = append(tunnels, st)
		}
	}
	if gw.Status.ActivePeer == activePeer && gw.Status.Ready == ready &&
		gw.Status.RoutesInjected == int32(len(gw.Spec.Routes)) && tunnelStatusesEqual(gw.Status.IPsec, tunnels) {
		return
	}
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.ActivePeer = activePeer
	gw.Status.Ready = ready
	gw.Status.RoutesInjected = int32(len(gw.Spec.Routes))
	gw.Status.IPsec = tunnels
	if err := a.client.Status().Patch(ctx, gw, patch); err != nil {
		a.log.Error(err, "updating gateway status")
	}
}

// cleanupGateway removes gateway-specific configuration (SNAT rules).
// IP forwarding is left enabled to avoid disrupting other services.
func (a *Agent) cleanupGateway() {
	rules := listMasqueradeRules()
	if rules == nil {
		rules = map[string]bool{}
	}
	if a.gwState != nil {
		for cidr := range a.gwState.snatRules {
			rules[cidr] = true
		}
	}
	for cidr := range rules {
		removeMasqueradeRule(cidr, a.wgMgr.InterfaceName())
	}
	a.gwState = nil
}

// syncSNATRules ensures the desired masquerade rules are installed
// and stale rules are removed.
func (a *Agent) syncSNATRules(desired map[string]bool) {
	if a.gwState == nil {
		// Seed tracking from the kernel: rules installed by a previous run
		// survive the restart now, and starting from an empty map would leave
		// any of them that are no longer desired in place forever.
		a.gwState = &gatewayState{snatRules: listMasqueradeRules()}
		if a.gwState.snatRules == nil {
			a.gwState.snatRules = map[string]bool{}
		}
	}

	ifaceName := a.wgMgr.InterfaceName()

	// Add missing rules
	for cidr := range desired {
		if !a.gwState.snatRules[cidr] {
			if err := addMasqueradeRule(cidr, ifaceName); err != nil {
				a.log.Error(err, "adding MASQUERADE rule", "cidr", cidr)
				continue
			}
			a.gwState.snatRules[cidr] = true
			a.log.Info("MASQUERADE added", "cidr", cidr)
		}
	}

	// Remove stale rules
	for cidr := range a.gwState.snatRules {
		if !desired[cidr] {
			removeMasqueradeRule(cidr, ifaceName)
			delete(a.gwState.snatRules, cidr)
			a.log.Info("MASQUERADE removed", "cidr", cidr)
		}
	}
}

// enableIPForwarding enables IPv4 forwarding via sysctl.
func enableIPForwarding() error {
	path := "/proc/sys/net/ipv4/ip_forward"

	// Try host path first (mounted at /host/proc/sys/net in DaemonSet)
	hostPath := "/host/proc/sys/net/ipv4/ip_forward"
	if _, err := os.Stat(hostPath); err == nil {
		path = hostPath
	}

	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading ip_forward: %w", err)
	}
	if strings.TrimSpace(string(current)) == "1" {
		return nil
	}

	if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
		return fmt.Errorf("writing ip_forward: %w", err)
	}
	fmt.Println("[gateway] IP forwarding enabled")
	return nil
}

// addMasqueradeRule adds an iptables MASQUERADE rule for traffic
// destined for the given CIDR. This ensures return traffic from the
// target network routes back through the gateway node.
// snatRuleComment tags the MASQUERADE rules this agent installs. The tag is
// what makes the rules discoverable after a restart: gwState is process
// memory, and shutdown no longer removes kernel state, so reconciliation must
// read ownership off the kernel itself.
const snatRuleComment = "wirekube-gw"

func addMasqueradeRule(cidr, _ string) error {
	args := []string{
		"-t", "nat", "-C", "POSTROUTING",
		"-d", cidr,
		"-m", "comment", "--comment", snatRuleComment,
		"-j", "MASQUERADE",
	}
	if err := exec.Command("iptables", args...).Run(); err == nil {
		removeLegacyMasqueradeRule(cidr)
		return nil
	}

	args[2] = "-A"
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %s: %w", strings.TrimSpace(string(out)), err)
	}
	// An older agent that crashed (no graceful cleanup) can have left the
	// untagged shape of this rule behind. It would double-SNAT harmlessly but
	// survive every tagged removal, so migrate it out whenever the tagged
	// rule is ensured.
	removeLegacyMasqueradeRule(cidr)
	return nil
}

// removeLegacyMasqueradeRule deletes the pre-tag rule shape for a CIDR.
// Bounded on purpose: legacy rules are only recognized for CIDRs named by
// current gateway CRs, because a bare "-d CIDR -j MASQUERADE" with an unknown
// destination cannot be attributed to WireKube safely.
func removeLegacyMasqueradeRule(cidr string) {
	_ = exec.Command("iptables",
		"-t", "nat", "-D", "POSTROUTING",
		"-d", cidr,
		"-j", "MASQUERADE").Run()
}

// listMasqueradeRules returns the destination CIDRs of every MASQUERADE rule
// carrying the wirekube comment tag, read from the kernel. Untagged rules are
// never claimed: a bare "-d CIDR -j MASQUERADE" could belong to anyone, and
// agents that predate the tag removed their rules in their own shutdown path.
func listMasqueradeRules() map[string]bool {
	out, err := exec.Command("iptables-save", "-t", "nat").Output()
	if err != nil {
		return nil
	}
	rules := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A POSTROUTING") ||
			!strings.Contains(line, "--comment "+quoteIfNeeded(snatRuleComment)) ||
			!strings.Contains(line, "-j MASQUERADE") {
			continue
		}
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "-d" {
				rules[fields[i+1]] = true
				break
			}
		}
	}
	return rules
}

// quoteIfNeeded matches iptables-save's own quoting: comments with spaces are
// emitted quoted, single-token comments bare.
func quoteIfNeeded(comment string) string {
	if strings.ContainsAny(comment, " \t") {
		return "\"" + comment + "\""
	}
	return comment
}

// removeMasqueradeRule removes the iptables MASQUERADE rule.
func removeMasqueradeRule(cidr, _ string) {
	// Tagged shape first, then the untagged shape older agents installed, so
	// a known-stale CIDR is cleared regardless of which generation added it.
	_ = exec.Command("iptables",
		"-t", "nat", "-D", "POSTROUTING",
		"-d", cidr,
		"-m", "comment", "--comment", snatRuleComment,
		"-j", "MASQUERADE").Run()
	_ = exec.Command("iptables",
		"-t", "nat", "-D", "POSTROUTING",
		"-d", cidr,
		"-j", "MASQUERADE").Run()
}

// shouldSkipGatewayRoute decides if a given CIDR (from a remote peer's AllowedIPs)
// should be excluded from this node's WireGuard config and kernel route table.
//
// A CIDR is skipped when:
//  1. This node's own IP is already within the CIDR (same-VPC optimization).
//  2. It's a gateway-injected route AND this node is not a designated client.
//  3. It's a gateway-injected route AND the CIDR contains a non-gateway peer's IP.
//     Such subnets are reachable via direct WireGuard tunnels; routing them through
//     the gateway would hairpin traffic and break local network services (e.g. cloud
//     LB health checks) because the WireKube routing table (priority 200) overrides
//     the main table's directly-connected routes (priority 32766).
func (a *Agent) shouldSkipGatewayRoute(ctx context.Context, cidr, myPeerName string, ownIP net.IP) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	if ownIP != nil && ipNet.Contains(ownIP) {
		return true
	}

	if a.gwClientCache == nil {
		a.buildGatewayClientCache(ctx)
	}

	if a.gwClientCache != nil {
		if clients, isGWRoute := a.gwClientCache[cidr]; isGWRoute {
			if len(clients) > 0 && !clients[myPeerName] {
				return true
			}
			for _, peerIP := range a.nonGwPeerIPs {
				if ipNet.Contains(peerIP) {
					return true
				}
			}
		}
	}

	return false
}

// collectNonGatewayPeerIPs builds a list of node IPs for all peers that are NOT
// active gateway peers. Gateway route CIDRs containing these IPs are skipped on
// non-gateway nodes to prevent routing local-network traffic through the tunnel.
func (a *Agent) collectNonGatewayPeerIPs(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList) {
	gwPeers := map[string]bool{}
	gwList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, gwList); err == nil {
		for i := range gwList.Items {
			// Use electActivePeer (reads Spec.PeerRefs) rather than Status.ActivePeer
			// so new gateways are recognised immediately, before their status is set.
			ap, err := a.electActivePeer(ctx, &gwList.Items[i])
			if err != nil {
				// Keep the previous filter rather than build one from a
				// partial view.
				return
			}
			if ap != "" {
				gwPeers[ap] = true
			}
		}
	}

	a.nonGwPeerIPs = make([]net.IP, 0, len(peerList.Items))
	for i := range peerList.Items {
		p := &peerList.Items[i]
		if gwPeers[p.Name] {
			continue
		}
		if len(p.Spec.AllowedIPs) > 0 {
			ip, _, _ := net.ParseCIDR(p.Spec.AllowedIPs[0])
			if ip != nil {
				a.nonGwPeerIPs = append(a.nonGwPeerIPs, ip)
			}
		}
	}
}

// buildGatewayClientCache populates a map of gateway CIDR → allowed client peers.
// Rebuilt every sync cycle.
func (a *Agent) buildGatewayClientCache(ctx context.Context) {
	a.gwClientCache = make(map[string]map[string]bool)

	gwList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, gwList); err != nil {
		return
	}

	for i := range gwList.Items {
		gw := &gwList.Items[i]
		clientSet := make(map[string]bool, len(gw.Spec.ClientRefs))
		for _, c := range gw.Spec.ClientRefs {
			clientSet[c] = true
		}
		for _, route := range gw.Spec.Routes {
			a.gwClientCache[route.CIDR] = clientSet
		}
	}
}
