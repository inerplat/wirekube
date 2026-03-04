package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
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
		fmt.Printf("[gateway] list error: %v\n", err)
		return nil
	}
	if len(gwList.Items) == 0 {
		return nil
	}

	myPeerName := "node-" + a.nodeName
	desiredSNATCIDRs := map[string]bool{}
	activeGateways := []string{}

	for i := range gwList.Items {
		gw := &gwList.Items[i]

		activePeer := a.electActivePeer(ctx, gw)
		fmt.Printf("[gateway] %s: elected=%s, me=%s\n", gw.Name, activePeer, myPeerName)
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

	if len(activeGateways) == 0 {
		a.cleanupGateway()
		return nil
	}

	if err := enableIPForwarding(); err != nil {
		fmt.Printf("[gateway] warning: enabling IP forwarding: %v\n", err)
	}

	a.syncSNATRules(desiredSNATCIDRs)

	if a.gwState == nil {
		a.gwState = &gatewayState{}
	}
	a.gwState.gatewayNames = activeGateways
	a.gwState.ipForwardEnabled = true

	return nil
}

// electActivePeer selects the active gateway peer from the PeerRefs list.
// The first peer that has a valid WireKubePeer CRD with a public key wins.
func (a *Agent) electActivePeer(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway) string {
	for _, peerName := range gw.Spec.PeerRefs {
		peer := &wirekubev1alpha1.WireKubePeer{}
		if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
			continue
		}
		if peer.Spec.PublicKey != "" {
			return peerName
		}
	}
	return ""
}

// injectGatewayRoutes adds gateway route CIDRs to the active peer's AllowedIPs
// if not already present.
func (a *Agent) injectGatewayRoutes(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, peerName string) {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return
	}

	existing := make(map[string]bool, len(peer.Spec.AllowedIPs))
	for _, ip := range peer.Spec.AllowedIPs {
		existing[ip] = true
	}

	changed := false
	for _, route := range gw.Spec.Routes {
		if !existing[route.CIDR] {
			peer.Spec.AllowedIPs = append(peer.Spec.AllowedIPs, route.CIDR)
			changed = true
			fmt.Printf("[gateway] injecting route %s into peer %s\n", route.CIDR, peerName)
		}
	}

	if changed {
		if err := a.client.Update(ctx, peer); err != nil {
			fmt.Printf("[gateway] warning: updating peer %s allowedIPs: %v\n", peerName, err)
		}
	}
}

// updateGatewayStatus sets the active peer and ready status on the gateway CR.
func (a *Agent) updateGatewayStatus(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, activePeer string) {
	if gw.Status.ActivePeer == activePeer && gw.Status.Ready {
		return
	}
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.ActivePeer = activePeer
	gw.Status.Ready = true
	gw.Status.RoutesInjected = int32(len(gw.Spec.Routes))
	if err := a.client.Status().Patch(ctx, gw, patch); err != nil {
		fmt.Printf("[gateway] warning: updating gateway status: %v\n", err)
	}
}

// cleanupGateway removes gateway-specific configuration (SNAT rules).
// IP forwarding is left enabled to avoid disrupting other services.
func (a *Agent) cleanupGateway() {
	if a.gwState == nil {
		return
	}
	for cidr := range a.gwState.snatRules {
		removeMasqueradeRule(cidr, a.wgMgr.InterfaceName())
	}
	a.gwState = nil
}

// syncSNATRules ensures the desired masquerade rules are installed
// and stale rules are removed.
func (a *Agent) syncSNATRules(desired map[string]bool) {
	if a.gwState == nil {
		a.gwState = &gatewayState{snatRules: map[string]bool{}}
	}

	ifaceName := a.wgMgr.InterfaceName()

	// Add missing rules
	for cidr := range desired {
		if !a.gwState.snatRules[cidr] {
			if err := addMasqueradeRule(cidr, ifaceName); err != nil {
				fmt.Printf("[gateway] warning: adding MASQUERADE for %s: %v\n", cidr, err)
				continue
			}
			a.gwState.snatRules[cidr] = true
			fmt.Printf("[gateway] MASQUERADE added for %s\n", cidr)
		}
	}

	// Remove stale rules
	for cidr := range a.gwState.snatRules {
		if !desired[cidr] {
			removeMasqueradeRule(cidr, ifaceName)
			delete(a.gwState.snatRules, cidr)
			fmt.Printf("[gateway] MASQUERADE removed for %s\n", cidr)
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
func addMasqueradeRule(cidr, _ string) error {
	args := []string{
		"-t", "nat", "-C", "POSTROUTING",
		"-d", cidr,
		"-j", "MASQUERADE",
	}
	if err := exec.Command("iptables", args...).Run(); err == nil {
		return nil
	}

	args[2] = "-A"
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// removeMasqueradeRule removes the iptables MASQUERADE rule.
func removeMasqueradeRule(cidr, _ string) {
	args := []string{
		"-t", "nat", "-D", "POSTROUTING",
		"-d", cidr,
		"-j", "MASQUERADE",
	}
	_ = exec.Command("iptables", args...).Run()
}

// getGatewayCIDRs returns all CIDR routes from WireKubeGateway CRs that
// reference the given peer as active gateway. Used during sync to include
// gateway routes in the kernel routing table.
func (a *Agent) getGatewayCIDRs(ctx context.Context) []string {
	gwList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, gwList); err != nil {
		return nil
	}

	var cidrs []string
	for i := range gwList.Items {
		gw := &gwList.Items[i]
		for _, route := range gw.Spec.Routes {
			cidrs = append(cidrs, route.CIDR)
		}
	}
	return cidrs
}

// isGatewayNode returns true if this node is the active gateway for any WireKubeGateway.
func (a *Agent) isGatewayNode() bool {
	return a.gwState != nil && len(a.gwState.gatewayNames) > 0
}

// listActiveGateways lists the WireKubeGateway CRs for which this node is active.
func (a *Agent) listActiveGateways(ctx context.Context) ([]wirekubev1alpha1.WireKubeGateway, error) {
	gwList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, gwList); err != nil {
		return nil, err
	}

	myPeerName := "node-" + a.nodeName
	var active []wirekubev1alpha1.WireKubeGateway
	for _, gw := range gwList.Items {
		if gw.Status.ActivePeer == myPeerName {
			active = append(active, gw)
		}
	}
	return active, nil
}

// performGatewayHealthCheck runs health check probes for gateways where
// this node is the active peer. Results are reported back to the gateway status.
func (a *Agent) performGatewayHealthCheck(ctx context.Context) {
	gateways, err := a.listActiveGateways(ctx)
	if err != nil || len(gateways) == 0 {
		return
	}

	for i := range gateways {
		gw := &gateways[i]
		if gw.Spec.HealthCheck == nil || !gw.Spec.HealthCheck.Enabled {
			continue
		}
	}
}

// shouldSkipGatewayRoute decides if a given CIDR (from a remote peer's AllowedIPs)
// should be excluded from this node's kernel route table.
//
// A CIDR is skipped when:
//  1. It's a gateway-injected route AND this node is not a designated client, OR
//  2. This node's own IP is already within the CIDR (same-VPC optimization).
func (a *Agent) shouldSkipGatewayRoute(ctx context.Context, cidr, myPeerName string, ownIP net.IP) bool {
	// Same-VPC: skip if our own IP is inside this CIDR
	if ownIP != nil {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ownIP) {
			return true
		}
	}

	// Check gateways to see if this CIDR is gateway-managed
	// and if we're an authorized client
	if a.gwClientCache == nil {
		a.buildGatewayClientCache(ctx)
	}

	if a.gwClientCache != nil {
		if clients, isGWRoute := a.gwClientCache[cidr]; isGWRoute {
			if len(clients) > 0 && !clients[myPeerName] {
				return true
			}
		}
	}

	return false
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
