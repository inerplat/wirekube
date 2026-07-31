package agent

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

const (
	externalEgressFilterChain = "WIREKUBE-EXT-FWD"
	externalEgressNATChain    = "WIREKUBE-EXT-NAT"
)

var (
	runExternalEgressIPTables        = runExternalEgressCommand
	detectExternalEgressDefaultIface = defaultIPv4RouteInterface
)

type externalEgressState struct {
	lastKey string
}

type externalEgressPeer struct {
	name          string
	sourceCIDR    string
	allowedCIDRs  []string
	excludedCIDRs []string
}

type externalEgressIPTablesRule struct {
	table string
	chain string
	args  []string
}

func (a *Agent) syncExternalPeerEgress(ctx context.Context, externalList *wirekubev1alpha1.WireKubeExternalPeerList) error {
	if externalList == nil {
		return nil
	}

	peers := make([]externalEgressPeer, 0)
	for i := range externalList.Items {
		ep := &externalList.Items[i]
		peer, ok, err := externalEgressPeerFromCR(ep, a.nodeName)
		if err != nil {
			a.log.Error(err, "skipping external peer egress", "peer", ep.Name)
			continue
		}
		if ok {
			peers = append(peers, peer)
		}
	}

	if len(peers) == 0 {
		return a.cleanupExternalEgressRules()
	}

	if err := enableIPForwarding(); err != nil {
		a.log.Error(err, "enabling IP forwarding for external peer egress")
	}

	outIface := ""
	wgIface := ""
	var err error
	wgIface = a.wgMgr.InterfaceName()
	if wgIface == "" {
		return fmt.Errorf("wireguard interface name is empty")
	}
	outIface, err = detectExternalEgressDefaultIface(ctx)
	if err != nil {
		return err
	}

	rules := buildExternalEgressIPTablesRules(peers, wgIface, outIface)
	return a.applyExternalEgressRules(rules)
}

func (a *Agent) cleanupExternalEgressRules() error {
	exists, err := externalEgressChainsExist()
	if err != nil {
		if a.extEgressState == nil {
			return nil
		}
		return err
	}
	if !exists {
		a.extEgressState = nil
		return nil
	}
	if a.extEgressState == nil {
		a.extEgressState = &externalEgressState{}
	}
	if err := ensureExternalEgressChains(); err != nil {
		return err
	}
	if err := flushExternalEgressChains(); err != nil {
		return err
	}
	a.extEgressState.lastKey = ""
	return nil
}

func externalEgressPeerFromCR(ep *wirekubev1alpha1.WireKubeExternalPeer, nodeName string) (externalEgressPeer, bool, error) {
	if ep == nil || ep.Spec.Egress == nil || !ep.Spec.Egress.Enabled {
		return externalEgressPeer{}, false, nil
	}
	if ep.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		return externalEgressPeer{}, false, nil
	}
	if ep.Status.IngressPeerName != nodeName {
		return externalEgressPeer{}, false, nil
	}
	if ep.Status.AssignedMeshIP == "" {
		return externalEgressPeer{}, false, fmt.Errorf("assigned mesh IP is empty")
	}
	mode := ep.Spec.Egress.Mode
	if mode == "" {
		mode = wirekubev1alpha1.ExternalPeerEgressModeMasquerade
	}
	if mode != wirekubev1alpha1.ExternalPeerEgressModeMasquerade {
		return externalEgressPeer{}, false, fmt.Errorf("unsupported egress mode %q", mode)
	}

	source, err := normalizeIPv4CIDR(ep.Status.AssignedMeshIP)
	if err != nil {
		return externalEgressPeer{}, false, fmt.Errorf("invalid assigned mesh IP: %w", err)
	}

	allowed, err := normalizeIPv4CIDRs(defaultIfEmpty(ep.Spec.Egress.AllowedCIDRs, []string{"0.0.0.0/0"}))
	if err != nil {
		return externalEgressPeer{}, false, fmt.Errorf("invalid egress allowed CIDR: %w", err)
	}
	excluded, err := normalizeIPv4CIDRs(append(defaultExternalEgressExcludedCIDRs(), ep.Spec.Egress.ExcludedCIDRs...))
	if err != nil {
		return externalEgressPeer{}, false, fmt.Errorf("invalid egress excluded CIDR: %w", err)
	}

	return externalEgressPeer{
		name:          ep.Name,
		sourceCIDR:    source,
		allowedCIDRs:  allowed,
		excludedCIDRs: excluded,
	}, true, nil
}

func normalizeIPv4CIDRs(cidrs []string) ([]string, error) {
	out := make([]string, 0, len(cidrs))
	seen := map[string]struct{}{}
	for _, cidr := range cidrs {
		normalized, err := normalizeIPv4CIDR(cidr)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func normalizeIPv4CIDR(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return "", err
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("%s is not an IPv4 CIDR", cidr)
	}
	return prefix.String(), nil
}

func defaultIfEmpty(in, fallback []string) []string {
	if len(in) > 0 {
		return in
	}
	return fallback
}

func defaultExternalEgressExcludedCIDRs() []string {
	return []string{
		"0.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}
}

func buildExternalEgressIPTablesRules(peers []externalEgressPeer, wgIface, outIface string) []externalEgressIPTablesRule {
	if len(peers) == 0 || wgIface == "" || outIface == "" {
		return nil
	}

	rules := make([]externalEgressIPTablesRule, 0)
	for _, peer := range peers {
		for _, cidr := range peer.excludedCIDRs {
			rules = append(rules, externalEgressIPTablesRule{
				table: "filter",
				chain: externalEgressFilterChain,
				args:  []string{"-i", wgIface, "-s", peer.sourceCIDR, "-o", outIface, "-d", cidr, "-j", "DROP"},
			})
		}
		for _, cidr := range peer.allowedCIDRs {
			rules = append(rules, externalEgressIPTablesRule{
				table: "filter",
				chain: externalEgressFilterChain,
				args:  []string{"-i", wgIface, "-s", peer.sourceCIDR, "-o", outIface, "-d", cidr, "-j", "ACCEPT"},
			})
		}
		rules = append(rules, externalEgressIPTablesRule{
			table: "filter",
			chain: externalEgressFilterChain,
			args:  []string{"-i", outIface, "-o", wgIface, "-d", peer.sourceCIDR, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		})
		rules = append(rules, externalEgressIPTablesRule{
			table: "filter",
			chain: externalEgressFilterChain,
			args:  []string{"-i", wgIface, "-s", peer.sourceCIDR, "-o", outIface, "-j", "DROP"},
		})
		for _, cidr := range peer.allowedCIDRs {
			rules = append(rules, externalEgressIPTablesRule{
				table: "nat",
				chain: externalEgressNATChain,
				args:  []string{"-s", peer.sourceCIDR, "-o", outIface, "-d", cidr, "-j", "MASQUERADE"},
			})
		}
	}
	return rules
}

func (a *Agent) applyExternalEgressRules(rules []externalEgressIPTablesRule) error {
	if a.extEgressState == nil {
		a.extEgressState = &externalEgressState{}
	}
	if err := ensureExternalEgressChains(); err != nil {
		return err
	}

	key := externalEgressRulesKey(rules)
	if a.extEgressState.lastKey != key {
		if err := flushExternalEgressChains(); err != nil {
			return err
		}
		a.extEgressState.lastKey = key
	}

	for _, rule := range rules {
		if err := ensureExternalEgressRule(rule); err != nil {
			return err
		}
	}
	return nil
}

func ensureExternalEgressChains() error {
	for _, chain := range []struct {
		table      string
		chain      string
		parent     string
		insertArgs []string
	}{
		{table: "filter", chain: externalEgressFilterChain, parent: "FORWARD", insertArgs: []string{"-j", externalEgressFilterChain}},
		{table: "nat", chain: externalEgressNATChain, parent: "POSTROUTING", insertArgs: []string{"-j", externalEgressNATChain}},
	} {
		if out, err := runExternalEgressIPTables("-t", chain.table, "-N", chain.chain); err != nil && !iptablesAlreadyExists(out) {
			return fmt.Errorf("create iptables chain %s/%s: %s: %w", chain.table, chain.chain, strings.TrimSpace(out), err)
		}
		checkArgs := append([]string{"-t", chain.table, "-C", chain.parent}, chain.insertArgs...)
		if _, err := runExternalEgressIPTables(checkArgs...); err == nil {
			continue
		}
		insertArgs := append([]string{"-t", chain.table, "-I", chain.parent, "1"}, chain.insertArgs...)
		if out, err := runExternalEgressIPTables(insertArgs...); err != nil {
			return fmt.Errorf("insert iptables jump %s/%s: %s: %w", chain.table, chain.parent, strings.TrimSpace(out), err)
		}
	}
	return nil
}

func externalEgressChainsExist() (bool, error) {
	for _, chain := range []struct {
		table string
		chain string
	}{
		{table: "filter", chain: externalEgressFilterChain},
		{table: "nat", chain: externalEgressNATChain},
	} {
		out, err := runExternalEgressIPTables("-t", chain.table, "-S", chain.chain)
		if err == nil {
			return true, nil
		}
		if iptablesNoSuchChain(out) {
			continue
		}
		return false, fmt.Errorf("inspect iptables chain %s/%s: %s: %w", chain.table, chain.chain, strings.TrimSpace(out), err)
	}
	return false, nil
}

func flushExternalEgressChains() error {
	for _, chain := range []struct {
		table string
		chain string
	}{
		{table: "filter", chain: externalEgressFilterChain},
		{table: "nat", chain: externalEgressNATChain},
	} {
		if out, err := runExternalEgressIPTables("-t", chain.table, "-F", chain.chain); err != nil {
			return fmt.Errorf("flush iptables chain %s/%s: %s: %w", chain.table, chain.chain, strings.TrimSpace(out), err)
		}
	}
	return nil
}

func ensureExternalEgressRule(rule externalEgressIPTablesRule) error {
	checkArgs := append([]string{"-t", rule.table, "-C", rule.chain}, rule.args...)
	if _, err := runExternalEgressIPTables(checkArgs...); err == nil {
		return nil
	}
	addArgs := append([]string{"-t", rule.table, "-A", rule.chain}, rule.args...)
	if out, err := runExternalEgressIPTables(addArgs...); err != nil {
		return fmt.Errorf("add iptables rule %s/%s %s: %s: %w", rule.table, rule.chain, strings.Join(rule.args, " "), strings.TrimSpace(out), err)
	}
	return nil
}

func externalEgressRulesKey(rules []externalEgressIPTablesRule) string {
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts = append(parts, rule.table+"/"+rule.chain+" "+strings.Join(rule.args, " "))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

func iptablesAlreadyExists(out string) bool {
	out = strings.ToLower(out)
	return strings.Contains(out, "chain already exists") || strings.Contains(out, "file exists")
}

func iptablesNoSuchChain(out string) bool {
	out = strings.ToLower(out)
	return strings.Contains(out, "no chain/target/match by that name") ||
		strings.Contains(out, "does not exist") ||
		strings.Contains(out, "not found")
}

func defaultIPv4RouteInterface(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("detect default route interface: %w", err)
	}
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" && fields[i+1] != "" {
				return fields[i+1], nil
			}
		}
	}
	return "", fmt.Errorf("default route interface not found")
}

func runExternalEgressCommand(args ...string) (string, error) {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	return string(out), err
}
