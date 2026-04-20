//go:build linux

package wireguard

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
)

// Routing constants used by UserspaceEngine for the fwmark/table scheme.
// 0x574B = "WK" in ASCII.
const (
	WKFwMark     = 0x574B
	WKRouteTable = 0x574B
)

// EnsureRoutingRules sets up the fwmark and WireKube routing table ip rules.
//
//  1. fwmark 0x574B → main table: WG socket bypasses tunnel routes
//  2. all → WireKube table (priority 200): normal traffic uses WG tunnel routes
//
// The fwmark rule priority is placed AFTER the kernel's local routing table
// rule to ensure packets to 127.0.0.0/8 (relay proxy) are delivered via
// loopback rather than the main table's default route. Some CNIs (notably
// Cilium) move the local table from its default priority 0 to higher values
// like 100; we detect the current local table priority and place our rule
// 10 positions after it (minimum 110).
func EnsureRoutingRules() error {
	fwPrio := fwmarkRulePriority()

	// Migrate: remove stale fwmark rule at the old hard-coded priority 100.
	if fwPrio != 100 {
		old := netlink.NewRule()
		old.Mark = WKFwMark
		old.Table = 254
		old.Priority = 100
		_ = netlink.RuleDel(old)
	}

	fwRule := netlink.NewRule()
	fwRule.Mark = WKFwMark
	fwRule.Table = 254
	fwRule.Priority = fwPrio
	if !ruleExists(fwRule) {
		if err := netlink.RuleAdd(fwRule); err != nil {
			return fmt.Errorf("adding fwmark rule: %w", err)
		}
	}

	wgRule := netlink.NewRule()
	wgRule.Table = WKRouteTable
	wgRule.Priority = 200
	// SuppressPrefixlen 0 makes the rule skip default routes (prefix /0) in
	// the WK table. Since we only add /32 host routes, those still match.
	// Traffic that doesn't match any /32 falls through to the next rule
	// (main table), preserving connectivity to the API server and other
	// destinations not reachable through WireGuard tunnels.
	wgRule.SuppressPrefixlen = 0

	// Always remove and re-add the WK rule to ensure SuppressPrefixlen is
	// applied. A stale rule without suppress (from a previous agent run or
	// a failed setup attempt) would trap non-WG traffic and break API access.
	staleWG := netlink.NewRule()
	staleWG.Table = WKRouteTable
	staleWG.Priority = 200
	_ = netlink.RuleDel(staleWG) // ignore error if rule doesn't exist

	if err := netlink.RuleAdd(wgRule); err != nil {
		return fmt.Errorf("adding wg table rule: %w", err)
	}

	return nil
}

// RemoveRoutingRules removes the fwmark and WireKube routing table ip rules.
func RemoveRoutingRules() {
	// Remove fwmark rule at the dynamically chosen priority and the legacy 100.
	for _, prio := range []int{fwmarkRulePriority(), 100} {
		fwRule := netlink.NewRule()
		fwRule.Mark = WKFwMark
		fwRule.Table = 254
		fwRule.Priority = prio
		_ = netlink.RuleDel(fwRule)
	}

	wgRule := netlink.NewRule()
	wgRule.Table = WKRouteTable
	wgRule.Priority = 200
	_ = netlink.RuleDel(wgRule)
}

// SyncRoutesForLink ensures exactly the given CIDRs are routed through the
// given link in the WireKube routing table. Routes present in the kernel but
// not in desired are removed. Routes in desired but not in kernel are added.
// Routes whose preferred source IP changed are replaced.
func SyncRoutesForLink(linkIndex int, preferredSrc net.IP, desired []string) error {
	// Build desired set
	desiredSet := make(map[string]struct{}, len(desired))
	for _, cidr := range desired {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parsing desired CIDR %s: %w", cidr, err)
		}
		desiredSet[ipnet.String()] = struct{}{}
	}

	routeFilter := &netlink.Route{Table: WKRouteTable, LinkIndex: linkIndex}
	current, err := netlink.RouteListFiltered(syscall.AF_INET, routeFilter, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return fmt.Errorf("listing routes: %w", err)
	}

	for _, r := range current {
		if r.Dst == nil {
			continue
		}
		if _, ok := desiredSet[r.Dst.String()]; !ok {
			_ = netlink.RouteDel(&r)
			continue
		}
		if preferredSrc != nil && !preferredSrc.Equal(r.Src) {
			_ = netlink.RouteDel(&r)
		}
	}

	// Add missing routes (including those just deleted for src mismatch)
	for _, cidr := range desired {
		if err := AddRouteForLink(linkIndex, preferredSrc, cidr); err != nil {
			log.Printf("warning: adding route %s: %v\n", cidr, err)
		}
	}
	return nil
}

// isRouteExists returns true when an error from netlink.RouteAdd indicates
// that the route already exists. netlink returns a sentinel string rather
// than a typed error, so a string compare is the interface we have.
func isRouteExists(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "file exists"
}

// AddRouteForLink adds a route for dst through the given link in the WireKube
// routing table.
func AddRouteForLink(linkIndex int, preferredSrc net.IP, dst string) error {
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		return fmt.Errorf("parsing dst CIDR %s: %w", dst, err)
	}
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       ipnet,
		Table:     WKRouteTable,
		Src:       preferredSrc,
	}
	if addErr := netlink.RouteAdd(route); addErr != nil {
		if isRouteExists(addErr) {
			return nil
		}
		return addErr
	}
	return nil
}

// DelRouteForLink removes a route for dst through the given link.
func DelRouteForLink(linkIndex int, dst string) error {
	_, ipnet, err := net.ParseCIDR(dst)
	if err != nil {
		return nil
	}
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       ipnet,
		Table:     WKRouteTable,
	}
	return netlink.RouteDel(route)
}

// fwmarkRulePriority returns the ip rule priority for the fwmark rule.
// It must be AFTER the local routing table rule so that packets to loopback
// (127.0.0.0/8) are routed via lo before the fwmark rule can send them to
// the main table's default route. Returns max(localPriority+10, 110),
// capped below the WireKube table rule at 200.
func fwmarkRulePriority() int {
	localPrio := 0
	rules, _ := netlink.RuleList(syscall.AF_INET)
	for _, r := range rules {
		if r.Table == 255 && r.Priority > localPrio {
			localPrio = r.Priority
		}
	}
	prio := localPrio + 10
	if prio < 110 {
		prio = 110
	}
	if prio >= 200 {
		prio = 199
	}
	return prio
}

// ruleExists checks if a matching ip rule already exists.
func ruleExists(target *netlink.Rule) bool {
	rules, _ := netlink.RuleList(syscall.AF_INET)
	for _, r := range rules {
		if r.Mark == target.Mark && r.Table == target.Table && r.Priority == target.Priority {
			return true
		}
	}
	return false
}

// setRpFilterForIface sets rp_filter=2 (loose mode) on the given interface
// AND on "all". Linux uses max(conf/all, conf/<iface>) as the effective value,
// so "all" must also be loosened — otherwise strict rp_filter on "all" overrides
// the per-interface setting. Without this, relay TCP packets arriving on eth0
// from cross-VPC peers are dropped because the reverse path resolves through
// the WireGuard routing table (wire_kube), not eth0.
func setRpFilterForIface(ifaceName string) {
	for _, iface := range []string{ifaceName, "all"} {
		paths := []string{
			fmt.Sprintf("/host/proc/sys/net/ipv4/conf/%s/rp_filter", iface),
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface),
		}
		for _, path := range paths {
			if err := os.WriteFile(path, []byte("2"), 0644); err == nil {
				log.Printf("[wireguard] rp_filter=2 set on %s\n", iface)
				break
			}
		}
	}
}

// disableXfrmForIface disables xfrm (IPSec) policy matching on the given
// interface so IPSec policies don't intercept tunnel traffic.
func disableXfrmForIface(ifaceName string) {
	for _, sysctl := range []string{"disable_xfrm", "disable_policy"} {
		paths := []string{
			fmt.Sprintf("/host/proc/sys/net/ipv4/conf/%s/%s", ifaceName, sysctl),
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/%s", ifaceName, sysctl),
		}
		set := false
		for _, path := range paths {
			if err := os.WriteFile(path, []byte("1"), 0644); err == nil {
				set = true
				break
			}
		}
		if !set {
			log.Printf("[wireguard] warning: could not set %s on %s\n", sysctl, ifaceName)
		}
	}
	log.Printf("[wireguard] xfrm bypass enabled on %s\n", ifaceName)
}
