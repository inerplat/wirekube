//go:build linux

package agent

import (
	"errors"
	"net"
	"net/url"
	"syscall"

	"github.com/vishvananda/netlink"
)

const (
	apiServerRulePriority = 199
	mainRouteTable        = 254
)

// ensureAPIServerRoute adds an ip rule that forces API server traffic to use
// the main routing table, bypassing the WireKube routing table. Without this,
// once a WireGuard /32 route is installed for the control-plane node, all
// traffic to that IP — including K8s API requests — gets routed through the
// WG tunnel. If the tunnel can't reliably carry TCP (e.g. relay-only mode),
// the agent loses API server connectivity and crashes.
//
// Rule: to <API_SERVER_IP>/32 lookup main priority 199
// This sits just below the fwmark rule and above the WK table rule (priority 200).
func (a *Agent) ensureAPIServerRoute() {
	apiIP := apiServerIP(a.apiServer)

	rules, err := netlink.RuleList(syscall.AF_INET)
	if err == nil {
		hasCurrent, stale := apiserverRulePlan(rules, apiIP)
		for _, r := range stale {
			rule := r
			if err := netlink.RuleDel(&rule); err != nil && !errors.Is(err, syscall.ESRCH) {
				a.log.Error(err, "failed to remove stale API server ip rule", "rule", rule.String())
			} else {
				a.log.Info("stale API server route rule removed", "rule", rule.String())
			}
		}
		if hasCurrent {
			return
		}
	}

	if apiIP == nil {
		return
	}

	rule := netlink.NewRule()
	rule.Dst = &net.IPNet{IP: apiIP, Mask: net.CIDRMask(32, 32)}
	rule.Table = mainRouteTable
	rule.Priority = apiServerRulePriority

	if err := netlink.RuleAdd(rule); err != nil {
		if rules, listErr := netlink.RuleList(syscall.AF_INET); listErr == nil {
			if hasCurrent, _ := apiserverRulePlan(rules, apiIP); hasCurrent {
				return
			}
		}
		a.log.Error(err, "failed to add API server ip rule", "ip", apiIP)
	} else {
		a.log.Info("API server route protected", "ip", apiIP, "rule", "to "+apiIP.String()+"/32 lookup main prio 199")
	}
}

func apiserverRulePlan(rules []netlink.Rule, apiIP net.IP) (bool, []netlink.Rule) {
	hasCurrent := false
	stale := []netlink.Rule{}
	for _, r := range rules {
		if !isManagedAPIServerRule(r) {
			continue
		}
		if apiIP != nil && r.Dst.IP.Equal(apiIP) {
			hasCurrent = true
			continue
		}
		stale = append(stale, r)
	}
	return hasCurrent, stale
}

func isManagedAPIServerRule(r netlink.Rule) bool {
	if r.Table != mainRouteTable || r.Priority != apiServerRulePriority {
		return false
	}
	if r.Dst == nil || r.Src != nil || r.Mark != 0 || r.Mask != nil || r.Invert {
		return false
	}
	if r.Tos != 0 || r.TunID != 0 || !isUnsetRuleInt(r.Flow) || r.IifName != "" || r.OifName != "" {
		return false
	}
	if r.Dport != nil || r.Sport != nil || r.IPProto != 0 || r.UIDRange != nil {
		return false
	}
	ones, bits := r.Dst.Mask.Size()
	return bits == 32 && ones == 32
}

func isUnsetRuleInt(v int) bool {
	return v == 0 || v == -1
}

// apiServerIP extracts the API server IP from the rest config host actually used
// by this agent. Proxy-node deployments commonly override the in-cluster
// KUBERNETES_SERVICE_HOST with an external apiserver URL; route protection must
// follow the effective restConfig.Host, not the ambient kubelet env.
func apiServerIP(apiServer string) net.IP {
	return parseHostIP(apiServer)
}

// isAPIServerCIDR reports whether a CIDR matches the API server IP.
func (a *Agent) isAPIServerCIDR(cidr string) bool {
	apiIP := apiServerIP(a.apiServer)
	if apiIP == nil {
		return false
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := ipnet.Mask.Size()
	return ones == 32 && ipnet.IP.Equal(apiIP)
}

func parseHostIP(rawURL string) net.IP {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4()
	}
	return nil
}
