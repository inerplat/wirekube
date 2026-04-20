//go:build linux

package agent

import (
	"net"
	"net/url"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
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
	apiIP := apiServerIP()
	if apiIP == nil {
		return
	}

	rule := netlink.NewRule()
	rule.Dst = &net.IPNet{IP: apiIP, Mask: net.CIDRMask(32, 32)}
	rule.Table = 254 // main
	rule.Priority = 199

	// Check if rule already exists.
	rules, err := netlink.RuleList(syscall.AF_INET)
	if err == nil {
		for _, r := range rules {
			if r.Dst != nil && r.Dst.IP.Equal(apiIP) && r.Table == 254 && r.Priority == 199 {
				return
			}
		}
	}

	if err := netlink.RuleAdd(rule); err != nil {
		a.log.Error(err, "failed to add API server ip rule", "ip", apiIP)
	} else {
		a.log.Info("API server route protected", "ip", apiIP, "rule", "to "+apiIP.String()+"/32 lookup main prio 199")
	}
}

// apiServerIP extracts the API server IP from environment or rest config host.
func apiServerIP() net.IP {
	// Try KUBERNETES_SERVICE_HOST first (set by kubelet for in-cluster pods).
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		if ip := net.ParseIP(host); ip != nil {
			return ip.To4()
		}
	}

	// Try WIREKUBE_KUBE_APISERVER flag/env.
	if apiServer := os.Getenv("WIREKUBE_KUBE_APISERVER"); apiServer != "" {
		return parseHostIP(apiServer)
	}

	return nil
}

// isAPIServerCIDR reports whether a CIDR matches the API server IP.
func (a *Agent) isAPIServerCIDR(cidr string) bool {
	apiIP := apiServerIP()
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
