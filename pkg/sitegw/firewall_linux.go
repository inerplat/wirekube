//go:build linux

package sitegw

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/inerplat/wirekube/pkg/ipsec"
)

// Chains of the namespace firewall.
const (
	FirewallInputChain   = "WIREKUBE-SITEGW-IN"
	FirewallForwardChain = "WIREKUBE-SITEGW-FWD"
)

var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// FirewallRules are the IPv4 rules of the namespace firewall, by chain. The
// local network (tenant) may not reach the gateway itself, may send nothing
// out but what an IPsec policy or an XFRM interface encrypts, and receives
// nothing but what IPsec decrypted. Forwarded traffic that does not touch
// the tenant leg is dropped, so nothing from the uplink side reaches the
// tunnels and the gateway routes nothing between other networks. The rules
// name only the tenant leg, so they hold whatever the other interfaces are
// called.
func FirewallRules(tenant string) map[string][][]string {
	xfrmi := ipsec.InterfacePrefix + "+"
	return map[string][][]string{
		// Nor may the remote sites: what IPsec decrypted for the gateway
		// itself is dropped. IKE is not ESP, so charon is unaffected.
		FirewallInputChain: {
			{"-i", tenant, "-j", "DROP"},
			{"-i", xfrmi, "-j", "DROP"},
			{"-m", "policy", "--dir", "in", "--pol", "ipsec", "-j", "DROP"},
		},
		FirewallForwardChain: {
			{"-i", tenant, "!", "-o", xfrmi, "-m", "policy", "--dir", "out", "--pol", "none", "-j", "DROP"},
			{"!", "-i", xfrmi, "-o", tenant, "-m", "policy", "--dir", "in", "--pol", "none", "-j", "DROP"},
			{"!", "-i", tenant, "!", "-o", tenant, "-j", "DROP"},
		},
	}
}

// FirewallRules6 are the IPv6 rules: the tunnels carry IPv4 only, so IPv6
// from or to the tenant leg is dropped outright.
func FirewallRules6(tenant string) map[string][][]string {
	return map[string][][]string{
		FirewallInputChain: {
			{"-i", tenant, "-j", "DROP"},
		},
		FirewallForwardChain: {
			{"-i", tenant, "-j", "DROP"},
			{"-o", tenant, "-j", "DROP"},
		},
	}
}

var firewallHooks = map[string]string{FirewallInputChain: "INPUT", FirewallForwardChain: "FORWARD"}

// EnsureFirewall installs the namespace firewall, for IPv4 and IPv6, and the
// sysctls the gateway needs: forwarding, and loose reverse-path filtering
// inherited by XFRM interfaces created later. Missing rules are added and
// nothing is flushed, so a rule never goes missing while it runs. Both
// interfaces must exist: rules naming an absent one would match nothing.
// UplinkAddresses are the IPv4 addresses of the uplink interface.
func UplinkAddresses(uplink string) ([]netip.Addr, error) {
	link, err := netlink.LinkByName(uplink)
	if err != nil {
		return nil, fmt.Errorf("uplink interface %s: %w", uplink, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP.To4()); ok {
			out = append(out, ip)
		}
	}
	return out, nil
}

func EnsureFirewall(tenant, uplink string) error {
	if !ifaceName.MatchString(tenant) || !ifaceName.MatchString(uplink) || tenant == uplink {
		return fmt.Errorf("interface names %q and %q are not two valid, different names", tenant, uplink)
	}
	for _, name := range []string{tenant, uplink} {
		if _, err := netlink.LinkByName(name); err != nil {
			return fmt.Errorf("interface %s: %w", name, err)
		}
	}
	if err := ensureRules("iptables", FirewallRules(tenant)); err != nil {
		return err
	}
	// A kernel booted with ipv6.disable=1 has no IPv6 to filter, and
	// ip6tables fails there.
	if _, err := os.Stat("/proc/sys/net/ipv6"); err == nil {
		if err := ensureRules("ip6tables", FirewallRules6(tenant)); err != nil {
			return err
		}
	}
	for path, want := range map[string]string{
		"/proc/sys/net/ipv4/ip_forward":             "1",
		"/proc/sys/net/ipv4/conf/default/rp_filter": "2",
	} {
		if err := ensureSysctl(path, want); err != nil {
			return err
		}
	}
	return nil
}

func ensureRules(cmd string, chains map[string][][]string) error {
	for chain, rules := range chains {
		if _, err := xtables(cmd, "-S", chain); err != nil {
			if _, err := xtables(cmd, "-N", chain); err != nil {
				return err
			}
		}
		for _, rule := range rules {
			if _, err := xtables(cmd, append([]string{"-C", chain}, rule...)...); err != nil {
				if _, err := xtables(cmd, append([]string{"-A", chain}, rule...)...); err != nil {
					return err
				}
			}
		}
		hook := firewallHooks[chain]
		if _, err := xtables(cmd, "-C", hook, "-j", chain); err != nil {
			if _, err := xtables(cmd, "-I", hook, "1", "-j", chain); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureSysctl(path, want string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if strings.TrimSpace(string(b)) == want {
		return nil
	}
	if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
		return fmt.Errorf("setting %s (run sitegw firewall in a privileged init container): %w", path, err)
	}
	return nil
}

// xtables waits at most 5s for the xtables lock, so a stuck holder cannot
// stall the sync loop.
func xtables(cmd string, args ...string) (string, error) {
	out, err := exec.Command(cmd, append([]string{"-w", "5"}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %s: %w", cmd, strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}
