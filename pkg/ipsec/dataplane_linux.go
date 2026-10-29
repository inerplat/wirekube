//go:build linux

package ipsec

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

const (
	// RouteTable holds the remote traffic selectors of tunnels this node
	// terminates. It is separate from the WireKube WireGuard table, which
	// belongs to the wire_kube link alone and is pruned of routes on any
	// other link.
	RouteTable = 0x574C
	// RulePriority sits before the WireGuard table rule (200), so remote
	// networks go into the tunnel even if a WireGuard route overlaps them.
	// 199 is the API server bypass rule. The table holds only remote
	// selectors, so preceding that rule and the fwmark rule matters only for
	// a selector covering the API server or a WireGuard endpoint.
	RulePriority = 198
)

// EnsureRule installs "from all lookup RouteTable" with suppress_prefixlen 0
// so a default route in the table can never capture all traffic. A non-empty
// iif limits the rule to traffic arriving on that interface.
func EnsureRule(iif string) error {
	rule := ipsecRule(iif)
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("listing ip rules: %w", err)
	}
	present := false
	for i := range rules {
		r := rules[i]
		if r.Table != RouteTable {
			continue
		}
		if r.Priority == RulePriority && r.SuppressPrefixlen == 0 && r.Src == nil && r.Dst == nil && r.Mark == 0 && r.IifName == iif {
			present = true
			continue
		}
		// A rule for this table at another priority or with other selectors
		// would shadow or duplicate this one.
		_ = netlink.RuleDel(&r)
	}
	if present {
		return nil
	}
	if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("adding ip rule for table %#x: %w", RouteTable, err)
	}
	return nil
}

// ipv6DisableParam is the ipv6 module parameter set by ipv6.disable=1.
var ipv6DisableParam = "/sys/module/ipv6/parameters/disable"

// XFRMInterfaceBlocker explains why this kernel cannot create XFRM
// interfaces, or returns "" when it may. It answers without trying: with
// ipv6.disable=1, creating an XFRM interface makes xfrm_interface fail to
// load, and the failed load removes every IPsec SA on the node without
// charon noticing.
func XFRMInterfaceBlocker() string {
	b, err := os.ReadFile(ipv6DisableParam)
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		return "the kernel was booted with ipv6.disable=1, so xfrm_interface cannot load"
	}
	return ""
}

// IsUnsupported reports whether err means the kernel cannot create XFRM
// interfaces at all, for example because xfrm_interface fails to load on a
// kernel booted with ipv6.disable=1.
func IsUnsupported(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EAFNOSUPPORT)
}

// RemoveRule deletes every rule pointing at RouteTable.
func RemoveRule() {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		_ = netlink.RuleDel(ipsecRule(""))
		return
	}
	for i := range rules {
		if rules[i].Table == RouteTable {
			_ = netlink.RuleDel(&rules[i])
		}
	}
}

func ipsecRule(iif string) *netlink.Rule {
	r := netlink.NewRule()
	r.IifName = iif
	r.Table = RouteTable
	r.Priority = RulePriority
	r.SuppressPrefixlen = 0
	return r
}

// EnsureInterface creates or repairs the XFRM interface for a tunnel.
func EnsureInterface(name string, ifID uint32, mtu int) error {
	if link, err := netlink.LinkByName(name); err == nil {
		x, ok := link.(*netlink.Xfrmi)
		if !ok || x.Ifid != ifID {
			// A link of the right name but the wrong kind or ID would steer
			// tunnel traffic into the wrong SA; rebuild it.
			if err := netlink.LinkDel(link); err != nil {
				return fmt.Errorf("replacing %s: %w", name, err)
			}
		} else {
			if link.Attrs().MTU != mtu {
				if err := netlink.LinkSetMTU(link, mtu); err != nil {
					return fmt.Errorf("setting MTU on %s: %w", name, err)
				}
			}
			if link.Attrs().Flags&net.FlagUp == 0 {
				if err := netlink.LinkSetUp(link); err != nil {
					return fmt.Errorf("bringing up %s: %w", name, err)
				}
			}
			return setLooseRPFilter(name)
		}
	}
	x := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}, Ifid: ifID}
	if err := netlink.LinkAdd(x); err != nil {
		return fmt.Errorf("creating XFRM interface %s (if_id %d): %w", name, ifID, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("looking up %s after creation: %w", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up %s: %w", name, err)
	}
	return setLooseRPFilter(name)
}

// setLooseRPFilter makes reverse-path filtering on the XFRM interface loose.
// Decrypted packets come from remote networks routed through this interface
// in a non-main table; loose mode accepts them as long as any route exists.
func setLooseRPFilter(name string) error {
	path := "/proc/sys/net/ipv4/conf/" + name + "/rp_filter"
	// The agent DaemonSet mounts the host's /proc/sys/net under /host, since
	// /proc/sys may be read-only in the container.
	if _, err := os.Stat("/host/proc/sys/net/ipv4/conf/" + name); err == nil {
		path = "/host" + path
	}
	// An interface inherits conf/default when it is created, so a namespace
	// whose default is loose needs no write, which matters where /proc/sys
	// is read-only.
	if cur, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(cur)) == "2" {
		return nil
	}
	if err := os.WriteFile(path, []byte("2"), 0o644); err != nil {
		return fmt.Errorf("setting rp_filter on %s: %w", name, err)
	}
	return nil
}

// DeleteInterface removes a WireKube XFRM interface; a missing one is fine.
func DeleteInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(link)
}

// ListInterfaces returns WireKube-owned XFRM interfaces present on the node.
func ListInterfaces() ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	var out []string
	for _, l := range links {
		if _, ok := l.(*netlink.Xfrmi); ok && strings.HasPrefix(l.Attrs().Name, InterfacePrefix) {
			out = append(out, l.Attrs().Name)
		}
	}
	return out, nil
}

// SyncRoutes makes RouteTable contain exactly the given prefixes on the given
// interfaces. src, when set, is the preferred source for traffic the gateway
// node originates itself; it should be the node's mesh IP so that traffic
// matches the mesh-side traffic selector.
func SyncRoutes(desired map[string][]string, src net.IP) error {
	type key struct {
		dst  string
		link int
	}
	want := map[key]*netlink.Route{}
	for ifName, prefixes := range desired {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("looking up %s: %w", ifName, err)
		}
		for _, p := range prefixes {
			_, dst, err := net.ParseCIDR(p)
			if err != nil {
				return fmt.Errorf("parsing %s: %w", p, err)
			}
			want[key{dst.String(), link.Attrs().Index}] = &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       dst,
				Table:     RouteTable,
				Src:       src,
				Scope:     netlink.SCOPE_LINK,
			}
		}
	}

	current, err := netlink.RouteListFiltered(syscall.AF_INET, &netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("listing table %#x: %w", RouteTable, err)
	}
	for i := range current {
		r := current[i]
		if r.Dst == nil {
			_ = netlink.RouteDel(&r)
			continue
		}
		w, ok := want[key{r.Dst.String(), r.LinkIndex}]
		if !ok || !w.Src.Equal(r.Src) {
			_ = netlink.RouteDel(&r)
			continue
		}
		delete(want, key{r.Dst.String(), r.LinkIndex})
	}
	var errs []error
	for _, r := range want {
		if err := netlink.RouteReplace(r); err != nil {
			errs = append(errs, fmt.Errorf("route %s dev %d: %w", r.Dst, r.LinkIndex, err))
		}
	}
	return errors.Join(errs...)
}

// RemoveTunnelState removes the XFRM interfaces, the tunnel route table and
// its rule. The plaintext guard is left to SyncGuard, so a node that stops
// terminating IPsec can keep dropping traffic it would otherwise forward
// unencrypted.
func RemoveTunnelState() error {
	var errs []error
	ifaces, err := ListInterfaces()
	if err != nil {
		errs = append(errs, err)
	}
	for _, name := range ifaces {
		if err := DeleteInterface(name); err != nil {
			errs = append(errs, err)
		}
	}
	if err := SyncRoutes(nil, nil); err != nil {
		errs = append(errs, err)
	}
	RemoveRule()
	return errors.Join(errs...)
}
