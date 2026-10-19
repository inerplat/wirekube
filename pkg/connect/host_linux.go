//go:build linux

package connect

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// DefaultInterfaceName is the tunnel interface connect asks for. It stays
// clear of the agent's own interface so connect can run on a cluster node.
const DefaultInterfaceName = "wkconnect0"

// Supported reports whether this process can run a connect session: creating
// the tunnel and routing through it takes root or CAP_NET_ADMIN.
func Supported() error {
	if unix.Geteuid() == 0 {
		return nil
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err == nil && data[0].Effective&(1<<unix.CAP_NET_ADMIN) != 0 {
		return nil
	}
	return errors.New("connect needs root or CAP_NET_ADMIN to create the tunnel interface; rerun it with sudo")
}

type linuxHost struct {
	name     string
	link     netlink.Link
	addr     netip.Prefix
	routes   map[netip.Prefix]bool
	routeSrc netip.Addr
	dns      bool
}

func newHostNetwork(name string) (hostNetwork, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("look up tunnel interface %s: %w", name, err)
	}
	return &linuxHost{name: name, link: link, routes: map[netip.Prefix]bool{}}, nil
}

func (h *linuxHost) SetAddress(p netip.Prefix) error {
	addr := &netlink.Addr{IPNet: prefixToIPNet(p)}
	if err := netlink.AddrReplace(h.link, addr); err != nil {
		return fmt.Errorf("assign %s to %s: %w", p, h.name, err)
	}
	// A reissued peer can come back with a different address; the old one
	// would otherwise linger as a second source address on the link.
	if h.addr.IsValid() && h.addr != p {
		err := netlink.AddrDel(h.link, &netlink.Addr{IPNet: prefixToIPNet(h.addr)})
		if err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("remove previous address %s: %w", h.addr, err)
		}
	}
	h.addr = p
	if err := netlink.LinkSetUp(h.link); err != nil {
		return fmt.Errorf("bring %s up: %w", h.name, err)
	}
	return nil
}

func (h *linuxHost) SyncRoutes(routes []netip.Prefix, src netip.Addr) ([]string, error) {
	var warnings []string
	srcChanged := h.routeSrc != src
	want := make(map[netip.Prefix]bool, len(routes))
	for _, p := range routes {
		want[p] = true
		r := h.route(p, src)
		if h.routes[p] {
			// Ours, so replacing it is safe; it only needs touching when the
			// address it is sourced from changed.
			if srcChanged {
				if err := netlink.RouteReplace(r); err != nil {
					return warnings, fmt.Errorf("route %s via %s: %w", p, h.name, err)
				}
			}
			continue
		}
		err := netlink.RouteAdd(r)
		if errors.Is(err, unix.EEXIST) {
			warnings = append(warnings, fmt.Sprintf("%s is already routed on this host; leaving that route in place, so it does not go through the tunnel", p))
			continue
		}
		if err != nil {
			return warnings, fmt.Errorf("route %s via %s: %w", p, h.name, err)
		}
		h.routes[p] = true
	}
	h.routeSrc = src
	for p := range h.routes {
		if want[p] {
			continue
		}
		// The kernel only matches a delete against a route of the same
		// scope, and an unset scope is universe, not a wildcard.
		err := netlink.RouteDel(&netlink.Route{LinkIndex: h.link.Attrs().Index, Dst: prefixToIPNet(p), Scope: netlink.SCOPE_LINK})
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return warnings, fmt.Errorf("remove route %s: %w", p, err)
		}
		delete(h.routes, p)
	}
	return warnings, nil
}

func (h *linuxHost) route(p netip.Prefix, src netip.Addr) *netlink.Route {
	r := &netlink.Route{
		LinkIndex: h.link.Attrs().Index,
		Dst:       prefixToIPNet(p),
		Scope:     netlink.SCOPE_LINK,
		Protocol:  unix.RTPROT_STATIC,
	}
	if src.IsValid() && src.Is4() == p.Addr().Is4() {
		r.Src = net.IP(src.AsSlice())
	}
	return r
}

// SetDNS hands the cluster domain to systemd-resolved as a routing domain on
// the tunnel link, so only cluster names go to the cluster resolver and the
// link's settings vanish with the link.
func (h *linuxHost) SetDNS(cfg DNSConfig) error {
	resolvectl, err := exec.LookPath("resolvectl")
	if err != nil {
		return fmt.Errorf("%w: resolvectl not found (systemd-resolved is required)", ErrDNSUnsupported)
	}
	if out, err := exec.Command(resolvectl, "dns", h.name, cfg.Server.String()).CombinedOutput(); err != nil {
		return fmt.Errorf("%w: resolvectl dns: %s", ErrDNSUnsupported, strings.TrimSpace(string(out)))
	}
	h.dns = true
	args := []string{"domain", h.name, "~" + cfg.Domain}
	args = append(args, cfg.Search...)
	if out, err := exec.Command(resolvectl, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl domain: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (h *linuxHost) Close() error {
	if !h.dns {
		return nil
	}
	// The link is about to disappear, which drops its resolved settings too;
	// reverting first just avoids a window where resolved still forwards
	// cluster names to a dead link.
	if out, err := exec.Command("resolvectl", "revert", h.name).CombinedOutput(); err != nil {
		return fmt.Errorf("resolvectl revert: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}
