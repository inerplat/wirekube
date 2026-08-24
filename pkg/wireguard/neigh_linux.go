//go:build linux

package wireguard

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"
)

// NeighborEntry is one resolved neighbour: an address on an attached link and
// the hardware address that answers for it.
type NeighborEntry struct {
	Address netip.Addr
	MAC     string
	// Reachable is true while the kernel considers the entry usable without
	// re-resolving it. Entries the kernel is still probing (INCOMPLETE) or has
	// given up on (FAILED) carry no MAC and are dropped before this.
	Reachable bool
}

// NeighborsOnLinks reads the IPv4 neighbour table for every attached link
// except excludeIface, answering which addresses this host has resolved on the
// wire and what answered for them.
//
// A resolved entry is evidence about layer 2 and nothing else: the address
// answered an ARP request on one of this host's links, and the MAC is that
// answer. It says nothing about WireGuard state, which is what makes it usable
// as the observer's half of an adjacency check. It does require the address to
// have been resolved at some point, so an address this host never sends to has
// no entry.
func NeighborsOnLinks(excludeIface string) ([]NeighborEntry, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	out := []NeighborEntry{}
	for _, l := range links {
		name := l.Attrs().Name
		if name == excludeIface || name == "lo" {
			continue
		}
		neighs, err := netlink.NeighList(l.Attrs().Index, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("listing neighbours on %s: %w", name, err)
		}
		for _, n := range neighs {
			if n.IP == nil || len(n.HardwareAddr) == 0 {
				continue
			}
			addr, ok := netip.AddrFromSlice(n.IP.To4())
			if !ok {
				continue
			}
			out = append(out, NeighborEntry{
				Address:   addr,
				MAC:       strings.ToLower(n.HardwareAddr.String()),
				Reachable: n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_DELAY|netlink.NUD_PROBE|netlink.NUD_PERMANENT) != 0,
			})
		}
	}
	return out, nil
}

// LocalLinkAddresses reports the addresses configured on this host's attached
// links together with the MAC of the link each sits on. Published in the node's
// own peer status, this is the claim an observer matches its neighbour table
// against — the other half of the adjacency check.
func LocalLinkAddresses(excludeIface string) ([]LinkAddressInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	out := []LinkAddressInfo{}
	for _, l := range links {
		name := l.Attrs().Name
		if name == excludeIface || name == "lo" {
			continue
		}
		mac := strings.ToLower(l.Attrs().HardwareAddr.String())
		if mac == "" {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("listing addresses on %s: %w", name, err)
		}
		for _, a := range addrs {
			if a.IP == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(a.IP.To4())
			if !ok || !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, LinkAddressInfo{Address: addr, MAC: mac, Interface: name})
		}
	}
	return out, nil
}

// LinkAddressInfo is one address this host answers for, with the MAC that
// answers for it.
type LinkAddressInfo struct {
	Address   netip.Addr
	MAC       string
	Interface string
}
