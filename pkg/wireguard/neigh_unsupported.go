//go:build !linux

package wireguard

import "net/netip"

// NeighborEntry is one resolved neighbour: an address on an attached link and
// the hardware address that answers for it.
type NeighborEntry struct {
	Address   netip.Addr
	MAC       string
	Reachable bool
}

// LinkAddressInfo is one address this host answers for, with the MAC that
// answers for it.
type LinkAddressInfo struct {
	Address   netip.Addr
	MAC       string
	Interface string
}

// NeighborsOnLinks requires netlink; there is no neighbour table to read here.
func NeighborsOnLinks(_ string) ([]NeighborEntry, error) { return nil, nil }

// LocalLinkAddresses requires netlink; there are no attached links to report.
func LocalLinkAddresses(_ string) ([]LinkAddressInfo, error) { return nil, nil }
