//go:build !linux

package wireguard

import "net/netip"

// LocalLinkPrefixes requires netlink; on non-linux there is no dataplane and
// no local reachability to consult.
func LocalLinkPrefixes(_ string) []netip.Prefix { return nil }
