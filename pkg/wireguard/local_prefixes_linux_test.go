//go:build linux

package wireguard

import (
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestLocalPrefixesFromRoutes(t *testing.T) {
	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	names := map[int]string{1: "eth0", 2: "wire_kube", 3: "wg0"}
	routes := []netlink.Route{
		{LinkIndex: 1, Scope: netlink.SCOPE_LINK, Dst: cidr("10.213.103.64/26")}, // physical: kept
		{LinkIndex: 2, Scope: netlink.SCOPE_LINK, Dst: cidr("198.18.0.0/16")},    // our tunnel: excluded
		{LinkIndex: 3, Scope: netlink.SCOPE_LINK, Dst: cidr("10.10.0.0/24")},     // other tunnel: kept on purpose
		{LinkIndex: 1, Scope: unix.RT_SCOPE_UNIVERSE, Dst: cidr("0.0.0.0/0")},    // not scope link
		{LinkIndex: 1, Scope: netlink.SCOPE_LINK, Dst: nil},                      // no destination
		{LinkIndex: 1, Scope: netlink.SCOPE_LINK, Dst: cidr("fd00::/64")},        // IPv6: skipped
	}
	got := localPrefixesFromRoutes(routes, names, "wire_kube")
	want := []netip.Prefix{netip.MustParsePrefix("10.213.103.64/26"), netip.MustParsePrefix("10.10.0.0/24")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
