//go:build linux

package sitegw

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestFirewallDropsTransitThatSkipsTheTenantLeg(t *testing.T) {
	var transit bool
	for _, r := range FirewallRules("net1")[FirewallForwardChain] {
		if strings.Join(r, " ") == "! -i net1 ! -o net1 -j DROP" {
			transit = true
		}
	}
	if !transit {
		t.Fatal("no rule drops forwarded traffic that does not touch the tenant leg")
	}
}

// Run as: WIREKUBE_NETNS_TESTS=1 unshare -rn go test ./pkg/sitegw -run Uplink
func TestUplinkAddressesReadsIPv4(t *testing.T) {
	if os.Getenv("WIREKUBE_NETNS_TESTS") == "" {
		t.Skip("needs a throwaway network namespace; set WIREKUBE_NETNS_TESTS=1")
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	got, err := UplinkAddresses("lo")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("addresses = %v, %v", got, err)
	}
}
