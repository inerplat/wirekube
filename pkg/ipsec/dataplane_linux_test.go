//go:build linux

package ipsec

import (
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

// Run as: unshare -rn go test ./pkg/ipsec -run Rule
func TestRuleIsScopedToTheInputInterface(t *testing.T) {
	if os.Getenv("WIREKUBE_NETNS_TESTS") == "" {
		t.Skip("needs a throwaway network namespace; set WIREKUBE_NETNS_TESTS=1")
	}
	if err := EnsureRule(""); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRule("net1"); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRule("net1"); err != nil {
		t.Fatal(err)
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	var ours []netlink.Rule
	for _, r := range rules {
		if r.Table == RouteTable {
			ours = append(ours, r)
		}
	}
	if len(ours) != 1 || ours[0].IifName != "net1" {
		t.Fatalf("rules for table %#x = %+v", RouteTable, ours)
	}
}
