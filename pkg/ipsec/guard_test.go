package ipsec

import (
	"strings"
	"testing"
)

func TestGuardRuleDropsOnlyUnprotectedTrafficOutsideXFRMInterfaces(t *testing.T) {
	args := strings.Join(GuardRuleArgs(SelectorPair{"198.18.0.0/16", "10.88.1.0/24"}), " ")
	for _, want := range []string{
		"-s 198.18.0.0/16 -d 10.88.1.0/24",
		"! -o wkx+",
		"-m policy --dir out --pol none",
		"-j DROP",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("rule %q lacks %q", args, want)
		}
	}
}

func TestGuardDiffAddsBeforeItRemoves(t *testing.T) {
	keep := SelectorPair{"198.18.0.0/16", "10.88.1.0/24"}
	gone := SelectorPair{"198.18.0.0/16", "10.99.0.0/16"}
	added := SelectorPair{"10.42.0.0/16", "10.88.1.0/24"}
	add, remove := guardDiff([]string{keep.comment(), gone.comment()}, []SelectorPair{keep, added, keep})
	if len(add) != 1 || add[0] != added {
		t.Errorf("add = %v", add)
	}
	if len(remove) != 1 || remove[0] != gone.comment() {
		t.Errorf("remove = %v", remove)
	}
}

func TestParseGuardRules(t *testing.T) {
	out := `-N WIREKUBE-IPSEC-GUARD
-A WIREKUBE-IPSEC-GUARD -s 198.18.0.0/16 -d 10.88.1.0/24 ! -o wkx+ -m policy --dir out --pol none -m comment --comment "wk-ipsec:198.18.0.0/16>10.88.1.0/24" -j DROP
-A WIREKUBE-IPSEC-GUARD -j RETURN
`
	got := parseGuardRules(out)
	rule, ok := got["wk-ipsec:198.18.0.0/16>10.88.1.0/24"]
	if len(got) != 1 || !ok {
		t.Fatalf("got %v", got)
	}
	if rule[0] != "-s" || rule[len(rule)-1] != "DROP" {
		t.Errorf("rule args = %v; want the body after -A CHAIN", rule)
	}
	// The args are passed to iptables -D, which would look for a comment
	// with literal quotes and match nothing.
	for _, a := range rule {
		if strings.Contains(a, "\"") {
			t.Errorf("rule args keep the quotes iptables -S adds: %v", rule)
		}
	}
}
