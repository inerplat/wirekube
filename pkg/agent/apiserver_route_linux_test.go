//go:build linux

package agent

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestAPIServerIPUsesEffectiveRestConfigHost(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "192.0.2.1")
	t.Setenv("WIREKUBE_KUBE_APISERVER", "https://192.0.2.2:443")

	got := apiServerIP("https://10.0.0.10:6443")
	if got == nil || got.String() != "10.0.0.10" {
		t.Fatalf("apiServerIP() = %v, want 10.0.0.10", got)
	}
}

func TestAPIServerIPIgnoresHostnames(t *testing.T) {
	got := apiServerIP("https://cluster.example.com:443")
	if got != nil {
		t.Fatalf("apiServerIP() = %v, want nil for hostname apiserver", got)
	}
}

func TestAPIServerRulePlanRemovesStaleManagedRule(t *testing.T) {
	current := apiserverRule("10.0.0.10/32")
	stale := apiserverRule("192.0.2.10/32")
	unrelated := apiserverRule("203.0.113.10/32")
	unrelated.Priority = 32766

	hasCurrent, staleRules := apiserverRulePlan([]netlink.Rule{current, stale, unrelated}, net.ParseIP("10.0.0.10"))
	if !hasCurrent {
		t.Fatal("current apiserver rule was not detected")
	}
	if len(staleRules) != 1 || !staleRules[0].Dst.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("staleRules = %+v, want only 192.0.2.10/32", staleRules)
	}
}

func TestAPIServerRulePlanRemovesAllManagedRulesForHostnameAPIServer(t *testing.T) {
	rules := []netlink.Rule{
		apiserverRule("192.0.2.10/32"),
		apiserverRule("10.0.0.10/32"),
	}

	hasCurrent, staleRules := apiserverRulePlan(rules, nil)
	if hasCurrent {
		t.Fatal("hostname apiserver should not have a current IP rule")
	}
	if len(staleRules) != 2 {
		t.Fatalf("staleRules len = %d, want 2", len(staleRules))
	}
}

func TestIsManagedAPIServerRuleRejectsSelectorRule(t *testing.T) {
	rule := apiserverRule("192.0.2.10/32")
	rule.Mark = 1234
	if isManagedAPIServerRule(rule) {
		t.Fatal("marked rule should not be treated as managed apiserver rule")
	}
}

func apiserverRule(cidr string) netlink.Rule {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	r := *netlink.NewRule()
	r.Table = mainRouteTable
	r.Priority = apiServerRulePriority
	r.Dst = ipnet
	return r
}
