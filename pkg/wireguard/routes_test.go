//go:build linux

package wireguard

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestWgRuleHealthyIn(t *testing.T) {
	tests := []struct {
		name  string
		rules []netlink.Rule
		want  bool
	}{
		{
			name:  "healthy: table+priority+suppress0",
			rules: []netlink.Rule{wkRule()},
			want:  true,
		},
		{
			name:  "unhealthy: rule without suppress (sentinel -1)",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.SuppressPrefixlen = -1 })},
			want:  false,
		},
		{
			name:  "unhealthy: wrong priority",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.Priority = 100 })},
			want:  false,
		},
		{
			name:  "unhealthy: wrong table",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.Table = 254 })},
			want:  false,
		},
		{
			name:  "unhealthy: empty",
			rules: nil,
			want:  false,
		},
		{
			name: "healthy among unrelated rules",
			rules: []netlink.Rule{
				{Table: 255, Priority: 100, SuppressPrefixlen: -1},
				wkRule(),
				{Table: 254, Priority: 32766, SuppressPrefixlen: -1},
			},
			want: true,
		},
		{
			name: "unhealthy: stale duplicate with healthy rule",
			rules: []netlink.Rule{
				wkRule(),
				wkRule(func(r *netlink.Rule) { r.SuppressPrefixlen = -1 }),
			},
			want: false,
		},
		{
			name: "unhealthy: duplicate exact rules",
			rules: []netlink.Rule{
				wkRule(),
				wkRule(),
			},
			want: false,
		},
		{
			name:  "unhealthy: selector-limited mark rule",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.Mark = WKFwMark })},
			want:  false,
		},
		{
			name: "unhealthy: selector-limited source rule",
			rules: []netlink.Rule{
				wkRule(func(r *netlink.Rule) {
					r.Src = mustCIDR(t, "10.0.0.0/24")
				}),
			},
			want: false,
		},
		{
			name:  "unhealthy: selector-limited input interface rule",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.IifName = "eth0" })},
			want:  false,
		},
		{
			name:  "unhealthy: inverted rule",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.Invert = true })},
			want:  false,
		},
		{
			name:  "unhealthy: selector-limited port rule",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.Dport = netlink.NewRulePortRange(51820, 51820) })},
			want:  false,
		},
		{
			name:  "unhealthy: selector-limited uid rule",
			rules: []netlink.Rule{wkRule(func(r *netlink.Rule) { r.UIDRange = netlink.NewRuleUIDRange(1000, 1000) })},
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wgRuleHealthyIn(tt.rules); got != tt.want {
				t.Errorf("wgRuleHealthyIn() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWgTableRulePlan(t *testing.T) {
	tests := []struct {
		name        string
		rules       []netlink.Rule
		wantHealthy bool
		wantDelete  int
	}{
		{
			name:        "healthy exact rule needs no delete",
			rules:       []netlink.Rule{wkRule()},
			wantHealthy: true,
			wantDelete:  0,
		},
		{
			name:        "missing rule adds without delete",
			rules:       []netlink.Rule{{Table: 254, Priority: 200, SuppressPrefixlen: -1}},
			wantHealthy: false,
			wantDelete:  0,
		},
		{
			name:        "stale rule is deleted before add",
			rules:       []netlink.Rule{wkRule(func(r *netlink.Rule) { r.SuppressPrefixlen = -1 })},
			wantHealthy: false,
			wantDelete:  1,
		},
		{
			name: "healthy and stale duplicate are both replaced",
			rules: []netlink.Rule{
				wkRule(),
				wkRule(func(r *netlink.Rule) { r.SuppressPrefixlen = -1 }),
			},
			wantHealthy: false,
			wantDelete:  2,
		},
		{
			name: "duplicate exact rules are replaced",
			rules: []netlink.Rule{
				wkRule(),
				wkRule(),
			},
			wantHealthy: false,
			wantDelete:  2,
		},
		{
			name: "selector-limited rule is deleted but unrelated rules are ignored",
			rules: []netlink.Rule{
				{Table: 255, Priority: 100, SuppressPrefixlen: -1},
				wkRule(func(r *netlink.Rule) { r.IifName = "eth0" }),
				{Table: 254, Priority: 32766, SuppressPrefixlen: -1},
			},
			wantHealthy: false,
			wantDelete:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHealthy, gotDelete := wgTableRulePlan(tt.rules)
			if gotHealthy != tt.wantHealthy {
				t.Fatalf("wgTableRulePlan() healthy = %v, want %v", gotHealthy, tt.wantHealthy)
			}
			if len(gotDelete) != tt.wantDelete {
				t.Fatalf("wgTableRulePlan() delete len = %d, want %d", len(gotDelete), tt.wantDelete)
			}
			for _, r := range gotDelete {
				if r.Table != WKRouteTable || r.Priority != 200 {
					t.Fatalf("delete candidate = table %d priority %d, want table %d priority 200", r.Table, r.Priority, WKRouteTable)
				}
			}
		})
	}
}

func wkRule(mods ...func(*netlink.Rule)) netlink.Rule {
	r := netlink.NewRule()
	r.Table = WKRouteTable
	r.Priority = 200
	r.SuppressPrefixlen = 0
	for _, mod := range mods {
		mod(r)
	}
	return *r
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr %q: %v", cidr, err)
	}
	return ipNet
}
