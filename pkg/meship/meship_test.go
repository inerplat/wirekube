package meship

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestIPForNameDeterministic(t *testing.T) {
	const cidr = "100.64.0.0/10"
	const name = "alice"

	first, err := IPForName(name, cidr)
	if err != nil {
		t.Fatalf("IPForName: %v", err)
	}
	for i := range 50 {
		got, err := IPForName(name, cidr)
		if err != nil {
			t.Fatalf("IPForName iter %d: %v", i, err)
		}
		if got != first {
			t.Fatalf("non-deterministic: iter %d returned %q, first was %q", i, got, first)
		}
	}
}

func TestIPForNameDistinctNames(t *testing.T) {
	const cidr = "100.64.0.0/10"
	seen := make(map[string]string, 100)
	for i := range 100 {
		name := fmt.Sprintf("peer-%d", i)
		got, err := IPForName(name, cidr)
		if err != nil {
			t.Fatalf("IPForName(%q): %v", name, err)
		}
		if prev, ok := seen[got]; ok {
			t.Fatalf("collision: %q and %q both → %s", prev, name, got)
		}
		seen[name] = got
	}
}

func TestIPForNameInvalidCIDR(t *testing.T) {
	cases := []string{
		"",
		"not-a-cidr",
		"100.64.0.0",        // missing prefix
		"300.0.0.0/10",      // bad octet
		"100.64.0.0/badnum", // bad mask
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := IPForName("alice", c); err == nil {
				t.Fatalf("expected error for invalid CIDR %q", c)
			}
		})
	}
}

func TestIPForNameRejectsIPv6(t *testing.T) {
	if _, err := IPForName("alice", "fd00::/64"); err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
}

func TestIPForNameRejectsTooSmall(t *testing.T) {
	// /31 has only 2 addresses; /32 only 1. /30 is the smallest accepted
	// (size == 4: net, two hosts, broadcast).
	cases := []struct {
		cidr   string
		reject bool
	}{
		{"10.0.0.0/31", true},
		{"10.0.0.0/32", true},
		{"10.0.0.0/30", false},
		{"10.0.0.0/24", false},
	}
	for _, c := range cases {
		t.Run(c.cidr, func(t *testing.T) {
			_, err := IPForName("alice", c.cidr)
			if c.reject && err == nil {
				t.Fatalf("expected error for %q", c.cidr)
			}
			if !c.reject && err != nil {
				t.Fatalf("unexpected error for %q: %v", c.cidr, err)
			}
		})
	}
}

func TestIPForNameStaysWithinCIDR(t *testing.T) {
	const cidr = "100.64.0.0/10"
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	for i := range 200 {
		name := fmt.Sprintf("name-%d", i)
		got, err := IPForName(name, cidr)
		if err != nil {
			t.Fatalf("IPForName(%q): %v", name, err)
		}
		if !strings.HasSuffix(got, "/32") {
			t.Fatalf("expected /32, got %q", got)
		}
		ipStr := strings.TrimSuffix(got, "/32")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("parse failed: %q", got)
		}
		if !ipnet.Contains(ip) {
			t.Fatalf("IP %s outside %s", got, cidr)
		}
		// Also confirm we didn't pick the network or broadcast address.
		if ip.Equal(ipnet.IP) {
			t.Fatalf("name %q produced network address %s", name, got)
		}
	}
}
