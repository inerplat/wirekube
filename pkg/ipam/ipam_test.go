package ipam

import (
	"strings"
	"testing"
)

func TestNew_ValidCIDR(t *testing.T) {
	cases := []struct {
		cidr string
		size uint32
	}{
		{"10.100.0.0/24", 256},
		{"10.100.0.0/16", 65536},
		{"192.168.1.0/30", 4},
	}
	for _, tc := range cases {
		m, err := New(tc.cidr)
		if err != nil {
			t.Fatalf("New(%q) error: %v", tc.cidr, err)
		}
		if m.size != tc.size {
			t.Errorf("New(%q) size = %d, want %d", tc.cidr, m.size, tc.size)
		}
	}
}

func TestNew_InvalidCIDR(t *testing.T) {
	if _, err := New("not-a-cidr"); err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestAllocate_FirstAvailable(t *testing.T) {
	m, _ := New("10.100.0.0/24")

	// Empty slice → allocate first host address
	ip, err := m.Allocate(nil)
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}
	if ip != "10.100.0.1/32" {
		t.Errorf("Allocate() = %q, want %q", ip, "10.100.0.1/32")
	}
}

func TestAllocate_SkipsAllocated(t *testing.T) {
	m, _ := New("10.100.0.0/24")

	allocated := []string{"10.100.0.1/32", "10.100.0.2/32"}
	ip, err := m.Allocate(allocated)
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}
	if ip != "10.100.0.3/32" {
		t.Errorf("Allocate() = %q, want %q", ip, "10.100.0.3/32")
	}
}

func TestAllocate_PlainIPAllocated(t *testing.T) {
	m, _ := New("10.100.0.0/24")

	// Allocated list of plain IPs (not in CIDR notation)
	allocated := []string{"10.100.0.1", "10.100.0.2"}
	ip, err := m.Allocate(allocated)
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}
	if ip != "10.100.0.3/32" {
		t.Errorf("Allocate() = %q, want %q", ip, "10.100.0.3/32")
	}
}

func TestAllocate_Exhausted(t *testing.T) {
	// /30 → 4 addresses; excluding network(.0) and broadcast(.3), only .1 and .2 are usable
	m, _ := New("10.0.0.0/30")

	allocated := []string{"10.0.0.1/32", "10.0.0.2/32"}
	_, err := m.Allocate(allocated)
	if err == nil {
		t.Error("expected exhausted error, got nil")
	}
	if !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestAllocate_SkipsNetworkAndBroadcast(t *testing.T) {
	m, _ := New("10.0.0.0/30")

	// Even with nothing allocated, .0(network) and .3(broadcast) must not be allocated
	ip, err := m.Allocate(nil)
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}
	if ip != "10.0.0.1/32" {
		t.Errorf("Allocate() = %q, want %q", ip, "10.0.0.1/32")
	}
}

func TestContains(t *testing.T) {
	m, _ := New("10.100.0.0/24")

	cases := []struct {
		input string
		want  bool
	}{
		{"10.100.0.1/32", true},
		{"10.100.0.1", true},
		{"10.100.0.255", true},
		{"10.100.1.1", false},
		{"192.168.0.1", false},
		{"invalid", false},
	}
	for _, tc := range cases {
		got := m.Contains(tc.input)
		if got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestAllocate_Sequential(t *testing.T) {
	m, _ := New("10.100.0.0/24")

	var allocated []string
	// Allocate first 5 sequentially
	for i := 1; i <= 5; i++ {
		ip, err := m.Allocate(allocated)
		if err != nil {
			t.Fatalf("Allocate step %d error: %v", i, err)
		}
		allocated = append(allocated, ip)
	}

	// Must be .1~.5 in order
	expected := []string{
		"10.100.0.1/32", "10.100.0.2/32", "10.100.0.3/32",
		"10.100.0.4/32", "10.100.0.5/32",
	}
	for i, ip := range allocated {
		if ip != expected[i] {
			t.Errorf("allocated[%d] = %q, want %q", i, ip, expected[i])
		}
	}
}
