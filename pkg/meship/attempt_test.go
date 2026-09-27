package meship

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// liveMesh and livePeers are addresses WireKube has already assigned in a
// running mesh. Attempt 0 has to keep reproducing them exactly: an agent that
// derived a different first candidate would move a peer that is up and
// carrying traffic.
const liveMesh = "198.18.18.0/24"

var livePeers = map[string]string{
	"master":  "198.18.18.74/32",
	"worker1": "198.18.18.83/32",
	"worker2": "198.18.18.180/32",
	"worker3": "198.18.18.23/32",
	"worker4": "198.18.18.120/32",
	"worker5": "198.18.18.217/32",
	"worker6": "198.18.18.60/32",
	"worker7": "198.18.18.157/32",
	"worker8": "198.18.18.226/32",
}

func TestAttemptZeroPinsLiveAddresses(t *testing.T) {
	for name, want := range livePeers {
		got, err := IPForNameAttempt(name, liveMesh, 0)
		if err != nil {
			t.Fatalf("IPForNameAttempt(%q, 0): %v", name, err)
		}
		if got != want {
			t.Errorf("IPForNameAttempt(%q, 0) = %s, want %s", name, got, want)
		}
	}
}

// TestAttemptZeroMatchesIPForName covers the names the live mesh does not,
// across every CIDR width the allocator accepts.
func TestAttemptZeroMatchesIPForName(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/30", "10.0.0.0/29", "192.168.7.0/24", "100.64.0.0/10", "10.0.0.0/8"} {
		for i := range 300 {
			name := fmt.Sprintf("peer-%d", i)
			want, err := IPForName(name, cidr)
			if err != nil {
				t.Fatalf("IPForName(%q, %q): %v", name, cidr, err)
			}
			got, err := IPForNameAttempt(name, cidr, 0)
			if err != nil {
				t.Fatalf("IPForNameAttempt(%q, %q, 0): %v", name, cidr, err)
			}
			if got != want {
				t.Fatalf("attempt 0 for %q in %s = %s, want %s", name, cidr, got, want)
			}
		}
	}
}

// TestAttemptsVisitEveryAddressOnce is the property the probing allocator
// depends on: a caller that keeps incrementing the attempt never re-probes an
// address it has already ruled out, and reaches every free one.
func TestAttemptsVisitEveryAddressOnce(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/30", "10.0.0.0/29", "10.1.2.0/28", "192.168.7.0/24"} {
		capacity, err := Capacity(cidr)
		if err != nil {
			t.Fatalf("Capacity(%q): %v", cidr, err)
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", cidr, err)
		}
		broadcast := broadcastOf(ipnet)
		for _, name := range []string{"alice", "bob", "worker1", ""} {
			seen := make(map[string]int, capacity)
			for attempt := range capacity {
				got, err := IPForNameAttempt(name, cidr, attempt)
				if err != nil {
					t.Fatalf("IPForNameAttempt(%q, %q, %d): %v", name, cidr, attempt, err)
				}
				if prev, ok := seen[got]; ok {
					t.Fatalf("%q in %s: attempts %d and %d both → %s", name, cidr, prev, attempt, got)
				}
				seen[got] = attempt

				ip := net.ParseIP(strings.TrimSuffix(got, "/32"))
				if ip == nil || !ipnet.Contains(ip) {
					t.Fatalf("%q in %s attempt %d: %s outside the CIDR", name, cidr, attempt, got)
				}
				if ip.Equal(ipnet.IP) {
					t.Fatalf("%q in %s attempt %d: network address %s", name, cidr, attempt, got)
				}
				if ip.Equal(broadcast) {
					t.Fatalf("%q in %s attempt %d: broadcast address %s", name, cidr, attempt, got)
				}
			}
			if len(seen) != capacity {
				t.Fatalf("%q in %s: covered %d of %d addresses", name, cidr, len(seen), capacity)
			}
		}
	}
}

// TestAttemptsWrapAtCapacity documents what a caller past the capacity sees,
// so an unbounded retry loop degrades into re-probing rather than escaping the
// CIDR.
func TestAttemptsWrapAtCapacity(t *testing.T) {
	const cidr = "192.168.7.0/24"
	capacity, err := Capacity(cidr)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []int{0, 1, 37, capacity - 1} {
		want, err := IPForNameAttempt("alice", cidr, attempt)
		if err != nil {
			t.Fatal(err)
		}
		got, err := IPForNameAttempt("alice", cidr, attempt+capacity)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("attempt %d wrapped to %s, want %s", attempt+capacity, got, want)
		}
	}
}

// TestLargeAttemptDoesNotOverflow guards the uint64 widening in the walk: a
// 32-bit multiply of stride by attempt would wrap and land off the sequence.
func TestLargeAttemptDoesNotOverflow(t *testing.T) {
	const cidr = "100.64.0.0/10"
	capacity, err := Capacity(cidr)
	if err != nil {
		t.Fatal(err)
	}
	_, ipnet, _ := net.ParseCIDR(cidr)
	for _, attempt := range []int{capacity - 1, capacity, 1 << 30, 1<<31 - 1} {
		got, err := IPForNameAttempt("alice", cidr, attempt)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		ip := net.ParseIP(strings.TrimSuffix(got, "/32"))
		if ip == nil || !ipnet.Contains(ip) {
			t.Fatalf("attempt %d produced %s, outside %s", attempt, got, cidr)
		}
		want, err := IPForNameAttempt("alice", cidr, attempt%capacity)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("attempt %d = %s, want the wrapped %s", attempt, got, want)
		}
	}
}

// TestCollidingNamesDivergeOnRetry is why the stride is hashed separately. If
// both names walked with the same stride they would collide on every attempt,
// and the loser would probe the whole range behind the winner.
func TestCollidingNamesDivergeOnRetry(t *testing.T) {
	const cidr = "192.168.7.0/24"
	first, second, ok := collidingPair(t, cidr)
	if !ok {
		t.Skip("no colliding pair found in the sampled names")
	}
	a, err := IPForNameAttempt(first, cidr, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := IPForNameAttempt(second, cidr, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("%q and %q collide at attempt 0 and again at attempt 1 (%s)", first, second, a)
	}
}

func TestIPForNameAttemptRejectsNegative(t *testing.T) {
	if _, err := IPForNameAttempt("alice", "100.64.0.0/10", -1); err == nil {
		t.Fatal("expected an error for a negative attempt")
	}
}

func TestIPForNameAttemptRejectsUnusableCIDRs(t *testing.T) {
	for _, cidr := range []string{"", "not-a-cidr", "fd00::/64", "10.0.0.0/31", "10.0.0.0/32"} {
		if _, err := IPForNameAttempt("alice", cidr, 3); err == nil {
			t.Errorf("IPForNameAttempt accepted mesh CIDR %q", cidr)
		}
		if _, err := Capacity(cidr); err == nil {
			t.Errorf("Capacity accepted mesh CIDR %q", cidr)
		}
	}
}

func TestCapacity(t *testing.T) {
	for cidr, want := range map[string]int{
		"10.0.0.0/30":    2,
		"10.0.0.0/24":    254,
		"100.64.0.0/10":  4194302,
		"198.18.18.0/24": 254,
	} {
		got, err := Capacity(cidr)
		if err != nil {
			t.Fatalf("Capacity(%q): %v", cidr, err)
		}
		if got != want {
			t.Errorf("Capacity(%q) = %d, want %d", cidr, got, want)
		}
	}
}

// collidingPair finds two names that hash to the same attempt-0 address.
func collidingPair(t *testing.T, cidr string) (string, string, bool) {
	t.Helper()
	seen := make(map[string]string)
	for i := range 4096 {
		name := fmt.Sprintf("node-%d", i)
		got, err := IPForNameAttempt(name, cidr, 0)
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := seen[got]; ok {
			return prev, name, true
		}
		seen[got] = name
	}
	return "", "", false
}

func broadcastOf(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	mask := net.IP(ipnet.Mask).To4()
	out := make(net.IP, 4)
	for i := range out {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

func TestContains(t *testing.T) {
	for _, c := range []struct {
		address string
		want    bool
	}{
		{"198.18.18.1/32", true},
		{"198.18.18.254/32", true},
		{"198.18.18.0/32", false},   // the network address
		{"198.18.18.255/32", false}, // the broadcast address
		{"198.18.19.1/32", false},   // outside
		{"198.18.18.1/24", false},   // not a host address
		{"198.18.18.1", false},      // no prefix length
		{"198.18.18.1/32 ", false},  // trailing space
		{"fd00::1/128", false},      // IPv6
		{"", false},
	} {
		if got := Contains(c.address, liveMesh); got != c.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", c.address, liveMesh, got, c.want)
		}
	}
	for _, meshCIDR := range []string{"", "not-a-cidr", "fd00::/64", "10.0.0.0/31"} {
		if Contains("198.18.18.1/32", meshCIDR) {
			t.Errorf("Contains accepted mesh CIDR %q", meshCIDR)
		}
	}
}

// TestContainsAcceptsEveryAddressTheWalkProduces is the invariant that ties
// the two halves together: a recorded address is rejected as stale only when
// the walk could not have produced it.
func TestContainsAcceptsEveryAddressTheWalkProduces(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/30", "10.1.2.0/28", "192.168.7.0/24", "172.16.0.0/20"} {
		capacity, err := Capacity(cidr)
		if err != nil {
			t.Fatal(err)
		}
		for attempt := range capacity {
			address, err := IPForNameAttempt("alice", cidr, attempt)
			if err != nil {
				t.Fatal(err)
			}
			if !Contains(address, cidr) {
				t.Fatalf("attempt %d in %s produced %s, which Contains rejects", attempt, cidr, address)
			}
		}
	}
}
