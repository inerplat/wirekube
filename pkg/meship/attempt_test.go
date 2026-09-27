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

// TestCandidateWalkVectors pins the whole walk, not just its first step.
//
// The property tests below prove the walk is a permutation, which any coprime
// stride satisfies, so they stay green if the stride changes. The stride is
// contract: idlectl reproduces this package to claim a worker's address before
// the node exists, and a change here that its suite does not catch leaves the
// two probing different candidates for the same name, which shows up as a
// wasted claim rather than as a failure.
func TestCandidateWalkVectors(t *testing.T) {
	for _, c := range []struct {
		meshCIDR string
		name     string
		attempt  int
		want     string
	}{
		{"198.18.18.0/24", "master", 0, "198.18.18.74/32"},
		{"198.18.18.0/24", "master", 1, "198.18.18.55/32"},
		{"198.18.18.0/24", "master", 2, "198.18.18.36/32"},
		{"198.18.18.0/24", "master", 3, "198.18.18.17/32"},
		{"198.18.18.0/24", "master", 7, "198.18.18.195/32"},
		{"198.18.18.0/24", "master", 31, "198.18.18.247/32"},
		{"198.18.18.0/24", "master", 32, "198.18.18.228/32"},
		{"198.18.18.0/24", "master", 253, "198.18.18.93/32"},
		{"198.18.18.0/24", "master", 254, "198.18.18.74/32"},
		{"198.18.18.0/24", "master", 1000, "198.18.18.124/32"},
		{"198.18.18.0/24", "worker1", 0, "198.18.18.83/32"},
		{"198.18.18.0/24", "worker1", 1, "198.18.18.138/32"},
		{"198.18.18.0/24", "worker1", 2, "198.18.18.193/32"},
		{"198.18.18.0/24", "worker1", 3, "198.18.18.248/32"},
		{"198.18.18.0/24", "worker1", 7, "198.18.18.214/32"},
		{"198.18.18.0/24", "worker1", 31, "198.18.18.10/32"},
		{"198.18.18.0/24", "worker1", 32, "198.18.18.65/32"},
		{"198.18.18.0/24", "worker1", 253, "198.18.18.28/32"},
		{"198.18.18.0/24", "worker1", 254, "198.18.18.83/32"},
		{"198.18.18.0/24", "worker1", 1000, "198.18.18.219/32"},
		{"198.18.18.0/24", "node-a", 0, "198.18.18.52/32"},
		{"198.18.18.0/24", "node-a", 1, "198.18.18.223/32"},
		{"198.18.18.0/24", "node-a", 2, "198.18.18.140/32"},
		{"198.18.18.0/24", "node-a", 3, "198.18.18.57/32"},
		{"198.18.18.0/24", "node-a", 7, "198.18.18.233/32"},
		{"198.18.18.0/24", "node-a", 31, "198.18.18.19/32"},
		{"198.18.18.0/24", "node-a", 32, "198.18.18.190/32"},
		{"198.18.18.0/24", "node-a", 253, "198.18.18.135/32"},
		{"198.18.18.0/24", "node-a", 254, "198.18.18.52/32"},
		{"198.18.18.0/24", "node-a", 1000, "198.18.18.110/32"},
		{"198.18.18.0/24", "", 0, "198.18.18.132/32"},
		{"198.18.18.0/24", "", 1, "198.18.18.119/32"},
		{"198.18.18.0/24", "", 2, "198.18.18.106/32"},
		{"198.18.18.0/24", "", 3, "198.18.18.93/32"},
		{"198.18.18.0/24", "", 7, "198.18.18.41/32"},
		{"198.18.18.0/24", "", 31, "198.18.18.237/32"},
		{"198.18.18.0/24", "", 32, "198.18.18.224/32"},
		{"198.18.18.0/24", "", 253, "198.18.18.145/32"},
		{"198.18.18.0/24", "", 254, "198.18.18.132/32"},
		{"198.18.18.0/24", "", 1000, "198.18.18.86/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 0, "198.18.18.231/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 1, "198.18.18.212/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 2, "198.18.18.193/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 3, "198.18.18.174/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 7, "198.18.18.98/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 31, "198.18.18.150/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 32, "198.18.18.131/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 253, "198.18.18.250/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 254, "198.18.18.231/32"},
		{"198.18.18.0/24", "a-very-long-node-name-that-goes-on", 1000, "198.18.18.27/32"},
		{"100.64.0.0/10", "master", 0, "100.77.197.136/32"},
		{"100.64.0.0/10", "master", 1, "100.102.213.161/32"},
		{"100.64.0.0/10", "master", 2, "100.127.229.186/32"},
		{"100.64.0.0/10", "master", 3, "100.88.245.213/32"},
		{"100.64.0.0/10", "master", 7, "100.125.54.59/32"},
		{"100.64.0.0/10", "master", 31, "100.86.184.167/32"},
		{"100.64.0.0/10", "master", 32, "100.111.200.192/32"},
		{"100.64.0.0/10", "master", 253, "100.82.175.3/32"},
		{"100.64.0.0/10", "master", 254, "100.107.191.28/32"},
		{"100.64.0.0/10", "master", 1000, "100.116.170.62/32"},
		{"100.64.0.0/10", "worker1", 0, "100.97.55.95/32"},
		{"100.64.0.0/10", "worker1", 1, "100.100.75.24/32"},
		{"100.64.0.0/10", "worker1", 2, "100.103.94.209/32"},
		{"100.64.0.0/10", "worker1", 3, "100.106.114.138/32"},
		{"100.64.0.0/10", "worker1", 7, "100.118.193.110/32"},
		{"100.64.0.0/10", "worker1", 31, "100.64.154.202/32"},
		{"100.64.0.0/10", "worker1", 32, "100.67.174.131/32"},
		{"100.64.0.0/10", "worker1", 253, "100.107.181.76/32"},
		{"100.64.0.0/10", "worker1", 254, "100.110.201.5/32"},
		{"100.64.0.0/10", "worker1", 1000, "100.102.66.103/32"},
		{"100.64.0.0/10", "node-a", 0, "100.67.181.186/32"},
		{"100.64.0.0/10", "node-a", 1, "100.115.179.213/32"},
		{"100.64.0.0/10", "node-a", 2, "100.99.177.242/32"},
		{"100.64.0.0/10", "node-a", 3, "100.83.176.15/32"},
		{"100.64.0.0/10", "node-a", 7, "100.83.168.129/32"},
		{"100.64.0.0/10", "node-a", 31, "100.83.123.45/32"},
		{"100.64.0.0/10", "node-a", 32, "100.67.121.74/32"},
		{"100.64.0.0/10", "node-a", 253, "100.113.215.227/32"},
		{"100.64.0.0/10", "node-a", 254, "100.97.214.0/32"},
		{"100.64.0.0/10", "node-a", 1000, "100.124.85.12/32"},
		{"100.64.0.0/10", "", 0, "100.92.161.206/32"},
		{"100.64.0.0/10", "", 1, "100.81.176.99/32"},
		{"100.64.0.0/10", "", 2, "100.70.190.248/32"},
		{"100.64.0.0/10", "", 3, "100.123.205.139/32"},
		{"100.64.0.0/10", "", 7, "100.80.7.223/32"},
		{"100.64.0.0/10", "", 31, "100.73.101.207/32"},
		{"100.64.0.0/10", "", 32, "100.126.116.98/32"},
		{"100.64.0.0/10", "", 253, "100.76.10.185/32"},
		{"100.64.0.0/10", "", 254, "100.65.25.78/32"},
		{"100.64.0.0/10", "", 1000, "100.93.150.128/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 0, "100.118.150.223/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 1, "100.123.215.250/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 2, "100.65.25.23/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 3, "100.70.90.50/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 7, "100.91.94.158/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 31, "100.89.121.42/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 32, "100.94.186.69/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 253, "100.103.238.184/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 254, "100.109.47.211/32"},
		{"100.64.0.0/10", "a-very-long-node-name-that-goes-on", 1000, "100.124.232.251/32"},
		{"10.0.0.0/30", "master", 0, "10.0.0.2/32"},
		{"10.0.0.0/30", "master", 1, "10.0.0.1/32"},
		{"10.0.0.0/30", "master", 2, "10.0.0.2/32"},
		{"10.0.0.0/30", "master", 3, "10.0.0.1/32"},
		{"10.0.0.0/30", "master", 7, "10.0.0.1/32"},
		{"10.0.0.0/30", "master", 31, "10.0.0.1/32"},
		{"10.0.0.0/30", "master", 32, "10.0.0.2/32"},
		{"10.0.0.0/30", "master", 253, "10.0.0.1/32"},
		{"10.0.0.0/30", "master", 254, "10.0.0.2/32"},
		{"10.0.0.0/30", "master", 1000, "10.0.0.2/32"},
		{"10.0.0.0/30", "worker1", 0, "10.0.0.1/32"},
		{"10.0.0.0/30", "worker1", 1, "10.0.0.2/32"},
		{"10.0.0.0/30", "worker1", 2, "10.0.0.1/32"},
		{"10.0.0.0/30", "worker1", 3, "10.0.0.2/32"},
		{"10.0.0.0/30", "worker1", 7, "10.0.0.2/32"},
		{"10.0.0.0/30", "worker1", 31, "10.0.0.2/32"},
		{"10.0.0.0/30", "worker1", 32, "10.0.0.1/32"},
		{"10.0.0.0/30", "worker1", 253, "10.0.0.2/32"},
		{"10.0.0.0/30", "worker1", 254, "10.0.0.1/32"},
		{"10.0.0.0/30", "worker1", 1000, "10.0.0.1/32"},
		{"10.0.0.0/30", "node-a", 0, "10.0.0.2/32"},
		{"10.0.0.0/30", "node-a", 1, "10.0.0.1/32"},
		{"10.0.0.0/30", "node-a", 2, "10.0.0.2/32"},
		{"10.0.0.0/30", "node-a", 3, "10.0.0.1/32"},
		{"10.0.0.0/30", "node-a", 7, "10.0.0.1/32"},
		{"10.0.0.0/30", "node-a", 31, "10.0.0.1/32"},
		{"10.0.0.0/30", "node-a", 32, "10.0.0.2/32"},
		{"10.0.0.0/30", "node-a", 253, "10.0.0.1/32"},
		{"10.0.0.0/30", "node-a", 254, "10.0.0.2/32"},
		{"10.0.0.0/30", "node-a", 1000, "10.0.0.2/32"},
		{"10.0.0.0/30", "", 0, "10.0.0.2/32"},
		{"10.0.0.0/30", "", 1, "10.0.0.1/32"},
		{"10.0.0.0/30", "", 2, "10.0.0.2/32"},
		{"10.0.0.0/30", "", 3, "10.0.0.1/32"},
		{"10.0.0.0/30", "", 7, "10.0.0.1/32"},
		{"10.0.0.0/30", "", 31, "10.0.0.1/32"},
		{"10.0.0.0/30", "", 32, "10.0.0.2/32"},
		{"10.0.0.0/30", "", 253, "10.0.0.1/32"},
		{"10.0.0.0/30", "", 254, "10.0.0.2/32"},
		{"10.0.0.0/30", "", 1000, "10.0.0.2/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 0, "10.0.0.1/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 1, "10.0.0.2/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 2, "10.0.0.1/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 3, "10.0.0.2/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 7, "10.0.0.2/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 31, "10.0.0.2/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 32, "10.0.0.1/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 253, "10.0.0.2/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 254, "10.0.0.1/32"},
		{"10.0.0.0/30", "a-very-long-node-name-that-goes-on", 1000, "10.0.0.1/32"},
		{"172.16.0.0/20", "master", 0, "172.16.4.22/32"},
		{"172.16.0.0/20", "master", 1, "172.16.11.27/32"},
		{"172.16.0.0/20", "master", 2, "172.16.2.34/32"},
		{"172.16.0.0/20", "master", 3, "172.16.9.39/32"},
		{"172.16.0.0/20", "master", 7, "172.16.5.63/32"},
		{"172.16.0.0/20", "master", 31, "172.16.13.203/32"},
		{"172.16.0.0/20", "master", 32, "172.16.4.210/32"},
		{"172.16.0.0/20", "master", 253, "172.16.4.229/32"},
		{"172.16.0.0/20", "master", 254, "172.16.11.234/32"},
		{"172.16.0.0/20", "master", 1000, "172.16.3.12/32"},
		{"172.16.0.0/20", "worker1", 0, "172.16.10.159/32"},
		{"172.16.0.0/20", "worker1", 1, "172.16.2.164/32"},
		{"172.16.0.0/20", "worker1", 2, "172.16.10.167/32"},
		{"172.16.0.0/20", "worker1", 3, "172.16.2.172/32"},
		{"172.16.0.0/20", "worker1", 7, "172.16.2.188/32"},
		{"172.16.0.0/20", "worker1", 31, "172.16.3.28/32"},
		{"172.16.0.0/20", "worker1", 32, "172.16.11.31/32"},
		{"172.16.0.0/20", "worker1", 253, "172.16.6.148/32"},
		{"172.16.0.0/20", "worker1", 254, "172.16.14.151/32"},
		{"172.16.0.0/20", "worker1", 1000, "172.16.10.65/32"},
		{"172.16.0.0/20", "node-a", 0, "172.16.14.28/32"},
		{"172.16.0.0/20", "node-a", 1, "172.16.0.131/32"},
		{"172.16.0.0/20", "node-a", 2, "172.16.2.232/32"},
		{"172.16.0.0/20", "node-a", 3, "172.16.5.77/32"},
		{"172.16.0.0/20", "node-a", 7, "172.16.14.225/32"},
		{"172.16.0.0/20", "node-a", 31, "172.16.8.97/32"},
		{"172.16.0.0/20", "node-a", 32, "172.16.10.198/32"},
		{"172.16.0.0/20", "node-a", 253, "172.16.12.57/32"},
		{"172.16.0.0/20", "node-a", 254, "172.16.14.158/32"},
		{"172.16.0.0/20", "node-a", 1000, "172.16.9.208/32"},
		{"172.16.0.0/20", "", 0, "172.16.3.94/32"},
		{"172.16.0.0/20", "", 1, "172.16.9.167/32"},
		{"172.16.0.0/20", "", 2, "172.16.15.240/32"},
		{"172.16.0.0/20", "", 3, "172.16.6.59/32"},
		{"172.16.0.0/20", "", 7, "172.16.15.97/32"},
		{"172.16.0.0/20", "", 31, "172.16.6.77/32"},
		{"172.16.0.0/20", "", 32, "172.16.12.150/32"},
		{"172.16.0.0/20", "", 253, "172.16.10.73/32"},
		{"172.16.0.0/20", "", 254, "172.16.0.148/32"},
		{"172.16.0.0/20", "", 1000, "172.16.3.152/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 0, "172.16.5.55/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 1, "172.16.14.10/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 2, "172.16.6.223/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 3, "172.16.15.178/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 7, "172.16.3.4/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 31, "172.16.6.230/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 32, "172.16.15.185/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 253, "172.16.14.212/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 254, "172.16.7.169/32"},
		{"172.16.0.0/20", "a-very-long-node-name-that-goes-on", 1000, "172.16.1.191/32"},
	} {
		got, err := IPForNameAttempt(c.name, c.meshCIDR, c.attempt)
		if err != nil {
			t.Fatalf("IPForNameAttempt(%q, %q, %d): %v", c.name, c.meshCIDR, c.attempt, err)
		}
		if got != c.want {
			t.Errorf("IPForNameAttempt(%q, %q, %d) = %s, want %s", c.name, c.meshCIDR, c.attempt, got, c.want)
		}
	}
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
