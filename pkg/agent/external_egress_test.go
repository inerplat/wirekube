package agent

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestExternalEgressPeerFromCRDefaults(t *testing.T) {
	ep := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{Name: "alice"},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			Egress: &wirekubev1alpha1.ExternalPeerEgressSpec{
				Enabled: true,
			},
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			Phase:           wirekubev1alpha1.ExternalPeerPhaseActive,
			IngressPeerName: "worker1",
			AssignedMeshIP:  "198.18.18.176/32",
		},
	}

	peer, ok, err := externalEgressPeerFromCR(ep, "worker1")
	if err != nil {
		t.Fatalf("externalEgressPeerFromCR: %v", err)
	}
	if !ok {
		t.Fatal("externalEgressPeerFromCR skipped active ingress peer")
	}
	if peer.name != "alice" {
		t.Fatalf("name = %q, want alice", peer.name)
	}
	if peer.sourceCIDR != "198.18.18.176/32" {
		t.Fatalf("sourceCIDR = %q, want 198.18.18.176/32", peer.sourceCIDR)
	}
	if !reflect.DeepEqual(peer.allowedCIDRs, []string{"0.0.0.0/0"}) {
		t.Fatalf("allowedCIDRs = %#v, want 0.0.0.0/0", peer.allowedCIDRs)
	}
	if !slices.Contains(peer.excludedCIDRs, "169.254.0.0/16") {
		t.Fatalf("excludedCIDRs missing link-local block: %#v", peer.excludedCIDRs)
	}
}

func TestExternalEgressPeerFromCRSkipsNonIngressNode(t *testing.T) {
	ep := &wirekubev1alpha1.WireKubeExternalPeer{
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			Egress: &wirekubev1alpha1.ExternalPeerEgressSpec{
				Enabled: true,
			},
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			Phase:           wirekubev1alpha1.ExternalPeerPhaseActive,
			IngressPeerName: "worker2",
			AssignedMeshIP:  "198.18.18.176/32",
		},
	}

	_, ok, err := externalEgressPeerFromCR(ep, "worker1")
	if err != nil {
		t.Fatalf("externalEgressPeerFromCR: %v", err)
	}
	if ok {
		t.Fatal("externalEgressPeerFromCR enabled egress on a non-ingress node")
	}
}

func TestExternalEgressPeerFromCRValidatesIPv4Policy(t *testing.T) {
	ep := &wirekubev1alpha1.WireKubeExternalPeer{
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			Egress: &wirekubev1alpha1.ExternalPeerEgressSpec{
				Enabled:      true,
				AllowedCIDRs: []string{"2001:db8::/32"},
			},
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			Phase:           wirekubev1alpha1.ExternalPeerPhaseActive,
			IngressPeerName: "worker1",
			AssignedMeshIP:  "198.18.18.176/32",
		},
	}

	_, _, err := externalEgressPeerFromCR(ep, "worker1")
	if err == nil {
		t.Fatal("externalEgressPeerFromCR accepted an IPv6 egress CIDR")
	}
}

func TestBuildExternalEgressIPTablesRules(t *testing.T) {
	peers := []externalEgressPeer{
		{
			name:          "alice",
			sourceCIDR:    "198.18.18.176/32",
			allowedCIDRs:  []string{"0.0.0.0/0"},
			excludedCIDRs: []string{"169.254.0.0/16"},
		},
	}

	rules := buildExternalEgressIPTablesRules(peers, "wire_kube", "eth0")
	wantRules := []externalEgressIPTablesRule{
		{
			table: "filter",
			chain: externalEgressFilterChain,
			args:  []string{"-i", "wire_kube", "-s", "198.18.18.176/32", "-o", "eth0", "-d", "169.254.0.0/16", "-j", "DROP"},
		},
		{
			table: "filter",
			chain: externalEgressFilterChain,
			args:  []string{"-i", "wire_kube", "-s", "198.18.18.176/32", "-o", "eth0", "-d", "0.0.0.0/0", "-j", "ACCEPT"},
		},
		{
			table: "filter",
			chain: externalEgressFilterChain,
			args:  []string{"-i", "eth0", "-o", "wire_kube", "-d", "198.18.18.176/32", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		},
		{
			table: "filter",
			chain: externalEgressFilterChain,
			args:  []string{"-i", "wire_kube", "-s", "198.18.18.176/32", "-o", "eth0", "-j", "DROP"},
		},
		{
			table: "nat",
			chain: externalEgressNATChain,
			args:  []string{"-s", "198.18.18.176/32", "-o", "eth0", "-d", "0.0.0.0/0", "-j", "MASQUERADE"},
		},
	}
	if !reflect.DeepEqual(rules, wantRules) {
		t.Fatalf("rules = %#v, want %#v", rules, wantRules)
	}
}

func TestExternalEgressRulesKeyIsOrderStable(t *testing.T) {
	a := []externalEgressIPTablesRule{
		{table: "nat", chain: externalEgressNATChain, args: []string{"-s", "198.18.18.2/32", "-j", "MASQUERADE"}},
		{table: "filter", chain: externalEgressFilterChain, args: []string{"-s", "198.18.18.2/32", "-j", "ACCEPT"}},
	}
	b := []externalEgressIPTablesRule{
		a[1],
		a[0],
	}
	if externalEgressRulesKey(a) != externalEgressRulesKey(b) {
		t.Fatal("externalEgressRulesKey changed when rule order changed")
	}
}

func TestCleanupExternalEgressRulesFlushesExistingChainsAfterRestart(t *testing.T) {
	originalRun := runExternalEgressIPTables
	defer func() {
		runExternalEgressIPTables = originalRun
	}()

	var calls []string
	runExternalEgressIPTables = func(args ...string) (string, error) {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		switch {
		case strings.Contains(call, "-S "+externalEgressFilterChain),
			strings.Contains(call, "-S "+externalEgressNATChain):
			return "", nil
		case strings.Contains(call, "-N "+externalEgressFilterChain),
			strings.Contains(call, "-N "+externalEgressNATChain):
			return "Chain already exists", errors.New("exists")
		default:
			return "", nil
		}
	}

	a := &Agent{}
	if err := a.cleanupExternalEgressRules(); err != nil {
		t.Fatalf("cleanupExternalEgressRules: %v", err)
	}

	for _, want := range []string{
		"-t filter -F " + externalEgressFilterChain,
		"-t nat -F " + externalEgressNATChain,
	} {
		if !slices.Contains(calls, want) {
			t.Fatalf("iptables calls missing %q: %#v", want, calls)
		}
	}
	if a.extEgressState == nil {
		t.Fatal("cleanupExternalEgressRules did not initialize state after flushing existing chains")
	}
	if a.extEgressState.lastKey != "" {
		t.Fatalf("lastKey = %q, want empty", a.extEgressState.lastKey)
	}
}
