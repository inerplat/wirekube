package agent

import (
	"slices"
	"testing"

	"github.com/go-logr/logr"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/meship"
)

func meshWithCIDR(cidr string) *wirekubev1alpha1.WireKubeMesh {
	return &wirekubev1alpha1.WireKubeMesh{Spec: wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: cidr}}
}

func TestApplyMeshIPDerivesWhenNothingRecorded(t *testing.T) {
	want, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	spec := &wirekubev1alpha1.WireKubePeerSpec{}
	got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", "", spec)
	if got != want {
		t.Errorf("returned %q, want %q", got, want)
	}
	if !slices.Equal(spec.AllowedIPs, []string{want}) {
		t.Errorf("AllowedIPs = %v, want [%s]", spec.AllowedIPs, want)
	}
}

// TestApplyMeshIPHonoursTheRecordedAddress is the whole point of the recorded
// field: an allocator moved this peer off its hashed address, and the agent
// must not drag it back on the next upsert.
func TestApplyMeshIPHonoursTheRecordedAddress(t *testing.T) {
	const recorded = "198.18.18.200/32"
	hashed, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if hashed == recorded {
		t.Fatalf("test vector is useless: worker1 already hashes to %s", recorded)
	}
	spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{recorded, "10.42.0.0/24"}}
	got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", recorded, spec)
	if got != recorded {
		t.Errorf("returned %q, want the recorded %q", got, recorded)
	}
	if !slices.Equal(spec.AllowedIPs, []string{recorded, "10.42.0.0/24"}) {
		t.Errorf("AllowedIPs = %v, want the recorded address first and the gateway route kept", spec.AllowedIPs)
	}
}

// TestApplyMeshIPRestoresTheRecordedAddressToTheFront covers the peer whose
// AllowedIPs were reordered or cleared out of band.
func TestApplyMeshIPRestoresTheRecordedAddressToTheFront(t *testing.T) {
	const recorded = "198.18.18.200/32"
	spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{"10.42.0.0/24", recorded}}
	got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", recorded, spec)
	if got != recorded {
		t.Errorf("returned %q, want %q", got, recorded)
	}
	if !slices.Equal(spec.AllowedIPs, []string{recorded, "10.42.0.0/24"}) {
		t.Errorf("AllowedIPs = %v, want the recorded address moved to the front without duplicating it", spec.AllowedIPs)
	}
}

// TestApplyMeshIPRejectsAStaleRecord covers a record left behind by a mesh
// whose CIDR has since moved or shrunk. Honouring it would put the peer on an
// address the mesh does not route.
func TestApplyMeshIPRejectsAStaleRecord(t *testing.T) {
	want, err := meship.IPForName("worker1", "198.18.18.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, recorded := range []string{
		"10.9.9.9/32",       // outside the mesh CIDR
		"198.18.18.0/32",    // the network address
		"198.18.18.255/32",  // the broadcast address
		"198.18.18.0/24",    // not a host address
		"198.18.18.200",     // missing the prefix length
		"not-an-address",    //
		"fd00::1/128",       // IPv6
		"198.18.18.200/31",  // wrong prefix length
		"198.18.18.200/32 ", // trailing space
	} {
		spec := &wirekubev1alpha1.WireKubePeerSpec{}
		got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/24"), "worker1", recorded, spec)
		if got != want {
			t.Errorf("recorded %q: returned %q, want the re-derived %q", recorded, got, want)
		}
		if !slices.Equal(spec.AllowedIPs, []string{want}) {
			t.Errorf("recorded %q: AllowedIPs = %v, want [%s]", recorded, spec.AllowedIPs, want)
		}
	}
}

func TestApplyMeshIPLeavesManualPeersAloneWithoutAMeshCIDR(t *testing.T) {
	for _, mesh := range []*wirekubev1alpha1.WireKubeMesh{nil, meshWithCIDR("")} {
		spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{"192.168.1.0/24"}}
		if got := applyMeshIP(logr.Discard(), mesh, "worker1", "198.18.18.200/32", spec); got != "" {
			t.Errorf("returned %q, want no address", got)
		}
		if !slices.Equal(spec.AllowedIPs, []string{"192.168.1.0/24"}) {
			t.Errorf("AllowedIPs = %v, want the manual entry untouched", spec.AllowedIPs)
		}
	}
}

func TestApplyMeshIPReportsNothingForAnUnusableMeshCIDR(t *testing.T) {
	spec := &wirekubev1alpha1.WireKubePeerSpec{AllowedIPs: []string{"192.168.1.0/24"}}
	if got := applyMeshIP(logr.Discard(), meshWithCIDR("198.18.18.0/31"), "worker1", "", spec); got != "" {
		t.Errorf("returned %q, want no address", got)
	}
	if !slices.Equal(spec.AllowedIPs, []string{"192.168.1.0/24"}) {
		t.Errorf("AllowedIPs = %v, want them untouched", spec.AllowedIPs)
	}
}

func TestWithinMesh(t *testing.T) {
	for _, c := range []struct {
		address string
		want    bool
	}{
		{"198.18.18.1/32", true},
		{"198.18.18.254/32", true},
		{"198.18.18.0/32", false},
		{"198.18.18.255/32", false},
		{"198.18.19.1/32", false},
		{"198.18.18.1/24", false},
		{"", false},
	} {
		if got := withinMesh(c.address, "198.18.18.0/24"); got != c.want {
			t.Errorf("withinMesh(%q) = %v, want %v", c.address, got, c.want)
		}
	}
	if withinMesh("198.18.18.1/32", "not-a-cidr") {
		t.Error("withinMesh accepted an unparseable mesh CIDR")
	}
}
