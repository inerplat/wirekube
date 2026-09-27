package meshalloc

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestClaimWireFormat pins the half of this package that is a protocol rather
// than an implementation.
//
// The Lease name *is* the arbitration: two claimants that compute different
// names for one address do not contend, they both succeed, and the mesh ends
// up with the duplicate the allocator exists to prevent. Idlectl claims
// alongside the agent for workers it enrols and cannot import this package, so
// it reproduces these literals; changing one side alone breaks the
// arbitration silently, with no build error and no failing request.
func TestClaimWireFormat(t *testing.T) {
	for _, c := range []struct{ mesh, address, want string }{
		{"default", "198.18.18.74/32", "wirekube-default-198-18-18-74"},
		{"default", "198.18.18.74", "wirekube-default-198-18-18-74"},
		{"prod", "10.0.0.1/32", "wirekube-prod-10-0-0-1"},
	} {
		if got := ClaimName(c.mesh, c.address); got != c.want {
			t.Errorf("ClaimName(%q, %q) = %q, want %q", c.mesh, c.address, got, c.want)
		}
	}

	for name, want := range map[string]string{
		"MeshLabel":         "wirekube.io/mesh",
		"PeerLabel":         "wirekube.io/peer-name",
		"ClaimLabel":        "wirekube.io/claim",
		"ClaimAddress":      "address",
		"AddressAnnotation": "wirekube.io/address",
		"AttemptAnnotation": "wirekube.io/attempt",
	} {
		got := map[string]string{
			"MeshLabel":         MeshLabel,
			"PeerLabel":         PeerLabel,
			"ClaimLabel":        ClaimLabel,
			"ClaimAddress":      ClaimAddress,
			"AddressAnnotation": AddressAnnotation,
			"AttemptAnnotation": AttemptAnnotation,
		}[name]
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	a := &Allocator{Namespace: "wirekube-system", MeshName: "default", MeshCIDR: "198.18.18.0/24"}
	lease := a.leaseFor("worker1", "198.18.18.74/32", 3)
	if lease.Name != "wirekube-default-198-18-18-74" || lease.Namespace != "wirekube-system" {
		t.Errorf("lease = %s/%s", lease.Namespace, lease.Name)
	}
	for key, want := range map[string]string{
		ClaimLabel: ClaimAddress,
		MeshLabel:  "default",
		PeerLabel:  "worker1",
	} {
		if got := lease.Labels[key]; got != want {
			t.Errorf("label %s = %q, want %q", key, got, want)
		}
	}
	for key, want := range map[string]string{
		AddressAnnotation: "198.18.18.74/32",
		AttemptAnnotation: "3",
	} {
		if got := lease.Annotations[key]; got != want {
			t.Errorf("annotation %s = %q, want %q", key, got, want)
		}
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != "worker1" {
		t.Errorf("holderIdentity = %v, want worker1", lease.Spec.HolderIdentity)
	}
	if preferred := a.leaseFor("worker1", "198.18.18.74/32", -1); preferred.Annotations[AttemptAnnotation] != "preferred" {
		t.Errorf("attempt annotation for a caller-supplied address = %q, want \"preferred\"",
			preferred.Annotations[AttemptAnnotation])
	}
}

// TestValidateRejectsAMeshNameThatCannotNameClaims: the mesh name goes into
// every claim name, so one long enough to blow the object-name limit would
// fail every create rather than a recognisable subset of them.
func TestValidateRejectsAMeshNameThatCannotNameClaims(t *testing.T) {
	long := ""
	for range 250 {
		long += "x"
	}
	a := &Allocator{Client: fake.NewClientBuilder().Build(), Namespace: "wirekube-system", MeshName: long, MeshCIDR: "198.18.18.0/24"}
	if err := a.validate(); err == nil {
		t.Fatal("a mesh name too long to name claims was accepted")
	}
	if len(ClaimName("default", "255.255.255.255/32")) > 253 {
		t.Error("the default mesh name already overflows the object-name limit")
	}
}
