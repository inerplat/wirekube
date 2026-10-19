package agent

import (
	"context"
	"testing"

	"github.com/go-logr/logr/testr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func TestGatewayLoserDropsInjectedRoutes(t *testing.T) {
	const ann = "wirekube.io/gateway-cidrs"
	objs := []client.Object{
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"},
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "a", AllowedIPs: []string{"198.18.0.1/32", "10.77.1.0/24"}}},
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-b", Annotations: map[string]string{ann: "10.77.1.0/24"}},
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "b", AllowedIPs: []string{"198.18.0.2/32", "10.77.1.0/24"}}},
		&wirekubev1alpha1.WireKubeGateway{ObjectMeta: metav1.ObjectMeta{Name: "site"},
			Spec: wirekubev1alpha1.WireKubeGatewaySpec{PeerRefs: []string{"gw-a", "gw-b"},
				Routes: []wirekubev1alpha1.GatewayRoute{{CIDR: "10.77.1.0/24"}}}},
	}
	c := ctrlclientfake.NewClientBuilder().WithScheme(ipsecTestScheme(t)).WithObjects(objs...).Build()
	a := &Agent{log: testr.New(t), client: c, nodeName: "gw-b", gwRetainedRulesChecked: true}

	if err := a.setupGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := &wirekubev1alpha1.WireKubePeer{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "gw-b"}, b); err != nil {
		t.Fatal(err)
	}
	if len(b.Spec.AllowedIPs) != 1 || b.Spec.AllowedIPs[0] != "198.18.0.2/32" {
		t.Fatalf("losing peer still advertises gateway CIDRs: %v", b.Spec.AllowedIPs)
	}
	if b.Annotations[ann] != "" {
		t.Errorf("injected-CIDR annotation not cleared: %q", b.Annotations[ann])
	}
}

func TestGatewayDeletionWithdrawsInjectedRoutes(t *testing.T) {
	const ann = "wirekube.io/gateway-cidrs"
	peer := &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a", Annotations: map[string]string{ann: "10.77.1.0/24"}},
		Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "a", AllowedIPs: []string{"198.18.0.1/32", "10.77.1.0/24"}}}
	c := ctrlclientfake.NewClientBuilder().WithScheme(ipsecTestScheme(t)).WithObjects(peer).Build()
	a := &Agent{log: testr.New(t), client: c, nodeName: "gw-a", gwRetainedRulesChecked: true}

	if err := a.setupGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := &wirekubev1alpha1.WireKubePeer{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "gw-a"}, got)
	if len(got.Spec.AllowedIPs) != 1 {
		t.Fatalf("routes of a deleted gateway still advertised: %v", got.Spec.AllowedIPs)
	}
}

// TestControllerElectedGatewayIsLeftToTheController covers a gateway the
// election controller owns: the agent acts on status.activePeer and leaves
// route advertisements to the controller, even for its own peer.
func TestControllerElectedGatewayIsLeftToTheController(t *testing.T) {
	const ann = "wirekube.io/gateway-cidrs"
	objs := []client.Object{
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"},
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "a", AllowedIPs: []string{"198.18.0.1/32"}}},
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-b"},
			Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "b", AllowedIPs: []string{"198.18.0.2/32"}}},
		&wirekubev1alpha1.WireKubeGateway{ObjectMeta: metav1.ObjectMeta{Name: "site",
			Annotations: map[string]string{wirekubev1alpha1.GatewayElectionAnnotation: wirekubev1alpha1.GatewayElectionController}},
			Spec: wirekubev1alpha1.WireKubeGatewaySpec{PeerRefs: []string{"gw-a", "gw-b"},
				Routes: []wirekubev1alpha1.GatewayRoute{{CIDR: "10.77.1.0/24"}}},
			Status: wirekubev1alpha1.WireKubeGatewayStatus{ActivePeer: "gw-b"}},
	}
	c := ctrlclientfake.NewClientBuilder().WithScheme(ipsecTestScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeGateway{}).Build()

	// gw-a is first in peerRefs, but the controller chose gw-b.
	a := &Agent{log: testr.New(t), client: c, nodeName: "gw-a", gwRetainedRulesChecked: true}
	gw := &wirekubev1alpha1.WireKubeGateway{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "site"}, gw)
	if got, _ := a.electActivePeer(context.Background(), gw); got != "gw-b" {
		t.Fatalf("electActivePeer = %q, want the controller's gw-b", got)
	}
	// Under its own election gw-a would take the gateway and advertise it;
	// here it must do neither.
	if err := a.setupGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	peer := &wirekubev1alpha1.WireKubePeer{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "gw-a"}, peer)
	if len(peer.Spec.AllowedIPs) != 1 || peer.Annotations[ann] != "" {
		t.Fatalf("agent edited advertisements of a controller-elected gateway: %v %v", peer.Spec.AllowedIPs, peer.Annotations)
	}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "site"}, gw)
	if gw.Status.ActivePeer != "gw-b" {
		t.Fatalf("agent rewrote the controller's activePeer to %q", gw.Status.ActivePeer)
	}
}

// TestStaleElectionIsNotWrittenOverATakeover covers an agent that elected a
// gateway from a list read before the controller took it over: its write of
// activePeer must fail rather than override the controller's choice.
func TestStaleElectionIsNotWrittenOverATakeover(t *testing.T) {
	gwObj := &wirekubev1alpha1.WireKubeGateway{ObjectMeta: metav1.ObjectMeta{Name: "site"},
		Spec: wirekubev1alpha1.WireKubeGatewaySpec{PeerRefs: []string{"gw-a", "gw-b"},
			Routes: []wirekubev1alpha1.GatewayRoute{{CIDR: "10.77.1.0/24"}}}}
	c := ctrlclientfake.NewClientBuilder().WithScheme(ipsecTestScheme(t)).WithObjects(gwObj).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeGateway{}).Build()
	a := &Agent{log: testr.New(t), client: c, nodeName: "gw-a"}

	stale := &wirekubev1alpha1.WireKubeGateway{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "site"}, stale); err != nil {
		t.Fatal(err)
	}
	// Meanwhile the controller takes over and picks gw-b.
	fresh := stale.DeepCopy()
	fresh.Annotations = map[string]string{wirekubev1alpha1.GatewayElectionAnnotation: wirekubev1alpha1.GatewayElectionController}
	if err := c.Update(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	fresh.Status.ActivePeer = "gw-b"
	if err := c.Status().Update(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}

	a.updateGatewayStatus(context.Background(), stale, "gw-a")
	got := &wirekubev1alpha1.WireKubeGateway{}
	_ = c.Get(context.Background(), client.ObjectKey{Name: "site"}, got)
	if got.Status.ActivePeer != "gw-b" {
		t.Fatalf("activePeer = %q; a stale election overwrote the controller's", got.Status.ActivePeer)
	}
}
