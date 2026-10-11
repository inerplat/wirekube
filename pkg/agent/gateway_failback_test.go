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
