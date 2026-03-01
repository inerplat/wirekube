package e2e

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestPeer_CreateAndGet(t *testing.T) {
	ctx := context.Background()

	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-peer-create"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey:            "dGVzdHB1YmtleTEK",
			Endpoint:             "198.51.100.1:51820",
			AllowedIPs:           []string{"10.10.0.0/16"},
			PersistentKeepalive:  25,
		},
	}
	if err := k8sClient.Create(ctx, peer); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, peer) })

	got := &wirekubev1alpha1.WireKubePeer{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(peer), got); err != nil {
		t.Fatalf("get peer: %v", err)
	}
	if got.Spec.PublicKey != "dGVzdHB1YmtleTEK" {
		t.Errorf("PublicKey = %s, want dGVzdHB1YmtleTEK", got.Spec.PublicKey)
	}
	if got.Spec.Endpoint != "198.51.100.1:51820" {
		t.Errorf("Endpoint = %s, want 198.51.100.1:51820", got.Spec.Endpoint)
	}
	if len(got.Spec.AllowedIPs) != 1 || got.Spec.AllowedIPs[0] != "10.10.0.0/16" {
		t.Errorf("AllowedIPs = %v, want [10.10.0.0/16]", got.Spec.AllowedIPs)
	}
}

func TestPeer_UpdateAllowedIPs(t *testing.T) {
	ctx := context.Background()

	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-peer-update"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey:   "dXBkYXRla2V5MQo=",
			Endpoint:    "198.51.100.2:51820",
			AllowedIPs:  []string{"172.20.2.7/32"},
		},
	}
	if err := k8sClient.Create(ctx, peer); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, peer) })

	latest := &wirekubev1alpha1.WireKubePeer{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(peer), latest); err != nil {
		t.Fatalf("get peer: %v", err)
	}

	patch := client.MergeFrom(latest.DeepCopy())
	latest.Spec.AllowedIPs = []string{"172.20.2.7/32", "10.10.0.0/16"}
	if err := k8sClient.Patch(ctx, latest, patch); err != nil {
		t.Fatalf("patch peer: %v", err)
	}

	got := &wirekubev1alpha1.WireKubePeer{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(peer), got); err != nil {
		t.Fatalf("get updated peer: %v", err)
	}
	if len(got.Spec.AllowedIPs) != 2 {
		t.Errorf("AllowedIPs count = %d, want 2", len(got.Spec.AllowedIPs))
	}
}

func TestPeer_StatusUpdate(t *testing.T) {
	ctx := context.Background()

	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-peer-status"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "c3RhdHVza2V5MQo=",
			Endpoint:  "198.51.100.3:51820",
		},
	}
	if err := k8sClient.Create(ctx, peer); err != nil {
		t.Fatalf("create peer: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, peer) })

	peer.Status.Connected = true
	if err := k8sClient.Status().Update(ctx, peer); err != nil {
		t.Fatalf("update peer status: %v", err)
	}

	got := &wirekubev1alpha1.WireKubePeer{}
	if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(peer), got); err != nil {
		t.Fatalf("get peer: %v", err)
	}
	if !got.Status.Connected {
		t.Error("peer should be connected")
	}
}

func TestPeer_MultipleAllowedIPs(t *testing.T) {
	ctx := context.Background()

	peers := []struct {
		name       string
		allowedIPs []string
	}{
		{"multi-peer-1", []string{"172.20.2.7/32"}},
		{"multi-peer-2", []string{"10.10.1.6/32"}},
		{"multi-peer-3", []string{"10.20.1.6/32"}},
	}

	for _, tc := range peers {
		peer := &wirekubev1alpha1.WireKubePeer{
			ObjectMeta: metav1.ObjectMeta{Name: tc.name},
			Spec: wirekubev1alpha1.WireKubePeerSpec{
				PublicKey:   "bXVsdGlrZXkK",
				Endpoint:    "198.51.100.10:51820",
				AllowedIPs:  tc.allowedIPs,
			},
		}
		if err := k8sClient.Create(ctx, peer); err != nil {
			t.Fatalf("create peer %s: %v", tc.name, err)
		}
		t.Cleanup(func() { _ = k8sClient.Delete(ctx, peer) })
	}

	list := &wirekubev1alpha1.WireKubePeerList{}
	if err := k8sClient.List(ctx, list); err != nil {
		t.Fatalf("list peers: %v", err)
	}
	if len(list.Items) < 3 {
		t.Errorf("peer count = %d, want >= 3", len(list.Items))
	}
}
