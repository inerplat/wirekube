package e2e

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestMeshReconciler_DefaultsApplied(t *testing.T) {
	ctx := context.Background()

	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "defaults-test"},
		Spec:       wirekubev1alpha1.WireKubeMeshSpec{},
	}
	if err := k8sClient.Create(ctx, mesh); err != nil {
		t.Fatalf("create WireKubeMesh: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, mesh) })

	eventually(t, func() bool {
		got := &wirekubev1alpha1.WireKubeMesh{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(mesh), got); err != nil {
			return false
		}
		return got.Spec.ListenPort == 51820 &&
			got.Spec.InterfaceName == "wire_kube" &&
			got.Spec.MTU == 1420
	}, defaultTimeout, defaultInterval, "Mesh defaults to be applied")
}

func TestMeshReconciler_DefaultSTUNServers(t *testing.T) {
	ctx := context.Background()

	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "stun-defaults-test"},
		Spec:       wirekubev1alpha1.WireKubeMeshSpec{},
	}
	if err := k8sClient.Create(ctx, mesh); err != nil {
		t.Fatalf("create WireKubeMesh: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, mesh) })

	eventually(t, func() bool {
		got := &wirekubev1alpha1.WireKubeMesh{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(mesh), got); err != nil {
			return false
		}
		return len(got.Spec.STUNServers) >= 2
	}, defaultTimeout, defaultInterval, "STUN servers defaults to be applied")
}

func TestMeshReconciler_PreservesUserValues(t *testing.T) {
	ctx := context.Background()

	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "user-values-test"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			ListenPort:    55555,
			InterfaceName: "wg1",
			MTU:           1380,
			STUNServers:   []string{"stun:my-stun.example.com:3478"},
		},
	}
	if err := k8sClient.Create(ctx, mesh); err != nil {
		t.Fatalf("create WireKubeMesh: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, mesh) })

	eventually(t, func() bool {
		got := &wirekubev1alpha1.WireKubeMesh{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(mesh), got); err != nil {
			return false
		}
		return got.Spec.ListenPort == 55555 &&
			got.Spec.InterfaceName == "wg1" &&
			got.Spec.MTU == 1380 &&
			len(got.Spec.STUNServers) == 1 &&
			got.Spec.STUNServers[0] == "stun:my-stun.example.com:3478"
	}, defaultTimeout, defaultInterval, "user-provided values to be preserved")
}

func TestMeshReconciler_StatusCountsPeers(t *testing.T) {
	ctx := context.Background()

	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "status-count-test"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			ListenPort: 51820,
		},
	}
	if err := k8sClient.Create(ctx, mesh); err != nil {
		t.Fatalf("create WireKubeMesh: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, mesh) })

	peer1 := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "count-peer-1"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "dGVzdGtleTEK",
			Endpoint:  "1.1.1.1:51820",
		},
	}
	peer2 := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "count-peer-2"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "dGVzdGtleTIK",
			Endpoint:  "2.2.2.2:51820",
		},
	}
	if err := k8sClient.Create(ctx, peer1); err != nil {
		t.Fatalf("create peer1: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, peer1) })
	if err := k8sClient.Create(ctx, peer2); err != nil {
		t.Fatalf("create peer2: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, peer2) })

	patch := client.MergeFrom(mesh.DeepCopy())
	if mesh.Annotations == nil {
		mesh.Annotations = map[string]string{}
	}
	mesh.Annotations["wirekube.io/reconcile-trigger"] = "1"
	if err := k8sClient.Patch(ctx, mesh, patch); err != nil {
		t.Fatalf("patch mesh to trigger reconcile: %v", err)
	}

	eventually(t, func() bool {
		got := &wirekubev1alpha1.WireKubeMesh{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(mesh), got); err != nil {
			return false
		}
		return got.Status.TotalPeers >= 2
	}, defaultTimeout, defaultInterval, "Mesh status to reflect peer count")
}

func TestMeshReconciler_StatusCountsReadyPeers(t *testing.T) {
	ctx := context.Background()

	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "ready-count-test"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			ListenPort: 51820,
		},
	}
	if err := k8sClient.Create(ctx, mesh); err != nil {
		t.Fatalf("create WireKubeMesh: %v", err)
	}
	t.Cleanup(func() { _ = k8sClient.Delete(ctx, mesh) })

	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "ready-peer-1"},
		Spec: wirekubev1alpha1.WireKubePeerSpec{
			PublicKey: "cmVhZHlrZXkxCg==",
			Endpoint:  "3.3.3.3:51820",
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

	patch := client.MergeFrom(mesh.DeepCopy())
	if mesh.Annotations == nil {
		mesh.Annotations = map[string]string{}
	}
	mesh.Annotations["wirekube.io/reconcile-trigger"] = "ready"
	if err := k8sClient.Patch(ctx, mesh, patch); err != nil {
		t.Fatalf("patch mesh: %v", err)
	}

	eventually(t, func() bool {
		got := &wirekubev1alpha1.WireKubeMesh{}
		if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(mesh), got); err != nil {
			return false
		}
		return got.Status.ReadyPeers >= 1 && got.Status.TotalPeers >= 1
	}, defaultTimeout, defaultInterval, "Mesh status to reflect ready peer count")
}
