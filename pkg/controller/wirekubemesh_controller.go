// Package controller contains reconciliation logic for WireKube CRDs.
package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

const (
	AnnotationEndpoint   = "wirekube.io/endpoint"
	DefaultListenPort    = 51820
	DefaultInterfaceName = "wire_kube"
	DefaultMTU           = 1420
	DefaultKeepalive     = 25
)

// WireKubeMeshReconciler reconciles WireKubeMesh objects.
type WireKubeMeshReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubemeshes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubemeshes/status,verbs=get;update;patch

func (r *WireKubeMeshReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	if err := r.Get(ctx, req.NamespacedName, mesh); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Apply defaults
	needsPatch := false
	if mesh.Spec.ListenPort == 0 {
		mesh.Spec.ListenPort = DefaultListenPort
		needsPatch = true
	}
	if mesh.Spec.InterfaceName == "" {
		mesh.Spec.InterfaceName = DefaultInterfaceName
		needsPatch = true
	}
	if mesh.Spec.MTU == 0 {
		mesh.Spec.MTU = DefaultMTU
		needsPatch = true
	}
	if len(mesh.Spec.STUNServers) == 0 {
		mesh.Spec.STUNServers = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
		}
		needsPatch = true
	}
	if needsPatch {
		if err := r.Update(ctx, mesh); err != nil && !apierrors.IsConflict(err) {
			return ctrl.Result{}, err
		}
	}

	// Update status: count peers
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := r.List(ctx, peerList); err != nil {
		return ctrl.Result{}, err
	}

	readyCount := int32(0)
	for _, p := range peerList.Items {
		if p.Status.Connected {
			readyCount++
		}
	}

	mesh.Status.ReadyPeers = readyCount
	mesh.Status.TotalPeers = int32(len(peerList.Items))
	if err := r.Status().Update(ctx, mesh); err != nil && !apierrors.IsConflict(err) {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireKubeMeshReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubeMesh{}).
		Complete(r)
}
