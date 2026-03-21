// Package controller contains Kubernetes controller-runtime reconcilers
// for WireKube CRDs (WireKubeMesh, WireKubePeer).
//
// TODO: Implement full reconciliation logic. Currently provides stub types
// referenced by test/e2e.
package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// WireKubeMeshReconciler reconciles WireKubeMesh objects.
type WireKubeMeshReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile handles WireKubeMesh changes.
func (r *WireKubeMeshReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var mesh wirekubev1alpha1.WireKubeMesh
	if err := r.Get(ctx, req.NamespacedName, &mesh); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// TODO: implement reconciliation logic
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the manager.
func (r *WireKubeMeshReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubeMesh{}).
		Complete(r)
}

// WireKubePeerReconciler reconciles WireKubePeer objects.
type WireKubePeerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile handles WireKubePeer changes.
func (r *WireKubePeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var peer wirekubev1alpha1.WireKubePeer
	if err := r.Get(ctx, req.NamespacedName, &peer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// TODO: implement reconciliation logic
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller with the manager.
func (r *WireKubePeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubePeer{}).
		Complete(r)
}
