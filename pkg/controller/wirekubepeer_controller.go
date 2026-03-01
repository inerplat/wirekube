package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// WireKubePeerReconciler watches WireKubePeer events.
// Peers are created by agents (for local nodes) or by users (for external peers).
// This controller only handles cleanup when a peer is explicitly deleted.
type WireKubePeerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubepeers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubepeers/status,verbs=get;update;patch

func (r *WireKubePeerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := r.Get(ctx, req.NamespacedName, peer); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireKubePeerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubePeer{}).
		Complete(r)
}
