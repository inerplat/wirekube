package controller

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

const (
	GatewayNamespace      = "wirekube-system"
	GatewayImage          = "ghcr.io/wirekube/gateway:latest"
	GatewayContainerName  = "wirekube-gateway"
)

// WireKubeGatewayReconciler manages Gateway Deployments for non-VPN nodes.
type WireKubeGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubegateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubegateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

func (r *WireKubeGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	gw := &wirekubev1alpha1.WireKubeGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Ensure gateway Deployment exists
	deploy := r.buildDeployment(gw)
	existing := &appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKey{Namespace: GatewayNamespace, Name: deploy.Name}, existing)
	if apierrors.IsNotFound(err) {
		if createErr := r.Create(ctx, deploy); createErr != nil {
			return ctrl.Result{}, fmt.Errorf("creating gateway deployment: %w", createErr)
		}
	} else if err != nil {
		return ctrl.Result{}, err
	} else {
		// Update routing envs if routedCIDRs changed
		patch := client.MergeFrom(existing.DeepCopy())
		existing.Spec = deploy.Spec
		if patchErr := r.Patch(ctx, existing, patch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
	}

	// Update status from pod
	r.updateStatus(ctx, gw, deploy.Name)
	return ctrl.Result{}, nil
}

func (r *WireKubeGatewayReconciler) buildDeployment(gw *wirekubev1alpha1.WireKubeGateway) *appsv1.Deployment {
	routedCIDRs := joinStrings(gw.Spec.RoutedCIDRs, ",")
	labels := map[string]string{
		"app":                     "wirekube-gateway",
		"wirekube.io/gateway":     gw.Name,
	}

	replicas := int32(1)
	privileged := true
	hostNetwork := true

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wirekube-gateway-" + gw.Name,
			Namespace: GatewayNamespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: wirekubev1alpha1.GroupVersion.String(),
					Kind:       "WireKubeGateway",
					Name:       gw.Name,
					UID:        gw.UID,
				},
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					HostNetwork: hostNetwork,
					NodeName:    gw.Spec.NodeName,
					Containers: []corev1.Container{
						{
							Name:  GatewayContainerName,
							Image: GatewayImage,
							Env: []corev1.EnvVar{
								{Name: "ROUTED_CIDRS", Value: routedCIDRs},
								{Name: "MASQUERADE", Value: boolToStr(gw.Spec.MasqueradeEnabled)},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *WireKubeGatewayReconciler) updateStatus(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, deployName string) {
	podList := &corev1.PodList{}
	_ = r.List(ctx, podList, client.InNamespace(GatewayNamespace),
		client.MatchingLabels{"wirekube.io/gateway": gw.Name})

	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.Ready = false
	gw.Status.PodIP = ""
	gw.Status.PodName = ""
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			gw.Status.Ready = true
			gw.Status.PodIP = pod.Status.PodIP
			gw.Status.PodName = pod.Name
			break
		}
	}
	_ = r.Status().Patch(ctx, gw, patch)
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireKubeGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubeGateway{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
