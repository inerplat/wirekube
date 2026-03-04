package controller

import (
	"context"
	"fmt"
	"net"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

const (
	// gatewayRouteLabel marks CIDRs injected by the gateway controller
	// so they can be distinguished from user-defined AllowedIPs.
	gatewayRouteLabel = "wirekube.io/gateway"
)

// WireKubeGatewayReconciler reconciles WireKubeGateway objects.
// It manages route injection into gateway peers' AllowedIPs and performs
// health-check-based HA failover across multiple PeerRefs.
type WireKubeGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubegateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubegateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wirekube.io,resources=wirekubepeers,verbs=get;list;watch;update;patch

func (r *WireKubeGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &wirekubev1alpha1.WireKubeGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	routeCIDRs := make([]string, 0, len(gw.Spec.Routes))
	for _, route := range gw.Spec.Routes {
		routeCIDRs = append(routeCIDRs, route.CIDR)
	}

	// Determine peer health for HA
	peerHealth := make(map[string]string, len(gw.Spec.PeerRefs))
	for _, peerName := range gw.Spec.PeerRefs {
		health := r.checkPeerHealth(ctx, gw, peerName)
		peerHealth[peerName] = health
	}

	// Elect active peer: first healthy peer in PeerRefs order (priority-based)
	activePeer := ""
	for _, peerName := range gw.Spec.PeerRefs {
		if peerHealth[peerName] == "healthy" {
			activePeer = peerName
			break
		}
	}
	if activePeer == "" && len(gw.Spec.PeerRefs) > 0 {
		activePeer = gw.Spec.PeerRefs[0]
		logger.Info("no healthy peer found, defaulting to first peer", "peer", activePeer)
	}

	// Inject routes into the active peer's AllowedIPs
	injectedCount := int32(0)
	for _, peerName := range gw.Spec.PeerRefs {
		if peerName == activePeer {
			count, err := r.injectRoutes(ctx, peerName, gw.Name, routeCIDRs)
			if err != nil {
				logger.Error(err, "injecting routes into active peer", "peer", peerName)
				return ctrl.Result{}, err
			}
			injectedCount = int32(count)
		} else {
			// Remove routes from inactive peers (failover cleanup)
			if _, err := r.injectRoutes(ctx, peerName, gw.Name, nil); err != nil {
				logger.Error(err, "removing routes from inactive peer", "peer", peerName)
			}
		}
	}

	// Update gateway status
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.ActivePeer = activePeer
	gw.Status.Ready = peerHealth[activePeer] == "healthy"
	gw.Status.RoutesInjected = injectedCount
	gw.Status.PeerHealth = peerHealth
	now := metav1.Now()
	gw.Status.LastHealthCheck = &now

	r.setCondition(gw, activePeer != "", peerHealth)

	if err := r.Status().Patch(ctx, gw, patch); err != nil {
		if !apierrors.IsConflict(err) {
			return ctrl.Result{}, err
		}
	}

	// Requeue for periodic health checking
	requeueAfter := 30 * time.Second
	if gw.Spec.HealthCheck != nil && gw.Spec.HealthCheck.Enabled && gw.Spec.HealthCheck.IntervalSeconds > 0 {
		requeueAfter = time.Duration(gw.Spec.HealthCheck.IntervalSeconds) * time.Second
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// checkPeerHealth determines whether a peerRef is healthy.
// It checks: 1) peer CRD exists, 2) peer has a public key, 3) health check target (if configured).
func (r *WireKubeGatewayReconciler) checkPeerHealth(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, peerName string) string {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := r.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return "unhealthy"
	}
	if peer.Spec.PublicKey == "" {
		return "unhealthy"
	}

	if gw.Spec.HealthCheck == nil || !gw.Spec.HealthCheck.Enabled {
		return "healthy"
	}

	// TCP connect probe to health check target
	timeout := 5 * time.Second
	if gw.Spec.HealthCheck.TimeoutSeconds > 0 {
		timeout = time.Duration(gw.Spec.HealthCheck.TimeoutSeconds) * time.Second
	}

	target := gw.Spec.HealthCheck.Target
	_, _, err := net.SplitHostPort(target)
	if err != nil {
		return "healthy"
	}

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "unhealthy"
	}
	conn.Close()
	return "healthy"
}

// injectRoutes manages the gateway-injected CIDRs in a peer's AllowedIPs.
// It preserves user-defined AllowedIPs and only modifies gateway-owned CIDRs.
// Returns the number of routes actually injected.
func (r *WireKubeGatewayReconciler) injectRoutes(ctx context.Context, peerName, gwName string, cidrs []string) (int, error) {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := r.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return 0, fmt.Errorf("getting peer %s: %w", peerName, err)
	}

	// Annotations track which CIDRs are gateway-injected vs user-defined.
	// Format: wirekube.io/gateway=<gwName>:<cidr1>,<cidr2>,...
	annotations := peer.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	annotKey := fmt.Sprintf("%s/%s", gatewayRouteLabel, gwName)
	oldInjected := parseCSV(annotations[annotKey])

	// Build new AllowedIPs: (existing - old injected) + new cidrs
	newAllowed := make([]string, 0, len(peer.Spec.AllowedIPs)+len(cidrs))
	oldSet := toSet(oldInjected)
	for _, ip := range peer.Spec.AllowedIPs {
		if !oldSet[ip] {
			newAllowed = append(newAllowed, ip)
		}
	}
	newAllowed = append(newAllowed, cidrs...)

	// Check if anything actually changed
	if sliceEqual(peer.Spec.AllowedIPs, newAllowed) {
		return len(cidrs), nil
	}

	patch := client.MergeFrom(peer.DeepCopy())
	peer.Spec.AllowedIPs = newAllowed

	if len(cidrs) > 0 {
		annotations[annotKey] = joinCSV(cidrs)
	} else {
		delete(annotations, annotKey)
	}
	peer.SetAnnotations(annotations)

	if err := r.Patch(ctx, peer, patch); err != nil {
		return 0, fmt.Errorf("patching peer %s AllowedIPs: %w", peerName, err)
	}

	return len(cidrs), nil
}

func (r *WireKubeGatewayReconciler) setCondition(gw *wirekubev1alpha1.WireKubeGateway, hasActive bool, peerHealth map[string]string) {
	healthyCount := 0
	for _, h := range peerHealth {
		if h == "healthy" {
			healthyCount++
		}
	}

	readyCond := metav1.Condition{
		Type:               "Ready",
		ObservedGeneration: gw.Generation,
		LastTransitionTime: metav1.Now(),
	}

	switch {
	case healthyCount == len(peerHealth) && hasActive:
		readyCond.Status = metav1.ConditionTrue
		readyCond.Reason = "AllPeersHealthy"
		readyCond.Message = fmt.Sprintf("All %d gateway peers are healthy", healthyCount)
	case hasActive:
		readyCond.Status = metav1.ConditionTrue
		readyCond.Reason = "DegradedHA"
		readyCond.Message = fmt.Sprintf("%d of %d gateway peers healthy", healthyCount, len(peerHealth))
	default:
		readyCond.Status = metav1.ConditionFalse
		readyCond.Reason = "NoHealthyPeer"
		readyCond.Message = "No healthy gateway peer available"
	}

	// Replace or append the Ready condition
	found := false
	for i, c := range gw.Status.Conditions {
		if c.Type == "Ready" {
			gw.Status.Conditions[i] = readyCond
			found = true
			break
		}
	}
	if !found {
		gw.Status.Conditions = append(gw.Status.Conditions, readyCond)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *WireKubeGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubeGateway{}).
		Complete(r)
}

// --- helpers ---

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			if part != "" {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	return result
}

func joinCSV(items []string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for _, item := range items[1:] {
		result += "," + item
	}
	return result
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
