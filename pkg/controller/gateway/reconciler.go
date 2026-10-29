// Package gateway elects every WireKubeGateway's active peer and makes exactly
// that peer advertise its routes, withdrawing them from every other peer,
// including a dead one whose own agent cannot.
package gateway

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/failover"
	"github.com/inerplat/wirekube/pkg/sitegw"
)

// InjectedCIDRsAnnotation lists, on a WireKubePeer, the gateway routes in its
// spec.allowedIPs that a gateway put there, so they can be told apart from
// the peer's own and withdrawn.
const InjectedCIDRsAnnotation = "wirekube.io/gateway-cidrs"

// pollInterval re-evaluates every gateway even without an event: a node that
// dies produces none, it just stops reporting.
const pollInterval = 30 * time.Second

// allGateways is the one request this reconciler handles. Advertisements span
// gateways (one peer can serve several), so every pass settles all of them.
var allGateways = reconcile.Request{NamespacedName: types.NamespacedName{Name: "all-gateways"}}

// Reconciler is the gateway election controller.
type Reconciler struct {
	client.Client
	// Now is injectable for tests.
	Now func() time.Time

	mu       sync.Mutex
	trackers map[string]*failover.Tracker
	// markedUnknown holds the gateways this process marked Unknown; they are
	// not marked again until their holder is live.
	markedUnknown map[string]bool
}

// SetupWithManager registers the reconciler. Gateway and peer events both
// map to the single all-gateways request.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	toAll := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{allGateways}
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("wirekubegateway-election").
		Watches(&wirekubev1alpha1.WireKubeGateway{}, toAll).
		Watches(&wirekubev1alpha1.WireKubePeer{}, toAll).
		Complete(r)
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) tracker(gateway string) *failover.Tracker {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trackers == nil {
		r.trackers = map[string]*failover.Tracker{}
	}
	t, ok := r.trackers[gateway]
	if !ok {
		t = &failover.Tracker{}
		r.trackers[gateway] = t
	}
	return t
}

func (r *Reconciler) forgetGatewaysExcept(gateways []wirekubev1alpha1.WireKubeGateway) {
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := make(map[string]bool, len(gateways))
	for i := range gateways {
		keep[gateways[i].Name] = true
	}
	for name := range r.trackers {
		if !keep[name] {
			delete(r.trackers, name)
		}
	}
	for name := range r.markedUnknown {
		if !keep[name] {
			delete(r.markedUnknown, name)
		}
	}
}

// Reconcile elects every gateway's active peer, then makes each peer
// advertise exactly the routes of the gateways it serves.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	gateways := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := r.List(ctx, gateways); err != nil {
		return reconcile.Result{}, fmt.Errorf("list WireKubeGateway: %w", err)
	}
	peers := &wirekubev1alpha1.WireKubePeerList{}
	if err := r.List(ctx, peers); err != nil {
		return reconcile.Result{}, fmt.Errorf("list WireKubePeer: %w", err)
	}
	now := r.now()
	byName := make(map[string]*wirekubev1alpha1.WireKubePeer, len(peers.Items))
	for i := range peers.Items {
		byName[peers.Items[i].Name] = &peers.Items[i]
	}

	desired := map[string]map[string]bool{}
	// Routes of gateways agents still elect on their own: whatever those
	// agents advertise for them is left exactly as it is.
	agentOwned := map[string]bool{}
	var errs []error
	// With no reports to go by, every peer counts toward ownership.
	reporting := failover.Live(peers.Items, now, failover.LivenessThreshold, "")
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		owned, err := r.settleOwnership(ctx, gw, byName, reporting)
		if err != nil {
			errs = append(errs, err)
		}
		if !owned {
			for _, route := range gw.Spec.Routes {
				agentOwned[route.CIDR] = true
			}
			continue
		}
		persisted := gw.Status.ActivePeer
		live := failover.Live(peers.Items, now, failover.LivenessThreshold, persisted)
		health := make(map[string]bool, len(gw.Spec.PeerRefs))
		for _, name := range gw.Spec.PeerRefs {
			health[name] = eligible(byName[name], gw, live)
		}
		active := r.tracker(gw.Name).Choose(failover.Choice{
			Preferred: gw.Spec.PeerRefs,
			Current:   persisted,
			Healthy:   func(name string) bool { return health[name] },
		}, now)
		// With no peer eligible, moving the gateway helps nobody and taking
		// it away would cut a path that may still work; keep it.
		if active == "" && byName[persisted] != nil && slices.Contains(gw.Spec.PeerRefs, persisted) {
			active = persisted
		}
		if err := r.writeStatus(ctx, gw, active, health); err != nil {
			// Agents act on the recorded holder, so the routes stay with it
			// until the move is recorded.
			errs = append(errs, err)
			active = persisted
		} else if silent := silentHolder(active, persisted, live); silent != "" {
			if err := r.markTunnelsUnknown(ctx, gw, silent, now); err != nil {
				errs = append(errs, err)
			}
		} else {
			r.setMarkedUnknown(gw.Name, false)
		}
		if active != "" {
			if desired[active] == nil {
				desired[active] = map[string]bool{}
			}
			for _, route := range gw.Spec.Routes {
				desired[active][route.CIDR] = true
			}
		}
	}

	r.forgetGatewaysExcept(gateways.Items)

	for i := range peers.Items {
		if err := r.advertise(ctx, &peers.Items[i], desired[peers.Items[i].Name], agentOwned); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return reconcile.Result{}, errs[0]
	}
	return reconcile.Result{RequeueAfter: pollInterval}, nil
}

// settleOwnership decides whether this controller elects gw: only while every
// live peerRef runs an agent that follows it, since an agent that elects on its
// own would fight it. Rechecked each pass; recorded in gw's annotation.
func (r *Reconciler) settleOwnership(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, byName map[string]*wirekubev1alpha1.WireKubePeer, live func(string) bool) (bool, error) {
	capable := true
	for _, name := range gw.Spec.PeerRefs {
		if p := byName[name]; p != nil && live(name) && !p.Status.GatewayElection {
			capable = false
			break
		}
	}
	if capable == gw.ElectedByController() {
		return capable, nil
	}
	patch := client.MergeFrom(gw.DeepCopy())
	if capable {
		if gw.Annotations == nil {
			gw.Annotations = map[string]string{}
		}
		gw.Annotations[wirekubev1alpha1.GatewayElectionAnnotation] = wirekubev1alpha1.GatewayElectionController
	} else {
		delete(gw.Annotations, wirekubev1alpha1.GatewayElectionAnnotation)
	}
	if err := r.Patch(ctx, gw, patch); err != nil {
		// Leave it as it stood; the next pass retries.
		return !capable, fmt.Errorf("change election ownership of gateway %s: %w", gw.Name, err)
	}
	return capable, nil
}

// eligible reports whether peer can serve gw right now: it exists, has a
// key, its agent is alive, and its health check (when enabled) passes. A
// node that has not reported a probe yet is given the benefit of the doubt.
func eligible(peer *wirekubev1alpha1.WireKubePeer, gw *wirekubev1alpha1.WireKubeGateway, live func(string) bool) bool {
	if peer == nil || peer.Spec.PublicKey == "" || !live(peer.Name) {
		return false
	}
	if gw.Spec.HealthCheck == nil || !gw.Spec.HealthCheck.Enabled {
		return true
	}
	for _, probe := range peer.Status.GatewayProbes {
		if probe.Gateway == gw.Name {
			return probe.Healthy
		}
	}
	return true
}

func (r *Reconciler) writeStatus(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, active string, health map[string]bool) error {
	peerHealth := make(map[string]string, len(health))
	for name, ok := range health {
		peerHealth[name] = "unhealthy"
		if ok {
			peerHealth[name] = "healthy"
		}
	}
	if gw.Status.ActivePeer == active && mapsEqual(gw.Status.PeerHealth, peerHealth) {
		return nil
	}
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.ActivePeer = active
	gw.Status.PeerHealth = peerHealth
	if err := r.Status().Patch(ctx, gw, patch); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("update gateway %s status: %w", gw.Name, err)
	}
	return nil
}

// markTunnelsUnknown replaces the tunnel states a silent active peer wrote:
// nothing else would overwrite them, and a dead node's last word is often
// Established. The agent rewrites them once it reports again.
// silentHolder names the peer whose tunnel states nobody refreshes: the
// active peer while it does not report, or the last one once none holds.
func silentHolder(active, persisted string, live func(string) bool) string {
	if active == "" {
		return persisted
	}
	if !live(active) {
		return active
	}
	return ""
}

func (r *Reconciler) markTunnelsUnknown(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, active string, now time.Time) error {
	if len(gw.Spec.IPsec) == 0 || len(gw.Status.IPsec) == 0 {
		return nil
	}
	r.mu.Lock()
	marked := r.markedUnknown[gw.Name]
	r.mu.Unlock()
	if marked {
		return nil
	}
	msg := fmt.Sprintf("peer %s has not reported for %s; its last tunnel state may be stale", active, failover.LivenessThreshold)
	prev := map[string]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
	for _, st := range gw.Status.IPsec {
		prev[st.Name] = st
	}
	next := make([]wirekubev1alpha1.GatewayIPsecTunnelStatus, 0, len(gw.Spec.IPsec))
	for _, t := range gw.Spec.IPsec {
		st := prev[t.Name]
		st.Name = t.Name
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseUnknown
		st.Reason = wirekubev1alpha1.IPsecReasonNotReporting
		st.Message = msg
		st.Carrier = false
		next = append(next, st)
	}
	sitegw.KeepTransitionTimes(gw.Status.IPsec, next, now)
	summary := sitegw.Summary(next)
	if !gw.Status.Ready && gw.Status.IPsecSummary == summary && sitegw.StatusesEqual(gw.Status.IPsec, next) {
		return nil
	}
	// Locked to the version read, so a report the agent wrote meanwhile
	// is not overwritten; the next pass looks again.
	patch := client.MergeFromWithOptions(gw.DeepCopy(), client.MergeFromWithOptimisticLock{})
	gw.Status.IPsec = next
	gw.Status.IPsecSummary = summary
	gw.Status.Ready = false
	if err := r.Status().Patch(ctx, gw, patch); err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			return nil
		}
		return fmt.Errorf("mark gateway %s tunnels unknown: %w", gw.Name, err)
	}
	r.setMarkedUnknown(gw.Name, true)
	return nil
}

func (r *Reconciler) setMarkedUnknown(gw string, v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !v {
		delete(r.markedUnknown, gw)
		return
	}
	if r.markedUnknown == nil {
		r.markedUnknown = map[string]bool{}
	}
	r.markedUnknown[gw] = true
}

// advertise makes peer's spec.allowedIPs carry exactly the gateway routes in
// want, leaving the peer's own entries alone, and leaving alone any route in
// agentOwned it already advertises: an agent still elects that gateway.
func (r *Reconciler) advertise(ctx context.Context, peer *wirekubev1alpha1.WireKubePeer, want, agentOwned map[string]bool) error {
	previous := map[string]bool{}
	for _, cidr := range strings.Split(peer.Annotations[InjectedCIDRsAnnotation], ",") {
		if cidr != "" {
			previous[cidr] = true
		}
	}
	keep := map[string]bool{}
	for cidr := range want {
		keep[cidr] = true
	}
	for cidr := range previous {
		if agentOwned[cidr] {
			keep[cidr] = true
		}
	}
	allowed := make([]string, 0, len(peer.Spec.AllowedIPs)+len(keep))
	for _, cidr := range peer.Spec.AllowedIPs {
		if !previous[cidr] && !keep[cidr] {
			allowed = append(allowed, cidr)
		}
	}
	injected := make([]string, 0, len(keep))
	for cidr := range keep {
		injected = append(injected, cidr)
	}
	sort.Strings(injected)
	allowed = append(allowed, injected...)

	annotation := strings.Join(injected, ",")
	if slices.Equal(peer.Spec.AllowedIPs, allowed) && peer.Annotations[InjectedCIDRsAnnotation] == annotation {
		return nil
	}
	// The peer's own agent writes this object too; a conflict is retried by
	// the requeue.
	patch := client.MergeFromWithOptions(peer.DeepCopy(), client.MergeFromWithOptimisticLock{})
	peer.Spec.AllowedIPs = allowed
	if annotation == "" {
		delete(peer.Annotations, InjectedCIDRsAnnotation)
	} else {
		if peer.Annotations == nil {
			peer.Annotations = map[string]string{}
		}
		peer.Annotations[InjectedCIDRsAnnotation] = annotation
	}
	if err := r.Patch(ctx, peer, patch); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("update gateway routes advertised by %s: %w", peer.Name, err)
	}
	return nil
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
