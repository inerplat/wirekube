package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
	"github.com/inerplat/wirekube/pkg/sitegw"
)

// ipsecState is the agent's view of the tunnels it terminates.
type ipsecState struct {
	engine *sitegw.Engine
	// reported holds the metric label sets this node published.
	reported map[[2]string]bool
}

// EnableIPsec makes the agent terminate gateway IPsec tunnels through charon.
// failures may be nil.
func (a *Agent) EnableIPsec(charon ipsec.Charon, failures *ipsec.FailureWatcher) {
	a.ipsec = a.newIPsecState(charon, sitegw.KernelDataplane{}, failures)
}

func (a *Agent) newIPsecState(charon ipsec.Charon, dp sitegw.Dataplane, failures *ipsec.FailureWatcher) *ipsecState {
	e := sitegw.NewEngine(charon, dp, failures, a.log)
	e.EnableForwarding = enableIPForwarding
	e.OnGuard = recordGuardMetrics
	e.CharonHint = "check that the charon DaemonSet runs on this node (chart agent.ipsec.charon.nodeSelector, wirekubectl --charon-node-selector)"
	return &ipsecState{engine: e, reported: map[[2]string]bool{}}
}

// tunnelPlan ties an engine plan to the gateway that defines it.
type tunnelPlan struct {
	*sitegw.Plan
	gw *wirekubev1alpha1.WireKubeGateway
}

// pendingGateway is a gateway with tunnels and no elected peer.
type pendingGateway struct {
	gw     *wirekubev1alpha1.WireKubeGateway
	reason string
}

// errTransient marks an API error that aborts the sync instead of being acted on.
var errTransient = errors.New("transient API error")

// setupIPsec reconciles kernel state, charon and status.ipsec for the
// gateways that elect this node, and tears down tunnels served elsewhere.
func (a *Agent) setupIPsec(ctx context.Context) {
	if a.ipsec == nil {
		a.reconcileDisabledIPsec(ctx)
		return
	}
	list := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, list); err != nil {
		a.log.Error(err, "listing gateways for IPsec")
		return
	}

	plans, pending, err := a.planTunnels(ctx, list.Items)
	if err != nil {
		// Acting on a partial view could tear down a working tunnel.
		a.log.Error(err, "IPsec reconcile skipped this sync")
		return
	}
	for _, pg := range pending {
		a.writePendingStatus(ctx, pg)
	}
	e := a.ipsec.engine
	if len(plans) == 0 && !e.Active() {
		return
	}

	e.RouteSource = func() net.IP { return a.ownMeshIP(ctx) }
	enginePlans := make([]*sitegw.Plan, len(plans))
	for i, p := range plans {
		enginePlans[i] = p.Plan
	}
	res := e.Sync(enginePlans)
	a.writeActiveStatus(ctx, plans, res.Statuses)
}

// Replaceable in tests.
var (
	removeTunnelState = ipsec.RemoveTunnelState
	syncDisabledGuard = ipsec.SyncGuard
)

// reconcileDisabledIPsec runs with IPsec off. Once per process it removes
// leftover XFRM interfaces and routes. It keeps the plaintext guard for
// gateways that elect this node and still define tunnels, because they still
// route the remote networks here.
func (a *Agent) reconcileDisabledIPsec(ctx context.Context) {
	if !a.ipsecDisabledCleaned {
		if err := removeTunnelState(); err != nil {
			a.log.Error(err, "removing IPsec state left by a previous agent")
		} else {
			a.ipsecDisabledCleaned = true
		}
	}
	list := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := a.client.List(ctx, list); err != nil {
		return
	}
	mesh, err := a.getMesh(ctx)
	if err != nil {
		return
	}
	var pairs []ipsec.SelectorPair
	for i := range list.Items {
		gw := &list.Items[i]
		if len(gw.Spec.IPsec) == 0 {
			continue
		}
		active, err := a.electActivePeer(ctx, gw)
		if err != nil {
			return
		}
		if active != a.nodeName {
			continue
		}
		for j := range gw.Spec.IPsec {
			t := &ipsec.Tunnel{LocalTS: gw.Spec.IPsec[j].LocalTrafficSelectors, RemoteTS: gw.Spec.IPsec[j].RemoteTrafficSelectors}
			if len(t.LocalTS) == 0 && mesh.Spec.MeshCIDR != "" {
				t.LocalTS = []string{mesh.Spec.MeshCIDR}
			}
			if len(t.RemoteTS) == 0 {
				for _, r := range gw.Spec.Routes {
					t.RemoteTS = append(t.RemoteTS, r.CIDR)
				}
			}
			pairs = append(pairs, sitegw.GuardablePairs(t)...)
		}
	}
	if len(pairs) == 0 && a.ipsecDisabledGuardClear {
		return
	}
	if err := syncDisabledGuard(pairs); err != nil {
		a.log.Error(err, "syncing IPsec plaintext guard with IPsec disabled")
		return
	}
	a.ipsecDisabledGuardClear = len(pairs) == 0
}

// planTunnels resolves the tunnels of gateways that elect this node. A tunnel
// that fails to resolve is kept with Err set so its status says why.
func (a *Agent) planTunnels(ctx context.Context, gateways []wirekubev1alpha1.WireKubeGateway) ([]*tunnelPlan, []*pendingGateway, error) {
	mesh, err := a.getMesh(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading WireKubeMesh: %w", err)
	}

	var plans []*tunnelPlan
	var pending []*pendingGateway
	for i := range gateways {
		gw := &gateways[i]
		if len(gw.Spec.IPsec) == 0 {
			continue
		}
		active, err := a.electActivePeer(ctx, gw)
		if err != nil {
			return nil, nil, err
		}
		if active == "" {
			pending = append(pending, &pendingGateway{gw, "no peer in peerRefs is elected; check status.peerHealth"})
			continue
		}
		if active != a.nodeName {
			continue
		}
		localID, err := a.defaultLocalID(ctx)
		if err != nil {
			return nil, nil, err
		}
		for j := range gw.Spec.IPsec {
			s := &gw.Spec.IPsec[j]
			p := &tunnelPlan{gw: gw, Plan: &sitegw.Plan{Group: gw.Name, Name: s.Name, Index: j, Dataplane: s.Dataplane, LastPhase: lastPhase(gw, s.Name)}}
			p.Tunnel, p.Err = a.resolveTunnel(ctx, gw, s, mesh.Spec.MeshCIDR, localID)
			if errors.Is(p.Err, errTransient) {
				return nil, nil, p.Err
			}
			plans = append(plans, p)
		}
	}
	enginePlans := make([]*sitegw.Plan, len(plans))
	byPlan := make(map[*sitegw.Plan]*tunnelPlan, len(plans))
	for i, p := range plans {
		enginePlans[i] = p.Plan
		byPlan[p.Plan] = p
	}
	sitegw.Validate(enginePlans)
	for i, p := range enginePlans {
		plans[i] = byPlan[p]
	}
	return plans, pending, nil
}

func lastPhase(gw *wirekubev1alpha1.WireKubeGateway, tunnel string) wirekubev1alpha1.IPsecTunnelPhase {
	for _, st := range gw.Status.IPsec {
		if st.Name == tunnel {
			return st.Phase
		}
	}
	return ""
}

// defaultLocalID is the address in this node's WireKubePeer endpoint: the
// public IP the remote gateway is configured with, which charon does not see
// locally behind 1:1 NAT.
func (a *Agent) defaultLocalID(ctx context.Context) (string, error) {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, peer); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("reading WireKubePeer %s: %w: %w", a.nodeName, errTransient, err)
	}
	return ipsec.EndpointHost(peer.Spec.Endpoint), nil
}

func (a *Agent) resolveTunnel(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, s *wirekubev1alpha1.GatewayIPsecTunnel, meshCIDR, localID string) (*ipsec.Tunnel, error) {
	t := ipsec.FromSpec(gw, s, meshCIDR, localID)

	psk, err := a.readPreSharedKey(ctx, s.PreSharedKeyRef)
	if err != nil {
		return t, err
	}
	t.PreSharedKey = psk
	return t, t.Validate()
}

// readPreSharedKey reads only from the agent's namespace, so a gateway cannot
// make the agent read arbitrary Secrets.
func (a *Agent) readPreSharedKey(ctx context.Context, ref wirekubev1alpha1.IPsecSecretKeyRef) (string, error) {
	ns := a.podNamespace
	if ns == "" {
		ns = "wirekube-system"
	}
	key := ref.Key
	if key == "" {
		key = ipsec.DefaultPreSharedKeyID
	}
	sec := &corev1.Secret{}
	if err := a.client.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, sec); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("pre-shared key Secret %s/%s not found", ns, ref.Name)
		}
		return "", fmt.Errorf("reading Secret %s/%s: %w: %w", ns, ref.Name, errTransient, err)
	}
	v, ok := sec.Data[key]
	if !ok || len(v) == 0 {
		return "", fmt.Errorf("Secret %s/%s has no key %q", ns, ref.Name, key)
	}
	return string(v), nil
}

// ownMeshIP is the source address for traffic the gateway node originates.
func (a *Agent) ownMeshIP(ctx context.Context) net.IP {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, peer); err != nil || len(peer.Spec.AllowedIPs) == 0 {
		return nil
	}
	ip, _, err := net.ParseCIDR(peer.Spec.AllowedIPs[0])
	if err != nil {
		return nil
	}
	return ip
}

func (a *Agent) writeActiveStatus(ctx context.Context, plans []*tunnelPlan, statuses []wirekubev1alpha1.GatewayIPsecTunnelStatus) {
	byGateway := map[string][]*tunnelPlan{}
	gateways := map[string]*wirekubev1alpha1.WireKubeGateway{}
	tunnelStatus := map[*tunnelPlan]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
	for i, p := range plans {
		byGateway[p.gw.Name] = append(byGateway[p.gw.Name], p)
		gateways[p.gw.Name] = p.gw
		tunnelStatus[p] = statuses[i]
	}
	for name, ps := range byGateway {
		statuses := map[string]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
		for _, p := range ps {
			statuses[p.Name] = tunnelStatus[p]
		}
		gw := gateways[name]
		next := make([]wirekubev1alpha1.GatewayIPsecTunnelStatus, 0, len(gw.Spec.IPsec))
		ready := false
		for _, t := range gw.Spec.IPsec {
			st := statuses[t.Name]
			ready = ready || st.Phase == wirekubev1alpha1.IPsecTunnelPhaseEstablished
			next = append(next, st)
		}
		a.writeGatewayIPsecStatus(ctx, gw, next, ready)
		a.recordTunnelMetrics(gw.Name, next)
	}
	a.dropStaleTunnelMetrics(byGateway)
}

// writePendingStatus marks the tunnels of a gateway without an elected peer
// Pending. Every agent writes it; identical writes are no-ops.
func (a *Agent) writePendingStatus(ctx context.Context, pg *pendingGateway) {
	next := make([]wirekubev1alpha1.GatewayIPsecTunnelStatus, 0, len(pg.gw.Spec.IPsec))
	for _, t := range pg.gw.Spec.IPsec {
		next = append(next, wirekubev1alpha1.GatewayIPsecTunnelStatus{
			Name: t.Name, Phase: wirekubev1alpha1.IPsecTunnelPhasePending, Message: pg.reason,
		})
	}
	a.writeGatewayIPsecStatus(ctx, pg.gw, next, false)
}

// writeGatewayIPsecStatus patches status only when it changed.
func (a *Agent) writeGatewayIPsecStatus(ctx context.Context, gw *wirekubev1alpha1.WireKubeGateway, next []wirekubev1alpha1.GatewayIPsecTunnelStatus, ready bool) {
	sitegw.KeepTransitionTimes(gw.Status.IPsec, next, time.Now())
	summary := sitegw.Summary(next)
	if gw.Status.Ready == ready && gw.Status.IPsecSummary == summary && sitegw.StatusesEqual(gw.Status.IPsec, next) {
		return
	}
	patch := client.MergeFrom(gw.DeepCopy())
	gw.Status.IPsec = next
	gw.Status.IPsecSummary = summary
	gw.Status.Ready = ready
	if err := a.client.Status().Patch(ctx, gw, patch); err != nil {
		a.log.Error(err, "updating gateway IPsec status", "gateway", gw.Name)
	}
}
