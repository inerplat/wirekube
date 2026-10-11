package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

// ipsecDataplane is the kernel side of IPsec termination, an interface so
// reconcile logic is testable without netlink.
type ipsecDataplane interface {
	EnsureRule() error
	RemoveRule()
	EnsureInterface(name string, ifID uint32, mtu int) error
	DeleteInterface(name string) error
	ListInterfaces() ([]string, error)
	SyncRoutes(desired map[string][]string, src net.IP) error
	// IsUnsupported reports whether an EnsureInterface error means the
	// kernel has no XFRM interface support.
	IsUnsupported(err error) bool
	// SyncGuard drops tunnel traffic that IPsec will not process.
	SyncGuard(pairs []ipsec.SelectorPair) error
	// GuardDrops returns the packets each guard rule dropped.
	GuardDrops() (map[ipsec.SelectorPair]uint64, error)
	// XFRMInterfaceBlocker says why XFRM interfaces must not be tried, or "".
	XFRMInterfaceBlocker() string
}

type kernelIPsecDataplane struct{}

func (kernelIPsecDataplane) EnsureRule() error { return ipsec.EnsureRule() }
func (kernelIPsecDataplane) RemoveRule()       { ipsec.RemoveRule() }
func (kernelIPsecDataplane) EnsureInterface(n string, id uint32, mtu int) error {
	return ipsec.EnsureInterface(n, id, mtu)
}
func (kernelIPsecDataplane) DeleteInterface(n string) error    { return ipsec.DeleteInterface(n) }
func (kernelIPsecDataplane) ListInterfaces() ([]string, error) { return ipsec.ListInterfaces() }
func (kernelIPsecDataplane) SyncRoutes(d map[string][]string, src net.IP) error {
	return ipsec.SyncRoutes(d, src)
}
func (kernelIPsecDataplane) IsUnsupported(err error) bool { return ipsec.IsUnsupported(err) }
func (kernelIPsecDataplane) XFRMInterfaceBlocker() string { return ipsec.XFRMInterfaceBlocker() }
func (kernelIPsecDataplane) GuardDrops() (map[ipsec.SelectorPair]uint64, error) {
	return ipsec.GuardDrops()
}
func (kernelIPsecDataplane) SyncGuard(p []ipsec.SelectorPair) error {
	return ipsec.SyncGuard(p)
}

// ipsecState is the agent's view of the tunnels it terminates.
type ipsecState struct {
	charon    ipsec.Charon
	dataplane ipsecDataplane
	failures  *ipsec.FailureWatcher // may be nil
	// active keeps the teardown path running until it is confirmed.
	active bool
	// xfrmiUnsupported sends Auto tunnels to policy mode; xfrmiReason says why.
	xfrmiUnsupported bool
	xfrmiReason      string
	xfrmiChecked     bool
	// reported holds the metric label sets this node published.
	reported map[[2]string]bool
	// keys holds a digest of each loaded connection's pre-shared key, so a
	// key change reconnects. Never logged.
	keys map[string][sha256.Size]byte
}

// EnableIPsec makes the agent terminate gateway IPsec tunnels through charon.
// failures may be nil.
func (a *Agent) EnableIPsec(charon ipsec.Charon, failures *ipsec.FailureWatcher) {
	// active starts true so the first sync removes what a previous process
	// left, even when this node terminates nothing.
	a.ipsec = &ipsecState{charon: charon, dataplane: kernelIPsecDataplane{}, failures: failures, active: true,
		reported: map[[2]string]bool{}, keys: map[string][sha256.Size]byte{}}
}

// tunnelPlan is one tunnel this node should terminate, or a reason it cannot.
type tunnelPlan struct {
	gw     *wirekubev1alpha1.WireKubeGateway
	spec   *wirekubev1alpha1.GatewayIPsecTunnel
	index  int // position in gw.Spec.IPsec; earlier tunnels are preferred
	tunnel *ipsec.Tunnel
	err    error
	// carrier marks the one tunnel of a redundancy group that gets the routes.
	carrier bool
	// loadedNow means start_action already started it this sync.
	loadedNow bool
	// guardErr is why the plaintext guard for this tunnel is not installed.
	// The connection stays loaded, since an SA still encrypts the traffic
	// the routes keep pulling here, but the tunnel reports Error.
	guardErr error
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
	if len(plans) == 0 && !a.ipsec.active {
		return
	}

	dataplaneClean := a.reconcileIPsecDataplane(ctx, plans)
	charonClean, charonErr := a.reconcileCharon(plans)
	a.writeActiveStatus(ctx, plans, charonErr)
	a.ipsec.active = len(plans) > 0 || !dataplaneClean || charonErr != nil || !charonClean
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
			pairs = append(pairs, guardablePairs(t)...)
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
// that fails to resolve is kept with err set so its status says why.
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
			pending = append(pending, &pendingGateway{gw, "no peer in peerRefs has a WireKubePeer with a public key"})
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
			p := &tunnelPlan{gw: gw, spec: &gw.Spec.IPsec[j], index: j}
			p.tunnel, p.err = a.resolveTunnel(ctx, gw, p.spec, mesh.Spec.MeshCIDR, localID)
			if errors.Is(p.err, errTransient) {
				return nil, nil, p.err
			}
			plans = append(plans, p)
		}
	}
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].gw.Name != plans[j].gw.Name {
			return plans[i].gw.Name < plans[j].gw.Name
		}
		return plans[i].index < plans[j].index
	})
	rejectDuplicateInterfaceIDs(plans)
	rejectOverlappingRemoteSelectors(plans)
	rejectConflictingKeys(plans)
	return plans, pending, nil
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

func rejectDuplicateInterfaceIDs(plans []*tunnelPlan) {
	byID := map[uint32]*tunnelPlan{}
	for _, p := range plans {
		if p.err != nil {
			continue
		}
		if q, dup := byID[p.tunnel.InterfaceID]; dup {
			p.err = fmt.Errorf("interface ID %d is also used by tunnel %s; set interfaceID", p.tunnel.InterfaceID, q.tunnel.Name)
			continue
		}
		byID[p.tunnel.InterfaceID] = p
	}
}

// rejectOverlappingRemoteSelectors fails partial overlaps between tunnels.
// Identical selectors are allowed: they form a redundancy group.
func rejectOverlappingRemoteSelectors(plans []*tunnelPlan) {
	var seen []*tunnelPlan
	for _, p := range plans {
		if p.err != nil {
			continue
		}
		for _, q := range seen {
			if prefixesOverlap(p.tunnel.RemoteTS, q.tunnel.RemoteTS) && !samePrefixSet(p.tunnel.RemoteTS, q.tunnel.RemoteTS) {
				p.err = fmt.Errorf("remote selectors partly overlap tunnel %s on this node; use identical selectors for redundant tunnels, or disjoint ones", q.tunnel.Name)
				break
			}
		}
		if p.err == nil {
			seen = append(seen, p)
		}
	}
}

// samePrefixSet compares selector lists ignoring order and host bits.
func samePrefixSet(a, b []string) bool {
	norm := func(in []string) map[string]bool {
		out := map[string]bool{}
		for _, s := range in {
			if p, err := netip.ParsePrefix(s); err == nil {
				out[p.Masked().String()] = true
			}
		}
		return out
	}
	x, y := norm(a), norm(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}

func redundancyGroups(plans []*tunnelPlan) [][]*tunnelPlan {
	var groups [][]*tunnelPlan
	for _, p := range plans {
		if p.err != nil {
			continue
		}
		placed := false
		for i := range groups {
			if samePrefixSet(groups[i][0].tunnel.RemoteTS, p.tunnel.RemoteTS) {
				groups[i] = append(groups[i], p)
				placed = true
				break
			}
		}
		if !placed {
			groups = append(groups, []*tunnelPlan{p})
		}
	}
	return groups
}

func lastPhase(p *tunnelPlan) wirekubev1alpha1.IPsecTunnelPhase {
	for _, st := range p.gw.Status.IPsec {
		if st.Name == p.spec.Name {
			return st.Phase
		}
	}
	return ""
}

// rejectConflictingKeys fails tunnels that share a remote identity but not a
// key: charon scopes keys to the identity, so either key could match.
func rejectConflictingKeys(plans []*tunnelPlan) {
	keyByID := map[string]*tunnelPlan{}
	for _, p := range plans {
		if p.err != nil {
			continue
		}
		id := p.tunnel.RemoteID
		if id == "" {
			id = p.tunnel.RemoteAddress
		}
		if q, ok := keyByID[id]; ok && q.tunnel.PreSharedKey != p.tunnel.PreSharedKey {
			p.err = fmt.Errorf("remote identity %s is also used by tunnel %s with a different pre-shared key", id, q.tunnel.Name)
			continue
		}
		keyByID[id] = p
	}
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

// chooseCarriers routes each redundancy group into its first tunnel that was
// Established at the last sync, or its first tunnel. Policy mode cannot steer
// between identical selectors, so such a group keeps only its first tunnel.
func (a *Agent) chooseCarriers(plans []*tunnelPlan, routes map[string][]string) {
	for _, group := range redundancyGroups(plans) {
		if len(group) > 1 {
			for _, p := range group {
				if !p.tunnel.RouteBased {
					for _, q := range group[1:] {
						q.err = fmt.Errorf("redundant tunnels (identical remote selectors as %s) need the XFRMInterface dataplane, and this tunnel group runs in policy mode%s",
							group[0].tunnel.Name, a.policyModeReason())
					}
					group = group[:1]
					break
				}
			}
		}
		carrier := group[0]
		for _, p := range group {
			if lastPhase(p) == wirekubev1alpha1.IPsecTunnelPhaseEstablished {
				carrier = p
				break
			}
		}
		carrier.carrier = true
		if carrier.tunnel.RouteBased {
			routes[ipsec.InterfaceName(carrier.tunnel.InterfaceID)] = carrier.tunnel.RemoteTS
		}
	}
}

func (a *Agent) policyModeReason() string {
	if a.ipsec.xfrmiReason != "" {
		return " because XFRM interfaces are unavailable: " + a.ipsec.xfrmiReason
	}
	return ""
}

// reconcileIPsecDataplane syncs XFRM interfaces, routes and the guard with the
// plans, and reports whether every step succeeded. Plans with errors get no
// interface, so they do not blackhole their remote networks.
func (a *Agent) reconcileIPsecDataplane(ctx context.Context, plans []*tunnelPlan) bool {
	clean := true
	dp := a.ipsec.dataplane
	routes := map[string][]string{}
	keep := map[string]bool{}
	if !a.ipsec.xfrmiChecked {
		a.ipsec.xfrmiChecked = true
		if reason := dp.XFRMInterfaceBlocker(); reason != "" {
			a.ipsec.xfrmiUnsupported = true
			a.ipsec.xfrmiReason = reason
			a.log.Info("XFRM interfaces unavailable; Auto tunnels use policy-based steering", "reason", reason)
		}
	}
	for _, p := range plans {
		if p.err != nil {
			continue
		}
		mode := p.spec.Dataplane
		if mode == "" {
			mode = wirekubev1alpha1.IPsecDataplaneAuto
		}
		if mode == wirekubev1alpha1.IPsecDataplanePolicy ||
			(mode == wirekubev1alpha1.IPsecDataplaneAuto && a.ipsec.xfrmiUnsupported) {
			p.tunnel.RouteBased = false
			continue
		}
		if a.ipsec.xfrmiReason != "" {
			// Trying would remove the node's SAs; see XFRMInterfaceBlocker.
			p.err = fmt.Errorf("the XFRMInterface dataplane is unavailable: %s; use Auto or Policy", a.ipsec.xfrmiReason)
			continue
		}
		name := ipsec.InterfaceName(p.tunnel.InterfaceID)
		if err := dp.EnsureInterface(name, p.tunnel.InterfaceID, p.tunnel.MTU); err != nil {
			if mode == wirekubev1alpha1.IPsecDataplaneAuto && dp.IsUnsupported(err) {
				a.ipsec.xfrmiUnsupported = true
				a.ipsec.xfrmiReason = err.Error()
				a.log.Info("kernel cannot create XFRM interfaces; Auto tunnels use policy-based steering", "reason", err.Error())
				p.tunnel.RouteBased = false
				continue
			}
			p.err = err
			continue
		}
		p.tunnel.RouteBased = true
		keep[name] = true
	}
	a.chooseCarriers(plans, routes)

	// Guard every elected tunnel, failed ones included: the remote networks
	// are still routed here, and without a CHILD_SA they would leave in
	// plaintext.
	var pairs []ipsec.SelectorPair
	for _, p := range plans {
		if p.tunnel != nil {
			pairs = append(pairs, guardablePairs(p.tunnel)...)
		}
	}
	if err := dp.SyncGuard(pairs); err != nil {
		a.log.Error(err, "syncing IPsec plaintext guard")
		clean = false
		for _, p := range plans {
			if p.tunnel != nil {
				p.guardErr = err
			}
		}
	}
	recordGuardMetrics(dp, pairs)

	if len(keep) > 0 {
		if err := dp.EnsureRule(); err != nil {
			a.log.Error(err, "installing IPsec routing rule")
		}
		if err := enableIPForwarding(); err != nil {
			a.log.Error(err, "enabling IP forwarding for IPsec")
		}
	}
	if err := dp.SyncRoutes(routes, a.ownMeshIP(ctx)); err != nil {
		a.log.Error(err, "syncing IPsec routes")
		clean = false
	}

	present, err := dp.ListInterfaces()
	if err != nil {
		a.log.Error(err, "listing IPsec interfaces")
		clean = false
	}
	for _, name := range present {
		if !keep[name] {
			if err := dp.DeleteInterface(name); err != nil {
				a.log.Error(err, "removing stale IPsec interface", "interface", name)
				clean = false
			}
		}
	}
	if len(keep) == 0 {
		dp.RemoveRule()
	}
	return clean
}

func prefixesOverlap(a, b []string) bool {
	for _, x := range a {
		px, err := netip.ParsePrefix(x)
		if err != nil {
			continue
		}
		for _, y := range b {
			py, err := netip.ParsePrefix(y)
			if err == nil && px.Masked().Overlaps(py.Masked()) {
				return true
			}
		}
	}
	return false
}

// guardablePairs skips unparsable selectors so the rest stay guarded.
func guardablePairs(t *ipsec.Tunnel) []ipsec.SelectorPair {
	var out []ipsec.SelectorPair
	for _, p := range t.Pairs() {
		if _, err := netip.ParsePrefix(p.Local); err != nil {
			continue
		}
		if _, err := netip.ParsePrefix(p.Remote); err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
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

// reconcileCharon loads the planned connections and unloads all others. A
// changed tunnel has a new connection name; its old connection is unloaded
// before the new one loads, since both would offer a key for one identity.
// It reports whether every unload succeeded.
func (a *Agent) reconcileCharon(plans []*tunnelPlan) (bool, error) {
	st := a.ipsec
	loaded, err := st.charon.ListConns()
	if err != nil {
		if len(plans) == 0 {
			// Normal on nodes outside the charon node selector; retried in
			// case it is a restarting charon with tunnels still loaded.
			a.log.V(1).Info("IKE daemon unreachable; retrying the teardown next sync", "reason", err.Error())
			return false, nil
		}
		a.log.Error(err, "IKE daemon unreachable")
		return false, fmt.Errorf("%w; check that the charon DaemonSet runs on this node (chart agent.ipsec.charon.nodeSelector, wirekubectl --charon-node-selector)", err)
	}
	clean := true
	isLoaded := map[string]bool{}
	for _, n := range loaded {
		isLoaded[n] = true
	}

	want := map[string]bool{}
	unload := func(n string) {
		if err := st.charon.UnloadConn(n); err != nil {
			a.log.Error(err, "unloading IPsec tunnel", "connection", n)
			clean = false
			return
		}
		_ = st.charon.UnloadShared(n)
		delete(isLoaded, n)
		delete(st.keys, n)
		a.log.Info("unloaded IPsec tunnel", "connection", n)
	}
	for _, p := range plans {
		if p.err != nil {
			continue
		}
		name := p.tunnel.ConnName()
		want[name] = true
		key := sha256.Sum256([]byte(p.tunnel.PreSharedKey))
		if isLoaded[name] {
			loadedKey, known := st.keys[name]
			switch {
			case known && loadedKey == key:
				continue
			case !known:
				// Loaded before this process started. Reloading the key
				// leaves established SAs alone.
				if err := st.charon.LoadShared(p.tunnel); err != nil {
					p.err = err
				} else {
					st.keys[name] = key
				}
				continue
			default:
				a.log.Info("IPsec pre-shared key changed; reconnecting", "tunnel", p.tunnel.Name)
				unload(name)
				if isLoaded[name] {
					continue
				}
			}
		}
		var stuck string
		for _, n := range loaded {
			if key, _ := ipsec.KeyOfConn(n); key == p.tunnel.Name && isLoaded[n] {
				a.log.Info("IPsec tunnel settings changed; replacing its connection", "tunnel", p.tunnel.Name)
				unload(n)
				if isLoaded[n] {
					stuck = n
				}
			}
		}
		if stuck != "" {
			// Loading the replacement now would leave both definitions,
			// and possibly both SAs, in charon.
			p.err = fmt.Errorf("new settings wait for connection %s to unload", stuck)
			continue
		}
		if err := st.charon.LoadShared(p.tunnel); err != nil {
			p.err = err
			continue
		}
		if err := st.charon.LoadConn(p.tunnel); err != nil {
			// Unloading only walks loaded connections, so drop the key here.
			_ = st.charon.UnloadShared(name)
			p.err = err
			continue
		}
		p.loadedNow = true
		st.keys[name] = key
		dataplane := wirekubev1alpha1.IPsecDataplanePolicy
		if p.tunnel.RouteBased {
			dataplane = wirekubev1alpha1.IPsecDataplaneXFRMInterface
		}
		a.log.Info("loaded IPsec tunnel", "tunnel", p.tunnel.Name, "connection", name, "remote", p.tunnel.RemoteAddress,
			"localID", p.tunnel.LocalID, "dataplane", dataplane)
	}

	for _, n := range loaded {
		if !want[n] && isLoaded[n] {
			unload(n)
		}
	}
	return clean, nil
}

// failureMemory is how long a logged negotiation failure stays in status.
const failureMemory = 10 * time.Minute

// tunnelStatus reads one tunnel's state from charon and re-initiates a loaded
// connection that has no IKE_SA.
func (a *Agent) tunnelStatus(p *tunnelPlan, charonErr error) wirekubev1alpha1.GatewayIPsecTunnelStatus {
	st := wirekubev1alpha1.GatewayIPsecTunnelStatus{Name: p.spec.Name, Carrier: p.carrier && p.err == nil}
	if p.tunnel != nil {
		if p.tunnel.RouteBased {
			st.Dataplane = wirekubev1alpha1.IPsecDataplaneXFRMInterface
			st.InterfaceID = int64(p.tunnel.InterfaceID)
			st.InterfaceName = ipsec.InterfaceName(p.tunnel.InterfaceID)
		} else if p.err == nil {
			st.Dataplane = wirekubev1alpha1.IPsecDataplanePolicy
		}
		st.LocalID = p.tunnel.LocalID
		st.LocalTrafficSelectors = p.tunnel.LocalTS
		st.RemoteTrafficSelectors = p.tunnel.RemoteTS
	}
	switch {
	case p.err != nil:
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Message = p.err.Error()
	case charonErr != nil:
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Message = charonErr.Error()
	default:
		conn := p.tunnel.ConnName()
		sa, err := a.ipsec.charon.SA(conn)
		if err != nil {
			st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
			st.Message = err.Error()
			break
		}
		if sa.IKEState == "" && !p.loadedNow {
			// charon does not retry after giving up or after a local delete.
			if err := a.ipsec.charon.Initiate(conn); err != nil {
				a.log.Error(err, "initiating IPsec tunnel", "tunnel", p.tunnel.Name)
			}
		}
		st.IKEState = sa.IKEState
		st.InstalledChildSAs = int32(sa.InstalledChildSAs)
		if sa.InstalledChildSAs > 0 {
			st.Phase = wirekubev1alpha1.IPsecTunnelPhaseEstablished
			a.ipsec.failures.Forget(conn)
		} else {
			st.Phase = wirekubev1alpha1.IPsecTunnelPhaseConnecting
			if f, ok := a.ipsec.failures.Last(conn, time.Now().Add(-failureMemory)); ok {
				st.Message = fmt.Sprintf("%s (charon: %s)", f.Reason, f.Log)
			} else if !p.loadedNow {
				st.Message = "no CHILD_SA yet; check the remote gateway's settings and the charon log"
			}
		}
	}
	if p.guardErr != nil && st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Message = fmt.Sprintf("plaintext guard not installed (%v); traffic for this tunnel can leave unencrypted while no SA covers it", p.guardErr)
	}
	return st
}

func (a *Agent) writeActiveStatus(ctx context.Context, plans []*tunnelPlan, charonErr error) {
	byGateway := map[string][]*tunnelPlan{}
	gateways := map[string]*wirekubev1alpha1.WireKubeGateway{}
	for _, p := range plans {
		byGateway[p.gw.Name] = append(byGateway[p.gw.Name], p)
		gateways[p.gw.Name] = p.gw
	}
	for name, ps := range byGateway {
		statuses := map[string]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
		for _, p := range ps {
			statuses[p.spec.Name] = a.tunnelStatus(p, charonErr)
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
	prev := map[string]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
	for _, st := range gw.Status.IPsec {
		prev[st.Name] = st
	}
	now := metav1.NewTime(time.Now())
	for i := range next {
		old, ok := prev[next[i].Name]
		if ok && old.Phase == next[i].Phase && old.LastTransitionTime != nil {
			next[i].LastTransitionTime = old.LastTransitionTime
		} else {
			next[i].LastTransitionTime = &now
		}
	}
	summary := ipsecSummary(next)
	if gw.Status.Ready == ready && gw.Status.IPsecSummary == summary && tunnelStatusesEqual(gw.Status.IPsec, next) {
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

// ipsecSummary is the kubectl get column, e.g. "1/2 Established".
func ipsecSummary(tunnels []wirekubev1alpha1.GatewayIPsecTunnelStatus) string {
	if len(tunnels) == 0 {
		return ""
	}
	established := 0
	same := true
	for _, t := range tunnels {
		if t.Phase == wirekubev1alpha1.IPsecTunnelPhaseEstablished {
			established++
		}
		same = same && t.Phase == tunnels[0].Phase
	}
	if established == 0 && same {
		return string(tunnels[0].Phase)
	}
	return fmt.Sprintf("%d/%d Established", established, len(tunnels))
}

func tunnelStatusesEqual(a, b []wirekubev1alpha1.GatewayIPsecTunnelStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Name != y.Name || x.Phase != y.Phase || x.Carrier != y.Carrier || x.Dataplane != y.Dataplane || x.InterfaceName != y.InterfaceName ||
			x.InterfaceID != y.InterfaceID || x.IKEState != y.IKEState || x.InstalledChildSAs != y.InstalledChildSAs ||
			x.LocalID != y.LocalID || x.Message != y.Message ||
			!equalStrings(x.LocalTrafficSelectors, y.LocalTrafficSelectors) ||
			!equalStrings(x.RemoteTrafficSelectors, y.RemoteTrafficSelectors) {
			return false
		}
		if (x.LastTransitionTime == nil) != (y.LastTransitionTime == nil) ||
			(x.LastTransitionTime != nil && !x.LastTransitionTime.Equal(y.LastTransitionTime)) {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
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
