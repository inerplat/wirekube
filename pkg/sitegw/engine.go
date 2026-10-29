// Package sitegw terminates site-to-site IPsec tunnels. Its Engine applies a
// set of tunnel plans to charon and the kernel and reports each tunnel's
// state. The WireKube agent drives it for gateway peers; cmd/sitegw drives it
// on its own, without the mesh, for one network namespace.
package sitegw

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/go-logr/logr"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

// Dataplane is the kernel side of IPsec termination, an interface so the
// engine is testable without netlink.
type Dataplane interface {
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

// KernelDataplane is the Dataplane of the running kernel. A non-empty
// InputInterface sends only traffic arriving on it into the tunnels, and
// then the guard covers forwarded traffic only.
type KernelDataplane struct{ InputInterface string }

func (d KernelDataplane) EnsureRule() error { return ipsec.EnsureRule(d.InputInterface) }
func (KernelDataplane) RemoveRule()         { ipsec.RemoveRule() }
func (KernelDataplane) EnsureInterface(n string, id uint32, mtu int) error {
	return ipsec.EnsureInterface(n, id, mtu)
}
func (KernelDataplane) DeleteInterface(n string) error    { return ipsec.DeleteInterface(n) }
func (KernelDataplane) ListInterfaces() ([]string, error) { return ipsec.ListInterfaces() }
func (KernelDataplane) SyncRoutes(d map[string][]string, src net.IP) error {
	return ipsec.SyncRoutes(d, src)
}
func (KernelDataplane) IsUnsupported(err error) bool { return ipsec.IsUnsupported(err) }
func (KernelDataplane) XFRMInterfaceBlocker() string { return ipsec.XFRMInterfaceBlocker() }
func (KernelDataplane) GuardDrops() (map[ipsec.SelectorPair]uint64, error) {
	return ipsec.GuardDrops()
}
func (d KernelDataplane) SyncGuard(p []ipsec.SelectorPair) error {
	if d.InputInterface != "" {
		return ipsec.SyncGuard(p, []string{"FORWARD"})
	}
	return ipsec.SyncGuard(p, nil)
}

// Plan is one tunnel to terminate, or the reason it cannot be.
type Plan struct {
	// Group owns the tunnel: a WireKubeGateway, or a site gateway's
	// connection. Plans are ordered by Group, then Index.
	Group string
	// Name is the tunnel's name within its group.
	Name string
	// Index is the tunnel's position in its group; earlier tunnels are
	// preferred as carriers.
	Index     int
	Dataplane wirekubev1alpha1.IPsecDataplane
	// LastPhase is the phase the tunnel last reported. Empty falls back to
	// what this engine saw at its previous sync.
	LastPhase wirekubev1alpha1.IPsecTunnelPhase
	Tunnel    *ipsec.Tunnel
	Err       error

	// carrier marks the one tunnel of a redundancy group that gets the routes.
	carrier bool
	// loadedNow means start_action already started it this sync.
	loadedNow bool
	// guardErr is why the plaintext guard for this tunnel is not installed.
	// The connection stays loaded, since an SA still encrypts the traffic
	// the routes keep pulling here, but the tunnel reports Error.
	guardErr error
}

// Engine applies plans to charon and the kernel. It is not safe for
// concurrent use.
type Engine struct {
	Charon    ipsec.Charon
	Dataplane Dataplane
	Failures  *ipsec.FailureWatcher // may be nil
	Log       logr.Logger
	// RouteSource is the source address of routes into XFRM interfaces:
	// traffic the gateway originates must match the local selectors.
	RouteSource func() net.IP
	// EnableForwarding turns IP forwarding on when an XFRM interface is in
	// use; nil leaves forwarding alone.
	EnableForwarding func() error
	// OnGuard receives the guarded pairs after each sync; nil ignores them.
	OnGuard func(dp Dataplane, pairs []ipsec.SelectorPair)
	// CharonHint is appended to the error when charon is unreachable.
	CharonHint string

	// active keeps the teardown path running until it is confirmed. It
	// starts true so the first sync removes what a previous process left.
	active bool
	// xfrmiUnsupported sends Auto tunnels to policy mode; xfrmiReason says why.
	xfrmiUnsupported bool
	xfrmiReason      string
	xfrmiChecked     bool
	// keys holds a digest of each loaded connection's pre-shared key, so a
	// key change reconnects. Never logged.
	keys map[string][sha256.Size]byte
	// phases is each tunnel's phase at the previous sync, by tunnel key.
	phases map[string]wirekubev1alpha1.IPsecTunnelPhase
	// failureLogged is the charon line last logged for each connection.
	failureLogged map[string]string
}

// NewEngine returns an engine whose first sync clears what an earlier
// process left in charon and the kernel.
func NewEngine(charon ipsec.Charon, dp Dataplane, failures *ipsec.FailureWatcher, log logr.Logger) *Engine {
	return &Engine{Charon: charon, Dataplane: dp, Failures: failures, Log: log, active: true}
}

// Active reports whether the engine holds, or may still hold, tunnel state.
// With no plans and no state left, a caller may skip the sync.
func (e *Engine) Active() bool { return e.active }

// SetActive forces the next sync to run the teardown path.
func (e *Engine) SetActive(v bool) { e.active = v }

// ForgetKeys makes the next sync reload every pre-shared key, as after a
// restart.
func (e *Engine) ForgetKeys() { e.keys = map[string][sha256.Size]byte{} }

func (e *Engine) init() {
	if e.keys == nil {
		e.keys = map[string][sha256.Size]byte{}
	}
	if e.phases == nil {
		e.phases = map[string]wirekubev1alpha1.IPsecTunnelPhase{}
	}
	if e.failureLogged == nil {
		e.failureLogged = map[string]string{}
	}
}

// Result is the outcome of a sync.
type Result struct {
	// Statuses are the tunnels' states, in the order of the plans.
	Statuses []wirekubev1alpha1.GatewayIPsecTunnelStatus
	// CharonErr is set when charon could not be reached.
	CharonErr error
}

// Sync applies plans, which must have passed Validate, and reports each
// tunnel's state. A connection charon holds no IKE_SA for is initiated
// again here, since charon does not retry after giving up.
func (e *Engine) Sync(plans []*Plan) Result {
	e.init()
	dataplaneClean := e.reconcileDataplane(plans)
	charonClean, charonErr := e.reconcileCharon(plans)
	res := Result{CharonErr: charonErr, Statuses: make([]wirekubev1alpha1.GatewayIPsecTunnelStatus, len(plans))}
	seen := map[string]bool{}
	for i, p := range plans {
		var sa ipsec.SAState
		var saErr error
		if p.Err == nil && charonErr == nil {
			sa, saErr = e.observe(p)
		}
		res.Statuses[i] = e.tunnelStatus(p, sa, saErr, charonErr)
		if p.Tunnel != nil {
			e.phases[p.Tunnel.Name] = res.Statuses[i].Phase
			seen[p.Tunnel.Name] = true
			seen[p.Tunnel.ConnName()] = true
		}
	}
	for k := range e.phases {
		if !seen[k] {
			delete(e.phases, k)
		}
	}
	for k := range e.failureLogged {
		if !seen[k] {
			delete(e.failureLogged, k)
		}
	}
	e.active = len(plans) > 0 || !dataplaneClean || charonErr != nil || !charonClean
	return res
}

// observe reads a loaded tunnel's SAs and initiates it when charon holds no
// IKE_SA for it.
func (e *Engine) observe(p *Plan) (ipsec.SAState, error) {
	conn := p.Tunnel.ConnName()
	sa, err := e.Charon.SA(conn)
	if err != nil {
		return sa, err
	}
	if sa.IKEState == "" && !p.loadedNow {
		// charon does not retry after giving up or after a local delete.
		if err := e.Charon.Initiate(conn); err != nil {
			e.Log.Error(err, "initiating IPsec tunnel", "tunnel", p.Tunnel.Name)
		}
	}
	return sa, nil
}

// Validate orders plans and fails the ones that clash with an earlier one:
// a shared interface ID, partly overlapping remote selectors, or a remote
// identity used with two keys.
func Validate(plans []*Plan) {
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].Group != plans[j].Group {
			return plans[i].Group < plans[j].Group
		}
		return plans[i].Index < plans[j].Index
	})
	rejectIPv6Selectors(plans)
	rejectDuplicateInterfaceIDs(plans)
	rejectOverlappingRemoteSelectors(plans)
	rejectConflictingKeys(plans)
}

// rejectIPv6Selectors fails tunnels with IPv6 selectors: the plaintext
// guard covers IPv4 only, so such a tunnel could leak when its SA is gone.
func rejectIPv6Selectors(plans []*Plan) {
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		for _, c := range append(append([]string{}, p.Tunnel.LocalTS...), p.Tunnel.RemoteTS...) {
			if pfx, err := netip.ParsePrefix(c); err == nil && !pfx.Addr().Is4() {
				p.Err = fmt.Errorf("traffic selector %s is not IPv4; IPsec tunnels carry IPv4 only", c)
				break
			}
		}
	}
}

func rejectDuplicateInterfaceIDs(plans []*Plan) {
	byID := map[uint32]*Plan{}
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		if q, dup := byID[p.Tunnel.InterfaceID]; dup {
			p.Err = fmt.Errorf("interface ID %d is also used by tunnel %s; set interfaceID", p.Tunnel.InterfaceID, q.Tunnel.Name)
			continue
		}
		byID[p.Tunnel.InterfaceID] = p
	}
}

// rejectOverlappingRemoteSelectors fails partial overlaps between tunnels.
// Identical selectors are allowed: they form a redundancy group.
func rejectOverlappingRemoteSelectors(plans []*Plan) {
	var seen []*Plan
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		for _, q := range seen {
			if prefixesOverlap(p.Tunnel.RemoteTS, q.Tunnel.RemoteTS) && !samePrefixSet(p.Tunnel.RemoteTS, q.Tunnel.RemoteTS) {
				p.Err = fmt.Errorf("remote selectors partly overlap tunnel %s on this node; use identical selectors for redundant tunnels, or disjoint ones", q.Tunnel.Name)
				break
			}
		}
		if p.Err == nil {
			seen = append(seen, p)
		}
	}
}

// rejectConflictingKeys fails tunnels that share a remote identity but not a
// key: charon scopes keys to the identity, so either key could match.
func rejectConflictingKeys(plans []*Plan) {
	keyByID := map[string]*Plan{}
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		id := p.Tunnel.RemoteID
		if id == "" {
			id = p.Tunnel.RemoteAddress
		}
		if q, ok := keyByID[id]; ok && q.Tunnel.PreSharedKey != p.Tunnel.PreSharedKey {
			p.Err = fmt.Errorf("remote identity %s is also used by tunnel %s with a different pre-shared key", id, q.Tunnel.Name)
			continue
		}
		keyByID[id] = p
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

func redundancyGroups(plans []*Plan) [][]*Plan {
	var groups [][]*Plan
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		placed := false
		for i := range groups {
			if samePrefixSet(groups[i][0].Tunnel.RemoteTS, p.Tunnel.RemoteTS) {
				groups[i] = append(groups[i], p)
				placed = true
				break
			}
		}
		if !placed {
			groups = append(groups, []*Plan{p})
		}
	}
	return groups
}

// lastPhase is the tunnel's phase at the last sync. Unknown, which only an
// observer writes, says nothing about the tunnel and is skipped.
func (e *Engine) lastPhase(p *Plan) wirekubev1alpha1.IPsecTunnelPhase {
	if p.LastPhase != "" && p.LastPhase != wirekubev1alpha1.IPsecTunnelPhaseUnknown {
		return p.LastPhase
	}
	return e.phases[p.Tunnel.Name]
}

// hasChildSA reports whether charon has a CHILD_SA installed for the tunnel.
func (e *Engine) hasChildSA(p *Plan) bool {
	sa, err := e.Charon.SA(p.Tunnel.ConnName())
	return err == nil && sa.InstalledChildSAs > 0
}

// chooseCarriers routes each redundancy group into its first tunnel that was
// Established at the last sync, or its first tunnel. Policy mode cannot steer
// between identical selectors, so such a group keeps only its first tunnel.
func (e *Engine) chooseCarriers(plans []*Plan, routes map[string][]string) {
	for _, group := range redundancyGroups(plans) {
		if len(group) > 1 {
			for _, p := range group {
				if !p.Tunnel.RouteBased {
					for _, q := range group[1:] {
						q.Err = fmt.Errorf("redundant tunnels (identical remote selectors as %s) need the XFRMInterface dataplane, and this tunnel group runs in policy mode%s",
							group[0].Tunnel.Name, e.policyModeReason())
					}
					group = group[:1]
					break
				}
			}
		}
		var carrier *Plan
		for _, p := range group {
			if e.lastPhase(p) == wirekubev1alpha1.IPsecTunnelPhaseEstablished {
				carrier = p
				break
			}
		}
		if carrier == nil && len(group) > 1 {
			// No phase to go by, as after a restart: keep the routes on a
			// tunnel charon still has SAs for.
			for _, p := range group {
				if e.hasChildSA(p) {
					carrier = p
					break
				}
			}
		}
		if carrier == nil {
			carrier = group[0]
		}
		carrier.carrier = true
		if carrier.Tunnel.RouteBased {
			routes[ipsec.InterfaceName(carrier.Tunnel.InterfaceID)] = carrier.Tunnel.RemoteTS
		}
	}
}

func (e *Engine) policyModeReason() string {
	if e.xfrmiReason != "" {
		return " because XFRM interfaces are unavailable: " + e.xfrmiReason
	}
	return ""
}

// PolicyModeReason says why Auto tunnels run in policy mode, or "".
func (e *Engine) PolicyModeReason() string { return e.xfrmiReason }

// reconcileDataplane syncs XFRM interfaces, routes and the guard with the
// plans, and reports whether every step succeeded. Plans with errors get no
// interface, so they do not blackhole their remote networks.
func (e *Engine) reconcileDataplane(plans []*Plan) bool {
	clean := true
	dp := e.Dataplane
	routes := map[string][]string{}
	keep := map[string]bool{}
	if !e.xfrmiChecked {
		e.xfrmiChecked = true
		if reason := dp.XFRMInterfaceBlocker(); reason != "" {
			e.xfrmiUnsupported = true
			e.xfrmiReason = reason
			e.Log.Info("XFRM interfaces unavailable; Auto tunnels use policy-based steering", "reason", reason)
		}
	}
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		mode := p.Dataplane
		if mode == "" {
			mode = wirekubev1alpha1.IPsecDataplaneAuto
		}
		if mode == wirekubev1alpha1.IPsecDataplanePolicy ||
			(mode == wirekubev1alpha1.IPsecDataplaneAuto && e.xfrmiUnsupported) {
			p.Tunnel.RouteBased = false
			continue
		}
		if e.xfrmiReason != "" {
			// Trying would remove the node's SAs; see XFRMInterfaceBlocker.
			p.Err = fmt.Errorf("the XFRMInterface dataplane is unavailable: %s; use Auto or Policy", e.xfrmiReason)
			continue
		}
		name := ipsec.InterfaceName(p.Tunnel.InterfaceID)
		if err := dp.EnsureInterface(name, p.Tunnel.InterfaceID, p.Tunnel.MTU); err != nil {
			if mode == wirekubev1alpha1.IPsecDataplaneAuto && dp.IsUnsupported(err) {
				e.xfrmiUnsupported = true
				e.xfrmiReason = err.Error()
				e.Log.Info("kernel cannot create XFRM interfaces; Auto tunnels use policy-based steering", "reason", err.Error())
				p.Tunnel.RouteBased = false
				continue
			}
			p.Err = dataplaneFailure(err)
			continue
		}
		p.Tunnel.RouteBased = true
		keep[name] = true
	}
	e.chooseCarriers(plans, routes)

	// Guard every planned tunnel, failed ones included: the remote networks
	// are still routed here, and without a CHILD_SA they would leave in
	// plaintext.
	var pairs []ipsec.SelectorPair
	for _, p := range plans {
		if p.Tunnel != nil {
			pairs = append(pairs, GuardablePairs(p.Tunnel)...)
		}
	}
	if err := dp.SyncGuard(pairs); err != nil {
		e.Log.Error(err, "syncing IPsec plaintext guard")
		clean = false
		for _, p := range plans {
			if p.Tunnel != nil {
				p.guardErr = err
			}
		}
	}
	if e.OnGuard != nil {
		e.OnGuard(dp, pairs)
	}

	if len(keep) > 0 {
		if err := dp.EnsureRule(); err != nil {
			e.Log.Error(err, "installing IPsec routing rule")
		}
		if e.EnableForwarding != nil {
			if err := e.EnableForwarding(); err != nil {
				e.Log.Error(err, "enabling IP forwarding for IPsec")
			}
		}
	}
	var src net.IP
	if e.RouteSource != nil {
		src = e.RouteSource()
	}
	if err := dp.SyncRoutes(routes, src); err != nil {
		e.Log.Error(err, "syncing IPsec routes")
		clean = false
	}

	present, err := dp.ListInterfaces()
	if err != nil {
		e.Log.Error(err, "listing IPsec interfaces")
		clean = false
	}
	for _, name := range present {
		if !keep[name] {
			if err := dp.DeleteInterface(name); err != nil {
				e.Log.Error(err, "removing stale IPsec interface", "interface", name)
				clean = false
			}
		}
	}
	if len(keep) == 0 {
		dp.RemoveRule()
	}
	return clean
}

// GuardablePairs returns a tunnel's selector pairs, skipping unparsable
// selectors so the rest stay guarded.
func GuardablePairs(t *ipsec.Tunnel) []ipsec.SelectorPair {
	var out []ipsec.SelectorPair
	for _, p := range t.Pairs() {
		// The guard is iptables, IPv4 only; IPv6 tunnels are refused
		// elsewhere and their pairs would fail the whole guard.
		l, err := netip.ParsePrefix(p.Local)
		if err != nil || !l.Addr().Is4() {
			continue
		}
		r, err := netip.ParsePrefix(p.Remote)
		if err != nil || !r.Addr().Is4() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// reconcileCharon loads the planned connections and unloads all others. A
// changed tunnel has a new connection name; its old connection is unloaded
// before the new one loads, since both would offer a key for one identity.
// It reports whether every unload succeeded.
func (e *Engine) reconcileCharon(plans []*Plan) (bool, error) {
	loaded, err := e.Charon.ListConns()
	if err != nil {
		if len(plans) == 0 {
			// Normal where no charon runs; retried in case it is a
			// restarting charon with tunnels still loaded.
			e.Log.V(1).Info("IKE daemon unreachable; retrying the teardown next sync", "reason", err.Error())
			return false, nil
		}
		e.Log.Error(err, "IKE daemon unreachable")
		if e.CharonHint != "" {
			return false, fmt.Errorf("%w; %s", err, e.CharonHint)
		}
		return false, err
	}
	clean := true
	isLoaded := map[string]bool{}
	for _, n := range loaded {
		isLoaded[n] = true
	}

	want := map[string]bool{}
	unload := func(n string) {
		if err := e.Charon.UnloadConn(n); err != nil {
			e.Log.Error(err, "unloading IPsec tunnel", "connection", n)
			clean = false
			return
		}
		_ = e.Charon.UnloadShared(n)
		delete(isLoaded, n)
		delete(e.keys, n)
		e.Log.Info("unloaded IPsec tunnel", "connection", n)
	}
	for _, p := range plans {
		if p.Err != nil {
			continue
		}
		name := p.Tunnel.ConnName()
		want[name] = true
		key := sha256.Sum256([]byte(p.Tunnel.PreSharedKey))
		if isLoaded[name] {
			loadedKey, known := e.keys[name]
			switch {
			case known && loadedKey == key:
				continue
			case !known:
				// Loaded before this process started. Reloading the key
				// leaves established SAs alone.
				if err := e.Charon.LoadShared(p.Tunnel); err != nil {
					p.Err = charonFailure(err)
				} else {
					e.keys[name] = key
				}
				continue
			default:
				e.Log.Info("IPsec pre-shared key changed; reconnecting", "tunnel", p.Tunnel.Name)
				unload(name)
				if isLoaded[name] {
					continue
				}
			}
		}
		var stuck string
		for _, n := range loaded {
			if key, _ := ipsec.KeyOfConn(n); key == p.Tunnel.Name && isLoaded[n] {
				e.Log.Info("IPsec tunnel settings changed; replacing its connection", "tunnel", p.Tunnel.Name)
				unload(n)
				if isLoaded[n] {
					stuck = n
				}
			}
		}
		if stuck != "" {
			// Loading the replacement now would leave both definitions,
			// and possibly both SAs, in charon.
			p.Err = charonFailure(fmt.Errorf("new settings wait for connection %s to unload", stuck))
			continue
		}
		if err := e.Charon.LoadShared(p.Tunnel); err != nil {
			p.Err = charonFailure(err)
			continue
		}
		if err := e.Charon.LoadConn(p.Tunnel); err != nil {
			// Unloading only walks loaded connections, so drop the key here.
			_ = e.Charon.UnloadShared(name)
			p.Err = charonFailure(err)
			continue
		}
		p.loadedNow = true
		e.keys[name] = key
		dataplane := wirekubev1alpha1.IPsecDataplanePolicy
		if p.Tunnel.RouteBased {
			dataplane = wirekubev1alpha1.IPsecDataplaneXFRMInterface
		}
		e.Log.Info("loaded IPsec tunnel", "tunnel", p.Tunnel.Name, "connection", name, "remote", p.Tunnel.RemoteAddress,
			"localID", p.Tunnel.LocalID, "dataplane", dataplane)
	}

	for _, n := range loaded {
		if !want[n] && isLoaded[n] {
			unload(n)
		}
	}
	return clean, nil
}

// Runtime failures, as opposed to a tunnel that cannot be applied as
// specified, are wrapped in these so status names the right cause.
var (
	errCharonCall = errors.New("IKE daemon")
	errDataplane  = errors.New("dataplane")
)

// charonFailure marks err as charon's unavailability, unless charon answered
// and refused what the tunnel asks for, which is the tunnel's problem.
func charonFailure(err error) error {
	if errors.Is(err, ipsec.ErrRejected) {
		return err
	}
	return fmt.Errorf("%w: %w", errCharonCall, err)
}
func dataplaneFailure(err error) error { return fmt.Errorf("%w: %w", errDataplane, err) }

// failureMemory is how long a logged negotiation failure stays in status.
const failureMemory = 10 * time.Minute

// ErrNoChildSA is the message of a loaded tunnel that is not up and whose
// failure charon has not explained.
var ErrNoChildSA = errors.New("no CHILD_SA yet; check the remote gateway's settings and the charon log")

// tunnelStatus is one tunnel's state from the plan and what charon said. It
// has no side effects on charon.
func (e *Engine) tunnelStatus(p *Plan, sa ipsec.SAState, saErr, charonErr error) wirekubev1alpha1.GatewayIPsecTunnelStatus {
	st := wirekubev1alpha1.GatewayIPsecTunnelStatus{Name: p.Name, Carrier: p.carrier && p.Err == nil}
	if p.Tunnel != nil {
		if p.Tunnel.RouteBased {
			st.Dataplane = wirekubev1alpha1.IPsecDataplaneXFRMInterface
			st.InterfaceID = int64(p.Tunnel.InterfaceID)
			st.InterfaceName = ipsec.InterfaceName(p.Tunnel.InterfaceID)
		} else if p.Err == nil {
			st.Dataplane = wirekubev1alpha1.IPsecDataplanePolicy
		}
		st.LocalID = p.Tunnel.LocalID
		st.LocalTrafficSelectors = p.Tunnel.LocalTS
		st.RemoteTrafficSelectors = p.Tunnel.RemoteTS
	}
	switch {
	case p.Err != nil:
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Message = p.Err.Error()
		switch {
		case errors.Is(p.Err, errCharonCall):
			st.Reason = wirekubev1alpha1.IPsecReasonIKEDaemonUnavailable
		case errors.Is(p.Err, errDataplane):
			st.Reason = wirekubev1alpha1.IPsecReasonDataplaneError
		default:
			st.Reason = wirekubev1alpha1.IPsecReasonConfigError
		}
	case charonErr != nil:
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Reason = wirekubev1alpha1.IPsecReasonIKEDaemonUnavailable
		st.Message = charonErr.Error()
	case saErr != nil:
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Reason = wirekubev1alpha1.IPsecReasonIKEDaemonUnavailable
		st.Message = saErr.Error()
	default:
		conn := p.Tunnel.ConnName()
		st.IKEState = sa.IKEState
		st.InstalledChildSAs = int32(sa.InstalledChildSAs)
		if sa.InstalledChildSAs > 0 {
			st.Phase = wirekubev1alpha1.IPsecTunnelPhaseEstablished
			e.Failures.Forget(conn)
			delete(e.failureLogged, conn)
			break
		}
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseConnecting
		if f, ok := e.Failures.Last(conn, time.Now().Add(-failureMemory)); ok {
			st.Reason = f.Code
			st.Message = f.Reason
			// The charon line goes to the log, not to status: it changes
			// with every attempt and may carry what the peer sent.
			if e.failureLogged[conn] != f.Log {
				e.failureLogged[conn] = f.Log
				e.Log.Info("IPsec negotiation failed", "tunnel", p.Tunnel.Name, "reason", f.Code, "charon", f.Log)
			}
		} else if !p.loadedNow {
			st.Message = ErrNoChildSA.Error()
		}
	}
	if p.guardErr != nil && st.Phase != wirekubev1alpha1.IPsecTunnelPhaseError {
		st.Phase = wirekubev1alpha1.IPsecTunnelPhaseError
		st.Reason = wirekubev1alpha1.IPsecReasonGuardNotInstalled
		st.Message = fmt.Sprintf("plaintext guard not installed (%v); traffic for this tunnel can leave unencrypted while no SA covers it", p.guardErr)
	}
	return st
}
