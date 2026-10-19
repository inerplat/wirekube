package connect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/externalpeer"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

const (
	// ClientLabel marks external peers a connect session issued, so a rerun
	// may replace its own leftover but never an operator-issued peer.
	ClientLabel = "wirekube.io/client"
	// ClientLabelValue is the ClientLabel value connect writes.
	ClientLabelValue = "connect"
	// HostAnnotation records which machine issued the peer.
	HostAnnotation = "wirekube.io/connect-host"

	handshakeWarnAfter = 30 * time.Second
	cleanupTimeout     = 30 * time.Second
)

// Options configures a connect session.
type Options struct {
	Name          string
	Host          string
	TTL           time.Duration
	Allowed       []string
	IngressPeer   string
	MTU           int32
	WaitActive    time.Duration
	InterfaceName string

	DNS             bool
	DNSServer       string
	ClusterDomain   string
	SearchNamespace string

	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	Out               io.Writer

	// OpenDataplane, Resolve, LocalPrefixes and Now are overridable for tests.
	OpenDataplane func(ifName string, mtu int, privateKey [32]byte) (Dataplane, error)
	Resolve       func(ctx context.Context, hostport string) (netip.AddrPort, error)
	LocalPrefixes func() []netip.Prefix
	Now           func() time.Time
}

// Run carries cluster traffic through a peer issued for this host until ctx ends
// or the peer is removed, then tears everything down. It heartbeats the peer, and
// issues a fresh one if the machine went quiet long enough to lose it.
func Run(ctx context.Context, c client.Client, opts Options) (err error) {
	opts.defaults()
	kp, err := wireguard.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	s := &session{opts: &opts, c: c, privateKey: kp.Private, publicKey: kp.PublicKeyBase64()}
	defer func() {
		if s.dp != nil {
			if closeErr := s.dp.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("restore host network: %w", closeErr))
			}
		}
		if s.peer == nil {
			return
		}
		// ctx is usually already cancelled here, since that is how a session
		// ends; the delete still has to go through.
		delCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		if delErr := deleteOwnPeer(delCtx, c, s.peer); delErr != nil {
			err = errors.Join(err, fmt.Errorf("remove external peer %s: %w", opts.Name, delErr))
		}
	}()

	if opts.TTL > 0 {
		s.deadline = opts.Now().Add(opts.TTL)
	}
	if err := s.establish(ctx); err != nil {
		return err
	}
	for {
		err := s.watch(ctx)
		if !errors.Is(err, errStale) {
			return err
		}
		fmt.Fprintf(opts.Out, "%v; issuing a fresh external peer\n", err)
		for {
			err := s.establish(ctx)
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, errSessionExpired) {
				return err
			}
			// The usual cause is the network still coming back after a
			// resume, so keep trying rather than ending the session.
			fmt.Fprintf(opts.Out, "warning: reissue failed, retrying: %v\n", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(opts.PollInterval):
			}
		}
	}
}

// errStale means this session went quiet long enough that the controller
// has reclaimed, or is about to reclaim, its peer.
var errStale = errors.New("session went quiet")

// errSessionExpired means the session reached its --ttl, which no reissue
// may extend.
var errSessionExpired = errors.New("session reached its --ttl")

type session struct {
	opts       *Options
	c          client.Client
	privateKey [32]byte
	publicKey  string

	dp       Dataplane
	mtu      int
	peer     *wirekubev1alpha1.WireKubeExternalPeer
	cfg      TunnelConfig
	endpoint netip.AddrPort
	dnsDone  bool

	// deadline is when --ttl ends the session; zero without one. A
	// reissued peer gets only what is left of it.
	deadline time.Time

	issuedAt  time.Time
	lastBeat  time.Time
	lastTick  time.Time
	connected bool
	warned    bool
	mtuWarned bool
}

// staleAfter is how long the session may go without a successful heartbeat
// before it assumes its peer is gone. It is a beat short of the controller's
// timeout so the session moves first rather than racing the reclaim.
func (o *Options) staleAfter() time.Duration {
	return wirekubev1alpha1.ExternalPeerHeartbeatTimeout - o.HeartbeatInterval
}

// establish issues the session's peer, waits for the controller to activate
// it, and programs the dataplane for it, opening the dataplane on first use.
func (s *session) establish(ctx context.Context) error {
	o := s.opts
	if err := replaceLeftover(ctx, s.c, o.Name, o.WaitActive); err != nil {
		return err
	}
	now := o.Now()
	peerOpts := *o
	if !s.deadline.IsZero() {
		left := s.deadline.Sub(now)
		if left <= 0 {
			return errSessionExpired
		}
		peerOpts.TTL = left.Truncate(time.Second) + time.Second
	}
	cr := newPeer(peerOpts, s.publicKey)
	cr.Annotations[wirekubev1alpha1.ExternalPeerHeartbeatAnnotation] = beatValue(now)
	if err := s.c.Create(ctx, cr); err != nil {
		return fmt.Errorf("create WireKubeExternalPeer %s: %w", o.Name, err)
	}
	s.peer, s.issuedAt, s.lastBeat, s.lastTick = cr, now, now, now
	s.connected, s.warned = false, false
	fmt.Fprintf(o.Out, "issued external peer %s, waiting for the controller\n", o.Name)

	active, err := externalpeer.WaitForActive(ctx, s.c, o.Name, o.WaitActive)
	if err != nil {
		return err
	}
	cfg, err := ConfigFromStatus(active)
	if err != nil {
		return err
	}
	endpoint, err := o.resolveEndpoint(ctx, cfg)
	if err != nil {
		return err
	}
	if s.dp == nil {
		dp, err := o.OpenDataplane(o.InterfaceName, cfg.MTU, s.privateKey)
		if err != nil {
			return err
		}
		s.dp, s.mtu = dp, cfg.MTU
	}
	s.pinMTU(&cfg)
	warnings, err := s.dp.Apply(cfg, endpoint)
	s.reportWarnings(warnings)
	if err != nil {
		return err
	}
	s.cfg, s.endpoint = cfg, endpoint
	o.reportConfig(s.dp.Name(), cfg, endpoint, active.Status.IngressPeerName)

	if o.DNS && !s.dnsDone {
		o.configureDNS(ctx, s.c, s.dp)
		s.dnsDone = true
	}
	fmt.Fprintln(o.Out, "connected; press Ctrl-C to disconnect")
	return nil
}

// pinMTU holds cfg to the MTU the interface was created with, which cannot
// change without recreating it.
func (s *session) pinMTU(cfg *TunnelConfig) {
	if cfg.MTU == s.mtu {
		return
	}
	if !s.mtuWarned {
		fmt.Fprintf(s.opts.Out, "warning: peer MTU is now %d; reconnect to apply it\n", cfg.MTU)
		s.mtuWarned = true
	}
	cfg.MTU = s.mtu
}

func (s *session) reportWarnings(warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(s.opts.Out, "warning: %s\n", w)
	}
}

func beatValue(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (o *Options) defaults() {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.WaitActive == 0 {
		o.WaitActive = 60 * time.Second
	}
	if o.PollInterval == 0 {
		o.PollInterval = 10 * time.Second
	}
	if o.HeartbeatInterval == 0 {
		o.HeartbeatInterval = 30 * time.Second
	}
	if o.Now == nil {
		// Wall clock on purpose: a monotonic reading does not advance while
		// the machine is suspended, which is exactly the gap to detect.
		o.Now = func() time.Time { return time.Now().Round(0) }
	}
	if o.InterfaceName == "" {
		o.InterfaceName = DefaultInterfaceName
	}
	if o.ClusterDomain == "" {
		o.ClusterDomain = "cluster.local"
	}
	if o.SearchNamespace == "" {
		o.SearchNamespace = "default"
	}
	if o.OpenDataplane == nil {
		o.OpenDataplane = OpenDataplane
	}
	if o.Resolve == nil {
		o.Resolve = resolveUDP
	}
	if o.LocalPrefixes == nil {
		o.LocalPrefixes = localPrefixes
	}
}

func newPeer(opts Options, publicKey string) *wirekubev1alpha1.WireKubeExternalPeer {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        opts.Name,
			Labels:      map[string]string{ClientLabel: ClientLabelValue},
			Annotations: map[string]string{HostAnnotation: opts.Host},
		},
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			DisplayName:         opts.Name,
			PublicKey:           publicKey,
			AllowedDestinations: opts.Allowed,
			IngressPeer:         opts.IngressPeer,
			MTU:                 opts.MTU,
		},
	}
	if opts.TTL > 0 {
		cr.Spec.TTL = &metav1.Duration{Duration: opts.TTL}
	}
	return cr
}

// replaceLeftover deletes a peer a previous session of this name left behind and
// waits until it is gone, so the new peer does not race its finalizer. A peer
// connect did not issue is never touched.
func replaceLeftover(ctx context.Context, c client.Client, name string, timeout time.Duration) error {
	existing := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(ctx, client.ObjectKey{Name: name}, existing)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get external peer %s: %w", name, err)
	}
	if existing.Labels[ClientLabel] != ClientLabelValue {
		return fmt.Errorf("external peer %s already exists and was not issued by connect; choose another --name", name)
	}
	if existing.DeletionTimestamp.IsZero() {
		if err := c.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("remove leftover external peer %s: %w", name, err)
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		err := c.Get(ctx, client.ObjectKey{Name: name}, &wirekubev1alpha1.WireKubeExternalPeer{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get external peer %s: %w", name, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for leftover external peer %s to be deleted", name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// deleteOwnPeer deletes the session's peer unless something has already
// replaced it under the same name, such as a newer session on this host.
func deleteOwnPeer(ctx context.Context, c client.Client, own *wirekubev1alpha1.WireKubeExternalPeer) error {
	current := &wirekubev1alpha1.WireKubeExternalPeer{}
	err := c.Get(ctx, client.ObjectKey{Name: own.Name}, current)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.UID != own.UID {
		return nil
	}
	err = c.Delete(ctx, current, client.Preconditions{UID: &own.UID})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return err
}

func (o *Options) resolveEndpoint(ctx context.Context, cfg TunnelConfig) (netip.AddrPort, error) {
	endpoint, err := o.Resolve(ctx, cfg.Endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve relay endpoint %s: %w", cfg.Endpoint, err)
	}
	if err := CheckEndpointReachable(endpoint, cfg.Routes); err != nil {
		return netip.AddrPort{}, err
	}
	return endpoint, nil
}

func (o *Options) reportConfig(ifName string, cfg TunnelConfig, endpoint netip.AddrPort, ingress string) {
	fmt.Fprintf(o.Out, "interface %s address %s mtu %d\n", ifName, cfg.Address, cfg.MTU)
	fmt.Fprintf(o.Out, "ingress %s via relay %s (%s)\n", ingress, cfg.Endpoint, endpoint)
	for _, r := range cfg.Routes {
		fmt.Fprintf(o.Out, "  route %s\n", r)
	}
	for _, w := range LocalOverlaps(cfg.Routes, o.LocalPrefixes()) {
		fmt.Fprintf(o.Out, "warning: %s; the more specific route wins\n", w)
	}
}

// configureDNS is best effort: a session that reaches the cluster by IP is
// still useful, so a resolver that cannot be found or programmed only warns.
func (o *Options) configureDNS(ctx context.Context, c client.Client, dp Dataplane) {
	server, err := o.dnsServer(ctx, c)
	if err != nil {
		fmt.Fprintf(o.Out, "warning: cluster DNS not configured: %v\n", err)
		return
	}
	cfg := DNSConfig{
		Server: server,
		Domain: o.ClusterDomain,
		Search: []string{
			o.SearchNamespace + ".svc." + o.ClusterDomain,
			"svc." + o.ClusterDomain,
		},
	}
	if err := dp.SetDNS(cfg); err != nil {
		fmt.Fprintf(o.Out, "warning: cluster DNS not configured: %v\n", err)
		return
	}
	fmt.Fprintf(o.Out, "dns *.%s via %s (search %s)\n", cfg.Domain, cfg.Server, cfg.Search[0])
}

func (o *Options) dnsServer(ctx context.Context, c client.Client) (netip.Addr, error) {
	if o.DNSServer != "" {
		return netip.ParseAddr(o.DNSServer)
	}
	svc := &corev1.Service{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: "kube-dns"}, svc); err != nil {
		return netip.Addr{}, fmt.Errorf("read kube-system/kube-dns (pass --dns-server to skip the lookup): %w", err)
	}
	addr, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("kube-system/kube-dns has no usable ClusterIP %q", svc.Spec.ClusterIP)
	}
	return addr, nil
}

// watch follows the peer's status for the life of the session: heartbeats,
// reprograms the dataplane when the status changes, and ends when the peer is
// revoked. It returns errStale when the session went quiet long enough to lose it.
func (s *session) watch(ctx context.Context) error {
	o := s.opts
	ticker := time.NewTicker(o.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(o.Out, "disconnecting")
			return nil
		case <-ticker.C:
		}

		now := o.Now()
		// --ttl is also enforced here, not only by the controller deleting
		// the peer: a controller that is down, or a resume shortly after the
		// deadline, would otherwise let the session run on past it.
		if !s.deadline.IsZero() && !now.Before(s.deadline) {
			return errSessionExpired
		}
		// A tick long after the previous one means the process was frozen, e.g. a
		// suspended machine, so the peer is replaced rather than waited on.
		if gap := now.Sub(s.lastTick); gap >= o.staleAfter() {
			s.lastTick = now
			return fmt.Errorf("%w: no activity for %s (was this machine suspended?)", errStale, gap.Round(time.Second))
		}
		s.lastTick = now
		s.reportHandshake(now)

		cr := &wirekubev1alpha1.WireKubeExternalPeer{}
		err := s.c.Get(ctx, client.ObjectKey{Name: o.Name}, cr)
		switch {
		case ctx.Err() != nil:
			continue
		case apierrors.IsNotFound(err), err == nil && (!cr.DeletionTimestamp.IsZero() || cr.UID != s.peer.UID):
			if quiet := now.Sub(s.lastBeat); quiet >= o.staleAfter() {
				return fmt.Errorf("%w: external peer %s was reclaimed after %s without a heartbeat", errStale, o.Name, quiet.Round(time.Second))
			}
			return fmt.Errorf("external peer %s was deleted", o.Name)
		case err != nil:
			fmt.Fprintf(o.Out, "warning: read external peer: %v\n", err)
			continue
		}
		s.beat(ctx, cr, now)

		if cr.Status.Phase == wirekubev1alpha1.ExternalPeerPhaseRevoked || cr.Status.Phase == wirekubev1alpha1.ExternalPeerPhaseFailed {
			return fmt.Errorf("external peer %s is %s: %s", o.Name, cr.Status.Phase, externalpeer.LastConditionMessage(cr.Status.Conditions))
		}
		if cr.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
			continue
		}
		next, err := ConfigFromStatus(cr)
		if err != nil {
			fmt.Fprintf(o.Out, "warning: %v\n", err)
			continue
		}
		s.pinMTU(&next)
		if next.Equal(s.cfg) {
			continue
		}
		nextEndpoint := s.endpoint
		if next.Endpoint != s.cfg.Endpoint {
			if nextEndpoint, err = o.Resolve(ctx, next.Endpoint); err != nil {
				fmt.Fprintf(o.Out, "warning: resolve relay endpoint %s: %v\n", next.Endpoint, err)
				continue
			}
		}
		if err := CheckEndpointReachable(nextEndpoint, next.Routes); err != nil {
			fmt.Fprintf(o.Out, "warning: ignoring status update: %v\n", err)
			continue
		}
		warnings, err := s.dp.Apply(next, nextEndpoint)
		s.reportWarnings(warnings)
		if err != nil {
			return fmt.Errorf("apply updated peer status: %w", err)
		}
		fmt.Fprintln(o.Out, "peer status changed; tunnel updated")
		o.reportConfig(s.dp.Name(), next, nextEndpoint, cr.Status.IngressPeerName)
		s.cfg, s.endpoint = next, nextEndpoint
	}
}

// beat refreshes the heartbeat once it is due. A failure is only reported:
// the next tick retries, and a peer reclaimed meanwhile is caught by watch.
func (s *session) beat(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, now time.Time) {
	if now.Sub(s.lastBeat) < s.opts.HeartbeatInterval {
		return
	}
	patch := client.MergeFrom(cr.DeepCopy())
	if cr.Annotations == nil {
		cr.Annotations = map[string]string{}
	}
	cr.Annotations[wirekubev1alpha1.ExternalPeerHeartbeatAnnotation] = beatValue(now)
	if err := s.c.Patch(ctx, cr, patch); err != nil {
		fmt.Fprintf(s.opts.Out, "warning: heartbeat: %v\n", err)
		return
	}
	s.lastBeat = now
}

func (s *session) reportHandshake(now time.Time) {
	hs := s.dp.LastHandshake()
	switch {
	case !hs.IsZero() && !s.connected:
		s.connected = true
		fmt.Fprintln(s.opts.Out, "handshake with ingress completed")
	case hs.IsZero() && !s.warned && now.Sub(s.issuedAt) > handshakeWarnAfter:
		s.warned = true
		fmt.Fprintf(s.opts.Out, "warning: no handshake with the ingress after %s; check that UDP to %s is allowed\n", handshakeWarnAfter, s.endpoint)
	}
}

func resolveUDP(ctx context.Context, hostport string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no addresses for %s", host)
	}
	// Prefer IPv4: the relay's raw WireGuard listener is commonly exposed
	// through a v4-only NodePort or load balancer.
	pick := addrs[0]
	for _, a := range addrs {
		if a.Unmap().Is4() {
			pick = a
			break
		}
	}
	return netip.ParseAddrPort(net.JoinHostPort(pick.Unmap().String(), port))
}

func localPrefixes() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(ipn.String())
		// Host prefixes (the tunnel's own /32 among them) are addresses,
		// not attached networks, and would flag every session.
		if err != nil || p.IsSingleIP() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		out = append(out, p.Masked())
	}
	return out
}
