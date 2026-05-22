package external

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/wirekube/wirekube/pkg/relay"
)

// RemoteRelayController is a RelayController that talks to a relay over
// TCP using the forwarder control frames defined in pkg/relay/protocol.go
// (0x10 RegisterForwarder, 0x11 UnregisterForwarder).
//
// Each call opens a one-shot TCP connection: dial, write request, read
// response, close. This avoids reserving a long-lived "controller pubkey"
// in the relay's peer table and matches the relay's expectation that the
// FIRST frame on a fresh connection determines the connection mode (peer
// register vs forwarder control).
//
// Legacy control traffic is rare, so the per-call dial is fine. The reconciler
// is the sole caller, and
// its workqueue serializes Reconcile invocations per object — the mutex
// here only guards against concurrent calls for *different* objects.
type RemoteRelayController struct {
	// addr is the relay's TCP control address (host:port). Same address as
	// the data plane listener; the relay multiplexes by first-frame type.
	addr string
	// endpoint is the public host:port the reconciler writes into
	// status.relayEndpoint. Distinct from addr because the control plane
	// and data plane may use different DNS names (cluster-internal vs
	// public).
	endpoint string
	// dialTimeout bounds each connect; defaults to 5s if zero.
	dialTimeout time.Duration
	// rwTimeout bounds each request/response cycle once connected;
	// defaults to 10s if zero.
	rwTimeout time.Duration

	mu sync.Mutex // serializes control ops; one in flight at a time
}

// NewRemoteRelayController constructs a RelayController that targets the
// relay at controlAddr (TCP host:port). The publicEndpoint argument is
// the host:port embedded in WireKubeExternalPeer.status.relayEndpoint
// — typically the operator's externally-visible DNS name for the relay
// pool.
func NewRemoteRelayController(controlAddr, publicEndpoint string) *RemoteRelayController {
	return &RemoteRelayController{
		addr:        controlAddr,
		endpoint:    publicEndpoint,
		dialTimeout: 5 * time.Second,
		rwTimeout:   10 * time.Second,
	}
}

// RelayEndpoint returns the public host:port advertised to external
// peers in their conf.
func (c *RemoteRelayController) RelayEndpoint() string { return c.endpoint }

// RegisterForwarder sends a 0x10 ForwarderRegister frame with port=0
// (request server-side allocation) and parses the response. Returns the
// allocated port. Returns an error if the relay replies with 0xFF or the
// connection fails.
func (c *RemoteRelayController) RegisterForwarder(ctx context.Context, ingress, external [32]byte) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registerForwarderAtPortLocked(ctx, 0, ingress, external)
}

// registerForwarderAtPort sends a 0x10 ForwarderRegister frame with a specific
// UDP port. A port of 0 asks the target relay to allocate from its local pool.
func (c *RemoteRelayController) registerForwarderAtPort(ctx context.Context, port uint16, ingress, external [32]byte) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registerForwarderAtPortLocked(ctx, port, ingress, external)
}

func (c *RemoteRelayController) registerForwarderAtPortLocked(ctx context.Context, port uint16, ingress, external [32]byte) (uint16, error) {
	resp, err := c.roundTrip(ctx, relay.MakeForwarderRegisterFrame(port, ingress, external))
	if err != nil {
		return 0, err
	}
	if resp.Type == relay.MsgError {
		return 0, fmt.Errorf("relay refused forwarder register: %s", string(resp.Body))
	}
	if resp.Type != relay.MsgForwarderRegister {
		return 0, fmt.Errorf("unexpected response type %#x to forwarder register", resp.Type)
	}
	port, gotIngress, ext, err := relay.ParseForwarderRegisterFrame(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("parse forwarder register response: %w", err)
	}
	if gotIngress != ingress || ext != external {
		return 0, errors.New("forwarder register response pubkey mismatch")
	}
	if port == 0 {
		return 0, errors.New("forwarder register response missing port")
	}
	return port, nil
}

// UnregisterForwarder sends 0x11. Idempotent: an unknown port returns nil
// from the relay, matching LocalRelayController semantics.
func (c *RemoteRelayController) UnregisterForwarder(ctx context.Context, port uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.roundTrip(ctx, relay.MakeForwarderUnregisterFrame(port))
	if err != nil {
		return err
	}
	if resp.Type == relay.MsgError {
		return fmt.Errorf("relay refused forwarder unregister: %s", string(resp.Body))
	}
	if resp.Type != relay.MsgForwarderUnregister {
		return fmt.Errorf("unexpected response type %#x to forwarder unregister", resp.Type)
	}
	return nil
}

func (c *RemoteRelayController) ProbeIngressLatency(ctx context.Context, ingressPubKeys [][32]byte) (map[[32]byte]time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.roundTrip(ctx, relay.MakeIngressProbeRequestFrame(ingressPubKeys))
	if err != nil {
		return nil, err
	}
	if resp.Type == relay.MsgError {
		return nil, fmt.Errorf("relay refused ingress probe: %s", string(resp.Body))
	}
	if resp.Type != relay.MsgIngressProbe {
		return nil, fmt.Errorf("unexpected response type %#x to ingress probe", resp.Type)
	}
	results, err := relay.ParseIngressProbeResponseFrame(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse ingress probe response: %w", err)
	}
	out := make(map[[32]byte]time.Duration, len(results))
	for _, result := range results {
		out[result.PubKey] = result.RTT
	}
	return out, nil
}

// roundTrip dials the relay, writes one frame, reads one frame back, and
// closes. Honours ctx cancellation via SetDeadline.
func (c *RemoteRelayController) roundTrip(ctx context.Context, req relay.Frame) (relay.Frame, error) {
	var d net.Dialer
	d.Timeout = c.dialTimeout
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return relay.Frame{}, fmt.Errorf("dial relay %s: %w", c.addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.rwTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return relay.Frame{}, fmt.Errorf("set deadline: %w", err)
	}

	if err := relay.WriteFrame(conn, req); err != nil {
		return relay.Frame{}, fmt.Errorf("write frame: %w", err)
	}

	resp, err := relay.ReadFrame(conn)
	if err != nil {
		return relay.Frame{}, fmt.Errorf("read frame: %w", err)
	}
	return resp, nil
}

// FanoutRelayController registers the same external-peer forwarder mapping on
// every discovered relay replica. The first replica allocates a global port;
// all remaining replicas are then instructed to bind that exact port so a
// public UDP load balancer can land external-peer datagrams on any backend.
type FanoutRelayController struct {
	controlAddr string
	endpoint    string

	dialTimeout time.Duration
	rwTimeout   time.Duration

	mu            sync.Mutex
	controllersFn func() []*RemoteRelayController
}

// NewFanoutRelayController returns a RelayController that expands controlAddr
// through DNS on each operation. Headless Service names resolve to relay pod
// IPs and therefore get fanout; public LB hostnames normally resolve to public
// IPs and intentionally fall back to one control connection.
func NewFanoutRelayController(controlAddr, publicEndpoint string) *FanoutRelayController {
	return &FanoutRelayController{
		controlAddr: controlAddr,
		endpoint:    publicEndpoint,
		dialTimeout: 5 * time.Second,
		rwTimeout:   10 * time.Second,
	}
}

func (c *FanoutRelayController) RelayEndpoint() string { return c.endpoint }

func (c *FanoutRelayController) RegisterForwarder(ctx context.Context, ingress, external [32]byte) (uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	controllers := c.controllers()
	if len(controllers) == 0 {
		return 0, errors.New("relay fanout: no control endpoints")
	}

	port, err := controllers[0].registerForwarderAtPort(ctx, 0, ingress, external)
	if err != nil {
		return 0, fmt.Errorf("relay fanout register %s: %w", controllers[0].addr, err)
	}
	registered := controllers[:1]

	for _, rc := range controllers[1:] {
		got, err := rc.registerForwarderAtPort(ctx, port, ingress, external)
		if err != nil {
			return 0, errors.Join(
				fmt.Errorf("relay fanout register %s: %w", rc.addr, err),
				rollbackFanout(ctx, registered, port),
			)
		}
		if got != port {
			return 0, errors.Join(
				fmt.Errorf("relay fanout register %s: port mismatch: got %d want %d", rc.addr, got, port),
				rollbackFanout(ctx, registered, port),
			)
		}
		registered = append(registered, rc)
	}
	return port, nil
}

func (c *FanoutRelayController) EnsureForwarder(ctx context.Context, port uint16, ingress, external [32]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for _, rc := range c.controllers() {
		got, err := rc.registerForwarderAtPort(ctx, port, ingress, external)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay fanout ensure %s: %w", rc.addr, err))
			continue
		}
		if got != port {
			errs = append(errs, fmt.Errorf("relay fanout ensure %s: port mismatch: got %d want %d", rc.addr, got, port))
		}
	}
	return errors.Join(errs...)
}

func (c *FanoutRelayController) UnregisterForwarder(ctx context.Context, port uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for _, rc := range c.controllers() {
		if err := rc.UnregisterForwarder(ctx, port); err != nil {
			errs = append(errs, fmt.Errorf("relay fanout unregister %s: %w", rc.addr, err))
		}
	}
	return errors.Join(errs...)
}

func (c *FanoutRelayController) ProbeIngressLatency(ctx context.Context, ingressPubKeys [][32]byte) (map[[32]byte]time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	controllers := c.controllers()
	if len(controllers) == 0 {
		return nil, errors.New("relay fanout: no control endpoints")
	}

	type response struct {
		addr string
		got  map[[32]byte]time.Duration
		err  error
	}
	responses := make(chan response, len(controllers))
	for _, rc := range controllers {
		go func(rc *RemoteRelayController) {
			got, err := rc.ProbeIngressLatency(ctx, ingressPubKeys)
			responses <- response{addr: rc.addr, got: got, err: err}
		}(rc)
	}

	seen := make(map[[32]byte]int, len(ingressPubKeys))
	maxRTT := make(map[[32]byte]time.Duration, len(ingressPubKeys))
	var errs []error
	for range controllers {
		resp := <-responses
		if resp.err != nil {
			errs = append(errs, fmt.Errorf("relay fanout ingress probe %s: %w", resp.addr, resp.err))
			continue
		}
		for key, rtt := range resp.got {
			seen[key]++
			if rtt > maxRTT[key] {
				maxRTT[key] = rtt
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	out := make(map[[32]byte]time.Duration, len(maxRTT))
	for key, count := range seen {
		if count == len(controllers) {
			out[key] = maxRTT[key]
		}
	}
	return out, nil
}

func (c *FanoutRelayController) controllers() []*RemoteRelayController {
	if c.controllersFn != nil {
		return c.controllersFn()
	}
	addrs := resolveRelayControlAddrs(c.controlAddr)
	out := make([]*RemoteRelayController, 0, len(addrs))
	for _, addr := range addrs {
		rc := NewRemoteRelayController(addr, c.endpoint)
		rc.dialTimeout = c.dialTimeout
		rc.rwTimeout = c.rwTimeout
		out = append(out, rc)
	}
	return out
}

func rollbackFanout(ctx context.Context, controllers []*RemoteRelayController, port uint16) error {
	var errs []error
	for _, rc := range controllers {
		if err := rc.UnregisterForwarder(ctx, port); err != nil {
			errs = append(errs, fmt.Errorf("relay fanout rollback %s: %w", rc.addr, err))
		}
	}
	return errors.Join(errs...)
}

func resolveRelayControlAddrs(controlAddr string) []string {
	host, port, err := net.SplitHostPort(controlAddr)
	if err != nil {
		return []string{controlAddr}
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return []string{controlAddr}
	}

	seen := make(map[string]struct{}, len(ips))
	var out []string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
			continue
		}
		addr := net.JoinHostPort(ipStr, port)
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return []string{controlAddr}
	}
	sort.Strings(out)
	return out
}
