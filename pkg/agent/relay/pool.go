package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

// Pool manages connections to multiple relay server instances.
// All agents register on every relay so that any relay can deliver packets
// to any agent, regardless of which replica the sender is connected to.
//
// Discovery uses DNS resolution of the relay address — a Kubernetes Headless
// Service returns all pod IPs. The pool periodically re-resolves to pick up
// new replicas or drop removed ones.
type Pool struct {
	relayAddr string
	myPubKey  [relayproto.PubKeySize]byte
	wgPort    int

	mu      sync.RWMutex
	clients map[string]*Client // keyed by resolved IP:port
	proxies map[[relayproto.PubKeySize]byte]*UDPProxy

	// bindDelivery, when set, routes incoming relay data packets directly
	// to the WireKubeBind instead of through UDPProxy. Used in userspace
	// WireGuard mode where the Bind handles relay receive internally.
	bindDelivery func(srcKey [32]byte, payload []byte)

	// hintHandler, when set, receives bimodal hints relayed from remote peers.
	hintHandler func(srcKey [32]byte)

	cancel context.CancelFunc
}

// NewPool creates a relay pool that discovers and connects to all instances
// behind the given address (typically a Headless Service DNS name).
func NewPool(relayAddr string, myPubKey [relayproto.PubKeySize]byte, wgPort int) *Pool {
	return &Pool{
		relayAddr: relayAddr,
		myPubKey:  myPubKey,
		wgPort:    wgPort,
		clients:   make(map[string]*Client),
		proxies:   make(map[[relayproto.PubKeySize]byte]*UDPProxy),
	}
}

// Connect resolves the relay address and connects to all discovered endpoints.
// It starts a background goroutine that periodically re-resolves DNS to track
// replica changes (scale-up, scale-down, restarts).
func (p *Pool) Connect(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	endpoints := p.resolve()
	if len(endpoints) == 0 {
		// Fall back to the raw address (non-headless Service or external relay).
		endpoints = []string{p.relayAddr}
	}

	var firstErr error
	for _, ep := range endpoints {
		if err := p.connectOne(ctx, ep); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	go p.discoveryLoop(ctx)

	if firstErr != nil && len(p.connectedClients()) == 0 {
		return firstErr
	}
	return nil
}

// IsConnected returns true if at least one relay is connected.
func (p *Pool) IsConnected() bool {
	return len(p.connectedClients()) > 0
}

// GetOrCreateProxy returns the UDP proxy for a given peer, creating one if needed.
func (p *Pool) GetOrCreateProxy(peerPubKey [relayproto.PubKeySize]byte) (*UDPProxy, error) {
	p.mu.RLock()
	proxy, ok := p.proxies[peerPubKey]
	p.mu.RUnlock()
	if ok {
		return proxy, nil
	}

	proxy, err := NewUDPProxy(peerPubKey, p, p.wgPort)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if existing, ok := p.proxies[peerPubKey]; ok {
		p.mu.Unlock()
		proxy.Close()
		return existing, nil
	}
	p.proxies[peerPubKey] = proxy
	p.mu.Unlock()

	go proxy.Run()
	return proxy, nil
}

// LastRelayHandshake returns the most recent time a WireGuard handshake packet
// was delivered to WG via the relay proxy for the given peer. Returns the zero
// time if no proxy exists or no handshake has been relayed yet.
func (p *Pool) LastRelayHandshake(peerPubKey [relayproto.PubKeySize]byte) time.Time {
	p.mu.RLock()
	proxy, ok := p.proxies[peerPubKey]
	p.mu.RUnlock()
	if !ok {
		return time.Time{}
	}
	return proxy.LastHandshakeDelivered()
}

// HoldDelivery blocks relay packet delivery to WG for the given peer until
// the returned function is called. Returns a no-op if no proxy exists.
// Used by the ICE engine to take a clean WG stats snapshot without a
// concurrent relay packet contaminating ActualEndpoint via WG roaming.
func (p *Pool) HoldDelivery(peerPubKey [relayproto.PubKeySize]byte) func() {
	p.mu.RLock()
	proxy, ok := p.proxies[peerPubKey]
	p.mu.RUnlock()
	if !ok {
		return func() {}
	}
	return proxy.HoldDelivery()
}

// SuspendDelivery blocks relay→WG delivery for the given peer for the
// duration of an ICE probe. Packets are buffered internally. Call
// ResumeDelivery when the probe completes.
func (p *Pool) SuspendDelivery(peerPubKey [relayproto.PubKeySize]byte) {
	p.mu.RLock()
	proxy, ok := p.proxies[peerPubKey]
	p.mu.RUnlock()
	if ok {
		proxy.SuspendDelivery()
	}
}

// ResumeDelivery re-enables relay→WG delivery after a probe.
// flush=true delivers buffered packets (probe failed, relay resumes).
// flush=false discards them (probe succeeded, direct path active).
func (p *Pool) ResumeDelivery(peerPubKey [relayproto.PubKeySize]byte, flush bool) {
	p.mu.RLock()
	proxy, ok := p.proxies[peerPubKey]
	p.mu.RUnlock()
	if ok {
		proxy.ResumeDelivery(flush)
	}
}

// IsDeliverySuspended reports whether delivery for the given peer is suspended.
func (p *Pool) IsDeliverySuspended(peerPubKey [relayproto.PubKeySize]byte) bool {
	p.mu.RLock()
	proxy, ok := p.proxies[peerPubKey]
	p.mu.RUnlock()
	if !ok {
		return false
	}
	return proxy.IsSuspended()
}

// RemoveProxy stops and removes a proxy for a peer.
func (p *Pool) RemoveProxy(peerPubKey [relayproto.PubKeySize]byte) {
	p.mu.Lock()
	proxy, ok := p.proxies[peerPubKey]
	if ok {
		delete(p.proxies, peerPubKey)
	}
	p.mu.Unlock()

	if ok {
		proxy.Close()
	}
}

// SendNATProbe asks the relay to send a UDP probe from a different source port
// to the specified mapped endpoint. Used for port-restricted cone detection.
func (p *Pool) SendNATProbe(ip net.IP, port int) error {
	clients := p.connectedClients()
	if len(clients) == 0 {
		return fmt.Errorf("no relay connected")
	}
	return clients[0].SendNATProbe(ip, port)
}

// RelayIP returns the IP of the first connected relay server.
func (p *Pool) RelayIP() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for addr := range p.clients {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			return host
		}
	}
	host, _, _ := net.SplitHostPort(p.relayAddr)
	return host
}

// SendToPeer sends a UDP payload to a remote peer through any connected relay.
// It tries each connected relay in order until one succeeds.
func (p *Pool) SendToPeer(destPubKey [relayproto.PubKeySize]byte, payload []byte) error {
	clients := p.connectedClients()
	if len(clients) == 0 {
		return fmt.Errorf("no relay connected")
	}

	var lastErr error
	for _, c := range clients {
		if err := c.SendToPeer(destPubKey, payload); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// SendBimodalHint forwards a bimodal-hint to destPubKey via the first
// reachable relay. The hint tells the destination peer to dual-send on both
// direct and relay legs for the next few seconds.
func (p *Pool) SendBimodalHint(destPubKey [relayproto.PubKeySize]byte) error {
	clients := p.connectedClients()
	if len(clients) == 0 {
		return fmt.Errorf("no relay connected")
	}
	var lastErr error
	for _, c := range clients {
		if err := c.SendBimodalHint(destPubKey); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// Close shuts down all relay clients and proxies.
func (p *Pool) Close() {
	if p.cancel != nil {
		p.cancel()
	}

	p.mu.Lock()
	for key, proxy := range p.proxies {
		proxy.Close()
		delete(p.proxies, key)
	}
	for addr, c := range p.clients {
		c.Close()
		delete(p.clients, addr)
	}
	p.mu.Unlock()
}

// SetBindDelivery registers a callback that receives relay data packets
// directly, bypassing UDPProxy. Used in userspace WireGuard mode where
// the WireKubeBind handles relay receive internally.
func (p *Pool) SetBindDelivery(fn func(srcKey [32]byte, payload []byte)) {
	p.mu.Lock()
	p.bindDelivery = fn
	p.mu.Unlock()
}

// SetBimodalHintHandler registers a callback invoked when a remote peer
// relays a bimodal-hint identifying itself as the sender. The bind marks
// that peer for a short dual-send window so the local datapath immediately
// cooperates with the remote's failover.
func (p *Pool) SetBimodalHintHandler(fn func(srcKey [32]byte)) {
	p.mu.Lock()
	p.hintHandler = fn
	p.mu.Unlock()
}

// HasBindDelivery reports whether a bind delivery callback is registered.
// When true, relay packets are routed to the Bind and UDPProxy is not needed.
func (p *Pool) HasBindDelivery() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.bindDelivery != nil
}

func (p *Pool) handleData(srcKey [relayproto.PubKeySize]byte, payload []byte) {
	p.mu.RLock()
	bd := p.bindDelivery
	proxy, ok := p.proxies[srcKey]
	p.mu.RUnlock()

	if bd != nil {
		bd(srcKey, payload)
		return
	}
	if ok {
		proxy.DeliverToWireGuard(payload)
	}
}

func (p *Pool) handleHint(srcKey [relayproto.PubKeySize]byte) {
	p.mu.RLock()
	h := p.hintHandler
	p.mu.RUnlock()
	if h != nil {
		h(srcKey)
	}
}

func (p *Pool) connectedClients() []*Client {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*Client, 0, len(p.clients))
	for _, c := range p.clients {
		if c.IsConnected() {
			result = append(result, c)
		}
	}
	return result
}

func (p *Pool) connectOne(ctx context.Context, addr string) error {
	p.mu.RLock()
	_, exists := p.clients[addr]
	p.mu.RUnlock()
	if exists {
		return nil
	}

	c := NewClient(addr, p.myPubKey, p.wgPort)
	c.onData = p.handleData
	c.onHint = p.handleHint
	err := c.Connect(ctx)

	p.mu.Lock()
	if _, dup := p.clients[addr]; dup {
		p.mu.Unlock()
		c.Close()
		return nil
	}
	p.clients[addr] = c
	p.mu.Unlock()

	return err
}

// resolve does a DNS lookup on the relay address host to get all IPs.
// For Kubernetes headless services, DNS returns each pod's private IP, so we
// connect to each pod separately. For external relays (ELB, public addresses),
// DNS may return multiple anycast IPs that all route to the same server;
// connecting to each would register the same WireGuard pubkey multiple times,
// causing the server to close older connections (EOF loop). To avoid this, we
// only return private RFC-1918 IPs — if the resolved IPs are all public, the
// caller falls back to the raw hostname (a single connection).
func (p *Pool) resolve() []string {
	host, port, err := net.SplitHostPort(p.relayAddr)
	if err != nil {
		return nil
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil
	}

	endpoints := make([]string, 0, len(ips))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && isPrivateIP(ip) {
			endpoints = append(endpoints, net.JoinHostPort(ipStr, port))
		}
	}
	return endpoints
}

// isPrivateIP reports whether ip is in a private (RFC-1918 / RFC-4193 / loopback) range.
func isPrivateIP(ip net.IP) bool {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"127.0.0.0/8",
		"::1/128",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// discoveryLoop periodically re-resolves DNS and connects to new replicas.
func (p *Pool) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		endpoints := p.resolve()
		if len(endpoints) == 0 {
			continue
		}

		// Connect to new endpoints.
		for _, ep := range endpoints {
			if err := p.connectOne(ctx, ep); err != nil {
				log.Printf("relay-pool: failed to connect to new replica %s: %v", ep, err)
			}
		}

		// Remove clients for endpoints that no longer resolve.
		epSet := make(map[string]struct{}, len(endpoints))
		for _, ep := range endpoints {
			epSet[ep] = struct{}{}
		}

		p.mu.Lock()
		for addr, c := range p.clients {
			if _, ok := epSet[addr]; !ok {
				c.Close()
				delete(p.clients, addr)
				log.Printf("relay-pool: removed stale relay %s", addr)
			}
		}
		p.mu.Unlock()
	}
}
