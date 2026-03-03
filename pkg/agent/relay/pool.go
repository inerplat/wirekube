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

func (p *Pool) handleData(srcKey [relayproto.PubKeySize]byte, payload []byte) {
	p.mu.RLock()
	proxy, ok := p.proxies[srcKey]
	p.mu.RUnlock()
	if ok {
		proxy.DeliverToWireGuard(payload)
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

// resolve does a DNS lookup on the relay address host to get all IPs
// (headless service returns all pod IPs).
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
	for _, ip := range ips {
		endpoints = append(endpoints, net.JoinHostPort(ip, port))
	}
	return endpoints
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
