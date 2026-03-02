package relay

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

// Client manages a TCP connection to the relay server and routes packets
// between local UDP proxies and remote peers via the relay.
type Client struct {
	relayAddr string
	myPubKey  [relayproto.PubKeySize]byte
	wgPort    int

	mu      sync.RWMutex
	conn    net.Conn
	writer  *bufio.Writer
	proxies map[[relayproto.PubKeySize]byte]*UDPProxy
	cancel  context.CancelFunc
}

func NewClient(relayAddr string, myPubKey [relayproto.PubKeySize]byte, wgPort int) *Client {
	return &Client{
		relayAddr: relayAddr,
		myPubKey:  myPubKey,
		wgPort:    wgPort,
		proxies:   make(map[[relayproto.PubKeySize]byte]*UDPProxy),
	}
}

// Connect establishes TCP connection to relay and registers.
func (c *Client) Connect(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	conn, err := net.DialTimeout("tcp", c.relayAddr, 10*time.Second)
	if err != nil {
		cancel()
		return fmt.Errorf("connecting to relay %s: %w", c.relayAddr, err)
	}

	c.mu.Lock()
	c.conn = conn
	c.writer = bufio.NewWriterSize(conn, 64*1024)
	c.mu.Unlock()

	regFrame := relayproto.MakeRegisterFrame(c.myPubKey)
	if err := relayproto.WriteFrame(c.writer, regFrame); err != nil {
		conn.Close()
		cancel()
		return fmt.Errorf("sending register: %w", err)
	}
	if err := c.writer.Flush(); err != nil {
		conn.Close()
		cancel()
		return fmt.Errorf("flushing register: %w", err)
	}

	go c.readLoop(ctx)
	go c.keepaliveLoop(ctx)

	log.Printf("relay-client: connected to %s", c.relayAddr)
	return nil
}

func (c *Client) readLoop(ctx context.Context) {
	reader := bufio.NewReader(c.conn)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := relayproto.ReadFrame(reader)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("relay-client: read error: %v", err)
			}
			return
		}

		switch frame.Type {
		case relayproto.MsgData:
			srcKey, payload, err := relayproto.ParseDataFrame(frame.Body)
			if err != nil {
				log.Printf("relay-client: bad data frame: %v", err)
				continue
			}

			c.mu.RLock()
			proxy, ok := c.proxies[srcKey]
			c.mu.RUnlock()

			if !ok {
				continue
			}

			proxy.DeliverToWireGuard(payload)

		case relayproto.MsgError:
			log.Printf("relay-client: server error: %s", string(frame.Body))

		case relayproto.MsgKeepalive:
			// no-op
		}
	}
}

func (c *Client) keepaliveLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.writer != nil {
				_ = relayproto.WriteFrame(c.writer, relayproto.MakeKeepaliveFrame())
				_ = c.writer.Flush()
			}
			c.mu.Unlock()
		}
	}
}

// SendToPeer sends a UDP payload to a remote peer through the relay.
func (c *Client) SendToPeer(destPubKey [relayproto.PubKeySize]byte, payload []byte) error {
	frame := relayproto.MakeDataFrame(destPubKey, payload)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writer == nil {
		return fmt.Errorf("not connected")
	}
	if err := relayproto.WriteFrame(c.writer, frame); err != nil {
		return err
	}
	return c.writer.Flush()
}

// GetOrCreateProxy returns the UDP proxy for a given peer, creating one if needed.
// The returned proxy's ListenAddr can be used as the WireGuard peer endpoint.
func (c *Client) GetOrCreateProxy(peerPubKey [relayproto.PubKeySize]byte) (*UDPProxy, error) {
	c.mu.RLock()
	proxy, ok := c.proxies[peerPubKey]
	c.mu.RUnlock()
	if ok {
		return proxy, nil
	}

	proxy, err := NewUDPProxy(peerPubKey, c, c.wgPort)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if existing, ok := c.proxies[peerPubKey]; ok {
		c.mu.Unlock()
		proxy.Close()
		return existing, nil
	}
	c.proxies[peerPubKey] = proxy
	c.mu.Unlock()

	go proxy.Run()
	return proxy, nil
}

// RemoveProxy stops and removes a proxy for a peer.
func (c *Client) RemoveProxy(peerPubKey [relayproto.PubKeySize]byte) {
	c.mu.Lock()
	proxy, ok := c.proxies[peerPubKey]
	if ok {
		delete(c.proxies, peerPubKey)
	}
	c.mu.Unlock()

	if ok {
		proxy.Close()
	}
}

// Close shuts down the relay client and all proxies.
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}

	c.mu.Lock()
	for key, proxy := range c.proxies {
		proxy.Close()
		delete(c.proxies, key)
	}
	if c.conn != nil {
		c.conn.Close()
	}
	c.mu.Unlock()
}
