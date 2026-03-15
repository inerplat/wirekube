package relay

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

// Client manages a TCP connection to the relay server and routes packets
// between local UDP proxies and remote peers via the relay.
//
// Connection lifecycle:
//   - Connect() dials the relay and starts a background reconnect loop.
//   - If the TCP connection drops, the client automatically reconnects
//     with exponential backoff (1s → 30s cap).
//   - Proxies survive reconnections — they are bound to the Client, not the
//     TCP connection, and resume forwarding once the new connection is up.
// DataHandler is called when a Data frame arrives. If nil, the Client falls
// back to its own proxy map. Pool sets this to route data through its own
// proxy map instead.
type DataHandler func(srcKey [relayproto.PubKeySize]byte, payload []byte)

type Client struct {
	relayAddr string
	myPubKey  [relayproto.PubKeySize]byte
	wgPort    int

	mu      sync.RWMutex
	conn    net.Conn
	writer  *bufio.Writer
	proxies map[[relayproto.PubKeySize]byte]*UDPProxy

	onData      DataHandler
	connected   atomic.Bool
	reconnectCh chan struct{} // signalled by readLoop on disconnect
	cancel      context.CancelFunc
}

func NewClient(relayAddr string, myPubKey [relayproto.PubKeySize]byte, wgPort int) *Client {
	return &Client{
		relayAddr:   relayAddr,
		myPubKey:    myPubKey,
		wgPort:      wgPort,
		proxies:     make(map[[relayproto.PubKeySize]byte]*UDPProxy),
		reconnectCh: make(chan struct{}, 1),
	}
}

// IsConnected returns whether the relay TCP connection is alive.
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// Connect establishes a TCP connection to the relay and starts the background
// reconnect loop. If the initial dial fails the error is returned, but the
// reconnect loop still runs so the client will eventually come online.
func (c *Client) Connect(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	err := c.dial(ctx)
	if err != nil {
		// Seed the reconnect loop so it starts retrying immediately.
		c.signalReconnect()
	}

	go c.reconnectLoop(ctx)

	return err
}

// dial performs a single TCP connect + register handshake.
func (c *Client) dial(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp", c.relayAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to relay %s: %w", c.relayAddr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	writer := bufio.NewWriterSize(conn, 64*1024)
	regFrame := relayproto.MakeRegisterFrame(c.myPubKey)
	if err := relayproto.WriteFrame(writer, regFrame); err != nil {
		conn.Close()
		return fmt.Errorf("sending register: %w", err)
	}
	if err := writer.Flush(); err != nil {
		conn.Close()
		return fmt.Errorf("flushing register: %w", err)
	}

	c.mu.Lock()
	old := c.conn
	c.conn = conn
	c.writer = writer
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}

	c.connected.Store(true)

	go c.readLoop(ctx)
	go c.keepaliveLoop(ctx, conn)

	log.Printf("relay-client: connected to %s", c.relayAddr)
	return nil
}

func (c *Client) readLoop(ctx context.Context) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return
	}

	reader := bufio.NewReader(conn)
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
				c.signalReconnect()
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

			if c.onData != nil {
				c.onData(srcKey, payload)
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

// keepaliveLoop is scoped to a single TCP connection. It exits when the
// connection changes or the context is cancelled.
func (c *Client) keepaliveLoop(ctx context.Context, forConn net.Conn) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			sameConn := c.conn == forConn
			w := c.writer
			c.mu.RUnlock()
			if !sameConn || w == nil {
				return
			}
			c.mu.Lock()
			var writeErr error
			if c.writer != nil {
				writeErr = relayproto.WriteFrame(c.writer, relayproto.MakeKeepaliveFrame())
				if writeErr == nil {
					writeErr = c.writer.Flush()
				}
			}
			c.mu.Unlock()
			if writeErr != nil {
				c.signalReconnect()
				return
			}
		}
	}
}

func (c *Client) signalReconnect() {
	c.connected.Store(false)
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.writer = nil
	}
	c.mu.Unlock()
	select {
	case c.reconnectCh <- struct{}{}:
	default:
	}
}

func (c *Client) reconnectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.reconnectCh:
		}

		backoff := time.Second
		const maxBackoff = 30 * time.Second

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			if err := c.dial(ctx); err != nil {
				log.Printf("relay-client: reconnect failed: %v (retry in %v)", err, backoff)
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				continue
			}
			log.Printf("relay-client: reconnected")
			break
		}
	}
}

// SendNATProbe asks the relay to send a UDP probe from a different source port
// to the specified mapped endpoint. Used for port-restricted cone detection.
func (c *Client) SendNATProbe(ip net.IP, port int) error {
	frame := relayproto.MakeNATProbeFrame(ip, port)
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
