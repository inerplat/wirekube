package relay

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	relayproto "github.com/inerplat/wirekube/pkg/relay"
)

var clientDebug = os.Getenv("WIREKUBE_BIND_DEBUG") == "1"

// Client manages a TCP connection to the relay server and routes packets
// between local UDP proxies and remote peers via the relay.
//
// Connection lifecycle:
//   - Connect() dials the relay and starts a background reconnect loop.
//   - If the TCP connection drops, the client automatically reconnects
//     with exponential backoff (1s → 30s cap).
//   - Proxies survive reconnections — they are bound to the Client, not the
//     TCP connection, and resume forwarding once the new connection is up.
//
// DataHandler is called when a Data frame arrives. If nil, the Client falls
// back to its own proxy map. Pool sets this to route data through its own
// proxy map instead.
type DataHandler func(srcKey [relayproto.PubKeySize]byte, payload []byte)

// ExternalDataHandler is called when a raw WireGuard datagram arrives from a
// relay shared external listener. relayAddr identifies the TCP relay client
// that owns the token, so responses can be sent back to the same relay.
type ExternalDataHandler func(relayAddr string, sourceToken uint64, sourceAddr string, payload []byte)

// HintHandler is called when a BimodalHint frame arrives from a sender key.
// The handler should mark the sender peer to receive dual-leg sends for a
// short trust window so asymmetric UDP blackholes recover immediately.
type HintHandler func(srcKey [relayproto.PubKeySize]byte)

type Client struct {
	relayAddr string
	myPubKey  [relayproto.PubKeySize]byte
	wgPort    int
	proxyMode ProxyMode
	proxyURL  *url.URL
	tokenFile string

	mu      sync.RWMutex
	conn    net.Conn
	writer  *bufio.Writer
	proxies map[[relayproto.PubKeySize]byte]*UDPProxy

	onData     DataHandler
	onExternal ExternalDataHandler
	onHint     HintHandler
	connected  atomic.Bool
	// lastRxNs is when the current connection last delivered a frame, and
	// echoSeen whether the relay has echoed a keepalive on it. Together they
	// let keepaliveLoop tell a dead inbound direction from an idle one.
	lastRxNs    atomic.Int64
	echoSeen    atomic.Bool
	reconnectCh chan struct{} // signalled by readLoop on disconnect
	cancel      context.CancelFunc
}

func NewClient(relayAddr string, myPubKey [relayproto.PubKeySize]byte, wgPort int) *Client {
	return &Client{
		relayAddr:   relayAddr,
		myPubKey:    myPubKey,
		wgPort:      wgPort,
		proxyMode:   ProxyDisabled,
		proxies:     make(map[[relayproto.PubKeySize]byte]*UDPProxy),
		reconnectCh: make(chan struct{}, 1),
	}
}

func (c *Client) SetProxyMode(mode ProxyMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proxyMode = mode.normalized()
	c.proxyURL = nil
}

func (c *Client) SetProxyURL(proxyURL *url.URL) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proxyMode = ProxyExplicit
	c.proxyURL = proxyURL
}

func (c *Client) SetTokenFile(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenFile = path
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

const dialTimeout = 10 * time.Second

// relayWriteTimeout bounds every client-side relay TCP write. The server
// kills a stalled connection from its side; without a client-side bound the
// writing goroutine instead blocks indefinitely while holding c.mu, wedging
// the keepalive, every other relay sender and signalReconnect — which needs
// the same mutex — until the server's RST happens to arrive.
var relayWriteTimeout = 10 * time.Second

// relayKeepaliveInterval is how often the client sends a keepalive, which the
// relay echoes. relayRxTimeout is how long the connection may then deliver
// nothing before the client gives up on it. The timeout sits above the longest
// inbound stall a connection is expected to ride out on its own and below the
// point where the stall has outlived the relay's patience: tearing down
// earlier would turn every short stall into a reconnect.
var (
	relayKeepaliveInterval = 2 * time.Second
	relayRxTimeout         = 8 * time.Second
)

// dial performs a single TCP connect + register handshake.
// The TCP socket is marked with the WireKube fwmark (SO_MARK) so that
// it bypasses the WireKube routing table and uses the main table.
// Without this, relay TCP would be routed through the WG tunnel itself,
// creating a circular dependency that kills relay connectivity.
func (c *Client) dial(ctx context.Context) error {
	dialer := net.Dialer{
		Timeout: dialTimeout,
		Control: dialControl,
	}
	c.mu.RLock()
	proxyMode := c.proxyMode
	proxyURL := c.proxyURL
	tokenFile := c.tokenFile
	c.mu.RUnlock()
	conn, err := dialRelay(ctx, &dialer, c.relayAddr, proxyMode, proxyURL, tokenFile)
	if err != nil {
		return fmt.Errorf("connecting to relay %s: %w", c.relayAddr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) //nolint:errcheck
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
	c.echoSeen.Store(false)
	c.lastRxNs.Store(time.Now().UnixNano())
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
			// Only the loop whose connection is still current may tear the
			// client down. A connection that keepaliveLoop dropped or a
			// reconnect replaced also ends here, with "use of closed network
			// connection"; signalling for it would close the replacement and
			// start a reconnect cascade.
			if ctx.Err() == nil && c.dropConn(conn) {
				log.Printf("relay-client: read error: %v", err)
			}
			return
		}
		c.lastRxNs.Store(time.Now().UnixNano())

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

		case relayproto.MsgBimodalHint:
			srcKey, err := relayproto.ParseBimodalHintFrame(frame.Body)
			if err != nil {
				log.Printf("relay-client: bad bimodal hint frame: %v", err)
				continue
			}
			if c.onHint != nil {
				c.onHint(srcKey)
			}

		case relayproto.MsgRelayProbe:
			token, err := relayproto.ParseRelayProbeFrame(frame.Body)
			if err != nil {
				log.Printf("relay-client: bad relay probe frame: %v", err)
				continue
			}
			if err := c.sendFrame(relayproto.MakeRelayProbeFrame(token)); err != nil {
				// sendFrame already dropped the connection it failed on.
				log.Printf("relay-client: relay probe response failed: %v", err)
				return
			}

		case relayproto.MsgExternalData:
			sourceToken, sourceAddr, payload, err := relayproto.ParseExternalDataFrame(frame.Body)
			if err != nil {
				log.Printf("relay-client: bad external data frame: %v", err)
				continue
			}
			if c.onExternal != nil {
				c.onExternal(c.relayAddr, sourceToken, sourceAddr, payload)
			}

		case relayproto.MsgError:
			log.Printf("relay-client: server error: %s", string(frame.Body))

		case relayproto.MsgKeepalive:
			// The relay echoes keepalives; seeing one arms the receive
			// timeout in keepaliveLoop. A relay that predates the echo never
			// sends this, and the timeout stays off.
			c.echoSeen.Store(true)
		}
	}
}

// keepaliveLoop is scoped to a single TCP connection. It exits when the
// connection changes or the context is cancelled.
func (c *Client) keepaliveLoop(ctx context.Context, forConn net.Conn) {
	ticker := time.NewTicker(relayKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			sameConn := c.conn == forConn
			c.mu.RUnlock()
			if !sameConn {
				return
			}
			// The relay echoes every keepalive, so once one echo has been
			// seen a healthy connection delivers a frame at least every
			// interval. Silence past relayRxTimeout means the inbound
			// direction is dead even though our writes still succeed — the
			// state in which the relay has already closed the connection and
			// its RST is stuck behind the same blackout. Reconnecting now
			// instead of waiting for that RST also discards the relay's stale
			// queue and the old connection's backed-off retransmit timer.
			if c.echoSeen.Load() {
				if silent := time.Since(time.Unix(0, c.lastRxNs.Load())); silent > relayRxTimeout {
					log.Printf("relay-client: no frame from relay for %v, reconnecting", silent.Round(time.Millisecond))
					c.dropConn(forConn)
					return
				}
			}
			if err := c.sendFrame(relayproto.MakeKeepaliveFrame()); err != nil {
				return
			}
		}
	}
}

// dropConn tears down forConn and wakes the reconnect loop, but only while
// forConn is still the client's current connection, and reports whether it
// did. A caller that decided on stale evidence must not close the replacement
// a reconnect already installed.
func (c *Client) dropConn(forConn net.Conn) bool {
	c.mu.Lock()
	if forConn == nil || c.conn != forConn {
		c.mu.Unlock()
		return false
	}
	c.connected.Store(false)
	c.conn.Close()
	c.conn = nil
	c.writer = nil
	c.mu.Unlock()
	select {
	case c.reconnectCh <- struct{}{}:
	default:
	}
	return true
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

// sendFrame writes one frame to the current relay connection. The write is
// bounded by relayWriteTimeout so a stalled socket cannot hold c.mu — and
// every other relay sender queued behind it — indefinitely. A failed write
// tears the connection down for the reconnect loop: bufio's error is sticky
// and a timed-out batch may have left a partial frame on the wire, so the
// stream cannot be trusted again.
func (c *Client) sendFrame(frame relayproto.Frame) error {
	c.mu.Lock()
	if c.writer == nil {
		c.mu.Unlock()
		return fmt.Errorf("not connected")
	}
	conn := c.conn
	if conn != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
	}
	err := relayproto.WriteFrame(c.writer, frame)
	if err == nil {
		err = c.writer.Flush()
	}
	c.mu.Unlock()
	if err != nil {
		// Drop the connection this write failed on, not whatever is current
		// by now: a reconnect may already have replaced it.
		c.dropConn(conn)
	}
	return err
}

// SendNATProbe asks the relay to send a UDP probe from a different source port
// to the specified mapped endpoint. Used for port-restricted cone detection.
func (c *Client) SendNATProbe(ip net.IP, port int) error {
	return c.sendFrame(relayproto.MakeNATProbeFrame(ip, port))
}

// SendToPeer sends a UDP payload to a remote peer through the relay.
func (c *Client) SendToPeer(destPubKey [relayproto.PubKeySize]byte, payload []byte) error {
	return c.sendFrame(relayproto.MakeDataFrame(destPubKey, payload))
}

// SendToExternal sends a raw WireGuard response packet back to a source token
// owned by this relay connection's shared external listener.
func (c *Client) SendToExternal(sourceToken uint64, payload []byte) error {
	if err := c.sendFrame(relayproto.MakeExternalDataFrame(sourceToken, "", payload)); err != nil {
		return err
	}
	if clientDebug {
		log.Printf("relay-client: external response sent relay=%s token=%d len=%d", c.relayAddr, sourceToken, len(payload))
	}
	return nil
}

// SendBimodalHint asks the relay to deliver a hint to destPubKey telling it
// to dual-send subsequent packets on both direct and relay legs. Used when
// the local receive watermark has stalled but send keeps succeeding, which
// indicates an asymmetric UDP blackhole.
func (c *Client) SendBimodalHint(destPubKey [relayproto.PubKeySize]byte) error {
	return c.sendFrame(relayproto.MakeBimodalHintFrame(destPubKey))
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
