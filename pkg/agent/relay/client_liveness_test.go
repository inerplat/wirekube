package relay

import (
	"bufio"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	relayproto "github.com/inerplat/wirekube/pkg/relay"
)

func withFastKeepalive(t *testing.T) {
	t.Helper()
	oldI, oldT := relayKeepaliveInterval, relayRxTimeout
	relayKeepaliveInterval, relayRxTimeout = 20*time.Millisecond, 150*time.Millisecond
	t.Cleanup(func() { relayKeepaliveInterval, relayRxTimeout = oldI, oldT })
}

// pipeClient wires a Client to one end of a pipe and runs its read and
// keepalive loops, the way dial does after registering.
func pipeClient(t *testing.T) (*Client, net.Conn) {
	t.Helper()
	server, clientSide := net.Pipe()
	t.Cleanup(func() { server.Close(); clientSide.Close() })
	c := NewClient("pipe", [32]byte{}, 0)
	c.conn = clientSide
	c.writer = bufio.NewWriterSize(clientSide, 64*1024)
	c.lastRxNs.Store(time.Now().UnixNano())
	c.connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.readLoop(ctx) }()
	go func() { defer wg.Done(); c.keepaliveLoop(ctx, clientSide) }()
	// The loops read package-level knobs that tests override; they must be
	// gone before any cleanup restores those knobs or the next test sets them.
	t.Cleanup(func() {
		cancel()
		server.Close()
		clientSide.Close()
		wg.Wait()
	})
	return c, server
}

func waitDisconnected(c *Client, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !c.IsConnected() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// Once the relay has echoed a keepalive, an inbound direction that goes
// silent past relayRxTimeout tears the connection down for the reconnect
// loop, even though the client's own writes keep succeeding.
func TestKeepaliveDropsConnectionWhenInboundGoesSilent(t *testing.T) {
	withFastKeepalive(t)
	c, server := pipeClient(t)

	// The relay: echo keepalives for a while, then keep reading (so client
	// writes succeed) but never answer again.
	echo := make(chan bool, 1)
	echo <- true
	go func() {
		r := bufio.NewReader(server)
		answer := true
		for {
			if _, err := relayproto.ReadFrame(r); err != nil {
				return
			}
			select {
			case answer = <-echo:
			default:
			}
			if answer {
				_ = relayproto.WriteFrame(server, relayproto.MakeKeepaliveFrame())
			}
		}
	}()

	time.Sleep(200 * time.Millisecond) // several echoed keepalives
	if !c.IsConnected() {
		t.Fatal("connection dropped while the relay was echoing keepalives")
	}
	echo <- false
	if !waitDisconnected(c, 2*time.Second) {
		t.Fatal("connection kept after the inbound direction went silent past relayRxTimeout")
	}
	select {
	case <-c.reconnectCh:
	default:
		t.Fatal("silent connection was dropped without waking the reconnect loop")
	}
}

// A relay that predates the echo never answers a keepalive. The receive
// timeout must stay disarmed there, or every idle connection would flap.
func TestKeepaliveToleratesRelayWithoutEcho(t *testing.T) {
	withFastKeepalive(t)
	c, server := pipeClient(t)
	go func() {
		r := bufio.NewReader(server)
		for {
			if _, err := relayproto.ReadFrame(r); err != nil {
				return
			}
		}
	}()
	if waitDisconnected(c, 600*time.Millisecond) {
		t.Fatal("connection to a relay that never echoes was dropped as silent")
	}
}

// dropConn must not close a connection that already replaced the one the
// caller judged dead.
func TestDropConnIgnoresReplacedConnection(t *testing.T) {
	oldServer, oldConn := net.Pipe()
	defer oldServer.Close()
	defer oldConn.Close()
	newServer, newConn := net.Pipe()
	defer newServer.Close()
	defer newConn.Close()

	c := NewClient("pipe", [32]byte{}, 0)
	c.conn = newConn
	c.writer = bufio.NewWriter(newConn)
	c.connected.Store(true)

	c.dropConn(oldConn)
	if !c.IsConnected() || c.conn != newConn {
		t.Fatal("dropConn for a stale connection tore down its replacement")
	}
}

// A read loop whose connection was already replaced ends with a read error on
// the closed socket. It must leave the replacement alone: tearing it down from
// there is what turned one reconnect into a cascade of three.
func TestReadLoopOnReplacedConnectionLeavesReplacementAlone(t *testing.T) {
	oldServer, oldConn := net.Pipe()
	defer oldServer.Close()
	newServer, newConn := net.Pipe()
	defer newServer.Close()
	defer newConn.Close()

	c := NewClient("pipe", [32]byte{}, 0)
	c.conn = oldConn
	c.writer = bufio.NewWriter(oldConn)
	c.connected.Store(true)

	done := make(chan struct{})
	go func() { defer close(done); c.readLoop(context.Background()) }()
	time.Sleep(20 * time.Millisecond) // let the loop pick up oldConn

	// What dial does on a reconnect: install the new connection, close the old.
	c.mu.Lock()
	c.conn = newConn
	c.writer = bufio.NewWriter(newConn)
	c.mu.Unlock()
	oldConn.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("read loop did not exit after its connection closed")
	}
	if !c.IsConnected() || c.conn != newConn {
		t.Fatal("the stale read loop tore down the replacement connection")
	}
	select {
	case <-c.reconnectCh:
		t.Fatal("the stale read loop woke the reconnect loop")
	default:
	}
}
