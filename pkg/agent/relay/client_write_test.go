package relay

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// A stalled relay socket must fail the write within relayWriteTimeout and
// tear the connection down for the reconnect loop, instead of blocking
// forever while holding c.mu — which wedges the keepalive, every other relay
// sender and signalReconnect behind it.
func TestSendToPeerBoundedByWriteDeadline(t *testing.T) {
	old := relayWriteTimeout
	relayWriteTimeout = 100 * time.Millisecond
	defer func() { relayWriteTimeout = old }()

	server, clientSide := net.Pipe()
	defer server.Close()

	c := NewClient("pipe", [32]byte{}, 0)
	c.conn = clientSide
	c.writer = bufio.NewWriterSize(clientSide, 64*1024)
	c.connected.Store(true)

	done := make(chan error, 1)
	go func() { done <- c.SendToPeer([32]byte{1}, make([]byte, 1400)) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("SendToPeer succeeded on a stalled socket")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendToPeer blocked past relayWriteTimeout")
	}
	if c.IsConnected() {
		t.Fatal("client still marked connected after a failed write")
	}
	if c.conn != nil {
		t.Fatal("failed write did not clear the connection for the reconnect loop")
	}
}

// A healthy socket keeps working: the deadline must not disturb the normal
// path, and a write error on a dead connection must be reported to the caller.
func TestSendToPeerSucceedsOnLiveSocket(t *testing.T) {
	server, clientSide := net.Pipe()
	defer server.Close()
	defer clientSide.Close()

	c := NewClient("pipe", [32]byte{}, 0)
	c.conn = clientSide
	c.writer = bufio.NewWriterSize(clientSide, 64*1024)
	c.connected.Store(true)

	done := make(chan error, 1)
	go func() { done <- c.SendToPeer([32]byte{1}, make([]byte, 1400)) }()

	buf := make([]byte, 4096)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendToPeer on a live socket: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendToPeer blocked on a live socket")
	}
	if !c.IsConnected() {
		t.Fatal("live write dropped the connection state")
	}
}
