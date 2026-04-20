//go:build linux

package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// mockRelayTransport implements RelayTransport for testing.
type mockRelayTransport struct {
	mu        sync.Mutex
	sent      []mockRelayCall
	hints     [][32]byte
	connected bool
}

type mockRelayCall struct {
	destKey [32]byte
	payload []byte
}

func (m *mockRelayTransport) SendToPeer(dest [32]byte, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mockRelayCall{dest, append([]byte(nil), payload...)})
	return nil
}

func (m *mockRelayTransport) SendBimodalHint(dest [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hints = append(m.hints, dest)
	return nil
}

func (m *mockRelayTransport) IsConnected() bool { return m.connected }

func TestBindOpenClose(t *testing.T) {
	b := NewWireKubeBind()

	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if port == 0 {
		t.Error("Open() returned port 0")
	}
	if len(fns) != 1 {
		t.Errorf("Open() without relay returned %d ReceiveFuncs, want 1", len(fns))
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func TestBindOpenWithRelay(t *testing.T) {
	b := NewWireKubeBind()
	b.SetRelayTransport(&mockRelayTransport{connected: true})

	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	if len(fns) != 2 {
		t.Errorf("Open() with relay returned %d ReceiveFuncs, want 2", len(fns))
	}

	b.Close()
}

func TestBindParseEndpoint(t *testing.T) {
	b := NewWireKubeBind()

	ep, err := b.ParseEndpoint("192.168.1.1:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint() error: %v", err)
	}
	wkep, ok := ep.(*WireKubeEndpoint)
	if !ok {
		t.Fatal("ParseEndpoint() did not return *WireKubeEndpoint")
	}
	if wkep.dst != netip.MustParseAddrPort("192.168.1.1:51820") {
		t.Errorf("endpoint dst = %v, want 192.168.1.1:51820", wkep.dst)
	}

	_, err = b.ParseEndpoint("invalid")
	if err == nil {
		t.Error("ParseEndpoint(invalid) should return error")
	}
}

func TestBindPathTable(t *testing.T) {
	b := NewWireKubeBind()

	pubKey := "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleT0="
	addr := netip.MustParseAddrPort("1.2.3.4:51820")

	b.SetPeerPath(pubKey, PathModeDirect, addr)

	pp := b.GetPeerPath(pubKey)
	if pp == nil {
		t.Fatal("GetPeerPath() returned nil")
	}
	if pp.Mode.Load() != PathModeDirect {
		t.Errorf("mode = %d, want PathModeDirect(%d)", pp.Mode.Load(), PathModeDirect)
	}
	if pp.DirectAddr != addr {
		t.Errorf("addr = %v, want %v", pp.DirectAddr, addr)
	}

	// Switch to relay
	b.SetPeerPath(pubKey, PathModeRelay, addr)
	if pp.Mode.Load() != PathModeRelay {
		t.Errorf("mode after relay switch = %d, want PathModeRelay(%d)", pp.Mode.Load(), PathModeRelay)
	}
}

func TestBindSendReceive(t *testing.T) {
	a := NewWireKubeBind()
	b := NewWireKubeBind()

	fnsA, portA, err := a.Open(0)
	if err != nil {
		t.Fatalf("Open A: %v", err)
	}
	defer a.Close()

	fnsB, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open B: %v", err)
	}
	defer b.Close()

	_ = fnsA

	// Send from A to B
	epB := &WireKubeEndpoint{dst: netip.MustParseAddrPort("127.0.0.1:" + fmt.Sprintf("%d", portA))}
	_ = epB

	// Parse B's endpoint for A to send to
	bPort := b.port
	epToB, err := a.ParseEndpoint(fmt.Sprintf("127.0.0.1:%d", bPort))
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}

	payload := []byte("hello-wirekube")
	if err := a.Send([][]byte{payload}, epToB); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Receive on B
	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	n, err := fnsB[0](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("ReceiveFunc: %v", err)
	}
	if n != 1 {
		t.Fatalf("received %d packets, want 1", n)
	}
	if sizes[0] != len(payload) {
		t.Errorf("received size = %d, want %d", sizes[0], len(payload))
	}
	if string(bufs[0][:sizes[0]]) != string(payload) {
		t.Errorf("received = %q, want %q", bufs[0][:sizes[0]], payload)
	}
}

func TestBindRelayDelivery(t *testing.T) {
	b := NewWireKubeBind()
	b.SetRelayTransport(&mockRelayTransport{connected: true})

	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer b.Close()

	if len(fns) < 2 {
		t.Fatal("expected 2 ReceiveFuncs with relay, got", len(fns))
	}

	srcKey := [32]byte{1, 2, 3}
	pubKey := base64.StdEncoding.EncodeToString(srcKey[:])
	b.SetPeerPath(pubKey, PathModeRelay, netip.MustParseAddrPort("127.0.0.1:51820"))

	// Deliver a relay packet
	pkt := RelayPacket{
		SrcKey:  srcKey,
		Payload: []byte("relay-payload"),
	}
	b.DeliverRelayPacket(pkt)

	// Read from relay ReceiveFunc (fns[1])
	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	done := make(chan error, 1)
	go func() {
		n, err := fns[1](bufs, sizes, eps)
		if err != nil {
			done <- err
			return
		}
		if n != 1 {
			done <- fmt.Errorf("received %d packets, want 1", n)
			return
		}
		if string(bufs[0][:sizes[0]]) != "relay-payload" {
			done <- fmt.Errorf("payload = %q, want %q", bufs[0][:sizes[0]], "relay-payload")
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay ReceiveFunc timed out")
	}

	pp := b.GetPeerPath(pubKey)
	if pp == nil {
		t.Fatal("GetPeerPath() returned nil")
	}
	if pp.RelayHealth.LastSeen.Load() == 0 {
		t.Fatal("RelayHealth.LastSeen was not updated on relay receive")
	}
}

// TestBindAcceptsDirectPacketsWhileRelayPreferred verifies dual-path behavior:
// Direct packets are accepted with real endpoints even when relay is preferred,
// enabling seamless path switching without endpoint virtualization.
func TestBindAcceptsDirectPacketsWhileRelayPreferred(t *testing.T) {
	b := NewWireKubeBind()
	b.SetRelayTransport(&mockRelayTransport{connected: true})

	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer b.Close()

	if len(fns) < 2 {
		t.Fatal("expected 2 ReceiveFuncs with relay")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(sender): %v", err)
	}
	defer sender.Close()

	senderAddr, err := netip.ParseAddrPort(sender.LocalAddr().String())
	if err != nil {
		t.Fatalf("ParseAddrPort(sender): %v", err)
	}

	srcKey := [32]byte{9, 9, 9}
	pubKey := base64.StdEncoding.EncodeToString(srcKey[:])
	b.SetPeerPath(pubKey, PathModeRelay, senderAddr)

	done := make(chan struct {
		payload string
		ep      *WireKubeEndpoint
		err     string
	}, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)

		n, err := fns[0](bufs, sizes, eps)
		if err != nil {
			done <- struct {
				payload string
				ep      *WireKubeEndpoint
				err     string
			}{err: fmt.Sprintf("direct receive error: %v", err)}
			return
		}
		if n != 1 {
			done <- struct {
				payload string
				ep      *WireKubeEndpoint
				err     string
			}{err: fmt.Sprintf("direct receive count=%d", n)}
			return
		}
		wkep, _ := eps[0].(*WireKubeEndpoint)
		done <- struct {
			payload string
			ep      *WireKubeEndpoint
			err     string
		}{
			payload: string(bufs[0][:sizes[0]]),
			ep:      wkep,
		}
	}()

	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	if _, err := sender.WriteToUDP([]byte("direct-packet"), target); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	select {
	case got := <-done:
		if got.err != "" {
			t.Fatal(got.err)
		}
		if got.payload != "direct-packet" {
			t.Fatalf("payload = %q, want %q", got.payload, "direct-packet")
		}
		if got.ep == nil {
			t.Fatal("expected WireKubeEndpoint")
		}
		// In dual-path mode, endpoints are NOT virtualized. This allows WireGuard
		// to learn actual peer addresses for proper path switching.
		if got.ep.dst != senderAddr {
			t.Fatalf("endpoint dst = %v, want %v", got.ep.dst, senderAddr)
		}
		// Note: peerKey is not set for direct UDP receives (unlike relay receives).
		// WireGuard identifies peers by the key in the WireGuard crypto header,
		// not by source endpoint.
	case <-time.After(2 * time.Second):
		t.Fatal("direct packet should have been received promptly")
	}

	relayPkt := RelayPacket{SrcKey: srcKey, Payload: []byte("relay-payload")}
	b.DeliverRelayPacket(relayPkt)

	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[1](bufs, sizes, eps)
	if err != nil {
		t.Fatalf("relay receive error: %v", err)
	}
	if n != 1 {
		t.Fatalf("relay receive count=%d, want 1", n)
	}
	if got := string(bufs[0][:sizes[0]]); got != "relay-payload" {
		t.Fatalf("relay payload = %q, want %q", got, "relay-payload")
	}
}

func TestBindLearnsReboundDirectAddrByIP(t *testing.T) {
	b := NewWireKubeBind()

	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer b.Close()

	originalAddr := netip.MustParseAddrPort("127.0.0.1:51820")
	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	b.SetPeerPath(pubKey, PathModeDirect, originalAddr)

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(sender): %v", err)
	}
	defer sender.Close()

	done := make(chan error, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		_, err := fns[0](bufs, sizes, eps)
		done <- err
	}()

	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}
	if _, err := sender.WriteToUDP([]byte{1, 0, 0, 0, 0}, target); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ReceiveFunc: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct packet receive timed out")
	}

	pp := b.GetPeerPath(pubKey)
	if pp == nil {
		t.Fatal("GetPeerPath() returned nil")
	}
	if got := pp.DirectHealth.LastSeen.Load(); got == 0 {
		t.Fatal("DirectHealth.LastSeen was not updated for rebound direct source port")
	}
	if _, ok := b.addrToPeer.Load(sender.LocalAddr().String()); !ok {
		t.Fatalf("addrToPeer did not learn rebound sender addr %s", sender.LocalAddr().String())
	}
}

func TestBindSendRelayMode(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	_, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	// Use a valid 32-byte key (base64 encoded)
	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("1.2.3.4:51820")
	b.SetPeerPath(pubKey, PathModeRelay, addr)

	ep := &WireKubeEndpoint{dst: addr}
	payload := []byte("relay-test")
	if err := b.Send([][]byte{payload}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.sent) != 1 {
		t.Fatalf("relay received %d calls, want 1", len(relay.sent))
	}
	if string(relay.sent[0].payload) != "relay-test" {
		t.Errorf("relay payload = %q, want %q", relay.sent[0].payload, "relay-test")
	}
}

// TestBindSendDoesNotUpdateReceiveEvidence guards the invariant that
// PathHealth.LastSeen is updated only by actual receives. A successful
// Send() returns nil whenever the local UDP stack accepts the buffer,
// which is independent of whether the peer's return path is alive —
// so treating send success as receive evidence would suppress direct→relay
// failover when only inbound WG UDP is firewalled. This test locks in
// the receive-only semantic so the regression fixed in fc747e7 / 97b7ccf
// cannot silently return.
func TestBindSendDoesNotUpdateReceiveEvidence(t *testing.T) {
	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("127.0.0.1:59997")
	// WireGuard control packet (type 1 = handshake init). Probing/RelayProbe
	// branches classify packets by IsControl, so using a control payload
	// exercises both the UDP WriteToUDP side and the relay SendToPeer side
	// inside those modes.
	controlPayload := []byte{1, 0, 0, 0, 0}

	cases := []struct {
		name string
		mode int32
	}{
		{"direct", PathModeDirect},
		{"warm", PathModeWarm},
		{"relay", PathModeRelay},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := &mockRelayTransport{connected: true}
			b := NewWireKubeBind()
			b.SetRelayTransport(relay)

			if _, _, err := b.Open(0); err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer b.Close()

			b.SetPeerPath(pubKey, tc.mode, addr)
			pp := b.GetPeerPath(pubKey)
			if pp == nil {
				t.Fatal("GetPeerPath() returned nil")
			}

			ep := &WireKubeEndpoint{dst: addr}
			if err := b.Send([][]byte{controlPayload}, ep); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if got := pp.DirectHealth.LastSeen.Load(); got != 0 {
				t.Fatalf("DirectHealth.LastSeen = %d, want 0 after send-only traffic", got)
			}
			if got := pp.RelayHealth.LastSeen.Load(); got != 0 {
				t.Fatalf("RelayHealth.LastSeen = %d, want 0 after send-only traffic", got)
			}
		})
	}
}

// TestBindSendWarmModeDuplicatesPackets verifies that PathModeWarm sends
// each outgoing packet on BOTH the UDP leg and the relay leg (Tailscale
// DERP-style duplicate send). This is the correctness contract that makes
// direct→relay failover blackout-free: if the direct leg stops working,
// the receiver has already accepted the relay copy of every packet in
// flight at the moment trust expired.
func TestBindSendWarmModeDuplicatesPackets(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("127.0.0.1:59997")
	b.SetPeerPath(pubKey, PathModeWarm, addr)

	ep := &WireKubeEndpoint{dst: addr}
	// Mix control (type 1) and data (type 4) packets to verify the mode
	// does not split by packet type — warm sends every packet on every leg.
	payloads := [][]byte{{1, 0, 0, 0, 0}, {4, 0, 0, 0, 0}}
	if err := b.Send(payloads, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.sent) != len(payloads) {
		t.Fatalf("relay received %d sends, want %d (one per outgoing packet regardless of type)",
			len(relay.sent), len(payloads))
	}
}

// TestBindSendDirectModeSkipsRelayWhenFresh verifies the bandwidth-saving
// property of PathModeDirect: when the direct receive watermark is fresh
// (within directTrustWindow), Send uses the UDP leg only. The relay stays
// connected by the relay pool but is not exercised on the datapath.
//
// Pair this with TestBindSendDirectModeUsesRelayWhenStale, which asserts
// the other half of the contract — stale LastSeen (or zero, meaning no
// direct packet ever observed) forces dual-send defensively.
func TestBindSendDirectModeSkipsRelayWhenFresh(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("127.0.0.1:59996")
	b.SetPeerPath(pubKey, PathModeDirect, addr)
	// Simulate a recent direct receive so the datapath trust window treats
	// direct as proven. Without this the Send() auto-upgrades to dual send
	// because LastSeen == 0 reads as "never proven, be defensive".
	pp := b.GetPeerPath(pubKey)
	if pp == nil {
		t.Fatal("GetPeerPath() returned nil")
	}
	pp.DirectHealth.LastSeen.Store(time.Now().UnixNano())

	ep := &WireKubeEndpoint{dst: addr}
	if err := b.Send([][]byte{{1, 0, 0, 0, 0}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.sent) != 0 {
		t.Fatalf("relay received %d sends under fresh PathModeDirect, want 0", len(relay.sent))
	}
}

// TestBindSendDirectModeUsesRelayWhenStale asserts the converse: if a peer
// is in PathModeDirect but its direct receive watermark has not updated
// within directTrustWindow (3s), Send() dual-paths the current packet to
// the relay leg too. This is the datapath's automatic failover mechanism
// — it bounds blackout to the trust window without waiting for the agent
// to demote the peer to PathModeWarm.
func TestBindSendDirectModeUsesRelayWhenStale(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("127.0.0.1:59995")
	b.SetPeerPath(pubKey, PathModeDirect, addr)
	pp := b.GetPeerPath(pubKey)
	if pp == nil {
		t.Fatal("GetPeerPath() returned nil")
	}
	// Set the watermark deep in the past so the trust window is definitely
	// expired. Zero would also work (the code treats 0 as "never"), but
	// using a non-zero stale value exercises the "had RX once, then lost"
	// failover path that the test name describes.
	pp.DirectHealth.LastSeen.Store(time.Now().Add(-1 * time.Hour).UnixNano())

	ep := &WireKubeEndpoint{dst: addr}
	if err := b.Send([][]byte{{1, 0, 0, 0, 0}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.sent) != 1 {
		t.Fatalf("relay received %d sends under stale PathModeDirect, want 1 (datapath auto-fallback)", len(relay.sent))
	}
}

// TestBindSendFiresBimodalHintOnStale asserts that a stale direct receive
// watermark in PathModeDirect triggers a relay-delivered BimodalHint so the
// remote peer (which cannot observe its own outbound blackhole) is pulled
// into dual-send mode. Without this, asymmetric UDP drops would wait for
// the agent's control plane to time out (~30s).
func TestBindSendFiresBimodalHintOnStale(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("127.0.0.1:59994")
	b.SetPeerPath(pubKey, PathModeDirect, addr)
	pp := b.GetPeerPath(pubKey)
	if pp == nil {
		t.Fatal("GetPeerPath() returned nil")
	}
	pp.DirectHealth.LastSeen.Store(time.Now().Add(-1 * time.Hour).UnixNano())

	ep := &WireKubeEndpoint{dst: addr}
	if err := b.Send([][]byte{{1, 0, 0, 0, 0}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.hints) != 1 {
		t.Fatalf("bimodal hints sent = %d, want 1", len(relay.hints))
	}
}

// TestBindSendRateLimitsBimodalHints asserts the rate-limit: repeated stale
// sends within bimodalHintSendInterval produce only one outbound hint.
func TestBindSendRateLimitsBimodalHints(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	addr := netip.MustParseAddrPort("127.0.0.1:59993")
	b.SetPeerPath(pubKey, PathModeDirect, addr)
	pp := b.GetPeerPath(pubKey)
	pp.DirectHealth.LastSeen.Store(time.Now().Add(-1 * time.Hour).UnixNano())

	ep := &WireKubeEndpoint{dst: addr}
	for i := 0; i < 5; i++ {
		if err := b.Send([][]byte{{1, 0, 0, 0, 0}}, ep); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.hints) != 1 {
		t.Fatalf("rate-limited hints = %d, want exactly 1", len(relay.hints))
	}
}

// TestBindMarkBimodalHintForcesDualSend asserts that an inbound hint makes
// subsequent Sends dual-path to the peer even when its Mode is Direct and
// the local direct watermark is fresh (the asymmetric case).
func TestBindMarkBimodalHintForcesDualSend(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pubKeyBytes := make([]byte, 32)
	pubKeyBytes[0] = 0x42
	pubKey := base64.StdEncoding.EncodeToString(pubKeyBytes)
	addr := netip.MustParseAddrPort("127.0.0.1:59992")
	b.SetPeerPath(pubKey, PathModeDirect, addr)
	pp := b.GetPeerPath(pubKey)
	pp.DirectHealth.LastSeen.Store(time.Now().UnixNano())

	var srcKey [32]byte
	copy(srcKey[:], pubKeyBytes)
	b.MarkBimodalHint(srcKey)

	ep := &WireKubeEndpoint{dst: addr}
	if err := b.Send([][]byte{{1, 0, 0, 0, 0}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}

	relay.mu.Lock()
	defer relay.mu.Unlock()
	if len(relay.sent) != 1 {
		t.Fatalf("relay sends under hinted PathModeDirect = %d, want 1", len(relay.sent))
	}
	// The locally-sent hint is NOT in this assertion: we are testing the
	// inbound-hint path, not the stale-detection path.
}

func TestBindBatchSize(t *testing.T) {
	b := NewWireKubeBind()
	if b.BatchSize() != 1 {
		t.Errorf("BatchSize() = %d, want 1", b.BatchSize())
	}
}
