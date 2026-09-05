//go:build linux

package wireguard

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// fakeClock drives the bind's trust windows and pending TTL without sleeping.
type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Now().UnixNano())
	return c
}

func (c *fakeClock) Now() int64                   { return c.ns.Load() }
func (c *fakeClock) Advance(d time.Duration)      { c.ns.Add(int64(d)) }
func (c *fakeClock) At(d time.Duration) int64     { return c.Now() + int64(d) }
func (c *fakeClock) Before(d time.Duration) int64 { return c.Now() - int64(d) }

// hbPeer is one open bind with a real key pair, a fake clock and a quiescent
// scheduler (the tick override channel is never fed, so ticks happen only
// through tick()).
type hbPeer struct {
	b     *WireKubeBind
	kp    *KeyPair
	key   string // base64 public key
	fns   []conn.ReceiveFunc
	addr  netip.AddrPort
	relay *mockRelayTransport
}

func newHBPeer(t *testing.T, clock *fakeClock, withRelay bool) *hbPeer {
	t.Helper()
	p := &hbPeer{b: NewWireKubeBind(), kp: mustKeyPair(t)}
	p.key = p.kp.PublicKeyBase64()
	p.b.nowNs = clock.Now
	p.b.hbTickOverride = make(chan time.Time)
	if withRelay {
		p.relay = &mockRelayTransport{connected: true}
		p.b.SetRelayTransport(p.relay)
	}
	p.b.SetHeartbeatConfig(p.kp, testMeshMTU)
	fns, port, err := p.b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { p.b.Close() })
	p.fns = fns
	p.addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
	return p
}

func (p *hbPeer) udp() *net.UDPConn {
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	return p.b.udp4
}

// know registers other as a peer in the given mode and marks the session
// active so the scheduler considers it.
func (p *hbPeer) know(t *testing.T, other *hbPeer, mode int32, clock *fakeClock) *PeerPath {
	t.Helper()
	p.b.SetPeerPath(other.key, mode, other.addr)
	pp := p.b.GetPeerPath(other.key)
	if pp == nil {
		t.Fatal("GetPeerPath returned nil")
	}
	if pp.hbKey.Load() == nil {
		t.Fatal("heartbeat key not derived by SetPeerPath")
	}
	pp.lastSendNs.Store(clock.Now())
	return pp
}

func (p *hbPeer) tick(t *testing.T) {
	t.Helper()
	if err := p.b.heartbeatTick(p.udp()); err != nil {
		t.Fatalf("heartbeatTick: %v", err)
	}
}

// recv runs the direct ReceiveFunc once with a deadline and returns its
// result. Heartbeat frames must come back as (0, nil).
func (p *hbPeer) recv(t *testing.T) (int, error) {
	t.Helper()
	if err := p.udp().SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	return p.fns[0](bufs, sizes, eps)
}

func (p *hbPeer) recvHeartbeat(t *testing.T) {
	t.Helper()
	n, err := p.recv(t)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 0 {
		t.Fatalf("receive returned %d packets for a heartbeat frame, want 0 (must never reach wireguard-go)", n)
	}
}

// capture is a plain UDP socket standing in for a peer whose replies the test
// crafts by hand.
type capture struct {
	c    *net.UDPConn
	addr netip.AddrPort
}

func newCapture(t *testing.T) *capture {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return &capture{c: c, addr: netip.MustParseAddrPort(c.LocalAddr().String())}
}

// read returns the next datagram, or nil after wait with nothing received.
func (c *capture) read(t *testing.T, wait time.Duration) []byte {
	t.Helper()
	if err := c.c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, _, err := c.c.ReadFromUDPAddrPort(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		t.Fatalf("capture read: %v", err)
	}
	return buf[:n]
}

func (c *capture) send(t *testing.T, frame []byte, to netip.AddrPort) {
	t.Helper()
	if _, err := c.c.WriteToUDPAddrPort(frame, to); err != nil {
		t.Fatalf("capture write: %v", err)
	}
}

// pongFor builds the pong a peer holding key would send for ping.
func pongFor(t *testing.T, ping []byte, sender [32]byte, key *[32]byte) []byte {
	t.Helper()
	hdr, ok := decodeHeartbeatHeader(ping)
	if !ok {
		t.Fatal("ping header did not decode")
	}
	return encodeHeartbeat(heartbeatFrame{
		Type: heartbeatTypePong, FrameLen: hdr.FrameLen, TxID: hdr.TxID, SentAt: hdr.SentAt, Sender: sender,
	}, key[:])
}

func stats(t *testing.T, p *hbPeer, key string) PathStats {
	t.Helper()
	s, ok := p.b.PeerPathStats(key)
	if !ok {
		t.Fatalf("PeerPathStats(%s) = not found", shortKey(key))
	}
	return s
}

// A ping/pong round trip between two binds refreshes the pinger's lastPongNs
// and RTT and nothing else: neither side's data watermark moves, an inbound
// ping refreshes nothing on the responder, and both frames are swallowed
// before wireguard-go sees them.
func TestHeartbeatRoundTripSetsPongNotLastSeen(t *testing.T) {
	clock := newFakeClock()
	a, b := newHBPeer(t, clock, false), newHBPeer(t, clock, false)
	ppB := a.know(t, b, PathModeDirect, clock)
	ppA := b.know(t, a, PathModeDirect, clock)

	sentAt := clock.Now()
	a.tick(t)
	b.recvHeartbeat(t) // ping consumed, pong sent
	clock.Advance(5 * time.Millisecond)
	a.recvHeartbeat(t) // pong consumed

	if got := a.b.LastDirectPong(b.key); got != clock.Now() {
		t.Fatalf("LastDirectPong = %d, want %d", got, clock.Now())
	}
	if got := ppB.rttNs.Load(); got != clock.Now()-sentAt {
		t.Fatalf("rttNs = %d, want %d (from the pending entry, not the echoed field)", got, clock.Now()-sentAt)
	}
	if ppB.DirectHealth.LastSeen.Load() != 0 || ppA.DirectHealth.LastSeen.Load() != 0 {
		t.Fatal("heartbeat frames refreshed a data watermark")
	}
	if ppA.LearnedAddr().IsValid() {
		t.Fatal("inbound ping stamped a learned address")
	}
	if b.b.LastDirectPong(a.key) != 0 {
		t.Fatal("inbound ping refreshed the responder's pong watermark")
	}
	sa := stats(t, a, b.key)
	if sa.PingsSent != 1 || sa.PongsRecv != 1 || sa.AuthFail != 0 || sa.ReplayDrop != 0 {
		t.Fatalf("A stats = %+v", sa)
	}
	if sa.LastMTUPongNs != 0 {
		t.Fatal("small pong recorded as MTU pong")
	}
	if sb := stats(t, b, a.key); sb.PingsSent != 0 || sb.PongsRecv != 0 {
		t.Fatalf("B stats = %+v, want no pings or pongs", sb)
	}
}

// Every malformed or unauthenticated inbound frame is dropped with the right
// counter and without a pong, and still never reaches wireguard-go.
// testMeshMTU is the mesh MTU every test peer is configured with, so a test
// can compute the probe and slack sizes the same way the code does.
const testMeshMTU = 1420

func TestHeartbeatDropsBadFrames(t *testing.T) {
	clock := newFakeClock()
	b := newHBPeer(t, clock, false)
	cap := newCapture(t)
	a := mustKeyPair(t)
	b.b.SetPeerPath(a.PublicKeyBase64(), PathModeDirect, cap.addr)
	key := b.b.GetPeerPath(a.PublicKeyBase64()).hbKey.Load()
	if key == nil {
		t.Fatal("no heartbeat key")
	}
	valid := func(frameLen uint16, sentAt int64) []byte {
		return encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePing, FrameLen: frameLen, SentAt: sentAt, Sender: a.Public}, key[:])
	}

	// Sanity: a good ping is answered.
	cap.send(t, valid(92, clock.Now()), b.addr)
	b.recvHeartbeat(t)
	if pong := cap.read(t, time.Second); len(pong) != 92 {
		t.Fatalf("good ping got pong of %d bytes, want 92", len(pong))
	}

	badMAC := valid(92, clock.Now())
	badMAC[70] ^= 1
	wrongVersion := valid(92, clock.Now())
	wrongVersion[4] = 2
	unknownType := encodeHeartbeat(heartbeatFrame{Type: 9, FrameLen: 92, SentAt: clock.Now(), Sender: a.Public}, key[:])
	stranger := mustKeyPair(t)
	strangerKey, _ := deriveHeartbeatKey(stranger.Private, stranger.Public, b.kp.Public)
	unknownSender := encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePing, FrameLen: 92, SentAt: clock.Now(), Sender: stranger.Public}, strangerKey[:])

	cases := []struct {
		name               string
		frame              []byte
		authFail, replayDr uint64
	}{
		{"frame_len shorter than datagram", append(valid(92, clock.Now()), 0), 1, 0},
		{"frame_len longer than datagram", valid(1452, clock.Now())[:1451], 1, 0},
		{"bad MAC", badMAC, 1, 0},
		{"unsupported version", wrongVersion, 1, 0},
		{"unknown type", unknownType, 1, 0},
		// Past the slack this node allows above its own MTU probe. Sizes
		// between the two the scheduler emits are accepted on purpose, so a
		// peer mid-MTU-change is not read as a forger; see the accepted case
		// asserted after this table.
		{"ping size past the allowed range", valid(uint16(heartbeatMTUProbeLen(testMeshMTU)+heartbeatSizeSlack+1), clock.Now()), 1, 0},
		{"sent_at too old", valid(92, clock.Before(61*time.Second)), 0, 1},
		{"sent_at too far ahead", valid(92, clock.At(61*time.Second)), 0, 1},
		{"unknown sender", unknownSender, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := stats(t, b, a.PublicKeyBase64())
			cap.send(t, tc.frame, b.addr)
			b.recvHeartbeat(t)
			after := stats(t, b, a.PublicKeyBase64())
			if after.AuthFail-before.AuthFail != tc.authFail {
				t.Errorf("authFail delta = %d, want %d", after.AuthFail-before.AuthFail, tc.authFail)
			}
			if after.ReplayDrop-before.ReplayDrop != tc.replayDr {
				t.Errorf("replayDrop delta = %d, want %d", after.ReplayDrop-before.ReplayDrop, tc.replayDr)
			}
			if pong := cap.read(t, 100*time.Millisecond); pong != nil {
				t.Errorf("dropped frame was answered with %d bytes", len(pong))
			}
		})
	}

	// A peer whose mesh MTU differs from ours probes at a size we never emit.
	// Reflecting it is deliberate: rejecting it would turn an MTU change into
	// authentication failures on one side and a latched dual-send veto on the
	// other, for the length of a rolling restart.
	t.Run("size between the emitted sizes is answered", func(t *testing.T) {
		const odd = 1400
		before := stats(t, b, a.PublicKeyBase64())
		cap.send(t, valid(odd, clock.Now()), b.addr)
		b.recvHeartbeat(t)
		after := stats(t, b, a.PublicKeyBase64())
		if after.AuthFail != before.AuthFail {
			t.Errorf("authFail delta = %d, want 0 for a peer with a different MTU", after.AuthFail-before.AuthFail)
		}
		pong := cap.read(t, time.Second)
		if len(pong) != odd {
			t.Fatalf("pong of %d bytes, want %d (the ping's own length, so the reflection ratio stays 1.0)", len(pong), odd)
		}
	})
}

// A pong mirrors the ping's frame_len exactly (reflection ratio 1.0), for
// both allowed sizes.
func TestHeartbeatPongMirrorsPingLength(t *testing.T) {
	clock := newFakeClock()
	b := newHBPeer(t, clock, false)
	cap := newCapture(t)
	a := mustKeyPair(t)
	b.b.SetPeerPath(a.PublicKeyBase64(), PathModeDirect, cap.addr)
	key := b.b.GetPeerPath(a.PublicKeyBase64()).hbKey.Load()

	for _, size := range []uint16{92, 1452} {
		ping := encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePing, FrameLen: size, SentAt: clock.Now(), Sender: a.Public, TxID: [12]byte{byte(size)}}, key[:])
		cap.send(t, ping, b.addr)
		b.recvHeartbeat(t)
		pong := cap.read(t, time.Second)
		if len(pong) != int(size) {
			t.Fatalf("pong for %d-byte ping is %d bytes", size, len(pong))
		}
		hdr, _ := decodeHeartbeatHeader(pong)
		if hdr.Type != heartbeatTypePong || hdr.TxID != [12]byte{byte(size)} || hdr.Sender != b.kp.Public || hdr.SentAt != clock.Now() {
			t.Fatalf("pong header = %+v", hdr)
		}
		if !verifyHeartbeatMAC(pong, key[:]) {
			t.Fatal("pong MAC does not verify under the pair key")
		}
	}
}

// Pong acceptance is by pending txid: unknown, already consumed and stale
// entries are replay drops, a size mismatch is an auth failure, and none of
// them moves the watermark.
func TestHeartbeatPongTxIDRules(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, false)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	pp := a.b.GetPeerPath(peer.PublicKeyBase64())
	pp.lastSendNs.Store(clock.Now())
	key := pp.hbKey.Load()

	expect := func(t *testing.T, pong []byte, wantAuth, wantReplay, wantPongs uint64, wantWatermark int64) {
		t.Helper()
		before := stats(t, a, peer.PublicKeyBase64())
		cap.send(t, pong, a.addr)
		a.recvHeartbeat(t)
		after := stats(t, a, peer.PublicKeyBase64())
		if d := after.AuthFail - before.AuthFail; d != wantAuth {
			t.Errorf("authFail delta = %d, want %d", d, wantAuth)
		}
		if d := after.ReplayDrop - before.ReplayDrop; d != wantReplay {
			t.Errorf("replayDrop delta = %d, want %d", d, wantReplay)
		}
		if d := after.PongsRecv - before.PongsRecv; d != wantPongs {
			t.Errorf("pongsRecv delta = %d, want %d", d, wantPongs)
		}
		if after.LastPongNs != wantWatermark {
			t.Errorf("lastPongNs = %d, want %d", after.LastPongNs, wantWatermark)
		}
	}

	// Unknown txid: nothing pending yet.
	unknown := encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePong, FrameLen: 92, SentAt: clock.Now(), Sender: peer.Public, TxID: [12]byte{9}}, key[:])
	expect(t, unknown, 0, 1, 0, 0)

	a.tick(t)
	ping := cap.read(t, time.Second)
	if len(ping) != 92 {
		t.Fatalf("ping = %d bytes", len(ping))
	}

	// Size mismatch: the entry stays for the genuine pong.
	hdr, _ := decodeHeartbeatHeader(ping)
	wrongSize := encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePong, FrameLen: 1452, SentAt: hdr.SentAt, TxID: hdr.TxID, Sender: peer.Public}, key[:])
	expect(t, wrongSize, 1, 0, 0, 0)

	// Genuine pong matches and is consumed.
	pong := pongFor(t, ping, peer.Public, key)
	expect(t, pong, 0, 0, 1, clock.Now())
	// The same pong again is a replay.
	clock.Advance(time.Millisecond)
	expect(t, pong, 0, 1, 0, clock.Before(time.Millisecond))

	// Stale: a pong more than 3s after its ping is not evidence.
	a.tick(t)
	late := pongFor(t, cap.read(t, time.Second), peer.Public, key)
	clock.Advance(heartbeatPendingTTL() + time.Millisecond)
	expect(t, late, 0, 1, 0, clock.Before(heartbeatPendingTTL()+2*time.Millisecond))
}

func heartbeatPendingTTL() time.Duration { return time.Duration(heartbeatPendingTTLNs) }

// Pong replies are rate-limited per peer (4/s, burst 8): a flood of pings
// within one instant yields at most the burst.
func TestHeartbeatPongRateLimit(t *testing.T) {
	clock := newFakeClock()
	b := newHBPeer(t, clock, false)
	cap := newCapture(t)
	a := mustKeyPair(t)
	b.b.SetPeerPath(a.PublicKeyBase64(), PathModeDirect, cap.addr)
	key := b.b.GetPeerPath(a.PublicKeyBase64()).hbKey.Load()

	for i := 0; i < 12; i++ {
		ping := encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePing, FrameLen: 92, SentAt: clock.Now(), Sender: a.Public, TxID: [12]byte{byte(i)}}, key[:])
		cap.send(t, ping, b.addr)
		b.recvHeartbeat(t)
	}
	got := 0
	for cap.read(t, 100*time.Millisecond) != nil {
		got++
	}
	if got != int(heartbeatPongPeerBurst) {
		t.Fatalf("pongs = %d for 12 instantaneous pings, want the burst (%d)", got, int(heartbeatPongPeerBurst))
	}
	// One second later the bucket has refilled by the rate.
	clock.Advance(time.Second)
	for i := 0; i < 12; i++ {
		ping := encodeHeartbeat(heartbeatFrame{Type: heartbeatTypePing, FrameLen: 92, SentAt: clock.Now(), Sender: a.Public, TxID: [12]byte{0x80, byte(i)}}, key[:])
		cap.send(t, ping, b.addr)
		b.recvHeartbeat(t)
	}
	got = 0
	for cap.read(t, 100*time.Millisecond) != nil {
		got++
	}
	if got != int(heartbeatPongPeerRate) {
		t.Fatalf("pongs after 1s = %d, want the rate (%d)", got, int(heartbeatPongPeerRate))
	}
}

// The scheduler pings only peers in Direct or Warm with a usable address and
// an active session. Relay-mode peers, MarkBimodalHint stubs (Mode 0, no
// address) and idle sessions get nothing.
func TestHeartbeatSchedulerSkipsRelayStubAndIdle(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, false)
	relayCap, idleCap, warmCap := newCapture(t), newCapture(t), newCapture(t)
	relayPeer, idlePeer, warmPeer, stubPeer := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)

	a.b.SetPeerPath(relayPeer.PublicKeyBase64(), PathModeRelay, relayCap.addr)
	a.b.GetPeerPath(relayPeer.PublicKeyBase64()).lastSendNs.Store(clock.Now())

	a.b.SetPeerPath(idlePeer.PublicKeyBase64(), PathModeDirect, idleCap.addr)
	// Never sent to: lastSendNs == 0.

	a.b.SetPeerPath(warmPeer.PublicKeyBase64(), PathModeWarm, warmCap.addr)
	a.b.GetPeerPath(warmPeer.PublicKeyBase64()).lastSendNs.Store(clock.Now())

	a.b.MarkBimodalHint(stubPeer.Public)
	stub := a.b.GetPeerPath(stubPeer.PublicKeyBase64())
	if stub == nil || stub.hbKey.Load() == nil {
		t.Fatal("stub entry missing or without a derived key")
	}
	stub.lastSendNs.Store(clock.Now())

	a.tick(t)

	if f := warmCap.read(t, time.Second); len(f) != 92 {
		t.Fatalf("Warm peer got %d bytes, want a 92-byte ping", len(f))
	}
	if f := relayCap.read(t, 100*time.Millisecond); f != nil {
		t.Fatal("Relay-mode peer was pinged")
	}
	if f := idleCap.read(t, 100*time.Millisecond); f != nil {
		t.Fatal("idle session was pinged")
	}
	if s := stats(t, a, stubPeer.PublicKeyBase64()); s.PingsSent != 0 {
		t.Fatalf("stub entry pingsSent = %d, want 0", s.PingsSent)
	}
	if s := stats(t, a, relayPeer.PublicKeyBase64()); s.PingsSent != 0 {
		t.Fatalf("relay peer pingsSent = %d, want 0", s.PingsSent)
	}
	if s := stats(t, a, warmPeer.PublicKeyBase64()); s.PingsSent != 1 {
		t.Fatalf("warm peer pingsSent = %d, want 1", s.PingsSent)
	}

	// A session that was active goes idle after 45s without a Send.
	clock.Advance(46 * time.Second)
	a.tick(t)
	if f := warmCap.read(t, 100*time.Millisecond); f != nil {
		t.Fatal("session idle for 46s was still pinged")
	}
	// Heartbeat frames do not count as sends: lastSendNs is untouched.
	if s := stats(t, a, warmPeer.PublicKeyBase64()); s.LastSendNs != clock.Before(46*time.Second) {
		t.Fatalf("lastSendNs moved to %d after heartbeat traffic", s.LastSendNs)
	}
}

// The probe goes where the data goes: the address of the last direct write
// while it is under 60s old, then AuthAddr, then DirectAddr.
func TestHeartbeatProbeAddressFollowsLastSendDst(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, false)
	direct, roamed, auth := newCapture(t), newCapture(t), newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, direct.addr)
	pp := a.b.GetPeerPath(peer.PublicKeyBase64())
	pp.DirectHealth.LastSeen.Store(clock.Now())

	// The device roamed the endpoint to a new port; Send writes there and
	// records it, so the probe follows.
	if err := a.b.Send([][]byte{{4, 0, 0, 0}}, &WireKubeEndpoint{dst: roamed.addr, relayPeerKey: relayPeerKey{peerKey: peer.Public}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if roamed.read(t, time.Second) == nil {
		t.Fatal("data did not reach the roamed address")
	}
	a.tick(t)
	if f := roamed.read(t, time.Second); !hasHeartbeatMagic(f) {
		t.Fatalf("roamed address got %d bytes, want the ping", len(f))
	}
	if f := direct.read(t, 100*time.Millisecond); f != nil {
		t.Fatal("bootstrap address was pinged while lastSendDst is fresh")
	}

	// Once the last write is over 60s old, AuthAddr outranks it. (Stored
	// directly: NoteAuthenticatedAddr refuses loopback, which is all a unit
	// test has.)
	authAddr := auth.addr
	pp.authAddr.Store(&authAddr)
	clock.Advance(61 * time.Second)
	pp.lastSendNs.Store(clock.Now()) // keep the session active without a direct write
	a.tick(t)
	if f := auth.read(t, time.Second); !hasHeartbeatMagic(f) {
		t.Fatalf("auth address got %d bytes, want the ping", len(f))
	}
	if f := roamed.read(t, 100*time.Millisecond); f != nil {
		t.Fatal("stale lastSendDst was still probed")
	}

	// Without an authenticated address the bootstrap address is the fallback.
	pp.authAddr.Store(nil)
	a.tick(t)
	if f := direct.read(t, time.Second); !hasHeartbeatMagic(f) {
		t.Fatalf("bootstrap address got %d bytes, want the ping", len(f))
	}
}

// Every 10th tick is an MTU probe of mtu+32 bytes; the others are 92 bytes.
func TestHeartbeatMTUProbeCadence(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, false)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	a.b.GetPeerPath(peer.PublicKeyBase64()).lastSendNs.Store(clock.Now())

	var sizes []int
	for i := 0; i < 20; i++ {
		a.tick(t)
		f := cap.read(t, time.Second)
		if f == nil {
			t.Fatalf("tick %d produced no ping", i+1)
		}
		sizes = append(sizes, len(f))
		clock.Advance(time.Second)
	}
	for i, n := range sizes {
		want := heartbeatMinLen
		if (i+1)%heartbeatMTUProbeEvery == 0 {
			want = 1452
		}
		if n != want {
			t.Errorf("tick %d: ping is %d bytes, want %d", i+1, n, want)
		}
	}
	if s := stats(t, a, peer.PublicKeyBase64()); s.PingsSent != 20 {
		t.Fatalf("pingsSent = %d, want 20", s.PingsSent)
	}
}

// answerPing reads the one ping the last tick produced and pongs it to a,
// unless it is an MTU probe and answerMTU is false; a then consumes the pong.
// Returns whether a pong was sent.
func answerPing(t *testing.T, a *hbPeer, cap *capture, sender [32]byte, key *[32]byte, answerMTU bool) bool {
	t.Helper()
	ping := cap.read(t, time.Second)
	if ping == nil {
		t.Fatal("tick produced no ping")
	}
	if len(ping) != heartbeatMinLen && !answerMTU {
		return false
	}
	cap.send(t, pongFor(t, ping, sender, key), a.addr)
	a.recvHeartbeat(t)
	return true
}

// Three consecutive MTU probes lost while small pongs keep arriving set the
// veto: Send dual-sends although the small-pong evidence is fresh. The next
// MTU pong clears it.
func TestHeartbeatMTUStaleVetoForcesDualSend(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	pp := a.b.GetPeerPath(peer.PublicKeyBase64())
	key := pp.hbKey.Load()
	ep := &WireKubeEndpoint{dst: cap.addr}

	relaySends := func() int {
		a.relay.mu.Lock()
		defer a.relay.mu.Unlock()
		return len(a.relay.sent)
	}
	sendData := func(t *testing.T) {
		t.Helper()
		if err := a.b.Send([][]byte{{4, 0, 0, 0}}, ep); err != nil {
			t.Fatalf("Send: %v", err)
		}
		cap.read(t, time.Second) // drain the data frame
	}

	// Ticks 1..33 with only small pings answered: MTU probes at 10, 20, 30
	// expire at 14, 24, 34.
	sendData(t) // session active
	for tick := 1; tick <= 33; tick++ {
		a.tick(t)
		answerPing(t, a, cap, peer.Public, key, false)
		clock.Advance(time.Second)
		if tick%20 == 0 {
			sendData(t)
		}
	}
	if pp.mtuStale.Load() {
		t.Fatal("mtuStale set before the third MTU probe expired")
	}
	before := relaySends()
	sendData(t)
	if relaySends() != before {
		t.Fatal("fresh small pongs did not keep the send direct-only")
	}

	a.tick(t) // tick 34: third miss
	answerPing(t, a, cap, peer.Public, key, false)
	if !pp.mtuStale.Load() {
		t.Fatal("mtuStale not set after three unanswered MTU probes with fresh small pongs")
	}
	before = relaySends()
	sendData(t)
	if relaySends() != before+1 {
		t.Fatalf("mtuStale did not force the relay leg (relay sends %d → %d)", before, relaySends())
	}
	if s := stats(t, a, peer.PublicKeyBase64()); !s.MTUStale || s.LastMTUPongNs != 0 {
		t.Fatalf("stats = %+v, want MTUStale and no MTU pong yet", s)
	}

	// Ticks 35..40; the probe at 40 is answered and clears the veto.
	for tick := 35; tick <= 40; tick++ {
		clock.Advance(time.Second)
		a.tick(t)
		answerPing(t, a, cap, peer.Public, key, tick == 40)
	}
	if pp.mtuStale.Load() {
		t.Fatal("MTU pong did not clear the veto")
	}
	if s := stats(t, a, peer.PublicKeyBase64()); s.LastMTUPongNs != clock.Now() {
		t.Fatalf("LastMTUPongNs = %d, want %d", s.LastMTUPongNs, clock.Now())
	}
	before = relaySends()
	sendData(t)
	if relaySends() != before {
		t.Fatal("send still dual after the veto cleared")
	}
}

// When the peer stops answering, the pong evidence ages out inside the trust
// window and Send adds the relay leg — no control-plane round trip needed.
func TestHeartbeatPeerStopsAnsweringForcesDualSendWithin3s(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	pp := a.b.GetPeerPath(peer.PublicKeyBase64())
	pp.lastSendNs.Store(clock.Now())
	key := pp.hbKey.Load()
	ep := &WireKubeEndpoint{dst: cap.addr}

	a.tick(t)
	if !answerPing(t, a, cap, peer.Public, key, true) {
		t.Fatal("first ping was not answered")
	}
	if err := a.b.Send([][]byte{{4}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(a.relay.sent) != 0 {
		t.Fatal("fresh pong did not keep the send direct-only")
	}

	// The peer goes silent: pings keep going out, no pongs come back.
	for i := 0; i < 3; i++ {
		clock.Advance(time.Second)
		a.tick(t)
		cap.read(t, 200*time.Millisecond) // swallow, no reply
	}
	clock.Advance(100 * time.Millisecond) // 3.1s since the last pong
	if err := a.b.Send([][]byte{{4}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(a.relay.sent) != 1 {
		t.Fatalf("relay sends = %d after 3.1s of silence, want 1 (dual-send)", len(a.relay.sent))
	}
	if len(a.relay.hints) != 1 {
		t.Fatalf("bimodal hints = %d, want 1 (stale evidence fires the hint)", len(a.relay.hints))
	}
}

// Leg counters describe what was actually written, after the port-0 and
// relayAvailable overrides, and grow by len(bufs).
func TestSendLegCountersReflectOverridesAndBatchSize(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	peer := mustKeyPair(t)
	addr := netip.MustParseAddrPort("127.0.0.1:59990")
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, addr)
	pp := a.b.GetPeerPath(peer.PublicKeyBase64())
	ep := &WireKubeEndpoint{dst: addr}
	two := [][]byte{{4, 0}, {4, 1}}

	check := func(t *testing.T, direct, dual, relay uint64) {
		t.Helper()
		s := stats(t, a, peer.PublicKeyBase64())
		if s.SentDirectOnly != direct || s.SentDual != dual || s.SentRelayOnly != relay {
			t.Fatalf("counters direct=%d dual=%d relay=%d, want %d/%d/%d", s.SentDirectOnly, s.SentDual, s.SentRelayOnly, direct, dual, relay)
		}
	}

	// No evidence: dual, by two.
	if err := a.b.Send(two, ep); err != nil {
		t.Fatal(err)
	}
	check(t, 0, 2, 0)
	if s := stats(t, a, peer.PublicKeyBase64()); s.LastSendNs != clock.Now() {
		t.Fatalf("lastSendNs = %d, want %d", s.LastSendNs, clock.Now())
	}

	// Fresh pong: direct only.
	pp.lastPongNs.Store(clock.Now())
	if err := a.b.Send(two, ep); err != nil {
		t.Fatal(err)
	}
	check(t, 2, 2, 0)

	// Relay mode: relay only.
	pp.Mode.Store(PathModeRelay)
	if err := a.b.Send(two, ep); err != nil {
		t.Fatal(err)
	}
	check(t, 2, 2, 2)

	// Warm with fresh evidence but a synthetic endpoint and no usable direct
	// address: the port-0 override turns it relay-only, and the counter
	// follows the override, not the mode.
	pp.Mode.Store(PathModeWarm)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeWarm, netip.AddrPort{})
	synthetic := &WireKubeEndpoint{dst: relaySyntheticAddrFor(peer.Public), relayPeerKey: relayPeerKey{peerKey: peer.Public}}
	if err := a.b.Send(two, synthetic); err != nil {
		t.Fatal(err)
	}
	check(t, 2, 2, 4)

	// Stale evidence with no relay configured: the relayAvailable override
	// leaves the direct leg alone, and the counter says direct-only.
	noRelay := newHBPeer(t, clock, false)
	noRelay.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, addr)
	if err := noRelay.b.Send(two, ep); err != nil {
		t.Fatal(err)
	}
	if s := stats(t, noRelay, peer.PublicKeyBase64()); s.SentDirectOnly != 2 || s.SentDual != 0 {
		t.Fatalf("no-relay counters = %+v, want direct-only 2", s)
	}
}

// Close stops and joins the scheduler; a new Open starts with an empty pending
// table so pongs to the previous socket generation cannot refresh trust.
func TestHeartbeatCloseJoinsSchedulerAndOpenClearsPending(t *testing.T) {
	clock := newFakeClock()
	a := newHBPeer(t, clock, false)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	pp := a.b.GetPeerPath(peer.PublicKeyBase64())
	pp.lastSendNs.Store(clock.Now())
	key := pp.hbKey.Load()

	a.tick(t)
	oldPing := cap.read(t, time.Second)
	if oldPing == nil {
		t.Fatal("no ping")
	}
	done := a.b.hbDone
	if err := a.b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Close returned before the scheduler exited")
	}
	if a.b.hbStop != nil || a.b.hbDone != nil {
		t.Fatal("scheduler channels survived Close")
	}

	a.b.hbTickOverride = make(chan time.Time)
	fns, port, err := a.b.Open(0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	a.fns = fns
	a.addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)

	cap.send(t, pongFor(t, oldPing, peer.Public, key), a.addr)
	a.recvHeartbeat(t)
	if s := stats(t, a, peer.PublicKeyBase64()); s.ReplayDrop != 1 || s.LastPongNs != 0 {
		t.Fatalf("pong for the previous generation: stats = %+v, want one replay drop and no watermark", s)
	}
}
