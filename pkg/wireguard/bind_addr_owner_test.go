//go:build linux

package wireguard

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// Real 32-byte keys: Send decodes the claimant keys before handing them to the
// relay, so a placeholder string would silently drop the relay fan-out.
var (
	ownerA = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 32))
	ownerB = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xb2}, 32))
)

// Ten nodes behind one NAT advertise the same public addr:port (an RFC 5737
// documentation address here, so a stray packet cannot leave the host). An
// address claimed by several peers must resolve to none of them: naming one
// would give Send another peer's mode and address its relay copies to the
// wrong key.
func TestPeerForAddrRefusesContestedAddress(t *testing.T) {
	b := NewWireKubeBind()
	shared := netip.MustParseAddrPort("198.51.100.84:51820").String()

	b.claimAddr(shared, ownerA)
	if key, ok := b.peerForAddr(shared); !ok || key != ownerA {
		t.Fatalf("single claim resolved to (%q, %v), want (%q, true)", key, ok, ownerA)
	}

	b.claimAddr(shared, ownerB)
	if key, ok := b.peerForAddr(shared); ok {
		t.Fatalf("contested address resolved to %q, want no resolution", key)
	}

	// Releasing one claim leaves the address unambiguous again.
	b.releaseAddr(shared, ownerB)
	if key, ok := b.peerForAddr(shared); !ok || key != ownerA {
		t.Fatalf("after release resolved to (%q, %v), want (%q, true)", key, ok, ownerA)
	}
}

// Releasing one peer's claim must leave the other claims on that address
// intact, so that one peer moving off a shared-NAT address does not make it
// unresolvable for everyone still behind it.
func TestReleaseAddrKeepsOtherClaims(t *testing.T) {
	b := NewWireKubeBind()
	shared := "198.51.100.84:51820"

	b.claimAddr(shared, ownerA)
	b.claimAddr(shared, ownerB)
	b.releaseAddr(shared, ownerA)

	key, ok := b.peerForAddr(shared)
	if !ok || key != ownerB {
		t.Fatalf("resolved to (%q, %v), want (%q, true)", key, ok, ownerB)
	}

	b.releaseAddr(shared, ownerB)
	if _, ok := b.peerForAddr(shared); ok {
		t.Fatal("address still resolves after every claim was released")
	}
}

// SetPeerPath moving a peer to a new address must release the old claim for
// that peer only, and a unique LAN address must stay attributable.
func TestSetPeerPathMovesClaimWithoutStrandingPeers(t *testing.T) {
	b := NewWireKubeBind()
	shared := netip.MustParseAddrPort("198.51.100.84:51820")
	lan := netip.MustParseAddrPort("10.213.103.74:51820")

	b.SetPeerPath(ownerA, PathModeRelay, shared)
	b.SetPeerPath(ownerB, PathModeRelay, shared)
	if _, ok := b.peerForAddr(shared.String()); ok {
		t.Fatal("shared address resolved while two peers claimed it")
	}

	// Peer A learns its LAN candidate and moves off the shared address.
	b.SetPeerPath(ownerA, PathModeWarm, lan)

	key, ok := b.peerForAddr(lan.String())
	if !ok || key != ownerA {
		t.Fatalf("LAN address resolved to (%q, %v), want (%q, true)", key, ok, ownerA)
	}
	key, ok = b.peerForAddr(shared.String())
	if !ok || key != ownerB {
		t.Fatalf("shared address resolved to (%q, %v), want (%q, true) once uncontested", key, ok, ownerB)
	}
}

// A contested destination must not silently lose the relay leg: a peer that
// needs the relay to be reachable at all would be sent direct-only, and direct
// is exactly what does not work for it.
func TestSendKeepsRelayLegOnContestedAddress(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	shared := netip.MustParseAddrPort("198.51.100.84:51820")
	b.SetPeerPath(ownerA, PathModeRelay, shared)
	b.SetPeerPath(ownerB, PathModeRelay, shared)

	// A handshake initiation: this is the frame that has to reach the peer for a
	// contested address to resolve itself.
	handshake := make([]byte, 148)
	handshake[0] = 1
	if err := b.Send([][]byte{handshake}, NewWireKubeEndpoint(shared)); err != nil {
		t.Fatalf("Send on contested address: %v", err)
	}
	if got := len(relay.sent); got != 2 {
		t.Fatalf("relay copies = %d, want one per claimant (2)", got)
	}
}

// ForgetPeer must release the departed peer's claims, otherwise the next peer
// that takes that address is contested from the start and never resolves.
func TestForgetPeerReleasesClaims(t *testing.T) {
	b := NewWireKubeBind()
	addr := netip.MustParseAddrPort("10.213.103.74:51820")

	b.SetPeerPath(ownerA, PathModeWarm, addr)
	if key, ok := b.peerForAddr(addr.String()); !ok || key != ownerA {
		t.Fatalf("resolved to (%q, %v), want (%q, true)", key, ok, ownerA)
	}

	b.ForgetPeer(ownerA)
	if _, ok := b.peerForAddr(addr.String()); ok {
		t.Fatal("address still claimed after ForgetPeer")
	}
	if b.GetPeerPath(ownerA) != nil {
		t.Fatal("path entry survived ForgetPeer")
	}

	// The address is now free for whoever takes it next.
	b.SetPeerPath(ownerB, PathModeWarm, addr)
	if key, ok := b.peerForAddr(addr.String()); !ok || key != ownerB {
		t.Fatalf("reused address resolved to (%q, %v), want (%q, true)", key, ok, ownerB)
	}
}

// The receive path can be holding a PeerPath while the sync goroutine forgets
// the peer. A claim recorded after the release would outlive the path entry and
// leave the address contested forever, so a forgotten peer must not re-claim.
func TestForgottenPeerCannotReclaimAddress(t *testing.T) {
	b := NewWireKubeBind()
	addr := netip.MustParseAddrPort("10.213.103.74:51820")

	b.SetPeerPath(ownerA, PathModeWarm, addr)
	v, ok := b.pathTable.Load(ownerA)
	if !ok {
		t.Fatal("path entry missing")
	}
	pp := v.(*PeerPath)

	b.ForgetPeer(ownerA)

	// Simulates the racing receive path: it still holds pp from before.
	b.updateLearnedAddr(pp, ownerA, addr)

	if _, ok := b.peerForAddr(addr.String()); ok {
		t.Fatal("forgotten peer re-claimed its address")
	}
}

// Claims are a set, not a refcount: releasing the learned address must not drop
// a SetPeerPath claim on the same address.
func TestLearnedAddrChangeKeepsDirectAddrClaim(t *testing.T) {
	b := NewWireKubeBind()
	shared := netip.MustParseAddrPort("198.51.100.84:51820")
	roamed := netip.MustParseAddrPort("198.51.100.84:2968")

	b.SetPeerPath(ownerA, PathModeWarm, shared)
	v, _ := b.pathTable.Load(ownerA)
	pp := v.(*PeerPath)

	// The peer is first seen at its configured address, then its NAT port drifts.
	b.updateLearnedAddr(pp, ownerA, shared)
	b.updateLearnedAddr(pp, ownerA, roamed)

	if key, ok := b.peerForAddr(shared.String()); !ok || key != ownerA {
		t.Fatalf("configured address resolved to (%q, %v), want (%q, true)", key, ok, ownerA)
	}
	if key, ok := b.peerForAddr(roamed.String()); !ok || key != ownerA {
		t.Fatalf("roamed address resolved to (%q, %v), want (%q, true)", key, ok, ownerA)
	}
}

// A relay-delivered packet is synthesized as 127.0.0.1:0, which resolves to no
// peer by address. Its key therefore has to survive resolution even when the
// path entry is missing, or the frame ends up with no usable leg and is dropped.
func TestSendKeyedEndpointKeepsRelayLegWithoutPathEntry(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	raw, err := base64.StdEncoding.DecodeString(ownerA)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	var key [32]byte
	copy(key[:], raw)

	// No SetPeerPath: this is the "path entry gone" case.
	ep := &WireKubeEndpoint{
		dst:          netip.MustParseAddrPort("127.0.0.1:0"),
		relayPeerKey: relayPeerKey{peerKey: key},
	}
	frame := make([]byte, 148)
	frame[0] = 1
	if err := b.Send([][]byte{frame}, ep); err != nil {
		t.Fatalf("Send on keyed endpoint without a path entry: %v", err)
	}
	if got := len(relay.sent); got != 1 {
		t.Fatalf("relay copies = %d, want 1", got)
	}
}

// Transport data must reach a contested peer that only works over relay: the
// fan-out is limited by recipient (peers not already committed to direct), not
// by frame type, so data is not silently confined to the direct leg.
func TestContestedFanOutCarriesDataForRelayPeers(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	shared := netip.MustParseAddrPort("198.51.100.84:51820")
	b.SetPeerPath(ownerA, PathModeRelay, shared)
	b.SetPeerPath(ownerB, PathModeDirect, shared)

	data := make([]byte, 64)
	data[0] = 4 // transport data
	if err := b.Send([][]byte{data}, NewWireKubeEndpoint(shared)); err != nil {
		t.Fatalf("Send(data): %v", err)
	}
	if got := len(relay.sent); got != 1 {
		t.Fatalf("relay copies = %d, want 1 (only the relay-needing claimant)", got)
	}
	if relay.sent[0].destKey != mustKey(t, ownerA) {
		t.Fatal("relay copy went to the direct-mode claimant")
	}
}

func mustKey(t *testing.T, b64 string) [32]byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad test key %q: %v", b64, err)
	}
	var k [32]byte
	copy(k[:], raw)
	return k
}

// Seeding a same-segment peer to Warm is only safe because Warm keeps the relay
// leg: a peer that is on the segment but unreachable directly must keep
// working. Assert the dispatch decision, not the mode name.
func TestSendWarmUsesBothLegs(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	lan := netip.MustParseAddrPort("10.213.103.74:51820")
	b.SetPeerPath(ownerA, PathModeWarm, lan)

	handshake := make([]byte, 148)
	handshake[0] = 1
	if err := b.Send([][]byte{handshake}, NewWireKubeEndpoint(lan)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := len(relay.sent); got != 1 {
		t.Fatalf("relay copies = %d, want 1 (Warm must keep the relay leg)", got)
	}
	if relay.sent[0].destKey != mustKey(t, ownerA) {
		t.Fatal("relay copy addressed to the wrong peer")
	}
}

// A relay-delivered packet must never be surfaced at a real address.
// wireguard-go roams the peer endpoint to whatever the bind hands it, and the
// local-subnet bypass reads that endpoint as its proof that the peer is on the
// segment. Surfacing the peer's advertised LAN address here made every relayed
// keepalive testify to a direct path that was not there.
func TestRelayReceiveDoesNotBorrowARealAddress(t *testing.T) {
	b := NewWireKubeBind()
	b.SetRelayTransport(&mockRelayTransport{connected: true})
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	lan := netip.MustParseAddrPort("10.213.103.74:51820")
	roamed := netip.MustParseAddrPort("10.213.103.74:2968")
	b.SetPeerPath(ownerA, PathModeWarm, lan)
	v, _ := b.pathTable.Load(ownerA)
	pp := v.(*PeerPath)
	b.updateLearnedAddr(pp, ownerA, roamed) // both candidates now valid

	b.DeliverRelayPacket(RelayPacket{SrcKey: mustKey(t, ownerA), Payload: []byte("relayed")})

	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	if _, err := fns[1](bufs, sizes, eps); err != nil {
		t.Fatalf("relay receive: %v", err)
	}
	// Per-peer synthetic inside 127.0.0.0/8: still loopback, still port 0, but
	// distinct per peer so wireguard-go's cookie and rate-limit buckets, which
	// key on the address alone, do not collapse across peers.
	got := eps[0].(*WireKubeEndpoint).dst
	if !got.Addr().IsLoopback() || got.Port() != 0 {
		t.Fatalf("relay endpoint = %v, want a loopback address with port 0", got)
	}
	if got.Addr() == netip.MustParseAddr("10.213.103.74") || got == roamed || got == lan {
		t.Fatalf("relay endpoint borrowed a real address: %v", got)
	}
	if want := relaySyntheticAddrFor(mustKey(t, ownerA)); got != want {
		t.Fatalf("relay endpoint = %v, want the peer's synthetic %v", got, want)
	}
	if pp.RelayHealth.LastSeen.Load() == 0 {
		t.Error("relay receive did not refresh the relay watermark")
	}
}

// The synthetic has no UDP destination, so the direct leg has to take its
// address from the agent-owned path table. Without that, a peer in Warm lost
// its direct leg as soon as anything arrived over the relay — which in Warm is
// every packet, since both legs carry a copy.
func TestSendUsesPathTableAddressForSyntheticEndpoint(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	lan := netip.MustParseAddrPort("127.0.0.1:51821")
	b.SetPeerPath(ownerA, PathModeWarm, lan)

	ep := &WireKubeEndpoint{
		dst:          netip.MustParseAddrPort("127.0.0.1:0"),
		relayPeerKey: relayPeerKey{peerKey: mustKey(t, ownerA)},
	}
	frame := make([]byte, 148)
	frame[0] = 1
	if err := b.Send([][]byte{frame}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// The relay leg is unconditional in Warm; the direct leg is what regressed,
	// and a send to a closed local port still exercises the address choice.
	if len(relay.sent) != 1 {
		t.Fatalf("relay copies = %d, want 1", len(relay.sent))
	}
}

// A peer with no usable direct address must still be reachable: the synthetic
// stays relay-only rather than being sent to a port-zero destination.
func TestSendSyntheticWithoutDirectAddrStaysRelayOnly(t *testing.T) {
	relay := &mockRelayTransport{connected: true}
	b := NewWireKubeBind()
	b.SetRelayTransport(relay)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ep := &WireKubeEndpoint{
		dst:          netip.MustParseAddrPort("127.0.0.1:0"),
		relayPeerKey: relayPeerKey{peerKey: mustKey(t, ownerA)},
	}
	frame := make([]byte, 148)
	frame[0] = 1
	if err := b.Send([][]byte{frame}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(relay.sent) != 1 {
		t.Fatalf("relay copies = %d, want 1", len(relay.sent))
	}
}

// Two peers must not share a synthetic address: wireguard-go derives the mac2
// cookie and the handshake rate-limit bucket from the endpoint address alone,
// so a shared one makes a single cookie valid for every relay-delivered peer
// and puts them all in one bucket during a mass re-handshake.
func TestRelaySyntheticAddrIsPerPeer(t *testing.T) {
	a := relaySyntheticAddrFor(mustKey(t, ownerA))
	b := relaySyntheticAddrFor(mustKey(t, ownerB))
	if a == b {
		t.Fatalf("synthetics collide: %v", a)
	}
	for _, addr := range []netip.AddrPort{a, b} {
		if !addr.Addr().IsLoopback() {
			t.Errorf("%v is not loopback", addr)
		}
		if addr.Port() != 0 {
			t.Errorf("%v has a non-zero port; Send would treat it as a real destination", addr)
		}
		if addr.Addr().As4()[3] == 0 {
			t.Errorf("%v ends in .0", addr)
		}
	}
}

// An IP-only match is a guess about which peer sent the packet, so the endpoint
// must not carry a key derived from it. Two peers behind one NAT, one of them
// symmetric with no claimable address, is the case that mis-addresses relay
// copies to the wrong peer for the rest of that endpoint's life.
func TestDirectReceiveKeysOnlyExactMatches(t *testing.T) {
	b := NewWireKubeBind()
	exact := netip.MustParseAddrPort("198.51.100.84:51820")
	sameIPOtherPort := netip.MustParseAddrPort("198.51.100.84:2968")

	b.SetPeerPath(ownerA, PathModeWarm, exact)

	if key, pp, ok, isExact := b.lookupPeerByDirectAddr(exact); !ok || !isExact || key != ownerA || pp == nil {
		t.Fatalf("exact lookup = (%q, %v, %v, %v)", key, pp != nil, ok, isExact)
	}
	key, pp, ok, isExact := b.lookupPeerByDirectAddr(sameIPOtherPort)
	if !ok || pp == nil || key != ownerA {
		t.Fatalf("IP-only lookup should still resolve for liveness: (%q, %v, %v)", key, pp != nil, ok)
	}
	if isExact {
		t.Fatal("IP-only match reported as exact; its key would ride on the endpoint")
	}
}

// The confirmed address is only meaningful under the endpoint that was
// configured when it was recorded. Once the agent points the peer somewhere
// else — the same-NAT LAN candidate replacing a public address, say — Send has
// to follow, or the first relay copy roams the device endpoint to the synthetic
// and every later frame goes back to the address the agent already abandoned,
// which is also the address that can never confirm the new one.
func TestSetPeerPathClearsAuthAddrWhenDirectAddressMoves(t *testing.T) {
	b := NewWireKubeBind()
	public := netip.MustParseAddrPort("198.51.100.84:51820")
	lan := netip.MustParseAddrPort("192.0.2.10:51820")

	b.SetPeerPath(ownerA, PathModeWarm, public)
	b.NoteAuthenticatedAddr(ownerA, public)
	pp := b.GetPeerPath(ownerA)
	if got := pp.AuthAddr(); got != public {
		t.Fatalf("AuthAddr = %v, want %v", got, public)
	}

	// driveTransportMode reconfirms the same path every sync tick, which must
	// leave the confirmation standing.
	b.SetPeerPath(ownerA, PathModeWarm, public)
	if got := pp.AuthAddr(); got != public {
		t.Fatalf("AuthAddr after reconfirming the same address = %v, want %v", got, public)
	}

	b.SetPeerPath(ownerA, PathModeWarm, lan)
	if got := pp.AuthAddr(); got.IsValid() {
		t.Fatalf("AuthAddr after the direct address moved = %v, want it cleared", got)
	}
	if got := pp.DirectAddr(); got != lan {
		t.Fatalf("DirectAddr = %v, want %v", got, lan)
	}
}
