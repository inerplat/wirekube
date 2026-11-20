package wireguard

import (
	"testing"
	"time"
)

// wgData builds a WireGuard transport data message of the given size.
func wgData(size int) []byte {
	b := make([]byte, size)
	b[0] = 4
	return b
}

func relaySends(m *mockRelayTransport) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func withDualCopyRate(t *testing.T, bytesPerSec float64) {
	t.Helper()
	old := dualCopyBytesPerSec
	dualCopyBytesPerSec = bytesPerSec
	t.Cleanup(func() { dualCopyBytesPerSec = old })
}

// The relay copy of a dual-send is bounded per peer: once the byte budget is
// spent the packet still goes out direct and the copy is withheld, and the
// budget refills with time. Without the bound, a relay whose own connection
// to the peer rides this direct leg turns the copies into a feedback loop.
func TestDualCopyBudgetBoundsRelayCopies(t *testing.T) {
	withDualCopyRate(t, 10_000) // 10 kB/s, 10 kB burst
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	// No evidence yet, so the direct leg is stale and every send is dual.
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	ep := &WireKubeEndpoint{dst: cap.addr}

	const size, n = 1000, 30
	for i := 0; i < n; i++ {
		if err := a.b.Send([][]byte{wgData(size)}, ep); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if got := relaySends(a.relay); got != 10 {
		t.Fatalf("relay copies = %d, want 10 (10 kB budget / 1 kB packets)", got)
	}
	s := stats(t, a, peer.PublicKeyBase64())
	if s.SentCopyLimited != n-10 {
		t.Fatalf("SentCopyLimited = %d, want %d", s.SentCopyLimited, n-10)
	}
	if s.SentDual != 10 || s.SentDirectOnly != n-10 {
		t.Fatalf("dual=%d direct_only=%d, want 10 and %d: a limited packet must still go direct", s.SentDual, s.SentDirectOnly, n-10)
	}

	// Half a second refills half the budget.
	clock.Advance(500 * time.Millisecond)
	for i := 0; i < n; i++ {
		if err := a.b.Send([][]byte{wgData(size)}, ep); err != nil {
			t.Fatalf("Send after refill %d: %v", i, err)
		}
	}
	if got := relaySends(a.relay); got != 15 {
		t.Fatalf("relay copies after 0.5s = %d, want 15", got)
	}
}

// Handshakes are exempt: the relay copy of a handshake is what re-establishes
// a session across a one-way blackout, and it must not wait behind data.
func TestDualCopyBudgetExemptsHandshakes(t *testing.T) {
	withDualCopyRate(t, 1000)
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	ep := &WireKubeEndpoint{dst: cap.addr}

	// Spend the whole budget on data.
	for i := 0; i < 5; i++ {
		if err := a.b.Send([][]byte{wgData(1000)}, ep); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	before := relaySends(a.relay)
	if before != 1 {
		t.Fatalf("relay copies = %d, want 1", before)
	}
	initiation := make([]byte, 148)
	initiation[0] = 1
	if err := a.b.Send([][]byte{initiation}, ep); err != nil {
		t.Fatalf("Send handshake: %v", err)
	}
	if got := relaySends(a.relay); got != before+1 {
		t.Fatalf("handshake relay copy withheld with the data budget spent (copies %d → %d)", before, got)
	}
}

// A relay-only peer has no direct leg, so the relay send is the delivery path
// and the budget must never apply to it.
func TestDualCopyBudgetNeverLimitsRelayOnly(t *testing.T) {
	withDualCopyRate(t, 1000)
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeRelay, cap.addr)
	ep := &WireKubeEndpoint{dst: cap.addr}

	const n = 20
	for i := 0; i < n; i++ {
		if err := a.b.Send([][]byte{wgData(1000)}, ep); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if got := relaySends(a.relay); got != n {
		t.Fatalf("relay-only sends = %d, want %d", got, n)
	}
	if s := stats(t, a, peer.PublicKeyBase64()); s.SentCopyLimited != 0 || s.SentRelayOnly != n {
		t.Fatalf("limited=%d relay_only=%d, want 0 and %d", s.SentCopyLimited, s.SentRelayOnly, n)
	}
}

// Rate 0 removes the bound (the documented kill switch).
func TestDualCopyBudgetDisabled(t *testing.T) {
	withDualCopyRate(t, 0)
	clock := newFakeClock()
	a := newHBPeer(t, clock, true)
	cap := newCapture(t)
	peer := mustKeyPair(t)
	a.b.SetPeerPath(peer.PublicKeyBase64(), PathModeDirect, cap.addr)
	ep := &WireKubeEndpoint{dst: cap.addr}
	for i := 0; i < 20; i++ {
		if err := a.b.Send([][]byte{wgData(1000)}, ep); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if got := relaySends(a.relay); got != 20 {
		t.Fatalf("relay copies = %d with the budget disabled, want 20", got)
	}
}
