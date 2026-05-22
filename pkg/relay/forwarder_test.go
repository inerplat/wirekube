package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/wirekube/wirekube/pkg/relay/portalloc"
)

// recordingDispatcher captures every Dispatch call. Tests assert on the
// recorded slice. A channel signals new arrivals so tests don't need to
// poll.
type recordingDispatcher struct {
	mu     sync.Mutex
	calls  []dispatchCall
	signal chan struct{}
	failOn func(ingress [PubKeySize]byte) error // optional fault injection
}

type dispatchCall struct {
	Ingress  [PubKeySize]byte
	External [PubKeySize]byte
	Payload  []byte
	From     netip.AddrPort
}

func newRecordingDispatcher() *recordingDispatcher {
	return &recordingDispatcher{
		signal: make(chan struct{}, 64),
	}
}

// Dispatch implements IngressDispatcher.
func (r *recordingDispatcher) Dispatch(ingress, external [PubKeySize]byte, payload []byte, from netip.AddrPort) error {
	if r.failOn != nil {
		if err := r.failOn(ingress); err != nil {
			return err
		}
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	r.mu.Lock()
	r.calls = append(r.calls, dispatchCall{Ingress: ingress, External: external, Payload: cp, From: from})
	r.mu.Unlock()
	select {
	case r.signal <- struct{}{}:
	default:
	}
	return nil
}

func (r *recordingDispatcher) snapshot() []dispatchCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]dispatchCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// waitForCalls blocks until at least n calls have been recorded or the
// timeout elapses.
func (r *recordingDispatcher) waitForCalls(t *testing.T, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		r.mu.Lock()
		got := len(r.calls)
		r.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-r.signal:
		case <-deadline:
			r.mu.Lock()
			final := len(r.calls)
			r.mu.Unlock()
			t.Fatalf("waited for %d dispatch calls, got %d after %s", n, final, timeout)
		}
	}
}

// sharedAlloc is a single package-wide port allocator. Forwarder tests
// share it so parallel tests don't hand out the same port number from
// independent allocators (which would cause UDP bind clashes against the
// real OS port space). Range 40960-49151 (per spec) is outside the
// production default 32768-40959.
var sharedAlloc = func() *portalloc.Allocator {
	a, err := portalloc.New(40960, 49151)
	if err != nil {
		panic(err)
	}
	return a
}()

// testAlloc returns the shared allocator. Kept as a function for symmetry
// with future per-test allocators.
func testAlloc(t *testing.T) *portalloc.Allocator {
	t.Helper()
	return sharedAlloc
}

// allocBindablePort returns a port in the test range that is currently
// bindable. A port may be in our allocator's space yet held by the OS
// from a recent test; in that case retry up to a small bound.
func allocBindablePort(t *testing.T, alloc *portalloc.Allocator) uint16 {
	t.Helper()
	for i := 0; i < 50; i++ {
		p, err := alloc.Allocate()
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		// Probe that the kernel will let us bind it.
		l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(p)})
		if err != nil {
			// Not bindable; release and try the next.
			alloc.Release(p)
			continue
		}
		_ = l.Close()
		return p
	}
	t.Fatalf("could not find a bindable port in 50 tries")
	return 0
}

func sendUDP(t *testing.T, port uint16, payloads ...[]byte) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()
	for _, p := range payloads {
		if _, err := conn.Write(p); err != nil {
			t.Fatalf("UDP write: %v", err)
		}
	}
}

func TestForwarder_RegisterDispatchesPackets(t *testing.T) {
	t.Parallel()
	alloc := testAlloc(t)
	disp := newRecordingDispatcher()
	fw := NewForwarder(disp)
	defer fw.Close()

	ingress := pubkey(0xAA)
	external := pubkey(0xBB)

	port := allocBindablePort(t, alloc)
	defer alloc.Release(port)

	if err := fw.Register(port, ingress, external); err != nil {
		t.Fatalf("Register: %v", err)
	}

	payloads := [][]byte{
		[]byte("hello"),
		[]byte("world"),
	}
	sendUDP(t, port, payloads...)

	disp.waitForCalls(t, 2, 2*time.Second)

	calls := disp.snapshot()
	if got := len(calls); got != 2 {
		t.Fatalf("got %d dispatch calls, want 2", got)
	}
	totalIn := 0
	for i, c := range calls {
		if c.Ingress != ingress {
			t.Fatalf("call[%d] ingress = %x, want %x", i, c.Ingress[:8], ingress[:8])
		}
		if string(c.Payload) != string(payloads[i]) {
			t.Fatalf("call[%d] payload = %q, want %q", i, c.Payload, payloads[i])
		}
		if !c.From.IsValid() {
			t.Fatalf("call[%d] From not valid", i)
		}
		totalIn += len(c.Payload)
	}

	stats, err := fw.Stats(port)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.BytesIn != uint64(totalIn) {
		t.Fatalf("BytesIn = %d, want %d", stats.BytesIn, totalIn)
	}
	if stats.LastPacket.IsZero() {
		t.Fatalf("LastPacket is zero")
	}
	if !stats.ExternalAddr.IsValid() {
		t.Fatalf("ExternalAddr is invalid")
	}
}

func TestForwarder_DuplicateRegisterRejected(t *testing.T) {
	t.Parallel()
	alloc := testAlloc(t)
	fw := NewForwarder(nil) // noop dispatcher
	defer fw.Close()

	port := allocBindablePort(t, alloc)
	defer alloc.Release(port)

	if err := fw.Register(port, pubkey(1), pubkey(2)); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := fw.Register(port, pubkey(3), pubkey(4))
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("second Register err = %v, want ErrPortInUse", err)
	}
}

func TestForwarder_DuplicateRegisterSameMappingIsIdempotent(t *testing.T) {
	t.Parallel()
	alloc := testAlloc(t)
	fw := NewForwarder(nil)
	defer fw.Close()

	port := allocBindablePort(t, alloc)
	defer alloc.Release(port)
	ingress := pubkey(1)
	external := pubkey(2)

	if err := fw.Register(port, ingress, external); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := fw.Register(port, ingress, external); err != nil {
		t.Fatalf("second Register same mapping: %v", err)
	}
}

func TestForwarder_UnregisterReleasesListener(t *testing.T) {
	t.Parallel()
	alloc := testAlloc(t)
	disp := newRecordingDispatcher()
	fw := NewForwarder(disp)
	defer fw.Close()

	port := allocBindablePort(t, alloc)
	defer alloc.Release(port)

	if err := fw.Register(port, pubkey(0xAA), pubkey(0xBB)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Sanity: the dispatcher receives one packet first.
	sendUDP(t, port, []byte("ping"))
	disp.waitForCalls(t, 1, 2*time.Second)

	if err := fw.Unregister(port); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	// After Unregister the port must be re-bindable by an unrelated
	// listener, proving the forwarder released it.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
	if err != nil {
		t.Fatalf("rebind after Unregister: %v", err)
	}
	_ = probe.Close()

	// Stats and Unregister on the now-unknown port must report ErrUnknownPort.
	if _, err := fw.Stats(port); !errors.Is(err, ErrUnknownPort) {
		t.Fatalf("Stats after Unregister err = %v, want ErrUnknownPort", err)
	}
	if err := fw.Unregister(port); !errors.Is(err, ErrUnknownPort) {
		t.Fatalf("second Unregister err = %v, want ErrUnknownPort", err)
	}
}

func TestForwarder_TwoIngressPeersRoutedIndependently(t *testing.T) {
	t.Parallel()
	alloc := testAlloc(t)
	disp := newRecordingDispatcher()
	fw := NewForwarder(disp)
	defer fw.Close()

	ingress1 := pubkey(0x11)
	ingress2 := pubkey(0x22)
	ext1 := pubkey(0xA1)
	ext2 := pubkey(0xA2)

	port1 := allocBindablePort(t, alloc)
	defer alloc.Release(port1)
	port2 := allocBindablePort(t, alloc)
	defer alloc.Release(port2)

	if err := fw.Register(port1, ingress1, ext1); err != nil {
		t.Fatalf("Register port1: %v", err)
	}
	if err := fw.Register(port2, ingress2, ext2); err != nil {
		t.Fatalf("Register port2: %v", err)
	}

	sendUDP(t, port1, []byte("from-ext1-A"), []byte("from-ext1-B"))
	sendUDP(t, port2, []byte("from-ext2-X"))

	disp.waitForCalls(t, 3, 2*time.Second)

	calls := disp.snapshot()
	ingressSeen := map[[PubKeySize]byte][]string{}
	for _, c := range calls {
		ingressSeen[c.Ingress] = append(ingressSeen[c.Ingress], string(c.Payload))
	}

	if got := len(ingressSeen[ingress1]); got != 2 {
		t.Fatalf("ingress1 received %d datagrams, want 2 (saw %v)", got, ingressSeen[ingress1])
	}
	if got := len(ingressSeen[ingress2]); got != 1 {
		t.Fatalf("ingress2 received %d datagrams, want 1 (saw %v)", got, ingressSeen[ingress2])
	}

	// Per-port stats reflect independent counters.
	s1, err := fw.Stats(port1)
	if err != nil {
		t.Fatalf("Stats port1: %v", err)
	}
	s2, err := fw.Stats(port2)
	if err != nil {
		t.Fatalf("Stats port2: %v", err)
	}
	wantIn1 := uint64(len("from-ext1-A") + len("from-ext1-B"))
	wantIn2 := uint64(len("from-ext2-X"))
	if s1.BytesIn != wantIn1 {
		t.Fatalf("port1 BytesIn = %d, want %d", s1.BytesIn, wantIn1)
	}
	if s2.BytesIn != wantIn2 {
		t.Fatalf("port2 BytesIn = %d, want %d", s2.BytesIn, wantIn2)
	}
}

func TestForwarder_StatsForUnknownPort(t *testing.T) {
	t.Parallel()
	fw := NewForwarder(nil)
	defer fw.Close()
	_, err := fw.Stats(40961)
	if !errors.Is(err, ErrUnknownPort) {
		t.Fatalf("Stats err = %v, want ErrUnknownPort", err)
	}
}

func TestForwarder_NoopDispatcherDefault(t *testing.T) {
	// When constructed with a nil dispatcher the forwarder must still bind
	// and accept datagrams without panicking.
	t.Parallel()
	alloc := testAlloc(t)
	fw := NewForwarder(nil)
	defer fw.Close()

	port := allocBindablePort(t, alloc)
	defer alloc.Release(port)

	if err := fw.Register(port, pubkey(1), pubkey(2)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	sendUDP(t, port, []byte("dropped-but-counted"))

	// Give the read loop a moment to count it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, err := fw.Stats(port)
		if err == nil && s.BytesIn > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("BytesIn never updated")
}

// pubkey returns a deterministic [PubKeySize]byte filled with v for tests.
func pubkey(v byte) [PubKeySize]byte {
	var k [PubKeySize]byte
	for i := range k {
		k[i] = v
	}
	return k
}

// TestForwarder_OversizedDatagramTruncationObserved exercises the boundary
// where the kernel hands us a datagram exactly equal to readBufferSize.
// The forwarder must record the truncation in Stats.Truncated so an
// undersized buffer is detectable in production rather than silently
// corrupting the inner WG framing.
func TestForwarder_OversizedDatagramTruncationObserved(t *testing.T) {
	t.Parallel()
	alloc := testAlloc(t)
	disp := newRecordingDispatcher()
	fw := NewForwarder(disp)
	defer fw.Close()

	ingress := pubkey(0xCC)
	external := pubkey(0xDD)
	port := allocBindablePort(t, alloc)
	defer alloc.Release(port)

	if err := fw.Register(port, ingress, external); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Send a 3 KiB payload; readBufferSize is 2 KiB so the kernel will
	// truncate to exactly readBufferSize bytes.
	big := make([]byte, 3072)
	for i := range big {
		big[i] = byte(i % 251)
	}
	sendUDP(t, port, big)

	disp.waitForCalls(t, 1, 2*time.Second)

	calls := disp.snapshot()
	if got := len(calls); got != 1 {
		t.Fatalf("got %d dispatch calls, want 1", got)
	}
	if got := len(calls[0].Payload); got != readBufferSize {
		t.Fatalf("dispatched payload length = %d, want truncated to %d", got, readBufferSize)
	}

	stats, err := fw.Stats(port)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Truncated != 1 {
		t.Fatalf("Stats.Truncated = %d, want 1 — truncation went unobserved", stats.Truncated)
	}
	if stats.BytesIn != uint64(readBufferSize) {
		t.Fatalf("Stats.BytesIn = %d, want %d", stats.BytesIn, readBufferSize)
	}
}
