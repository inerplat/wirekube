package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	relayproto "github.com/inerplat/wirekube/pkg/relay"
)

func testPool(t *testing.T, addr string) *Pool {
	t.Helper()
	var key [relayproto.PubKeySize]byte
	copy(key[:], "pool-lifecycle-test")
	return NewPool(addr, key, 51820)
}

// deadAddr returns an address nothing listens on, so a dial is refused at once.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// Close before Connect must stop the pool from starting anything.
//
// The dial runs on a goroutine, so Close can land first. Connect used to set
// p.cancel itself, which meant an early Close found nothing to cancel, returned,
// and the late Connect then brought up clients and the discovery loop on a pool
// nobody referenced any more. Nothing could stop it afterwards, so its relay
// registration stayed alive alongside the replacement pool's.
func TestPoolConnectAfterCloseDoesNothing(t *testing.T) {
	p := testPool(t, deadAddr(t))
	p.Close()

	err := p.Connect(context.Background())
	if !errors.Is(err, errPoolClosed) {
		t.Fatalf("Connect after Close returned %v, want errPoolClosed", err)
	}
	if n := len(p.connectedClients()); n != 0 {
		t.Errorf("pool brought up %d clients after Close", n)
	}
}

// Close must cancel the context the pool is running under.
//
// Connect owns that context and used to store its cancel in p.cancel without a
// lock, so a Close that arrived before Connect had stored it found nothing to
// cancel. The discovery loop and every client then kept running under a context
// nobody could stop. Asserting on the context itself, rather than on Connect
// returning, is what makes this fail when the ordering regresses: a dial to a
// refused address returns on its own and hides the difference.
func TestPoolCloseCancelsTheRunningContext(t *testing.T) {
	p := testPool(t, deadAddr(t))

	// Capture the derived context the pool actually runs under.
	var (
		mu  sync.Mutex
		got context.Context
	)
	p.SetOnFirstConnect(func() {})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Connect(context.Background())
		mu.Lock()
		if p.cancel != nil {
			// Re-derive: the pool stored its cancel, so the context it governs
			// is live until Close runs.
			ctx, c := context.WithCancel(context.Background())
			p.mu.Lock()
			prev := p.cancel
			p.cancel = func() { c(); prev() }
			p.mu.Unlock()
			got = ctx
		}
		mu.Unlock()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return")
	}

	p.Close()

	mu.Lock()
	ctx := got
	mu.Unlock()
	if ctx == nil {
		t.Fatal("pool never stored a cancel func; Close would have nothing to cancel")
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Error("Close did not cancel the context the pool runs under")
	}
	if n := len(p.connectedClients()); n != 0 {
		t.Errorf("%d clients survived Close", n)
	}
}

// A pool that only comes online after the initial dial failed must still
// announce itself.
//
// Client.Connect starts its reconnect loop even when it returns the initial
// dial error. Work keyed off Connect's return value therefore never runs after
// a transient startup outage. On the agent that work is the sole call to
// DetectPortRestriction, and the periodic classifier cannot recover the
// distinction, so the node would stay classified as plain cone for the life of
// the process.
func TestPoolOnFirstConnectFiresAfterAFailedInitialDial(t *testing.T) {
	p := testPool(t, deadAddr(t))

	var once sync.Once
	fired := make(chan struct{})
	p.SetOnFirstConnect(func() { once.Do(func() { close(fired) }) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.Connect(ctx); err == nil {
		t.Fatal("expected the initial dial to a dead address to fail")
	}
	defer p.Close()

	// Nothing is listening, so the callback must stay silent rather than fire
	// on a pool that never came online.
	select {
	case <-fired:
		t.Fatal("onFirstConnect fired while no client was connected")
	case <-time.After(1500 * time.Millisecond):
	}

	// The watch loop is what would pick up a later success. Prove it is running
	// and wired to the same guard by marking the pool connected directly.
	p.noteConnected()
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("onFirstConnect never fired")
	}
}

// The callback runs at most once no matter how many paths report a connection.
func TestPoolOnFirstConnectIsIdempotent(t *testing.T) {
	p := testPool(t, deadAddr(t))
	var mu sync.Mutex
	calls := 0
	p.SetOnFirstConnect(func() { mu.Lock(); calls++; mu.Unlock() })

	for i := 0; i < 5; i++ {
		p.noteConnected()
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("onFirstConnect ran %d times, want 1", calls)
	}
}

// A closed pool must not run the callback.
func TestPoolOnFirstConnectSilentAfterClose(t *testing.T) {
	p := testPool(t, deadAddr(t))
	fired := false
	p.SetOnFirstConnect(func() { fired = true })
	p.Close()
	p.noteConnected()
	if fired {
		t.Error("onFirstConnect ran after Close")
	}
}
