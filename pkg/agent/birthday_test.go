package agent

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// newTestProxy builds a holePunchProxy backed by real loopback UDP sockets but
// without starting Run(), so ListenAddr() and Close() work in tests.
func newTestProxy(t *testing.T) *holePunchProxy {
	t.Helper()
	lc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen local: %v", err)
	}
	hc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		lc.Close()
		t.Fatalf("listen hole: %v", err)
	}
	return &holePunchProxy{localConn: lc, holeConn: hc, stopCh: make(chan struct{})}
}

// TestApplyBirthdayOutcomeFailure verifies a failed attack (nil proxy) marks the
// peer's ICE state failed without needing a WireGuard manager.
func TestApplyBirthdayOutcomeFailure(t *testing.T) {
	a := &Agent{log: logr.Discard()}
	peer := &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "peer-a"}}

	a.applyBirthdayOutcome(birthdayOutcome{peer: peer, proxy: nil})

	state := a.getICEState("peer-a")
	if state.State != iceStateFailed {
		t.Fatalf("state = %v, want %v", state.State, iceStateFailed)
	}
	if state.LastCheck.IsZero() {
		t.Fatal("LastCheck not set on failure")
	}
}

// TestBirthdayResultsHandoffRace exercises the birthdayCh handoff: many
// background goroutines report results concurrently while a single sync-side
// goroutine drains them and mutates the iceStates map. Under `go test -race`
// this asserts the fix — background attacks no longer touch shared maps; all
// mutation happens on the draining (sync) goroutine.
func TestBirthdayResultsHandoffRace(t *testing.T) {
	a := &Agent{log: logr.Discard(), birthdayCh: make(chan birthdayOutcome, 16)}
	ctx := context.Background()

	const senders = 8
	const perSender = 50
	target := senders * perSender

	var wg sync.WaitGroup
	wg.Add(senders)
	for s := 0; s < senders; s++ {
		go func(s int) {
			defer wg.Done()
			for i := 0; i < perSender; i++ {
				peer := &wirekubev1alpha1.WireKubePeer{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("peer-%d-%d", s, i)},
				}
				a.reportBirthday(ctx, peer, nil) // failure path: no wgMgr needed
			}
		}(s)
	}

	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			a.drainBirthdayResults()
			select {
			case <-stop:
				a.drainBirthdayResults() // final pass
				return
			default:
				runtime.Gosched()
			}
		}
	}()

	wg.Wait()     // all results sent (drainer keeps the buffer clear)
	close(stop)   // let the drainer finish and exit
	<-drained

	if got := len(a.iceStates); got != target {
		t.Fatalf("iceStates = %d, want %d", got, target)
	}
}

// TestBirthdayResultsSuccessRace exercises the success path: applyBirthdayOutcome
// folds a non-nil proxy via upgradeToDirect, which mutates peerFirstSeen,
// holePunchEndpoints, relayGracePeers and relayedPeers. Concurrent senders push
// results while the single sync-side goroutine drains; under `go test -race`
// this proves those maps keep their single-writer invariant.
func TestBirthdayResultsSuccessRace(t *testing.T) {
	a := &Agent{
		log:                logr.Discard(),
		wgMgr:              &fakeWGEngine{},
		birthdayCh:         make(chan birthdayOutcome, 16),
		iceStates:          map[string]*peerICEState{},
		peerFirstSeen:      map[string]time.Time{},
		holePunchEndpoints: map[string]string{},
		directEndpoints:    map[string]string{},
		relayedPeers:       map[string]bool{},
		relayGracePeers:    map[string]bool{},
	}
	ctx := context.Background()

	const target = 48
	proxies := make([]*holePunchProxy, target)
	peers := make([]*wirekubev1alpha1.WireKubePeer, target)
	for i := 0; i < target; i++ {
		proxies[i] = newTestProxy(t)
		name := fmt.Sprintf("peer-%d", i)
		peers[i] = &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: name}}
		// Seed as relayed so upgradeToDirect exercises the relayGracePeers path.
		a.relayedPeers[name] = true
	}
	t.Cleanup(func() {
		for _, p := range proxies {
			p.Close()
		}
	})

	const senders = 6
	var wg sync.WaitGroup
	wg.Add(senders)
	for s := 0; s < senders; s++ {
		go func(s int) {
			defer wg.Done()
			for i := s; i < target; i += senders {
				a.reportBirthday(ctx, peers[i], proxies[i])
			}
		}(s)
	}

	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			a.drainBirthdayResults()
			select {
			case <-stop:
				a.drainBirthdayResults()
				return
			default:
				runtime.Gosched()
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-drained

	if got := len(a.holePunchEndpoints); got != target {
		t.Fatalf("holePunchEndpoints = %d, want %d", got, target)
	}
	if len(a.relayedPeers) != 0 {
		t.Fatalf("relayedPeers = %d, want 0 (all upgraded to direct)", len(a.relayedPeers))
	}
	if got := len(a.relayGracePeers); got != target {
		t.Fatalf("relayGracePeers = %d, want %d", got, target)
	}
}

// TestReportBirthdayClosesProxyOnCancel verifies the shutdown leak guard: when
// the context is done before the result is drained, reportBirthday closes the
// proxy instead of leaking it.
func TestReportBirthdayClosesProxyOnCancel(t *testing.T) {
	a := &Agent{log: logr.Discard(), birthdayCh: make(chan birthdayOutcome)} // unbuffered: send blocks
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	proxy := newTestProxy(t)
	a.reportBirthday(ctx, &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "p"}}, proxy)

	// Close is idempotent (sync.Once); if reportBirthday already closed it, the
	// stopCh is closed and a second Close is a no-op. Detect closure via stopCh.
	select {
	case <-proxy.stopCh:
		// closed as expected
	default:
		t.Fatal("proxy was not closed on ctx cancellation")
	}
}
