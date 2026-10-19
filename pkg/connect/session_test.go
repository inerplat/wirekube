package connect

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

type fakeDataplane struct {
	mu      sync.Mutex
	applied []TunnelConfig
	dns     *DNSConfig
	closed  bool
}

func (f *fakeDataplane) Name() string { return "wkconnect0" }

func (f *fakeDataplane) Apply(cfg TunnelConfig, _ netip.AddrPort) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, cfg)
	return nil, nil
}

func (f *fakeDataplane) SetDNS(cfg DNSConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dns = &cfg
	return nil
}

func (f *fakeDataplane) LastHandshake() time.Time { return time.Time{} }

func (f *fakeDataplane) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeDataplane) appliedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wirekubev1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func testClient(t *testing.T, objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeExternalPeer{}).
		WithObjects(objs...).
		Build()
}

func testOptions(dp *fakeDataplane, out *syncBuffer) Options {
	return Options{
		Name:         "connect-alice-laptop",
		Host:         "laptop",
		WaitActive:   5 * time.Second,
		PollInterval: 10 * time.Millisecond,
		DNS:          true,
		Out:          out,
		OpenDataplane: func(string, int, [32]byte) (Dataplane, error) {
			return dp, nil
		},
		Resolve: func(context.Context, string) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.0.2.1:30479"), nil
		},
		LocalPrefixes: func() []netip.Prefix { return nil },
	}
}

// activate plays the controller: it waits for the session's peer and marks
// it Active with the given destinations.
func activate(t *testing.T, ctx context.Context, c client.Client, name string, allowed ...string) {
	t.Helper()
	for ctx.Err() == nil {
		cr := &wirekubev1alpha1.WireKubeExternalPeer{}
		// Only a peer the controller has not seen yet; a reissue test
		// must not activate the old peer on its way out.
		if err := c.Get(ctx, client.ObjectKey{Name: name}, cr); err == nil && cr.Status.Phase == "" {
			cr.Status = activePeer(allowed...).Status
			if err := c.Status().Update(ctx, cr); err == nil {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunConnectsFollowsStatusAndCleansUp(t *testing.T) {
	dnsSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kube-dns"},
		Spec:       corev1.ServiceSpec{ClusterIP: "10.96.0.10"},
	}
	c := testClient(t, dnsSvc)
	dp := &fakeDataplane{}
	out := &syncBuffer{}
	opts := testOptions(dp, out)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()

	activate(t, ctx, c, opts.Name, "10.96.0.0/12", "100.64.0.0/10")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })

	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(ctx, client.ObjectKey{Name: opts.Name}, cr); err != nil {
		t.Fatal(err)
	}
	if cr.Labels[ClientLabel] != ClientLabelValue || cr.Annotations[HostAnnotation] != "laptop" {
		t.Fatalf("peer metadata = %v %v", cr.Labels, cr.Annotations)
	}

	// The controller widens the destinations, e.g. a node joined.
	cr.Status.AllowedDestinations = append(cr.Status.AllowedDestinations, "10.244.0.0/16")
	if err := c.Status().Update(ctx, cr); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reapply", func() bool { return dp.appliedCount() == 2 })
	dp.mu.Lock()
	routes := dp.applied[1].Routes
	dns := dp.dns
	dp.mu.Unlock()
	if len(routes) != 3 {
		t.Fatalf("reapplied routes = %v", routes)
	}
	if dns == nil || dns.Server != netip.MustParseAddr("10.96.0.10") || dns.Search[0] != "default.svc.cluster.local" {
		t.Fatalf("dns = %+v", dns)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !dp.closed {
		t.Fatal("dataplane was not closed")
	}
	err := c.Get(context.Background(), client.ObjectKey{Name: opts.Name}, &wirekubev1alpha1.WireKubeExternalPeer{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("peer still present after disconnect: %v", err)
	}
}

func TestRunEndsWhenPeerIsDeleted(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	out := &syncBuffer{}
	opts := testOptions(dp, out)
	opts.DNS = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()

	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })
	cr := &wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: opts.Name}}
	if err := c.Delete(ctx, cr); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "was deleted") {
			t.Fatalf("Run = %v, want a deleted-peer error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end after its peer was deleted")
	}
	if !dp.closed {
		t.Fatal("dataplane was not closed")
	}
}

func TestRunRefusesEndpointInsideRoutes(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	opts := testOptions(dp, &syncBuffer{})
	opts.Resolve = func(context.Context, string) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("10.96.5.5:30479"), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	err := Run(ctx, c, opts)
	if err == nil || !strings.Contains(err.Error(), "falls inside") {
		t.Fatalf("Run = %v, want a routing-loop error", err)
	}
	if dp.appliedCount() != 0 {
		t.Fatal("dataplane was programmed despite the loop")
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: opts.Name}, &wirekubev1alpha1.WireKubeExternalPeer{}); !apierrors.IsNotFound(err) {
		t.Fatalf("peer left behind after a failed session: %v", err)
	}
}

func TestReplaceLeftover(t *testing.T) {
	ours := &wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{
		Name: "mine", Labels: map[string]string{ClientLabel: ClientLabelValue},
	}}
	theirs := &wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "contractor"}}
	c := testClient(t, ours, theirs)
	ctx := context.Background()

	if err := replaceLeftover(ctx, c, "mine", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: "mine"}, &wirekubev1alpha1.WireKubeExternalPeer{}); !apierrors.IsNotFound(err) {
		t.Fatalf("leftover not removed: %v", err)
	}
	err := replaceLeftover(ctx, c, "contractor", time.Second)
	if err == nil || !strings.Contains(err.Error(), "not issued by connect") {
		t.Fatalf("replaceLeftover on a foreign peer = %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: "contractor"}, &wirekubev1alpha1.WireKubeExternalPeer{}); err != nil {
		t.Fatalf("foreign peer was touched: %v", err)
	}
	if err := replaceLeftover(ctx, c, "absent", time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteOwnPeerSparesAReplacement(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	own := &wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
	if err := c.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, own.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	newer := &wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: "p", UID: "newer"}}
	if err := c.Create(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := deleteOwnPeer(ctx, c, own); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKey{Name: "p"}, &wirekubev1alpha1.WireKubeExternalPeer{}); err != nil {
		t.Fatalf("a newer session's peer was deleted: %v", err)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestRunHeartbeats(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	opts := testOptions(dp, &syncBuffer{})
	opts.DNS = false
	opts.HeartbeatInterval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")

	beat := func() string {
		cr := &wirekubev1alpha1.WireKubeExternalPeer{}
		if err := c.Get(ctx, client.ObjectKey{Name: opts.Name}, cr); err != nil {
			return ""
		}
		return cr.Annotations[wirekubev1alpha1.ExternalPeerHeartbeatAnnotation]
	}
	first := beat()
	if first == "" {
		t.Fatal("peer was issued without a heartbeat")
	}
	waitFor(t, "a fresh heartbeat", func() bool { return beat() != first })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// offsetClock is a wall clock the test can jump forward.
type offsetClock struct{ offset atomic.Int64 }

func (c *offsetClock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

func TestRunReissuesAfterSuspend(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	out := &syncBuffer{}
	opts := testOptions(dp, out)
	opts.DNS = false
	clock := &offsetClock{}
	opts.Now = clock.now

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })

	// The machine sleeps through the controller's heartbeat timeout.
	clock.offset.Add(int64(10 * time.Minute))
	waitFor(t, "reissue notice", func() bool { return strings.Contains(out.String(), "was this machine suspended") })
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "reapply on the new peer", func() bool { return dp.appliedCount() == 2 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !dp.closed {
		t.Fatal("dataplane was not closed")
	}
}

func TestRunReissuesAfterReclaimDuringOutage(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeExternalPeer{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				return errors.New("network is unreachable")
			},
		}).
		Build()
	dp := &fakeDataplane{}
	out := &syncBuffer{}
	opts := testOptions(dp, out)
	opts.DNS = false
	// Every reading moves the clock 20s on: ticks stay close together, so
	// this is not a suspend, but the failing heartbeats go stale quickly.
	var calls atomic.Int64
	base := time.Now()
	opts.Now = func() time.Time { return base.Add(time.Duration(calls.Add(1)) * 20 * time.Second) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })

	// Play the controller: reclaim the peer once its heartbeat is stale.
	waitFor(t, "a stale heartbeat", func() bool {
		return time.Duration(calls.Load())*20*time.Second > wirekubev1alpha1.ExternalPeerHeartbeatTimeout
	})
	if err := c.Delete(ctx, &wirekubev1alpha1.WireKubeExternalPeer{ObjectMeta: metav1.ObjectMeta{Name: opts.Name}}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reissue notice", func() bool { return strings.Contains(out.String(), "without a heartbeat") })
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "reapply on the new peer", func() bool { return dp.appliedCount() == 2 })
	if strings.Contains(out.String(), "was this machine suspended") {
		t.Fatal("an outage was mistaken for a suspend")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestRunSuspendPastTTLEnds covers a machine sleeping through its session's
// --ttl: on resume the session must end, not reissue itself a fresh peer.
func TestRunSuspendPastTTLEnds(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	opts := testOptions(dp, &syncBuffer{})
	opts.DNS = false
	opts.TTL = 10 * time.Minute
	clock := &offsetClock{}
	opts.Now = clock.now

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })

	clock.offset.Add(int64(15 * time.Minute))
	select {
	case err := <-done:
		if !errors.Is(err, errSessionExpired) {
			t.Fatalf("Run = %v, want the session to end at its TTL", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session outlived its TTL")
	}
	if dp.appliedCount() != 1 {
		t.Fatal("a peer was reissued past the TTL")
	}
}

// TestRunReissueGetsTheRemainingTTL covers a suspend shorter than --ttl:
// the reissued peer may only live out what is left of the session.
func TestRunReissueGetsTheRemainingTTL(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	out := &syncBuffer{}
	opts := testOptions(dp, out)
	opts.DNS = false
	opts.TTL = time.Hour
	clock := &offsetClock{}
	opts.Now = clock.now

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })

	clock.offset.Add(int64(20 * time.Minute))
	waitFor(t, "reissue", func() bool {
		cr := &wirekubev1alpha1.WireKubeExternalPeer{}
		return c.Get(ctx, client.ObjectKey{Name: opts.Name}, cr) == nil && cr.Status.Phase == ""
	})
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(ctx, client.ObjectKey{Name: opts.Name}, cr); err != nil {
		t.Fatal(err)
	}
	if cr.Spec.TTL == nil || cr.Spec.TTL.Duration > 41*time.Minute || cr.Spec.TTL.Duration < 39*time.Minute {
		t.Fatalf("reissued TTL = %v, want what is left of the hour", cr.Spec.TTL)
	}
	cancel()
	<-done
}

// TestRunEndsAtTTLWithoutTheController covers a session whose --ttl passes
// while the controller is not around to delete its peer.
func TestRunEndsAtTTLWithoutTheController(t *testing.T) {
	c := testClient(t)
	dp := &fakeDataplane{}
	opts := testOptions(dp, &syncBuffer{})
	opts.DNS = false
	opts.TTL = 2 * time.Minute
	clock := &offsetClock{}
	opts.Now = clock.now

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, opts) }()
	activate(t, ctx, c, opts.Name, "10.96.0.0/12")
	waitFor(t, "first apply", func() bool { return dp.appliedCount() == 1 })

	// Short of a suspend, and the peer is still there.
	clock.offset.Add(int64(3 * time.Minute))
	select {
	case err := <-done:
		if !errors.Is(err, errSessionExpired) {
			t.Fatalf("Run = %v, want the session to end at its TTL", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session outlived its TTL")
	}
}
