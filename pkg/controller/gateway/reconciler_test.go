package gateway

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/failover"
)

type fixture struct {
	t   *testing.T
	c   client.Client
	r   *Reconciler
	now time.Time
}

func newFixture(t *testing.T, objs ...client.Object) *fixture {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wirekubev1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, now: time.Now()}
	f.c = fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).
		WithStatusSubresource(&wirekubev1alpha1.WireKubeGateway{}, &wirekubev1alpha1.WireKubePeer{}).
		Build()
	f.r = &Reconciler{Client: f.c, Now: func() time.Time { return f.now }}
	return f
}

// peer is a node running a current agent, which follows the controller.
func peer(name, ownIP string, allowed ...string) *wirekubev1alpha1.WireKubePeer {
	return &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: name + "-key", AllowedIPs: append([]string{ownIP}, allowed...)},
		Status:     wirekubev1alpha1.WireKubePeerStatus{GatewayElection: true},
	}
}

func gateway(name string, refs []string, cidrs ...string) *wirekubev1alpha1.WireKubeGateway {
	gw := &wirekubev1alpha1.WireKubeGateway{ObjectMeta: metav1.ObjectMeta{Name: name}}
	gw.Spec.PeerRefs = refs
	for _, c := range cidrs {
		gw.Spec.Routes = append(gw.Spec.Routes, wirekubev1alpha1.GatewayRoute{CIDR: c})
	}
	return gw
}

// report refreshes the named peers' self-reports at the current time.
func (f *fixture) report(names ...string) {
	f.t.Helper()
	for _, name := range names {
		p := f.peer(name)
		at := metav1.NewTime(f.now)
		p.Status.LastReportedAt = &at
		if err := f.c.Status().Update(context.Background(), p); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) advance(d time.Duration, alive ...string) {
	f.t.Helper()
	for left := d; left > 0; left -= 30 * time.Second {
		step := min(left, 30*time.Second)
		f.now = f.now.Add(step)
		f.report(alive...)
	}
}

func (f *fixture) reconcile() {
	f.t.Helper()
	if _, err := f.r.Reconcile(context.Background(), allGateways); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) peer(name string) *wirekubev1alpha1.WireKubePeer {
	f.t.Helper()
	p := &wirekubev1alpha1.WireKubePeer{}
	if err := f.c.Get(context.Background(), client.ObjectKey{Name: name}, p); err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fixture) active(gw string) string {
	f.t.Helper()
	g := &wirekubev1alpha1.WireKubeGateway{}
	if err := f.c.Get(context.Background(), client.ObjectKey{Name: gw}, g); err != nil {
		f.t.Fatal(err)
	}
	return g.Status.ActivePeer
}

func TestGatewayFailsOverAndWithdrawsTheDeadPeersRoutes(t *testing.T) {
	f := newFixture(t,
		peer("gw-a", "198.18.0.1/32"), peer("gw-b", "198.18.0.2/32"),
		gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24"))
	f.report("gw-a", "gw-b")
	f.reconcile()
	if f.active("site") != "gw-a" {
		t.Fatalf("active = %q, want gw-a", f.active("site"))
	}
	if got := f.peer("gw-a").Spec.AllowedIPs; !slices.Equal(got, []string{"198.18.0.1/32", "10.77.1.0/24"}) {
		t.Fatalf("gw-a advertises %v", got)
	}

	// gw-a dies: its WireKubePeer stays, its reports stop.
	f.advance(failover.LivenessThreshold+30*time.Second, "gw-b")
	f.reconcile()
	if f.active("site") != "gw-b" {
		t.Fatalf("active = %q after gw-a went silent, want gw-b", f.active("site"))
	}
	a, b := f.peer("gw-a"), f.peer("gw-b")
	if !slices.Equal(a.Spec.AllowedIPs, []string{"198.18.0.1/32"}) || a.Annotations[InjectedCIDRsAnnotation] != "" {
		t.Fatalf("the dead peer still advertises the gateway: %v %v", a.Spec.AllowedIPs, a.Annotations)
	}
	if !slices.Equal(b.Spec.AllowedIPs, []string{"198.18.0.2/32", "10.77.1.0/24"}) {
		t.Fatalf("gw-b advertises %v", b.Spec.AllowedIPs)
	}

	// gw-a returns and settles; the gateway goes back to it.
	f.advance(30*time.Second, "gw-a", "gw-b")
	f.reconcile()
	if f.active("site") != "gw-b" {
		t.Fatal("failed back before gw-a settled")
	}
	f.advance(failover.FailbackDelay, "gw-a", "gw-b")
	f.reconcile()
	if f.active("site") != "gw-a" {
		t.Fatalf("active = %q, want a failback to gw-a", f.active("site"))
	}
}

func TestGatewayFollowsHealthCheck(t *testing.T) {
	gw := gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24")
	gw.Spec.HealthCheck = &wirekubev1alpha1.GatewayHealthCheck{Enabled: true, Target: "10.77.1.1:443"}
	f := newFixture(t, peer("gw-a", "198.18.0.1/32"), peer("gw-b", "198.18.0.2/32"), gw)
	f.report("gw-a", "gw-b")
	f.reconcile()

	a := f.peer("gw-a")
	a.Status.GatewayProbes = []wirekubev1alpha1.GatewayProbeStatus{{Gateway: "site", Healthy: false, ConsecutiveFailures: 3, CheckedAt: metav1.NewTime(f.now)}}
	if err := f.c.Status().Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	if f.active("site") != "gw-b" {
		t.Fatalf("active = %q while gw-a cannot reach the target, want gw-b", f.active("site"))
	}
	g := &wirekubev1alpha1.WireKubeGateway{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "site"}, g)
	if g.Status.PeerHealth["gw-a"] != "unhealthy" || g.Status.PeerHealth["gw-b"] != "healthy" {
		t.Fatalf("peerHealth = %v", g.Status.PeerHealth)
	}
}

// TestGatewayHoldsWhenNothingIsEligible covers every peer failing at once:
// the gateway keeps its active peer rather than withdrawing its routes.
func TestGatewayHoldsWhenNothingIsEligible(t *testing.T) {
	gw := gateway("site", []string{"gw-a"}, "10.77.1.0/24")
	gw.Spec.HealthCheck = &wirekubev1alpha1.GatewayHealthCheck{Enabled: true, Target: "10.77.1.1"}
	f := newFixture(t, peer("gw-a", "198.18.0.1/32"), gw)
	f.report("gw-a")
	f.reconcile()
	a := f.peer("gw-a")
	a.Status.GatewayProbes = []wirekubev1alpha1.GatewayProbeStatus{{Gateway: "site", Healthy: false, CheckedAt: metav1.NewTime(f.now)}}
	if err := f.c.Status().Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	if f.active("site") != "gw-a" || !slices.Contains(f.peer("gw-a").Spec.AllowedIPs, "10.77.1.0/24") {
		t.Fatal("the gateway was taken down with no healthy peer to move to")
	}
}

func TestGatewayAllSilentHoldsStill(t *testing.T) {
	f := newFixture(t, peer("gw-a", "198.18.0.1/32"), peer("gw-b", "198.18.0.2/32"),
		gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24"))
	f.report("gw-a", "gw-b")
	f.reconcile()
	f.advance(10 * time.Minute)
	f.reconcile()
	if f.active("site") != "gw-a" {
		t.Fatalf("active = %q with every agent silent, want it left on gw-a", f.active("site"))
	}
}

func TestGatewayAdvertisementsAcrossGatewaysAndDeletion(t *testing.T) {
	f := newFixture(t,
		peer("gw-a", "198.18.0.1/32", "192.168.9.0/24"),
		gateway("one", []string{"gw-a"}, "10.77.1.0/24"),
		gateway("two", []string{"gw-a"}, "10.88.0.0/16"))
	f.report("gw-a")
	f.reconcile()
	want := []string{"198.18.0.1/32", "192.168.9.0/24", "10.77.1.0/24", "10.88.0.0/16"}
	if got := f.peer("gw-a").Spec.AllowedIPs; !slices.Equal(got, want) {
		t.Fatalf("advertised %v, want %v", got, want)
	}

	if err := f.c.Delete(context.Background(), gateway("two", nil)); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	want = []string{"198.18.0.1/32", "192.168.9.0/24", "10.77.1.0/24"}
	if got := f.peer("gw-a").Spec.AllowedIPs; !slices.Equal(got, want) {
		t.Fatalf("after deleting a gateway, advertised %v, want %v", got, want)
	}
}

// TestGatewayTakeoverWaitsForEveryLiveAgent covers a rolling upgrade: while a
// live peerRef still runs an agent that elects on its own, the controller
// leaves the gateway, and the routes that agent advertises, alone.
func TestGatewayTakeoverWaitsForEveryLiveAgent(t *testing.T) {
	const ann = InjectedCIDRsAnnotation
	old := peer("gw-a", "198.18.0.1/32", "10.77.1.0/24")
	old.Status.GatewayElection = false
	old.Annotations = map[string]string{ann: "10.77.1.0/24"}
	gw := gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24")
	gw.Status.ActivePeer = "gw-a"
	f := newFixture(t, old, peer("gw-b", "198.18.0.2/32"), gw)
	f.report("gw-a", "gw-b")
	f.reconcile()

	g := &wirekubev1alpha1.WireKubeGateway{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "site"}, g)
	if g.ElectedByController() {
		t.Fatal("took over a gateway an older agent still elects")
	}
	if got := f.peer("gw-a").Spec.AllowedIPs; !slices.Equal(got, []string{"198.18.0.1/32", "10.77.1.0/24"}) {
		t.Fatalf("an agent-elected gateway's routes were touched: %v", got)
	}

	// gw-a upgrades.
	a := f.peer("gw-a")
	a.Status.GatewayElection = true
	if err := f.c.Status().Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "site"}, g)
	if !g.ElectedByController() || g.Status.ActivePeer != "gw-a" {
		t.Fatalf("not taken over once every agent follows: %v %q", g.Annotations, g.Status.ActivePeer)
	}

	// A dead older peer does not hold the takeover up.
	f2 := newFixture(t, func() *wirekubev1alpha1.WireKubePeer {
		p := peer("gw-x", "198.18.0.9/32")
		p.Status.GatewayElection = false
		return p
	}(), peer("gw-y", "198.18.0.8/32"), gateway("other", []string{"gw-x", "gw-y"}, "10.99.0.0/16"))
	f2.report("gw-x", "gw-y")
	f2.advance(failover.LivenessThreshold+30*time.Second, "gw-y")
	f2.reconcile()
	if f2.active("other") != "gw-y" {
		t.Fatalf("active = %q; a silent older peer blocked the takeover", f2.active("other"))
	}
}

// statusPatchFails rejects gateway status writes.
type statusPatchFails struct{ client.Client }

func (s statusPatchFails) Status() client.SubResourceWriter { return failingStatus{s.Client.Status()} }

type failingStatus struct{ client.SubResourceWriter }

func (failingStatus) Patch(context.Context, client.Object, client.Patch, ...client.SubResourcePatchOption) error {
	return errors.New("etcdserver: request timed out")
}

// TestGatewayRoutesStayWithTheRecordedHolder covers a failover whose status
// write fails: agents still treat the old holder as the gateway, so its
// routes must not move yet.
func TestGatewayRoutesStayWithTheRecordedHolder(t *testing.T) {
	f := newFixture(t, peer("gw-a", "198.18.0.1/32"), peer("gw-b", "198.18.0.2/32"),
		gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24"))
	f.report("gw-a", "gw-b")
	f.reconcile()
	if f.active("site") != "gw-a" {
		t.Fatal("setup")
	}
	f.advance(failover.LivenessThreshold+30*time.Second, "gw-b")
	f.r.Client = statusPatchFails{f.c}
	if _, err := f.r.Reconcile(context.Background(), allGateways); err == nil {
		t.Fatal("a failed status write was not reported")
	}
	if !slices.Contains(f.peer("gw-a").Spec.AllowedIPs, "10.77.1.0/24") || slices.Contains(f.peer("gw-b").Spec.AllowedIPs, "10.77.1.0/24") {
		t.Fatalf("routes moved without the move being recorded: a=%v b=%v", f.peer("gw-a").Spec.AllowedIPs, f.peer("gw-b").Spec.AllowedIPs)
	}
}

// TestGatewayIsHandedBackWhenAnOlderAgentReturns covers a node that was
// down through the takeover and comes back still running an older agent,
// which elects the gateway on its own whatever the annotation says.
func TestGatewayIsHandedBackWhenAnOlderAgentReturns(t *testing.T) {
	old := peer("gw-a", "198.18.0.1/32")
	old.Status.GatewayElection = false
	f := newFixture(t, old, peer("gw-b", "198.18.0.2/32"), gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24"))
	f.report("gw-a", "gw-b")
	f.advance(failover.LivenessThreshold+30*time.Second, "gw-b")
	f.reconcile()
	g := &wirekubev1alpha1.WireKubeGateway{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "site"}, g)
	if !g.ElectedByController() || g.Status.ActivePeer != "gw-b" {
		t.Fatalf("setup: not taken over with the older peer silent: %v %q", g.Annotations, g.Status.ActivePeer)
	}

	// gw-a returns, not upgraded, and advertises the gateway itself.
	f.advance(30*time.Second, "gw-a", "gw-b")
	a := f.peer("gw-a")
	a.Spec.AllowedIPs = append(a.Spec.AllowedIPs, "10.77.1.0/24")
	a.Annotations = map[string]string{InjectedCIDRsAnnotation: "10.77.1.0/24"}
	if err := f.c.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "site"}, g)
	if g.ElectedByController() {
		t.Fatal("kept the gateway while an older agent elects it too")
	}
	if !slices.Contains(f.peer("gw-a").Spec.AllowedIPs, "10.77.1.0/24") {
		t.Fatal("touched the routes of a gateway handed back to the agents")
	}
}

// TestGatewayDoesNotFailBackOntoADeadPeerWhenAllGoQuiet covers a gateway that
// moved off a dead peer: when every agent then stops reporting, the dead
// peer must not count as alive and draw the gateway back.
func TestGatewayDoesNotFailBackOntoADeadPeerWhenAllGoQuiet(t *testing.T) {
	f := newFixture(t, peer("gw-a", "198.18.0.1/32"), peer("gw-b", "198.18.0.2/32"),
		gateway("site", []string{"gw-a", "gw-b"}, "10.77.1.0/24"))
	f.report("gw-a", "gw-b")
	f.reconcile()
	f.advance(failover.LivenessThreshold+30*time.Second, "gw-b")
	f.reconcile()
	if f.active("site") != "gw-b" {
		t.Fatal("setup: no failover")
	}
	f.advance(10 * time.Minute)
	f.reconcile()
	if f.active("site") != "gw-b" {
		t.Fatalf("active = %q once everyone went quiet, want it left on gw-b", f.active("site"))
	}
}
