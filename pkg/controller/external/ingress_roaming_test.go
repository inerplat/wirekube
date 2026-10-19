package external

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/failover"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

// sharedIngressPubKey reads the shared identity the controller created.
func sharedIngressPubKey(t *testing.T, c client.Client) string {
	t.Helper()
	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: "wirekube-system", Name: wirekubev1alpha1.ExternalIngressSecretName}
	if err := c.Get(context.Background(), key, secret); err != nil {
		t.Fatalf("shared ingress Secret: %v", err)
	}
	kp, err := wireguard.ParseKeyPair(string(secret.Data[wirekubev1alpha1.ExternalIngressSecretKey]))
	if err != nil {
		t.Fatal(err)
	}
	return kp.PublicKeyBase64()
}

// roamingFixture is a cluster of two ingress-capable nodes whose liveness the
// test drives through their self-reports.
type roamingFixture struct {
	t   *testing.T
	c   client.Client
	r   *Reconciler
	now time.Time
}

func newRoamingFixture(t *testing.T, cr *wirekubev1alpha1.WireKubeExternalPeer) *roamingFixture {
	f := &roamingFixture{t: t, now: time.Now()}
	f.c = newFakeClient(t, cr, newReadyMesh(),
		newIngressPeerWith("node-a", ingressPubKey()),
		newIngressPeerWith("node-b", alternateIngressPubKey()),
	)
	f.r = &Reconciler{
		Client: f.c, Scheme: testScheme(t), Relay: newMockRelay(testRelayHost),
		Now: func() time.Time { return f.now },
	}
	f.report("node-a", "node-b")
	return f
}

// report refreshes the named nodes' self-reports at the current time.
func (f *roamingFixture) report(names ...string) {
	f.t.Helper()
	for _, name := range names {
		peer := &wirekubev1alpha1.WireKubePeer{}
		if err := f.c.Get(context.Background(), types.NamespacedName{Name: name}, peer); err != nil {
			f.t.Fatal(err)
		}
		at := metav1.NewTime(f.now)
		peer.Status.LastReportedAt = &at
		if err := f.c.Status().Update(context.Background(), peer); err != nil {
			f.t.Fatal(err)
		}
	}
}

// advance moves time on, with only the named nodes still reporting.
func (f *roamingFixture) advance(d time.Duration, alive ...string) {
	f.t.Helper()
	step := 30 * time.Second
	for left := d; left > 0; left -= step {
		if left < step {
			step = left
		}
		f.now = f.now.Add(step)
		f.report(alive...)
	}
}

func (f *roamingFixture) reconcile() (ctrl.Result, *wirekubev1alpha1.WireKubeExternalPeer) {
	f.t.Helper()
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}})
	if err != nil {
		f.t.Fatal(err)
	}
	return res, getCR(f.t, f.c, testExternalName)
}

func TestRoaming_FailsOverWhenTheIngressGoesSilent(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName))
	res := reconcileTwice(t, f.r, testExternalName)
	_, got := f.reconcile()
	first := got.Status.IngressPeerName
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive || first == "" {
		t.Fatalf("not issued: %+v", got.Status)
	}
	shared := sharedIngressPubKey(t, f.c)
	if got.Status.IngressPublicKey != shared {
		t.Fatal("a new peer was not issued under the shared identity")
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > requeueLong {
		t.Fatalf("a roaming peer must be polled for ingress health, got %+v", res)
	}
	other := "node-b"
	if first == "node-b" {
		other = "node-a"
	}

	// The serving node stops reporting; the peer moves within the threshold
	// plus one poll, keeping the key its client already has.
	f.advance(failover.LivenessThreshold+requeueLong, other)
	_, got = f.reconcile()
	if got.Status.IngressPeerName != other {
		t.Fatalf("ingress = %q after %s went silent, want %s", got.Status.IngressPeerName, first, other)
	}
	if got.Status.IngressPublicKey != shared || got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("failover changed the client-facing identity or phase: %+v", got.Status)
	}

	// Its recovery does not pull the peer back: there is no preference.
	f.advance(10*time.Minute, "node-a", "node-b")
	if _, got = f.reconcile(); got.Status.IngressPeerName != other {
		t.Fatalf("peer moved back to %s without a preference", got.Status.IngressPeerName)
	}
}

func TestRoaming_PreferredIngressFailsBackAfterSettling(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.IngressPeer = "node-a"
	}))
	reconcileTwice(t, f.r, testExternalName)
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-a" {
		t.Fatalf("ingress = %q, want the preferred node-a", got.Status.IngressPeerName)
	}

	f.advance(failover.LivenessThreshold+requeueLong, "node-b")
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-b" {
		t.Fatalf("ingress = %q while node-a is down, want node-b", got.Status.IngressPeerName)
	}

	// node-a is back but has not settled yet.
	f.advance(30*time.Second, "node-a", "node-b")
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-b" {
		t.Fatal("failed back before the preferred node settled")
	}
	f.advance(failover.FailbackDelay, "node-a", "node-b")
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-a" {
		t.Fatalf("ingress = %q, want a failback to node-a", got.Status.IngressPeerName)
	}
}

func TestRoaming_NodeKeyPeerStaysPinned(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName, issuedUnderNodeKey("node-a", ingressPubKey())))
	reconcileTwice(t, f.r, testExternalName)
	f.advance(10*time.Minute, "node-b")
	_, got := f.reconcile()
	if got.Status.IngressPeerName != "node-a" || got.Status.IngressPublicKey != ingressPubKey() {
		t.Fatalf("a peer issued under node-a's key was moved: %+v", got.Status)
	}
}

// TestRoaming_AllSilentHoldsStill covers every node going quiet at once, which
// points at status writes failing, not every node dying, so the peer stays put.
func TestRoaming_AllSilentHoldsStill(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName))
	reconcileTwice(t, f.r, testExternalName)
	_, before := f.reconcile()
	f.advance(10 * time.Minute)
	_, got := f.reconcile()
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive || got.Status.IngressPeerName != before.Status.IngressPeerName {
		t.Fatalf("peer moved or parked with every node silent: %+v", got.Status)
	}
}

func TestRoaming_NoReachableIngressIsPending(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName))
	// The relay can reach neither node.
	f.r.Relay = newProbeRelay(testRelayHost, map[[32]byte]time.Duration{})
	reconcileTwice(t, f.r, testExternalName)
	_, got := f.reconcile()
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Fatalf("phase = %q with no node reachable, want Pending", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonNoReadyIngressPeer {
		t.Fatalf("Reason = %q", cond.Reason)
	}
}

func TestSharedIngressKeyIsCreatedOnceAndReused(t *testing.T) {
	c := newFakeClient(t)
	r := &Reconciler{Client: c, Scheme: testScheme(t)}
	first, ok := r.sharedIngressKey(context.Background())
	if !ok {
		t.Fatal("shared identity unavailable")
	}
	// A second controller (a new leader) reads the same identity.
	r2 := &Reconciler{Client: c, Scheme: testScheme(t)}
	second, ok := r2.sharedIngressKey(context.Background())
	if !ok || second != first {
		t.Fatal("a second controller minted a different identity")
	}
}

// secretReadsFail makes every Secret read fail, as when the API server or
// RBAC refuses it.
type secretReadsFail struct {
	client.Client
	fail bool
}

func (s *secretReadsFail) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Secret); ok && s.fail {
		return errors.New("secrets is forbidden")
	}
	return s.Client.Get(ctx, key, obj, opts...)
}

func TestRoaming_UnreadableIdentityNeverRewritesTheIssuedKey(t *testing.T) {
	sharedKP, _ := wireguard.GenerateKeyPair()
	cr := newExternalPeer(testExternalName, issuedUnderNodeKey("node-a", sharedKP.PublicKeyBase64()))
	f := newRoamingFixture(t, cr)
	failing := &secretReadsFail{Client: f.c, fail: true}
	f.r.Client = failing

	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: testExternalName}}
	f.r.Reconcile(ctx, req) // adds the finalizer
	if _, err := f.r.Reconcile(ctx, req); err == nil {
		t.Fatal("reconcile went ahead without the identity the peer was issued under")
	}
	if got := getCR(t, f.c, testExternalName); got.Status.IngressPublicKey != sharedKP.PublicKeyBase64() {
		t.Fatalf("issued key rewritten to %q", got.Status.IngressPublicKey)
	}
}

func TestRoaming_FailedRefreshKeepsTheLastIdentity(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName))
	failing := &secretReadsFail{Client: f.c}
	f.r.Client = failing
	reconcileTwice(t, f.r, testExternalName)
	shared := sharedIngressPubKey(t, f.c)

	failing.fail = true
	f.advance(2*sharedKeyCacheTTL, "node-a", "node-b")
	_, got := f.reconcile()
	if got.Status.IngressPublicKey != shared || got.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
		t.Fatalf("a failed refresh disturbed the peer: %+v", got.Status)
	}
}

// TestRoaming_SkipsAgentsWithoutSharedIngress covers a rolling upgrade: a
// node still on an agent that cannot serve the shared identity must not be
// handed a peer issued under it, however healthy it looks.
func TestRoaming_SkipsAgentsWithoutSharedIngress(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.IngressPeer = "node-a"
	}))
	old := &wirekubev1alpha1.WireKubePeer{}
	if err := f.c.Get(context.Background(), types.NamespacedName{Name: "node-a"}, old); err != nil {
		t.Fatal(err)
	}
	old.Status.SharedExternalIngress = false
	if err := f.c.Status().Update(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	reconcileTwice(t, f.r, testExternalName)
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-b" {
		t.Fatalf("ingress = %q, want node-b while node-a runs an older agent", got.Status.IngressPeerName)
	}
}

// TestRoaming_OlderControllerRewriteIsUndone covers an older controller writing
// a node key into a shared-identity peer's status: the annotation keeps the peer
// roaming, and the next reconcile restores the shared key.
func TestRoaming_OlderControllerRewriteIsUndone(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName))
	reconcileTwice(t, f.r, testExternalName)
	_, got := f.reconcile()
	shared := sharedIngressPubKey(t, f.c)
	if got.Annotations[wirekubev1alpha1.ExternalPeerIssuedIngressKeyAnnotation] != shared {
		t.Fatalf("issued key not recorded: %v", got.Annotations)
	}

	node := got.Status.IngressPeerName
	nodeKey := ingressPubKey()
	if node == "node-b" {
		nodeKey = alternateIngressPubKey()
	}
	got.Status.IngressPublicKey = nodeKey
	if err := f.c.Status().Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if _, got = f.reconcile(); got.Status.IngressPublicKey != shared {
		t.Fatalf("ingressPublicKey = %q after the rewrite, want the shared key back", got.Status.IngressPublicKey)
	}
}

// TestRoaming_RotatedIdentityParksThePeer covers a peer whose shared identity was
// rotated away: it waits for re-issue instead of being given a key its client
// does not have.
func TestRoaming_RotatedIdentityParksThePeer(t *testing.T) {
	retired, _ := wireguard.GenerateKeyPair()
	cr := newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Annotations = map[string]string{wirekubev1alpha1.ExternalPeerIssuedIngressKeyAnnotation: retired.PublicKeyBase64()}
		p.Status.IngressPeerName = "node-a"
		p.Status.IngressPublicKey = retired.PublicKeyBase64()
	})
	f := newRoamingFixture(t, cr)
	reconcileTwice(t, f.r, testExternalName)
	_, got := f.reconcile()
	if got.Status.Phase != wirekubev1alpha1.ExternalPeerPhasePending {
		t.Fatalf("phase = %q, want Pending", got.Status.Phase)
	}
	if cond := findCondition(got.Status.Conditions, conditionReady); cond.Reason != reasonIngressIdentityRetired {
		t.Fatalf("Reason = %q", cond.Reason)
	}
	if got.Status.IngressPublicKey != retired.PublicKeyBase64() {
		t.Fatalf("issued key rewritten to %q", got.Status.IngressPublicKey)
	}
}

// TestRoaming_NoFailbackOntoADeadNodeWhenAllGoQuiet covers a peer that moved
// off a dead preferred node: when every node then stops reporting, the dead
// node must not count as alive and draw the peer back.
func TestRoaming_NoFailbackOntoADeadNodeWhenAllGoQuiet(t *testing.T) {
	f := newRoamingFixture(t, newExternalPeer(testExternalName, func(p *wirekubev1alpha1.WireKubeExternalPeer) {
		p.Spec.IngressPeer = "node-a"
	}))
	reconcileTwice(t, f.r, testExternalName)
	f.advance(failover.LivenessThreshold+requeueLong, "node-b")
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-b" {
		t.Fatal("setup: no failover")
	}
	f.advance(10 * time.Minute)
	if _, got := f.reconcile(); got.Status.IngressPeerName != "node-b" {
		t.Fatalf("ingress = %q once every node went quiet, want it left on node-b", got.Status.IngressPeerName)
	}
}
