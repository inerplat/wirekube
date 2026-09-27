package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inerplat/wirekube/pkg/meshalloc"
	"github.com/inerplat/wirekube/pkg/meship"
)

// allocNamespace creates a namespace per test so claims from one test cannot
// be seen by another. A claim Lease is named after the address, which is the
// whole arbitration mechanism, so tests sharing a namespace would arbitrate
// against each other.
func allocNamespace(t *testing.T) string {
	t.Helper()
	name := "ns-" + sanitize(t.Name())
	if len(name) > 63 {
		name = name[:63]
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(context.Background(), ns); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create namespace %s: %v", name, err)
	}
	return name
}

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

func newAllocator(t *testing.T, cidr string) *meshalloc.Allocator {
	t.Helper()
	return &meshalloc.Allocator{
		Client:    k8sClient,
		Namespace: allocNamespace(t),
		MeshName:  "default",
		MeshCIDR:  cidr,
	}
}

// TestAllocateKeepsTheHashedAddress is the migration guarantee: an
// uncontended mesh keeps handing out exactly what meship.IPForName does, so
// turning the allocator on moves nobody.
func TestAllocateKeepsTheHashedAddress(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	for _, name := range []string{"master", "worker1", "worker2", "worker3"} {
		want, err := meship.IPForName(name, a.MeshCIDR)
		if err != nil {
			t.Fatal(err)
		}
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: name})
		if err != nil {
			t.Fatalf("Allocate(%q): %v", name, err)
		}
		if got.Address != want {
			t.Errorf("Allocate(%q) = %s, want the hashed %s", name, got.Address, want)
		}
		if got.Attempt != 0 {
			t.Errorf("Allocate(%q) took attempt %d, want the first candidate", name, got.Attempt)
		}
	}
}

// TestAllocateIsIdempotent covers the agent restarting: it must get its own
// address back, not a new one, and without depending on anything it stored.
func TestAllocateIsIdempotent(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	first, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
		if err != nil {
			t.Fatalf("Allocate call %d: %v", i, err)
		}
		if got.Address != first.Address {
			t.Fatalf("call %d returned %s, want the held %s", i, got.Address, first.Address)
		}
		if !got.Adopted {
			t.Errorf("call %d did not report the claim as adopted", i)
		}
	}
}

// TestAllocateMovesTheSecondClaimant is the case the allocator exists for. The
// two names hash to the same /32; the first one to claim keeps it and the
// second gets a different address rather than advertising a duplicate.
func TestAllocateMovesTheSecondClaimant(t *testing.T) {
	const cidr = "198.18.18.0/24"
	first, second := collidingNames(t, cidr)
	a := newAllocator(t, cidr)

	won, err := a.Allocate(context.Background(), meshalloc.Request{Holder: first})
	if err != nil {
		t.Fatal(err)
	}
	moved, err := a.Allocate(context.Background(), meshalloc.Request{Holder: second})
	if err != nil {
		t.Fatal(err)
	}
	if moved.Address == won.Address {
		t.Fatalf("%q and %q both got %s", first, second, won.Address)
	}
	if moved.Attempt == 0 {
		t.Errorf("%q reported attempt 0 but did not get its hashed address", second)
	}
	// And the loser's address is sticky from then on.
	again, err := a.Allocate(context.Background(), meshalloc.Request{Holder: second})
	if err != nil {
		t.Fatal(err)
	}
	if again.Address != moved.Address {
		t.Errorf("%q moved again, from %s to %s", second, moved.Address, again.Address)
	}
}

// TestAllocateHonoursAFreePreferredAddress covers a peer already advertising
// an address that is not its hash — a mesh adopting the allocator must leave
// it where it is instead of renumbering it.
func TestAllocateHonoursAFreePreferredAddress(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	const preferred = "198.18.18.222/32"
	hashed, err := meship.IPForName("worker1", a.MeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	if hashed == preferred {
		t.Fatal("test vector is useless: worker1 already hashes to the preferred address")
	}
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1", Preferred: preferred})
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != preferred {
		t.Errorf("Allocate = %s, want the preferred %s", got.Address, preferred)
	}
}

// TestAllocateIgnoresAnUnusablePreferredAddress: a record from an older or
// wider mesh CIDR must not put the peer outside the mesh.
func TestAllocateIgnoresAnUnusablePreferredAddress(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	want, err := meship.IPForName("worker1", a.MeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	for _, preferred := range []string{"10.9.9.9/32", "198.18.18.0/32", "198.18.18.255/32", "garbage"} {
		a.Namespace = allocNamespace(t) // a fresh pool per case
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1", Preferred: preferred})
		if err != nil {
			t.Fatalf("preferred %q: %v", preferred, err)
		}
		if got.Address != want {
			t.Errorf("preferred %q: got %s, want the re-derived %s", preferred, got.Address, want)
		}
	}
}

// TestAllocateTakenPreferredAddressMoves: the peer wanted its old address but
// somebody else holds it now, so it takes another rather than duplicating.
func TestAllocateTakenPreferredAddressMoves(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	held, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "incumbent"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "latecomer", Preferred: held.Address})
	if err != nil {
		t.Fatal(err)
	}
	if got.Address == held.Address {
		t.Fatalf("latecomer took %s, which incumbent holds", held.Address)
	}
}

// TestAllocateExhaustsExactly fills a /29 — six usable addresses — and checks
// the seventh caller gets a terminal error rather than looping. The mesh CIDR
// has to be widened at that point; nothing frees up on its own.
func TestAllocateExhaustsExactly(t *testing.T) {
	const cidr = "198.18.18.0/29"
	a := newAllocator(t, cidr)
	capacity, err := meship.Capacity(cidr)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]string, capacity)
	for i := range capacity {
		name := fmt.Sprintf("peer-%d", i)
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: name})
		if err != nil {
			t.Fatalf("filling slot %d: %v", i, err)
		}
		if prev, ok := seen[got.Address]; ok {
			t.Fatalf("%s handed to both %q and %q", got.Address, prev, name)
		}
		seen[got.Address] = name
	}
	if len(seen) != capacity {
		t.Fatalf("filled %d of %d addresses", len(seen), capacity)
	}
	if _, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "one-too-many"}); !errors.Is(err, meshalloc.ErrExhausted) {
		t.Fatalf("Allocate on a full mesh returned %v, want ErrExhausted", err)
	}
}

// TestAllocateFindsTheLastFreeAddress is the dense-pool case. A /24 with 253
// of 254 addresses claimed must still be searched exactly, not by probing 253
// occupied candidates one create at a time.
func TestAllocateFindsTheLastFreeAddress(t *testing.T) {
	const cidr = "198.18.18.0/24"
	a := newAllocator(t, cidr)
	capacity, err := meship.Capacity(cidr)
	if err != nil {
		t.Fatal(err)
	}
	var free string
	for i := range capacity {
		name := fmt.Sprintf("filler-%d", i)
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: name})
		if err != nil {
			t.Fatalf("filling slot %d: %v", i, err)
		}
		if i == capacity-1 {
			free = got.Address
			if err := a.Release(context.Background(), name); err != nil {
				t.Fatalf("Release: %v", err)
			}
		}
	}
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "latecomer"})
	if err != nil {
		t.Fatalf("Allocate into a mesh with one free address: %v", err)
	}
	if got.Address != free {
		t.Errorf("got %s, want the only free address %s", got.Address, free)
	}
}

// TestAllocateConcurrentCallersNeverShare is the property the Lease create
// buys: etcd admits one creator per name, so no amount of concurrency can hand
// the same address to two peers.
func TestAllocateConcurrentCallersNeverShare(t *testing.T) {
	const peers = 40
	a := newAllocator(t, "198.18.18.0/24")

	var mu sync.Mutex
	got := make(map[string]string, peers)
	var wg sync.WaitGroup
	errs := make([]error, peers)
	for i := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("racer-%d", i)
			result, err := a.Allocate(context.Background(), meshalloc.Request{Holder: name})
			if err != nil {
				errs[i] = err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if prev, ok := got[result.Address]; ok {
				errs[i] = fmt.Errorf("%s handed to both %q and %q", result.Address, prev, name)
				return
			}
			got[result.Address] = name
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if len(got) != peers {
		t.Errorf("handed out %d distinct addresses to %d peers", len(got), peers)
	}
}

// TestAllocateConcurrentSamePeerConverges: two goroutines allocating for one
// peer name (an agent restarting into itself) must settle on one address and
// leave exactly one claim behind.
func TestAllocateConcurrentSamePeerConverges(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	const callers = 8
	results := make([]meshalloc.Result, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	// A converged allocation leaves one claim; the duplicate collapse in
	// heldClaim is what gets it there.
	settled, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
	if err != nil {
		t.Fatal(err)
	}
	claims := countClaims(t, a.Namespace)
	if claims != 1 {
		t.Errorf("worker1 holds %d claims after %d concurrent allocations, want 1", claims, callers)
	}
	for i, r := range results {
		if r.Address != settled.Address {
			t.Logf("caller %d initially got %s; settled on %s", i, r.Address, settled.Address)
		}
	}
}

func TestReleaseFreesTheAddressForSomebodyElse(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	held, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Release(context.Background(), "worker1"); err != nil {
		t.Fatal(err)
	}
	if n := countClaims(t, a.Namespace); n != 0 {
		t.Fatalf("%d claims left after Release, want 0", n)
	}
	// Releasing twice is not an error.
	if err := a.Release(context.Background(), "worker1"); err != nil {
		t.Fatalf("second Release: %v", err)
	}
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "successor", Preferred: held.Address})
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != held.Address {
		t.Errorf("successor got %s, want the freed %s", got.Address, held.Address)
	}
}

// TestReleaseLeavesAnotherHoldersClaimAlone: tearing down an enrolment after
// its address was reassigned must not take the new holder's claim with it.
func TestReleaseLeavesAnotherHoldersClaimAlone(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	if _, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "keeper"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Release(context.Background(), "stranger"); err != nil {
		t.Fatal(err)
	}
	if n := countClaims(t, a.Namespace); n != 1 {
		t.Errorf("%d claims left, want keeper's to survive", n)
	}
}

func TestAllocateRejectsAnIncompleteAllocator(t *testing.T) {
	for name, a := range map[string]*meshalloc.Allocator{
		"no client":    {Namespace: "x", MeshName: "default", MeshCIDR: "198.18.18.0/24"},
		"no namespace": {Client: k8sClient, MeshName: "default", MeshCIDR: "198.18.18.0/24"},
		"no mesh name": {Client: k8sClient, Namespace: "x", MeshCIDR: "198.18.18.0/24"},
		"no cidr":      {Client: k8sClient, Namespace: "x", MeshName: "default"},
		"bad cidr":     {Client: k8sClient, Namespace: "x", MeshName: "default", MeshCIDR: "198.18.18.0/31"},
	} {
		if _, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"}); err == nil {
			t.Errorf("%s: Allocate succeeded", name)
		}
	}
}

func countClaims(t *testing.T, namespace string) int {
	t.Helper()
	claims := &coordinationv1.LeaseList{}
	if err := k8sClient.List(context.Background(), claims,
		client.InNamespace(namespace),
		client.MatchingLabels{meshalloc.ClaimLabel: meshalloc.ClaimAddress}); err != nil {
		t.Fatalf("list claims: %v", err)
	}
	return len(claims.Items)
}

// collidingNames finds two names that hash into the same address in cidr.
func collidingNames(t *testing.T, cidr string) (string, string) {
	t.Helper()
	seen := make(map[string]string)
	for i := range 8192 {
		name := fmt.Sprintf("collide-%d", i)
		address, err := meship.IPForName(name, cidr)
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := seen[address]; ok {
			return prev, name
		}
		seen[address] = name
	}
	t.Fatalf("no colliding pair in %s", cidr)
	return "", ""
}

// countingClient counts the API calls an allocation makes, so the cost of a
// dense pool is asserted rather than assumed.
type countingClient struct {
	client.Client
	mu      sync.Mutex
	creates int
	lists   int
	gets    int
}

func (c *countingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.mu.Lock()
	c.creates++
	c.mu.Unlock()
	return c.Client.Create(ctx, obj, opts...)
}

func (c *countingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	c.mu.Lock()
	c.lists++
	c.mu.Unlock()
	return c.Client.List(ctx, list, opts...)
}

func (c *countingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *countingClient) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.creates, c.lists, c.gets = 0, 0, 0
}

func (c *countingClient) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creates + c.lists + c.gets
}

// TestAllocateCostIsBounded pins the API-call budget, because the obvious
// implementation of "hash, and on a conflict try the next one" degrades badly
// exactly where it matters: a /24 with 253 of 254 addresses taken would cost
// 253 failed creates to find the last one, and an unbounded retry loop would
// never admit it had run out.
//
// The probe cap turns that into a bounded walk plus one exact list. The
// budgets below are generous ceilings, not targets — the point is that they
// exist and do not scale with how full the mesh is.
func TestAllocateCostIsBounded(t *testing.T) {
	const cidr = "198.18.18.0/24"
	counter := &countingClient{Client: k8sClient}
	a := &meshalloc.Allocator{
		Client:    counter,
		Namespace: allocNamespace(t),
		MeshName:  "default",
		MeshCIDR:  cidr,
	}
	capacity, err := meship.Capacity(cidr)
	if err != nil {
		t.Fatal(err)
	}

	// An empty mesh: one list to check for an existing claim, one create.
	counter.reset()
	if _, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "first"}); err != nil {
		t.Fatal(err)
	}
	if got := counter.total(); got > 3 {
		t.Errorf("allocating into an empty mesh cost %d API calls (%d list, %d create, %d get), want at most 3",
			got, counter.lists, counter.creates, counter.gets)
	}

	// The steady state — an agent restarting — must not write at all.
	counter.reset()
	if _, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "first"}); err != nil {
		t.Fatal(err)
	}
	if counter.creates != 0 {
		t.Errorf("re-allocating for a peer that already holds a claim issued %d creates, want none", counter.creates)
	}
	if got := counter.total(); got > 2 {
		t.Errorf("re-allocating cost %d API calls, want at most 2", got)
	}

	var lastFree string
	for i := 1; i < capacity; i++ {
		name := fmt.Sprintf("filler-%d", i)
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: name})
		if err != nil {
			t.Fatalf("filling slot %d: %v", i, err)
		}
		lastFree = got.Address
		if i == capacity-1 {
			if err := a.Release(context.Background(), name); err != nil {
				t.Fatal(err)
			}
		}
	}

	// One address free out of 254. The naive walk would cost 253 creates.
	counter.reset()
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "latecomer"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != lastFree {
		t.Fatalf("got %s, want the only free address %s", got.Address, lastFree)
	}
	if total := counter.total(); total > 80 {
		t.Errorf("finding the last free address in a %s cost %d API calls (%d list, %d create, %d get), want a bounded walk",
			cidr, total, counter.lists, counter.creates, counter.gets)
	}
	t.Logf("last free address in a full %s: %d API calls (%d list, %d create, %d get)",
		cidr, counter.total(), counter.lists, counter.creates, counter.gets)

	// And a genuinely full mesh reports exhaustion at the same bounded cost.
	counter.reset()
	if _, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "one-too-many"}); !errors.Is(err, meshalloc.ErrExhausted) {
		t.Fatalf("Allocate on a full mesh returned %v, want ErrExhausted", err)
	}
	if total := counter.total(); total > 600 {
		t.Errorf("reporting exhaustion cost %d API calls, want it bounded by the pool size", total)
	}
	t.Logf("exhaustion in a full %s: %d API calls (%d list, %d create, %d get)",
		cidr, counter.total(), counter.lists, counter.creates, counter.gets)
}

// TestAllocateSurvivesAFreeFormHolder. An external peer's display name is
// free-form text, and a holder that is not a valid label value does not merely
// fail the create — it fails the list, where an unparseable selector surfaces
// as an error that looks nothing like the label that caused it. The label is
// only a selector shortcut, so reducing it is fine; producing an invalid one
// is not.
func TestAllocateSurvivesAFreeFormHolder(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	seen := make(map[string]string)
	for _, holder := range []string{
		"Alice's Laptop",
		"집 데스크톱",
		"dev box #2",
		"-leading-dash-",
		"...",
		strings.Repeat("long", 40),
	} {
		got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: holder})
		if err != nil {
			t.Errorf("Allocate(%q): %v", holder, err)
			continue
		}
		if prev, ok := seen[got.Address]; ok {
			t.Errorf("%s handed to both %q and %q", got.Address, prev, holder)
		}
		seen[got.Address] = holder

		// And it has to be able to find its own claim again, which is the part
		// a lossy label would break if the read and the write disagreed.
		again, err := a.Allocate(context.Background(), meshalloc.Request{Holder: holder})
		if err != nil {
			t.Errorf("re-Allocate(%q): %v", holder, err)
			continue
		}
		if again.Address != got.Address {
			t.Errorf("%q moved from %s to %s", holder, got.Address, again.Address)
		}
		if !again.Adopted {
			t.Errorf("%q did not find its own claim", holder)
		}
	}
}

// TestAllocateSeparatesTheHolderFromTheHashName. An external peer's address
// comes from its display name and must keep doing so — moving it would
// renumber peers that are up — while the claim is held under the resource
// name, which is what the reaper looks up and what is safe in a label.
func TestAllocateSeparatesTheHolderFromTheHashName(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	const displayName = "Alice's Laptop"
	want, err := meship.IPForName(displayName, a.MeshCIDR)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "laptop-cr", Name: displayName})
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != want {
		t.Errorf("address = %s, want the one the display name hashes to, %s", got.Address, want)
	}
	// The resource name holds it, so the reaper — which knows resource names,
	// not display names — sees the claim as answered for.
	if holder := claimHolder(t, a.Namespace, got.Address, a.MeshName); holder != "laptop-cr" {
		t.Errorf("holder = %q, want the resource name", holder)
	}
}

// TestAllocateDropsAClaimTheCIDRNoLongerCovers. After the mesh CIDR moves, a
// claim made under the old one is not an allocation, it is a leftover.
// Adopting it would hand back an address the mesh cannot route, and the caller
// would fall back to an unclaimed one — a duplicate, which is the whole point
// of the package.
func TestAllocateDropsAClaimTheCIDRNoLongerCovers(t *testing.T) {
	a := newAllocator(t, "198.18.18.0/24")
	held, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
	if err != nil {
		t.Fatal(err)
	}

	a.MeshCIDR = "198.18.19.0/24"
	got, err := a.Allocate(context.Background(), meshalloc.Request{Holder: "worker1"})
	if err != nil {
		t.Fatal(err)
	}
	if !meship.Contains(got.Address, a.MeshCIDR) {
		t.Fatalf("got %s, which %s cannot route", got.Address, a.MeshCIDR)
	}
	if got.Address == held.Address {
		t.Fatalf("kept %s from the previous CIDR", held.Address)
	}
	// The stale claim goes back; leaving it would hold an address nobody can
	// use, and nothing else collects a claim whose holder is still present.
	if n := countClaims(t, a.Namespace); n != 1 {
		t.Errorf("%d claims, want only the new one", n)
	}
}

func claimHolder(t *testing.T, namespace, address, mesh string) string {
	t.Helper()
	lease := &coordinationv1.Lease{}
	key := client.ObjectKey{Namespace: namespace, Name: meshalloc.ClaimName(mesh, address)}
	if err := k8sClient.Get(context.Background(), key, lease); err != nil {
		t.Fatalf("get claim: %v", err)
	}
	if lease.Spec.HolderIdentity == nil {
		return ""
	}
	return *lease.Spec.HolderIdentity
}
