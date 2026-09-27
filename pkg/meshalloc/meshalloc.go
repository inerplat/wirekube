// Package meshalloc hands out mesh overlay addresses that no two peers share.
//
// meship reduces a hash of the peer's name into the mesh CIDR, which is
// reproducible from the name alone but not injective: two names can land on
// the same /32, and both peers then advertise it. Widening the CIDR only moves
// the birthday bound; it does not remove the case.
//
// The allocator keeps the hash as the first choice and resolves the rest with
// the arbiter every caller already trusts — the API server. A claim is a Lease
// named after the address, so creating it is the arbitration: etcd admits
// exactly one creator per name, and the loser learns it lost from the
// AlreadyExists it gets back. There is no central allocator process, no
// watch-and-hope, and no second source of truth to reconcile.
//
// On a conflict the caller walks to its next meship candidate, which is a
// name-specific permutation of the usable range, so two peers contending for
// the same address diverge immediately instead of chasing each other down the
// same sequence.
//
// The package is deliberately usable before the peer it allocates for exists:
// an enrolment tool claims the address, then brings up a node that advertises
// it. Claims therefore carry no ownerReference — garbage collection would
// delete a claim whose owner has not been created yet — and are reclaimed by
// the reaper in pkg/controller/meshalloc instead.
package meshalloc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inerplat/wirekube/pkg/meship"
)

const (
	// MeshLabel names the mesh a claim belongs to, so claims for different
	// meshes in one cluster can be counted and reaped separately.
	MeshLabel = "wirekube.io/mesh"
	// PeerLabel names the peer holding the claim. The reaper selects on it
	// to find the claims of a peer that no longer exists.
	PeerLabel = "wirekube.io/peer-name"
	// ClaimLabel marks the Lease as an address claim rather than one of the
	// leader-election Leases WireKube also keeps in the same namespace.
	ClaimLabel = "wirekube.io/claim"
	// ClaimAddress is the ClaimLabel value for an address claim.
	ClaimAddress = "address"

	// AddressAnnotation records the claimed address in CIDR notation. The
	// Lease name encodes it too, but only in a lossy dashed form, so the
	// annotation is what consumers read.
	AddressAnnotation = "wirekube.io/address"
	// AttemptAnnotation records which meship candidate won, purely as a
	// diagnostic: a fleet where this is routinely non-zero is running close
	// enough to full that the mesh CIDR wants widening.
	AttemptAnnotation = "wirekube.io/attempt"

	// probeLimit caps how many candidates a single Allocate walks before it
	// stops probing blind and lists the claims it is contending with.
	//
	// Probing is one API call per occupied candidate, so in a pool that is a
	// fraction f full the expected cost is 1/(1-f) calls — under three even at
	// two thirds full. It is only as the pool approaches full that the
	// expected walk grows without bound, and there the LIST is both cheaper
	// and exact. The cap is what switches between the two.
	//
	// The LIST is affordable because density and pool size pull in opposite
	// directions: a mesh dense enough to reach the cap is necessarily a small
	// one (a /24 that is 99% full holds 251 claims), while the large meshes
	// where a full list would hurt are the ones nowhere near full, so they
	// reach the cap with probability f^32 — vanishing. Measured: the last free
	// address in a 253-of-254 /24 costs 67 API calls, against 253 for an
	// uncapped walk, and the figure does not grow with how full the mesh is.
	probeLimit = 32
)

// ErrExhausted reports that every usable address in the mesh CIDR is claimed.
// It is not a transient condition: nothing frees up on its own, and the mesh
// CIDR has to be widened.
var ErrExhausted = errors.New("meshalloc: every address in the mesh CIDR is claimed")

// Allocator claims mesh addresses as Leases in a single namespace.
type Allocator struct {
	// Client creates and deletes the claim Leases.
	Client client.Client
	// Reader serves the reads that decide an allocation. It must not be
	// cached. A cached read can still be serving a claim that has since been
	// deleted, or miss one just created, and both mistakes end the same way:
	// the Get after an AlreadyExists sees the previous holder, this caller
	// concludes the claim is its own, and two peers advertise one address.
	//
	// Leave it nil when Client is already uncached; a controller-runtime
	// manager's client is not, and should pass mgr.GetAPIReader().
	Reader client.Reader
	// Namespace holds the claim Leases. It is the namespace WireKube itself
	// runs in, so the claims are cleaned up with the installation.
	Namespace string
	// MeshName scopes claims to one WireKubeMesh.
	MeshName string
	// MeshCIDR is the range to allocate from.
	MeshCIDR string
}

// Request describes the claim to make.
type Request struct {
	// Holder identifies who holds the claim. It is the name the reaper looks
	// up to decide whether the claim is still answered for, so it has to be a
	// WireKubePeer or WireKubeExternalPeer name — both of which are Kubernetes
	// object names, and so safe to put in a label.
	Holder string
	// Name is the name the address derives from. It defaults to Holder, and
	// differs only where WireKube itself derives from something else: an
	// external peer's address comes from its display name, which is free-form
	// text and must never be used as the holder. Deriving from the wrong one
	// would renumber a peer that is already up.
	Name string
	// Preferred is the address the caller already holds, if any. It is taken
	// when it is usable and free, so adopting the allocator renumbers nobody.
	Preferred string
}

func (r Request) hashName() string {
	if r.Name != "" {
		return r.Name
	}
	return r.Holder
}

// Result is a claimed address and how it was reached.
type Result struct {
	// Address is the claimed /32 in CIDR notation.
	Address string
	// Attempt is the meship candidate index that won; 0 means the peer got
	// the address its name hashes to.
	Attempt int
	// Adopted is true when the claim already existed and belonged to this
	// peer, which is the normal path on every call after the first.
	Adopted bool
}

// Allocate returns the address peerName holds, claiming one if it does not
// hold one yet. It is idempotent: a peer that already holds a claim gets the
// same address back on every call without writing anything.
//
// Preference order:
//
//  1. A claim peerName already holds. This is the steady state and it is what
//     makes the address sticky across restarts — a peer must never drift onto
//     a different address just because the one ahead of it in the walk has
//     since been freed.
//  2. preferred, when it is given, inside the mesh CIDR, and unclaimed. The
//     caller passes the address the peer is already advertising so that a mesh
//     migrating onto the allocator keeps every peer exactly where it is.
//  3. The meship walk, starting at the peer's hashed address.
//
// A preferred address held by somebody else is not an error: the peer moves.
// That is the case the allocator exists for, and refusing it would leave two
// peers advertising the same /32 rather than fixing it.
func (a *Allocator) Allocate(ctx context.Context, request Request) (Result, error) {
	if err := a.validate(); err != nil {
		return Result{}, err
	}
	if request.Holder == "" {
		return Result{}, fmt.Errorf("meshalloc: a claim needs a holder")
	}
	capacity, err := meship.Capacity(a.MeshCIDR)
	if err != nil {
		return Result{}, err
	}

	held, found, err := a.heldClaim(ctx, request)
	if err != nil {
		return Result{}, err
	}
	if found {
		return held, nil
	}

	if request.Preferred != "" && meship.Contains(request.Preferred, a.MeshCIDR) {
		result, claimed, err := a.claim(ctx, request.Holder, request.Preferred, -1)
		if err != nil {
			return Result{}, err
		}
		if claimed {
			return result, nil
		}
	}

	probed := min(probeLimit, capacity)
	for attempt := range probed {
		address, err := meship.IPForNameAttempt(request.hashName(), a.MeshCIDR, attempt)
		if err != nil {
			return Result{}, err
		}
		result, claimed, err := a.claim(ctx, request.Holder, address, attempt)
		if err != nil {
			return Result{}, err
		}
		if claimed {
			return result, nil
		}
	}
	if probed == capacity {
		// The walk is a permutation, so it has already tried every address.
		return Result{}, fmt.Errorf("%w: %s holds %d addresses", ErrExhausted, a.MeshCIDR, capacity)
	}
	return a.allocateFromFreeList(ctx, request, capacity)
}

// heldClaim returns the claim peerName already holds, if any.
//
// Holding more than one is not supposed to happen, but a create whose response
// was lost and a subsequent walk that picked a different candidate can leave a
// stray behind, and nothing else would ever collect it: the reaper only
// reclaims claims whose holder no longer exists. So the extras are released
// here, where the holder is present and can say which one it kept.
func (a *Allocator) heldClaim(ctx context.Context, request Request) (Result, bool, error) {
	claims, err := a.list(ctx, client.MatchingLabels{PeerLabel: labelSafe(request.Holder)})
	if err != nil {
		return Result{}, false, err
	}
	var mine, stale []*coordinationv1.Lease
	for i := range claims.Items {
		lease := &claims.Items[i]
		// The label is lossy and therefore ambiguous; holderIdentity is the
		// authoritative holder.
		if holderOf(lease) != request.Holder || addressOf(lease) == "" {
			continue
		}
		// A claim the mesh CIDR no longer covers is not an allocation, it is a
		// leftover from the CIDR it was made under. Adopting it would hand back
		// an address the mesh cannot route, and the caller would quietly fall
		// back to an unclaimed one — a duplicate, which is the whole thing this
		// package exists to prevent.
		if meship.Contains(addressOf(lease), a.MeshCIDR) {
			mine = append(mine, lease)
		} else {
			stale = append(stale, lease)
		}
	}

	keep := (*coordinationv1.Lease)(nil)
	for _, lease := range mine {
		if keep == nil || betterClaim(lease, keep, request.Preferred) {
			keep = lease
		}
	}
	// Release everything this holder should not be holding: the stale ones,
	// and any duplicate beyond the one kept. Nothing else would collect the
	// duplicates — the reaper only reclaims claims whose holder is gone — and
	// here the holder is present and can say which one it kept.
	for _, lease := range append(stale, mine...) {
		if lease == keep {
			continue
		}
		uid := lease.UID
		if err := a.Client.Delete(ctx, lease, client.Preconditions{UID: &uid}); err != nil &&
			!apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return Result{}, false, fmt.Errorf("release the superseded claim on mesh address %s: %w", addressOf(lease), err)
		}
	}
	if keep == nil {
		return Result{}, false, nil
	}
	return Result{Address: addressOf(keep), Attempt: attemptOf(keep), Adopted: true}, true, nil
}

// betterClaim decides which of two claims held by the same peer to keep: the
// one the peer is already advertising, else the earliest candidate, else the
// lower address so the choice does not depend on list order.
func betterClaim(candidate, incumbent *coordinationv1.Lease, preferred string) bool {
	if preferred != "" {
		if a, b := addressOf(candidate) == preferred, addressOf(incumbent) == preferred; a != b {
			return a
		}
	}
	if a, b := attemptOf(candidate), attemptOf(incumbent); a != b {
		return a < b
	}
	return addressOf(candidate) < addressOf(incumbent)
}

// allocateFromFreeList takes over when blind probing has been unlucky enough
// times to suggest the pool is dense. Listing the claims once costs a single
// API call and turns the remaining search exact: the walk skips straight to
// candidates nothing is known to hold, so a mesh with one free address left
// finds it in one further create rather than in as many creates as there are
// occupied addresses.
//
// The list can be stale by the time a create lands. That is fine — the create
// is still the arbiter, and a lost race just advances to the next unclaimed
// candidate.
func (a *Allocator) allocateFromFreeList(ctx context.Context, request Request, capacity int) (Result, error) {
	taken, err := a.claimedAddresses(ctx)
	if err != nil {
		return Result{}, err
	}
	for attempt := range capacity {
		address, err := meship.IPForNameAttempt(request.hashName(), a.MeshCIDR, attempt)
		if err != nil {
			return Result{}, err
		}
		if _, occupied := taken[address]; occupied {
			continue
		}
		result, claimed, err := a.claim(ctx, request.Holder, address, attempt)
		if err != nil {
			return Result{}, err
		}
		if claimed {
			return result, nil
		}
		taken[address] = struct{}{}
	}
	return Result{}, fmt.Errorf("%w: %s holds %d addresses", ErrExhausted, a.MeshCIDR, capacity)
}

// claim attempts to take address for peerName. It reports claimed=false only
// when the address is held by somebody else; every other outcome is either a
// successful claim or an error.
func (a *Allocator) claim(ctx context.Context, peerName, address string, attempt int) (Result, bool, error) {
	lease := a.leaseFor(peerName, address, attempt)
	err := a.Client.Create(ctx, lease)
	if err == nil {
		return Result{Address: address, Attempt: attempt}, true, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return Result{}, false, fmt.Errorf("claim mesh address %s for %s: %w", address, peerName, err)
	}

	existing := &coordinationv1.Lease{}
	if getErr := a.reader().Get(ctx, client.ObjectKeyFromObject(lease), existing); getErr != nil {
		if apierrors.IsNotFound(getErr) {
			// The holder released it between the create and the read. Report
			// it as taken rather than retrying here; the caller's walk comes
			// back around to it, and treating a vanished claim as ours would
			// hand out an address we never actually hold.
			return Result{}, false, nil
		}
		return Result{}, false, fmt.Errorf("read the claim on mesh address %s: %w", address, getErr)
	}
	if holderOf(existing) != peerName {
		return Result{}, false, nil
	}
	// Our own claim, from an earlier run or a create whose response was lost.
	return Result{Address: address, Attempt: attempt, Adopted: true}, true, nil
}

// Release drops peerName's claims. It is safe to call when there are none, and
// it never deletes a claim held by somebody else: an enrolment that is torn
// down after its address was already reassigned must not take the new holder's
// claim with it.
func (a *Allocator) Release(ctx context.Context, holder string) error {
	if err := a.validate(); err != nil {
		return err
	}
	claims, err := a.list(ctx, client.MatchingLabels{PeerLabel: labelSafe(holder)})
	if err != nil {
		return err
	}
	for i := range claims.Items {
		lease := &claims.Items[i]
		if holderOf(lease) != holder {
			continue
		}
		uid := lease.UID
		err := a.Client.Delete(ctx, lease, client.Preconditions{UID: &uid})
		if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return fmt.Errorf("release the claim on mesh address %s: %w", addressOf(lease), err)
		}
	}
	return nil
}

// claimedAddresses is the set of addresses currently claimed in this mesh.
func (a *Allocator) claimedAddresses(ctx context.Context) (map[string]struct{}, error) {
	claims, err := a.list(ctx)
	if err != nil {
		return nil, err
	}
	taken := make(map[string]struct{}, len(claims.Items))
	for i := range claims.Items {
		if address := addressOf(&claims.Items[i]); address != "" {
			taken[address] = struct{}{}
		}
	}
	return taken, nil
}

func (a *Allocator) list(ctx context.Context, extra ...client.ListOption) (*coordinationv1.LeaseList, error) {
	options := append([]client.ListOption{
		client.InNamespace(a.Namespace),
		client.MatchingLabels{ClaimLabel: ClaimAddress, MeshLabel: a.MeshName},
	}, extra...)
	claims := &coordinationv1.LeaseList{}
	if err := a.reader().List(ctx, claims, options...); err != nil {
		return nil, fmt.Errorf("list mesh address claims in %s: %w", a.Namespace, err)
	}
	return claims, nil
}

func (a *Allocator) leaseFor(peerName, address string, attempt int) *coordinationv1.Lease {
	holder := peerName
	attemptValue := fmt.Sprint(attempt)
	if attempt < 0 {
		// The address came from the caller rather than the walk, so there is
		// no candidate index to record.
		attemptValue = "preferred"
	}
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ClaimName(a.MeshName, address),
			Namespace: a.Namespace,
			Labels: map[string]string{
				ClaimLabel: ClaimAddress,
				MeshLabel:  a.MeshName,
				PeerLabel:  labelSafe(peerName),
			},
			Annotations: map[string]string{
				AddressAnnotation: address,
				AttemptAnnotation: attemptValue,
			},
		},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &holder},
	}
}

func (a *Allocator) validate() error {
	if a.Client == nil {
		return fmt.Errorf("meshalloc: no client configured")
	}
	if a.Namespace == "" {
		return fmt.Errorf("meshalloc: no namespace configured for address claims")
	}
	if a.MeshName == "" {
		return fmt.Errorf("meshalloc: no mesh name configured")
	}
	if a.MeshCIDR == "" {
		return fmt.Errorf("meshalloc: the mesh does not set spec.meshCIDR")
	}
	// The mesh name goes into the claim's name and into a label value, and it
	// is checked once here rather than at each create because the API server's
	// own rejection names a requirement rather than the mesh behind it.
	if longest := ClaimName(a.MeshName, "255.255.255.255/32"); len(longest) > validation.DNS1123SubdomainMaxLength {
		return fmt.Errorf("meshalloc: mesh name %q is too long to name address claims", a.MeshName)
	}
	for _, problem := range validation.IsValidLabelValue(a.MeshName) {
		return fmt.Errorf("meshalloc: mesh name %q cannot label address claims: %s", a.MeshName, problem)
	}
	return nil
}

// reader is the uncached read path, falling back to Client for callers whose
// client is already uncached.
func (a *Allocator) reader() client.Reader {
	if a.Reader != nil {
		return a.Reader
	}
	return a.Client
}

// ClaimName is the Lease name that arbitrates address within mesh. Two callers
// racing for one address must compute the same name or the arbitration does
// not happen, so this is the single definition of it.
func ClaimName(mesh, address string) string {
	host := strings.TrimSuffix(address, "/32")
	return "wirekube-" + mesh + "-" + strings.ReplaceAll(host, ".", "-")
}

// addressOf reads the claimed address off a claim Lease.
func addressOf(lease *coordinationv1.Lease) string {
	return lease.Annotations[AddressAnnotation]
}

func holderOf(lease *coordinationv1.Lease) string {
	if lease.Spec.HolderIdentity == nil {
		return ""
	}
	return *lease.Spec.HolderIdentity
}

// attemptOf reads the recorded candidate index off a claim, or -1 when the
// address did not come from the walk.
func attemptOf(lease *coordinationv1.Lease) int {
	attempt, err := strconv.Atoi(lease.Annotations[AttemptAnnotation])
	if err != nil {
		return -1
	}
	return attempt
}

// labelSafe renders a holder as a label value.
//
// It is lossy on purpose. A label value is at most 63 characters of
// alphanumerics, '-', '_' and '.', and holders can be longer than that; two
// holders that reduce to the same label is harmless, because the label is only
// a selector shortcut and holderIdentity is what actually decides ownership.
// Producing an invalid value is not harmless — it fails the create, and it
// fails the *list* too, where an unparseable selector turns into an error that
// looks nothing like the label that caused it.
func labelSafe(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
		if len(out) == 63 {
			break
		}
	}
	// A label value must start and end alphanumeric. Trimming can empty it,
	// which is still a valid value and still selects consistently.
	return strings.Trim(string(out), "-_.")
}
