// Package meshalloc reclaims mesh address claims that no peer holds any more
// and publishes how full the mesh is.
//
// Claims deliberately carry no ownerReference: an enrolment tool claims an
// address before the node that will advertise it exists, and Kubernetes
// garbage collection would delete a claim whose owner is missing. Something
// therefore has to collect the claims that outlive their holder, and this is
// it — a single leader-elected sweep, which is also the only place that can
// say how many addresses are left without every agent listing the pool.
package meshalloc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/meshalloc"
	"github.com/inerplat/wirekube/pkg/meship"
)

const (
	// DefaultInterval is how often the sweep runs. Reclaiming is never
	// urgent — the address stays unusable until it happens, but nothing is
	// broken by it staying unusable a little longer — so the sweep is slow
	// enough to be invisible on a large cluster.
	DefaultInterval = 2 * time.Minute

	// DefaultGrace is how long a claim may have no peer before it is
	// reclaimed. It has to cover the gap an enrolment opens: a tool claims
	// the address, then boots a machine that takes minutes to register its
	// peer, and reclaiming inside that window would hand the address to
	// somebody else while the machine is still coming up. A claim whose
	// creator wants longer says so in spec.leaseDurationSeconds.
	DefaultGrace = 15 * time.Minute
)

// Reaper reclaims orphaned address claims and reports pool occupancy.
type Reaper struct {
	// Client reads claims and peers and deletes the orphans.
	Client client.Client
	// Namespace holds the claim Leases.
	Namespace string
	// Log receives one line per reclaimed claim.
	Log logr.Logger
	// Interval overrides DefaultInterval.
	Interval time.Duration
	// Grace overrides DefaultGrace for claims that do not set
	// spec.leaseDurationSeconds.
	Grace time.Duration
	// Now is injectable for tests.
	Now func() time.Time

	// orphanedSince remembers when this process first saw a claim with no
	// peer, keyed by claim name.
	//
	// Keeping it in memory rather than writing it to the claim is deliberate:
	// renewing a timestamp on every claim on every sweep would be a steady
	// write load on etcd proportional to the fleet size, to record something
	// whose only consequence is how soon an unusable address becomes usable
	// again. Losing it to a restart or a leader change only delays a reclaim.
	orphanedSince map[string]time.Time
}

var _ manager.Runnable = (*Reaper)(nil)
var _ manager.LeaderElectionRunnable = (*Reaper)(nil)

// NeedLeaderElection keeps the sweep to one replica. Two reapers would not
// corrupt anything — the deletes are UID-guarded — but they would double the
// list traffic and race each other's grace timers.
func (r *Reaper) NeedLeaderElection() bool { return true }

// Start runs the sweep until ctx is cancelled.
func (r *Reaper) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.Sweep(ctx); err != nil {
			r.Log.Error(err, "sweeping mesh address claims")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Sweep reclaims what it can and refreshes the occupancy gauges once.
func (r *Reaper) Sweep(ctx context.Context) error {
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if err := r.Client.List(ctx, meshList); err != nil {
		return fmt.Errorf("list WireKubeMesh: %w", err)
	}

	holders, err := r.peerNames(ctx)
	if err != nil {
		return err
	}

	claims := &coordinationv1.LeaseList{}
	if err := r.Client.List(ctx, claims,
		client.InNamespace(r.Namespace),
		client.MatchingLabels{meshalloc.ClaimLabel: meshalloc.ClaimAddress}); err != nil {
		return fmt.Errorf("list mesh address claims in %s: %w", r.Namespace, err)
	}

	live := make(map[string]struct{}, len(claims.Items))
	byMesh := make(map[string]int, len(meshList.Items))
	for i := range claims.Items {
		claim := &claims.Items[i]
		live[claim.Name] = struct{}{}
		meshName := claim.Labels[meshalloc.MeshLabel]
		mesh := findMesh(meshList.Items, meshName)

		reason, reclaim := r.shouldReclaim(claim, mesh, holders)
		if !reclaim {
			byMesh[meshName]++
			continue
		}
		if err := r.reclaim(ctx, claim, reason); err != nil {
			// One stuck claim must not stop the sweep; the next one retries.
			r.Log.Error(err, "reclaiming mesh address claim", "claim", claim.Name)
			byMesh[meshName]++
		}
	}

	// Forget claims that no longer exist so the map cannot grow without bound
	// across a long-lived leader.
	for name := range r.orphanedSince {
		if _, ok := live[name]; !ok {
			delete(r.orphanedSince, name)
		}
	}

	for i := range meshList.Items {
		mesh := &meshList.Items[i]
		capacity, err := meship.Capacity(mesh.Spec.MeshCIDR)
		if err != nil {
			// A mesh with no usable CIDR has no pool to report on.
			clearOccupancy(mesh.Name)
			continue
		}
		setOccupancy(mesh.Name, capacity, byMesh[mesh.Name])
	}
	return nil
}

// shouldReclaim decides the fate of one claim.
func (r *Reaper) shouldReclaim(claim *coordinationv1.Lease, mesh *wirekubev1alpha1.WireKubeMesh, holders map[string]struct{}) (string, bool) {
	address := claim.Annotations[meshalloc.AddressAnnotation]
	if mesh == nil {
		return "the mesh it was claimed in no longer exists", true
	}
	if address == "" || !meship.Contains(address, mesh.Spec.MeshCIDR) {
		// The CIDR moved or shrank under the claim. The address can never be
		// handed out again, so holding it serves nobody — and the peer that
		// held it has already been renumbered by the allocator.
		return fmt.Sprintf("%s is outside the mesh CIDR %s", address, mesh.Spec.MeshCIDR), true
	}

	holder := ""
	if claim.Spec.HolderIdentity != nil {
		holder = *claim.Spec.HolderIdentity
	}
	if holder == "" {
		return "it names no holder", true
	}
	if _, ok := holders[holder]; ok {
		delete(r.orphanedSince, claim.Name)
		return "", false
	}

	// No peer holds it. Give the holder the grace period to appear: an
	// enrolment claims the address before the machine that will advertise it
	// has finished booting.
	since := r.orphanedAt(claim)
	grace := r.grace(claim)
	if r.now().Sub(since) < grace {
		return "", false
	}
	return fmt.Sprintf("no peer named %q has existed for %s", holder, grace), true
}

// orphanedAt is when this claim started looking orphaned: the later of when it
// was created and when this process first saw it without a peer. Taking the
// later of the two gives a claim created seconds ago the full grace period
// even on a leader that has been running for days, and gives a long-standing
// claim whose peer just vanished the full grace period too.
func (r *Reaper) orphanedAt(claim *coordinationv1.Lease) time.Time {
	if r.orphanedSince == nil {
		r.orphanedSince = map[string]time.Time{}
	}
	seen, ok := r.orphanedSince[claim.Name]
	if !ok {
		seen = r.now()
		r.orphanedSince[claim.Name] = seen
	}
	if created := claim.CreationTimestamp.Time; created.After(seen) {
		return created
	}
	return seen
}

// grace is how long this claim may stay unheld. A creator that knows its
// enrolment is slow says so in spec.leaseDurationSeconds, which is the field's
// ordinary meaning: how long the claim is good for without being renewed.
func (r *Reaper) grace(claim *coordinationv1.Lease) time.Duration {
	if seconds := claim.Spec.LeaseDurationSeconds; seconds != nil && *seconds > 0 {
		return time.Duration(*seconds) * time.Second
	}
	if r.Grace > 0 {
		return r.Grace
	}
	return DefaultGrace
}

func (r *Reaper) reclaim(ctx context.Context, claim *coordinationv1.Lease, reason string) error {
	uid := claim.UID
	err := r.Client.Delete(ctx, claim, client.Preconditions{UID: &uid})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		// Somebody else got there first, or the claim was replaced between
		// the list and the delete. Either way it is not ours to chase.
		return nil
	}
	if err != nil {
		return err
	}
	delete(r.orphanedSince, claim.Name)
	r.Log.Info("reclaimed mesh address claim",
		"claim", claim.Name,
		"address", claim.Annotations[meshalloc.AddressAnnotation],
		"reason", reason)
	return nil
}

// peerNames is every name that can legitimately hold a claim: cluster peers
// and external peers alike.
func (r *Reaper) peerNames(ctx context.Context) (map[string]struct{}, error) {
	peers := &wirekubev1alpha1.WireKubePeerList{}
	if err := r.Client.List(ctx, peers); err != nil {
		return nil, fmt.Errorf("list WireKubePeer: %w", err)
	}
	names := make(map[string]struct{}, len(peers.Items))
	for i := range peers.Items {
		names[peers.Items[i].Name] = struct{}{}
	}

	external := &wirekubev1alpha1.WireKubeExternalPeerList{}
	if err := r.Client.List(ctx, external); err != nil {
		return nil, fmt.Errorf("list WireKubeExternalPeer: %w", err)
	}
	for i := range external.Items {
		peer := &external.Items[i]
		names[peer.Name] = struct{}{}
		// The reconciler allocates under the display name, which is what the
		// address is derived from and therefore what holds the claim.
		if peer.Spec.DisplayName != "" {
			names[peer.Spec.DisplayName] = struct{}{}
		}
	}
	return names, nil
}

func (r *Reaper) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func findMesh(meshes []wirekubev1alpha1.WireKubeMesh, name string) *wirekubev1alpha1.WireKubeMesh {
	for i := range meshes {
		if meshes[i].Name == name {
			return &meshes[i]
		}
	}
	return nil
}
