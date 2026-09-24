package external

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/meship"
)

// FinalizerName is added to every WireKubeExternalPeer the reconciler owns so
// cleanup can run before the CR is removed from etcd.
const FinalizerName = "wirekube.io/external-peer-finalizer"

// Standard requeue cadences. Pending phases re-check on a short cycle so
// transient gaps (mesh CR not yet present, ingress peer not yet ready) clear
// quickly. Active phases need re-reconciliation only on TTL boundaries
// or external CR edits, so requeue is omitted unless TTL is set.
const (
	requeueShort = 15 * time.Second
	requeueLong  = 30 * time.Second
)

const (
	ingressLoadPenalty      = 50 * time.Millisecond
	unknownRelayRTTPenalty  = 30 * time.Second
	ingressProbeCallTimeout = 5 * time.Second
)

// Status condition types and reasons. Reasons are stable strings so they
// can be asserted on by tests and surfaced in dashboards. The Type stays
// a single "Ready" condition — additional types can be added later
// without breaking consumers that only watch Ready.
const (
	conditionReady = "Ready"

	reasonReconciled            = "Reconciled"
	reasonValidationFailed      = "ValidationFailed"
	reasonInvalidPublicKey      = "InvalidPublicKey"
	reasonMeshNotFound          = "MeshNotFound"
	reasonIngressPeerNotReady   = "IngressPeerNotReady"
	reasonIngressProbeFailed    = "IngressProbeFailed"
	reasonNoReadyIngressPeer    = "NoReadyIngressPeer"
	reasonRelayEndpointNotReady = "RelayEndpointNotReady"
)

// Reconciler reconciles WireKubeExternalPeer objects. It is platform-
// agnostic and depends only on the K8s client, a RelayController, and a
// clock function injected for tests.
//
// Behaviour summary:
//   - validates spec (displayName + 32-byte base64 publicKey).
//   - allocates a deterministic /32 from WireKubeMesh.spec.meshCIDR via
//     pkg/meship.
//   - picks an ingress WireKubePeer (pinned via spec.ingressPeer or
//     auto-selected from ready WireKubePeers) and resolves its pubkey.
//   - writes the relay shared raw-WireGuard endpoint into status.
//   - on deletion, removes the finalizer.
//   - on TTL expiry, deletes the CR.
type Reconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Relay         RelayController
	RelayResolver func(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh) RelayController
	// APIReader performs uncached reads for resource kinds that may not
	// exist on the cluster at all. ServiceCIDR is served only by newer
	// API servers, and reading an absent kind through the manager's cache
	// starts an informer that can never sync, stalling the reconcile.
	// Production callers set mgr.GetAPIReader(); when nil, Client is used.
	APIReader client.Reader
	// Now is injectable for deterministic TTL tests; production callers
	// leave it nil and the reconciler falls back to time.Now.
	Now func() time.Time
}

// SetupWithManager registers the reconciler with controller-runtime. It
// is intentionally separate from the constructor so the test suite can
// instantiate the reconciler without a manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Default the uncached reader here so no manager-registered caller can
	// forget it: reading an unserved kind through the cache starts an informer
	// that never syncs, which would hang the reconcile rather than fail it.
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubeExternalPeer{}).
		// status.allowedDestinations is derived from Nodes and gateways, and
		// an Active peer is otherwise never requeued. Without these watches a
		// node joining or a gateway being created would leave every issued
		// peer's rendered conf stale indefinitely.
		Watches(&corev1.Node{},
			r.enqueueAllExternalPeers(),
			builder.WithPredicates(nodePodCIDRChanged())).
		Watches(&wirekubev1alpha1.WireKubeGateway{},
			r.enqueueAllExternalPeers(),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// spec.meshCIDR and spec.serviceCIDRs both feed the derived list.
		Watches(&wirekubev1alpha1.WireKubeMesh{},
			r.enqueueAllExternalPeers(),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// enqueueAllExternalPeers maps an event on a derived-from resource to every
// WireKubeExternalPeer, since the defaults are cluster-wide rather than
// per-peer. Reconcile is cheap and idempotent when nothing actually changed:
// activeStatusMatches short-circuits before any write.
func (r *Reconciler) enqueueAllExternalPeers() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		list := &wirekubev1alpha1.WireKubeExternalPeerList{}
		if err := r.List(ctx, list); err != nil {
			return nil
		}
		requests := make([]reconcile.Request, 0, len(list.Items))
		for i := range list.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: list.Items[i].Name},
			})
		}
		return requests
	})
}

// nodePodCIDRChanged limits Node events to the ones that can move a pod CIDR.
// Node objects update every few seconds for status heartbeats, and enqueuing
// every external peer on each of those would be a reconcile storm. Update is
// still watched rather than dropped outright because kubelet registers a Node
// before the IPAM controller writes spec.podCIDR, so the CIDR usually arrives
// as an update rather than at creation.
func nodePodCIDRChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, oldOK := e.ObjectOld.(*corev1.Node)
			newNode, newOK := e.ObjectNew.(*corev1.Node)
			if !oldOK || !newOK {
				return false
			}
			return oldNode.Spec.PodCIDR != newNode.Spec.PodCIDR ||
				!slices.Equal(oldNode.Spec.PodCIDRs, newNode.Spec.PodCIDRs)
		},
	}
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) relayForMesh(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh) RelayController {
	if r.RelayResolver != nil {
		if relay := r.RelayResolver(ctx, mesh); relay != nil {
			return relay
		}
	}
	if r.Relay != nil {
		return r.Relay
	}
	return NewNoopRelayController("")
}

func (r *Reconciler) relayForCurrentMesh(ctx context.Context) (RelayController, error) {
	if r.RelayResolver == nil {
		return r.relayForMesh(ctx, nil), nil
	}
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if err := r.List(ctx, meshList); err != nil {
		return nil, fmt.Errorf("list WireKubeMesh for relay controller: %w", err)
	}
	if len(meshList.Items) == 0 {
		return r.relayForMesh(ctx, nil), nil
	}
	return r.relayForMesh(ctx, &meshList.Items[0]), nil
}

// Reconcile implements reconcile.Reconciler. It is structured as a single
// straight-line function so the ordering required by the plan (delete
// path → finalizer add → validation → allocation → status patch → TTL)
// is obvious from top to bottom.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := r.Get(ctx, req.NamespacedName, cr); err != nil {
		// Already deleted: nothing to do, no requeue.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 1. Deletion path.
	if cr.DeletionTimestamp != nil {
		return r.handleDeletion(ctx, cr)
	}

	// 2. Finalizer add.
	if !hasFinalizer(cr, FinalizerName) {
		cr.Finalizers = append(cr.Finalizers, FinalizerName)
		if err := r.Update(ctx, cr); err != nil {
			return ctrl.Result{}, err
		}
		// Requeue so the freshly read object (with the finalizer
		// observed) is the one we mutate status on.
		return ctrl.Result{Requeue: true}, nil
	}

	// 3. Validation.
	if cr.Spec.DisplayName == "" {
		return r.failValidation(ctx, cr, reasonValidationFailed, "spec.displayName is required")
	}
	if cr.Spec.PublicKey == "" {
		return r.failValidation(ctx, cr, reasonValidationFailed, "spec.publicKey is required")
	}
	if _, err := decodeWGKey(cr.Spec.PublicKey); err != nil {
		return r.failValidation(ctx, cr, reasonInvalidPublicKey, err.Error())
	}

	// 4. Read singleton WireKubeMesh.
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if err := r.List(ctx, meshList); err != nil {
		return ctrl.Result{}, fmt.Errorf("list WireKubeMesh: %w", err)
	}
	if len(meshList.Items) == 0 {
		return r.markPending(ctx, cr, reasonMeshNotFound, "no WireKubeMesh found", requeueShort)
	}
	mesh := &meshList.Items[0]
	relayCtl := r.relayForMesh(ctx, mesh)
	if relayCtl.RelayEndpoint() == "" {
		return r.markPending(ctx, cr, reasonRelayEndpointNotReady,
			"relay public endpoint is not ready; waiting before publishing external peer endpoint",
			requeueShort)
	}

	// 5. Deterministic /32 allocation.
	meshIP, err := meship.IPForName(cr.Spec.DisplayName, mesh.Spec.MeshCIDR)
	if err != nil {
		return r.failValidation(ctx, cr, reasonValidationFailed,
			fmt.Sprintf("compute mesh IP: %v", err))
	}

	// 6. Ingress peer pick.
	ingressPeerName, ingressPubKey, pendingResult, pendingErr, picked := r.pickIngressPeer(ctx, cr, relayCtl)
	if !picked {
		// pendingResult / pendingErr already set status; bubble up.
		return pendingResult, pendingErr
	}

	// 7. Resolve effective AllowedDestinations.
	//
	// If the operator set spec.allowedDestinations explicitly we honour it
	// verbatim (operator knows what they want — e.g. a narrow /24 carve-out
	// for contractor access). Otherwise we default to the mesh overlay CIDR,
	// every Node's pod CIDR(s), the Service ClusterIP range(s) and every
	// gateway route, so the rendered conf actually routes cluster traffic
	// through the ingress peer instead of leaving the client with a single
	// /32 self-route.
	allowed, destinationsDegraded, err := r.effectiveAllowedDestinations(ctx, cr, mesh, ingressPeerName)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("compute allowed destinations: %w", err)
	}

	// 8. Status patch — Active.
	//
	// External peers use the relay's shared raw-WireGuard UDP endpoint, not a
	// per-peer UDP forwarder port. The relay fans initial packets into the
	// connected ingress agents and then learns the answering ingress by source
	// token; wireguard-go on the selected ingress authenticates the actual peer.
	relayEndpoint := relayCtl.RelayEndpoint()
	if err := r.patchActiveStatus(ctx, cr, statusUpdate{
		assignedMeshIP:      meshIP,
		relayPort:           0,
		relayEndpoint:       relayEndpoint,
		publicKey:           cr.Spec.PublicKey,
		ingressPeerName:     ingressPeerName,
		ingressPublicKey:    base64.StdEncoding.EncodeToString(ingressPubKey[:]),
		allowedDestinations: allowed,
		mtu:                 effectiveMTU(cr),
	}); err != nil {
		return ctrl.Result{}, err
	}

	// 9. TTL handling.
	if cr.Spec.TTL != nil && cr.Spec.TTL.Duration > 0 {
		expiry := cr.CreationTimestamp.Time.Add(cr.Spec.TTL.Duration)
		now := r.now()
		if !now.Before(expiry) {
			if err := r.Delete(ctx, cr); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		requeue := expiry.Sub(now)
		// A degraded read has no watch event to bring it back, so retry
		// sooner than the TTL deadline when that lands first.
		if destinationsDegraded && requeueLong < requeue {
			requeue = requeueLong
		}
		return ctrl.Result{RequeueAfter: requeue}, nil
	}

	if destinationsDegraded {
		return ctrl.Result{RequeueAfter: requeueLong}, nil
	}
	return ctrl.Result{}, nil
}

// statusUpdate captures every field patched on the Active path. Grouping
// them keeps the patch site small and lets the test suite reason about
// the exact intended write.
type statusUpdate struct {
	assignedMeshIP      string
	relayPort           int32
	relayEndpoint       string
	publicKey           string
	ingressPeerName     string
	ingressPublicKey    string
	allowedDestinations []string
	mtu                 int32
}

// pickIngressPeer returns (peerName, peerPubKey, requeue, err, ok).
// ok=false indicates the caller should return the pending values. ok=true
// means the selected ingress peer and its public key are populated.
func (r *Reconciler) pickIngressPeer(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, relayCtl RelayController) (string, [32]byte, ctrl.Result, error, bool) {
	var zero [32]byte

	// Official WireGuard clients pin the server public key in their config.
	// Once an ingress peer has been allocated, keep using it until the external
	// peer is re-issued instead of silently migrating to another node.
	if cr.Status.IngressPeerName != "" {
		return r.resolveNamedIngressPeer(ctx, cr, cr.Status.IngressPeerName, "status.ingressPeerName", relayCtl)
	}

	if cr.Spec.IngressPeer != "" {
		return r.resolveNamedIngressPeer(ctx, cr, cr.Spec.IngressPeer, "spec.ingressPeer", relayCtl)
	}

	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := r.List(ctx, peerList); err != nil {
		return "", zero, ctrl.Result{}, fmt.Errorf("list WireKubePeer: %w", err), false
	}
	load, err := r.activeIngressLoad(ctx, cr.Name)
	if err != nil {
		return "", zero, ctrl.Result{}, err, false
	}
	latencies, probed, probeErr := r.probeIngressLatencies(ctx, relayCtl, peerList)
	if probeErr != nil {
		res, retErr := r.markPending(ctx, cr, reasonIngressProbeFailed,
			fmt.Sprintf("relay ingress probe failed: %v", probeErr), requeueShort)
		return "", zero, res, retErr, false
	}

	// Heartbeats are the only signal that survives a node whose agent stopped:
	// Status.Connected freezes at its last value, and the WireKubePeer CR
	// outlives a NotReady node because ownerReference GC only fires on Node
	// deletion. Without this filter an abandoned peer stays a candidate, and
	// since every candidate scores the same when no relay latency is known,
	// the tie-break falls through to name ordering — which is how a dead node
	// alphabetically ahead of the live ones wins and every client bound to it
	// silently fails to hand shake.
	liveByName := freshlyReportedPeers(peerList, r.now())

	candidates := make([]ingressCandidate, 0, len(peerList.Items))
	for i := range peerList.Items {
		peer := &peerList.Items[i]
		pubKey, ok, err := decodeIngressPeerPubKey(peer)
		if err != nil {
			return "", zero, ctrl.Result{}, err, false
		}
		if !ok {
			continue
		}
		// Only enforced once some peer publishes a heartbeat. A fleet still
		// running agents that predate the field reports nothing at all, and
		// excluding everyone there would strand external peers that work
		// today.
		if len(liveByName) > 0 && !liveByName[peer.Name] {
			continue
		}
		latency, reachable := latencies[pubKey]
		if probed && !reachable {
			continue
		}
		if !reachable && peer.Status.RelayLatencyMs > 0 {
			latency = time.Duration(peer.Status.RelayLatencyMs) * time.Millisecond
			reachable = true
		}
		if !reachable {
			latency = unknownRelayRTTPenalty
		}
		candidates = append(candidates, ingressCandidate{
			name:    peer.Name,
			pubKey:  pubKey,
			load:    load[peer.Name],
			latency: latency,
			score:   latency + time.Duration(load[peer.Name])*ingressLoadPenalty,
		})
	}
	if len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].score != candidates[j].score {
				return candidates[i].score < candidates[j].score
			}
			if candidates[i].load != candidates[j].load {
				return candidates[i].load < candidates[j].load
			}
			if candidates[i].latency != candidates[j].latency {
				return candidates[i].latency < candidates[j].latency
			}
			return candidates[i].name < candidates[j].name
		})
		best := candidates[0]
		return best.name, best.pubKey, ctrl.Result{}, nil, true
	}

	msg := "no ready WireKubePeer with a usable publicKey found"
	if probed {
		msg = "no ready WireKubePeer reachable from every relay replica"
	}
	res, retErr := r.markPending(ctx, cr, reasonNoReadyIngressPeer,
		msg, requeueLong)
	return "", zero, res, retErr, false
}

type ingressCandidate struct {
	name    string
	pubKey  [32]byte
	load    int
	latency time.Duration
	score   time.Duration
}

// ingressHeartbeatThreshold is how stale a peer's self-reported timestamp may
// get before it stops being eligible to front external clients. Agents refresh
// it every sync (30s by default), so this tolerates ten missed writes. Picking
// a dead ingress is worse than picking a slow one — the client pins the ingress
// public key in its config, so the mistake persists until the peer is re-issued.
const ingressHeartbeatThreshold = 5 * time.Minute

// freshlyReportedPeers returns the set of peers whose agent has published a
// heartbeat recently. An empty result means no peer reports one at all, which
// callers must treat as "no information" rather than "everyone is dead".
func freshlyReportedPeers(peerList *wirekubev1alpha1.WireKubePeerList, now time.Time) map[string]bool {
	live := map[string]bool{}
	for i := range peerList.Items {
		peer := &peerList.Items[i]
		if peer.Status.LastReportedAt == nil {
			continue
		}
		if now.Sub(peer.Status.LastReportedAt.Time) < ingressHeartbeatThreshold {
			live[peer.Name] = true
		}
	}
	return live
}

func (r *Reconciler) resolveNamedIngressPeer(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, peerName, source string, relayCtl RelayController) (string, [32]byte, ctrl.Result, error, bool) {
	var zero [32]byte
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := r.Get(ctx, types.NamespacedName{Name: peerName}, peer); err != nil {
		if apierrors.IsNotFound(err) {
			res, retErr := r.markPending(ctx, cr, reasonIngressPeerNotReady,
				fmt.Sprintf("%s WireKubePeer %q not found", source, peerName), requeueShort)
			return "", zero, res, retErr, false
		}
		return "", zero, ctrl.Result{}, fmt.Errorf("get WireKubePeer %q: %w", peerName, err), false
	}
	pubKey, ok, err := decodeIngressPeerPubKey(peer)
	if err != nil {
		return "", zero, ctrl.Result{}, err, false
	}
	if !ok {
		res, retErr := r.markPending(ctx, cr, reasonIngressPeerNotReady,
			fmt.Sprintf("%s WireKubePeer %q has no usable publicKey yet", source, peerName), requeueShort)
		return "", zero, res, retErr, false
	}
	if prober, ok := relayCtl.(IngressLatencyProber); ok {
		probeCtx, cancel := context.WithTimeout(ctx, ingressProbeCallTimeout)
		defer cancel()
		got, err := prober.ProbeIngressLatency(probeCtx, [][32]byte{pubKey})
		if err != nil {
			if errors.Is(err, ErrIngressProbeDisabled) {
				return peerName, pubKey, ctrl.Result{}, nil, true
			}
			res, retErr := r.markPending(ctx, cr, reasonIngressProbeFailed,
				fmt.Sprintf("relay ingress probe failed: %v", err), requeueShort)
			return "", zero, res, retErr, false
		}
		if _, ok := got[pubKey]; !ok {
			res, retErr := r.markPending(ctx, cr, reasonIngressPeerNotReady,
				fmt.Sprintf("%s WireKubePeer %q is not reachable from every relay replica", source, peerName), requeueShort)
			return "", zero, res, retErr, false
		}
	}
	return peerName, pubKey, ctrl.Result{}, nil, true
}

func (r *Reconciler) activeIngressLoad(ctx context.Context, currentName string) (map[string]int, error) {
	out := make(map[string]int)
	externalList := &wirekubev1alpha1.WireKubeExternalPeerList{}
	if err := r.List(ctx, externalList); err != nil {
		return nil, fmt.Errorf("list WireKubeExternalPeer for ingress load: %w", err)
	}
	for i := range externalList.Items {
		ep := &externalList.Items[i]
		if ep.Name == currentName {
			continue
		}
		if ep.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
			continue
		}
		if ep.Status.IngressPeerName == "" {
			continue
		}
		out[ep.Status.IngressPeerName]++
	}
	return out, nil
}

func (r *Reconciler) probeIngressLatencies(ctx context.Context, relayCtl RelayController, peerList *wirekubev1alpha1.WireKubePeerList) (map[[32]byte]time.Duration, bool, error) {
	prober, ok := relayCtl.(IngressLatencyProber)
	if !ok {
		return nil, false, nil
	}
	keys := make([][32]byte, 0, len(peerList.Items))
	for i := range peerList.Items {
		key, ok, err := decodeIngressPeerPubKey(&peerList.Items[i])
		if err != nil {
			return nil, true, err
		}
		if ok {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return map[[32]byte]time.Duration{}, true, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, ingressProbeCallTimeout)
	defer cancel()
	got, err := prober.ProbeIngressLatency(probeCtx, keys)
	if err != nil {
		if errors.Is(err, ErrIngressProbeDisabled) {
			return nil, false, nil
		}
		return nil, true, err
	}
	return got, true, nil
}

// decodeIngressPeerPubKey returns a WireKubePeer's decoded 32-byte WireGuard
// public key. ok=false means the peer exists but its publicKey field is empty
// or malformed, which happens transiently when an agent has not yet published
// its key.
func decodeIngressPeerPubKey(peer *wirekubev1alpha1.WireKubePeer) ([32]byte, bool, error) {
	var zero [32]byte
	if peer.Spec.PublicKey == "" {
		return zero, false, nil
	}
	pubKey, err := decodeWGKey(peer.Spec.PublicKey)
	if err != nil {
		// Treat malformed ingress pubkey as transient (not a CR
		// validation failure on the external peer).
		return zero, false, nil
	}
	return pubKey, true, nil
}

// decodeWGKey decodes a base64 WireGuard pubkey and returns the 32-byte
// fixed array form expected by the relay protocol.
func decodeWGKey(s string) ([32]byte, error) {
	var key [32]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("publicKey is not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("publicKey must decode to 32 bytes, got %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// handleDeletion removes the finalizer. It keeps the old relay-forwarder
// cleanup path for CRs created by earlier versions that still carry a
// status.relayPort allocation.
func (r *Reconciler) handleDeletion(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer) (ctrl.Result, error) {
	if !hasFinalizer(cr, FinalizerName) {
		// Foreign owner finished cleanup; nothing to do.
		return ctrl.Result{}, nil
	}
	if cr.Status.RelayPort != 0 {
		relayCtl, err := r.relayForCurrentMesh(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		if err := relayCtl.UnregisterForwarder(ctx, uint16(cr.Status.RelayPort)); err != nil {
			if !errors.Is(err, ErrNotImplemented) {
				return ctrl.Result{}, fmt.Errorf("unregister forwarder on delete: %w", err)
			}
		}
	}
	cr.Finalizers = removeString(cr.Finalizers, FinalizerName)
	if err := r.Update(ctx, cr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// failValidation transitions the CR to phase=Failed with the given
// reason. No requeue: validation failures are user-fixable and a watch
// will re-trigger when the spec is corrected.
func (r *Reconciler) failValidation(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, reason, msg string) (ctrl.Result, error) {
	patch := client.MergeFrom(cr.DeepCopy())
	cr.Status.Phase = wirekubev1alpha1.ExternalPeerPhaseFailed
	setCondition(&cr.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: metav1.NewTime(r.now()),
	})
	if err := r.Status().Patch(ctx, cr, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// markPending transitions the CR to phase=Pending with the given reason
// and requeues after the given duration. Used for any transient gap that
// the reconciler expects to clear without operator intervention (mesh CR
// not yet present or no ready ingress peer).
func (r *Reconciler) markPending(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, reason, msg string, requeue time.Duration) (ctrl.Result, error) {
	patch := client.MergeFrom(cr.DeepCopy())
	cr.Status.Phase = wirekubev1alpha1.ExternalPeerPhasePending
	setCondition(&cr.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: metav1.NewTime(r.now()),
	})
	if err := r.Status().Patch(ctx, cr, patch); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// patchActiveStatus writes the populated allocation result. Connected and
// LastHandshake are intentionally NOT touched here; the allocator does not
// observe live WireGuard handshakes.
func (r *Reconciler) patchActiveStatus(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, u statusUpdate) error {
	if activeStatusMatches(cr, u) {
		return nil
	}
	patch := client.MergeFrom(cr.DeepCopy())
	cr.Status.AssignedMeshIP = u.assignedMeshIP
	cr.Status.RelayPort = u.relayPort
	cr.Status.RelayEndpoint = u.relayEndpoint
	cr.Status.PublicKey = u.publicKey
	cr.Status.IngressPeerName = u.ingressPeerName
	cr.Status.IngressPublicKey = u.ingressPublicKey
	cr.Status.AllowedDestinations = u.allowedDestinations
	cr.Status.MTU = u.mtu
	cr.Status.Phase = wirekubev1alpha1.ExternalPeerPhaseActive
	setCondition(&cr.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             reasonReconciled,
		Message:            "external peer is allocated and bound to ingress peer",
		LastTransitionTime: metav1.NewTime(r.now()),
	})
	return r.Status().Patch(ctx, cr, patch)
}

func activeStatusMatches(cr *wirekubev1alpha1.WireKubeExternalPeer, u statusUpdate) bool {
	if cr.Status.AssignedMeshIP != u.assignedMeshIP ||
		cr.Status.RelayPort != u.relayPort ||
		cr.Status.RelayEndpoint != u.relayEndpoint ||
		cr.Status.PublicKey != u.publicKey ||
		cr.Status.IngressPeerName != u.ingressPeerName ||
		cr.Status.IngressPublicKey != u.ingressPublicKey ||
		cr.Status.MTU != u.mtu ||
		cr.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive ||
		!slices.Equal(cr.Status.AllowedDestinations, u.allowedDestinations) {
		return false
	}
	for _, c := range cr.Status.Conditions {
		if c.Type == conditionReady {
			return c.Status == metav1.ConditionTrue && c.Reason == reasonReconciled
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func effectiveMTU(cr *wirekubev1alpha1.WireKubeExternalPeer) int32 {
	if cr != nil && cr.Spec.MTU > 0 {
		return cr.Spec.MTU
	}
	return wirekubev1alpha1.DefaultExternalPeerMTU
}

// effectiveAllowedDestinations resolves the AllowedIPs list rendered into
// the external peer's WireGuard conf. When the operator set
// spec.allowedDestinations explicitly we honour it verbatim. Otherwise we
// build a sane default so the peer reaches the same cluster through the
// ingress peer that an in-cluster peer reaches:
//
//   - the mesh overlay CIDR,
//   - every Node's pod CIDR(s),
//   - the Service ClusterIP range(s), pinned by WireKubeMesh.spec.serviceCIDRs
//     or discovered from the cluster's ServiceCIDR objects,
//   - every WireKubeGateway route, so an external peer reaches the
//     off-cluster networks (VPCs, private links) that gateways carry.
//
// Without this defaulting the conf would only carry the peer's own /32 and
// the WireGuard client would install no routes for cluster destinations.
//
// A source that cannot be read is skipped rather than failing issuance, so a
// first-time peer still gets a conf that reaches most of the cluster. It must
// not, however, narrow a peer that already has destinations: the rendered conf
// is read back from status, so dropping a range because the apiserver blipped
// would hand the next downloader a conf that silently stops routing it. When
// any source failed and status already holds a list, that list is kept.
//
// The second return reports that a read failed. A failed read produces no
// watch event of its own, so the caller must requeue or the peer would hold
// the preserved list until something unrelated happens to trigger it.
//
// The derived list is sorted because Node, ServiceCIDR and gateway listings
// arrive in arbitrary order while status.allowedDestinations is compared with
// slices.Equal — an unsorted list would rewrite status on every reconcile. An
// explicit spec list keeps the operator's own order.
func (r *Reconciler) effectiveAllowedDestinations(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, mesh *wirekubev1alpha1.WireKubeMesh, ingressPeerName string) ([]string, bool, error) {
	if len(cr.Spec.AllowedDestinations) > 0 {
		return slices.Clone(cr.Spec.AllowedDestinations), false, nil
	}

	out := make([]string, 0, 8)
	seen := make(map[string]struct{})
	add := func(cidr string) {
		if cidr == "" {
			return
		}
		if _, ok := seen[cidr]; ok {
			return
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}

	if mesh != nil {
		add(mesh.Spec.MeshCIDR)
	}

	degraded := false

	nodeList := &corev1.NodeList{}
	if err := r.List(ctx, nodeList); err != nil {
		degraded = true
	} else {
		for i := range nodeList.Items {
			n := &nodeList.Items[i]
			for _, c := range n.Spec.PodCIDRs {
				add(c)
			}
			add(n.Spec.PodCIDR)
		}
	}

	serviceCIDRs, serviceCIDRsResolved := r.serviceCIDRs(ctx, mesh)
	if !serviceCIDRsResolved {
		degraded = true
	}
	for _, c := range serviceCIDRs {
		add(c)
	}

	gatewayList := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := r.List(ctx, gatewayList); err != nil {
		degraded = true
	} else {
		for i := range gatewayList.Items {
			gateway := &gatewayList.Items[i]
			if !gatewayServesPeer(gateway, ingressPeerName) {
				continue
			}
			for _, route := range gateway.Spec.Routes {
				add(route.CIDR)
			}
		}
	}

	sort.Strings(out)

	if degraded && len(cr.Status.AllowedDestinations) > 0 {
		return slices.Clone(cr.Status.AllowedDestinations), true, nil
	}
	return out, degraded, nil
}

// gatewayServesPeer reports whether the ingress peer would actually hold a
// kernel route for this gateway. An agent skips installing a gateway route on
// a node that a non-empty clientRefs list excludes (see shouldSkipGatewayRoute
// in pkg/agent/gateway.go), so advertising such a route to the external client
// would point it at an ingress that blackholes the traffic — strictly worse
// than leaving the destination off the tunnel.
//
// The elected gateway peer is served even though clientRefs normally omits it:
// it carries the routes natively (collectGatewayCIDRsForPeer), so an external
// peer that entered through the gateway node must not lose the route it is
// sitting on. A standby in peerRefs is not served — only the elected peer has
// the routes injected, so advertising through a standby would blackhole until
// it happens to be elected.
func gatewayServesPeer(gateway *wirekubev1alpha1.WireKubeGateway, peerName string) bool {
	if len(gateway.Spec.ClientRefs) == 0 {
		return true
	}
	return slices.Contains(gateway.Spec.ClientRefs, peerName) ||
		(gateway.Status.ActivePeer != "" && gateway.Status.ActivePeer == peerName)
}

// serviceCIDRGroupVersions are the API group/versions that have carried
// ServiceCIDR, newest first. The kind graduated v1alpha1 -> v1beta1 -> v1
// across releases, and k8s.io/api at the version this module builds against
// only contains the v1alpha1 Go type, so the object is read unstructured and
// the first group/version the server actually serves wins.
var serviceCIDRGroupVersions = []string{
	"networking.k8s.io/v1",
	"networking.k8s.io/v1beta1",
	"networking.k8s.io/v1alpha1",
}

// serviceCIDRs returns the Service ClusterIP ranges to advertise to external
// peers. An explicit WireKubeMesh.spec.serviceCIDRs wins so operators can
// pin a range on servers that do not serve ServiceCIDR at all.
// The second return reports whether the answer is trustworthy. A cluster that
// serves no ServiceCIDR group version resolves to (nil, true): that is a
// stable property, not a failed read. A Forbidden or transient error resolves
// to (nil, false) so the caller keeps whatever the peer already had.
func (r *Reconciler) serviceCIDRs(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh) ([]string, bool) {
	if mesh != nil && len(mesh.Spec.ServiceCIDRs) > 0 {
		return slices.Clone(mesh.Spec.ServiceCIDRs), true
	}
	return r.discoverServiceCIDRs(ctx)
}

// discoverServiceCIDRs reads the cluster's ServiceCIDR objects. A server that
// serves none of the known group/versions, or an agent whose RBAC omits the
// resource, yields nil and the peer is issued without ClusterIP reachability.
func (r *Reconciler) discoverServiceCIDRs(ctx context.Context) ([]string, bool) {
	resolved := true
	for _, gv := range serviceCIDRGroupVersions {
		list := &unstructured.UnstructuredList{}
		list.SetAPIVersion(gv)
		list.SetKind("ServiceCIDRList")
		if err := r.reader().List(ctx, list); err != nil {
			// A kind the server does not serve is the expected answer on an
			// older cluster and says nothing is wrong. Anything else — most
			// often a ClusterRole that was never reapplied — is a failed read
			// that must not be mistaken for "this cluster has no Services".
			if !serviceCIDRKindAbsent(err) {
				resolved = false
				logger := ctrl.LoggerFrom(ctx)
				if apierrors.IsForbidden(err) {
					logger.Info("not authorized to list ServiceCIDR; external peers will not learn the Service ClusterIP range",
						"apiVersion", gv, "err", err,
						"hint", "grant networking.k8s.io/servicecidrs to the agent ClusterRole or set WireKubeMesh.spec.serviceCIDRs")
				} else {
					logger.V(1).Info("listing ServiceCIDR failed", "apiVersion", gv, "err", err)
				}
			}
			continue
		}
		// This group/version is served; whatever it holds is authoritative,
		// including nothing at all. Do not fall through to an older one.
		out := make([]string, 0, len(list.Items))
		for i := range list.Items {
			item := &list.Items[i]
			if !serviceCIDRIsReady(item) {
				continue
			}
			cidrs, found, err := unstructured.NestedStringSlice(item.Object, "spec", "cidrs")
			if err != nil || !found {
				continue
			}
			out = append(out, cidrs...)
		}
		return out, true
	}
	return nil, resolved
}

// serviceCIDRKindAbsent reports whether the error means the server simply does
// not serve ServiceCIDR at this group/version, as opposed to a read that ought
// to have worked.
func serviceCIDRKindAbsent(err error) bool {
	return meta.IsNoMatchError(err) || apierrors.IsNotFound(err)
}

// serviceCIDRIsReady reports whether a ServiceCIDR is usable. A terminating
// range reports Ready=False and must not be advertised. Objects that carry no
// conditions at all are taken at face value rather than dropped: that is the
// only range the cluster has.
func serviceCIDRIsReady(obj *unstructured.Unstructured) bool {
	conditions, found, err := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if err != nil || !found {
		return true
	}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if condition["type"] != "Ready" {
			continue
		}
		return condition["status"] == string(metav1.ConditionTrue)
	}
	return true
}

// reader returns the uncached reader. SetupWithManager always populates it, so
// the fallback only serves tests that construct the reconciler without a
// manager and pass a client that can answer for the kinds they exercise.
func (r *Reconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func hasFinalizer(cr *wirekubev1alpha1.WireKubeExternalPeer, name string) bool {
	return slices.Contains(cr.Finalizers, name)
}

func removeString(in []string, want string) []string {
	out := in[:0]
	for _, s := range in {
		if s == want {
			continue
		}
		out = append(out, s)
	}
	return out
}

// setCondition replaces an existing condition of the same Type or
// appends a new one. LastTransitionTime is only updated when the Status
// changes, mirroring meta.SetStatusCondition semantics without pulling
// in apimachinery/api/meta.
func setCondition(conds *[]metav1.Condition, c metav1.Condition) {
	for i, existing := range *conds {
		if existing.Type != c.Type {
			continue
		}
		if existing.Status == c.Status {
			c.LastTransitionTime = existing.LastTransitionTime
		}
		(*conds)[i] = c
		return
	}
	*conds = append(*conds, c)
}
