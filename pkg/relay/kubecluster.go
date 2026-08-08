package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Kubernetes-lease-backed PeerRegistry.
//
// Replicas already share exactly one dependable datastore: the apiserver.
// Each replica maintains one replica lease ("I exist, reach me here") and one
// lease per locally connected peer ("this pubkey's session is on me"), and
// polls both sets into a local cache. The data path reads only that cache;
// apiserver latency or an outage degrades freshness, never packet forwarding.
//
// Lease shape:
//
//	name        wirekube-relay-replica-<hex(sha256(relayID))[:16]>
//	            wirekube-relay-peer-<hex(sha256(peer pubkey))>
//	labels      wirekube.io/relay-registry: replica | peer
//	annotations wirekube.io/cluster-addr: <podIP:clusterPort>
//	holder      relayID
type KubeRegistry struct {
	client    kubernetes.Interface
	namespace string
	relayID   string
	selfAddr  string

	mu        sync.RWMutex
	published map[[PubKeySize]byte]bool
	peerAddrs map[string]string
	replicas  []string

	// spawn runs the opportunistic lease writes that Publish/Withdraw fire
	// off the caller's goroutine. Tests replace it with an inline runner so
	// lease state is deterministic; production uses `go`.
	spawn func(func())

	errLog *suppressedLogger
}

const (
	registryLabelKey     = "wirekube.io/relay-registry"
	registryAddrAnno     = "wirekube.io/cluster-addr"
	replicaLeasePrefix   = "wirekube-relay-replica-"
	peerLeasePrefix      = "wirekube-relay-peer-"
	registrySyncInterval = 10 * time.Second
	registryAPITimeout   = 5 * time.Second
	// registryStaleAfter is the age at which an unrenewed lease stops
	// counting. 4.5 sync intervals: a replica can miss a few renewals during
	// an apiserver hiccup without its peers vanishing from the mesh.
	registryStaleAfter = 45 * time.Second
)

func NewKubeRegistry(client kubernetes.Interface, namespace, relayID, selfAddr string) *KubeRegistry {
	return &KubeRegistry{
		client:    client,
		namespace: namespace,
		relayID:   relayID,
		selfAddr:  selfAddr,
		published: make(map[[PubKeySize]byte]bool),
		peerAddrs: make(map[string]string),
		spawn:     func(f func()) { go f() },
		errLog:    newSuppressedLogger(30 * time.Second),
	}
}

func (r *KubeRegistry) SelfAddr() string { return r.selfAddr }

func (r *KubeRegistry) PublishPeer(pubKey [PubKeySize]byte) {
	r.mu.Lock()
	r.published[pubKey] = true
	// Serve lookups for our own peers from the cache immediately instead of
	// waiting a sync round trip through the apiserver.
	r.peerAddrs[peerLeaseSuffix(pubKey)] = r.selfAddr
	r.mu.Unlock()
	// Push the lease now so sibling replicas learn about the peer in one
	// poll interval rather than two.
	r.spawn(func() {
		ctx, cancel := context.WithTimeout(context.Background(), registryAPITimeout)
		defer cancel()
		if err := r.ensureLease(ctx, peerLeasePrefix+peerLeaseSuffix(pubKey), "peer"); err != nil {
			r.errLog.Logf("relay cluster: publish peer lease %x: %v", pubKey[:8], err)
		}
	})
}

func (r *KubeRegistry) WithdrawPeer(pubKey [PubKeySize]byte) {
	r.mu.Lock()
	delete(r.published, pubKey)
	if r.peerAddrs[peerLeaseSuffix(pubKey)] == r.selfAddr {
		delete(r.peerAddrs, peerLeaseSuffix(pubKey))
	}
	r.mu.Unlock()
	r.spawn(func() {
		ctx, cancel := context.WithTimeout(context.Background(), registryAPITimeout)
		defer cancel()
		err := r.client.CoordinationV1().Leases(r.namespace).Delete(ctx, peerLeasePrefix+peerLeaseSuffix(pubKey), metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			r.errLog.Logf("relay cluster: withdraw peer lease %x: %v", pubKey[:8], err)
		}
	})
}

func (r *KubeRegistry) LookupPeer(pubKey [PubKeySize]byte) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	addr, ok := r.peerAddrs[peerLeaseSuffix(pubKey)]
	return addr, ok
}

func (r *KubeRegistry) Replicas() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.replicas))
	copy(out, r.replicas)
	return out
}

// Run renews this replica's leases and refreshes the lookup caches until the
// context is cancelled.
func (r *KubeRegistry) Run(ctx context.Context) {
	r.syncOnce(ctx)
	ticker := time.NewTicker(registrySyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.syncOnce(ctx)
		}
	}
}

func (r *KubeRegistry) syncOnce(ctx context.Context) {
	callCtx, cancel := context.WithTimeout(ctx, registryAPITimeout)
	defer cancel()

	if err := r.ensureLease(callCtx, replicaLeasePrefix+shortHash(r.relayID), "replica"); err != nil {
		r.errLog.Logf("relay cluster: renew replica lease: %v", err)
	}

	r.mu.RLock()
	published := make([][PubKeySize]byte, 0, len(r.published))
	for k := range r.published {
		published = append(published, k)
	}
	r.mu.RUnlock()
	for _, pubKey := range published {
		if err := r.ensureLease(callCtx, peerLeasePrefix+peerLeaseSuffix(pubKey), "peer"); err != nil {
			r.errLog.Logf("relay cluster: renew peer lease %x: %v", pubKey[:8], err)
		}
	}

	r.refreshReplicas(callCtx)
	r.refreshPeers(callCtx)
}

func (r *KubeRegistry) refreshReplicas(ctx context.Context) {
	list, err := r.client.CoordinationV1().Leases(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: registryLabelKey + "=replica",
	})
	if err != nil {
		r.errLog.Logf("relay cluster: list replica leases: %v", err)
		return
	}
	replicas := make([]string, 0, len(list.Items))
	for i := range list.Items {
		if addr, ok := freshLeaseAddr(&list.Items[i]); ok {
			replicas = append(replicas, addr)
		}
	}
	r.mu.Lock()
	r.replicas = replicas
	r.mu.Unlock()
}

func (r *KubeRegistry) refreshPeers(ctx context.Context) {
	list, err := r.client.CoordinationV1().Leases(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: registryLabelKey + "=peer",
	})
	if err != nil {
		r.errLog.Logf("relay cluster: list peer leases: %v", err)
		return
	}
	peers := make(map[string]string, len(list.Items))
	for i := range list.Items {
		lease := &list.Items[i]
		addr, ok := freshLeaseAddr(lease)
		if !ok {
			continue
		}
		peers[leaseSuffix(lease.Name, peerLeasePrefix)] = addr
	}
	// Locally connected peers stay routed to self even if their lease write
	// is still in flight or the apiserver is behind.
	r.mu.Lock()
	for pubKey := range r.published {
		peers[peerLeaseSuffix(pubKey)] = r.selfAddr
	}
	r.peerAddrs = peers
	r.mu.Unlock()
}

func (r *KubeRegistry) ensureLease(ctx context.Context, name, kind string) error {
	leases := r.client.CoordinationV1().Leases(r.namespace)
	now := metav1.NewMicroTime(time.Now())

	existing, err := leases.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := leases.Create(ctx, &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Labels:      map[string]string{registryLabelKey: kind},
				Annotations: map[string]string{registryAddrAnno: r.selfAddr},
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity: &r.relayID,
				RenewTime:      &now,
			},
		}, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[registryAddrAnno] = r.selfAddr
	existing.Spec.HolderIdentity = &r.relayID
	existing.Spec.RenewTime = &now
	_, err = leases.Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

func freshLeaseAddr(lease *coordinationv1.Lease) (string, bool) {
	if lease.Spec.RenewTime == nil || time.Since(lease.Spec.RenewTime.Time) > registryStaleAfter {
		return "", false
	}
	addr := lease.Annotations[registryAddrAnno]
	return addr, addr != ""
}

func peerLeaseSuffix(pubKey [PubKeySize]byte) string {
	sum := sha256.Sum256(pubKey[:])
	return hex.EncodeToString(sum[:])
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func leaseSuffix(name, prefix string) string {
	return name[len(prefix):]
}
