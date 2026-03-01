package agent

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/wireguard"
)

// Agent is the per-node WireKube daemon.
// It manages the WireGuard interface and keeps peers in sync with WireKubePeer CRDs.
//
// Design:
//   - Agent creates/updates its own WireKubePeer (publicKey + endpoint auto-discovered).
//   - AllowedIPs on each WireKubePeer is defined by the user (site-to-site style).
//   - Agent syncs all WireKubePeer CRDs into WireGuard peer config + kernel routes.
//   - No IPAM, no mesh IP assignment, no kubelet modification.
type Agent struct {
	client    client.Client
	wgMgr     *wireguard.Manager
	nodeName  string
	syncEvery time.Duration
}

// NewAgent creates a new Agent.
func NewAgent(k8sClient client.Client, wgMgr *wireguard.Manager, nodeName string) *Agent {
	return &Agent{
		client:    k8sClient,
		wgMgr:     wgMgr,
		nodeName:  nodeName,
		syncEvery: 30 * time.Second,
	}
}

// Run starts the agent loop. Blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.setup(ctx); err != nil {
		return fmt.Errorf("agent setup: %w", err)
	}

	ticker := time.NewTicker(a.syncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.sync(ctx); err != nil {
				fmt.Printf("sync error: %v\n", err)
			}
		}
	}
}

// setup performs one-time initialization:
//  1. Load or generate WireGuard key pair.
//  2. Create the WireGuard interface.
//  3. Discover public endpoint (STUN / cloud metadata / node annotation).
//  4. Create or update this node's WireKubePeer with publicKey + endpoint.
func (a *Agent) setup(ctx context.Context) error {
	kp, err := wireguard.LoadOrGenerate()
	if err != nil {
		return fmt.Errorf("key management: %w", err)
	}

	mesh, err := a.getMesh(ctx)
	if err != nil {
		return err
	}

	if err := a.wgMgr.EnsureInterface(); err != nil {
		return fmt.Errorf("creating WireGuard interface: %w", err)
	}
	if err := a.wgMgr.Configure(); err != nil {
		return fmt.Errorf("configuring WireGuard interface: %w", err)
	}

	// Discover endpoint from node annotation or STUN
	node := &corev1.Node{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, node); err != nil {
		return fmt.Errorf("getting node: %w", err)
	}
	epResult, err := DiscoverEndpoint(ctx, node, int(mesh.Spec.ListenPort), mesh.Spec.STUNServers)
	if err != nil {
		fmt.Printf("warning: endpoint discovery failed: %v\n", err)
	}

	// Upsert our WireKubePeer
	peerName := "node-" + a.nodeName
	if err := a.upsertOwnPeer(ctx, peerName, kp.PublicKeyBase64(), epResult); err != nil {
		return fmt.Errorf("upserting own peer: %w", err)
	}

	// Initial sync
	return a.sync(ctx)
}

// upsertOwnPeer creates or updates this node's WireKubePeer with publicKey and endpoint.
// AllowedIPs is intentionally NOT set here — the user defines it.
func (a *Agent) upsertOwnPeer(ctx context.Context, name, pubKey string, ep *EndpointResult) error {
	existing := &wirekubev1alpha1.WireKubePeer{}
	err := a.client.Get(ctx, client.ObjectKey{Name: name}, existing)

	endpoint := ""
	method := ""
	if ep != nil {
		endpoint = ep.Endpoint
		method = string(ep.Method)
	}

	if apierrors.IsNotFound(err) {
		peer := &wirekubev1alpha1.WireKubePeer{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"wirekube.io/node": a.nodeName,
				},
			},
			Spec: wirekubev1alpha1.WireKubePeerSpec{
				PublicKey:           pubKey,
				Endpoint:            endpoint,
				PersistentKeepalive: 25,
			},
		}
		if createErr := a.client.Create(ctx, peer); createErr != nil && !apierrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("creating own WireKubePeer: %w", createErr)
		}
		if method != "" {
			_ = a.updateDiscoveryMethod(ctx, name, method)
		}
		return nil
	}
	if err != nil {
		return err
	}

	// Update publicKey and endpoint (preserve AllowedIPs set by user)
	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec.PublicKey = pubKey
	if endpoint != "" {
		existing.Spec.Endpoint = endpoint
	}
	if patchErr := a.client.Patch(ctx, existing, patch); patchErr != nil {
		return fmt.Errorf("patching own WireKubePeer: %w", patchErr)
	}
	if method != "" {
		_ = a.updateDiscoveryMethod(ctx, name, method)
	}
	return nil
}

func (a *Agent) updateDiscoveryMethod(ctx context.Context, name, method string) error {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: name}, peer); err != nil {
		return err
	}
	patch := client.MergeFrom(peer.DeepCopy())
	peer.Status.EndpointDiscoveryMethod = method
	return a.client.Status().Patch(ctx, peer, patch)
}

// sync reconciles WireGuard peer config and kernel routes with current WireKubePeer CRDs.
func (a *Agent) sync(ctx context.Context) error {
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := a.client.List(ctx, peerList); err != nil {
		return fmt.Errorf("listing peers: %w", err)
	}

	myPeerName := "node-" + a.nodeName
	wgPeers := make([]wireguard.PeerConfig, 0, len(peerList.Items))
	allRoutes := []string{}

	for _, p := range peerList.Items {
		// Skip self
		if p.Name == myPeerName {
			continue
		}
		// Skip peers not yet initialized (no public key)
		if p.Spec.PublicKey == "" {
			continue
		}

		wgPeers = append(wgPeers, wireguard.PeerConfig{
			PublicKeyB64:     p.Spec.PublicKey,
			Endpoint:         p.Spec.Endpoint,
			AllowedIPs:       p.Spec.AllowedIPs,
			KeepaliveSeconds: int(p.Spec.PersistentKeepalive),
		})

		// Collect routes: AllowedIPs → wg0
		allRoutes = append(allRoutes, p.Spec.AllowedIPs...)
	}

	if err := a.wgMgr.SyncPeers(wgPeers); err != nil {
		return fmt.Errorf("syncing WireGuard peers: %w", err)
	}

	// Sync kernel routes: AllowedIPs → wg interface
	if err := a.wgMgr.SyncRoutes(allRoutes); err != nil {
		return fmt.Errorf("syncing routes: %w", err)
	}

	// Update own peer status
	if err := a.updateOwnStatus(ctx, myPeerName); err != nil {
		fmt.Printf("warning: updating own peer status: %v\n", err)
	}

	return nil
}

// updateOwnStatus reads WireGuard stats and updates this node's WireKubePeer status.
func (a *Agent) updateOwnStatus(ctx context.Context, peerName string) error {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return err
	}

	stats, err := a.wgMgr.GetStats()
	if err != nil {
		return err
	}

	connected := false
	var totalRx, totalTx int64
	var lastHandshake time.Time
	for _, s := range stats {
		totalRx += s.BytesReceived
		totalTx += s.BytesSent
		if !s.LastHandshake.IsZero() && s.LastHandshake.After(lastHandshake) {
			lastHandshake = s.LastHandshake
		}
		if time.Since(s.LastHandshake) < 3*time.Minute {
			connected = true
		}
	}

	patch := client.MergeFrom(peer.DeepCopy())
	peer.Status.Connected = connected
	peer.Status.BytesReceived = totalRx
	peer.Status.BytesSent = totalTx
	if !lastHandshake.IsZero() {
		t := metav1.NewTime(lastHandshake)
		peer.Status.LastHandshake = &t
	}
	return a.client.Status().Patch(ctx, peer, patch)
}

func (a *Agent) getMesh(ctx context.Context) (*wirekubev1alpha1.WireKubeMesh, error) {
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if err := a.client.List(ctx, meshList); err != nil {
		return nil, err
	}
	if len(meshList.Items) == 0 {
		return nil, fmt.Errorf("no WireKubeMesh resource found")
	}
	return &meshList.Items[0], nil
}
