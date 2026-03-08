package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/agent/nat"
	agentrelay "github.com/wirekube/wirekube/pkg/agent/relay"
	relayproto "github.com/wirekube/wirekube/pkg/relay"
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

	relayPool    *agentrelay.Pool
	relayMode    string
	relayTimeout time.Duration
	relayRetry   time.Duration
	// isSymmetricNAT is set during endpoint discovery when STUN detects
	// endpoint-dependent mapping. When true, relay is preferred for symmetric peers.
	isSymmetricNAT bool
	// detectedNATType stores the exact NAT type detected during STUN discovery.
	detectedNATType string
	// peerFirstSeen tracks when we first observed a peer without handshake,
	// used to decide when to trigger relay fallback.
	peerFirstSeen map[string]time.Time
	// relayedPeers tracks which peers are currently using relay transport.
	relayedPeers map[string]bool
	// directEndpoints stores the original direct endpoint before relay override.
	directEndpoints map[string]string
	// directRetryTime tracks the last time we attempted direct connectivity for a relayed peer.
	directRetryTime map[string]time.Time
	// directProbing tracks peers currently being probed for direct connectivity.
	directProbing map[string]bool
	// iceStates tracks per-peer ICE negotiation state.
	iceStates map[string]*peerICEState
	// holePunchEndpoints maps peer name → birthday-attack proxy listen address.
	holePunchEndpoints map[string]string
	// ownPublicKeyB64 caches the base64-encoded public key.
	ownPublicKeyB64 string
	// portPrediction stores our NAT port prediction data from STUN.
	portPrediction *nat.PortPrediction
	// gwState tracks gateway configuration when this node serves as a VGW.
	gwState *gatewayState
	// gwClientCache maps gateway CIDR → set of authorized client peer names.
	// Rebuilt every sync cycle. nil means not yet built.
	gwClientCache map[string]map[string]bool
	// nonGwPeerIPs holds node IPs of peers that are NOT active gateway peers.
	// Rebuilt every sync cycle. Used to skip gateway route CIDRs that overlap
	// with peer subnets (those are reachable directly, not via gateway).
	nonGwPeerIPs []net.IP
	// latencyCycle counts sync iterations for periodic latency measurement.
	latencyCycle int
}

// NewAgent creates a new Agent.
func NewAgent(k8sClient client.Client, wgMgr *wireguard.Manager, nodeName string) *Agent {
	return &Agent{
		client:             k8sClient,
		wgMgr:              wgMgr,
		nodeName:           nodeName,
		syncEvery:          30 * time.Second,
		peerFirstSeen:      make(map[string]time.Time),
		relayedPeers:       make(map[string]bool),
		directEndpoints:    make(map[string]string),
		directRetryTime:    make(map[string]time.Time),
		directProbing:      make(map[string]bool),
		iceStates:          make(map[string]*peerICEState),
		holePunchEndpoints: make(map[string]string),
	}
}

// Run starts the agent loop. Blocks until ctx is cancelled.
// Setup is retried with exponential backoff to handle transient failures
// such as CNI not yet installed (DNS/API server unreachable).
func (a *Agent) Run(ctx context.Context) error {
	// Clean up stale interface from previous runs
	_ = a.wgMgr.DeleteInterface()

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if err := a.setup(ctx); err != nil {
			fmt.Printf("[agent] setup failed (retrying in %s): %v\n", backoff, err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			continue
		}
		break
	}
	defer a.cleanup()

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

// cleanup removes WireGuard routes and interface on shutdown.
func (a *Agent) cleanup() {
	fmt.Printf("[cleanup] removing routes and WireGuard interface %s\n", a.wgMgr.InterfaceName())
	// Close birthday-attack hole-punch proxies.
	for name, state := range a.iceStates {
		if state.holePunch != nil {
			state.holePunch.Close()
			state.holePunch = nil
		}
		delete(a.holePunchEndpoints, name)
	}
	a.cleanupGateway()
	if a.relayPool != nil {
		a.relayPool.Close()
	}
	if err := a.wgMgr.SyncRoutes(nil); err != nil {
		fmt.Printf("[cleanup] warning: flushing routes: %v\n", err)
	}
	if err := a.wgMgr.DeleteInterface(); err != nil {
		fmt.Printf("[cleanup] warning: deleting interface: %v\n", err)
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

	if err := a.applyMeshDefaults(ctx, mesh); err != nil {
		fmt.Printf("warning: applying mesh defaults: %v\n", err)
	}

	// Discover endpoint BEFORE creating WireGuard interface.
	// STUN needs to bind the listen port, which WireGuard will claim.
	node := &corev1.Node{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, node); err != nil {
		return fmt.Errorf("getting node: %w", err)
	}
	epResult, err := DiscoverEndpoint(ctx, node, int(mesh.Spec.ListenPort), mesh.Spec.STUNServers)
	if err != nil {
		fmt.Printf("warning: endpoint discovery failed: %v\n", err)
	}
	if epResult != nil {
		a.detectedNATType = string(epResult.NATType)
		if epResult.NATType == nat.NATSymmetric {
			a.isSymmetricNAT = true
			fmt.Printf("[setup] symmetric NAT detected — relay for symmetric peers, direct for cone/public peers\n")
		} else if epResult.NATType == nat.NATCone {
			fmt.Printf("[setup] cone NAT detected — direct P2P for all peers\n")
		}
	}

	if err := a.wgMgr.EnsureInterface(); err != nil {
		return fmt.Errorf("creating WireGuard interface: %w", err)
	}
	if err := a.wgMgr.Configure(); err != nil {
		return fmt.Errorf("configuring WireGuard interface: %w", err)
	}

	a.ownPublicKeyB64 = kp.PublicKeyBase64()

	// Store port prediction from STUN for birthday attack support.
	if epResult != nil && epResult.PortPrediction != nil {
		a.portPrediction = epResult.PortPrediction
	}

	// Upsert our WireKubePeer
	peerName := a.nodeName
	if err := a.upsertOwnPeer(ctx, mesh, node, peerName, kp.PublicKeyBase64(), epResult); err != nil {
		return fmt.Errorf("upserting own peer: %w", err)
	}

	// Initialize relay client if configured (relay-first: connect immediately).
	if err := a.initRelay(ctx, mesh, kp.PublicKeyBase64()); err != nil {
		fmt.Printf("warning: relay init failed (will retry): %v\n", err)
	}

	// Publish ICE candidates and port prediction to CRD.
	candidates := a.gatherICECandidates(epResult)
	var natPP *nat.PortPrediction
	if epResult != nil {
		natPP = epResult.PortPrediction
	}
	if err := a.publishICEState(ctx, peerName, candidates, natPP, iceStateGathering); err != nil {
		fmt.Printf("warning: publishing ICE state: %v\n", err)
	}

	// Initial sync
	return a.sync(ctx)
}

// upsertOwnPeer creates or updates this node's WireKubePeer with publicKey and endpoint.
// AllowedIPs is NOT overwritten when already set by the user. Auto-detection is opt-in
// via WireKubeMesh.spec.autoAllowedIPs and WireKubeMesh.spec.podCIDRRouting.
func (a *Agent) upsertOwnPeer(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh, node *corev1.Node, name, pubKey string, ep *EndpointResult) error {
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
		applyAutoAllowedIPs(mesh, node, &peer.Spec)
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
	applyAutoAllowedIPs(mesh, node, &existing.Spec)
	if patchErr := a.client.Patch(ctx, existing, patch); patchErr != nil {
		return fmt.Errorf("patching own WireKubePeer: %w", patchErr)
	}
	if method != "" {
		_ = a.updateDiscoveryMethod(ctx, name, method)
	}
	return nil
}

// applyAutoAllowedIPs applies automatic AllowedIPs settings from the mesh config to a peer spec.
// autoAllowedIPs.strategy=node-internal-ip: sets InternalIP/32 only when AllowedIPs is empty.
// podCIDRRouting.enabled=true: appends Node.Spec.PodCIDR if not already present.
func applyAutoAllowedIPs(mesh *wirekubev1alpha1.WireKubeMesh, node *corev1.Node, spec *wirekubev1alpha1.WireKubePeerSpec) {
	if mesh == nil || node == nil {
		return
	}
	// Auto-set InternalIP/32 only when AllowedIPs is currently empty.
	if mesh.Spec.AutoAllowedIPs != nil &&
		mesh.Spec.AutoAllowedIPs.Strategy == "node-internal-ip" &&
		len(spec.AllowedIPs) == 0 {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				spec.AllowedIPs = []string{addr.Address + "/32"}
				break
			}
		}
	}
	// Append pod CIDR when enabled and Node.Spec.PodCIDR is set by CNI.
	if mesh.Spec.PodCIDRRouting != nil && mesh.Spec.PodCIDRRouting.Enabled && node.Spec.PodCIDR != "" {
		spec.AllowedIPs = mergeCIDRs(spec.AllowedIPs, []string{node.Spec.PodCIDR})
	}
}

// mergeCIDRs returns a deduplicated union of two CIDR slices, preserving order.
func mergeCIDRs(existing, additional []string) []string {
	seen := make(map[string]struct{}, len(existing))
	result := make([]string, 0, len(existing)+len(additional))
	for _, c := range existing {
		seen[c] = struct{}{}
		result = append(result, c)
	}
	for _, c := range additional {
		if _, ok := seen[c]; !ok {
			result = append(result, c)
		}
	}
	return result
}

func (a *Agent) updateDiscoveryMethod(ctx context.Context, name, method string) error {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: name}, peer); err != nil {
		return err
	}
	patch := client.MergeFrom(peer.DeepCopy())
	peer.Status.EndpointDiscoveryMethod = method
	if a.detectedNATType != "" {
		peer.Status.NATType = a.detectedNATType
	}
	return a.client.Status().Patch(ctx, peer, patch)
}

// sync reconciles WireGuard peer config and kernel routes with current WireKubePeer CRDs.
func (a *Agent) sync(ctx context.Context) error {
	// Re-ensure the KUBE-FIREWALL iptables exception each cycle.
	// kube-proxy may create the chain after the agent starts.
	if a.relayPool != nil {
		a.wgMgr.AllowFwmarkLoopback()
	}

	// Invalidate gateway client cache so it's rebuilt with fresh data this cycle
	a.gwClientCache = nil
	a.nonGwPeerIPs = nil

	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := a.client.List(ctx, peerList); err != nil {
		return fmt.Errorf("listing peers: %w", err)
	}

	a.collectNonGatewayPeerIPs(ctx, peerList)

	myPeerName := a.nodeName
	wgPeers := make([]wireguard.PeerConfig, 0, len(peerList.Items))
	allRoutes := []string{}
	ownAllowedIPsSet := false

	// Build stats map for relay fallback decisions
	statsByKey := make(map[string]wireguard.PeerStats)
	if a.relayPool != nil {
		if stats, err := a.wgMgr.GetStats(); err == nil {
			for _, s := range stats {
				statsByKey[s.PublicKeyB64] = s
			}
		}
	}

	remotePeerNames := []string{}

	var ownIP net.IP
	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == myPeerName {
			if len(p.Spec.AllowedIPs) > 0 {
				ownAllowedIPsSet = true
				ip, _, _ := net.ParseCIDR(p.Spec.AllowedIPs[0])
				if ip != nil {
					ownIP = ip
					a.wgMgr.SetPreferredSrc(ip.String())
				}
			}
			continue
		}
		if p.Spec.PublicKey == "" {
			continue
		}

		endpoint := a.resolveEndpointForPeer(p, statsByKey)
		remotePeerNames = append(remotePeerNames, p.Name)

		filteredAllowedIPs := make([]string, 0, len(p.Spec.AllowedIPs))
		for _, cidr := range p.Spec.AllowedIPs {
			if a.shouldSkipGatewayRoute(ctx, cidr, myPeerName, ownIP) {
				continue
			}
			filteredAllowedIPs = append(filteredAllowedIPs, cidr)
			allRoutes = append(allRoutes, cidr)
		}

		wgPeers = append(wgPeers, wireguard.PeerConfig{
			PublicKeyB64:     p.Spec.PublicKey,
			Endpoint:         endpoint,
			AllowedIPs:       filteredAllowedIPs,
			KeepaliveSeconds: int(p.Spec.PersistentKeepalive),
			ForceEndpoint:    a.directProbing[p.Name],
		})
	}

	// When own allowedIPs is empty, this node has no identity in the mesh.
	// Remote peers will drop all packets from us (WG inbound filter).
	// Adding routes would hijack outgoing traffic (including SSH, kubelet)
	// into wire_kube where it gets silently dropped.
	if !ownAllowedIPsSet {
		allRoutes = nil
		a.wgMgr.SetPreferredSrc("")
		fmt.Printf("[sync] own allowedIPs empty — passive mode (handshake only, no routes)\n")
	}

	if err := a.wgMgr.SyncPeers(wgPeers); err != nil {
		return fmt.Errorf("syncing WireGuard peers: %w", err)
	}

	// Sync kernel routes: AllowedIPs → wg interface
	if err := a.wgMgr.SyncRoutes(allRoutes); err != nil {
		return fmt.Errorf("syncing routes: %w", err)
	}

	// Update own peer status
	if err := a.updateOwnStatus(ctx, myPeerName, remotePeerNames); err != nil {
		fmt.Printf("warning: updating own peer status: %v\n", err)
	}

	// Sync pod CIDR into own AllowedIPs if podCIDRRouting is enabled.
	// Runs every cycle to pick up PodCIDR assigned by CNI after agent startup.
	if err := a.syncOwnPodCIDR(ctx); err != nil {
		fmt.Printf("warning: syncing own pod CIDR: %v\n", err)
	}

	// Try upgrading relayed peers back to direct when conditions allow.
	a.tryDirectUpgrade(peerList, statsByKey)

	// Reflect NAT-mapped endpoints back to CRDs (only for direct peers)
	a.reflectNATEndpoints(ctx, peerList)

	// Configure gateway networking if this node is an active VGW
	if err := a.setupGateway(ctx); err != nil {
		fmt.Printf("[gateway] setup error: %v\n", err)
	}

	// Update Prometheus metrics.
	a.updateMetrics(ctx, peerList)

	// Measure peer latency every 5th sync cycle (~2.5 min) to avoid overhead.
	a.latencyCycle++
	if a.latencyCycle%5 == 0 {
		go a.measurePeerLatency(peerList)
	}

	return nil
}

// reflectNATEndpoints detects when WireGuard has learned a different endpoint
// for a peer (e.g. due to NAT port mapping) and patches the WireKubePeer CRD
// so other nodes also learn the correct endpoint.
// Skips peers using relay transport (their endpoints are local proxy addresses).
func (a *Agent) reflectNATEndpoints(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList) {
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		return
	}

	statsByKey := make(map[string]wireguard.PeerStats, len(stats))
	for _, s := range stats {
		statsByKey[s.PublicKeyB64] = s
	}

	for i := range peerList.Items {
		p := &peerList.Items[i]

		if a.relayedPeers[p.Name] {
			continue
		}

		// Symmetric NAT peers have a different NAT port mapping for each
		// outbound destination. Observing from one cone node and writing it
		// to the CRD would cause every other cone node to use the wrong port.
		if p.Status.NATType == "symmetric" {
			continue
		}

		s, ok := statsByKey[p.Spec.PublicKey]
		if !ok || s.ActualEndpoint == "" {
			continue
		}
		if time.Since(s.LastHandshake) > 3*time.Minute {
			continue
		}
		if s.ActualEndpoint == p.Spec.Endpoint {
			continue
		}
		if len(s.ActualEndpoint) > 10 && s.ActualEndpoint[:10] == "127.0.0.1:" {
			continue
		}

		crdHost, _, crdErr := net.SplitHostPort(p.Spec.Endpoint)
		actualHost, _, actualErr := net.SplitHostPort(s.ActualEndpoint)
		if crdErr == nil && actualErr == nil {
			// Same IP, different port: skip. Port changes within the same public IP
			// are a symptom of symmetric NAT (each destination sees a different mapping).
			// Only reflect when the public IP itself changes (e.g. dynamic IP rotation).
			if crdHost == actualHost {
				continue
			}
			// Never downgrade a public IP to a private IP. The kernel may hold
			// a stale private endpoint from before the peer switched to relay.
			actualIP := net.ParseIP(actualHost)
			crdIP := net.ParseIP(crdHost)
			if actualIP != nil && crdIP != nil && !crdIP.IsPrivate() && actualIP.IsPrivate() {
				continue
			}
		}

		fmt.Printf("[nat-reflect] peer %s: CRD=%s actual=%s → patching\n",
			p.Name, p.Spec.Endpoint, s.ActualEndpoint)
		patch := client.MergeFrom(p.DeepCopy())
		p.Spec.Endpoint = s.ActualEndpoint
		if patchErr := a.client.Patch(ctx, p, patch); patchErr != nil {
			fmt.Printf("[nat-reflect] warning: patching peer %s: %v\n", p.Name, patchErr)
		}
	}
}

// updateOwnStatus reads WireGuard stats and updates this node's WireKubePeer status.
func (a *Agent) updateOwnStatus(ctx context.Context, peerName string, remotePeerNames []string) error {
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
	if err := a.client.Status().Patch(ctx, peer, patch); err != nil {
		return err
	}

	// Write per-peer transport view to WireKubeMesh status.
	// Each agent writes only its own node key; JSON merge-patch merges other nodes' keys.
	return a.updateMeshNodeConnections(ctx, peerName, remotePeerNames)
}

// updateMeshNodeConnections writes this node's peer transport view and
// aggregated peer counts to WireKubeMesh status. This consolidates the
// reconciliation that was previously split across a separate operator.
func (a *Agent) updateMeshNodeConnections(ctx context.Context, myNode string, remotePeerNames []string) error {
	mesh, err := a.getMesh(ctx)
	if err != nil {
		return err
	}

	connections := make(map[string]string, len(remotePeerNames))
	for _, name := range remotePeerNames {
		if a.relayedPeers[name] {
			connections[name] = "relay"
		} else {
			connections[name] = "direct"
		}
	}

	// Count all peers for ReadyPeers/TotalPeers.
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if listErr := a.client.List(ctx, peerList); listErr != nil {
		return listErr
	}
	readyCount := int32(0)
	for _, p := range peerList.Items {
		if p.Status.Connected {
			readyCount++
		}
	}

	patch := client.MergeFrom(mesh.DeepCopy())
	if mesh.Status.NodeConnections == nil {
		mesh.Status.NodeConnections = make(map[string]map[string]string)
	}
	mesh.Status.NodeConnections[myNode] = connections
	mesh.Status.ReadyPeers = readyCount
	mesh.Status.TotalPeers = int32(len(peerList.Items))
	return a.client.Status().Patch(ctx, mesh, patch)
}

// initRelay sets up the relay client from the mesh relay configuration.
func (a *Agent) initRelay(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh, myPubKeyB64 string) error {
	if mesh.Spec.Relay == nil {
		return nil
	}

	relay := mesh.Spec.Relay
	a.relayMode = relay.Mode
	if a.relayMode == "never" {
		return nil
	}

	a.relayTimeout = time.Duration(relay.HandshakeTimeoutSeconds) * time.Second
	if a.relayTimeout == 0 {
		a.relayTimeout = 30 * time.Second
	}
	a.relayRetry = time.Duration(relay.DirectRetryIntervalSeconds) * time.Second
	if a.relayRetry == 0 {
		a.relayRetry = 120 * time.Second
	}

	var endpoint string
	switch relay.Provider {
	case "external":
		if relay.External == nil || relay.External.Endpoint == "" {
			return fmt.Errorf("external relay endpoint not configured")
		}
		endpoint = relay.External.Endpoint
	case "managed":
		port := int32(3478)
		if relay.Managed != nil && relay.Managed.Port != 0 {
			port = relay.Managed.Port
		}
		endpoint = a.discoverManagedRelay(ctx, port)
		if endpoint == "" {
			endpoint = fmt.Sprintf("wirekube-relay.wirekube-system.svc.cluster.local:%d", port)
		}
	default:
		return fmt.Errorf("unknown relay provider: %s", relay.Provider)
	}

	var pubKey [relayproto.PubKeySize]byte
	keyBytes, err := base64.StdEncoding.DecodeString(myPubKeyB64)
	if err != nil {
		return fmt.Errorf("decoding own public key: %w", err)
	}
	copy(pubKey[:], keyBytes)

	wgPort := a.wgMgr.ListenPort()
	fmt.Printf("[relay] proxy wgPort=%d (wg listen port)\n", wgPort)
	a.relayPool = agentrelay.NewPool(endpoint, pubKey, wgPort)
	if err := a.relayPool.Connect(ctx); err != nil {
		fmt.Printf("[relay] initial connect to %s failed (will retry in background): %v\n", endpoint, err)
		return nil
	}

	fmt.Printf("[relay] connected to %s (mode=%s)\n", endpoint, a.relayMode)
	return nil
}

// resolveEndpointForPeer determines the effective WireGuard endpoint for a peer.
//
// Relay-first strategy (DERP-like):
//   - New peers start on relay immediately for instant connectivity.
//   - ICE negotiation runs in the background to upgrade to a direct path.
//   - If a direct probe is active, the direct endpoint is returned temporarily.
//   - Birthday-attack hole-punched paths use a local proxy address.
func (a *Agent) resolveEndpointForPeer(peer *wirekubev1alpha1.WireKubePeer, stats map[string]wireguard.PeerStats) string {
	if a.relayPool == nil || a.relayMode == "never" {
		return peer.Spec.Endpoint
	}

	if a.relayMode == "always" {
		return a.enableRelayForPeer(peer)
	}

	// If peer has a birthday-attack hole-punched path, use it.
	if hp, ok := a.holePunchEndpoints[peer.Name]; ok && hp != "" {
		return hp
	}

	// If ICE has determined this peer is directly reachable (post-upgrade),
	// use the direct endpoint.
	iceState := a.getICEState(peer.Name)
	if iceState.State == iceStateConnected && !a.relayedPeers[peer.Name] {
		return peer.Spec.Endpoint
	}

	// If peer is being probed for direct connectivity, temporarily use direct.
	if a.directProbing[peer.Name] {
		if ep := a.directEndpoints[peer.Name]; ep != "" {
			return ep
		}
	}

	// Check if peer already has a healthy direct connection.
	s, hasStats := stats[peer.Spec.PublicKey]
	hasRecentHandshake := hasStats && !s.LastHandshake.IsZero() && time.Since(s.LastHandshake) < 3*time.Minute
	if hasRecentHandshake && !a.relayedPeers[peer.Name] && !isLocalhostEndpoint(s.ActualEndpoint) {
		iceState.State = iceStateConnected
		a.setICEState(peer.Name, iceState)
		return peer.Spec.Endpoint
	}

	// Default: relay-first. All new peers and peers without a proven direct path
	// go through relay for immediate connectivity.
	return a.enableRelayForPeer(peer)
}

// tryDirectUpgrade runs the ICE-based negotiation loop to upgrade relayed
// peers to direct connectivity. Replaces the old simple probe-based approach
// with a full ICE negotiation that includes:
//   - Candidate evaluation based on NAT type combination.
//   - Direct probe via STUN endpoints for cone ↔ cone / cone ↔ symmetric.
//   - Birthday attack for symmetric ↔ symmetric.
//   - Periodic retry with exponential backoff.
func (a *Agent) tryDirectUpgrade(peerList *wirekubev1alpha1.WireKubePeerList, stats map[string]wireguard.PeerStats) {
	a.runICENegotiation(context.Background(), peerList, stats)
}

func (a *Agent) enableRelayForPeer(peer *wirekubev1alpha1.WireKubePeer) string {
	if a.relayPool == nil {
		return peer.Spec.Endpoint
	}

	if !a.relayPool.IsConnected() {
		return peer.Spec.Endpoint
	}

	var pubKey [relayproto.PubKeySize]byte
	keyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey)
	if err != nil {
		return peer.Spec.Endpoint
	}
	copy(pubKey[:], keyBytes)

	proxy, err := a.relayPool.GetOrCreateProxy(pubKey)
	if err != nil {
		fmt.Printf("[relay] failed to create proxy for %s: %v\n", peer.Name, err)
		return peer.Spec.Endpoint
	}

	if !a.relayedPeers[peer.Name] {
		a.directEndpoints[peer.Name] = peer.Spec.Endpoint
		a.relayedPeers[peer.Name] = true
		fmt.Printf("[relay] peer %s: falling back to relay via %s\n", peer.Name, proxy.ListenAddr())
	}

	return proxy.ListenAddr()
}

func (a *Agent) disableRelayForPeer(peer *wirekubev1alpha1.WireKubePeer) {
	if a.relayPool == nil {
		return
	}

	var pubKey [relayproto.PubKeySize]byte
	keyBytes, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey)
	if err != nil {
		return
	}
	copy(pubKey[:], keyBytes)

	a.relayPool.RemoveProxy(pubKey)
	delete(a.relayedPeers, peer.Name)
	delete(a.directEndpoints, peer.Name)
}

// discoverManagedRelay queries the wirekube-relay Service to find an externally
// reachable address. This avoids the chicken-and-egg problem where the ClusterIP
// is only reachable through the CNI — which might not work yet for NAT'd nodes.
//
// Priority: LoadBalancer externalIP → LoadBalancer ingress → NodePort via node public IP → "" (fallback to ClusterIP DNS).
func (a *Agent) discoverManagedRelay(ctx context.Context, port int32) string {
	svc := &corev1.Service{}
	if err := a.client.Get(ctx, client.ObjectKey{
		Name:      "wirekube-relay",
		Namespace: "wirekube-system",
	}, svc); err != nil {
		return ""
	}

	// 1. ExternalIPs (manually configured public IPs)
	for _, ip := range svc.Spec.ExternalIPs {
		parsed := net.ParseIP(ip)
		if parsed != nil && !parsed.IsPrivate() {
			ep := fmt.Sprintf("%s:%d", ip, port)
			fmt.Printf("[relay] using externalIP: %s\n", ep)
			return ep
		}
	}

	// 2. LoadBalancer Ingress (cloud-assigned external IP/hostname)
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			ep := fmt.Sprintf("%s:%d", ing.IP, port)
			fmt.Printf("[relay] using LB ingress IP: %s\n", ep)
			return ep
		}
		if ing.Hostname != "" {
			ep := fmt.Sprintf("%s:%d", ing.Hostname, port)
			fmt.Printf("[relay] using LB ingress hostname: %s\n", ep)
			return ep
		}
	}

	// 3. NodePort — find a cluster node with a public IP and use NodePort
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer || svc.Spec.Type == corev1.ServiceTypeNodePort {
		var nodePort int32
		for _, p := range svc.Spec.Ports {
			if p.Port == port && p.NodePort != 0 {
				nodePort = p.NodePort
				break
			}
		}
		if nodePort != 0 {
			nodeList := &corev1.NodeList{}
			if err := a.client.List(ctx, nodeList); err == nil {
				for _, n := range nodeList.Items {
					for _, addr := range n.Status.Addresses {
						if addr.Type == corev1.NodeExternalIP {
							ep := fmt.Sprintf("%s:%d", addr.Address, nodePort)
							fmt.Printf("[relay] using NodePort: %s\n", ep)
							return ep
						}
					}
				}
			}
		}
	}

	return ""
}

func (a *Agent) getOwnPublicKey() string {
	return a.ownPublicKeyB64
}

// applyMeshDefaults fills in zero-value spec fields on the WireKubeMesh CR.
// This is idempotent — multiple agents may run it concurrently.
func (a *Agent) applyMeshDefaults(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh) error {
	needsPatch := false
	if mesh.Spec.ListenPort == 0 {
		mesh.Spec.ListenPort = 51820
		needsPatch = true
	}
	if mesh.Spec.InterfaceName == "" {
		mesh.Spec.InterfaceName = "wire_kube"
		needsPatch = true
	}
	if mesh.Spec.MTU == 0 {
		mesh.Spec.MTU = 1420
		needsPatch = true
	}
	if len(mesh.Spec.STUNServers) == 0 {
		mesh.Spec.STUNServers = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
		}
		needsPatch = true
	}
	if !needsPatch {
		return nil
	}
	if err := a.client.Update(ctx, mesh); err != nil && !apierrors.IsConflict(err) {
		return err
	}
	return nil
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

// syncOwnPodCIDR appends Node.Spec.PodCIDR to this node's WireKubePeer AllowedIPs
// when podCIDRRouting is enabled. Called every sync cycle to handle the case where
// the CNI (e.g. Cilium on a hybrid node) assigns PodCIDR after agent startup.
func (a *Agent) syncOwnPodCIDR(ctx context.Context) error {
	mesh, err := a.getMesh(ctx)
	if err != nil || mesh.Spec.PodCIDRRouting == nil || !mesh.Spec.PodCIDRRouting.Enabled {
		return nil
	}
	node := &corev1.Node{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, node); err != nil {
		return err
	}
	if node.Spec.PodCIDR == "" {
		return nil // CNI has not assigned a pod CIDR yet (e.g. VPC CNI on EKS cloud nodes)
	}
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, peer); err != nil {
		return err
	}
	for _, cidr := range peer.Spec.AllowedIPs {
		if cidr == node.Spec.PodCIDR {
			return nil // already present
		}
	}
	patch := client.MergeFrom(peer.DeepCopy())
	peer.Spec.AllowedIPs = append(peer.Spec.AllowedIPs, node.Spec.PodCIDR)
	fmt.Printf("[sync] pod CIDR %s added to own AllowedIPs\n", node.Spec.PodCIDR)
	return a.client.Patch(ctx, peer, patch)
}
