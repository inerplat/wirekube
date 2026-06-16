package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/wirekube/wirekube/pkg/agent/nat"
	agentrelay "github.com/wirekube/wirekube/pkg/agent/relay"
	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/meship"
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
	log          logr.Logger
	client       client.Client
	wgMgr        wireguard.WGEngine
	nodeName     string
	podName      string
	podNamespace string
	apiServer    string
	syncEvery    time.Duration

	relayPool    *agentrelay.Pool
	relayMode    string
	relayTimeout time.Duration
	relayRetry   time.Duration

	handshakeValidWindow  time.Duration
	directConnectedWindow time.Duration
	healthProbeTimeout    time.Duration
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
	// directProbing tracks peers being actively probed (ForceEndpoint=true).
	directProbing map[string]bool
	// passiveProbing tracks peers in passive observation mode.
	// WG endpoint is NOT changed — we observe if the peer initiates direct.
	passiveProbing map[string]time.Time
	// relayGracePeers tracks peers whose relay should be closed after one more cycle.
	// Allows make-before-break: WG switches to direct first, relay closes next cycle.
	relayGracePeers map[string]bool
	// iceStates tracks per-peer ICE negotiation state.
	iceStates map[string]*peerICEState
	// holePunchEndpoints maps peer name → birthday-attack proxy listen address.
	holePunchEndpoints map[string]string
	// relayPrewarmed tracks peers whose relay proxy has been pre-created for
	// make-before-break failover but not yet activated (WG still uses direct).
	relayPrewarmed map[string]bool
	// probeForced tracks symmetric NAT peers where the probe endpoint has already
	// been force-applied to WG once. After the first sync, ForceEndpoint is disabled
	// so WG can learn the peer's actual NAT-mapped port from incoming packets.
	probeForced map[string]bool
	// ownPublicKeyB64 caches the base64-encoded public key.
	ownPublicKeyB64 string
	// portPrediction stores our NAT port prediction data from STUN.
	portPrediction *nat.PortPrediction
	// gwState tracks gateway configuration when this node serves as a VGW.
	gwState *gatewayState
	// wasInterfacePreserved is set during setup when an existing WireGuard
	// interface was reused. Used to shorten the initial relayRetry so that
	// direct upgrade probing starts sooner after restart.
	wasInterfacePreserved bool
	// gwClientCache maps gateway CIDR → set of authorized client peer names.
	// Rebuilt every sync cycle. nil means not yet built.
	gwClientCache map[string]map[string]bool
	// nonGwPeerIPs holds node IPs of peers that are NOT active gateway peers.
	// Rebuilt every sync cycle. Used to skip gateway route CIDRs that overlap
	// with peer subnets (those are reachable directly, not via gateway).
	nonGwPeerIPs []net.IP
	// latencyCycle counts sync iterations for periodic latency measurement.
	latencyCycle int
	// peerTrafficSnapshots stores the previous per-peer byte counters so the
	// agent can distinguish actively transferring peers from idle peers.
	peerTrafficSnapshots map[string]peerTrafficSnapshot
	// pathMonitor is the single source of truth for "which transport mode
	// should each peer be on right now". It drives SetPeerPath calls and
	// feeds Status.Connections. The legacy relayedPeers/directProbing maps
	// are compatibility shims during the transition and will be removed.
	pathMonitor *PathMonitor
	// peerMetricLabels remembers which peer names this agent has emitted
	// Prometheus samples for. Every sync pass diffs the current peer list
	// against this set and calls DeletePartialMatch on the per-peer
	// GaugeVecs for every name that has since disappeared, so /metrics
	// stops advertising vanished peers within one sync interval instead
	// of leaking labels for the lifetime of the process.
	peerMetricLabels map[string]struct{}
}

type peerTrafficSnapshot struct {
	bytesSent     int64
	bytesReceived int64
	lastDirectRX  int64
}

// meaningfulTrafficDeltaBytes is the minimum per-sync byte delta that we treat
// as real data-plane traffic rather than keepalive / control-plane noise.
//
// In CI, a healthy but mostly idle mesh can accumulate multiple 32-byte
// keepalives inside one sync interval. A threshold that's too low makes
// isDirectConnected() tear down otherwise healthy direct paths during quiet
// periods, especially on slower CNIs. Real ping / data-plane traffic is still
// far above this threshold.
const meaningfulTrafficDeltaBytes = 512

const (
	envRelayProxyMode        = "WIREKUBE_RELAY_PROXY"
	nodeAnnotationRelayProxy = "wirekube.io/relay-proxy"
)

// NewAgent creates a new Agent.
func NewAgent(log logr.Logger, k8sClient client.Client, wgMgr wireguard.WGEngine, nodeName, podName, podNamespace, apiServer string) *Agent {
	a := &Agent{
		log:                  log,
		client:               k8sClient,
		wgMgr:                wgMgr,
		nodeName:             nodeName,
		podName:              podName,
		podNamespace:         podNamespace,
		apiServer:            apiServer,
		syncEvery:            parseSyncEvery(),
		peerFirstSeen:        make(map[string]time.Time),
		relayedPeers:         make(map[string]bool),
		directEndpoints:      make(map[string]string),
		directRetryTime:      make(map[string]time.Time),
		directProbing:        make(map[string]bool),
		passiveProbing:       make(map[string]time.Time),
		relayGracePeers:      make(map[string]bool),
		iceStates:            make(map[string]*peerICEState),
		holePunchEndpoints:   make(map[string]string),
		relayPrewarmed:       make(map[string]bool),
		probeForced:          make(map[string]bool),
		peerTrafficSnapshots: make(map[string]peerTrafficSnapshot),
		peerMetricLabels:     make(map[string]struct{}),
	}
	a.pathMonitor = NewPathMonitor(log.WithName("path"), wgMgr, PathMonitorConfig{}, time.Now)
	return a
}

// parseSyncEvery returns the sync interval from WIREKUBE_SYNC_INTERVAL_SECONDS
// or defaults to 30s. This allows test environments to use a shorter cycle.
func parseSyncEvery() time.Duration {
	if v := os.Getenv("WIREKUBE_SYNC_INTERVAL_SECONDS"); v != "" {
		if sec, err := strconv.Atoi(v); err == nil && sec >= 1 {
			return time.Duration(sec) * time.Second
		}
	}
	return 30 * time.Second
}

// Run starts the agent loop. Blocks until ctx is cancelled.
// Setup is retried with exponential backoff to handle transient failures
// such as CNI not yet installed (DNS/API server unreachable).
func (a *Agent) Run(ctx context.Context) error {
	// WireGuard interface is intentionally NOT deleted here.
	// If the interface already exists from a previous run with the same key,
	// it continues forwarding traffic during the restart window.
	// setup() validates the config and recreates only on mismatch.

	backoff := 2 * time.Second
	const maxBackoff = 60 * time.Second
	for {
		if err := a.setup(ctx); err != nil {
			a.log.Error(err, "setup failed, retrying", "backoff", backoff)
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

	// A legacy 250ms fastFailoverTick used to race with the sync loop and
	// force Relay transitions whenever its own direct-traffic heuristic
	// (handshake age + bytes delta) disagreed with PathMonitor's
	// LastDirectReceive-based decision. Tailscale's magicsock keeps a
	// single decision loop (heartbeat + trustBestAddrUntil) — WireKube now
	// does the same: PathMonitor is the sole control-plane authority, the
	// datapath trust window (bind.go) handles sub-second failover.

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.sync(ctx); err != nil {
				a.log.Error(err, "sync error")
			}
		}
	}
}

// cleanup tears down all WireGuard kernel state and releases user-space
// resources on graceful shutdown (SIGTERM). This runs on every normal pod
// termination so that rolling updates and node removals always start with a
// clean interface rather than inheriting stale peer/route state.
func (a *Agent) cleanup() {
	a.log.Info("shutting down: tearing down WireGuard interface", "interface", a.wgMgr.InterfaceName())
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
		a.log.Error(err, "flushing routes on shutdown")
	}
	if err := a.wgMgr.DeleteInterface(); err != nil {
		a.log.Error(err, "deleting WireGuard interface on shutdown")
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
		a.log.Error(err, "applying mesh defaults")
	}

	// If the WireGuard interface survives from a previous run, validate that
	// the key matches. A mismatch (e.g. /var/lib/wirekube deleted and
	// regenerated) requires a full teardown before reconfiguration.
	if a.wgMgr.InterfaceExists() {
		if a.wgMgr.ConfigMatchesKey(kp) {
			a.log.Info("existing WireGuard interface matches key, reusing", "interface", a.wgMgr.InterfaceName())
			a.wasInterfacePreserved = true
		} else {
			a.log.Info("key mismatch on existing interface, recreating")
			if err := a.wgMgr.SyncRoutes(nil); err != nil {
				a.log.Error(err, "clearing routes during interface recreation")
			}
			if err := a.wgMgr.DeleteInterface(); err != nil {
				a.log.Error(err, "deleting interface during recreation")
			}
		}
	}

	// Discover endpoint BEFORE creating WireGuard interface.
	// STUN needs to bind the listen port, which WireGuard will claim.
	node := &corev1.Node{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, node); err != nil {
		return fmt.Errorf("getting node: %w", err)
	}
	// Annotate own pod with node InternalIP so ServiceMonitor can scrape via
	// WireGuard (reachable through VGW) instead of the public host IP.
	if a.podName != "" {
		if ip := nodeInternalIP(node); ip != "" {
			a.annotateOwnPod(ctx, ip)
		}
	}

	epResult, err := DiscoverEndpoint(ctx, node, int(mesh.Spec.ListenPort), mesh.Spec.STUNServers)
	if err != nil {
		a.log.Error(err, "endpoint discovery failed")
	}
	if epResult != nil {
		a.detectedNATType = string(epResult.NATType)
		switch epResult.NATType {
		case nat.NATSymmetric:
			a.isSymmetricNAT = true
			a.log.Info("symmetric NAT detected, relay for symmetric peers, direct for cone/public peers")
		case nat.NATCone:
			a.log.Info("cone NAT detected, direct P2P for all peers")
		case nat.NATOpen:
			a.log.Info("no NAT detected (public IP on local interface), direct P2P for all peers")
		}
	}

	if err := a.wgMgr.EnsureInterface(); err != nil {
		return fmt.Errorf("creating WireGuard interface: %w", err)
	}
	if err := a.wgMgr.Configure(); err != nil {
		return fmt.Errorf("configuring WireGuard interface: %w", err)
	}

	// Ensure the API server is always reachable via the main routing table,
	// even when WireGuard routes capture its /32 IP. Without this, the agent
	// loses API server connectivity when the tunnel isn't fully operational.
	a.ensureAPIServerRoute()

	a.ownPublicKeyB64 = kp.PublicKeyBase64()

	// Store port prediction from STUN for birthday attack support.
	if epResult != nil && epResult.PortPrediction != nil {
		a.portPrediction = epResult.PortPrediction
	}

	// Upsert our WireKubePeer
	peerName := a.nodeName

	// When STUN fell back to an ephemeral port (preserved interface restart),
	// the cone NAT port mapping for the WG socket is unknown — the substituted
	// listenPort may be wrong. Prefer the existing CRD endpoint (set during
	// the initial startup when STUN could bind directly to the WG port).
	if epResult != nil && epResult.PortEstimated {
		existing := &wirekubev1alpha1.WireKubePeer{}
		if getErr := a.client.Get(ctx, client.ObjectKey{Name: peerName}, existing); getErr == nil && existing.Spec.Endpoint != "" {
			a.log.Info("preserved interface restart: keeping existing endpoint (ephemeral STUN port unreliable for cone NAT)", "endpoint", existing.Spec.Endpoint)
			epResult.Endpoint = existing.Spec.Endpoint
			epResult.PortEstimated = false
		}
	}

	if err := a.upsertOwnPeer(ctx, mesh, node, peerName, kp.PublicKeyBase64(), epResult); err != nil {
		return fmt.Errorf("upserting own peer: %w", err)
	}

	// Initialize relay client if configured (relay-first: connect immediately).
	if err := a.initRelay(ctx, mesh, kp.PublicKeyBase64()); err != nil {
		a.log.Error(err, "relay init failed, will retry")
	}

	// If initial STUN detected cone NAT and relay is available, refine detection
	// to distinguish port-restricted cone from address-restricted cone.
	if a.detectedNATType == string(nat.NATCone) && a.relayPool != nil && a.relayPool.IsConnected() {
		relayIP := a.relayPool.RelayIP()
		a.log.Info("starting port-restriction detection", "relayIP", relayIP)
		if relayIP != "" {
			probeFunc := func(ip net.IP, port int) error {
				return a.relayPool.SendNATProbe(ip, port)
			}
			refinedType, err := nat.DetectPortRestriction(ctx, mesh.Spec.STUNServers, relayIP, probeFunc)
			if err != nil {
				a.log.Error(err, "port-restriction detection failed, keeping cone")
			} else {
				a.detectedNATType = string(refinedType)
				if refinedType == nat.NATPortRestrictedCone {
					a.log.Info("port-restricted cone NAT detected, direct retry disabled for incompatible peers")
				} else {
					a.log.Info("address-restricted cone NAT confirmed, direct P2P possible")
				}
				// Update CRD with refined NAT type.
				if err := a.updateDiscoveryMethod(ctx, peerName, "stun"); err != nil {
					a.log.Error(err, "updating NAT type in CRD")
				}
			}
		}
	}

	// Recover ICE state from surviving WireGuard peers. If the interface was
	// preserved across a restart, peers with a recent handshake and a non-local
	// endpoint are already directly connected — mark them as such so the agent
	// doesn't force them through relay and wait relayRetry (120s) before probing.
	a.recoverICEStateFromWG()

	// Publish ICE candidates and port prediction to CRD.
	candidates := a.gatherICECandidates(epResult)
	var natPP *nat.PortPrediction
	if epResult != nil {
		natPP = epResult.PortPrediction
	}
	if err := a.publishICEState(ctx, peerName, candidates, natPP, iceStateGathering); err != nil {
		a.log.Error(err, "publishing ICE state")
	}

	// Initial sync
	return a.sync(ctx)
}

// upsertOwnPeer creates or updates this node's WireKubePeer with publicKey, endpoint,
// and mesh IP derived from WireKubeMesh.spec.meshCIDR.
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
					agentManagedPeerLabel: a.nodeName,
				},
				OwnerReferences: nodeOwnerReferences(node),
			},
			Spec: wirekubev1alpha1.WireKubePeerSpec{
				PublicKey:           pubKey,
				Endpoint:            endpoint,
				PersistentKeepalive: 25,
			},
		}
		applyMeshIP(a.log, mesh, name, &peer.Spec)
		applyNodeInternalIP(a.log, mesh, node, &peer.Spec)
		if createErr := a.client.Create(ctx, peer); createErr != nil && !apierrors.IsAlreadyExists(createErr) {
			return fmt.Errorf("creating own WireKubePeer: %w", createErr)
		}
		if method != "" {
			if err := a.updateDiscoveryMethod(ctx, name, method); err != nil {
				a.log.V(1).Info("updating discovery method", "error", err, "peer", name)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}

	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec.PublicKey = pubKey
	if endpoint != "" {
		existing.Spec.Endpoint = endpoint
	}
	// Backfill ownerReference for CRs created before this fix existed, so K8s
	// GC cascade-deletes them the moment the underlying Node is removed.
	if !hasNodeOwnerReference(existing.OwnerReferences, node) {
		existing.OwnerReferences = append(existing.OwnerReferences, nodeOwnerReferences(node)...)
	}
	applyMeshIP(a.log, mesh, name, &existing.Spec)
	applyNodeInternalIP(a.log, mesh, node, &existing.Spec)
	if patchErr := a.client.Patch(ctx, existing, patch); patchErr != nil {
		return fmt.Errorf("patching own WireKubePeer: %w", patchErr)
	}
	if method != "" {
		if err := a.updateDiscoveryMethod(ctx, name, method); err != nil {
			a.log.V(1).Info("updating discovery method", "error", err, "peer", name)
		}
	}
	return nil
}

// nodeOwnerReferences builds the OwnerReference slice that ties a
// WireKubePeer to its underlying K8s Node. K8s garbage collection
// cascade-deletes the peer the moment the owning Node is removed, so
// stale CRs never accumulate. Controller=false because the agent itself
// is the active reconciler — Node is only the lifecycle parent.
// BlockOwnerDeletion=false so the user can always remove a node without
// being held up by a peer CR.
func nodeOwnerReferences(node *corev1.Node) []metav1.OwnerReference {
	if node == nil || node.UID == "" {
		return nil
	}
	return []metav1.OwnerReference{{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       node.Name,
		UID:        node.UID,
	}}
}

// hasNodeOwnerReference reports whether the OwnerReference slice already
// contains a Node owner that matches the given node. Used by upsertOwnPeer
// to avoid duplicating the ownerRef when backfilling pre-existing CRs.
func hasNodeOwnerReference(refs []metav1.OwnerReference, node *corev1.Node) bool {
	if node == nil {
		return false
	}
	for _, r := range refs {
		if r.Kind == "Node" && r.UID == node.UID {
			return true
		}
	}
	return false
}

// applyMeshIP ensures the deterministic mesh IP is the first entry in AllowedIPs.
// If meshCIDR is not configured, AllowedIPs is left unchanged so that manually
// configured peers continue to work. Gateway-injected CIDRs beyond the mesh IP
// are preserved so that injectGatewayRoutes and applyMeshIP don't fight each other.
func applyMeshIP(log logr.Logger, mesh *wirekubev1alpha1.WireKubeMesh, peerName string, spec *wirekubev1alpha1.WireKubePeerSpec) {
	if mesh == nil || mesh.Spec.MeshCIDR == "" {
		return
	}
	meshIP, err := meship.IPForName(peerName, mesh.Spec.MeshCIDR)
	if err != nil {
		log.Error(err, "computing mesh IP", "peer", peerName, "meshCIDR", mesh.Spec.MeshCIDR)
		return
	}
	// If mesh IP is already first entry, preserve the rest (gateway CIDRs etc).
	if len(spec.AllowedIPs) > 0 && spec.AllowedIPs[0] == meshIP {
		return
	}
	// Replace only the first entry; keep any gateway-injected CIDRs that follow.
	extra := []string{}
	for _, cidr := range spec.AllowedIPs {
		if cidr != meshIP {
			extra = append(extra, cidr)
		}
	}
	spec.AllowedIPs = append([]string{meshIP}, extra...)
}

// applyNodeInternalIP, when WireKubeMesh.spec.autoAllowedIPs.includeNodeInternalIP
// is true, ensures the node's cluster-internal IP (Node.status.addresses[InternalIP])
// appears as a /32 entry in the peer's AllowedIPs. This keeps legacy references that
// still use the physical node IP (kubelet heartbeat, etcd client certs pinned to IP,
// in-cluster services) routable through the mesh alongside the deterministic meshIP.
//
// The entry is appended at the end, after meshIP and any gateway-injected CIDRs,
// and is not re-added if already present.
func applyNodeInternalIP(log logr.Logger, mesh *wirekubev1alpha1.WireKubeMesh, node *corev1.Node, spec *wirekubev1alpha1.WireKubePeerSpec) {
	if mesh == nil || mesh.Spec.AutoAllowedIPs == nil || !mesh.Spec.AutoAllowedIPs.IncludeNodeInternalIP {
		return
	}
	ip := preferredPeerInternalIP(node)
	if ip == "" {
		return
	}
	entry := ip + "/32"
	for _, cidr := range spec.AllowedIPs {
		if cidr == entry {
			return
		}
	}
	spec.AllowedIPs = append(spec.AllowedIPs, entry)
	log.V(1).Info("autoAllowedIPs: appended node internal IP", "peer", node.Name, "entry", entry)
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
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
	// Re-read relay mode from mesh CR so runtime changes are picked up.
	pokeAfterSync := false
	if mesh, err := a.getMesh(ctx); err == nil && mesh.Spec.Relay != nil {
		oldMode := a.relayMode
		newMode := mesh.Spec.Relay.Mode
		if oldMode != newMode {
			a.log.Info("relay mode changed", "oldMode", oldMode, "newMode", newMode)
			a.relayMode = newMode
			// When switching away from "always", reset ICE states so peers
			// re-evaluate connectivity immediately instead of waiting for
			// the relay retry interval. Without this, peers that were forced
			// to relay by mode=always stay stuck because their ICE state
			// (iceStateConnected) + relay endpoint causes probe failures.
			if oldMode == relayModeAlways && newMode != relayModeAlways {
				for name, state := range a.iceStates {
					if state.State == iceStateConnected && a.relayedPeers[name] {
						state.State = iceStateRelay
						state.LastCheck = time.Time{} // zero → immediate retry
						a.setICEState(name, state)
						a.log.Info("reset ICE state due to mode change", "peer", name, "newMode", newMode)
					}
				}
			}
			// Poke peers AFTER SyncPeers so that SetPeerPath(PathModeRelay)
			// has been applied in the bind. Poking before would send the
			// keepalive via the old path (Direct), causing the handshake
			// to complete over direct UDP instead of relay.
			if newMode == relayModeAlways && oldMode != relayModeAlways {
				pokeAfterSync = true
			}
		} else {
			a.relayMode = newMode
		}
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
	routeOwners := map[string]string{}
	allowRoutesBeforeHandshake := map[string]bool{}
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
	remotePeers := make(map[string]*wirekubev1alpha1.WireKubePeer, len(peerList.Items))
	externalList := &wirekubev1alpha1.WireKubeExternalPeerList{}
	externalByIngress := map[string][]string{}
	if err := a.client.List(ctx, externalList); err != nil {
		a.log.Error(err, "list WireKubeExternalPeer; skipping external peer sync")
		externalList = nil
	} else {
		for i := range externalList.Items {
			ep := &externalList.Items[i]
			if ep.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
				continue
			}
			if ep.Status.IngressPeerName == "" || ep.Status.PublicKey == "" || ep.Status.AssignedMeshIP == "" {
				continue
			}
			externalByIngress[ep.Status.IngressPeerName] = append(externalByIngress[ep.Status.IngressPeerName], ep.Status.AssignedMeshIP)
		}
	}

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
					if err := a.wgMgr.SetAddress(p.Spec.AllowedIPs[0]); err != nil {
						a.log.Error(err, "failed to assign address to WireGuard interface")
					}
				}
			}
			continue
		}
		if p.Spec.PublicKey == "" {
			continue
		}

		endpoint := a.resolveEndpointForPeer(p, statsByKey)
		remotePeerNames = append(remotePeerNames, p.Name)
		remotePeers[p.Name] = p

		filteredAllowedIPs := make([]string, 0, len(p.Spec.AllowedIPs))
		for _, cidr := range p.Spec.AllowedIPs {
			if a.shouldSkipGatewayRoute(ctx, cidr, myPeerName, ownIP) {
				continue
			}
			filteredAllowedIPs = append(filteredAllowedIPs, cidr)
			allRoutes = append(allRoutes, cidr)
			routeOwners[cidr] = p.Spec.PublicKey
		}
		for _, cidr := range externalByIngress[p.Name] {
			if a.shouldSkipGatewayRoute(ctx, cidr, myPeerName, ownIP) {
				continue
			}
			if containsString(filteredAllowedIPs, cidr) {
				continue
			}
			filteredAllowedIPs = append(filteredAllowedIPs, cidr)
			allRoutes = append(allRoutes, cidr)
			routeOwners[cidr] = p.Spec.PublicKey
		}

		// Symmetric peers must never be force-endpointed post-probe: the
		// NAT-mapped source port drifts and writing a stale value clobbers
		// wireguard-go's roamed endpoint.
		iceStateNow := a.getICEState(p.Name)
		peerIsSymmetric := p.Status.NATType == "symmetric"
		forceForProbe := a.directProbing[p.Name] && (!peerIsSymmetric || !a.probeForced[p.Name])
		if forceForProbe && peerIsSymmetric {
			a.probeForced[p.Name] = true
		}
		forceEp := forceForProbe ||
			(iceStateNow.State == iceStateConnected && !a.relayedPeers[p.Name] && !peerIsSymmetric)
		wgPeers = append(wgPeers, wireguard.PeerConfig{
			PublicKeyB64:     p.Spec.PublicKey,
			Endpoint:         endpoint,
			AllowedIPs:       filteredAllowedIPs,
			KeepaliveSeconds: a.keepaliveForPeer(p),
			ForceEndpoint:    forceEp,
		})
		if a.canRouteBeforeHandshake(p.Name) {
			allowRoutesBeforeHandshake[p.Spec.PublicKey] = true
		}
	}

	// Ingress-side external peer acceptance.
	//
	// WireKubeExternalPeer CRs describe off-cluster hosts that join the mesh
	// through the relay's shared raw-WireGuard UDP listener. The reconciler
	// picks one cluster ingress peer for each external peer and writes the
	// choice to status.ingressPeerName. Only that ingress agent adds the
	// official client's WG peer. Other agents route the external peer's /32
	// through the selected ingress by augmenting that WireKubePeer's
	// AllowedIPs above, which keeps VM-to-VM and cluster-to-external traffic
	// routable without installing the external peer key everywhere.
	//
	// We do NOT set Endpoint here: the ingress peer accepts inbound and the bind
	// transport mode auto-defaults to relay when the relay pool is connected
	// (see SetPeerPath in userspace_engine.go), so outbound responses flow
	// through the relay leg back to the shared relay listener and on to the
	// external peer.
	// KeepaliveSeconds is 0 because the external peer initiates keepalives;
	// the ingress peer only responds.
	if externalList != nil {
		for i := range externalList.Items {
			ep := &externalList.Items[i]
			if ep.Status.IngressPeerName != myPeerName {
				continue
			}
			if ep.Status.Phase != wirekubev1alpha1.ExternalPeerPhaseActive {
				continue
			}
			if ep.Status.PublicKey == "" || ep.Status.AssignedMeshIP == "" {
				continue
			}
			wgPeers = append(wgPeers, wireguard.PeerConfig{
				PublicKeyB64:     ep.Status.PublicKey,
				Endpoint:         "",
				AllowedIPs:       []string{ep.Status.AssignedMeshIP},
				KeepaliveSeconds: 0,
				ForceEndpoint:    false,
			})
			allRoutes = append(allRoutes, ep.Status.AssignedMeshIP)
			routeOwners[ep.Status.AssignedMeshIP] = ep.Status.PublicKey
		}
	}

	// When own allowedIPs is empty, this node has no identity in the mesh.
	// Remote peers will drop all packets from us (WG inbound filter).
	// Adding routes would hijack outgoing traffic (including SSH, kubelet)
	// into wire_kube where it gets silently dropped.
	if !ownAllowedIPsSet {
		allRoutes = nil
		a.wgMgr.SetPreferredSrc("")
		a.log.Info("own allowedIPs empty, passive mode (handshake only, no routes)")
	}

	if err := a.wgMgr.SyncPeers(wgPeers); err != nil {
		return fmt.Errorf("syncing WireGuard peers: %w", err)
	}

	// Poke all peers after SyncPeers has applied PathModeRelay in the bind.
	// This triggers an immediate WG handshake through the relay path.
	if pokeAfterSync {
		for _, p := range wgPeers {
			if err := a.wgMgr.PokeKeepalive(p.PublicKeyB64); err != nil {
				a.log.Error(err, "PokeKeepalive on always transition", "pubKey", p.PublicKeyB64[:8])
			}
		}
	}

	// Filter routes: direct-only peers need a handshake before routes are
	// installed, but relay-capable peers may need routes before the first
	// handshake so bootstrap traffic can traverse the relay. API server CIDRs
	// remain excluded regardless of transport mode.
	if len(allRoutes) > 0 {
		connectedRoutes := a.filterRoutesForConnectedPeers(allRoutes, routeOwners, allowRoutesBeforeHandshake)
		if len(connectedRoutes) < len(allRoutes) {
			a.log.V(2).Info("deferred routes for peers without handshake",
				"connected", len(connectedRoutes), "total", len(allRoutes))
		}
		allRoutes = connectedRoutes
	}

	// Sync kernel routes: AllowedIPs → wg interface
	if err := a.wgMgr.SyncRoutes(allRoutes); err != nil {
		return fmt.Errorf("syncing routes: %w", err)
	}

	// Process relay grace for peers upgraded to direct.
	// Unlike the old design which fully closed relay proxies, the new standby
	// mode keeps relay proxies alive but marks the peer as non-relayed. The
	// relay proxy remains pre-warmed for instant failover.
	a.processRelayGrace()

	// Ensure relay proxies exist for ALL peers in standby mode so that
	// failover from direct→relay is instant with no warmup delay.
	a.prewarmAllPeerRelays(peerList)

	// Refresh WG stats after relay proxy closures. processRelayGrace may have
	// just closed relay proxies, and WG's ForceEndpoint (set above for
	// iceStateConnected peers) may have triggered a re-handshake during this
	// sync cycle. Using fresh stats ensures isDirectConnected sees the new
	// LastHandshake rather than the stale snapshot from the start of the cycle.
	if freshStats, err := a.wgMgr.GetStats(); err == nil {
		statsByKey = make(map[string]wireguard.PeerStats, len(freshStats))
		for _, s := range freshStats {
			statsByKey[s.PublicKeyB64] = s
		}
	}

	// Try upgrading relayed peers back to direct when conditions allow.
	a.tryDirectUpgrade(peerList, statsByKey)

	// Drive the PathMonitor FSM for every remote peer and commit the
	// resulting transport mode to the Bind. This is the single authoritative
	// SetPeerPath call per sync cycle — legacy SetPeerPath calls earlier in
	// the pipeline (enableRelayForPeer, upgradeToDirect, probe logic) are
	// superseded by whatever PathMonitor.Evaluate returns here.
	a.driveTransportMode(remotePeerNames, remotePeers)

	// Publish status after ICE transitions so Status.Connections and Connected
	// reflect the current path choice instead of the pre-failover snapshot.
	if err := a.updateOwnStatus(ctx, myPeerName, remotePeerNames, remotePeers, statsByKey); err != nil {
		a.log.Error(err, "updating own peer status")
	}

	a.recordPeerTrafficSnapshots(statsByKey)

	// Keep the shortened retry interval until restart-era relay peers have had
	// a fair chance to reprobe back to direct. Some environments need more than
	// one aggressive cycle after restart before the direct path is observable
	// again; restoring the full interval immediately can strand them on relay
	// for minutes.
	if a.wasInterfacePreserved && a.relayRetry == restartRelayRetry {
		if a.hasPendingRestartRelayRecovery(remotePeerNames) {
			a.log.V(1).Info("keeping shortened relay retry while restart recovery is pending", "interval", a.relayRetry)
		} else {
			mesh, err := a.getMesh(ctx)
			if err == nil && mesh.Spec.Relay != nil {
				a.relayRetry = time.Duration(mesh.Spec.Relay.DirectRetryIntervalSeconds) * time.Second
				if a.relayRetry == 0 {
					a.relayRetry = 120 * time.Second
				}
				a.log.Info("restoring normal relay retry interval", "interval", a.relayRetry)
			}
			a.wasInterfacePreserved = false
		}
	}

	// Reflect NAT-mapped endpoints back to CRDs (only for direct peers)
	a.reflectNATEndpoints(ctx, peerList)

	// Configure gateway networking if this node is an active VGW
	if err := a.setupGateway(ctx); err != nil {
		a.log.Error(err, "gateway setup error")
	}

	// Delete legacy WireKubePeer CRs whose underlying Node has been removed.
	// New CRs are protected by Node ownerReferences (set in upsertOwnPeer),
	// so this loop is the safety net for entries created before that fix.
	a.cleanupOrphanedPeers(ctx, peerList)

	// Update Prometheus metrics.
	a.updateMetrics(ctx, peerList)

	// Measure peer latency every 5th sync cycle (~2.5 min) to avoid overhead.
	a.latencyCycle++
	if a.latencyCycle%5 == 0 {
		go a.measurePeerLatency(peerList)
	}

	return nil
}

// orphanGracePeriod is how long a WireKubePeer must have existed before
// cleanupOrphanedPeers will consider it for deletion when its owning Node
// is absent. The grace window prevents a transient Node list staleness
// (control-plane hiccup, agent restart, propagation lag during cluster
// scale-up) from racing with a brand-new peer whose Node has not yet
// surfaced in this agent's cache. Tuned well above any realistic
// propagation delay and well below the WG handshake window so the worst
// case is a 10-minute lag in cleanup, not silent peer deletion.
const orphanGracePeriod = 10 * time.Minute

// agentManagedPeerLabel marks a WireKubePeer as belonging to a K8s Node
// (set by upsertOwnPeer). Manually-created external peers (home PCs,
// remote VMs — see WireKubePeer type doc) do not carry this label and
// are exempt from cleanup so user-managed CRs are never silently
// deleted.
const agentManagedPeerLabel = "wirekube.io/node"

// cleanupOrphanedPeers deletes agent-managed WireKubePeer CRs whose
// corresponding K8s Node no longer exists. The recommended cleanup
// path is the Node ownerReference set by upsertOwnPeer — K8s garbage
// collection cascade-deletes the peer the moment the Node disappears.
// This loop is the safety net for two cases:
//   - CRs created before ownerReference support existed.
//   - CRs whose ownerReference has been stripped externally (manual edit)
//     and which would otherwise leak forever.
//
// Scope: only peers with the agentManagedPeerLabel are eligible. The
// agent's own peer is also exempt — that record is owned by the local
// cleanup() path on graceful shutdown. Concurrent Delete races across
// agents are tolerated via IsNotFound.
func (a *Agent) cleanupOrphanedPeers(ctx context.Context, peerList *wirekubev1alpha1.WireKubePeerList) {
	nodeList := &corev1.NodeList{}
	if err := a.client.List(ctx, nodeList); err != nil {
		a.log.V(1).Info("cleanupOrphanedPeers: listing nodes failed", "error", err)
		return
	}
	nodeNames := make(map[string]struct{}, len(nodeList.Items))
	for _, n := range nodeList.Items {
		nodeNames[n.Name] = struct{}{}
	}

	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == a.nodeName {
			continue
		}
		if _, agentManaged := p.Labels[agentManagedPeerLabel]; !agentManaged {
			continue
		}
		if _, alive := nodeNames[p.Name]; alive {
			continue
		}
		if time.Since(p.CreationTimestamp.Time) < orphanGracePeriod {
			continue
		}
		err := a.client.Delete(ctx, p)
		switch {
		case err == nil:
			a.log.Info("deleted orphaned WireKubePeer", "peer", p.Name, "reason", "no corresponding K8s Node")
		case apierrors.IsNotFound(err):
			a.log.V(1).Info("orphan already deleted by another agent", "peer", p.Name)
		default:
			a.log.Error(err, "deleting orphaned WireKubePeer", "peer", p.Name)
		}
	}
}

func (a *Agent) peerHadTrafficSinceLastSync(pubKey string, current wireguard.PeerStats) bool {
	prev, ok := a.peerTrafficSnapshots[pubKey]
	if !ok {
		return false
	}
	return current.BytesSent > prev.bytesSent || current.BytesReceived > prev.bytesReceived
}

func (a *Agent) peerHadMeaningfulTrafficSinceLastSync(pubKey string, current wireguard.PeerStats) bool {
	prev, ok := a.peerTrafficSnapshots[pubKey]
	if !ok {
		return false
	}
	deltaSent := current.BytesSent - prev.bytesSent
	if deltaSent < 0 {
		deltaSent = 0
	}
	deltaRecv := current.BytesReceived - prev.bytesReceived
	if deltaRecv < 0 {
		deltaRecv = 0
	}
	return deltaSent+deltaRecv > meaningfulTrafficDeltaBytes
}

func (a *Agent) recordPeerTrafficSnapshots(stats map[string]wireguard.PeerStats) {
	if a.peerTrafficSnapshots == nil {
		a.peerTrafficSnapshots = make(map[string]peerTrafficSnapshot, len(stats))
	}
	for pubKey, s := range stats {
		a.peerTrafficSnapshots[pubKey] = peerTrafficSnapshot{
			bytesSent:     s.BytesSent,
			bytesReceived: s.BytesReceived,
			lastDirectRX:  a.wgMgr.LastDirectReceive(pubKey),
		}
	}
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
		if time.Since(s.LastHandshake) > a.handshakeValidWindow {
			continue
		}
		if s.ActualEndpoint == p.Spec.Endpoint {
			continue
		}
		if isLocalhostEndpoint(s.ActualEndpoint) {
			continue
		}

		crdHost, _, crdErr := net.SplitHostPort(p.Spec.Endpoint)
		actualHost, _, actualErr := net.SplitHostPort(s.ActualEndpoint)
		if crdErr == nil && actualErr == nil {
			if crdHost == actualHost {
				// For symmetric NAT: same IP, different port = per-destination mapping.
				// Skip to avoid poisoning the CRD with an unstable port.
				// For cone NAT: same IP, different port = the actual stable NAT-mapped port
				// for this peer's WireGuard socket (e.g. when STUN couldn't bind to the WG
				// port during a preserved-interface restart and substituted listenPort).
				// Allow the update so future probes use the correct port.
				if p.Status.NATType != "cone" {
					continue
				}
			}
			// Never downgrade a public IP to a private IP. The kernel may hold
			// a stale private endpoint from before the peer switched to relay.
			actualIP := net.ParseIP(actualHost)
			crdIP := net.ParseIP(crdHost)
			if actualIP != nil && crdIP != nil && !crdIP.IsPrivate() && actualIP.IsPrivate() {
				continue
			}
		}

		a.log.V(1).Info("NAT endpoint reflection, patching peer", "peer", p.Name, "crdEndpoint", p.Spec.Endpoint, "actualEndpoint", s.ActualEndpoint)
		patch := client.MergeFrom(p.DeepCopy())
		p.Spec.Endpoint = s.ActualEndpoint
		if patchErr := a.client.Patch(ctx, p, patch); patchErr != nil {
			a.log.Error(patchErr, "NAT endpoint reflection patch failed", "peer", p.Name)
		}
	}
}

// filterRoutesForConnectedPeers returns CIDRs that are safe to install in the
// WireKube routing table. Direct-only peers still need a WireGuard handshake
// before routes are installed. Relay-capable peers may need routes before the
// first handshake because their first useful traffic can itself be what proves
// the relay path. API server CIDRs are never routed through WireKube.
func (a *Agent) filterRoutesForConnectedPeers(allRoutes []string, routeOwners map[string]string, allowBeforeHandshake map[string]bool) []string {
	stats, err := a.wgMgr.GetStats()
	if err != nil {
		a.log.Info("filterRoutes: GetStats failed, deferring all routes", "error", err)
		return nil // can't check, defer all routes until GetStats works
	}

	connected := make(map[string]bool)
	for _, s := range stats {
		a.log.V(1).Info("filterRoutes: peer stats", "pubKey", s.PublicKeyB64[:8], "lastHandshake", s.LastHandshake, "isZero", s.LastHandshake.IsZero())
		if !s.LastHandshake.IsZero() {
			connected[s.PublicKeyB64] = true
		}
	}
	a.log.Info("filterRoutes", "totalStats", len(stats), "connectedPeers", len(connected), "totalRoutes", len(allRoutes))

	var result []string
	for _, cidr := range allRoutes {
		// Never route API server traffic through the WG tunnel.
		// The ip rule (priority 199) provides primary protection, but
		// skipping the route entirely avoids any edge cases.
		if a.isAPIServerCIDR(cidr) {
			continue
		}
		key, ok := routeOwners[cidr]
		if !ok || connected[key] || allowBeforeHandshake[key] {
			result = append(result, cidr)
		}
	}
	return result
}

func (a *Agent) canRouteBeforeHandshake(peerName string) bool {
	if peerName == "" || a.relayMode == relayModeNever || !a.relayTransportUsable() {
		return false
	}
	if a.relayedPeers[peerName] {
		return true
	}
	if a.pathMonitor == nil {
		return false
	}
	switch a.pathMonitor.ModeFor(peerName) {
	case PathModeRelay, PathModeWarm:
		return true
	default:
		return false
	}
}

// updateOwnStatus reads WireGuard stats and updates this node's WireKubePeer status.
func (a *Agent) updateOwnStatus(
	ctx context.Context,
	peerName string,
	remotePeerNames []string,
	remotePeers map[string]*wirekubev1alpha1.WireKubePeer,
	statsByKey map[string]wireguard.PeerStats,
) error {
	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return err
	}

	if statsByKey == nil {
		stats, err := a.wgMgr.GetStats()
		if err != nil {
			return err
		}
		statsByKey = make(map[string]wireguard.PeerStats, len(stats))
		for _, s := range stats {
			statsByKey[s.PublicKeyB64] = s
		}
	}

	var totalRx, totalTx int64
	var lastHandshake time.Time
	for _, s := range statsByKey {
		totalRx += s.BytesReceived
		totalTx += s.BytesSent
		if !s.LastHandshake.IsZero() && s.LastHandshake.After(lastHandshake) {
			lastHandshake = s.LastHandshake
		}
	}

	connected := a.allRemotePeersTransportUsable(ctx, remotePeerNames, statsByKey)

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

	// Write per-peer transport view and aggregated counts.
	return a.updatePeerConnections(ctx, peerName, remotePeerNames, remotePeers, statsByKey)
}

// updatePeerConnections writes this node's per-peer transport view to its own
// WireKubePeer status and updates aggregate counts in WireKubeMesh.
// Each agent writes only to its own peer, avoiding write conflicts at scale.
func (a *Agent) updatePeerConnections(
	ctx context.Context,
	myNode string,
	remotePeerNames []string,
	remotePeers map[string]*wirekubev1alpha1.WireKubePeer,
	statsByKey map[string]wireguard.PeerStats,
) error {
	// Build connections map (this node's view of each remote peer).
	connections := make(map[string]string, len(remotePeerNames))
	for _, name := range remotePeerNames {
		connections[name] = a.publishedTransportForPeer(remotePeers[name], statsByKey)
	}
	a.log.V(1).Info("publishing transport view", "peer", myNode, "connections", connections)

	// Write connections to own WireKubePeer status.
	ownPeer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: myNode}, ownPeer); err != nil {
		return err
	}
	peerPatch := client.MergeFrom(ownPeer.DeepCopy())
	ownPeer.Status.Connections = connections
	if err := a.client.Status().Patch(ctx, ownPeer, peerPatch); err != nil {
		return err
	}

	// Update ReadyPeers/TotalPeers in WireKubeMesh (aggregate counts).
	// Multiple agents write these concurrently; last-write-wins is acceptable
	// since the values are eventually consistent approximations.
	mesh, err := a.getMesh(ctx)
	if err != nil {
		return err
	}
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
	meshPatch := client.MergeFrom(mesh.DeepCopy())
	mesh.Status.ReadyPeers = readyCount
	mesh.Status.TotalPeers = int32(len(peerList.Items))
	return a.client.Status().Patch(ctx, mesh, meshPatch)
}

// publishedTransportForPeer reports the user-visible transport mode for a
// peer ("direct" vs "relay"). PathMonitor is the single source of truth: only
// PathModeDirect (confirmed via fresh direct-receive evidence) publishes as
// "direct"; PathModeWarm (direct unproven or being demoted), PathUnknown, and
// PathModeRelay all publish as "relay", so the status never reports a probing
// or unknown path as confirmed direct.
// driveTransportMode asks PathMonitor for the current mode of every known
// peer and commits it to the Bind via SetPeerPath. This runs at the end of
// sync() and is authoritative — it overrides any intermediate SetPeerPath
// calls the legacy ICE code may have made earlier in the pipeline.
//
// For now we pass forceProbe=false unconditionally: PathMonitor's internal
// relayRetry backoff decides when Relay peers are probed for an opportunistic
// promotion to Warm. Future callers (e.g. an ICE layer that detects a peer
// initiating a handshake) can use pathMonitor.Evaluate(..., true) directly.
//
// The directAddr passed to SetPeerPath is the peer's configured endpoint.
// For symmetric-NAT peers where the real endpoint differs from the CRD
// advertisement, directEndpoints[name] holds the discovered NAT-mapped
// address; use that when present.
func (a *Agent) driveTransportMode(
	peerNames []string,
	peers map[string]*wirekubev1alpha1.WireKubePeer,
) {
	if a.pathMonitor == nil {
		return
	}
	for _, name := range peerNames {
		peer := peers[name]
		if peer == nil || peer.Spec.PublicKey == "" {
			continue
		}
		mode := a.pathMonitor.Evaluate(name, peer.Spec.PublicKey, false)
		directAddr := peer.Spec.Endpoint
		if ep, ok := a.directEndpoints[name]; ok && ep != "" {
			directAddr = ep
		}
		if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, mode.toWireguardPathMode(), directAddr); err != nil {
			a.log.Error(err, "SetPeerPath failed", "peer", name, "mode", mode)
		}
		// Mirror PathMonitor into the legacy relayedPeers map so any path
		// still reading that map (preferredTransportForPeer, forceEndpoint
		// decisions, restart-recovery checks) observes the same decision
		// PathMonitor made. ICE paths still write relayedPeers directly,
		// but this assignment happens at the end of every sync tick and
		// therefore wins, collapsing the old racing-writers problem.
		if mode == PathModeRelay {
			a.relayedPeers[name] = true
		} else {
			delete(a.relayedPeers, name)
		}
	}
	// Forget state for peers that disappeared.
	a.pathMonitor.ForgetMissing(peerNames)
}

func (a *Agent) publishedTransportForPeer(
	peer *wirekubev1alpha1.WireKubePeer,
	_ map[string]wireguard.PeerStats,
) string {
	// Only a confirmed direct path is reported as "direct". PathMonitor enters
	// PathModeDirect only after fresh direct-receive evidence; PathModeWarm
	// (direct unproven or being demoted), PathUnknown (not yet evaluated), and
	// PathModeRelay all report "relay" so the status never overstates a direct
	// path as confirmed. A nil peer or nil pathMonitor (test-only literal) has no
	// evidence of direct connectivity, so it reports the conservative "relay".
	if peer == nil || a.pathMonitor == nil {
		return "relay"
	}
	if a.pathMonitor.ModeFor(peer.Name) == PathModeDirect {
		return "direct"
	}
	return "relay"
}

// initRelay sets up the relay client from the mesh relay configuration.
func (a *Agent) initRelay(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh, myPubKeyB64 string) error {
	if mesh.Spec.Relay == nil {
		return nil
	}

	relay := mesh.Spec.Relay
	a.relayMode = relay.Mode
	if a.relayMode == relayModeNever {
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

	// Configurable handshake windows and health probe from NATTraversal spec.
	a.handshakeValidWindow = defaultHandshakeValidWindow
	a.directConnectedWindow = defaultDirectConnectedWindow
	a.healthProbeTimeout = 5 * time.Second
	if mesh.Spec.NATTraversal != nil {
		if v := mesh.Spec.NATTraversal.HandshakeValidWindowSeconds; v >= 5 {
			a.handshakeValidWindow = time.Duration(v) * time.Second
		}
		if v := mesh.Spec.NATTraversal.HealthProbeTimeoutSeconds; v >= 1 {
			a.healthProbeTimeout = time.Duration(v) * time.Second
		}
		if v := mesh.Spec.NATTraversal.DirectConnectedWindowSeconds; v > 0 {
			a.directConnectedWindow = time.Duration(v) * time.Second
		} else if a.handshakeValidWindow != defaultHandshakeValidWindow {
			// Auto-derive: handshakeValidWindow + 2 min grace
			a.directConnectedWindow = a.handshakeValidWindow + 2*time.Minute
		}
		// Enforce minimum: directConnectedWindow >= handshakeValidWindow + 30s
		if a.directConnectedWindow < a.handshakeValidWindow+30*time.Second {
			a.directConnectedWindow = a.handshakeValidWindow + 30*time.Second
		}
	}

	// After restart with a preserved interface, use a shorter initial retry
	// so direct upgrade probing starts quickly instead of waiting the full 120s.
	if a.wasInterfacePreserved {
		a.relayRetry = restartRelayRetry
		a.log.Info("interface preserved, using shortened relay retry for initial probing", "interval", a.relayRetry)
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
		endpoint = managedRelayControlEndpoint(a.podNamespace, port)
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
	a.relayPool = agentrelay.NewPool(endpoint, pubKey, wgPort)
	proxyMode := a.relayProxyMode(ctx)
	a.relayPool.SetProxyMode(proxyMode)
	a.log.Info("relay proxy configured", "wgPort", wgPort, "proxyMode", proxyMode)

	// Inject relay transport into the WG engine BEFORE Connect so that even
	// if the initial dial fails, the Bind is wired up and ready when the
	// background reconnect loop eventually succeeds.
	a.wgMgr.SetRelayTransport(a.relayPool)

	// In userspace mode, route incoming relay packets directly to the Bind
	// instead of through UDPProxy.
	type relayDeliverer interface {
		DeliverRelayPacket(wireguard.RelayPacket)
	}
	if rd, ok := a.wgMgr.(relayDeliverer); ok {
		a.relayPool.SetBindDelivery(func(pkt agentrelay.DeliveredPacket) {
			rd.DeliverRelayPacket(wireguard.RelayPacket{
				SrcKey: pkt.SrcKey,
				ExternalSource: wireguard.ExternalSource{
					Valid:     pkt.ExternalSource.Valid,
					RelayAddr: pkt.ExternalSource.RelayAddr,
					Token:     pkt.ExternalSource.Token,
					Addr:      pkt.ExternalSource.Addr,
				},
				Payload: pkt.Payload,
			})
		})
		a.log.Info("relay bind-delivery enabled (userspace mode)")
	}

	// Wire the relay-delivered bimodal hint through to the engine so the Bind
	// can dual-send to a peer that has told us its inbound direct leg is
	// blackholed. This is the cross-peer signal Tailscale provides through
	// disco; without it, asymmetric UDP drops stall for ~30s.
	a.relayPool.SetBimodalHintHandler(func(srcKey [32]byte) {
		a.wgMgr.MarkBimodalHint(srcKey)
	})

	if err := a.relayPool.Connect(ctx); err != nil {
		a.log.Error(err, "relay initial connect failed, will retry in background", "endpoint", endpoint)
		return nil
	}

	a.log.Info("relay connected", "endpoint", endpoint, "mode", a.relayMode)
	return nil
}

func (a *Agent) relayProxyMode(ctx context.Context) agentrelay.ProxyMode {
	defaultMode := agentrelay.ProxyDisabled
	if mode, ok := parseRelayProxyMode(os.Getenv(envRelayProxyMode)); ok {
		defaultMode = mode
	}

	node := &corev1.Node{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.nodeName}, node); err != nil {
		a.log.Error(err, "failed to read node relay proxy annotation; using default relay proxy policy", "annotation", nodeAnnotationRelayProxy, "defaultMode", defaultMode)
		return defaultMode
	}
	raw := strings.ToLower(strings.TrimSpace(node.Annotations[nodeAnnotationRelayProxy]))
	if raw == "" {
		return defaultMode
	}
	if mode, ok := parseRelayProxyMode(raw); ok {
		return mode
	}
	a.log.Info("unknown relay proxy annotation value; using default relay proxy policy", "annotation", nodeAnnotationRelayProxy, "value", raw, "defaultMode", defaultMode)
	return defaultMode
}

func parseRelayProxyMode(raw string) (agentrelay.ProxyMode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "env", "environment", "enabled", "enable", "true", "on", "proxy":
		return agentrelay.ProxyFromEnvironment, true
	case "disabled", "disable", "false", "off", "direct", "none":
		return agentrelay.ProxyDisabled, true
	default:
		return agentrelay.ProxyDisabled, false
	}
}

func managedRelayControlEndpoint(namespace string, port int32) string {
	if namespace == "" {
		namespace = "wirekube-system"
	}
	return fmt.Sprintf("wirekube-relay-control.%s.svc.cluster.local:%d", namespace, port)
}

func (a *Agent) preferredTransportForPeer(peerName string) string {
	if a.relayedPeers[peerName] {
		return "relay"
	}
	return "direct"
}

func (a *Agent) hasPendingRestartRelayRecovery(remotePeerNames []string) bool {
	for _, name := range remotePeerNames {
		if a.relayedPeers[name] {
			return true
		}
		state := a.getICEState(name)
		switch state.State {
		case iceStateRelay, iceStateChecking, iceStateFailed:
			return true
		}
	}
	return false
}

func (a *Agent) relayTransportUsable() bool {
	return a.relayPool != nil && a.relayPool.IsConnected()
}

func (a *Agent) peerTransportUsable(peer *wirekubev1alpha1.WireKubePeer, stats map[string]wireguard.PeerStats) bool {
	if a.preferredTransportForPeer(peer.Name) == "relay" {
		return a.relayTransportUsable()
	}
	return a.hasUsableWireGuardPath(peer, stats)
}

func (a *Agent) allRemotePeersTransportUsable(ctx context.Context, remotePeerNames []string, stats map[string]wireguard.PeerStats) bool {
	if len(remotePeerNames) == 0 {
		return false
	}

	for _, name := range remotePeerNames {
		if a.preferredTransportForPeer(name) == "relay" {
			if !a.relayTransportUsable() {
				return false
			}
			continue
		}

		remote := &wirekubev1alpha1.WireKubePeer{}
		if err := a.client.Get(ctx, client.ObjectKey{Name: name}, remote); err == nil {
			if !a.peerTransportUsable(remote, stats) {
				return false
			}
			continue
		}

		return false
	}

	return true
}

// resolveEndpointForPeer determines the effective WireGuard endpoint for a peer.
//
// Relay-first strategy (DERP-like):
//   - New peers start on relay immediately for instant connectivity.
//   - ICE negotiation runs in the background to upgrade to a direct path.
//   - If a direct probe is active, the direct endpoint is returned temporarily.
//   - Birthday-attack hole-punched paths use a local proxy address.
func (a *Agent) resolveEndpointForPeer(peer *wirekubev1alpha1.WireKubePeer, stats map[string]wireguard.PeerStats) string {
	if a.relayPool == nil || a.relayMode == relayModeNever {
		return peer.Spec.Endpoint
	}

	if a.relayMode == relayModeAlways {
		return a.enableRelayForPeer(peer)
	}

	// If peer has a birthday-attack hole-punched path, use it.
	if hp, ok := a.holePunchEndpoints[peer.Name]; ok && hp != "" {
		return hp
	}

	directEndpoint := func() string {
		if peer.Status.NATType == "symmetric" {
			if ep := a.directEndpoints[peer.Name]; ep != "" && !isLocalhostEndpoint(ep) {
				return ep
			}
			return ""
		}
		return peer.Spec.Endpoint
	}

	// If ICE has determined this peer is directly reachable (post-upgrade),
	// use the direct endpoint. For symmetric NAT peers, use the NAT-mapped
	// endpoint discovered during probe Phase 2 (stored in directEndpoints).
	// If no discovered endpoint exists, return "" so WG keeps its kernel-learned port.
	//
	// However, if the WG handshake has expired (no recent handshake or endpoint
	// is localhost), fall through to relay. This handles the case where WG UDP
	// is blocked after a successful direct upgrade — without this check, the
	// peer stays stuck in iceStateConnected with no actual connectivity.
	iceState := a.getICEState(peer.Name)
	if iceState.State == iceStateConnected && !a.relayedPeers[peer.Name] {
		if a.isDirectConnected(peer, stats) {
			return directEndpoint()
		}
		// Handshake expired or endpoint is localhost — fall through to relay.
	}

	// If peer is being probed for direct connectivity, temporarily use direct.
	if a.directProbing[peer.Name] {
		if ep := a.directEndpoints[peer.Name]; ep != "" {
			// Anchor LastCheck to when the endpoint is first written into WG config
			// (via SyncPeers, which runs before tryDirectUpgrade in the same sync).
			// Without this, evaluateICECheck sees LastCheck from startICECheck (one
			// sync cycle earlier) and evaluates before WG has time to handshake.
			if !iceState.directProbeApplied {
				iceState.directProbeApplied = true
				iceState.LastCheck = time.Now()
				a.setICEState(peer.Name, iceState)
			}
			return ep
		}
	}

	// If the dataplane already proves the peer is directly reachable, prefer
	// direct immediately even if a stale relay preference is still set. This
	// keeps relayedPeers from masking an already-recovered direct path after
	// restart or relay-mode transitions.
	if a.isDirectConnected(peer, stats) {
		if a.relayedPeers[peer.Name] {
			a.log.Info("direct dataplane observed while relay preferred, promoting peer", "peer", peer.Name)
			a.upgradeToDirect(peer, "")
		}
		iceState.State = iceStateConnected
		a.setICEState(peer.Name, iceState)
		return directEndpoint()
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
		a.log.V(2).Info("enableRelayForPeer: relayPool is nil, returning direct", "peer", peer.Name)
		return peer.Spec.Endpoint
	}

	if !a.relayPool.IsConnected() {
		a.log.V(2).Info("enableRelayForPeer: relayPool not connected, returning direct", "peer", peer.Name)
		return peer.Spec.Endpoint
	}

	// In userspace mode (bind delivery active), relay packets flow through
	// the WireKubeBind directly — no UDPProxy needed. Track the peer as
	// relayed, set the Bind's path mode to Relay, and return the original
	// endpoint. The Bind's Send() checks pathTable and routes via relay.
	if a.relayPool.HasBindDelivery() {
		if !a.relayedPeers[peer.Name] {
			a.directEndpoints[peer.Name] = peer.Spec.Endpoint
			a.relayedPeers[peer.Name] = true
			a.log.Info("peer using relay via bind (userspace mode)", "peer", peer.Name)
		}
		// Set PathModeRelay in the Bind so Send() routes through relay.
		if err := a.wgMgr.SetPeerPath(peer.Spec.PublicKey, wireguard.PathRelay, peer.Spec.Endpoint); err != nil {
			a.log.Error(err, "failed to set relay path", "peer", peer.Name)
		}
		a.log.V(1).Info("relay preference set", "peer", peer.Name, "mode", "relay", "directEndpoint", peer.Spec.Endpoint)
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
		a.log.Error(err, "failed to create relay proxy", "peer", peer.Name)
		return peer.Spec.Endpoint
	}

	if !a.relayedPeers[peer.Name] {
		a.directEndpoints[peer.Name] = peer.Spec.Endpoint
		a.relayedPeers[peer.Name] = true
		a.log.Info("peer falling back to relay", "peer", peer.Name, "proxyAddr", proxy.ListenAddr())
	}

	return proxy.ListenAddr()
}

// prewarmAllPeerRelays ensures a relay proxy exists for every remote peer,
// even peers currently on a direct path. The proxy sits idle in standby
// mode but is immediately available if the direct path fails, providing
// zero-delay failover.
func (a *Agent) prewarmAllPeerRelays(peerList *wirekubev1alpha1.WireKubePeerList) {
	if a.relayPool == nil || !a.relayPool.IsConnected() {
		return
	}
	if a.relayMode == relayModeNever {
		return
	}
	// In userspace mode (bind delivery active), relay packets flow through
	// the WireKubeBind — UDPProxy pre-warming is unnecessary.
	if a.relayPool.HasBindDelivery() {
		return
	}
	for i := range peerList.Items {
		p := &peerList.Items[i]
		if p.Name == a.nodeName || p.Spec.PublicKey == "" {
			continue
		}
		if a.relayedPeers[p.Name] {
			continue
		}
		var pubKey [relayproto.PubKeySize]byte
		keyBytes, err := base64.StdEncoding.DecodeString(p.Spec.PublicKey)
		if err != nil {
			continue
		}
		copy(pubKey[:], keyBytes)
		if _, err := a.relayPool.GetOrCreateProxy(pubKey); err != nil {
			a.log.Error(err, "failed to pre-warm relay proxy", "peer", p.Name)
		}
	}
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

// recoverICEStateFromWG inspects WireGuard kernel state after a restart and
// pre-populates ICE state for peers that already have a healthy direct connection.
// Without this, all peers would start in iceStateRelay and wait relayRetry (120s)
// before the first direct upgrade attempt, causing unnecessary relay detours.
func (a *Agent) recoverICEStateFromWG() {
	stats, err := a.wgMgr.GetStats()
	if err != nil || len(stats) == 0 {
		return
	}

	recovered := 0
	for _, s := range stats {
		if s.LastHandshake.IsZero() || time.Since(s.LastHandshake) > a.handshakeValidWindow {
			continue
		}
		if s.ActualEndpoint == "" || isLocalhostEndpoint(s.ActualEndpoint) {
			continue
		}

		peerName := a.findPeerNameByKey(s.PublicKeyB64)
		if peerName == "" {
			continue
		}

		// In userspace mode, bind-local direct RX history is lost across an
		// agent restart even when the preserved WG interface is still talking
		// directly to the peer. Treat a fresh non-localhost endpoint on a
		// preserved interface as restart-time direct evidence, and only fall
		// back to relay when we neither have recent bind proof nor preserved
		// direct WG state.
		if lastDirect := a.wgMgr.LastDirectReceive(s.PublicKeyB64); lastDirect >= 0 {
			hasRecentDirectRX := lastDirect > 0 && time.Since(time.Unix(0, lastDirect)) <= a.recentDirectReceiveWindow()
			if !hasRecentDirectRX && !a.wasInterfacePreserved {
				state := a.getICEState(peerName)
				state.State = iceStateRelay
				state.LastCheck = time.Time{}      // immediate reprobe
				state.NextProbeAfter = time.Time{} // no cooldown on restart recovery
				a.setICEState(peerName, state)
				continue
			}
		}

		state := a.getICEState(peerName)
		state.State = iceStateConnected
		state.FailCount = 0
		// This is restart recovery, not a fresh promotion. Keep the original
		// handshake window semantics so active peers still fail over promptly
		// if direct traffic does not resume after restart.
		state.UpgradedAt = time.Time{}
		a.directEndpoints[peerName] = s.ActualEndpoint
		delete(a.relayedPeers, peerName)
		a.setICEState(peerName, state)
		recovered++
	}

	if recovered > 0 {
		a.log.Info("recovered peers with existing direct connections", "count", recovered)
	}
}

// findPeerNameByKey resolves a WireGuard public key to the WireKubePeer name.
func (a *Agent) findPeerNameByKey(pubKeyB64 string) string {
	peerList := &wirekubev1alpha1.WireKubePeerList{}
	if err := a.client.List(context.Background(), peerList); err != nil {
		return ""
	}
	for _, p := range peerList.Items {
		if p.Spec.PublicKey == pubKeyB64 {
			return p.Name
		}
	}
	return ""
}

// keepaliveForPeer honours the peer CR's PersistentKeepalive, but shortens
// to 10s when THIS node sits behind a symmetric or port-restricted-cone
// NAT. Measured NCloud shared-NAT TTL sits below the default 25s: a ping
// started while the pinhole is closed loses ~10 packets before the next
// keepalive re-opens it. Tailscale can keep a fixed interval because it
// targets typical home/office NATs with longer TTL — this override is
// WireKube's concession to shared-CGNAT-grade deployments.
func (a *Agent) keepaliveForPeer(p *wirekubev1alpha1.WireKubePeer) int {
	ka := int(p.Spec.PersistentKeepalive)
	switch a.detectedNATType {
	case string(nat.NATSymmetric), string(nat.NATPortRestrictedCone):
		if ka == 0 || ka > 10 {
			ka = 10
		}
	}
	return ka
}

// nodeInternalIP returns the first InternalIP from the node's status addresses.
func nodeInternalIP(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return ""
}

// nodeAnnotationInternalIP is an optional per-node override for the address
// that autoAllowedIPs publishes. Cloud providers that attach a public IP
// directly to the NIC (Oracle Cloud, NCloud) make Node.InternalIP itself a
// public address, which defeats the point of "also route by private IP".
// Operators can set this annotation on the Node to force a specific private
// address into AllowedIPs without touching kubelet flags.
const nodeAnnotationInternalIP = "wirekube.io/internal-ip"

// preferredPeerInternalIP picks the address that autoAllowedIPs should
// append to a peer's AllowedIPs. It NEVER returns a public address even as
// a fallback — publishing a public IP in AllowedIPs silently rewrites
// routes for that IP onto the WireGuard interface, which in practice
// hijacks SSH / kubelet / apiserver traffic the first time the tunnel
// flaps. Priority:
//
//  1. Node annotation wirekube.io/internal-ip (operator override).
//  2. A Node.status.addresses entry of type InternalIP whose address is
//     in a private RFC1918 / CGNAT / loopback range.
//  3. Any Node.status.addresses entry (any type) whose address is private.
//  4. Empty string — autoAllowedIPs does not apply to this node. The
//     operator can still publish an address by setting the annotation.
func preferredPeerInternalIP(node *corev1.Node) string {
	if node == nil {
		return ""
	}
	if v, ok := node.Annotations[nodeAnnotationInternalIP]; ok {
		ip := net.ParseIP(strings.TrimSpace(v))
		if ip != nil && isPrivateOrLocal(ip) {
			return ip.String()
		}
	}
	var firstPrivateAny string
	for _, addr := range node.Status.Addresses {
		ip := net.ParseIP(addr.Address)
		if ip == nil || !isPrivateOrLocal(ip) {
			continue
		}
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
		if firstPrivateAny == "" {
			firstPrivateAny = addr.Address
		}
	}
	if firstPrivateAny != "" {
		return firstPrivateAny
	}
	// Cloud providers that attach a public IP directly to the NIC often
	// advertise that public IP as Node.InternalIP, leaving no private
	// address visible through the Kubernetes API at all. But the host
	// interface still has a private secondary (e.g. Oracle Cloud's
	// 10.0.0.0/24 on enp0s6 alongside the public /32). Scan local
	// interfaces as a last resort — still strictly filtering to private
	// ranges so we never end up advertising a public IP.
	return firstLocalPrivateIPv4()
}

// firstLocalPrivateIPv4 returns the first private IPv4 address found on a
// non-loopback, non-virtual interface. Returns empty when no private
// address exists — in that case autoAllowedIPs simply does not apply to
// this node, which is deliberate: we must never auto-publish a public IP.
func firstLocalPrivateIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			if isPrivateOrLocal(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

// isPrivateOrLocal reports whether ip is in a range that is safe to
// advertise via AllowedIPs without risking route-hijack of publicly
// addressable services. Excludes IsUnspecified / multicast implicitly.
func isPrivateOrLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// annotateOwnPod sets the wirekube.io/node-internal-ip annotation on the agent's
// own pod so that ServiceMonitor relabeling can replace the scrape address with
// the WireGuard-reachable internal IP instead of the public host IP.
func (a *Agent) annotateOwnPod(ctx context.Context, internalIP string) {
	pod := &corev1.Pod{}
	if err := a.client.Get(ctx, client.ObjectKey{Name: a.podName, Namespace: a.podNamespace}, pod); err != nil {
		a.log.Error(err, "getting own pod for metrics annotation")
		return
	}
	if pod.Annotations != nil && pod.Annotations["wirekube.io/node-internal-ip"] == internalIP {
		return
	}
	patch := client.MergeFrom(pod.DeepCopy())
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["wirekube.io/node-internal-ip"] = internalIP
	if err := a.client.Patch(ctx, pod, patch); err != nil {
		a.log.Error(err, "annotating own pod with node internal IP")
	}
}
