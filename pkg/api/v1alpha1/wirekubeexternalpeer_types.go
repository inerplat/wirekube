package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExternalPeerPhase represents the lifecycle phase of a WireKubeExternalPeer.
// +kubebuilder:validation:Enum=Pending;Active;Revoked;Failed
type ExternalPeerPhase string

const (
	// DefaultExternalPeerMTU is the conservative MTU rendered for official
	// WireGuard clients that enter through the shared relay listener. It is
	// lower than the in-cluster WireKube MTU because external VM-to-VM traffic
	// traverses both the raw-WireGuard relay leg and an in-cluster mesh hop.
	DefaultExternalPeerMTU int32 = 1248
)

const (
	// ExternalPeerPhasePending indicates the controller has not yet allocated
	// resources (mesh IP, relay port, keypair) for this peer.
	ExternalPeerPhasePending ExternalPeerPhase = "Pending"

	// ExternalPeerPhaseActive indicates resources are allocated and the
	// rendered conf is usable. The peer may or may not currently be connected.
	ExternalPeerPhaseActive ExternalPeerPhase = "Active"

	// ExternalPeerPhaseRevoked indicates the peer has been administratively
	// revoked. Existing tunnels are torn down and no new handshakes are accepted.
	ExternalPeerPhaseRevoked ExternalPeerPhase = "Revoked"

	// ExternalPeerPhaseFailed indicates the controller could not satisfy the
	// spec (e.g. mesh CIDR exhausted, relay port pool exhausted). See
	// status.conditions for details.
	ExternalPeerPhaseFailed ExternalPeerPhase = "Failed"
)

// WireKubeExternalPeerSpec defines the desired state of a WireKubeExternalPeer.
// External peers are off-cluster hosts (laptops, home machines) that join the
// mesh through an elected ingress WireKubePeer via the relay's shared
// raw-WireGuard UDP listener. They run only the official WireGuard client — no
// WireKube binary on the host.
type WireKubeExternalPeerSpec struct {
	// DisplayName is the human-readable label for this peer (shown in dashboards
	// and CLI output). It also seeds the deterministic /32 mesh-IP allocator,
	// so it must be stable for the lifetime of the peer.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	DisplayName string `json:"displayName"`

	// TTL, when set, instructs the controller to delete this CR after
	// metadata.creationTimestamp + ttl. Useful for time-boxed access (e.g.
	// temporary contractors). When unset, the peer lives until manually deleted.
	// +optional
	TTL *metav1.Duration `json:"ttl,omitempty"`

	// AllowedDestinations lists CIDR ranges this external peer is permitted
	// to reach through the mesh. The controller defaults this to the mesh
	// overlay CIDR plus the cluster pod CIDR(s) at admission/reconcile time
	// when left empty. Used to populate the AllowedIPs field of the rendered
	// WireGuard conf and to scope ingress-side routing.
	// +optional
	AllowedDestinations []string `json:"allowedDestinations,omitempty"`

	// MTU overrides the WireGuard interface MTU rendered into the official
	// client config. When unset, the controller records DefaultExternalPeerMTU
	// in status.mtu. External peers usually need a lower MTU than in-cluster
	// peers because VM-to-VM traffic crosses relay plus mesh encapsulation.
	// +optional
	// +kubebuilder:validation:Minimum=576
	// +kubebuilder:validation:Maximum=1420
	MTU int32 `json:"mtu,omitempty"`

	// IngressPeer, when set, pins this external peer to a specific WireKubePeer
	// by name. Useful when the operator wants the official WireGuard client to
	// use a particular node as its server identity. When empty, the controller
	// auto-selects the first ready WireKubePeer at allocation time and writes
	// the choice into status.ingressPeerName.
	// +optional
	IngressPeer string `json:"ingressPeer,omitempty"`

	// PublicKey is the external client's WireGuard public key. Issuance tooling
	// generates the keypair locally and stores only the public half in the
	// cluster; the private key is printed once and is never persisted.
	// +kubebuilder:validation:MinLength=44
	// +kubebuilder:validation:MaxLength=44
	PublicKey string `json:"publicKey"`
}

// WireKubeExternalPeerStatus defines the observed state of a
// WireKubeExternalPeer.
type WireKubeExternalPeerStatus struct {
	// AssignedMeshIP is the /32 address this peer occupies inside the mesh
	// overlay (e.g. "100.64.42.7/32"). Deterministically derived from
	// spec.displayName + WireKubeMesh.spec.meshCIDR by the controller.
	// +optional
	AssignedMeshIP string `json:"assignedMeshIP,omitempty"`

	// RelayPort is kept for compatibility with CRs issued by older versions that
	// allocated a per-peer relay UDP forwarder. New shared-listener peers leave
	// this empty and use RelayEndpoint directly.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	RelayPort int32 `json:"relayPort,omitempty"`

	// RelayEndpoint is the shared host:port string written into the rendered
	// conf's Endpoint field. Official WireGuard clients send raw WG UDP to this
	// single relay endpoint; the selected ingress agent authenticates the peer.
	// +optional
	RelayEndpoint string `json:"relayEndpoint,omitempty"`

	// PublicKey is the WireGuard public key in use for this peer. Mirrors
	// spec.publicKey.
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// IngressPeerName is the WireKubePeer name this external peer is bound to
	// as its official WireGuard server identity. Pinned at allocation time from
	// spec.ingressPeer or auto-selected. Migration to a different ingress peer
	// requires re-issuance.
	// +optional
	IngressPeerName string `json:"ingressPeerName,omitempty"`

	// IngressPublicKey is the WireGuard public key of the ingress peer. The
	// rendered conf places this in the [Peer] PublicKey field so the
	// external client can authenticate inbound traffic from the cluster.
	// Populated at allocation time from the selected ingress peer's
	// WireKubePeer.spec.publicKey; mirrors IngressPeerName.
	// +optional
	IngressPublicKey string `json:"ingressPublicKey,omitempty"`

	// AllowedDestinations is the effective AllowedIPs list rendered into
	// the external client's WireGuard conf. Mirrors Spec.AllowedDestinations
	// when the operator set one explicitly; otherwise the controller fills
	// it with the mesh overlay CIDR plus every Node's pod CIDR(s) so the
	// peer reaches both mesh nodes and pods through the ingress peer. The CLI
	// renders from this field rather than the spec so its output is
	// authoritative regardless of whether the operator overrode the
	// defaults.
	// +optional
	AllowedDestinations []string `json:"allowedDestinations,omitempty"`

	// MTU is the effective WireGuard interface MTU that clients should place in
	// the rendered [Interface] section. It mirrors spec.mtu when set; otherwise
	// it defaults to DefaultExternalPeerMTU.
	// +optional
	MTU int32 `json:"mtu,omitempty"`

	// Connected is reserved for ingress-observed client health. It is not set by
	// the allocation reconciler.
	// +optional
	Connected bool `json:"connected,omitempty"`

	// LastHandshake is reserved for the most recent WireGuard handshake observed
	// at the ingress peer for this peer's pubkey.
	// +optional
	LastHandshake *metav1.Time `json:"lastHandshake,omitempty"`

	// Phase is a coarse lifecycle label suitable for printer columns and
	// dashboards. See ExternalPeerPhase constants for the allowed values.
	// +optional
	Phase ExternalPeerPhase `json:"phase,omitempty"`

	// Conditions reflect the current detailed state of the external peer
	// (e.g. allocation success, revocation reason).
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wkep
// +kubebuilder:printcolumn:name="DisplayName",type=string,JSONPath=`.spec.displayName`
// +kubebuilder:printcolumn:name="MeshIP",type=string,JSONPath=`.status.assignedMeshIP`
// +kubebuilder:printcolumn:name="Ingress",type=string,JSONPath=`.status.ingressPeerName`
// +kubebuilder:printcolumn:name="MTU",type=integer,JSONPath=`.status.mtu`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireKubeExternalPeer represents an off-cluster host authorized to join the
// mesh through a selected ingress WireKubePeer via the relay's shared
// raw-WireGuard UDP listener. Lifecycle is owned by the cluster admin: the
// controller allocates a /32 on creation and tears it down on deletion or
// revocation.
type WireKubeExternalPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireKubeExternalPeerSpec   `json:"spec,omitempty"`
	Status WireKubeExternalPeerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WireKubeExternalPeerList contains a list of WireKubeExternalPeer.
type WireKubeExternalPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireKubeExternalPeer `json:"items"`
}
