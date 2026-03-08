package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireKubePeerSpec defines the desired state of WireKubePeer
type WireKubePeerSpec struct {
	// PublicKey is the WireGuard public key of this peer (base64 encoded).
	// Automatically set by the agent on the node this peer represents.
	// For manually created peers (external nodes, home PCs), set this explicitly.
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// Endpoint is the WireGuard endpoint address (host:port).
	// Must be a publicly reachable address. For NAT'd nodes this is the public IP:port.
	// Automatically discovered by the agent via STUN/cloud-metadata.
	// Can be overridden via the wirekube.io/endpoint node annotation.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// AllowedIPs is the list of CIDR ranges whose traffic will be routed through
	// this peer's WireGuard tunnel. Defined by the user — similar to site-to-site VPN.
	// Example: ["10.10.0.0/16", "192.168.1.0/24", "172.16.0.5/32"]
	// +optional
	AllowedIPs []string `json:"allowedIPs,omitempty"`

	// PersistentKeepalive specifies the keepalive interval in seconds.
	// Recommended value is 25 for peers behind NAT. Set to 0 to disable.
	// +optional
	// +kubebuilder:default=25
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	PersistentKeepalive int32 `json:"persistentKeepalive,omitempty"`
}

// ICECandidate represents a connectivity candidate discovered by the agent.
type ICECandidate struct {
	// Type is the candidate type: "host", "srflx", "relay", "prflx".
	Type string `json:"type"`

	// Address is the candidate address (IP:port).
	Address string `json:"address"`

	// Priority determines candidate pair ordering (higher is preferred).
	Priority int32 `json:"priority"`
}

// PortPrediction holds NAT port allocation pattern data from STUN observations.
// Used by peers to predict mapped ports for birthday attack hole punching.
type PortPrediction struct {
	// BasePort is the last observed STUN-mapped port.
	BasePort int32 `json:"basePort,omitempty"`

	// Increment is the average port increment between successive STUN mappings.
	// Positive for sequential allocation, 0 for unpredictable.
	Increment int32 `json:"increment,omitempty"`

	// Jitter is the observed variation in increments. High jitter = unreliable prediction.
	Jitter int32 `json:"jitter,omitempty"`

	// SamplePorts is the list of mapped ports observed from multiple STUN servers
	// (ordered by query time). Peers use this for refined prediction.
	SamplePorts []int32 `json:"samplePorts,omitempty"`
}

// WireKubePeerStatus defines the observed state of WireKubePeer
type WireKubePeerStatus struct {
	// Connected indicates whether this peer has an active WireGuard handshake.
	Connected bool `json:"connected,omitempty"`

	// LastHandshake is the timestamp of the most recent WireGuard handshake.
	// +optional
	LastHandshake *metav1.Time `json:"lastHandshake,omitempty"`

	// BytesReceived is the number of bytes received from this peer.
	BytesReceived int64 `json:"bytesReceived,omitempty"`

	// BytesSent is the number of bytes sent to this peer.
	BytesSent int64 `json:"bytesSent,omitempty"`

	// EndpointDiscoveryMethod records how the endpoint was discovered.
	// One of: manual, annotation, stun, aws-metadata, internal-ip
	// +optional
	EndpointDiscoveryMethod string `json:"endpointDiscoveryMethod,omitempty"`

	// NATType indicates the NAT mapping behavior detected on this node via STUN.
	// "cone": Endpoint-Independent Mapping — stable mapped port, direct P2P capable.
	// "symmetric": Endpoint-Dependent Mapping — mapped port changes per destination.
	// Empty string means NAT type was not determined (e.g., only one STUN server responded).
	// +optional
	NATType string `json:"natType,omitempty"`

	// ICECandidates lists connectivity candidates gathered by this peer's agent.
	// Other peers read these to determine the best connectivity path.
	// +optional
	ICECandidates []ICECandidate `json:"iceCandidates,omitempty"`

	// PortPrediction holds NAT port allocation pattern data.
	// Used for birthday attack when both peers are behind symmetric NAT.
	// +optional
	PortPrediction *PortPrediction `json:"portPrediction,omitempty"`

	// ICEState tracks the ICE negotiation phase for observability.
	// "gathering", "checking", "connected", "failed", "relay"
	// +optional
	ICEState string `json:"iceState,omitempty"`

	// RelayLatencyMs is the measured latency to this peer via relay, in milliseconds.
	// Only set when TransportMode is "relay".
	// +optional
	RelayLatencyMs int32 `json:"relayLatencyMs,omitempty"`

	// Conditions reflect the current state of the peer.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wkpeer
// +kubebuilder:printcolumn:name="Endpoint",type=string,JSONPath=`.spec.endpoint`
// +kubebuilder:printcolumn:name="AllowedIPs",type=string,JSONPath=`.spec.allowedIPs`
// +kubebuilder:printcolumn:name="Connected",type=boolean,JSONPath=`.status.connected`
// +kubebuilder:printcolumn:name="NAT",type=string,JSONPath=`.status.natType`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireKubePeer represents a WireGuard peer in the mesh.
// Each cluster node has one auto-managed peer (created by the agent).
// External peers (home PCs, remote VMs) are created manually by the user.
// The AllowedIPs field works like site-to-site VPN routing: traffic destined
// for these CIDRs will be routed through this peer's WireGuard tunnel.
type WireKubePeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireKubePeerSpec   `json:"spec,omitempty"`
	Status WireKubePeerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WireKubePeerList contains a list of WireKubePeer
type WireKubePeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireKubePeer `json:"items"`
}
