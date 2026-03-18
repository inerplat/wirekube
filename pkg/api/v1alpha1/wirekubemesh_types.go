package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireKubeMeshSpec defines the desired state of WireKubeMesh
type WireKubeMeshSpec struct {
	// ListenPort is the UDP port WireGuard listens on for incoming connections.
	// +kubebuilder:default=51820
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=65535
	ListenPort int32 `json:"listenPort,omitempty"`

	// InterfaceName is the name of the WireGuard network interface on each node.
	// +kubebuilder:default=wire_kube
	InterfaceName string `json:"interfaceName,omitempty"`

	// MTU is the MTU for the WireGuard interface.
	// +kubebuilder:default=1420
	// +kubebuilder:validation:Minimum=576
	// +kubebuilder:validation:Maximum=65535
	MTU int32 `json:"mtu,omitempty"`

	// STUNServers is a list of STUN server addresses used for public endpoint discovery.
	// At least two servers are recommended for Symmetric NAT detection (RFC 5780).
	// If omitted, built-in defaults (Google + Cloudflare STUN) are used.
	// +optional
	// +kubebuilder:validation:MinItems=2
	STUNServers []string `json:"stunServers,omitempty"`

	// APIServerURL is the URL of the Kubernetes API server (e.g. "https://10.0.0.1:6443").
	// When set, the agent uses this directly instead of in-cluster discovery.
	// +optional
	APIServerURL string `json:"apiServerURL,omitempty"`

	// Relay configures the relay fallback for peers behind Symmetric NAT.
	// When direct P2P and STUN fail, traffic is forwarded through a relay server.
	// +optional
	Relay *RelaySpec `json:"relay,omitempty"`

	// NATTraversal configures advanced NAT traversal options.
	// +optional
	NATTraversal *NATTraversalSpec `json:"natTraversal,omitempty"`

	// AutoAllowedIPs configures automatic AllowedIPs detection for each node's own WireKubePeer.
	// When enabled, the agent sets its own AllowedIPs from Node.Status.InternalIP if the field
	// is currently empty. This simplifies initial node onboarding without manual kubectl patch.
	// +optional
	AutoAllowedIPs *AutoAllowedIPsSpec `json:"autoAllowedIPs,omitempty"`

	// PodCIDRRouting enables automatic pod CIDR advertisement via AllowedIPs.
	// When enabled, the agent appends Node.Spec.PodCIDR to its own AllowedIPs each sync cycle.
	// Designed for hybrid environments where on-premises nodes use Cilium/Calico (which set
	// Node.Spec.PodCIDR), enabling direct pod-to-pod routing across the mesh tunnel.
	// +optional
	PodCIDRRouting *PodCIDRRoutingSpec `json:"podCIDRRouting,omitempty"`
}

// AutoAllowedIPsSpec configures automatic AllowedIPs detection for the agent's own WireKubePeer.
type AutoAllowedIPsSpec struct {
	// Strategy controls how the agent automatically sets AllowedIPs for its own WireKubePeer
	// when the field is currently empty.
	// "disabled" (default): AllowedIPs must be set manually by the user.
	// "node-internal-ip": use Node.Status.InternalIP/32 (the node's primary cluster IP).
	// +kubebuilder:default=disabled
	// +kubebuilder:validation:Enum=disabled;node-internal-ip
	// +optional
	Strategy string `json:"strategy,omitempty"`
}

// PodCIDRRoutingSpec enables automatic pod CIDR advertisement via AllowedIPs.
type PodCIDRRoutingSpec struct {
	// Enabled controls whether the agent appends Node.Spec.PodCIDR to its own AllowedIPs.
	// When true, pods on each node become directly reachable by other mesh nodes.
	// Only effective when the node's CNI sets Node.Spec.PodCIDR (e.g. Cilium, Calico, Flannel).
	// VPC CNI (EKS cloud nodes) typically does not set Node.Spec.PodCIDR and will be skipped.
	// +kubebuilder:default=false
	Enabled bool `json:"enabled"`
}

// NATTraversalSpec configures advanced NAT traversal strategies.
type NATTraversalSpec struct {
	// BirthdayAttack controls the symmetric-to-symmetric NAT hole punching strategy.
	// This technique opens many UDP sockets simultaneously to find a matching port pair.
	// Some NAT gateways may interpret this as malicious traffic and block the node.
	// "disabled" (default): never attempt birthday attack; symmetric↔symmetric peers stay on relay.
	// "enabled": attempt birthday attack for symmetric↔symmetric NAT pairs.
	// Individual peers can override this via the "wirekube.io/birthday-attack" annotation
	// (values: "enabled" or "disabled").
	// +kubebuilder:default=disabled
	// +kubebuilder:validation:Enum=enabled;disabled
	// +optional
	BirthdayAttack string `json:"birthdayAttack,omitempty"`

	// HandshakeValidWindowSeconds is the maximum age of a WireGuard LastHandshake
	// that still indicates a live direct connection. When exceeded, the agent
	// runs an active health probe (PokeKeepalive + re-handshake) before reverting
	// to relay. With active probing, this can safely be set much lower than
	// WireGuard's REKEY_AFTER_TIME (120s) — e.g. 10s for fast failure detection.
	// Minimum: 5. Default: 180 (3 minutes).
	// +kubebuilder:validation:Minimum=5
	// +optional
	HandshakeValidWindowSeconds int32 `json:"handshakeValidWindowSeconds,omitempty"`

	// HealthProbeTimeoutSeconds is how long the active health probe waits for
	// a WireGuard re-handshake after poking keepalive. If the handshake does not
	// complete within this window, the direct connection is considered dead.
	// Minimum: 1. Default: 5.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=30
	// +optional
	HealthProbeTimeoutSeconds int32 `json:"healthProbeTimeoutSeconds,omitempty"`

	// DirectConnectedWindowSeconds is the grace period after upgrading from relay
	// to direct. During this window, the agent uses a longer handshake validity
	// check to allow WG to complete its first direct re-handshake. Must be >=
	// HandshakeValidWindowSeconds + 30. Default: HandshakeValidWindowSeconds + 120.
	// +optional
	DirectConnectedWindowSeconds int32 `json:"directConnectedWindowSeconds,omitempty"`
}

// RelaySpec configures the WireKube relay for NAT traversal fallback.
type RelaySpec struct {
	// Mode controls when the relay is used.
	// "auto": try direct P2P first, fall back to relay on handshake timeout.
	// "always": always route through relay (useful for testing or strict NAT).
	// "never": disable relay entirely.
	// +kubebuilder:default=auto
	// +kubebuilder:validation:Enum=auto;always;never
	Mode string `json:"mode,omitempty"`

	// Provider selects how the relay server is provisioned.
	// "external": user provides a pre-existing relay endpoint (public IP server, third-party).
	// "managed": operator deploys and manages the relay as a Pod + LoadBalancer Service.
	// +kubebuilder:validation:Enum=external;managed
	Provider string `json:"provider"`

	// External configures a user-provided relay server.
	// Required when provider is "external".
	// +optional
	External *ExternalRelaySpec `json:"external,omitempty"`

	// Managed configures the operator-managed relay (Pod + LB).
	// Required when provider is "managed".
	// +optional
	Managed *ManagedRelaySpec `json:"managed,omitempty"`

	// HandshakeTimeoutSeconds is how long to wait for a direct WireGuard
	// handshake before falling back to relay (only used in "auto" mode).
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=300
	HandshakeTimeoutSeconds int32 `json:"handshakeTimeoutSeconds,omitempty"`

	// DirectRetryIntervalSeconds is how often to re-attempt direct P2P
	// while using relay, to upgrade back to direct when possible.
	// +kubebuilder:default=120
	// +kubebuilder:validation:Minimum=30
	DirectRetryIntervalSeconds int32 `json:"directRetryIntervalSeconds,omitempty"`
}

// ExternalRelaySpec configures a user-provided relay server.
type ExternalRelaySpec struct {
	// Endpoint is the relay server address (host:port).
	// Example: "relay.example.com:3478" or "203.0.113.10:3478"
	Endpoint string `json:"endpoint"`

	// Transport is the protocol used to connect to the relay.
	// +kubebuilder:default=tcp
	// +kubebuilder:validation:Enum=tcp;ws
	Transport string `json:"transport,omitempty"`

	// AuthSecretRef references a Kubernetes Secret containing the relay auth key.
	// The Secret must have a "token" key.
	// +optional
	AuthSecretRef *SecretKeyRef `json:"authSecretRef,omitempty"`
}

// ManagedRelaySpec configures the operator-managed relay.
type ManagedRelaySpec struct {
	// Replicas is the number of relay pod replicas.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`

	// ServiceType is the Kubernetes Service type for the relay.
	// "LoadBalancer" creates an external LB (recommended for cloud).
	// "NodePort" uses a fixed node port (for bare metal or environments without LB).
	// +kubebuilder:default=LoadBalancer
	// +kubebuilder:validation:Enum=LoadBalancer;NodePort
	ServiceType string `json:"serviceType,omitempty"`

	// Port is the TCP port the relay listens on.
	// +kubebuilder:default=3478
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Image overrides the relay container image.
	// +optional
	Image string `json:"image,omitempty"`

	// Resources sets resource requests/limits for the relay pod.
	// +optional
	Resources *RelayResources `json:"resources,omitempty"`
}

// RelayResources defines resource requests and limits for the relay pod.
type RelayResources struct {
	// CPURequest e.g. "100m"
	// +optional
	CPURequest string `json:"cpuRequest,omitempty"`
	// MemoryRequest e.g. "64Mi"
	// +optional
	MemoryRequest string `json:"memoryRequest,omitempty"`
	// CPULimit e.g. "500m"
	// +optional
	CPULimit string `json:"cpuLimit,omitempty"`
	// MemoryLimit e.g. "128Mi"
	// +optional
	MemoryLimit string `json:"memoryLimit,omitempty"`
}

// SecretKeyRef references a specific key within a Kubernetes Secret.
type SecretKeyRef struct {
	// Name of the Secret.
	Name string `json:"name"`
	// Namespace of the Secret. Defaults to wirekube-system.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// WireKubeMeshStatus defines the observed state of WireKubeMesh
type WireKubeMeshStatus struct {
	// ReadyPeers is the number of peers with an active WireGuard handshake.
	ReadyPeers int32 `json:"readyPeers,omitempty"`

	// TotalPeers is the total number of WireKubePeer resources in the cluster.
	TotalPeers int32 `json:"totalPeers,omitempty"`

	// Conditions reflect the current state of the WireKubeMesh.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wkmesh
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.spec.listenPort`
// +kubebuilder:printcolumn:name="Interface",type=string,JSONPath=`.spec.interfaceName`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyPeers`
// +kubebuilder:printcolumn:name="Total",type=integer,JSONPath=`.status.totalPeers`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireKubeMesh defines the cluster-wide WireGuard mesh configuration.
// Create one instance per cluster. The agent on each node reads this
// to configure the WireGuard interface parameters.
type WireKubeMesh struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireKubeMeshSpec   `json:"spec,omitempty"`
	Status WireKubeMeshStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WireKubeMeshList contains a list of WireKubeMesh
type WireKubeMeshList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireKubeMesh `json:"items"`
}
