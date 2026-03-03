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
