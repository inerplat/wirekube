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
	// +kubebuilder:default=wg0
	InterfaceName string `json:"interfaceName,omitempty"`

	// MTU is the MTU for the WireGuard interface.
	// +kubebuilder:default=1420
	// +kubebuilder:validation:Minimum=576
	// +kubebuilder:validation:Maximum=65535
	MTU int32 `json:"mtu,omitempty"`

	// STUNServers is a list of STUN server addresses used for public endpoint discovery.
	// +optional
	STUNServers []string `json:"stunServers,omitempty"`
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
