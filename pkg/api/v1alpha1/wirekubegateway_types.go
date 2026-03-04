package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireKubeGatewaySpec defines the desired state of WireKubeGateway.
// A gateway acts as a Virtual Gateway (VGW) in the mesh, enabling other nodes
// to access networks behind the gateway node via its WireGuard tunnel.
type WireKubeGatewaySpec struct {
	// PeerRefs references WireKubePeer resources that serve as gateway nodes.
	// The first healthy peer is elected as the active gateway (HA failover).
	// Each entry is a WireKubePeer name (e.g. "node-worker1").
	// +kubebuilder:validation:MinItems=1
	PeerRefs []string `json:"peerRefs"`

	// ClientRefs lists WireKubePeer names that should route traffic through this gateway.
	// Only these peers will get kernel routes for the gateway's CIDRs.
	// If empty, all mesh peers (except gateway peers and peers already in the CIDR) are clients.
	// +optional
	ClientRefs []string `json:"clientRefs,omitempty"`

	// Routes defines the CIDR ranges accessible through this gateway.
	// These CIDRs are injected into each gateway peer's AllowedIPs and
	// kernel routing table entries on all mesh nodes.
	// +kubebuilder:validation:MinItems=1
	Routes []GatewayRoute `json:"routes"`

	// SNAT configures source NAT on the gateway node so that return traffic
	// from the target network routes back through the gateway.
	// +optional
	SNAT *GatewaySNAT `json:"snat,omitempty"`

	// HealthCheck verifies that the target network is reachable through the gateway.
	// When the health check fails, traffic is rerouted to the next peer in PeerRefs.
	// +optional
	HealthCheck *GatewayHealthCheck `json:"healthCheck,omitempty"`
}

// GatewayRoute defines a network CIDR reachable through the gateway.
type GatewayRoute struct {
	// CIDR is the network range (e.g. "172.20.0.0/16").
	// +kubebuilder:validation:Pattern=`^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$`
	CIDR string `json:"cidr"`

	// Description is a human-readable label for this route.
	// +optional
	Description string `json:"description,omitempty"`
}

// GatewaySNAT configures source NAT on the gateway node.
type GatewaySNAT struct {
	// Enabled activates iptables MASQUERADE for traffic forwarded through the gateway.
	Enabled bool `json:"enabled"`

	// SourceIP overrides the SNAT source address.
	// When empty, the gateway node's first AllowedIP is used.
	// +optional
	SourceIP string `json:"sourceIP,omitempty"`
}

// GatewayHealthCheck probes the target network for reachability.
type GatewayHealthCheck struct {
	// Enabled activates periodic health checking.
	Enabled bool `json:"enabled"`

	// Target is the address to probe (e.g. "172.20.1.254:443").
	// TCP connect is used when a port is specified, ICMP ping otherwise.
	Target string `json:"target"`

	// IntervalSeconds is the probe interval.
	// +kubebuilder:default=30
	// +kubebuilder:validation:Minimum=5
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`

	// TimeoutSeconds is the probe timeout.
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`

	// FailureThreshold is the number of consecutive failures before marking unhealthy.
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	FailureThreshold int32 `json:"failureThreshold,omitempty"`
}

// WireKubeGatewayStatus defines the observed state of WireKubeGateway.
type WireKubeGatewayStatus struct {
	// ActivePeer is the WireKubePeer name currently serving as the active gateway.
	// +optional
	ActivePeer string `json:"activePeer,omitempty"`

	// Ready indicates the gateway is healthy and forwarding traffic.
	Ready bool `json:"ready,omitempty"`

	// RoutesInjected is the number of CIDR routes injected into the active peer.
	RoutesInjected int32 `json:"routesInjected,omitempty"`

	// PeerHealth maps each peerRef to its health status ("healthy" or "unhealthy").
	// +optional
	PeerHealth map[string]string `json:"peerHealth,omitempty"`

	// LastHealthCheck is the timestamp of the last health check probe.
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`

	// Conditions reflect the current state of the gateway.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wkgw
// +kubebuilder:printcolumn:name="Active",type=string,JSONPath=`.status.activePeer`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="Routes",type=integer,JSONPath=`.status.routesInjected`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireKubeGateway defines a virtual gateway in the WireKube mesh.
// It enables mesh nodes to reach networks (VPC CIDRs, private link endpoints)
// behind a designated gateway node, similar to a VGW in AWS Site-to-Site VPN.
// Multiple PeerRefs provide HA with automatic failover on health check failure.
type WireKubeGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WireKubeGatewaySpec   `json:"spec,omitempty"`
	Status WireKubeGatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WireKubeGatewayList contains a list of WireKubeGateway
type WireKubeGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WireKubeGateway `json:"items"`
}
