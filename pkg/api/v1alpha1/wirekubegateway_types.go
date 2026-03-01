package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WireKubeGatewaySpec defines the desired state of WireKubeGateway
type WireKubeGatewaySpec struct {
	// NodeName is the VPN-enabled node where the gateway pod will run.
	// The gateway pod bridges non-VPN nodes into the WireGuard mesh.
	NodeName string `json:"nodeName"`

	// RoutedCIDRs is the list of pod/node CIDRs belonging to non-VPN nodes
	// that should be routed through this gateway into the mesh.
	// +kubebuilder:validation:MinItems=1
	RoutedCIDRs []string `json:"routedCIDRs"`

	// MasqueradeEnabled controls whether the gateway performs SNAT (MASQUERADE)
	// for traffic from non-VPN nodes entering the mesh.
	// When true, mesh nodes see the gateway's mesh IP as the source.
	// +kubebuilder:default=true
	MasqueradeEnabled bool `json:"masqueradeEnabled,omitempty"`
}

// WireKubeGatewayStatus defines the observed state of WireKubeGateway
type WireKubeGatewayStatus struct {
	// Ready indicates whether the gateway pod is running and ready.
	Ready bool `json:"ready,omitempty"`

	// PodName is the name of the running gateway pod.
	// +optional
	PodName string `json:"podName,omitempty"`

	// PodIP is the IP address of the running gateway pod.
	// Non-VPN nodes route mesh traffic to this IP.
	// +optional
	PodIP string `json:"podIP,omitempty"`

	// Conditions reflect the current state of the gateway.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=wkgw
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=`.status.ready`
// +kubebuilder:printcolumn:name="PodIP",type=string,JSONPath=`.status.podIP`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// WireKubeGateway is the Schema for the wirekubegateways API.
// A gateway bridges non-VPN nodes (nodes without wg0) into the WireGuard mesh
// by running a privileged pod on a VPN node that performs NAT.
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
