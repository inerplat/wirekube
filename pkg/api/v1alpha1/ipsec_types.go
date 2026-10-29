package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPsecDataplane selects how traffic is steered into the tunnel.
// +kubebuilder:validation:Enum=Auto;XFRMInterface;Policy
type IPsecDataplane string

const (
	// IPsecDataplaneAuto uses an XFRM interface when the kernel supports one
	// and falls back to policy-based steering otherwise.
	IPsecDataplaneAuto IPsecDataplane = "Auto"
	// IPsecDataplaneXFRMInterface binds the CHILD_SA to a per-tunnel XFRM
	// interface and routes the remote selectors into it. Needs the
	// xfrm_interface module, which does not load on kernels booted with
	// ipv6.disable=1; there the tunnel reports Error.
	IPsecDataplaneXFRMInterface IPsecDataplane = "XFRMInterface"
	// IPsecDataplanePolicy relies on the CHILD_SA's kernel policies alone:
	// forwarded traffic matching the selectors is encrypted wherever the
	// kernel routes it. Redundant tunnels (identical remote selectors) are
	// not supported, and traffic the gateway node originates itself is
	// tunneled only if its source falls inside the local selectors.
	IPsecDataplanePolicy IPsecDataplane = "Policy"
)

// IPsecTunnelPhase is the lifecycle phase of a gateway IPsec tunnel.
// +kubebuilder:validation:Enum=Pending;Connecting;Established;Error;Unknown
type IPsecTunnelPhase string

const (
	// IPsecTunnelPhasePending means no gateway peer has been elected yet, so
	// nothing terminates the tunnel.
	IPsecTunnelPhasePending IPsecTunnelPhase = "Pending"
	// IPsecTunnelPhaseConnecting means the active gateway peer loaded the
	// connection into the IKE daemon but no CHILD_SA is installed yet.
	IPsecTunnelPhaseConnecting IPsecTunnelPhase = "Connecting"
	// IPsecTunnelPhaseEstablished means at least one CHILD_SA is installed.
	IPsecTunnelPhaseEstablished IPsecTunnelPhase = "Established"
	// IPsecTunnelPhaseError means the active gateway peer could not apply the
	// tunnel; status.message says why.
	IPsecTunnelPhaseError IPsecTunnelPhase = "Error"
	// IPsecTunnelPhaseUnknown means whoever terminates the tunnel stopped
	// reporting, so the last phase it wrote can no longer be trusted.
	IPsecTunnelPhaseUnknown IPsecTunnelPhase = "Unknown"
)

// IPsecTunnelReason is a machine-readable cause of a tunnel not being
// Established. Consumers must treat values they do not know as unexplained.
type IPsecTunnelReason string

const (
	// IPsecReasonConfigError: the tunnel cannot be applied as specified.
	IPsecReasonConfigError IPsecTunnelReason = "ConfigError"
	// IPsecReasonIKEDaemonUnavailable: charon cannot be reached.
	IPsecReasonIKEDaemonUnavailable IPsecTunnelReason = "IKEDaemonUnavailable"
	// IPsecReasonDataplaneError: the kernel refused an XFRM interface or route.
	IPsecReasonDataplaneError IPsecTunnelReason = "DataplaneError"
	// IPsecReasonGuardNotInstalled: the plaintext guard is missing.
	IPsecReasonGuardNotInstalled IPsecTunnelReason = "GuardNotInstalled"
	// IPsecReasonProposalMismatch: the two sides share no IKE or ESP proposal.
	IPsecReasonProposalMismatch IPsecTunnelReason = "ProposalMismatch"
	// IPsecReasonDHGroupMismatch: the DH groups differ.
	IPsecReasonDHGroupMismatch IPsecTunnelReason = "DHGroupMismatch"
	// IPsecReasonAuthenticationFailed: the pre-shared key or the IDs differ.
	IPsecReasonAuthenticationFailed IPsecTunnelReason = "AuthenticationFailed"
	// IPsecReasonTrafficSelectorMismatch: the networks on the two sides differ.
	IPsecReasonTrafficSelectorMismatch IPsecTunnelReason = "TrafficSelectorMismatch"
	// IPsecReasonPeerUnreachable: the remote gateway does not answer.
	IPsecReasonPeerUnreachable IPsecTunnelReason = "PeerUnreachable"
	// IPsecReasonNotReporting: the terminating peer stopped reporting.
	IPsecReasonNotReporting IPsecTunnelReason = "NotReporting"
)

// GatewayIPsecTunnel is a site-to-site IPsec tunnel terminated by the
// gateway's active peer. Mesh traffic for the gateway's routes reaches that
// peer through WireGuard and leaves through the tunnel; return traffic comes
// back the same way. The gateway should not enable SNAT: the remote side
// routes the local traffic selectors back through the tunnel.
type GatewayIPsecTunnel struct {
	// Name identifies the tunnel within the gateway.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// RemoteAddress is the public address (IP or DNS name) of the remote
	// IPsec gateway, for example a cloud VPN gateway.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9]([-A-Za-z0-9.:]*[A-Za-z0-9])?$`
	RemoteAddress string `json:"remoteAddress"`

	// RemoteID is the IKE identity expected from the remote gateway.
	// Defaults to RemoteAddress.
	// +optional
	RemoteID string `json:"remoteID,omitempty"`

	// LocalID is the IKE identity this side presents. Defaults to the IP
	// address in the active peer's WireKubePeer endpoint, which is the
	// address the remote gateway sees, also behind 1:1 NAT.
	// +optional
	LocalID string `json:"localID,omitempty"`

	// PreSharedKeyRef points at the pre-shared key. The Secret must live in
	// the agent's namespace; the agent reads no Secret outside it.
	PreSharedKeyRef IPsecSecretKeyRef `json:"preSharedKeyRef"`

	// LocalTrafficSelectors are the networks on the mesh side that the remote
	// gateway routes into the tunnel. Defaults to the mesh CIDR. Add pod
	// CIDRs here when pods must reach the remote network directly.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:Pattern=`^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$`
	LocalTrafficSelectors []string `json:"localTrafficSelectors,omitempty"`

	// RemoteTrafficSelectors are the networks behind the remote gateway.
	// Defaults to the gateway's routes, which is also what the mesh sends to
	// the gateway peer.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:Pattern=`^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$`
	RemoteTrafficSelectors []string `json:"remoteTrafficSelectors,omitempty"`

	// IKE configures the IKE_SA.
	// +optional
	IKE IKESettings `json:"ike,omitempty"`

	// ESP configures the CHILD_SA.
	// +optional
	ESP ESPSettings `json:"esp,omitempty"`

	// DPD configures dead peer detection.
	// +optional
	DPD DPDSettings `json:"dpd,omitempty"`

	// ForceEncapsulation forces UDP encapsulation (NAT-T on port 4500) even
	// when no NAT is detected. Useful when a firewall passes UDP but not ESP.
	// +optional
	ForceEncapsulation bool `json:"forceEncapsulation,omitempty"`

	// Dataplane selects how traffic is steered into the tunnel.
	// +kubebuilder:default=Auto
	// +optional
	Dataplane IPsecDataplane `json:"dataplane,omitempty"`

	// InterfaceID pins the XFRM interface ID. Zero derives a stable ID from
	// the tunnel name. 4294967295 is reserved by strongSwan.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=4294967294
	InterfaceID int64 `json:"interfaceID,omitempty"`

	// MTU of the XFRM interface. Defaults to 1400, which leaves room for ESP
	// with NAT-T inside a 1500-byte underlay.
	// +optional
	// +kubebuilder:validation:Minimum=576
	// +kubebuilder:validation:Maximum=9000
	MTU int32 `json:"mtu,omitempty"`
}

// IPsecSecretKeyRef selects a key of a Secret in the agent's namespace.
type IPsecSecretKeyRef struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key within the Secret. Defaults to "psk".
	// +optional
	Key string `json:"key,omitempty"`
}

// IKESettings configures the IKE_SA.
type IKESettings struct {
	// Version is the IKE version.
	// +kubebuilder:validation:Enum=1;2
	// +optional
	Version int32 `json:"version,omitempty"`
	// Proposals are strongSwan IKE proposals, for example
	// "aes256-sha256-modp2048". Defaults to that single proposal.
	// +optional
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]+(-[a-z0-9]+)*$`
	Proposals []string `json:"proposals,omitempty"`
	// LifetimeSeconds is the IKE_SA rekey time. Defaults to 28800.
	// +optional
	// +kubebuilder:validation:Minimum=120
	LifetimeSeconds int32 `json:"lifetimeSeconds,omitempty"`
}

// ESPSettings configures the CHILD_SA.
type ESPSettings struct {
	// Proposals are strongSwan ESP proposals. Defaults to
	// "aes256-sha256-modp2048".
	// +optional
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]+(-[a-z0-9]+)*$`
	Proposals []string `json:"proposals,omitempty"`
	// LifetimeSeconds is the CHILD_SA rekey time. Defaults to 3600.
	// +optional
	// +kubebuilder:validation:Minimum=120
	LifetimeSeconds int32 `json:"lifetimeSeconds,omitempty"`
}

// DPDSettings configures dead peer detection.
type DPDSettings struct {
	// DelaySeconds between DPD checks when the tunnel is idle. Defaults to 30.
	// +optional
	// +kubebuilder:validation:Minimum=1
	DelaySeconds int32 `json:"delaySeconds,omitempty"`
	// Action taken when the remote peer is declared dead.
	// +kubebuilder:validation:Enum=restart;clear;trap
	// +optional
	Action string `json:"action,omitempty"`
}

// GatewayIPsecTunnelStatus is the observed state of one tunnel, written by
// the gateway's active peer.
type GatewayIPsecTunnelStatus struct {
	// Name of the tunnel in spec.ipsec.
	Name string `json:"name"`
	// Carrier is true on the tunnel the remote networks are routed into.
	// Tunnels with identical remote selectors back each other up; only one
	// carries traffic at a time.
	// +optional
	Carrier bool `json:"carrier,omitempty"`
	// Phase summarises the tunnel state.
	// +optional
	Phase IPsecTunnelPhase `json:"phase,omitempty"`
	// Dataplane is the steering mode in use on the active peer.
	// +optional
	Dataplane IPsecDataplane `json:"dataplane,omitempty"`
	// InterfaceName is the XFRM interface carrying the tunnel on the active
	// peer; empty in Policy mode.
	// +optional
	InterfaceName string `json:"interfaceName,omitempty"`
	// InterfaceID is the XFRM interface ID in use.
	// +optional
	InterfaceID int64 `json:"interfaceID,omitempty"`
	// IKEState is the IKE_SA state reported by the IKE daemon when status
	// was last written. A change of this field alone does not trigger a
	// write, so it can lag.
	// +optional
	IKEState string `json:"ikeState,omitempty"`
	// InstalledChildSAs counts installed CHILD_SAs when status was last
	// written; like IKEState it can lag. The wirekube_ipsec_tunnel_child_sas
	// metric carries the live count.
	// +optional
	InstalledChildSAs int32 `json:"installedChildSAs,omitempty"`
	// LocalTrafficSelectors and RemoteTrafficSelectors are the selectors the
	// active peer applied, after defaulting.
	// +optional
	LocalTrafficSelectors []string `json:"localTrafficSelectors,omitempty"`
	// +optional
	RemoteTrafficSelectors []string `json:"remoteTrafficSelectors,omitempty"`
	// LocalID is the IKE identity in use after defaulting.
	// +optional
	LocalID string `json:"localID,omitempty"`
	// Reason is a machine-readable cause when the tunnel is not
	// Established, when known.
	// +optional
	Reason IPsecTunnelReason `json:"reason,omitempty"`
	// Message explains why the tunnel is not Established, when known.
	// +optional
	Message string `json:"message,omitempty"`
	// LastTransitionTime is when Phase last changed.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}
