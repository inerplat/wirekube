package ipsec

import (
	"net"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// FromSpec builds the tunnel a gateway peer terminates from its spec, with
// every default applied except the pre-shared key. meshCIDR defaults the
// local selectors and localID the local identity.
func FromSpec(gw *wirekubev1alpha1.WireKubeGateway, s *wirekubev1alpha1.GatewayIPsecTunnel, meshCIDR, localID string) *Tunnel {
	key := gw.Name + "/" + s.Name
	t := &Tunnel{
		Name:          key,
		RemoteAddress: s.RemoteAddress,
		RemoteID:      s.RemoteID,
		LocalID:       s.LocalID,
		LocalTS:       s.LocalTrafficSelectors,
		RemoteTS:      s.RemoteTrafficSelectors,
		IKEVersion:    int(s.IKE.Version),
		IKEProposals:  s.IKE.Proposals,
		IKELifetime:   int(s.IKE.LifetimeSeconds),
		ESPProposals:  s.ESP.Proposals,
		ESPLifetime:   int(s.ESP.LifetimeSeconds),
		DPDDelay:      int(s.DPD.DelaySeconds),
		DPDAction:     s.DPD.Action,
		ForceEncap:    s.ForceEncapsulation,
		InterfaceID:   uint32(s.InterfaceID),
		MTU:           int(s.MTU),
	}
	if t.LocalID == "" {
		t.LocalID = localID
	}
	if len(t.LocalTS) == 0 && meshCIDR != "" {
		t.LocalTS = []string{meshCIDR}
	}
	if len(t.RemoteTS) == 0 {
		for _, r := range gw.Spec.Routes {
			t.RemoteTS = append(t.RemoteTS, r.CIDR)
		}
	}
	if t.IKEVersion == 0 {
		t.IKEVersion = 2
	}
	if len(t.IKEProposals) == 0 {
		t.IKEProposals = []string{DefaultIKEProposal}
	}
	if t.IKELifetime == 0 {
		t.IKELifetime = DefaultIKELifetime
	}
	if len(t.ESPProposals) == 0 {
		t.ESPProposals = []string{DefaultESPProposal}
	}
	if t.ESPLifetime == 0 {
		t.ESPLifetime = DefaultESPLifetime
	}
	if t.DPDDelay == 0 {
		t.DPDDelay = DefaultDPDDelay
	}
	if t.DPDAction == "" {
		t.DPDAction = DefaultDPDAction
	}
	if t.InterfaceID == 0 {
		t.InterfaceID = DeriveInterfaceID(key)
	}
	if t.MTU == 0 {
		t.MTU = DefaultMTU
	}
	return t
}

// EndpointHost returns the IP address of a WireKubePeer endpoint
// ("host:port"), or "" when it holds no IP address. It is the default local
// identity of a gateway peer and the address its remote gateway sees.
func EndpointHost(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil {
		return ""
	}
	return host
}
