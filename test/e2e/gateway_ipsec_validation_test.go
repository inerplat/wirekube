package e2e

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func TestGatewayIPsecValidation(t *testing.T) {
	valid := func() wirekubev1alpha1.GatewayIPsecTunnel {
		return wirekubev1alpha1.GatewayIPsecTunnel{
			Name:                   "primary",
			RemoteAddress:          "203.0.113.10",
			PreSharedKeyRef:        wirekubev1alpha1.IPsecSecretKeyRef{Name: "psk"},
			RemoteTrafficSelectors: []string{"10.88.1.0/24"},
			IKE:                    wirekubev1alpha1.IKESettings{Proposals: []string{"aes256-sha256-modp2048"}},
		}
	}
	cases := map[string]struct {
		mutate  func(*wirekubev1alpha1.GatewayIPsecTunnel)
		wantErr string
	}{
		"valid":               {mutate: func(*wirekubev1alpha1.GatewayIPsecTunnel) {}},
		"hostname remote":     {mutate: func(t *wirekubev1alpha1.GatewayIPsecTunnel) { t.RemoteAddress = "vpn.example.net" }},
		"selector not a CIDR": {mutate: func(t *wirekubev1alpha1.GatewayIPsecTunnel) { t.RemoteTrafficSelectors = []string{"10.88.1.0"} }, wantErr: "remoteTrafficSelectors"},
		"remote with a space": {mutate: func(t *wirekubev1alpha1.GatewayIPsecTunnel) { t.RemoteAddress = "203.0.113.10 " }, wantErr: "remoteAddress"},
		"proposal with space": {mutate: func(t *wirekubev1alpha1.GatewayIPsecTunnel) { t.IKE.Proposals = []string{"aes256 sha256"} }, wantErr: "proposals"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tu := valid()
			tc.mutate(&tu)
			gw := &wirekubev1alpha1.WireKubeGateway{
				ObjectMeta: metav1.ObjectMeta{Name: "ipsec-validation-" + strings.ReplaceAll(name, " ", "-")},
				Spec: wirekubev1alpha1.WireKubeGatewaySpec{
					PeerRefs: []string{"node-a"},
					Routes:   []wirekubev1alpha1.GatewayRoute{{CIDR: "10.88.1.0/24"}},
					IPsec:    []wirekubev1alpha1.GatewayIPsecTunnel{tu},
				},
			}
			err := k8sClient.Create(context.Background(), gw)
			if err == nil {
				defer func() { _ = k8sClient.Delete(context.Background(), gw) }()
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("valid tunnel rejected: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("want an error about %s, got %v", tc.wantErr, err)
			}
		})
	}
}
