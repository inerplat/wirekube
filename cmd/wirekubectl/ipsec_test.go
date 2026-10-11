package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func ipsecCLIFixture(charonOn ...string) []client.Object {
	objs := []client.Object{
		&wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wirekubev1alpha1.WireKubeMeshSpec{MeshCIDR: "198.18.0.0/16"}},
		&wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "gw-a"}, Spec: wirekubev1alpha1.WireKubePeerSpec{PublicKey: "a", Endpoint: "198.51.100.1:51820"}},
		&wirekubev1alpha1.WireKubeGateway{
			ObjectMeta: metav1.ObjectMeta{Name: "site-gw"},
			Spec: wirekubev1alpha1.WireKubeGatewaySpec{
				PeerRefs: []string{"gw-a", "gw-b"},
				Routes:   []wirekubev1alpha1.GatewayRoute{{CIDR: "10.88.1.0/24"}},
				IPsec: []wirekubev1alpha1.GatewayIPsecTunnel{{
					Name: "primary", RemoteAddress: "203.0.113.10",
					PreSharedKeyRef: wirekubev1alpha1.IPsecSecretKeyRef{Name: "site-psk"},
					ESP:             wirekubev1alpha1.ESPSettings{Proposals: []string{"aes256gcm16"}},
				}},
			},
			Status: wirekubev1alpha1.WireKubeGatewayStatus{ActivePeer: "gw-a", IPsec: []wirekubev1alpha1.GatewayIPsecTunnelStatus{{
				Name: "primary", Phase: wirekubev1alpha1.IPsecTunnelPhaseConnecting, Carrier: true, Dataplane: wirekubev1alpha1.IPsecDataplanePolicy,
				Message: "authentication failed: check the pre-shared key and the local and remote IDs",
			}}},
		},
	}
	for _, node := range charonOn {
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "wirekube-charon-" + node, Namespace: "wirekube-system", Labels: map[string]string{"app.kubernetes.io/name": "wirekube-charon"}},
			Spec:       corev1.PodSpec{NodeName: node},
			Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		})
	}
	return objs
}

func runIPsecCLI(t *testing.T, objs []client.Object, args ...string) string {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	oldClient, oldOutput, oldNS := options.client, options.output, options.namespace
	options.client = func() (client.Client, error) { return c, nil }
	options.output = "text"
	options.namespace = "wirekube-system"
	t.Cleanup(func() { options.client, options.output, options.namespace = oldClient, oldOutput, oldNS })
	cmd := ipsecCmd()
	out := &bytes.Buffer{}
	cmd.SetArgs(args)
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestIPsecStatusShowsTunnelsAndMissingCharon(t *testing.T) {
	out := runIPsecCLI(t, ipsecCLIFixture(), "status")
	for _, want := range []string{"site-gw", "primary", "203.0.113.10", "gw-a", "Connecting", "authentication failed", "runs no ready charon pod"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
	if out := runIPsecCLI(t, ipsecCLIFixture("gw-a"), "status"); strings.Contains(out, "Warning") {
		t.Errorf("warned although charon runs on the active node:\n%s", out)
	}
}

func TestIPsecRemoteConfigMirrorsTheTunnelPerNode(t *testing.T) {
	out := runIPsecCLI(t, ipsecCLIFixture(), "remote-config", "site-gw")
	for _, want := range []string{
		"toward node gw-a (active)", "toward node gw-b (standby)",
		"198.51.100.1", // gw-a's address and IKE ID
		"Local networks              10.88.1.0/24", // the gateway routes, from the remote's side
		"Remote networks             198.18.0.0/16",
		"encryption AES-256-CBC, integrity SHA2-256, DH group 14 (MODP 2048)", // IKE default
		"encryption AES-256-GCM, PFS off",
		"get secret site-psk",
		"gw-b has no WireKubePeer",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("remote-config output lacks %q:\n%s", want, out)
		}
	}
}

func TestDoctorIPsecCheck(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ipsecCLIFixture("gw-a")...).Build()
	ok, message, relevant := checkIPsecTunnels(context.Background(), c)
	if !relevant || ok || !strings.Contains(message, "0/1 tunnels established") || !strings.Contains(message, "authentication failed") {
		t.Errorf("ok=%v relevant=%v message=%q", ok, relevant, message)
	}
	plain := fake.NewClientBuilder().WithScheme(scheme).Build()
	if _, _, relevant := checkIPsecTunnels(context.Background(), plain); relevant {
		t.Errorf("IPsec check reported for a cluster without tunnels")
	}
}

func TestIPsecRemoteConfigEscapesDottedSecretKeys(t *testing.T) {
	objs := ipsecCLIFixture()
	for _, o := range objs {
		if gw, ok := o.(*wirekubev1alpha1.WireKubeGateway); ok {
			gw.Spec.IPsec[0].PreSharedKeyRef.Key = "vpn.psk"
		}
	}
	out := runIPsecCLI(t, objs, "remote-config", "site-gw")
	if !strings.Contains(out, `jsonpath='{.data.vpn\.psk}'`) {
		t.Errorf("dotted key not escaped in the kubectl command:\n%s", out)
	}
}
