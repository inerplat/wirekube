package externalpeer

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// TestRenderConfigUsesTheIssuedKey covers a config re-downloaded while an
// older controller has written a node key into status: the rendered config
// must still name the key the agents serve the peer under.
func TestRenderConfigUsesTheIssuedKey(t *testing.T) {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{wirekubev1alpha1.ExternalPeerIssuedIngressKeyAnnotation: "issued-shared-key"},
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:   "100.64.0.9/32",
			RelayEndpoint:    "relay.example.test:30479",
			IngressPublicKey: "rewritten-node-key",
		},
	}
	conf := RenderConfig("private", cr)
	if !strings.Contains(conf, "PublicKey = issued-shared-key\n") {
		t.Fatalf("rendered config:\n%s", conf)
	}
}
