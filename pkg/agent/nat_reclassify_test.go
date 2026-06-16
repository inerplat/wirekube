package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/wirekube/wirekube/pkg/agent/nat"
	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestClassificationFromSTUN(t *testing.T) {
	if c := classificationFromSTUN(nil, errors.New("boom")); c.NATType != nat.NATUnknown || c.Error == "" {
		t.Fatalf("error case = %+v, want unknown + error", c)
	}
	if c := classificationFromSTUN(nil, nil); c.NATType != nat.NATUnknown || c.Error == "" {
		t.Fatalf("nil result = %+v, want unknown + error", c)
	}
	// 1 of 2 responded → unknown with a descriptive (retryable) error.
	c := classificationFromSTUN(&nat.STUNResult{NATType: nat.NATUnknown, ServersResponded: 1, ServersTotal: 2}, nil)
	if c.NATType != nat.NATUnknown || c.Error == "" {
		t.Fatalf("partial success = %+v, want unknown + error", c)
	}
	// 2 of 2 → cone, no error.
	c = classificationFromSTUN(&nat.STUNResult{NATType: nat.NATCone, ServersResponded: 2, ServersTotal: 2}, nil)
	if c.NATType != nat.NATCone || c.Error != "" {
		t.Fatalf("cone = %+v, want cone, no error", c)
	}
	// symmetric carries port prediction through.
	pp := &nat.PortPrediction{SamplePorts: []int{1, 2}}
	c = classificationFromSTUN(&nat.STUNResult{NATType: nat.NATSymmetric, PortPrediction: pp, ServersResponded: 2, ServersTotal: 2}, nil)
	if c.NATType != nat.NATSymmetric || c.PortPrediction == nil {
		t.Fatalf("symmetric = %+v, want symmetric + port prediction", c)
	}
}

func newReclassifyAgent(t *testing.T, peer *wirekubev1alpha1.WireKubePeer) *Agent {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(core): %v", err)
	}
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(wirekube): %v", err)
	}
	cb := ctrlclientfake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&wirekubev1alpha1.WireKubePeer{})
	if peer != nil {
		cb = cb.WithObjects(peer)
	}
	return &Agent{client: cb.Build(), nodeName: "test-node", log: logr.Discard()}
}

func ownPeer(natType string, withPortPrediction bool) *wirekubev1alpha1.WireKubePeer {
	p := &wirekubev1alpha1.WireKubePeer{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}}
	p.Status.NATType = natType
	if withPortPrediction {
		p.Status.PortPrediction = &wirekubev1alpha1.PortPrediction{SamplePorts: []int32{100, 200}}
	}
	return p
}

func readOwnPeer(t *testing.T, a *Agent) *wirekubev1alpha1.WireKubePeer {
	t.Helper()
	p := &wirekubev1alpha1.WireKubePeer{}
	if err := a.client.Get(context.Background(), ctrlclient.ObjectKey{Name: "test-node"}, p); err != nil {
		t.Fatalf("re-reading own peer: %v", err)
	}
	return p
}

func TestApplyNATClassificationUnknownKeepsPreviousType(t *testing.T) {
	a := newReclassifyAgent(t, ownPeer("symmetric", true))
	a.detectedNATType = "symmetric"
	a.isSymmetricNAT = true
	a.portPrediction = &nat.PortPrediction{SamplePorts: []int{1}}
	a.natClassifyInFlight = true

	a.applyNATClassification(context.Background(), &NATClassification{NATType: nat.NATUnknown, Error: "1 of 2 responded"})

	// Transient unknown must NOT wipe a previously-known classification.
	if a.detectedNATType != "symmetric" {
		t.Fatalf("detectedNATType = %q, want symmetric (unchanged on transient unknown)", a.detectedNATType)
	}
	if a.portPrediction == nil {
		t.Fatalf("portPrediction was wiped on transient unknown")
	}
	if a.natClassifyInFlight {
		t.Fatalf("natClassifyInFlight not cleared")
	}
}

func TestApplyNATClassificationSymmetricToConeClearsPortPrediction(t *testing.T) {
	a := newReclassifyAgent(t, ownPeer("symmetric", true)) // CRD starts with symmetric + portPrediction
	a.detectedNATType = "symmetric"
	a.isSymmetricNAT = true
	a.portPrediction = &nat.PortPrediction{SamplePorts: []int{1, 2}}

	a.applyNATClassification(context.Background(), &NATClassification{NATType: nat.NATCone, ServersResponded: 2, ServersTotal: 2})

	// In-memory state updated.
	if a.detectedNATType != "cone" || a.isSymmetricNAT {
		t.Fatalf("in-memory = (%q, sym=%v), want (cone, false)", a.detectedNATType, a.isSymmetricNAT)
	}
	if a.portPrediction != nil {
		t.Fatalf("portPrediction = %+v, want nil after symmetric→cone", a.portPrediction)
	}
	// CRD status updated AND the stale portPrediction actually cleared.
	got := readOwnPeer(t, a)
	if got.Status.NATType != "cone" {
		t.Fatalf("status.NATType = %q, want cone", got.Status.NATType)
	}
	if got.Status.PortPrediction != nil {
		t.Fatalf("status.PortPrediction = %+v, want nil (merge patch must clear it)", got.Status.PortPrediction)
	}
}

func TestApplyNATClassificationConeToSymmetricWritesPortPrediction(t *testing.T) {
	a := newReclassifyAgent(t, ownPeer("cone", false))
	a.detectedNATType = "cone"

	a.applyNATClassification(context.Background(), &NATClassification{
		NATType:          nat.NATSymmetric,
		PortPrediction:   &nat.PortPrediction{BasePort: 5000, SamplePorts: []int{5000, 5100}},
		ServersResponded: 2, ServersTotal: 2,
	})

	if a.detectedNATType != "symmetric" || !a.isSymmetricNAT {
		t.Fatalf("in-memory = (%q, sym=%v), want (symmetric, true)", a.detectedNATType, a.isSymmetricNAT)
	}
	got := readOwnPeer(t, a)
	if got.Status.NATType != "symmetric" {
		t.Fatalf("status.NATType = %q, want symmetric", got.Status.NATType)
	}
	if got.Status.PortPrediction == nil || len(got.Status.PortPrediction.SamplePorts) != 2 {
		t.Fatalf("status.PortPrediction = %+v, want 2 sample ports", got.Status.PortPrediction)
	}
}

// TestMaybeReclassifyNATAppliesDrainedResult drives the drain+apply path on the
// sync goroutine without launching the (network-bound) background probe: a
// completed classification is pre-placed on the channel and the pacing fields
// are set so no new goroutine is started.
func TestMaybeReclassifyNATAppliesDrainedResult(t *testing.T) {
	a := newReclassifyAgent(t, ownPeer("cone", false))
	a.detectedNATType = "cone"
	a.reclassifyEvery = time.Hour
	a.lastNATClassify = time.Now() // recent → no new probe launched
	a.natClassifyInFlight = true
	a.natClassCh = make(chan *NATClassification, 1)
	a.natClassCh <- &NATClassification{
		NATType:          nat.NATSymmetric,
		PortPrediction:   &nat.PortPrediction{SamplePorts: []int{7000, 7100}},
		ServersResponded: 2, ServersTotal: 2,
	}

	a.maybeReclassifyNAT(context.Background())

	if a.detectedNATType != "symmetric" {
		t.Fatalf("detectedNATType = %q, want symmetric (drained result applied)", a.detectedNATType)
	}
	if a.natClassifyInFlight {
		t.Fatalf("natClassifyInFlight not cleared after apply")
	}
	// Channel should be empty (drained, not refilled — no new probe this tick).
	select {
	case <-a.natClassCh:
		t.Fatalf("channel unexpectedly non-empty (a probe was launched)")
	default:
	}
}
