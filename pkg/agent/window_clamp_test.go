package agent

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// The two windows carry an invariant in both directions: the post-upgrade grace
// must exceed the steady-state handshake window (or a peer looks disconnected
// the moment it is upgraded) and must stay under WireGuard's RejectAfterTime of
// 180s (or a peer is called direct after the session has been discarded).
func TestApplyNATTraversalWindows(t *testing.T) {
	cases := map[string]struct {
		spec          *wirekubev1alpha1.NATTraversalSpec
		wantHandshake time.Duration
		wantDirect    time.Duration
	}{
		"nil spec keeps the packaged defaults": {
			spec:          nil,
			wantHandshake: defaultHandshakeValidWindow,
			wantDirect:    defaultDirectConnectedWindow,
		},
		"oversized handshake window is bounded, direct window stays above it": {
			spec:          &wirekubev1alpha1.NATTraversalSpec{HandshakeValidWindowSeconds: 180},
			wantHandshake: maxDirectConnectedWindow - 20*time.Second,
			wantDirect:    maxDirectConnectedWindow,
		},
		"short handshake window derives at least the rekey floor": {
			spec:          &wirekubev1alpha1.NATTraversalSpec{HandshakeValidWindowSeconds: 10},
			wantHandshake: 10 * time.Second,
			wantDirect:    minDirectConnectedWindow,
		},
		"explicit direct window is capped": {
			spec: &wirekubev1alpha1.NATTraversalSpec{
				HandshakeValidWindowSeconds:  30,
				DirectConnectedWindowSeconds: 600,
			},
			wantHandshake: 30 * time.Second,
			wantDirect:    maxDirectConnectedWindow,
		},
		"explicit direct window below the handshake window is raised": {
			spec: &wirekubev1alpha1.NATTraversalSpec{
				HandshakeValidWindowSeconds:  120,
				DirectConnectedWindowSeconds: 60,
			},
			wantHandshake: 120 * time.Second,
			wantDirect:    140 * time.Second,
		},
		"sub-minimum handshake value is ignored": {
			spec:          &wirekubev1alpha1.NATTraversalSpec{HandshakeValidWindowSeconds: 3},
			wantHandshake: defaultHandshakeValidWindow,
			wantDirect:    defaultDirectConnectedWindow,
		},
	}

	for name, tc := range cases {
		a := &Agent{log: logr.Discard()}
		a.applyNATTraversalWindows(tc.spec)

		if a.handshakeValidWindow != tc.wantHandshake {
			t.Errorf("%s: handshakeValidWindow = %v, want %v", name, a.handshakeValidWindow, tc.wantHandshake)
		}
		if a.directConnectedWindow != tc.wantDirect {
			t.Errorf("%s: directConnectedWindow = %v, want %v", name, a.directConnectedWindow, tc.wantDirect)
		}
		// Invariants, checked for every input rather than per case.
		if a.directConnectedWindow < a.handshakeValidWindow+20*time.Second {
			t.Errorf("%s: direct window %v is not at least 20s above the handshake window %v",
				name, a.directConnectedWindow, a.handshakeValidWindow)
		}
		if a.directConnectedWindow > maxDirectConnectedWindow {
			t.Errorf("%s: direct window %v exceeds the RejectAfterTime cap %v",
				name, a.directConnectedWindow, maxDirectConnectedWindow)
		}
	}
}
