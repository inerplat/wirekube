package externalpeer

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// WaitForActive polls a WireKubeExternalPeer until the reconciler has rendered
// enough status to produce a usable official WireGuard client config.
func WaitForActive(ctx context.Context, c client.Client, name string, timeout time.Duration) (*wirekubev1alpha1.WireKubeExternalPeer, error) {
	deadline := time.Now().Add(timeout)
	for {
		cr := &wirekubev1alpha1.WireKubeExternalPeer{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, cr); err != nil {
			return nil, fmt.Errorf("get peer: %w", err)
		}
		switch cr.Status.Phase {
		case wirekubev1alpha1.ExternalPeerPhaseActive:
			if cr.Status.AssignedMeshIP == "" || cr.Status.RelayEndpoint == "" || cr.Status.IngressPublicKey == "" {
				return nil, fmt.Errorf("phase=Active but status incomplete: meshIP=%q endpoint=%q ingressPubKey-set=%v",
					cr.Status.AssignedMeshIP, cr.Status.RelayEndpoint, cr.Status.IngressPublicKey != "")
			}
			return cr, nil
		case wirekubev1alpha1.ExternalPeerPhaseFailed:
			return nil, fmt.Errorf("controller marked peer as Failed: %s", LastConditionMessage(cr.Status.Conditions))
		case wirekubev1alpha1.ExternalPeerPhaseRevoked:
			return nil, fmt.Errorf("peer is Revoked")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for Phase=Active (current=%q): %s",
				cr.Status.Phase, LastConditionMessage(cr.Status.Conditions))
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Delete removes an external peer by name.
func Delete(ctx context.Context, c client.Client, name string) error {
	cr := &wirekubev1alpha1.WireKubeExternalPeer{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, cr); err != nil {
		return fmt.Errorf("get external peer: %w", err)
	}
	if err := c.Delete(ctx, cr); err != nil {
		return fmt.Errorf("delete external peer: %w", err)
	}
	return nil
}

// RenderConfig builds the WireGuard conf for an external peer.
func RenderConfig(privateKey string, cr *wirekubev1alpha1.WireKubeExternalPeer) string {
	allowed := cr.Status.AllowedDestinations
	if len(allowed) == 0 {
		allowed = []string{cr.Status.AssignedMeshIP}
	}
	mtu := EffectiveMTU(cr)
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&b, "Address = %s\n", cr.Status.AssignedMeshIP)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", cr.Status.IngressPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "Endpoint = %s\n", cr.Status.RelayEndpoint)
	fmt.Fprintf(&b, "PersistentKeepalive = 25\n")
	return b.String()
}

// EffectiveMTU returns the client-facing MTU from status, spec, or default.
func EffectiveMTU(cr *wirekubev1alpha1.WireKubeExternalPeer) int32 {
	if cr.Status.MTU > 0 {
		return cr.Status.MTU
	}
	if cr.Spec.MTU > 0 {
		return cr.Spec.MTU
	}
	return wirekubev1alpha1.DefaultExternalPeerMTU
}

// LastConditionMessage formats the most recent condition for command/UI output.
func LastConditionMessage(conds []metav1.Condition) string {
	if len(conds) == 0 {
		return "(no conditions yet)"
	}
	c := conds[len(conds)-1]
	return fmt.Sprintf("%s: %s", c.Reason, c.Message)
}
