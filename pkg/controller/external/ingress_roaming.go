package external

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/failover"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

// sharedKeyCacheTTL bounds how long a read of the shared identity is
// reused. Rotation is a Secret delete, so a short staleness is harmless.
const sharedKeyCacheTTL = time.Minute

// sharedIngressKey returns the shared external ingress identity's public
// key, creating the identity on first use. ok=false means it has never been
// readable (the Secret cannot be read or created).
func (r *Reconciler) sharedIngressKey(ctx context.Context) ([32]byte, bool) {
	r.sharedKeyMu.Lock()
	defer r.sharedKeyMu.Unlock()
	now := r.now()
	if r.sharedKeyOK && now.Sub(r.sharedKeyAt) < sharedKeyCacheTTL {
		return r.sharedKey, true
	}
	pub, err := r.loadOrCreateSharedIngressKey(ctx)
	if err != nil {
		// A failed refresh keeps the identity last read: dropping it would
		// send roaming peers down the node-key path for one bad read.
		if r.sharedKeyOK {
			logf.FromContext(ctx).Error(err, "refreshing the shared external ingress identity; keeping the one last read")
			return r.sharedKey, true
		}
		logf.FromContext(ctx).Error(err, "shared external ingress identity unavailable")
		return [32]byte{}, false
	}
	r.sharedKey, r.sharedKeyOK, r.sharedKeyAt = pub, true, now
	return pub, true
}

func (r *Reconciler) loadOrCreateSharedIngressKey(ctx context.Context) ([32]byte, error) {
	ns := r.claimNamespace()
	key := types.NamespacedName{Namespace: ns, Name: wirekubev1alpha1.ExternalIngressSecretName}
	// An uncached read: reading a Secret through the manager's client would
	// start a cluster-wide Secret informer.
	secret := &corev1.Secret{}
	err := r.reader().Get(ctx, key, secret)
	if apierrors.IsNotFound(err) {
		kp, genErr := wireguard.GenerateKeyPair()
		if genErr != nil {
			return [32]byte{}, genErr
		}
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: wirekubev1alpha1.ExternalIngressSecretName},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{wirekubev1alpha1.ExternalIngressSecretKey: []byte(kp.PrivateKeyBase64())},
		}
		err = r.Create(ctx, secret)
		if apierrors.IsAlreadyExists(err) {
			secret = &corev1.Secret{}
			err = r.reader().Get(ctx, key, secret)
		}
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("shared external ingress Secret %s: %w", key, err)
	}
	kp, err := wireguard.ParseKeyPair(string(secret.Data[wirekubev1alpha1.ExternalIngressSecretKey]))
	if err != nil {
		return [32]byte{}, fmt.Errorf("shared external ingress Secret %s: %w", key, err)
	}
	return kp.Public, nil
}

func (r *Reconciler) claimNamespace() string {
	if r.ClaimNamespace != "" {
		return r.ClaimNamespace
	}
	return "wirekube-system"
}

// roams reports whether cr's client config names the shared identity, or
// has not been issued yet and so will. Only such a peer can change ingress
// without its client config changing.
func roams(cr *wirekubev1alpha1.WireKubeExternalPeer, shared [32]byte) bool {
	issued := cr.ServerPublicKey()
	return issued == "" || issued == base64.StdEncoding.EncodeToString(shared[:])
}

// recordIssuedIngressKey stamps the shared identity onto cr's metadata the
// first time it is issued under it.
func (r *Reconciler) recordIssuedIngressKey(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, shared [32]byte) error {
	want := base64.StdEncoding.EncodeToString(shared[:])
	if cr.Annotations[wirekubev1alpha1.ExternalPeerIssuedIngressKeyAnnotation] == want {
		return nil
	}
	patch := client.MergeFrom(cr.DeepCopy())
	if cr.Annotations == nil {
		cr.Annotations = map[string]string{}
	}
	cr.Annotations[wirekubev1alpha1.ExternalPeerIssuedIngressKeyAnnotation] = want
	if err := r.Patch(ctx, cr, patch); err != nil {
		return fmt.Errorf("record issued ingress key on %s: %w", cr.Name, err)
	}
	return nil
}

// pinnedToNodeKey reports whether the node-key path may handle cr: not issued
// yet, issued under its ingress node's own key, or that node is gone. Anything
// else would get a node key its client does not have.
func (r *Reconciler) pinnedToNodeKey(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer) (bool, error) {
	issued := cr.ServerPublicKey()
	if issued == "" {
		return true, nil
	}
	if cr.Status.IngressPeerName == "" {
		return false, nil
	}
	node := &wirekubev1alpha1.WireKubePeer{}
	if err := r.Get(ctx, types.NamespacedName{Name: cr.Status.IngressPeerName}, node); err != nil {
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	}
	return node.Spec.PublicKey == issued, nil
}

// pickRoamingIngress chooses the node serving a roaming peer with the failover
// rules, with spec.ingressPeer as the preferred node.
func (r *Reconciler) pickRoamingIngress(ctx context.Context, cr *wirekubev1alpha1.WireKubeExternalPeer, relayCtl RelayController) (string, ctrl.Result, error, bool) {
	candidates, probed, res, err, ok := r.ingressCandidates(ctx, cr, relayCtl, failover.LivenessThreshold, true)
	if !ok {
		return "", res, err, false
	}
	healthy := make(map[string]bool, len(candidates))
	ranked := make([]string, 0, len(candidates))
	for _, c := range candidates {
		healthy[c.name] = true
		ranked = append(ranked, c.name)
	}
	choice := failover.Choice{
		Fallback: ranked,
		Current:  cr.Status.IngressPeerName,
		Healthy:  func(name string) bool { return healthy[name] },
	}
	if cr.Spec.IngressPeer != "" {
		choice.Preferred = []string{cr.Spec.IngressPeer}
	}
	name := r.ingressHealth.Choose(choice, r.now())
	if name == "" {
		res, err := r.markNoIngress(ctx, cr, probed)
		return "", res, err, false
	}
	return name, ctrl.Result{}, nil, true
}
