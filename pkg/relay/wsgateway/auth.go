package wsgateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	relayproto "github.com/wirekube/wirekube/pkg/relay"
)

const serviceAccountUsernamePrefix = "system:serviceaccount:"

type Authenticator struct {
	TokenReviews             kubernetes.Interface
	Client                   client.Client
	Audience                 string
	AgentServiceAccount      string
	PeerServiceAccountPrefix string
}

func (a *Authenticator) Authenticate(ctx context.Context, token string) ([relayproto.PubKeySize]byte, string, error) {
	var zero [relayproto.PubKeySize]byte
	if token == "" {
		return zero, "", fmt.Errorf("bearer token is empty")
	}

	review, err := a.TokenReviews.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{a.Audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return zero, "", fmt.Errorf("TokenReview: %w", err)
	}
	if !review.Status.Authenticated {
		return zero, "", fmt.Errorf("token was not authenticated: %s", review.Status.Error)
	}
	if !contains(review.Status.Audiences, a.Audience) {
		return zero, "", fmt.Errorf("token audience %q was not accepted", a.Audience)
	}

	namespace, serviceAccount, err := parseServiceAccountUsername(review.Status.User.Username)
	if err != nil {
		return zero, "", err
	}
	peerName, err := a.peerForIdentity(ctx, namespace, serviceAccount, review.Status.User.Extra)
	if err != nil {
		return zero, "", err
	}

	peer := &wirekubev1alpha1.WireKubePeer{}
	if err := a.Client.Get(ctx, client.ObjectKey{Name: peerName}, peer); err != nil {
		return zero, "", fmt.Errorf("get WireKubePeer %q: %w", peerName, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(peer.Spec.PublicKey)
	if err != nil || len(decoded) != relayproto.PubKeySize {
		return zero, "", fmt.Errorf("WireKubePeer %q has an invalid public key", peerName)
	}
	var expected [relayproto.PubKeySize]byte
	copy(expected[:], decoded)
	return expected, peerName, nil
}

func (a *Authenticator) peerForIdentity(ctx context.Context, namespace, serviceAccount string, extra map[string]authenticationv1.ExtraValue) (string, error) {
	identity := namespace + "/" + serviceAccount
	if identity == a.AgentServiceAccount {
		podName := firstExtra(extra, "authentication.kubernetes.io/pod-name")
		podUID := firstExtra(extra, "authentication.kubernetes.io/pod-uid")
		if podName == "" || podUID == "" {
			return "", fmt.Errorf("agent token is not bound to a Pod")
		}
		pod := &corev1.Pod{}
		if err := a.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, pod); err != nil {
			return "", fmt.Errorf("get bound Pod %s/%s: %w", namespace, podName, err)
		}
		if string(pod.UID) != podUID {
			return "", fmt.Errorf("bound Pod UID does not match")
		}
		if pod.Spec.ServiceAccountName != serviceAccount {
			return "", fmt.Errorf("bound Pod service account does not match")
		}
		if pod.Spec.NodeName == "" {
			return "", fmt.Errorf("bound Pod is not scheduled")
		}
		return pod.Spec.NodeName, nil
	}

	if a.PeerServiceAccountPrefix != "" && strings.HasPrefix(serviceAccount, a.PeerServiceAccountPrefix) {
		peerName := strings.TrimPrefix(serviceAccount, a.PeerServiceAccountPrefix)
		if peerName == "" {
			return "", fmt.Errorf("peer service account has no peer suffix")
		}
		return peerName, nil
	}
	return "", fmt.Errorf("service account %s is not allowed", identity)
}

func parseServiceAccountUsername(username string) (string, string, error) {
	if !strings.HasPrefix(username, serviceAccountUsernamePrefix) {
		return "", "", fmt.Errorf("identity %q is not a Kubernetes ServiceAccount", username)
	}
	parts := strings.Split(strings.TrimPrefix(username, serviceAccountUsernamePrefix), ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid ServiceAccount identity %q", username)
	}
	return parts[0], parts[1], nil
}

func firstExtra(extra map[string]authenticationv1.ExtraValue, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
