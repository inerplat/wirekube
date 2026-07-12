package wsgateway

import (
	"context"
	"encoding/base64"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
	controllerfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

func TestAuthenticatePodBoundAgent(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "wirekube-system", Name: "agent-worker2", UID: types.UID("pod-uid")},
		Spec:       corev1.PodSpec{ServiceAccountName: "wirekube-agent", NodeName: "worker2"},
	}
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "worker2"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: base64.StdEncoding.EncodeToString(key)},
	}
	auth := testAuthenticator(t, pod, peer)
	auth.TokenReviews.(*fake.Clientset).PrependReactor("create", "tokenreviews", tokenReviewReactor(authenticationv1.UserInfo{
		Username: "system:serviceaccount:wirekube-system:wirekube-agent",
		Extra: map[string]authenticationv1.ExtraValue{
			"authentication.kubernetes.io/pod-name": {"agent-worker2"},
			"authentication.kubernetes.io/pod-uid":  {"pod-uid"},
		},
	}))

	got, peerName, err := auth.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if peerName != "worker2" || string(got[:]) != string(key) {
		t.Fatalf("got peer=%q key=%x", peerName, got)
	}
}

func TestAuthenticateDedicatedPeerServiceAccount(t *testing.T) {
	key := make([]byte, 32)
	peer := &wirekubev1alpha1.WireKubePeer{
		ObjectMeta: metav1.ObjectMeta{Name: "worker7"},
		Spec:       wirekubev1alpha1.WireKubePeerSpec{PublicKey: base64.StdEncoding.EncodeToString(key)},
	}
	auth := testAuthenticator(t, peer)
	auth.TokenReviews.(*fake.Clientset).PrependReactor("create", "tokenreviews", tokenReviewReactor(authenticationv1.UserInfo{
		Username: "system:serviceaccount:wirekube-system:wirekube-relay-peer-worker7",
	}))

	_, peerName, err := auth.Authenticate(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if peerName != "worker7" {
		t.Fatalf("peerName=%q", peerName)
	}
}

func TestAuthenticateRejectsUnboundSharedAgentToken(t *testing.T) {
	auth := testAuthenticator(t)
	auth.TokenReviews.(*fake.Clientset).PrependReactor("create", "tokenreviews", tokenReviewReactor(authenticationv1.UserInfo{
		Username: "system:serviceaccount:wirekube-system:wirekube-agent",
	}))

	if _, _, err := auth.Authenticate(context.Background(), "token"); err == nil {
		t.Fatal("expected unbound agent token to be rejected")
	}
}

func testAuthenticator(t *testing.T, objects ...runtime.Object) *Authenticator {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return &Authenticator{
		TokenReviews:             fake.NewSimpleClientset(),
		Client:                   controllerfake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build(),
		Audience:                 "wirekube-relay",
		AgentServiceAccount:      "wirekube-system/wirekube-agent",
		PeerServiceAccountPrefix: "wirekube-relay-peer-",
	}
}

func tokenReviewReactor(user authenticationv1.UserInfo) clientgotesting.ReactionFunc {
	return func(action clientgotesting.Action) (bool, runtime.Object, error) {
		review := action.(clientgotesting.CreateAction).GetObject().(*authenticationv1.TokenReview).DeepCopy()
		review.Status.Authenticated = true
		review.Status.Audiences = []string{"wirekube-relay"}
		review.Status.User = user
		return true, review, nil
	}
}
