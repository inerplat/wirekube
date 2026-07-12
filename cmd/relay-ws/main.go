package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/relay/wsgateway"
)

func main() {
	addr := flag.String("addr", ":8081", "HTTP listen address")
	backendAddr := flag.String("backend-addr", "127.0.0.1:3478", "raw TCP relay backend")
	path := flag.String("path", "/relay", "WebSocket endpoint path")
	tlsCertFile := flag.String("tls-cert-file", "", "TLS certificate file")
	tlsPrivateKeyFile := flag.String("tls-private-key-file", "", "TLS private key file")
	audience := flag.String("audience", "wirekube-relay", "required ServiceAccount token audience")
	agentServiceAccount := flag.String("agent-service-account", "wirekube-system/wirekube-agent", "allowed Pod-bound agent ServiceAccount")
	peerServiceAccountPrefix := flag.String("peer-service-account-prefix", "wirekube-relay-peer-", "prefix for dedicated kubectl-issued per-peer ServiceAccounts")
	flag.Parse()

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Kubernetes clientset: %v", err)
	}
	scheme := clientgoscheme.Scheme
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		log.Fatalf("WireKube scheme: %v", err)
	}
	kubeClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("Kubernetes client: %v", err)
	}

	authenticator := &wsgateway.Authenticator{
		TokenReviews:             clientset,
		Client:                   kubeClient,
		Audience:                 *audience,
		AgentServiceAccount:      *agentServiceAccount,
		PeerServiceAccountPrefix: *peerServiceAccountPrefix,
	}
	server := wsgateway.NewServer(authenticator, *backendAddr, *path)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("wirekube-relay-ws listening on %s%s, backend %s", *addr, *path, *backendAddr)
	if err := wsgateway.ListenAndServe(ctx, *addr, server.Handler(), *tlsCertFile, *tlsPrivateKeyFile); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}
