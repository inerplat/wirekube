package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/inerplat/wirekube/pkg/relay"
)

func main() {
	addr := flag.String("addr", ":3478", "TCP listen address")
	fwLow := flag.Int("forwarder-port-low", 0, "lowest UDP port the legacy per-peer forwarder may allocate (inclusive); 0 disables it")
	fwHigh := flag.Int("forwarder-port-high", 0, "highest UDP port the legacy per-peer forwarder may allocate (inclusive); 0 disables it")
	externalWGAddr := flag.String("external-wg-addr", "", "optional UDP listen address for shared raw-WireGuard external peers")
	externalWGIngress := flag.String("external-wg-ingress-pubkey", "", "optional base64 WireGuard public key of a fixed in-cluster ingress peer for --external-wg-addr; empty enables dynamic ingress fanout")
	relayID := flag.String("relay-id", "", "unique replica identity for clustering; defaults to the hostname")
	clusterKube := flag.Bool("cluster-kube", false, "join other relay replicas through a Kubernetes-lease peer registry")
	clusterAddr := flag.String("cluster-addr", ":3479", "TCP listen address for replica-to-replica forwarding (requires --cluster-kube)")
	flag.Parse()

	if envAddr := os.Getenv("WIREKUBE_RELAY_ADDR"); envAddr != "" {
		*addr = envAddr
	}
	if v := os.Getenv("WIREKUBE_FORWARDER_PORT_LOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*fwLow = n
		}
	}
	if v := os.Getenv("WIREKUBE_FORWARDER_PORT_HIGH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*fwHigh = n
		}
	}
	if v := os.Getenv("WIREKUBE_EXTERNAL_WG_ADDR"); v != "" {
		*externalWGAddr = v
	}
	if v := os.Getenv("WIREKUBE_EXTERNAL_WG_INGRESS_PUBKEY"); v != "" {
		*externalWGIngress = v
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("wirekube-relay starting on %s", *addr)

	srv := relay.NewServer()
	if *clusterKube {
		if err := enableKubeCluster(srv, *relayID, *clusterAddr); err != nil {
			log.Fatalf("enable cluster: %v", err)
		}
	}
	if *fwHigh > 0 && *fwLow > 0 && *fwHigh >= *fwLow {
		if err := srv.EnableForwarder(uint16(*fwLow), uint16(*fwHigh)); err != nil {
			log.Fatalf("enable forwarder: %v", err)
		}
		log.Printf("wirekube-relay forwarder pool: %d-%d", *fwLow, *fwHigh)
	} else {
		log.Printf("wirekube-relay legacy per-peer forwarder disabled")
	}
	if *externalWGAddr != "" {
		var ingress [relay.PubKeySize]byte
		if *externalWGIngress != "" {
			parsed, err := parsePubKey(*externalWGIngress)
			if err != nil {
				log.Fatalf("external WG ingress pubkey: %v", err)
			}
			ingress = parsed
		}
		if err := srv.EnableExternalWGListener(*externalWGAddr, ingress); err != nil {
			log.Fatalf("enable external WG listener: %v", err)
		}
	}
	if err := srv.ListenAndServe(*addr); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// enableKubeCluster wires the server into the replica mesh: an in-cluster
// lease registry for peer ownership plus a replica-to-replica listener. The
// advertised address is POD_IP + the cluster listener port, so the pod spec
// must inject POD_IP (downward API) alongside POD_NAME/POD_NAMESPACE.
func enableKubeCluster(srv *relay.Server, relayID, clusterAddr string) error {
	if relayID == "" {
		relayID = os.Getenv("POD_NAME")
	}
	if relayID == "" {
		host, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("relay-id unset and hostname unavailable: %w", err)
		}
		relayID = host
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "wirekube-system"
	}
	podIP := os.Getenv("POD_IP")
	if podIP == "" {
		return fmt.Errorf("--cluster-kube requires the POD_IP env var (downward API)")
	}
	_, port, err := net.SplitHostPort(clusterAddr)
	if err != nil {
		return fmt.Errorf("parse --cluster-addr %q: %w", clusterAddr, err)
	}
	selfAddr := net.JoinHostPort(podIP, port)

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	registry := relay.NewKubeRegistry(client, namespace, relayID, selfAddr)
	cluster := relay.NewCluster(registry)
	srv.EnableCluster(cluster)

	ctx := context.Background()
	go registry.Run(ctx)
	go func() {
		if err := cluster.ListenAndServe(ctx, clusterAddr); err != nil {
			log.Fatalf("cluster listener: %v", err)
		}
	}()
	log.Printf("wirekube-relay cluster enabled: id=%s addr=%s namespace=%s", relayID, selfAddr, namespace)
	return nil
}

func parsePubKey(s string) ([relay.PubKeySize]byte, error) {
	var key [relay.PubKeySize]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, err
	}
	if len(raw) != relay.PubKeySize {
		return key, fmt.Errorf("decoded key length = %d, want %d", len(raw), relay.PubKeySize)
	}
	copy(key[:], raw)
	return key, nil
}
