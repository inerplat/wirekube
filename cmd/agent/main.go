// agent is the WireKube per-node agent.
// It runs as a DaemonSet on VPN-enabled nodes and manages the WireGuard interface.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	agentpkg "github.com/wirekube/wirekube/pkg/agent"
	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	externalctrl "github.com/wirekube/wirekube/pkg/controller/external"
	"github.com/wirekube/wirekube/pkg/wireguard"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	var nodeName string
	var meshName string
	var ifaceName string
	var listenPort int
	var mtu int
	var apiServer string
	var metricsAddr string

	var podName string
	var podNamespace string

	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "Name of this Kubernetes node")
	flag.StringVar(&podName, "pod-name", os.Getenv("POD_NAME"), "Name of this agent pod (used to annotate metrics scrape IP)")
	flag.StringVar(&podNamespace, "pod-namespace", os.Getenv("POD_NAMESPACE"), "Namespace of this agent pod")
	flag.StringVar(&meshName, "mesh-name", "default", "Name of the WireKubeMesh resource")
	flag.StringVar(&ifaceName, "interface", os.Getenv("WIREKUBE_INTERFACE"), "WireGuard interface name (overrides CR interfaceName)")
	flag.IntVar(&listenPort, "listen-port", 51820, "WireGuard UDP listen port")
	flag.IntVar(&mtu, "mtu", 1420, "WireGuard interface MTU")
	flag.StringVar(&apiServer, "kube-apiserver", os.Getenv("WIREKUBE_KUBE_APISERVER"), "Kubernetes API server URL (overrides in-cluster discovery)")
	flag.StringVar(&metricsAddr, "metrics-addr", ":9090", "Prometheus metrics listen address")

	// Development=false → production encoder (json) + InfoLevel gate for V(1).
	// This is the right default for steady-state agents; operators can still
	// turn on verbose traces with --zap-log-level=debug or --zap-devel=true.
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("agent")

	if nodeName == "" {
		log.Error(fmt.Errorf("node name required"), "pass --node-name or set NODE_NAME env var")
		os.Exit(1)
	}

	// Priority: --kube-apiserver flag > WireKubeMesh CR apiServerURL > in-cluster default
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Error(err, "in-cluster config failed")
		os.Exit(1)
	}

	if apiServer != "" {
		log.Info("API server set via flag/env", "server", apiServer)
		restConfig.Host = apiServer
	}

	k8sClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "creating Kubernetes client")
		os.Exit(1)
	}

	// Read WireKubeMesh CR for settings (apiServerURL, interfaceName, listenPort, mtu).
	// CNI may not be ready yet at startup (e.g. Cilium initializing); the API
	// server is unreachable until then. We MUST block here until mesh is read,
	// because listenPort committed below is used for the lifetime of the
	// wireguard-go interface — falling back to the default after a CRD-read
	// timeout produces a port mismatch with the rest of the cluster (other
	// agents discover the port from the CRD too) and the resulting agent has
	// no way to receive direct UDP. Better to crashloop until CNI is ready.
	var mesh *wirekubev1alpha1.WireKubeMesh
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	{
		const maxAttempts = 60 // ~10 minutes at 10s backoff
		backoff := 2 * time.Second
		var listErr error
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			listErr = k8sClient.List(context.Background(), meshList)
			if listErr == nil {
				break
			}
			log.Info("WireKubeMesh read failed, retrying", "attempt", attempt, "backoff", backoff, "error", listErr)
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff += 2 * time.Second
			}
		}
		if listErr != nil {
			log.Error(listErr, "WireKubeMesh unreadable after retries; cannot determine listen port — exiting")
			os.Exit(1)
		}
	}
	if len(meshList.Items) > 0 {
		mesh = &meshList.Items[0]

		if apiServer == "" && mesh.Spec.APIServerURL != "" {
			log.Info("API server overridden by WireKubeMesh CR", "server", mesh.Spec.APIServerURL)
			restConfig.Host = mesh.Spec.APIServerURL
			k8sClient, err = client.New(restConfig, client.Options{Scheme: scheme})
			if err != nil {
				log.Error(err, "creating Kubernetes client with CR apiServerURL")
				os.Exit(1)
			}
		}

		if ifaceName == "" && mesh.Spec.InterfaceName != "" {
			ifaceName = mesh.Spec.InterfaceName
		}
		if mesh.Spec.ListenPort > 0 {
			listenPort = int(mesh.Spec.ListenPort)
		}
		if mesh.Spec.MTU > 0 {
			mtu = int(mesh.Spec.MTU)
		}
	}
	log.Info("API server", "host", restConfig.Host)

	if ifaceName == "" {
		ifaceName = "wire_kube"
	}

	kp, err := wireguard.LoadOrGenerate()
	if err != nil {
		log.Error(err, "key management failed")
		os.Exit(1)
	}
	log.Info("WireGuard key ready", "publicKey", kp.PublicKeyBase64())
	log.Info("interface config", "name", ifaceName, "listenPort", listenPort, "mtu", mtu)

	// WireKube runs a single userspace (wireguard-go) engine. The custom Bind
	// drives the direct↔relay transport decision; the kernel engine was
	// removed because wgctrl's single-endpoint-per-peer model is incompatible
	// with warm-relay bimodal send (see PR #8 design notes).
	engine := wireguard.NewUserspaceEngine(ifaceName, listenPort, mtu, kp)

	// Start Prometheus metrics HTTP server.
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		log.Info("metrics server", "addr", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, mux); err != nil {
			log.Error(err, "metrics server failed")
		}
	}()

	a := agentpkg.NewAgent(log, k8sClient, engine, nodeName, podName, podNamespace, restConfig.Host)
	ctx := ctrl.SetupSignalHandler()

	// Start the WireKubeExternalPeer reconciler in a sibling controller-
	// runtime manager. It allocates relay forwarder mappings through the
	// relay control endpoint while advertising the public relay endpoint to
	// official WireGuard clients.
	relayNS := relayNamespace(podNamespace)
	if err := startExternalPeerReconciler(ctx, log, restConfig, scheme, relayNS); err != nil {
		// A reconciler-manager failure is non-fatal for the data plane
		// (cluster mesh works without external peers). Log and continue.
		log.Error(err, "external-peer reconciler failed to start; continuing without it")
	}

	log.Info("starting agent", "node", nodeName)
	if err := a.Run(ctx); err != nil && err != context.Canceled {
		log.Error(err, "agent error")
		engine.Close()
		os.Exit(1)
	}
	engine.Close()
}

func relayNamespace(podNamespace string) string {
	if podNamespace != "" {
		return podNamespace
	}
	return "wirekube-system"
}

// relayEndpointFromMesh derives the shared raw-WireGuard endpoint advertised
// to official WireGuard external peers from the mesh CR's relay configuration.
// The returned value is host:port; external peers no longer receive per-peer
// UDP forwarder ports.
func relayEndpointFromMesh(ctx context.Context, c client.Reader, mesh *wirekubev1alpha1.WireKubeMesh, namespace string) string {
	if mesh == nil || mesh.Spec.Relay == nil {
		return ""
	}
	if mesh.Spec.Relay.External != nil {
		return mesh.Spec.Relay.External.Endpoint
	}
	if mesh.Spec.Relay.Managed != nil {
		host := relayPublicHostFromService(ctx, c, namespace)
		if host == "" {
			return ""
		}
		port := int32(3478)
		if mesh.Spec.Relay.Managed.Port != 0 {
			port = mesh.Spec.Relay.Managed.Port
		}
		return net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	return ""
}

// relayControlAddrFromMesh returns an explicitly configured legacy relay
// control address. Shared external peers use relayEndpointFromMesh directly
// and do not need a relay control session.
func relayControlAddrFromMesh(mesh *wirekubev1alpha1.WireKubeMesh, _ string) string {
	if mesh == nil || mesh.Spec.Relay == nil {
		return ""
	}
	if mesh.Spec.Relay.External != nil {
		return mesh.Spec.Relay.External.ControlEndpoint
	}
	return ""
}

func relayPublicHostFromService(ctx context.Context, c client.Reader, namespace string) string {
	svc := &corev1.Service{}
	if err := c.Get(ctx, client.ObjectKey{Name: "wirekube-relay", Namespace: namespace}, svc); err != nil {
		return ""
	}
	for _, ip := range svc.Spec.ExternalIPs {
		if ip != "" {
			return ip
		}
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			return ing.IP
		}
		if ing.Hostname != "" {
			return ing.Hostname
		}
	}
	return ""
}

// startExternalPeerReconciler spins up a controller-runtime manager
// running the WireKubeExternalPeer reconciler. The manager runs in a
// background goroutine; its lifetime is bound to ctx (the agent's
// signal-aware context).
func startExternalPeerReconciler(ctx context.Context, log logr.Logger, restConfig *rest.Config, scheme *runtime.Scheme, relayNamespace string) error {
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:  "0",
		LeaderElection:          true,
		LeaderElectionID:        "wirekube-external-peer.wirekube.io",
		LeaderElectionNamespace: os.Getenv("POD_NAMESPACE"),
	})
	if err != nil {
		return fmt.Errorf("create external-peer manager: %w", err)
	}

	r := &externalctrl.Reconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Relay:  externalctrl.NewNoopRelayController(""),
		RelayResolver: func(ctx context.Context, mesh *wirekubev1alpha1.WireKubeMesh) externalctrl.RelayController {
			return relayControllerFromMesh(ctx, mgr.GetClient(), mesh, relayNamespace)
		},
	}
	if err := r.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup external-peer reconciler: %w", err)
	}

	go func() {
		log.Info("starting external-peer reconciler", "relayNamespace", relayNamespace)
		if err := mgr.Start(ctx); err != nil {
			log.Error(err, "external-peer manager exited")
		}
	}()
	return nil
}

func relayControllerFromMesh(ctx context.Context, c client.Reader, mesh *wirekubev1alpha1.WireKubeMesh, namespace string) externalctrl.RelayController {
	relayEndpoint := relayEndpointFromMesh(ctx, c, mesh, namespace)
	relayControlAddr := relayControlAddrFromMesh(mesh, namespace)
	if relayControlAddr != "" {
		return externalctrl.NewFanoutRelayController(relayControlAddr, relayEndpoint)
	}
	return externalctrl.NewNoopRelayController(relayEndpoint)
}
