// agent is the WireKube per-node agent.
// It runs as a DaemonSet on VPN-enabled nodes and manages the WireGuard interface.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	agentpkg "github.com/wirekube/wirekube/pkg/agent"
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

	opts := zap.Options{Development: true}
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
	// On failure (e.g. CNI not ready, API unreachable) we proceed with defaults;
	// the agent's setup retry loop will re-read mesh config once available.
	meshList := &wirekubev1alpha1.WireKubeMeshList{}
	if listErr := k8sClient.List(context.Background(), meshList); listErr != nil {
		log.Info("WireKubeMesh read failed (will retry in agent loop)", "error", listErr)
	} else if len(meshList.Items) > 0 {
		mesh := &meshList.Items[0]

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

	wgMgr, err := wireguard.NewManager(ifaceName, listenPort, mtu, kp)
	if err != nil {
		log.Error(err, "creating WireGuard manager")
		os.Exit(1)
	}
	defer wgMgr.Close()

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

	a := agentpkg.NewAgent(k8sClient, wgMgr, nodeName, podName, podNamespace)
	ctx := ctrl.SetupSignalHandler()
	log.Info("starting agent", "node", nodeName)
	if err := a.Run(ctx); err != nil && err != context.Canceled {
		log.Error(err, "agent error")
		os.Exit(1)
	}
}
