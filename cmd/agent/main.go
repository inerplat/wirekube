// agent is the WireKube per-node agent.
// It runs as a DaemonSet on VPN-enabled nodes and manages the WireGuard interface.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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

	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "Name of this Kubernetes node")
	flag.StringVar(&meshName, "mesh-name", "default", "Name of the WireKubeMesh resource")
	flag.StringVar(&ifaceName, "interface", "wg0", "WireGuard interface name")
	flag.IntVar(&listenPort, "listen-port", 51820, "WireGuard UDP listen port")
	flag.IntVar(&mtu, "mtu", 1420, "WireGuard interface MTU")

	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("agent")

	if nodeName == "" {
		log.Error(fmt.Errorf("node name required"), "pass --node-name or set NODE_NAME env var")
		os.Exit(1)
	}

	// Load or generate WireGuard key pair
	kp, err := wireguard.LoadOrGenerate()
	if err != nil {
		log.Error(err, "key management failed")
		os.Exit(1)
	}
	log.Info("WireGuard key ready", "publicKey", kp.PublicKeyBase64())

	// Create WireGuard manager
	wgMgr, err := wireguard.NewManager(ifaceName, listenPort, mtu, kp)
	if err != nil {
		log.Error(err, "creating WireGuard manager")
		os.Exit(1)
	}
	defer wgMgr.Close()

	// Create Kubernetes client
	k8sClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "creating Kubernetes client")
		os.Exit(1)
	}

	// Create and run agent
	a := agentpkg.NewAgent(k8sClient, wgMgr, nodeName)
	ctx := ctrl.SetupSignalHandler()
	log.Info("starting agent", "node", nodeName)
	if err := a.Run(ctx); err != nil && err != context.Canceled {
		log.Error(err, "agent error")
		os.Exit(1)
	}
}
