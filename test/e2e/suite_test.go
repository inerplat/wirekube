// Package e2e contains end-to-end tests using controller-runtime's envtest.
// It spins up a real kube-apiserver + etcd and runs the WireKube controllers against them.
//
// Prerequisites:
//
//	KUBEBUILDER_ASSETS must point to envtest binaries.
//	Run: go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
//	     setup-envtest use 1.30.0 --bin-dir /tmp/wirekube-envtest-bins
//	     export KUBEBUILDER_ASSETS=/tmp/wirekube-envtest-bins/k8s/1.30.0-$(go env GOOS)-$(go env GOARCH)
package e2e

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
	"github.com/wirekube/wirekube/pkg/controller"
)

var (
	k8sClient  client.Client
	testEnv    *envtest.Environment
	testScheme = k8sruntime.NewScheme()
	cancelFn   context.CancelFunc
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(testScheme))
	utilruntime.Must(appsv1.AddToScheme(testScheme))
	utilruntime.Must(corev1.AddToScheme(testScheme))
}

// TestMain starts the envtest environment and runs all tests.
func TestMain(m *testing.M) {
	log.SetLogger(zap.New(zap.UseDevMode(true)))

	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	crdDir := filepath.Join(repoRoot, "config", "crd")

	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		assets = "/tmp/wirekube-envtest-bins/k8s/1.30.0-darwin-arm64"
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdDir},
		ErrorIfCRDPathMissing: true,
		BinaryAssetsDirectory: assets,
	}

	cfg, err := testEnv.Start()
	if err != nil {
		panic("failed to start envtest: " + err.Error())
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		panic("failed to create k8sClient: " + err.Error())
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                testScheme,
		Metrics:               metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		panic("failed to create manager: " + err.Error())
	}

	if err = (&controller.WireKubeMeshReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to setup WireKubeMesh controller: " + err.Error())
	}

	if err = (&controller.WireKubePeerReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to setup WireKubePeer controller: " + err.Error())
	}

	if err = (&controller.WireKubeGatewayReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		panic("failed to setup WireKubeGateway controller: " + err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelFn = cancel

	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic("manager exited with error: " + err.Error())
		}
	}()

	code := m.Run()

	cancel()
	if err := testEnv.Stop(); err != nil {
		panic("failed to stop envtest: " + err.Error())
	}
	os.Exit(code)
}

// eventually polls fn until it returns true or timeout elapses.
func eventually(t *testing.T, fn func() bool, timeout, interval time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

const (
	defaultTimeout  = 15 * time.Second
	defaultInterval = 200 * time.Millisecond
)
