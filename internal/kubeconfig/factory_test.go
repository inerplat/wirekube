package kubeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestFactorySelectsExplicitContext(t *testing.T) {
	path := writeKubeconfig(t)
	factory := New(Options{
		Kubeconfig: path,
		Context:    "secondary",
		Timeout:    17 * time.Second,
	}, runtime.NewScheme())

	config, err := factory.RESTConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "https://secondary.example.test" {
		t.Fatalf("host=%q", config.Host)
	}
	if config.Timeout != 17*time.Second {
		t.Fatalf("timeout=%s", config.Timeout)
	}
	namespace, err := factory.Namespace()
	if err != nil {
		t.Fatal(err)
	}
	if namespace != "secondary-ns" {
		t.Fatalf("namespace=%q", namespace)
	}
}

func TestFactoryAppliesConnectionOverrides(t *testing.T) {
	factory := New(Options{
		Kubeconfig: writeKubeconfig(t),
		Overrides: &clientcmd.ConfigOverrides{
			Context:     clientcmdapi.Context{Cluster: "secondary"},
			AuthInfo:    clientcmdapi.AuthInfo{Token: "override-token", Impersonate: "alice"},
			ClusterInfo: clientcmdapi.Cluster{TLSServerName: "api.example.test"},
		},
	}, runtime.NewScheme())

	config, err := factory.RESTConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "https://secondary.example.test" {
		t.Fatalf("--cluster ignored: host=%q", config.Host)
	}
	if config.BearerToken != "override-token" || config.Impersonate.UserName != "alice" {
		t.Fatalf("auth overrides ignored: token=%q as=%q", config.BearerToken, config.Impersonate.UserName)
	}
	if config.TLSClientConfig.ServerName != "api.example.test" {
		t.Fatalf("--tls-server-name ignored: %q", config.TLSClientConfig.ServerName)
	}
}

func TestFactoryReportsMissingContext(t *testing.T) {
	factory := New(Options{
		Kubeconfig: writeKubeconfig(t),
		Context:    "missing",
	}, runtime.NewScheme())

	_, err := factory.RESTConfig()
	if err == nil || !strings.Contains(err.Error(), `context "missing" does not exist`) {
		t.Fatalf("error=%v", err)
	}
}

func writeKubeconfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	data := []byte(`apiVersion: v1
kind: Config
clusters:
  - name: primary
    cluster:
      server: https://primary.example.test
  - name: secondary
    cluster:
      server: https://secondary.example.test
contexts:
  - name: primary
    context:
      cluster: primary
      user: user
  - name: secondary
    context:
      cluster: secondary
      namespace: secondary-ns
      user: user
current-context: primary
users:
  - name: user
    user:
      token: test
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
