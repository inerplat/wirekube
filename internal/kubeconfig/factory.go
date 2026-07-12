package kubeconfig

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Options struct {
	Kubeconfig string
	Context    string
	Namespace  string
	Timeout    time.Duration
}

type Factory struct {
	options Options
	scheme  *runtime.Scheme
}

func New(options Options, scheme *runtime.Scheme) *Factory {
	return &Factory{options: options, scheme: scheme}
}

func (f *Factory) RESTConfig() (*rest.Config, error) {
	config, err := f.clientConfig().ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load Kubernetes configuration: %w", err)
	}
	config.Timeout = f.options.Timeout
	return config, nil
}

func (f *Factory) Client() (client.Client, error) {
	config, err := f.RESTConfig()
	if err != nil {
		return nil, err
	}
	c, err := client.New(config, client.Options{Scheme: f.scheme})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return c, nil
}

func (f *Factory) Discovery() (discovery.DiscoveryInterface, error) {
	config, err := f.RESTConfig()
	if err != nil {
		return nil, err
	}
	c, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes discovery client: %w", err)
	}
	return c, nil
}

func (f *Factory) RawConfig() (clientcmdapi.Config, error) {
	config, err := f.clientConfig().RawConfig()
	if err != nil {
		return clientcmdapi.Config{}, fmt.Errorf("load kubeconfig: %w", err)
	}
	return config, nil
}

func (f *Factory) Namespace() (string, error) {
	if f.options.Namespace != "" {
		return f.options.Namespace, nil
	}
	namespace, _, err := f.clientConfig().Namespace()
	if err != nil {
		return "", fmt.Errorf("resolve Kubernetes namespace: %w", err)
	}
	return namespace, nil
}

func (f *Factory) clientConfig() clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if f.options.Kubeconfig != "" {
		loadingRules.ExplicitPath = f.options.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: f.options.Context}
	if f.options.Namespace != "" {
		overrides.Context.Namespace = f.options.Namespace
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
}
