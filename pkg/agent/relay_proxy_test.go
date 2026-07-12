package agent

import (
	"context"
	"testing"

	"github.com/go-logr/logr/testr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentrelay "github.com/inerplat/wirekube/pkg/agent/relay"
)

func TestRelayProxyModeFromNodeAnnotation(t *testing.T) {
	tests := []struct {
		name       string
		env        string
		annotation string
		want       agentrelay.ProxyMode
	}{
		{name: "default direct", want: agentrelay.ProxyDisabled},
		{name: "enabled", annotation: "enabled", want: agentrelay.ProxyFromEnvironment},
		{name: "environment", annotation: "environment", want: agentrelay.ProxyFromEnvironment},
		{name: "disabled", annotation: "disabled", want: agentrelay.ProxyDisabled},
		{name: "direct", annotation: "direct", want: agentrelay.ProxyDisabled},
		{name: "env enables proxy", env: "environment", want: agentrelay.ProxyFromEnvironment},
		{name: "annotation disabled overrides env", env: "environment", annotation: "disabled", want: agentrelay.ProxyDisabled},
		{name: "annotation environment overrides env disabled", env: "disabled", annotation: "environment", want: agentrelay.ProxyFromEnvironment},
		{name: "unknown falls back to direct default", annotation: "surprise", want: agentrelay.ProxyDisabled},
		{name: "unknown falls back to env default", env: "environment", annotation: "surprise", want: agentrelay.ProxyFromEnvironment},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envRelayProxyMode, tt.env)
			annotations := map[string]string{}
			if tt.annotation != "" {
				annotations[nodeAnnotationRelayProxy] = tt.annotation
			}
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "worker1",
					Annotations: annotations,
				},
			}
			c := ctrlclientfake.NewClientBuilder().
				WithScheme(cleanupTestScheme(t)).
				WithObjects(node).
				Build()
			a := &Agent{
				log:      testr.New(t),
				client:   c,
				nodeName: "worker1",
			}

			if got := a.relayProxyMode(context.Background()); got != tt.want {
				t.Fatalf("relayProxyMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRelayProxyModeMissingNodeFallsBackToEnvironment(t *testing.T) {
	c := ctrlclientfake.NewClientBuilder().
		WithScheme(cleanupTestScheme(t)).
		Build()
	a := &Agent{
		log:      testr.New(t),
		client:   c,
		nodeName: "missing",
	}

	t.Setenv(envRelayProxyMode, "environment")
	if got := a.relayProxyMode(context.Background()); got != agentrelay.ProxyFromEnvironment {
		t.Fatalf("relayProxyMode() = %q, want %q", got, agentrelay.ProxyFromEnvironment)
	}
}

func TestRelayProxyModeMissingNodeDefaultsToDirect(t *testing.T) {
	c := ctrlclientfake.NewClientBuilder().
		WithScheme(cleanupTestScheme(t)).
		Build()
	a := &Agent{
		log:      testr.New(t),
		client:   c,
		nodeName: "missing",
	}

	if got := a.relayProxyMode(context.Background()); got != agentrelay.ProxyDisabled {
		t.Fatalf("relayProxyMode() = %q, want %q", got, agentrelay.ProxyDisabled)
	}
}
