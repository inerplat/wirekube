package install

import (
	"context"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

const testImage = "registry.example.test/wirekube@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestOptionsRequireExplicitRelayForNonInteractiveInstall(t *testing.T) {
	options := Options{Image: testImage, Yes: true}
	if err := options.Normalize(); err == nil || !strings.Contains(err.Error(), "--relay must be specified") {
		t.Fatalf("error=%v", err)
	}
}

func TestOptionsRequireImageDigest(t *testing.T) {
	options := Options{Image: "registry.example.test/wirekube:v1", Relay: RelayNone}
	if err := options.Normalize(); err == nil || !strings.Contains(err.Error(), "pinned by digest") {
		t.Fatalf("error=%v", err)
	}
}

func TestOptionsRejectNonNumericRelayEndpointPort(t *testing.T) {
	options := Options{Image: testImage, Relay: RelayExternal, RelayEndpoint: "relay.example.test:https"}
	if err := options.Normalize(); err == nil || !strings.Contains(err.Error(), "port must be between 1 and 65535") {
		t.Fatalf("error=%v", err)
	}
}

func TestOptionsRejectUnusableExplicitAgentAPIServer(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"bare host and port", "10.0.0.5:6443", "is not a valid URL"},
		{"wrong scheme", "ftp://api.example.test:6443", "must be an https:// or http:// URL"},
		{"in-cluster service", "https://kubernetes.default.svc:443", "nodes cannot reach"},
		{"loopback", "https://127.0.0.1:6443", "loopback address"},
		{"no host", "https://", "must include a host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := Options{Image: testImage, Relay: RelayNone, AgentAPIServer: tc.value}
			err := options.Normalize()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Normalize(%q) error=%v, want it to mention %q", tc.value, err, tc.want)
			}
			if !strings.Contains(err.Error(), "--agent-apiserver") {
				t.Fatalf("error %q does not name the flag", err)
			}
		})
	}
}

func TestAgentAPIServerInClusterSentinelSkipsInjection(t *testing.T) {
	for _, sentinel := range []string{AgentAPIServerInCluster, "none", "In-Cluster"} {
		options := Options{Image: testImage, Relay: RelayNone, AgentAPIServer: sentinel, ClusterServer: "https://api.example.test:6443"}
		if err := options.Normalize(); err != nil {
			t.Fatalf("sentinel %q rejected: %v", sentinel, err)
		}
		if got := agentAPIServerURL(options); got != "" {
			t.Fatalf("sentinel %q resolved to %q, want no injection", sentinel, got)
		}
	}
}

func TestSameInstallConfigComparesResolvedAgentAPIServer(t *testing.T) {
	base := Options{Image: testImage, Relay: RelayNone, ClusterServer: "https://api.example.test:6443"}
	if !sameInstallConfig(base, base) {
		t.Fatal("identical options compared unequal")
	}
	// A different kubeconfig entry changes the rendered agent env, so it must not
	// silently pass the install identity check.
	movedServer := base
	movedServer.ClusterServer = "https://bastion.example.test:6443"
	if sameInstallConfig(base, movedServer) {
		t.Fatal("a changed kubeconfig server must be detected as a config change")
	}
	explicit := base
	explicit.AgentAPIServer = "https://direct.example.test:6443"
	if sameInstallConfig(base, explicit) {
		t.Fatal("an explicit --agent-apiserver must be detected as a config change")
	}
	// Both resolve to no injection, so they are the same effective config.
	skipped := Options{Image: testImage, Relay: RelayNone, ClusterServer: "https://127.0.0.1:6443"}
	sentinel := Options{Image: testImage, Relay: RelayNone, AgentAPIServer: AgentAPIServerInCluster, ClusterServer: "https://api.example.test:6443"}
	if !sameInstallConfig(skipped, sentinel) {
		t.Fatal("options that both skip injection compared unequal")
	}
}

func TestOptionsAcceptReachableAgentAPIServerAndSkipUndetectedServer(t *testing.T) {
	options := Options{Image: testImage, Relay: RelayNone, AgentAPIServer: "https://api.example.test:6443"}
	if err := options.Normalize(); err != nil {
		t.Fatalf("reachable --agent-apiserver rejected: %v", err)
	}
	// An undetected or in-cluster kubeconfig server must stay a silent skip, not an error.
	skipped := Options{Image: testImage, Relay: RelayNone, ClusterServer: "https://kubernetes.default.svc:443"}
	if err := skipped.Normalize(); err != nil {
		t.Fatalf("unusable kubeconfig server must not fail Normalize: %v", err)
	}
	if got := agentAPIServerURL(skipped); got != "" {
		t.Fatalf("agentAPIServerURL=%q, want empty for an in-cluster server", got)
	}
}

func TestLoadBalancerDefaultsToUDP(t *testing.T) {
	options := Options{Image: testImage, Relay: RelayLoadBalancer}
	if err := options.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !options.RelayUDP {
		t.Fatal("load-balancer relay did not enable UDP by default")
	}
}

func TestLoadBalancerAllowsExplicitUDPDisable(t *testing.T) {
	options := Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDPConfigured: true}
	if err := options.Normalize(); err != nil {
		t.Fatal(err)
	}
	if options.RelayUDP {
		t.Fatal("explicit --relay-udp=false was overwritten")
	}
}

func TestOptionsRequireWSSURLAndPath(t *testing.T) {
	for _, endpoint := range []string{"", "https://relay.example.test/relay", "wss://relay.example.test"} {
		options := Options{Image: testImage, Relay: RelayExternal, RelayTransport: RelayTransportWSS, RelayEndpoint: endpoint}
		if err := options.Normalize(); err == nil {
			t.Fatalf("endpoint %q was accepted", endpoint)
		}
	}
}

func TestRenderUsesPortableDefaultsAndSeparateRelayServices(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Manifest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(manifest)
	for _, forbidden := range []string{"eks.amazonaws.com/nodegroup", "admin-web", ":v0.0."} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("manifest contains %q", forbidden)
		}
	}
	if !strings.Contains(text, testImage) {
		t.Fatal("manifest does not contain the pinned image")
	}
	services := map[string][]corev1.ServicePort{}
	for _, object := range bundle.Objects {
		if service, ok := object.(*corev1.Service); ok {
			services[service.Name] = service.Spec.Ports
		}
	}
	if len(services["wirekube-relay"]) != 1 || services["wirekube-relay"][0].Protocol != corev1.ProtocolTCP {
		t.Fatalf("TCP relay service=%v", services["wirekube-relay"])
	}
	if len(services["wirekube-relay-udp"]) != 1 || services["wirekube-relay-udp"][0].Protocol != corev1.ProtocolUDP {
		t.Fatalf("UDP relay service=%v", services["wirekube-relay-udp"])
	}
}

func TestRenderManagedWSSGatewayAndUDPLoadBalancer(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayTransport: RelayTransportWSS, RelayEndpoint: "wss://relay.example.test/relay", MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	services := map[string]*corev1.Service{}
	deployments := map[string]*appsv1.Deployment{}
	var mesh *wirekubev1alpha1.WireKubeMesh
	var relayServiceAccount *corev1.ServiceAccount
	var relayRole *rbacv1.ClusterRole
	for _, object := range bundle.Objects {
		switch typed := object.(type) {
		case *corev1.Service:
			services[typed.Name] = typed
		case *appsv1.Deployment:
			deployments[typed.Name] = typed
		case *corev1.ServiceAccount:
			if typed.Name == "wirekube-relay" {
				relayServiceAccount = typed
			}
		case *rbacv1.ClusterRole:
			if typed.Name == "wirekube-relay" {
				relayRole = typed
			}
		case *wirekubev1alpha1.WireKubeMesh:
			mesh = typed
		}
	}
	if services["wirekube-relay"] != nil {
		t.Fatal("managed WSS rendered an unused public TCP LoadBalancer")
	}
	if service := services["wirekube-relay-ws"]; service == nil || service.Spec.Type != corev1.ServiceTypeClusterIP || service.Spec.Ports[0].Port != 8081 {
		t.Fatalf("WebSocket backend Service=%+v", service)
	}
	if service := services["wirekube-relay-udp"]; service == nil || service.Spec.Type != corev1.ServiceTypeLoadBalancer || service.Spec.Ports[0].Protocol != corev1.ProtocolUDP {
		t.Fatalf("UDP LoadBalancer Service=%+v", service)
	}
	deployment := deployments["wirekube-relay-ws"]
	if deployment == nil || deployment.Spec.Template.Spec.ServiceAccountName != "wirekube-relay" {
		t.Fatalf("WebSocket Deployment=%+v", deployment)
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 2 {
		t.Fatalf("WebSocket replicas=%v, want 2", deployment.Spec.Replicas)
	}
	if deployment.Spec.Template.Spec.Affinity == nil || deployment.Spec.Template.Spec.Affinity.PodAntiAffinity == nil || len(deployment.Spec.Template.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) == 0 {
		t.Fatal("WebSocket Deployment does not prefer spreading replicas across nodes")
	}
	args := strings.Join(deployment.Spec.Template.Spec.Containers[0].Args, " ")
	if !strings.Contains(args, "--path=/relay") || !strings.Contains(args, "--agent-service-account=wirekube-system/wirekube-agent") {
		t.Fatalf("WebSocket gateway args=%q", args)
	}
	if relayServiceAccount == nil || relayRole == nil {
		t.Fatalf("relay authentication RBAC missing: serviceAccount=%v role=%v", relayServiceAccount, relayRole)
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.Managed == nil {
		t.Fatal("managed relay configuration was not rendered")
	}
	if managed := mesh.Spec.Relay.Managed; managed.Transport != RelayTransportWSS || managed.ControlEndpoint != "wss://relay.example.test/relay" {
		t.Fatalf("managed relay=%+v", managed)
	}
}

func TestAgentUsesClusterDNSOverHostNetwork(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var agent *appsv1.DaemonSet
	for _, object := range bundle.Objects {
		if daemonSet, ok := object.(*appsv1.DaemonSet); ok && daemonSet.Name == "wirekube-agent" {
			agent = daemonSet
		}
	}
	if agent == nil {
		t.Fatal("wirekube-agent DaemonSet was not rendered")
	}
	// The agent runs on the host network but dials the relay control plane through
	// the in-cluster headless Service (wirekube-relay-control.<ns>.svc.cluster.local),
	// so it must use ClusterFirstWithHostNet; DNSDefault resolves only host names and
	// leaves every peer unable to reach the relay.
	if !agent.Spec.Template.Spec.HostNetwork {
		t.Fatal("agent must run on the host network")
	}
	if agent.Spec.Template.Spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Fatalf("agent dnsPolicy=%q, want ClusterFirstWithHostNet so host-network pods resolve cluster Services", agent.Spec.Template.Spec.DNSPolicy)
	}
}

func TestAgentReceivesDirectAPIServerFromKubeconfigServer(t *testing.T) {
	// Peer self-registration happens before the node's CNI is ready, so the agent needs a
	// reachable apiserver URL instead of the in-cluster kubernetes Service ClusterIP.
	agent := renderAgentDaemonSet(t, Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0", ClusterServer: "https://api.example.test:6443"})
	if value, ok := agentEnvValue(agent, "WIREKUBE_KUBE_APISERVER"); !ok || value != "https://api.example.test:6443" {
		t.Fatalf("WIREKUBE_KUBE_APISERVER=%q present=%t, want the kubeconfig server", value, ok)
	}
}

func TestAgentAPIServerOverrideWinsOverKubeconfigServer(t *testing.T) {
	agent := renderAgentDaemonSet(t, Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0", ClusterServer: "https://api.example.test:6443", AgentAPIServer: "https://10.0.0.5:6443"})
	if value, ok := agentEnvValue(agent, "WIREKUBE_KUBE_APISERVER"); !ok || value != "https://10.0.0.5:6443" {
		t.Fatalf("WIREKUBE_KUBE_APISERVER=%q present=%t, want the --agent-apiserver override", value, ok)
	}
}

func TestAgentOmitsAPIServerWhenUnresolvedOrInCluster(t *testing.T) {
	for name, options := range map[string]Options{
		"unset":      {Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"},
		"service":    {Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0", ClusterServer: "https://kubernetes.default.svc:443"},
		"short name": {Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0", ClusterServer: "https://kubernetes:443"},
	} {
		t.Run(name, func(t *testing.T) {
			agent := renderAgentDaemonSet(t, options)
			if value, ok := agentEnvValue(agent, "WIREKUBE_KUBE_APISERVER"); ok {
				t.Fatalf("WIREKUBE_KUBE_APISERVER=%q, want the env var to be absent", value)
			}
		})
	}
}

func TestAgentAPIServerURLSkipsUnusableTargets(t *testing.T) {
	for name, testCase := range map[string]struct {
		options Options
		want    string
	}{
		"kubeconfig server":  {options: Options{ClusterServer: "https://api.example.test:6443"}, want: "https://api.example.test:6443"},
		"plain http":         {options: Options{ClusterServer: "http://api.example.test:8080"}, want: "http://api.example.test:8080"},
		"override":           {options: Options{ClusterServer: "https://api.example.test:6443", AgentAPIServer: "https://direct.example.test:6443"}, want: "https://direct.example.test:6443"},
		"empty":              {options: Options{}, want: ""},
		"whitespace only":    {options: Options{ClusterServer: "   "}, want: ""},
		"in-cluster service": {options: Options{ClusterServer: "https://kubernetes.default.svc:443"}, want: ""},
		"in-cluster short":   {options: Options{ClusterServer: "https://kubernetes:443"}, want: ""},
		"in-cluster mixed":   {options: Options{ClusterServer: "https://KUBERNETES.default.svc:443"}, want: ""},
		"loopback v4":        {options: Options{ClusterServer: "https://127.0.0.1:6443"}, want: ""},
		"loopback v6":        {options: Options{ClusterServer: "https://[::1]:6443"}, want: ""},
		"unspecified":        {options: Options{ClusterServer: "https://0.0.0.0:6443"}, want: ""},
		"localhost":          {options: Options{ClusterServer: "https://localhost:6443"}, want: ""},
		"credentials":        {options: Options{ClusterServer: "https://admin:secret@api.example.test:6443"}, want: ""},
		"no scheme":          {options: Options{ClusterServer: "api.example.test:6443"}, want: ""},
		"no host":            {options: Options{ClusterServer: "https://"}, want: ""},
		"malformed":          {options: Options{ClusterServer: "https://api.example.test:64 43/"}, want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := agentAPIServerURL(testCase.options); got != testCase.want {
				t.Fatalf("agentAPIServerURL()=%q, want %q", got, testCase.want)
			}
		})
	}
}

func renderAgentDaemonSet(t *testing.T, options Options) *appsv1.DaemonSet {
	t.Helper()
	bundle, err := Render(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range bundle.Objects {
		if daemonSet, ok := object.(*appsv1.DaemonSet); ok && daemonSet.Name == "wirekube-agent" {
			return daemonSet
		}
	}
	t.Fatal("wirekube-agent DaemonSet was not rendered")
	return nil
}

func agentEnvValue(agent *appsv1.DaemonSet, name string) (string, bool) {
	for _, env := range agent.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			return env.Value, true
		}
	}
	return "", false
}

func TestAgentRelayConfigRevisionChangesWithTransportAndEndpoint(t *testing.T) {
	tcpBundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	wssBundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayTransport: RelayTransportWSS, RelayEndpoint: "wss://relay.example.test/relay", RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	wssEndpointBundle, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayTransport: RelayTransportWSS, RelayEndpoint: "wss://relay-alt.example.test/relay", RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	revision := func(bundle *Bundle) string {
		for _, object := range bundle.Objects {
			if daemonSet, ok := object.(*appsv1.DaemonSet); ok && daemonSet.Name == "wirekube-agent" {
				return daemonSet.Spec.Template.Annotations["wirekube.io/relay-config-revision"]
			}
		}
		return ""
	}
	tcpRevision, wssRevision, wssEndpointRevision := revision(tcpBundle), revision(wssBundle), revision(wssEndpointBundle)
	if tcpRevision == "" || wssRevision == "" || wssEndpointRevision == "" || tcpRevision == wssRevision || wssRevision == wssEndpointRevision {
		t.Fatalf("relay config revisions: tcp=%q wss=%q wssEndpoint=%q", tcpRevision, wssRevision, wssEndpointRevision)
	}
}

func TestRenderNodePortWSSUsesSeparateUDPAddress(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNodePort, RelayTransport: RelayTransportWSS, RelayEndpoint: "wss://relay.example.test/relay", RelayUDP: true, RelayUDPEndpoint: "203.0.113.10:30479", MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	var wsService *corev1.Service
	for _, object := range bundle.Objects {
		switch typed := object.(type) {
		case *wirekubev1alpha1.WireKubeMesh:
			mesh = typed
		case *corev1.Service:
			if typed.Name == "wirekube-relay-ws" {
				wsService = typed
			}
		}
	}
	if wsService == nil || wsService.Spec.Type != corev1.ServiceTypeNodePort || wsService.Spec.Ports[0].NodePort != 30478 {
		t.Fatalf("WebSocket NodePort Service=%+v", wsService)
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if external := mesh.Spec.Relay.External; external.Transport != RelayTransportWSS || external.ControlEndpoint != "wss://relay.example.test/relay" || external.Endpoint != "203.0.113.10:30479" {
		t.Fatalf("external relay=%+v", external)
	}
}

func TestNodePortUDPUsesSeparateDataAndControlEndpoints(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNodePort, RelayEndpoint: "[2001:db8::10]:30478", RelayUDP: true, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	for _, object := range bundle.Objects {
		if typed, ok := object.(*wirekubev1alpha1.WireKubeMesh); ok {
			mesh = typed
			break
		}
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if mesh.Spec.Relay.External.ControlEndpoint != "[2001:db8::10]:30478" {
		t.Fatalf("controlEndpoint=%q", mesh.Spec.Relay.External.ControlEndpoint)
	}
	if mesh.Spec.Relay.External.Endpoint != "[2001:db8::10]:30479" {
		t.Fatalf("endpoint=%q", mesh.Spec.Relay.External.Endpoint)
	}
}

func TestNodePortTCPOnlyDoesNotAdvertiseRawWireGuardEndpoint(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNodePort, RelayEndpoint: "203.0.113.10:30478", MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	for _, object := range bundle.Objects {
		if typed, ok := object.(*wirekubev1alpha1.WireKubeMesh); ok {
			mesh = typed
			break
		}
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if got := mesh.Spec.Relay.External.ControlEndpoint; got != "203.0.113.10:30478" {
		t.Fatalf("controlEndpoint=%q", got)
	}
	if got := mesh.Spec.Relay.External.Endpoint; got != "" {
		t.Fatalf("endpoint=%q, want empty without UDP", got)
	}
}

func TestExternalRelaySeparatesControlAndUDPEndpoints(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayExternal, RelayEndpoint: "relay.example.test:443", RelayUDPEndpoint: "wg.example.test:51820", MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var mesh *wirekubev1alpha1.WireKubeMesh
	for _, object := range bundle.Objects {
		if typed, ok := object.(*wirekubev1alpha1.WireKubeMesh); ok {
			mesh = typed
			break
		}
	}
	if mesh == nil || mesh.Spec.Relay == nil || mesh.Spec.Relay.External == nil {
		t.Fatal("external relay configuration was not rendered")
	}
	if got := mesh.Spec.Relay.External.ControlEndpoint; got != "relay.example.test:443" {
		t.Fatalf("controlEndpoint=%q", got)
	}
	if got := mesh.Spec.Relay.External.Endpoint; got != "wg.example.test:51820" {
		t.Fatalf("endpoint=%q", got)
	}
}

func TestDefaultAgentRBACDoesNotGrantAdministrativeCreate(t *testing.T) {
	bundle, err := Render(Options{Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var role *rbacv1.ClusterRole
	for _, object := range bundle.Objects {
		if typed, ok := object.(*rbacv1.ClusterRole); ok && typed.Name == "wirekube-agent" {
			role = typed
			break
		}
	}
	if role == nil {
		t.Fatal("agent ClusterRole was not rendered")
	}
	for _, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource != "wirekubemeshes" && resource != "wirekubegateways" && resource != "wirekubeexternalpeers" {
				continue
			}
			for _, verb := range rule.Verbs {
				if verb == "create" {
					t.Fatalf("default agent role grants create on %s: %v", resource, rule.Verbs)
				}
			}
		}
	}
}

func TestPlannerAvoidsOccupiedCIDRsWithoutMutation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}, Spec: corev1.NodeSpec{PodCIDR: "100.96.0.0/11", PodCIDRs: []string{"100.96.0.0/11"}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: corev1.ServiceSpec{ClusterIP: "10.96.0.1", ClusterIPs: []string{"10.96.0.1"}}},
	).Build()
	plan, normalized, err := (Planner{Client: client}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "auto", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.MeshCIDR == "100.96.0.0/11" || plan.MeshCIDR == "100.96.0.0/11" {
		t.Fatalf("selected occupied CIDR: %s", normalized.MeshCIDR)
	}
	var namespaces corev1.NamespaceList
	if err := client.List(context.Background(), &namespaces); err != nil {
		t.Fatal(err)
	}
	if len(namespaces.Items) != 0 {
		t.Fatalf("planning mutated the cluster: %v", namespaces.Items)
	}
}

func TestPlannerRequiresExplicitMeshCIDRForNonInteractiveInstall(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	_, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "auto", Yes: true, WireKubeVersion: "v1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "--mesh-cidr must be explicit") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlannerAllowsAutoMeshCIDRForNonMutatingDryRunWithWarning(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	plan, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "auto", Yes: true, DryRun: true, WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "best effort") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings=%v", plan.Warnings)
	}
}

func TestPlannerRejectsExplicitMeshCIDROverlap(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}, Spec: corev1.NodeSpec{PodCIDR: "198.18.0.0/24", PodCIDRs: []string{"198.18.0.0/24"}}},
	).Build()

	_, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "198.18.0.0/16", WireKubeVersion: "v1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "overlaps observed cluster or local network") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlannerWarnsAboutPublicLoadBalancerCost(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	plan, _, err := (Planner{Client: c}).Build(context.Background(), Options{Image: testImage, Relay: RelayLoadBalancer, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Warnings) == 0 || !strings.Contains(plan.Warnings[0], "provider charges") {
		t.Fatalf("warnings=%v", plan.Warnings)
	}
}

func TestPlannerFailsWhenAccessPreflightIsDenied(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reviewer := &testAccessReviewer{err: fmt.Errorf("insufficient Kubernetes permissions: patch deployments.apps")}
	_, _, err := (Planner{Client: c, AccessReviewer: reviewer}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "insufficient Kubernetes permissions") {
		t.Fatalf("error=%v", err)
	}
	if !reviewer.called {
		t.Fatal("access reviewer was not called")
	}
}

func TestPlannerIncludesCreatePermissionsForWSSResources(t *testing.T) {
	previous, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reviewer := &testAccessReviewer{}
	_, _, err = (Planner{Client: c, AccessReviewer: reviewer}).Build(context.Background(), Options{Image: testImage, Relay: RelayLoadBalancer, RelayTransport: RelayTransportWSS, RelayEndpoint: "wss://relay.example.test/relay", PreviousResources: previous.Resources, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []AccessRequirement{
		{Group: "apps", Resource: "deployments", Verb: "create", Namespace: "wirekube-system"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "create"},
		{Resource: "serviceaccounts", Verb: "create", Namespace: "wirekube-system"},
	} {
		if !containsAccessRequirement(reviewer.requirements, want) {
			t.Fatalf("missing access requirement %+v in %v", want, reviewer.requirements)
		}
	}
}

func TestPlannerIncludesDeletePermissionsForPreviousWSSResources(t *testing.T) {
	previous, err := Render(Options{Image: testImage, Relay: RelayLoadBalancer, RelayTransport: RelayTransportWSS, RelayEndpoint: "wss://relay.example.test/relay", MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reviewer := &testAccessReviewer{}
	_, _, err = (Planner{Client: c, AccessReviewer: reviewer}).Build(context.Background(), Options{Image: testImage, Relay: RelayNone, PreviousResources: previous.Resources, MeshCIDR: "203.0.113.0/24", WireKubeVersion: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []AccessRequirement{
		{Group: "apps", Resource: "deployments", Verb: "delete", Namespace: "wirekube-system", Name: "wirekube-relay-ws"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "delete", Name: "wirekube-relay"},
		{Resource: "serviceaccounts", Verb: "delete", Namespace: "wirekube-system", Name: "wirekube-relay"},
	} {
		if !containsAccessRequirement(reviewer.requirements, want) {
			t.Fatalf("missing access requirement %+v in %v", want, reviewer.requirements)
		}
	}
}

func containsAccessRequirement(requirements []AccessRequirement, want AccessRequirement) bool {
	for _, requirement := range requirements {
		if requirement == want {
			return true
		}
	}
	return false
}

type testAccessReviewer struct {
	called       bool
	err          error
	requirements []AccessRequirement
}

func (r *testAccessReviewer) Review(_ context.Context, requirements []AccessRequirement) error {
	r.called = true
	r.requirements = append([]AccessRequirement(nil), requirements...)
	if len(requirements) == 0 {
		return fmt.Errorf("no access requirements were provided")
	}
	return r.err
}
