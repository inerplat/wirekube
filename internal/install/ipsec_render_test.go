package install

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDefaultCharonImage(t *testing.T) {
	for image, want := range map[string]string{
		"inerplat/wirekube:v1.2.3":                     "inerplat/wirekube-charon:v1.2.3",
		"registry.example.test:5000/team/wirekube:e2e": "registry.example.test:5000/team/wirekube-charon:e2e",
		"registry.example.test:5000/team/wirekube":     "",
		"inerplat/wirekube:v1@sha256:" + sixtyFourA():  "inerplat/wirekube-charon:v1",
		"inerplat/wirekube@sha256:" + sixtyFourA():     "",
		"localhost/wirekube:e2e":                       "localhost/wirekube-charon:e2e",
	} {
		if got := DefaultCharonImage(image); got != want {
			t.Errorf("DefaultCharonImage(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestIPsecWithAnUntaggedImageNeedsACharonImage(t *testing.T) {
	o := Options{Image: "inerplat/wirekube@sha256:" + sixtyFourA(), Relay: RelayNone, MeshCIDR: "100.96.0.0/11", IPsec: true}
	if err := o.Normalize(); err == nil || !strings.Contains(err.Error(), "--charon-image") {
		t.Fatalf("Normalize = %v; want an error asking for --charon-image", err)
	}
	o.CharonImage = "inerplat/wirekube-charon@sha256:" + sixtyFourA()
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
}

func sixtyFourA() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

type renderedIPsec struct {
	agent, charon *appsv1.DaemonSet
	roles         []*rbacv1.Role
	bindings      []*rbacv1.RoleBinding
}

func renderAgent(t *testing.T, o Options) renderedIPsec {
	t.Helper()
	bundle, err := Render(o)
	if err != nil {
		t.Fatal(err)
	}
	var out renderedIPsec
	for _, object := range bundle.Objects {
		switch typed := object.(type) {
		case *appsv1.DaemonSet:
			switch typed.Name {
			case "wirekube-agent":
				out.agent = typed
			case CharonDaemonSetName:
				out.charon = typed
			}
		case *rbacv1.Role:
			out.roles = append(out.roles, typed)
		case *rbacv1.RoleBinding:
			out.bindings = append(out.bindings, typed)
		}
	}
	if out.agent == nil {
		t.Fatal("no agent DaemonSet rendered")
	}
	return out
}

func TestRenderWithoutIPsecHasNoCharon(t *testing.T) {
	r := renderAgent(t, Options{Image: "inerplat/wirekube:v1", Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1",
		CharonNodeSelector: map[string]string{"role": "gw"}})
	if r.charon != nil {
		t.Errorf("charon DaemonSet rendered without --ipsec")
	}
	if n := len(r.agent.Spec.Template.Spec.Containers); n != 1 {
		t.Errorf("%d containers without --ipsec", n)
	}
	for _, e := range r.agent.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "WIREKUBE_ENABLE_IPSEC" {
			t.Errorf("IPsec enabled without --ipsec")
		}
	}
	if len(ipsecOnly(r.roles))+len(ipsecOnlyBindings(r.bindings)) != 0 {
		t.Errorf("IPsec Secret access granted without --ipsec")
	}
}

// TestRenderScopesExternalIngressSecretAccess pins the agent's standing
// Secret access to reading the one shared external ingress identity, plus
// the create the controller needs to mint it.
func TestRenderScopesExternalIngressSecretAccess(t *testing.T) {
	r := renderAgent(t, Options{Image: "inerplat/wirekube:v1", Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1"})
	var role *rbacv1.Role
	for _, candidate := range r.roles {
		if candidate.Name == "wirekube-agent-external-ingress" {
			role = candidate
		}
	}
	if role == nil || role.Namespace != "wirekube-system" || len(role.Rules) != 2 {
		t.Fatalf("external ingress role = %+v", role)
	}
	get, create := role.Rules[0], role.Rules[1]
	if len(get.Verbs) != 1 || get.Verbs[0] != "get" || len(get.ResourceNames) != 1 || get.ResourceNames[0] != "wirekube-external-ingress" {
		t.Errorf("read rule = %+v", get)
	}
	if len(create.Verbs) != 1 || create.Verbs[0] != "create" {
		t.Errorf("create rule = %+v", create)
	}
}

func ipsecOnly(roles []*rbacv1.Role) []*rbacv1.Role {
	var out []*rbacv1.Role
	for _, r := range roles {
		if r.Name == "wirekube-agent-ipsec" {
			out = append(out, r)
		}
	}
	return out
}

func ipsecOnlyBindings(bindings []*rbacv1.RoleBinding) []*rbacv1.RoleBinding {
	var out []*rbacv1.RoleBinding
	for _, b := range bindings {
		if b.Name == "wirekube-agent-ipsec" {
			out = append(out, b)
		}
	}
	return out
}

func TestRenderWithIPsecAddsCharonAndScopedSecretAccess(t *testing.T) {
	o := Options{Image: "inerplat/wirekube:v1", Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1", IPsec: true}
	r := renderAgent(t, o)
	agent := r.agent.Spec.Template.Spec
	if len(agent.Containers) != 1 {
		t.Errorf("agent pod has %d containers; charon belongs in its own DaemonSet", len(agent.Containers))
	}
	if r.charon == nil {
		t.Fatal("no charon DaemonSet")
	}
	charon := r.charon.Spec.Template.Spec
	if len(charon.Containers) != 1 || charon.Containers[0].Image != "inerplat/wirekube-charon:v1" || !charon.HostNetwork || charon.NodeSelector != nil {
		t.Fatalf("charon pod = %+v", charon)
	}
	env := map[string]string{}
	for _, e := range agent.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env["WIREKUBE_ENABLE_IPSEC"] != "true" || env["WIREKUBE_IPSEC_VICI_SOCKET"] != "/run/wirekube-ipsec/charon.vici" {
		t.Errorf("agent env = %v", env)
	}
	hostDir := func(spec corev1.PodSpec) bool {
		mounted := false
		for _, m := range spec.Containers[0].VolumeMounts {
			mounted = mounted || (m.Name == "ipsec-run" && m.MountPath == "/run/wirekube-ipsec")
		}
		for _, v := range spec.Volumes {
			if v.Name == "ipsec-run" {
				return mounted && v.HostPath != nil && v.HostPath.Path == "/run/wirekube-ipsec"
			}
		}
		return false
	}
	if !hostDir(agent) || !hostDir(charon) {
		t.Errorf("vici socket directory not shared on the host by agent and charon")
	}
	roles, bindings := ipsecOnly(r.roles), ipsecOnlyBindings(r.bindings)
	if len(roles) != 1 || roles[0].Namespace != "wirekube-system" || len(roles[0].Rules) != 1 ||
		roles[0].Rules[0].Resources[0] != "secrets" || len(roles[0].Rules[0].Verbs) != 1 || roles[0].Rules[0].Verbs[0] != "get" {
		t.Errorf("roles = %+v", roles)
	}
	if len(bindings) != 1 || bindings[0].Subjects[0].Name != "wirekube-agent" {
		t.Errorf("bindings = %+v", bindings)
	}

	o.CharonImage = "registry.example.test/charon:custom"
	o.CharonNodeSelector = map[string]string{"wirekube.io/gateway": "true"}
	r = renderAgent(t, o)
	if got := r.charon.Spec.Template.Spec.Containers[0].Image; got != "registry.example.test/charon:custom" {
		t.Errorf("explicit charon image ignored: %s", got)
	}
	if got := r.charon.Spec.Template.Spec.NodeSelector; got["wirekube.io/gateway"] != "true" || len(got) != 1 {
		t.Errorf("charon node selector = %v", got)
	}
	if r.agent.Spec.Template.Spec.NodeSelector != nil {
		t.Errorf("charon node selector leaked into the agent: %v", r.agent.Spec.Template.Spec.NodeSelector)
	}
}

func TestIPsecPlanRequiresRoleAccess(t *testing.T) {
	o := Options{Image: "inerplat/wirekube:v1", Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1", IPsec: true}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range installationAccessRequirements(o) {
		if r.Name == "wirekube-agent-ipsec" {
			found[r.Resource+"/"+r.Verb] = true
		}
	}
	for _, r := range installationAccessRequirements(o) {
		if r.Name == CharonDaemonSetName {
			found[r.Resource+"/"+r.Verb] = true
		}
	}
	for _, want := range []string{"roles/get", "roles/patch", "roles/delete", "rolebindings/get", "rolebindings/patch", "rolebindings/delete",
		"daemonsets/get", "daemonsets/patch", "daemonsets/delete"} {
		if !found[want] {
			t.Errorf("missing access requirement %s", want)
		}
	}
}

func TestWaitCharonReady(t *testing.T) {
	charon := func(desired, ready int32) *appsv1.DaemonSet {
		return &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: CharonDaemonSetName, Namespace: "wirekube-system", Generation: 1},
			Status:     appsv1.DaemonSetStatus{ObservedGeneration: 1, DesiredNumberScheduled: desired, UpdatedNumberScheduled: ready, NumberReady: ready},
		}
	}
	o := Options{Namespace: "wirekube-system", IPsec: true, CharonNodeSelector: map[string]string{"role": "gw"}}

	c := fake.NewClientBuilder().WithScheme(installTestScheme(t)).WithObjects(charon(2, 2)).Build()
	if err := (Installer{Client: c}).waitCharonReady(context.Background(), o); err != nil {
		t.Fatalf("rolled-out charon: %v", err)
	}

	c = fake.NewClientBuilder().WithScheme(installTestScheme(t)).WithObjects(charon(0, 0)).Build()
	if err := (Installer{Client: c}).waitCharonReady(context.Background(), o); err == nil || !strings.Contains(err.Error(), "no node matches") {
		t.Fatalf("charon on no node: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c = fake.NewClientBuilder().WithScheme(installTestScheme(t)).WithObjects(charon(2, 1)).Build()
	if err := (Installer{Client: c}).waitCharonReady(ctx, o); err == nil {
		t.Fatal("half-ready charon reported ready")
	}
}
