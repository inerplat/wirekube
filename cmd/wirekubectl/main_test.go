package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	internalinstall "github.com/inerplat/wirekube/internal/install"
	internalversion "github.com/inerplat/wirekube/internal/version"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/externalpeer"
)

const lifecycleTestImage = "registry.example.test/wirekube@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestMeshInitPreservesExistingSpec(t *testing.T) {
	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			ListenPort: 51822,
			MeshCIDR:   "198.18.0.0/16",
			Relay: &wirekubev1alpha1.RelaySpec{
				Mode:     "always",
				Provider: "external",
				External: &wirekubev1alpha1.ExternalRelaySpec{Endpoint: "relay.example.test:3478"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mesh).Build()
	runMeshInit(t, c)

	got := &wirekubev1alpha1.WireKubeMesh{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ListenPort != 51822 || got.Spec.MeshCIDR != "198.18.0.0/16" || got.Spec.Relay == nil || got.Spec.Relay.Mode != "always" {
		t.Fatalf("existing spec was changed: %+v", got.Spec)
	}
}

func TestMeshInitPatchesOnlyExplicitPort(t *testing.T) {
	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: wirekubev1alpha1.WireKubeMeshSpec{
			ListenPort: 51820,
			MeshCIDR:   "198.18.0.0/16",
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mesh).Build()
	runMeshInit(t, c, "--port", "51999")

	got := &wirekubev1alpha1.WireKubeMesh{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ListenPort != 51999 || got.Spec.MeshCIDR != "198.18.0.0/16" {
		t.Fatalf("unexpected spec: %+v", got.Spec)
	}
}

func TestVersionJSON(t *testing.T) {
	original := internalversion.Current()
	internalversion.Version = "v1.2.3"
	internalversion.Commit = "abcdef0"
	internalversion.BuildDate = "2026-07-12T00:00:00Z"
	t.Cleanup(func() {
		internalversion.Version = original.Version
		internalversion.Commit = original.Commit
		internalversion.BuildDate = original.BuildDate
		internalversion.DefaultImage = original.DefaultImage
	})

	oldOutput := options.output
	options.output = "json"
	t.Cleanup(func() { options.output = oldOutput })
	var out bytes.Buffer
	cmd := versionCmd()
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got internalversion.Info
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "v1.2.3" || got.Commit != "abcdef0" {
		t.Fatalf("version info=%+v", got)
	}
}

func TestUninstallPurgeRequiresSeparateConfirmationFlag(t *testing.T) {
	oldOutput := options.output
	options.output = "text"
	t.Cleanup(func() { options.output = oldOutput })
	cmd := newRootCommand()
	cmd.SetArgs([]string{"uninstall", "--purge", "--yes"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--confirm-purge") {
		t.Fatalf("error=%v", err)
	}
}

func TestInstallJSONRequiresNonInteractiveAcknowledgement(t *testing.T) {
	oldOutput := options.output
	options.output = "text"
	t.Cleanup(func() { options.output = oldOutput })
	cmd := newRootCommand()
	cmd.SetArgs([]string{"install", "--output", "json"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--yes or --dry-run") {
		t.Fatalf("error=%v", err)
	}
}

func TestInspectInstallationIncludesCRDAgentAndMeshReadiness(t *testing.T) {
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "wirekubemeshes.wirekube.io", Labels: map[string]string{"app.kubernetes.io/managed-by": "wirekubectl"}},
		Status:     apiextensionsv1.CustomResourceDefinitionStatus{Conditions: []apiextensionsv1.CustomResourceDefinitionCondition{{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue}}},
	}
	daemonSet := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-agent", Namespace: "wirekube-system", Labels: map[string]string{"app.kubernetes.io/managed-by": "wirekubectl"}},
		Spec:       appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", Image: lifecycleTestImage}}}}},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2},
	}
	mesh := &wirekubev1alpha1.WireKubeMesh{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"app.kubernetes.io/managed-by": "wirekubectl"}},
		Status:     wirekubev1alpha1.WireKubeMeshStatus{TotalPeers: 2, ReadyPeers: 1},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(crd, daemonSet, mesh).Build()
	inventory := &internalinstall.Inventory{
		InstallationID:  "installation-1",
		WireKubeVersion: "v1.0.0",
		Image:           lifecycleTestImage,
		Options:         internalinstall.Options{Namespace: "wirekube-system", Relay: internalinstall.RelayNone},
		Resources: []internalinstall.Resource{
			{APIVersion: apiextensionsv1.SchemeGroupVersion.String(), Kind: "CustomResourceDefinition", Name: crd.Name, Preserve: true},
			{APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "DaemonSet", Namespace: daemonSet.Namespace, Name: daemonSet.Name},
			{APIVersion: wirekubev1alpha1.GroupVersion.String(), Kind: "WireKubeMesh", Name: mesh.Name, Preserve: true},
		},
	}

	status := inspectInstallation(context.Background(), c, inventory)
	if status.Ready || !status.ComponentsReady || status.ConnectivityReady {
		t.Fatalf("status should distinguish installed components from incomplete connectivity: %+v", status)
	}
	if len(status.Components) != 3 {
		t.Fatalf("components=%v", status.Components)
	}
}

func TestWriteDoctorResultReturnsFailureAfterWritingJSON(t *testing.T) {
	oldOutput := options.output
	options.output = "json"
	t.Cleanup(func() { options.output = oldOutput })
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := writeDoctorResult(cmd, doctorOutput{SchemaVersion: internalinstall.SchemaVersion, Ready: false, Checks: []doctorCheck{{Name: "mesh", OK: false, Message: "not connected"}}})
	if err == nil || !strings.Contains(err.Error(), "failed checks") {
		t.Fatalf("error=%v", err)
	}
	if !strings.Contains(out.String(), `"ready": false`) || !strings.Contains(out.String(), `"mesh"`) {
		t.Fatalf("JSON output=%s", out.String())
	}
}

func TestUpgradeUsesReleasedDefaultImageInsteadOfStoredImage(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("image", "", "")
	flags := &lifecycleFlags{image: lifecycleTestImage}
	stored := internalinstall.Options{Image: "registry.example.test/wirekube@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}

	applyStoredLifecycleDefaults(cmd, flags, stored)
	if flags.image != lifecycleTestImage {
		t.Fatalf("image=%q, want released CLI default", flags.image)
	}

	flags.image = ""
	applyStoredLifecycleDefaults(cmd, flags, stored)
	if flags.image != stored.Image {
		t.Fatalf("image=%q, want stored fallback %q", flags.image, stored.Image)
	}
}

func runMeshInit(t *testing.T, c client.Client, args ...string) {
	t.Helper()
	oldClient, oldOutput := options.client, options.output
	options.client = func() (client.Client, error) { return c, nil }
	options.output = "text"
	t.Cleanup(func() {
		options.client = oldClient
		options.output = oldOutput
	})
	cmd := meshCmd()
	cmd.SetArgs(append([]string{"init"}, args...))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestRenderConfIncludesExternalPeerMTU(t *testing.T) {
	conf := externalpeer.RenderConfig("private", &wirekubev1alpha1.WireKubeExternalPeer{
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:      "100.102.23.169/32",
			IngressPublicKey:    "ingress",
			RelayEndpoint:       "relay.example.com:3478",
			AllowedDestinations: []string{"100.64.0.0/10"},
		},
	})
	if !strings.Contains(conf, "MTU = 1248\n") {
		t.Fatalf("rendered config missing external peer MTU:\n%s", conf)
	}
}

func TestRenderConfUsesStatusMTU(t *testing.T) {
	conf := externalpeer.RenderConfig("private", &wirekubev1alpha1.WireKubeExternalPeer{
		Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
			MTU: 1200,
		},
		Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
			AssignedMeshIP:      "100.102.23.169/32",
			IngressPublicKey:    "ingress",
			RelayEndpoint:       "relay.example.com:3478",
			AllowedDestinations: []string{"100.64.0.0/10"},
			MTU:                 1248,
		},
	})
	if !strings.Contains(conf, "MTU = 1248\n") {
		t.Fatalf("rendered config did not prefer status MTU:\n%s", conf)
	}
}

func TestWriteExternalPeerTable(t *testing.T) {
	now := time.Date(2026, 5, 21, 15, 0, 0, 0, time.UTC)
	created := metav1.NewTime(now.Add(-1 * time.Hour))
	var out bytes.Buffer
	err := writeExternalPeerTable(&out, []wirekubev1alpha1.WireKubeExternalPeer{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "alice",
				CreationTimestamp: created,
			},
			Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
				DisplayName: "Alice",
			},
			Status: wirekubev1alpha1.WireKubeExternalPeerStatus{
				Phase:           wirekubev1alpha1.ExternalPeerPhaseActive,
				AssignedMeshIP:  "100.102.23.169/32",
				RelayEndpoint:   "vpn.example.com:3478",
				IngressPeerName: "worker1",
				MTU:             1248,
			},
		},
	}, now)
	if err != nil {
		t.Fatalf("writeExternalPeerTable: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"NAME",
		"alice",
		"Active",
		"100.102.23.169/32",
		"vpn.example.com:3478",
		"worker1",
		"1248",
		"1h",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("external peer table missing %q:\n%s", want, got)
		}
	}
}

func TestExternalPeerMTUFallsBackToDefault(t *testing.T) {
	got := externalpeer.EffectiveMTU(&wirekubev1alpha1.WireKubeExternalPeer{})
	if got != wirekubev1alpha1.DefaultExternalPeerMTU {
		t.Fatalf("EffectiveMTU = %d, want %d", got, wirekubev1alpha1.DefaultExternalPeerMTU)
	}
}
