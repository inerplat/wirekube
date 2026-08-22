package install

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func TestDefaultUninstallPreservesCRDsAndCustomResources(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme, apiextensionsv1.AddToScheme, wirekubev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"}
	bundle, err := Render(options)
	if err != nil {
		t.Fatal(err)
	}
	inventory := Inventory{SchemaVersion: SchemaVersion, InstallationID: "installation-1", InstalledAt: time.Now(), UpdatedAt: time.Now(), Options: options, Resources: bundle.Resources}
	stampBundleInstallation(bundle, inventory.InstallationID)
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	objects := []client.Object{
		&corev1.ConfigMap{ObjectMeta: objectMeta(InventoryName, options.Namespace), Data: map[string]string{"inventory.json": string(data)}},
	}
	for _, object := range bundle.Objects {
		if typed, ok := object.(client.Object); ok {
			objects = append(objects, typed)
		}
	}
	for _, crd := range bundle.CRDs {
		objects = append(objects, crd)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	if _, err := (Installer{Client: c}).Uninstall(context.Background(), options.Namespace, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, &wirekubev1alpha1.WireKubeMesh{}); err != nil {
		t.Fatalf("mesh was removed: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: bundle.CRDs[0].Name}, &apiextensionsv1.CustomResourceDefinition{}); err != nil {
		t.Fatalf("CRD was removed: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: options.Namespace, Name: "wirekube-agent"}, &appsv1.DaemonSet{}); err == nil {
		t.Fatal("agent DaemonSet was not removed")
	}
}

func TestPurgeDeletesCRDsAndCustomResources(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme, apiextensionsv1.AddToScheme, wirekubev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"}
	bundle, err := Render(options)
	if err != nil {
		t.Fatal(err)
	}
	inventory := Inventory{SchemaVersion: SchemaVersion, InstallationID: "installation-1", InstalledAt: time.Now(), UpdatedAt: time.Now(), Options: options, Resources: bundle.Resources}
	stampBundleInstallation(bundle, inventory.InstallationID)
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	objects := []client.Object{
		&corev1.ConfigMap{ObjectMeta: objectMeta(InventoryName, options.Namespace), Data: map[string]string{"inventory.json": string(data)}},
	}
	for _, object := range bundle.Objects {
		if typed, ok := object.(client.Object); ok {
			objects = append(objects, typed)
		}
	}
	for _, crd := range bundle.CRDs {
		objects = append(objects, crd)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()

	if _, err := (Installer{Client: c}).Uninstall(context.Background(), options.Namespace, true); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, &wirekubev1alpha1.WireKubeMesh{}); err == nil {
		t.Fatal("mesh custom resource was not purged")
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: bundle.CRDs[0].Name}, &apiextensionsv1.CustomResourceDefinition{}); err == nil {
		t.Fatal("CRD was not purged")
	}
}

func TestInstallIsIdempotentWithSameInventory(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: true}
	options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0"}
	plan := Plan{SchemaVersion: SchemaVersion, Namespace: options.Namespace, Image: options.Image, Relay: options.Relay, MeshCIDR: options.MeshCIDR}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := (Installer{Client: c}).Apply(ctx, plan, options, "install")
	if err != nil {
		t.Fatal(err)
	}
	second, err := (Installer{Client: c}).Apply(ctx, plan, options, "install")
	if err != nil {
		t.Fatal(err)
	}
	if first.InstallationID == "" || second.InstallationID != first.InstallationID {
		t.Fatalf("installation IDs: first=%q second=%q", first.InstallationID, second.InstallationID)
	}
}

func TestAdoptForcesFieldOwnershipAndPlainInstallDoesNot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		adopt bool
	}{
		{"plain install never forces", false},
		{"adopt forces ownership", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := installTestScheme(t)
			base := fake.NewClientBuilder().WithScheme(scheme).Build()
			c := &applyTestClient{Client: base, ready: true, forcedApplies: map[string]bool{}}
			options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0", Adopt: tc.adopt}
			plan := Plan{SchemaVersion: SchemaVersion, Namespace: options.Namespace, Image: options.Image, Relay: options.Relay, MeshCIDR: options.MeshCIDR}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := (Installer{Client: c}).Apply(ctx, plan, options, "install"); err != nil {
				t.Fatal(err)
			}
			if len(c.forcedApplies) == 0 {
				t.Fatal("no apply patches were observed")
			}
			for name, forced := range c.forcedApplies {
				if name == InventoryName {
					if forced {
						t.Fatalf("inventory %s must never be force-applied", name)
					}
					continue
				}
				if forced != tc.adopt {
					t.Fatalf("object %s force=%t, want %t", name, forced, tc.adopt)
				}
			}
		})
	}
}

func TestInstallRejectsSecondNamespaceWithoutChangingClusterRBAC(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: true}
	firstOptions := Options{Namespace: "wirekube-a", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0"}
	secondOptions := firstOptions
	secondOptions.Namespace = "wirekube-b"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := (Installer{Client: c}).Apply(ctx, Plan{}, firstOptions, "install")
	if err != nil {
		t.Fatal(err)
	}
	_, err = (Installer{Client: c}).Apply(ctx, Plan{}, secondOptions, "install")
	if err == nil || !strings.Contains(err.Error(), "already installed cluster-wide in namespace wirekube-a") {
		t.Fatalf("error=%v", err)
	}

	binding := &rbacv1.ClusterRoleBinding{}
	if err := base.Get(ctx, client.ObjectKey{Name: "wirekube-agent"}, binding); err != nil {
		t.Fatal(err)
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Namespace != firstOptions.Namespace {
		t.Fatalf("ClusterRoleBinding subjects=%v", binding.Subjects)
	}
	if got := binding.Labels[InstallationIDLabel]; got != first.InstallationID {
		t.Fatalf("installation label=%q, want %q", got, first.InstallationID)
	}
}

func TestUpgradeInventoryFailureRestoresPreviousObjects(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: true}
	oldOptions := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0"}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := (Installer{Client: c}).Apply(ctx, Plan{}, oldOptions, "install"); err != nil {
		t.Fatal(err)
	}
	newOptions := oldOptions
	newOptions.Image = "registry.example.test/wirekube@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	c.failPatchName = InventoryName
	_, err := (Installer{Client: c}).Apply(ctx, Plan{}, newOptions, "upgrade")
	if err == nil || !strings.Contains(err.Error(), "write installation inventory") {
		t.Fatalf("error=%v", err)
	}

	daemonSet := &appsv1.DaemonSet{}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-agent"}, daemonSet); err != nil {
		t.Fatal(err)
	}
	if got := daemonSet.Spec.Template.Spec.Containers[0].Image; got != oldOptions.Image {
		t.Fatalf("agent image=%q, want rolled back image %q", got, oldOptions.Image)
	}
	inventory, err := (Installer{Client: base}).LoadInventory(ctx, oldOptions.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Image != oldOptions.Image {
		t.Fatalf("inventory image=%q, want %q", inventory.Image, oldOptions.Image)
	}
}

func TestUpgradeStaleDeleteFailureRestoresInventoryAndDeletedResources(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: true}
	oldOptions := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0"}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := (Installer{Client: c}).Apply(ctx, Plan{}, oldOptions, "install"); err != nil {
		t.Fatal(err)
	}

	newOptions := oldOptions
	newOptions.Relay = RelayNone
	newOptions.RelayUDP = false
	c.failDeleteName = "wirekube-relay"
	_, upgradeErr := (Installer{Client: c}).Apply(ctx, Plan{}, newOptions, "upgrade")
	if upgradeErr == nil || !strings.Contains(upgradeErr.Error(), "remove resources no longer selected") {
		t.Fatalf("error=%v", upgradeErr)
	}

	udpService := &corev1.Service{}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-relay-udp"}, udpService); err != nil {
		t.Fatalf("deleted stale Service was not restored after %v: %v", upgradeErr, err)
	}
	inventory, err := (Installer{Client: base}).LoadInventory(ctx, oldOptions.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Options.Relay != RelayLoadBalancer || !inventory.Options.RelayUDP {
		t.Fatalf("inventory options were not rolled back: %+v", inventory.Options)
	}
}

func TestUpgradeFromTCPLoadBalancerToWSSReplacesEntrypoint(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: true}
	oldOptions := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0"}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := (Installer{Client: c}).Apply(ctx, Plan{}, oldOptions, "install"); err != nil {
		t.Fatal(err)
	}
	oldDaemonSet := &appsv1.DaemonSet{}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-agent"}, oldDaemonSet); err != nil {
		t.Fatal(err)
	}
	oldRevision := oldDaemonSet.Spec.Template.Annotations["wirekube.io/relay-config-revision"]

	newOptions := oldOptions
	newOptions.RelayTransport = RelayTransportWSS
	newOptions.RelayEndpoint = "wss://relay.example.test/relay"
	if _, err := (Installer{Client: c}).Apply(ctx, Plan{}, newOptions, "upgrade"); err != nil {
		t.Fatal(err)
	}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-relay"}, &corev1.Service{}); !apierrors.IsNotFound(err) {
		t.Fatalf("raw TCP LoadBalancer was not removed: %v", err)
	}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-relay-ws"}, &appsv1.Deployment{}); err != nil {
		t.Fatalf("WebSocket gateway Deployment missing: %v", err)
	}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-relay-udp"}, &corev1.Service{}); err != nil {
		t.Fatalf("UDP LoadBalancer missing: %v", err)
	}
	newDaemonSet := &appsv1.DaemonSet{}
	if err := base.Get(ctx, types.NamespacedName{Namespace: oldOptions.Namespace, Name: "wirekube-agent"}, newDaemonSet); err != nil {
		t.Fatal(err)
	}
	newRevision := newDaemonSet.Spec.Template.Annotations["wirekube.io/relay-config-revision"]
	if oldRevision == "" || newRevision == "" || oldRevision == newRevision {
		t.Fatalf("agent relay config revision did not change: old=%q new=%q", oldRevision, newRevision)
	}
	inventory, err := (Installer{Client: base}).LoadInventory(ctx, oldOptions.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Options.RelayTransport != RelayTransportWSS || inventory.Options.RelayEndpoint != newOptions.RelayEndpoint || !inventory.Options.RelayUDP {
		t.Fatalf("inventory options=%+v", inventory.Options)
	}
}

func TestFreshInstallCRDTimeoutRollsBackCreatedCRDs(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: false}
	options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"}
	bundle, err := Render(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := (Installer{Client: c}).Apply(ctx, Plan{}, options, "install"); err == nil {
		t.Fatal("install unexpectedly succeeded")
	}
	for _, crd := range bundle.CRDs {
		err := base.Get(context.Background(), client.ObjectKey{Name: crd.Name}, &apiextensionsv1.CustomResourceDefinition{})
		if err == nil {
			t.Fatalf("created CRD %s was not rolled back", crd.Name)
		}
	}
}

func TestInstallConflictPreservesUnmanagedResourceAndRollsBackNewObjects(t *testing.T) {
	scheme := installTestScheme(t)
	unmanaged := &corev1.ServiceAccount{ObjectMeta: objectMeta("wirekube-agent", "wirekube-system")}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(unmanaged).Build()
	c := &applyTestClient{Client: base, ready: true}
	options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", WireKubeVersion: "v1.0.0"}
	bundle, err := Render(options)
	if err != nil {
		t.Fatal(err)
	}

	_, err = (Installer{Client: c}).Apply(context.Background(), Plan{}, options, "install")
	if err == nil || !strings.Contains(err.Error(), "not managed by wirekubectl") {
		t.Fatalf("error=%v", err)
	}
	if err := base.Get(context.Background(), client.ObjectKeyFromObject(unmanaged), &corev1.ServiceAccount{}); err != nil {
		t.Fatalf("unmanaged resource was removed: %v", err)
	}
	for _, crd := range bundle.CRDs {
		if err := base.Get(context.Background(), client.ObjectKey{Name: crd.Name}, &apiextensionsv1.CustomResourceDefinition{}); err == nil {
			t.Fatalf("created CRD %s was not rolled back", crd.Name)
		}
	}
}

func TestSameInstallConfigIgnoresTransientFlags(t *testing.T) {
	left := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only"}
	right := left
	right.DryRun = true
	right.Adopt = true
	right.Timeout = time.Minute
	if !sameInstallConfig(left, right) {
		t.Fatal("transient command flags changed the installation identity")
	}
	right.Image = "registry.example.test/wirekube@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if sameInstallConfig(left, right) {
		t.Fatal("different images were treated as the same installation")
	}
}

func TestSameInstallConfigTreatsLegacyEmptyTransportAsTCP(t *testing.T) {
	legacy := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayLoadBalancer, RelayUDP: true, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only"}
	current := legacy
	current.RelayTransport = RelayTransportTCP
	if !sameInstallConfig(legacy, current) {
		t.Fatal("legacy empty relay transport was not treated as tcp")
	}
	current.RelayTransport = RelayTransportWSS
	if sameInstallConfig(legacy, current) {
		t.Fatal("wss transport was treated as the legacy tcp transport")
	}
}

func TestSameInstallConfigTreatsLegacyZeroListenPortAsDefault(t *testing.T) {
	legacy := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayLoadBalancer, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", RelayTransport: RelayTransportTCP}
	current := legacy
	current.ListenPort = DefaultListenPort
	if !sameInstallConfig(legacy, current) {
		t.Fatal("legacy zero listen port was not treated as the default")
	}
	current.ListenPort = 51822
	if sameInstallConfig(legacy, current) {
		t.Fatal("a custom listen port was treated as the legacy default")
	}
	current.ListenPort = DefaultListenPort
	current.ImagePullSecrets = []string{"ncloud-registry"}
	if sameInstallConfig(legacy, current) {
		t.Fatal("a differing image pull secret list was treated as the same config")
	}
}

func TestLiveMeshListenPort(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := wirekubev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mesh := &wirekubev1alpha1.WireKubeMesh{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: wirekubev1alpha1.WireKubeMeshSpec{ListenPort: 51822}}
	withMesh := Planner{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(mesh).Build()}
	if got := withMesh.liveMeshListenPort(context.Background()); got != 51822 {
		t.Fatalf("liveMeshListenPort=%d, want 51822", got)
	}
	empty := Planner{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	if got := empty.liveMeshListenPort(context.Background()); got != 0 {
		t.Fatalf("liveMeshListenPort=%d, want 0 for a cluster without a mesh", got)
	}
}

func TestAdoptReplacesObjectsWithImmutableFieldConflicts(t *testing.T) {
	scheme := installTestScheme(t)
	oldSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "wirekube-agent"}}
	newSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "wirekube-agent"}}
	newDS := func() *appsv1.DaemonSet {
		return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "wirekube-system", Name: "wirekube-agent"}, Spec: appsv1.DaemonSetSpec{Selector: newSelector}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	t.Run("adopt replaces via orphan delete and recreate", func(t *testing.T) {
		existing := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "wirekube-system", Name: "wirekube-agent"}, Spec: appsv1.DaemonSetSpec{Selector: oldSelector}}
		base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
		c := &applyTestClient{Client: base, ready: true, immutableApplyNames: map[string]bool{"wirekube-agent": true}}
		outcome, err := (Installer{Client: c}).applyObject(ctx, newDS(), true, "install-id", false)
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.recreated {
			t.Fatal("outcome was not marked as recreated")
		}
		current := &appsv1.DaemonSet{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "wirekube-system", Name: "wirekube-agent"}, current); err != nil {
			t.Fatal(err)
		}
		if current.Spec.Selector.MatchLabels["app.kubernetes.io/name"] != "wirekube-agent" {
			t.Fatalf("selector was not replaced: %v", current.Spec.Selector)
		}
	})

	t.Run("without adopt the conflict surfaces", func(t *testing.T) {
		existing := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "wirekube-system", Name: "wirekube-agent", Labels: map[string]string{"app.kubernetes.io/managed-by": "wirekubectl"}}, Spec: appsv1.DaemonSetSpec{Selector: oldSelector}}
		base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
		c := &applyTestClient{Client: base, ready: true, immutableApplyNames: map[string]bool{"wirekube-agent": true}}
		if _, err := (Installer{Client: c}).applyObject(ctx, newDS(), false, "install-id", true); err == nil || !strings.Contains(err.Error(), "field is immutable") {
			t.Fatalf("err=%v, want the surfaced immutable-field conflict", err)
		}
	})

	t.Run("a failed recreate restores the deleted predecessor", func(t *testing.T) {
		existing := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "wirekube-system", Name: "wirekube-agent"}, Spec: appsv1.DaemonSetSpec{Selector: oldSelector}}
		base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
		// failCreateAfterDelete makes the post-deletion apply fail the way a
		// webhook rejection or a quota denial would.
		c := &applyTestClient{Client: base, ready: true, immutableApplyNames: map[string]bool{"wirekube-agent": true}, failCreateAfterDelete: true}
		_, err := (Installer{Client: c}).applyObject(ctx, newDS(), true, "install-id", false)
		if err == nil || !strings.Contains(err.Error(), "restored") {
			t.Fatalf("err=%v, want a failure reporting the restore", err)
		}
		current := &appsv1.DaemonSet{}
		if getErr := c.Get(ctx, client.ObjectKey{Namespace: "wirekube-system", Name: "wirekube-agent"}, current); getErr != nil {
			t.Fatalf("the predecessor was not restored: %v", getErr)
		}
		if current.Spec.Selector.MatchLabels["app"] != "wirekube-agent" {
			t.Fatalf("restored selector=%v, want the original", current.Spec.Selector)
		}
	})

	t.Run("CRDs are never replaced", func(t *testing.T) {
		existing := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: "wirekubemeshes.wirekube.io"}}
		base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
		c := &applyTestClient{Client: base, ready: true, immutableApplyNames: map[string]bool{"wirekubemeshes.wirekube.io": true}}
		desired := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: "wirekubemeshes.wirekube.io"}}
		if _, err := (Installer{Client: c}).applyObject(ctx, desired, true, "install-id", false); err == nil || !strings.Contains(err.Error(), "field is immutable") {
			t.Fatalf("err=%v, want the surfaced conflict instead of a CRD replacement", err)
		}
		if err := c.Get(ctx, client.ObjectKey{Name: "wirekubemeshes.wirekube.io"}, &apiextensionsv1.CustomResourceDefinition{}); err != nil {
			t.Fatalf("CRD disappeared: %v", err)
		}
	})
}

func TestAdoptClaimsResourcesOrphanedByAMissingInventory(t *testing.T) {
	orphan := func() *appsv1.DaemonSet {
		return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
			Namespace: "wirekube-system",
			Name:      "wirekube-agent",
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "wirekubectl", InstallationIDLabel: "installation-from-a-lost-inventory"},
		}}
	}
	desired := func() *appsv1.DaemonSet {
		return &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "wirekube-system", Name: "wirekube-agent"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	scheme := installTestScheme(t)
	withoutAdopt := &applyTestClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan()).Build(), ready: true}
	if _, err := (Installer{Client: withoutAdopt}).applyObject(ctx, desired(), false, "new-installation", false); err == nil || !strings.Contains(err.Error(), "--adopt") {
		t.Fatalf("err=%v, want a refusal that points at --adopt", err)
	}

	withAdopt := &applyTestClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan()).Build(), ready: true}
	if _, err := (Installer{Client: withAdopt}).applyObject(ctx, desired(), true, "new-installation", false); err != nil {
		t.Fatalf("--adopt must claim an orphaned resource, got %v", err)
	}
}

func TestUnreachableReadinessKeepsResourcesAndRecordsTheReason(t *testing.T) {
	scheme := installTestScheme(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	c := &applyTestClient{Client: base, ready: true, agentNeverReady: true, honorContext: true}
	options := Options{Namespace: "wirekube-system", Image: testImage, Relay: RelayNone, MeshCIDR: "100.96.0.0/11", NodeAddresses: "mesh-only", WireKubeVersion: "v1.0.0", Timeout: time.Second}
	plan := Plan{SchemaVersion: SchemaVersion, Namespace: options.Namespace, Image: options.Image, Relay: options.Relay, MeshCIDR: options.MeshCIDR}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := (Installer{Client: c}).Apply(ctx, plan, options, "install")
	if err != nil {
		t.Fatalf("an unreachable readiness condition must not fail the installation: %v", err)
	}
	if result.Ready {
		t.Fatal("result claims readiness that was never reached")
	}
	if result.NotReadyReason == "" {
		t.Fatal("result does not explain why readiness is incomplete")
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "wirekube-system", Name: "wirekube-agent"}, &appsv1.DaemonSet{}); err != nil {
		t.Fatalf("the agent DaemonSet was rolled back instead of kept: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "wirekube-system", Name: InventoryName}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("the inventory was not recorded, so a rerun cannot upgrade: %v", err)
	}
}

func TestUninstallDeletesResourcesRecordedByInventory(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	resource := Resource{APIVersion: "v1", Kind: "ConfigMap", Namespace: "wirekube-system", Name: "legacy-wirekube-resource"}
	inventory := Inventory{
		SchemaVersion:  SchemaVersion,
		InstallationID: "installation-1",
		Options:        Options{Namespace: "wirekube-system"},
		Resources:      []Resource{resource},
	}
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.ConfigMap{ObjectMeta: managedObjectMeta(resource.Name, resource.Namespace)},
		&corev1.ConfigMap{ObjectMeta: objectMeta(InventoryName, resource.Namespace), Data: map[string]string{"inventory.json": string(data)}},
	).Build()

	if _, err := (Installer{Client: c}).Uninstall(context.Background(), resource.Namespace, false); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: resource.Namespace, Name: resource.Name}, &corev1.ConfigMap{}); err == nil {
		t.Fatal("resource recorded by the inventory was not deleted")
	}
}

func TestUninstallRefusesToDeleteUnmanagedRecordedResource(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	resource := Resource{APIVersion: "v1", Kind: "ConfigMap", Namespace: "wirekube-system", Name: "user-owned"}
	inventory := Inventory{
		SchemaVersion:  SchemaVersion,
		InstallationID: "installation-1",
		Options:        Options{Namespace: resource.Namespace},
		Resources:      []Resource{resource},
	}
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.ConfigMap{ObjectMeta: objectMeta(resource.Name, resource.Namespace)},
		&corev1.ConfigMap{ObjectMeta: objectMeta(InventoryName, resource.Namespace), Data: map[string]string{"inventory.json": string(data)}},
	).Build()

	_, err = (Installer{Client: c}).Uninstall(context.Background(), resource.Namespace, false)
	if err == nil || !strings.Contains(err.Error(), "not managed by wirekubectl") {
		t.Fatalf("error=%v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: resource.Namespace, Name: resource.Name}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("unmanaged resource was deleted: %v", err)
	}
}

func TestUninstallRefusesResourceOwnedByDifferentInstallation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	resource := Resource{APIVersion: "v1", Kind: "ConfigMap", Namespace: "wirekube-system", Name: "owned-by-another-installation"}
	inventory := Inventory{
		SchemaVersion:  SchemaVersion,
		InstallationID: "installation-2",
		Options:        Options{Namespace: resource.Namespace},
		Resources:      []Resource{resource},
	}
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.ConfigMap{ObjectMeta: managedObjectMeta(resource.Name, resource.Namespace)},
		&corev1.ConfigMap{ObjectMeta: objectMeta(InventoryName, resource.Namespace), Data: map[string]string{"inventory.json": string(data)}},
	).Build()

	_, err = (Installer{Client: c}).Uninstall(context.Background(), resource.Namespace, false)
	if err == nil || !strings.Contains(err.Error(), "belongs to installation") {
		t.Fatalf("error=%v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: resource.Namespace, Name: resource.Name}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("resource owned by another installation was deleted: %v", err)
	}
}

func TestRemoveStaleResourcesDeletesOnlyResourcesAbsentFromNewPlan(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	stale := Resource{APIVersion: "v1", Kind: "Service", Namespace: "wirekube-system", Name: "wirekube-relay-udp"}
	retained := Resource{APIVersion: "v1", Kind: "Service", Namespace: "wirekube-system", Name: "wirekube-relay"}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Service{ObjectMeta: managedObjectMeta(stale.Name, stale.Namespace)},
		&corev1.Service{ObjectMeta: managedObjectMeta(retained.Name, retained.Namespace)},
	).Build()

	installer := Installer{Client: c}
	if err := installer.removeStaleResources(context.Background(), []Resource{retained, stale}, []Resource{retained}, "installation-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: stale.Namespace, Name: stale.Name}, &corev1.Service{}); err == nil {
		t.Fatal("stale resource was not deleted")
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: retained.Namespace, Name: retained.Name}, &corev1.Service{}); err != nil {
		t.Fatalf("retained resource was deleted: %v", err)
	}
}

func objectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace}
}

func managedObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "wirekubectl", InstallationIDLabel: "installation-1"}}
}

func installTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, rbacv1.AddToScheme, apiextensionsv1.AddToScheme, wirekubev1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	return scheme
}

type applyTestClient struct {
	client.Client
	ready          bool
	failPatchName  string
	failDeleteName string
	forcedApplies  map[string]bool
	// immutableApplyNames simulates a server-side immutable-field rejection:
	// apply patches over an EXISTING object with this name fail the way a
	// changed DaemonSet spec.selector does, while a create after deletion
	// succeeds.
	immutableApplyNames map[string]bool
	// failCreateAfterDelete makes the apply that follows a replacement
	// deletion fail, the way a webhook or quota rejection would.
	failCreateAfterDelete bool
	sawDelete             bool
	// agentNeverReady keeps the agent DaemonSet permanently short of its
	// desired count, the way a NotReady or drained node does.
	agentNeverReady bool
	// honorContext rejects writes once the context expires, the way a real
	// API client does. The fake client ignores deadlines, so without this a
	// step that runs after the whole timeout was consumed still succeeds.
	honorContext bool
}

func (c *applyTestClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if c.honorContext && ctx.Err() != nil {
		return ctx.Err()
	}
	if object.GetName() == c.failPatchName {
		return fmt.Errorf("injected patch failure for %s", object.GetName())
	}
	if patch.Type() != types.ApplyPatchType {
		return c.Client.Patch(ctx, object, patch, options...)
	}
	if c.immutableApplyNames[object.GetName()] {
		probe := reflect.New(reflect.TypeOf(object).Elem()).Interface().(client.Object)
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(object), probe); err == nil {
			return apierrors.NewInvalid(object.GetObjectKind().GroupVersionKind().GroupKind(), object.GetName(), field.ErrorList{field.Invalid(field.NewPath("spec", "selector"), "", "field is immutable")})
		}
	}
	if c.failCreateAfterDelete && c.sawDelete {
		return fmt.Errorf("injected post-deletion apply failure for %s", object.GetName())
	}
	if c.forcedApplies != nil {
		resolved := &client.PatchOptions{}
		for _, option := range options {
			option.ApplyToPatch(resolved)
		}
		c.forcedApplies[object.GetName()] = resolved.Force != nil && *resolved.Force
	}
	desired := object.DeepCopyObject().(client.Object)
	c.setStatus(desired)
	existing := reflect.New(reflect.TypeOf(desired).Elem()).Interface().(client.Object)
	err := c.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	if err != nil {
		return c.Client.Create(ctx, desired)
	}
	desired.SetResourceVersion(existing.GetResourceVersion())
	return c.Client.Update(ctx, desired)
}

func (c *applyTestClient) Delete(ctx context.Context, object client.Object, options ...client.DeleteOption) error {
	if object.GetName() == c.failDeleteName {
		return fmt.Errorf("injected delete failure for %s", object.GetName())
	}
	c.sawDelete = true
	return c.Client.Delete(ctx, object, options...)
}

func (c *applyTestClient) setStatus(object client.Object) {
	if !c.ready {
		return
	}
	switch typed := object.(type) {
	case *apiextensionsv1.CustomResourceDefinition:
		typed.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue}}
	case *appsv1.DaemonSet:
		if c.agentNeverReady {
			// One node cannot run its Pod, as with a NotReady or drained
			// node: the DaemonSet is applied but never fully ready.
			typed.Status.DesiredNumberScheduled = 2
			typed.Status.UpdatedNumberScheduled = 2
			typed.Status.NumberReady = 1
			typed.Status.NumberAvailable = 1
			return
		}
		typed.Status.DesiredNumberScheduled = 1
		typed.Status.UpdatedNumberScheduled = 1
		typed.Status.NumberReady = 1
		typed.Status.NumberAvailable = 1
	case *appsv1.Deployment:
		desired := int32(1)
		if typed.Spec.Replicas != nil {
			desired = *typed.Spec.Replicas
		}
		typed.Status.UpdatedReplicas = desired
		typed.Status.ReadyReplicas = desired
		typed.Status.AvailableReplicas = desired
	case *wirekubev1alpha1.WireKubeMesh:
		// A real single-agent mesh reports ReadyPeers=0 because the agent
		// has no remote peers; install must succeed regardless.
		typed.Status.TotalPeers = 1
		typed.Status.ReadyPeers = 0
	case *corev1.Service:
		if typed.Spec.Type == corev1.ServiceTypeLoadBalancer {
			typed.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.10"}}
		}
	}
}
