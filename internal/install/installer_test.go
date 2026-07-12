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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	right.Yes = true
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
}

func (c *applyTestClient) Patch(ctx context.Context, object client.Object, patch client.Patch, options ...client.PatchOption) error {
	if object.GetName() == c.failPatchName {
		return fmt.Errorf("injected patch failure for %s", object.GetName())
	}
	if patch.Type() != types.ApplyPatchType {
		return c.Client.Patch(ctx, object, patch, options...)
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
		typed.Status.DesiredNumberScheduled = 1
		typed.Status.UpdatedNumberScheduled = 1
		typed.Status.NumberReady = 1
		typed.Status.NumberAvailable = 1
	case *appsv1.Deployment:
		typed.Status.UpdatedReplicas = 1
		typed.Status.ReadyReplicas = 1
		typed.Status.AvailableReplicas = 1
	case *wirekubev1alpha1.WireKubeMesh:
		typed.Status.TotalPeers = 1
		typed.Status.ReadyPeers = 1
	case *corev1.Service:
		if typed.Spec.Type == corev1.ServiceTypeLoadBalancer {
			typed.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.10"}}
		}
	}
}
