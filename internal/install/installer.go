package install

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

type Installer struct {
	Client client.Client
}

func (i Installer) Apply(ctx context.Context, plan Plan, options Options, operation string) (Result, error) {
	existingInventory, inventoryErr := i.LoadInventory(ctx, options.Namespace)
	if err := i.ensureSingleton(ctx, options.Namespace); err != nil {
		return Result{}, err
	}
	if operation == "install" && inventoryErr == nil {
		if !sameInstallConfig(existingInventory.Options, options) {
			return Result{}, fmt.Errorf("WireKube installation %s already exists with different options; use wirekubectl upgrade", existingInventory.InstallationID)
		}
	}
	if operation == "upgrade" && apierrors.IsNotFound(inventoryErr) {
		return Result{}, fmt.Errorf("WireKube is not installed; use wirekubectl install")
	}
	if inventoryErr != nil && !apierrors.IsNotFound(inventoryErr) {
		return Result{}, inventoryErr
	}

	installationID := uuid.NewString()
	installedAt := time.Now().UTC()
	if existingInventory != nil {
		installationID = existingInventory.InstallationID
		installedAt = existingInventory.InstalledAt
	}
	bundle, err := Render(options)
	if err != nil {
		return Result{}, err
	}
	stampBundleInstallation(bundle, installationID)

	allowLegacyOwnership := existingInventory != nil
	journal := make([]rollbackAction, 0, len(bundle.CRDs)+len(bundle.Objects)+1)
	fail := func(cause error) (Result, error) {
		return Result{}, rollbackError(cause, journal)
	}

	for _, crd := range bundle.CRDs {
		outcome, err := i.applyObject(ctx, crd, options.Adopt, installationID, allowLegacyOwnership)
		if err != nil {
			return fail(err)
		}
		journal = appendApplyRollback(journal, i.Client, outcome)
	}
	if err := i.waitForCRDs(ctx, bundle.CRDs); err != nil {
		return fail(err)
	}
	for _, object := range bundle.Objects {
		clientObject, ok := object.(client.Object)
		if !ok {
			return fail(fmt.Errorf("rendered object %T is not a Kubernetes client object", object))
		}
		outcome, err := i.applyObject(ctx, clientObject, options.Adopt, installationID, allowLegacyOwnership)
		if err != nil {
			return fail(err)
		}
		journal = appendApplyRollback(journal, i.Client, outcome)
	}
	if err := i.waitReady(ctx, options); err != nil {
		return fail(err)
	}

	storedOptions := options
	storedOptions.Yes = false
	storedOptions.DryRun = false
	storedOptions.Adopt = false
	inventory := Inventory{
		SchemaVersion:   SchemaVersion,
		InstallationID:  installationID,
		InstalledAt:     installedAt,
		UpdatedAt:       time.Now().UTC(),
		WireKubeVersion: options.WireKubeVersion,
		Image:           options.Image,
		Options:         storedOptions,
		Resources:       bundle.Resources,
	}
	inventoryOutcome, err := i.saveInventory(ctx, options.Namespace, inventory, allowLegacyOwnership)
	if err != nil {
		return fail(err)
	}
	journal = appendApplyRollback(journal, i.Client, inventoryOutcome)
	if operation == "upgrade" && existingInventory != nil {
		for _, resource := range staleResources(existingInventory.Resources, bundle.Resources) {
			deleted, err := i.deleteManagedResource(ctx, resource, installationID)
			if err != nil {
				return fail(fmt.Errorf("remove resources no longer selected by the upgrade: %w", err))
			}
			if deleted != nil {
				journal = append(journal, restoreRollback(i.Client, deleted))
			}
		}
	}
	return Result{SchemaVersion: SchemaVersion, Operation: operation, InstallationID: installationID, Ready: true, Plan: plan, CompletedAt: time.Now().UTC()}, nil
}

func sameInstallConfig(left, right Options) bool {
	return left.Namespace == right.Namespace &&
		left.Image == right.Image &&
		left.Relay == right.Relay &&
		left.RelayEndpoint == right.RelayEndpoint &&
		left.RelayUDPEndpoint == right.RelayUDPEndpoint &&
		normalizedRelayTransport(left.RelayTransport) == normalizedRelayTransport(right.RelayTransport) &&
		left.RelayUDP == right.RelayUDP &&
		left.MeshCIDR == right.MeshCIDR &&
		left.NodeAddresses == right.NodeAddresses
}

func normalizedRelayTransport(transport string) string {
	if strings.TrimSpace(transport) == "" {
		return RelayTransportTCP
	}
	return transport
}

type applyOutcome struct {
	applied  client.Object
	previous client.Object
	created  bool
	changed  bool
}

type rollbackAction struct {
	description string
	run         func(context.Context) error
}

func stampBundleInstallation(bundle *Bundle, installationID string) {
	for _, crd := range bundle.CRDs {
		setInstallationID(crd, installationID)
	}
	for _, object := range bundle.Objects {
		if clientObject, ok := object.(client.Object); ok {
			setInstallationID(clientObject, installationID)
		}
	}
}

func setInstallationID(object metav1.Object, installationID string) {
	labels := object.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	} else {
		labels = copyLabels(labels)
	}
	labels[InstallationIDLabel] = installationID
	object.SetLabels(labels)
}

func (i Installer) ensureSingleton(ctx context.Context, namespace string) error {
	configMaps := &corev1.ConfigMapList{}
	if err := i.Client.List(ctx, configMaps); err != nil {
		return fmt.Errorf("list WireKube installation inventories: %w", err)
	}
	for index := range configMaps.Items {
		configMap := &configMaps.Items[index]
		if configMap.Name != InventoryName || configMap.Namespace == namespace {
			continue
		}
		inventory := &Inventory{}
		if err := json.Unmarshal([]byte(configMap.Data["inventory.json"]), inventory); err != nil {
			return fmt.Errorf("WireKube installation inventory in namespace %s is invalid: %w", configMap.Namespace, err)
		}
		return fmt.Errorf("WireKube is already installed cluster-wide in namespace %s as installation %s; use that namespace for upgrade or uninstall", configMap.Namespace, inventory.InstallationID)
	}
	return nil
}

func (i Installer) applyObject(ctx context.Context, desired client.Object, adopt bool, installationID string, allowLegacyOwnership bool) (applyOutcome, error) {
	existing := reflect.New(reflect.TypeOf(desired).Elem()).Interface().(client.Object)
	err := i.Client.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	created := apierrors.IsNotFound(err)
	if err != nil && !created {
		return applyOutcome{}, fmt.Errorf("inspect %s %s: %w", desired.GetObjectKind().GroupVersionKind().Kind, desired.GetName(), err)
	}
	if !created {
		if _, namespace := desired.(*corev1.Namespace); namespace {
			return applyOutcome{}, nil
		}
		labels := existing.GetLabels()
		existingInstallationID := labels[InstallationIDLabel]
		if existingInstallationID != "" && existingInstallationID != installationID {
			return applyOutcome{}, fmt.Errorf("%s %s belongs to WireKube installation %s, refusing to take ownership for installation %s", desired.GetObjectKind().GroupVersionKind().Kind, client.ObjectKeyFromObject(desired), existingInstallationID, installationID)
		}
		managed := labels["app.kubernetes.io/managed-by"] == "wirekubectl"
		if !managed && !adopt {
			return applyOutcome{}, fmt.Errorf("%s %s already exists and is not managed by wirekubectl; rerun with --adopt after reviewing it", desired.GetObjectKind().GroupVersionKind().Kind, client.ObjectKeyFromObject(desired))
		}
		if managed && existingInstallationID == "" && !allowLegacyOwnership && !adopt {
			return applyOutcome{}, fmt.Errorf("%s %s is managed by wirekubectl but has no installation ID; refusing to assume ownership without --adopt", desired.GetObjectKind().GroupVersionKind().Kind, client.ObjectKeyFromObject(desired))
		}
	}
	if err := i.Client.Patch(ctx, desired, client.Apply, client.FieldOwner(FieldManager)); err != nil {
		return applyOutcome{}, fmt.Errorf("apply %s %s: %w", desired.GetObjectKind().GroupVersionKind().Kind, client.ObjectKeyFromObject(desired), err)
	}
	outcome := applyOutcome{applied: desired.DeepCopyObject().(client.Object), created: created, changed: true}
	if !created {
		outcome.previous = existing.DeepCopyObject().(client.Object)
	}
	return outcome, nil
}

func appendApplyRollback(journal []rollbackAction, c client.Client, outcome applyOutcome) []rollbackAction {
	if !outcome.changed {
		return journal
	}
	if outcome.created {
		object := outcome.applied.DeepCopyObject().(client.Object)
		installationID := object.GetLabels()[InstallationIDLabel]
		return append(journal, rollbackAction{
			description: "delete newly created " + object.GetName(),
			run: func(ctx context.Context) error {
				current := reflect.New(reflect.TypeOf(object).Elem()).Interface().(client.Object)
				current.GetObjectKind().SetGroupVersionKind(object.GetObjectKind().GroupVersionKind())
				if err := c.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
					return client.IgnoreNotFound(err)
				}
				if current.GetLabels()[InstallationIDLabel] != installationID {
					return fmt.Errorf("resource ownership changed to installation %q", current.GetLabels()[InstallationIDLabel])
				}
				return client.IgnoreNotFound(c.Delete(ctx, current))
			},
		})
	}
	return append(journal, restoreRollback(c, outcome.previous))
}

func restoreRollback(c client.Client, snapshot client.Object) rollbackAction {
	snapshot = snapshot.DeepCopyObject().(client.Object)
	return rollbackAction{
		description: "restore " + snapshot.GetName(),
		run: func(ctx context.Context) error {
			current := reflect.New(reflect.TypeOf(snapshot).Elem()).Interface().(client.Object)
			current.GetObjectKind().SetGroupVersionKind(snapshot.GetObjectKind().GroupVersionKind())
			err := c.Get(ctx, client.ObjectKeyFromObject(snapshot), current)
			if apierrors.IsNotFound(err) {
				toCreate := snapshot.DeepCopyObject().(client.Object)
				toCreate.SetResourceVersion("")
				toCreate.SetUID("")
				toCreate.SetManagedFields(nil)
				toCreate.SetCreationTimestamp(metav1.Time{})
				return c.Create(ctx, toCreate)
			}
			if err != nil {
				return err
			}
			toRestore := snapshot.DeepCopyObject().(client.Object)
			toRestore.SetResourceVersion(current.GetResourceVersion())
			return c.Update(ctx, toRestore)
		},
	}
}

func rollbackError(cause error, journal []rollbackAction) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var failures []string
	for index := len(journal) - 1; index >= 0; index-- {
		if err := journal[index].run(rollbackCtx); err != nil {
			failures = append(failures, journal[index].description+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%w; rollback failures: %s", cause, strings.Join(failures, "; "))
	}
	return cause
}

func (i Installer) waitForCRDs(ctx context.Context, crds []*apiextensionsv1.CustomResourceDefinition) error {
	for _, desired := range crds {
		if err := poll(ctx, time.Second, func() (bool, error) {
			current := &apiextensionsv1.CustomResourceDefinition{}
			if err := i.Client.Get(ctx, client.ObjectKey{Name: desired.Name}, current); err != nil {
				return false, err
			}
			for _, condition := range current.Status.Conditions {
				if condition.Type == apiextensionsv1.Established && condition.Status == apiextensionsv1.ConditionTrue {
					return true, nil
				}
			}
			return false, nil
		}); err != nil {
			return fmt.Errorf("wait for CRD %s to become Established: %w", desired.Name, err)
		}
	}
	return nil
}

func (i Installer) waitReady(ctx context.Context, options Options) error {
	var desiredAgents int32
	if err := poll(ctx, 2*time.Second, func() (bool, error) {
		daemonSet := &appsv1.DaemonSet{}
		if err := i.Client.Get(ctx, types.NamespacedName{Namespace: options.Namespace, Name: "wirekube-agent"}, daemonSet); err != nil {
			return false, err
		}
		desiredAgents = daemonSet.Status.DesiredNumberScheduled
		return desiredAgents > 0 &&
			daemonSet.Status.ObservedGeneration >= daemonSet.Generation &&
			daemonSet.Status.UpdatedNumberScheduled == desiredAgents &&
			daemonSet.Status.NumberReady == desiredAgents &&
			daemonSet.Status.NumberAvailable == desiredAgents, nil
	}); err != nil {
		return fmt.Errorf("agent DaemonSet did not become ready; run wirekubectl doctor: %w", err)
	}
	if err := poll(ctx, 2*time.Second, func() (bool, error) {
		mesh := &wirekubev1alpha1.WireKubeMesh{}
		if err := i.Client.Get(ctx, client.ObjectKey{Name: "default"}, mesh); err != nil {
			return false, err
		}
		if mesh.Status.TotalPeers < desiredAgents {
			return false, nil
		}
		// A single agent has no remote peers, so it never reports
		// Connected; require only that its peer registered.
		return desiredAgents == 1 || mesh.Status.ReadyPeers >= desiredAgents, nil
	}); err != nil {
		return fmt.Errorf("WireKubeMesh did not establish connectivity for all %d agent peers; run wirekubectl doctor: %w", desiredAgents, err)
	}
	if options.Relay == RelayLoadBalancer || options.Relay == RelayNodePort {
		if err := poll(ctx, 2*time.Second, func() (bool, error) {
			deployment := &appsv1.Deployment{}
			if err := i.Client.Get(ctx, types.NamespacedName{Namespace: options.Namespace, Name: "wirekube-relay"}, deployment); err != nil {
				return false, err
			}
			return deploymentReady(deployment), nil
		}); err != nil {
			return fmt.Errorf("relay Deployment did not become ready; run wirekubectl doctor: %w", err)
		}
		if options.RelayTransport == RelayTransportWSS {
			if err := poll(ctx, 2*time.Second, func() (bool, error) {
				deployment := &appsv1.Deployment{}
				if err := i.Client.Get(ctx, types.NamespacedName{Namespace: options.Namespace, Name: "wirekube-relay-ws"}, deployment); err != nil {
					return false, err
				}
				return deploymentReady(deployment), nil
			}); err != nil {
				return fmt.Errorf("relay WebSocket Deployment did not become ready; run wirekubectl doctor: %w", err)
			}
		}
	}
	if options.Relay == RelayLoadBalancer {
		serviceNames := []string{}
		if options.RelayTransport == RelayTransportTCP {
			serviceNames = append(serviceNames, "wirekube-relay")
		}
		if options.RelayUDP {
			serviceNames = append(serviceNames, "wirekube-relay-udp")
		}
		for _, name := range serviceNames {
			if err := poll(ctx, 2*time.Second, func() (bool, error) {
				service := &corev1.Service{}
				if err := i.Client.Get(ctx, types.NamespacedName{Namespace: options.Namespace, Name: name}, service); err != nil {
					return false, err
				}
				return len(service.Status.LoadBalancer.Ingress) > 0, nil
			}); err != nil {
				return fmt.Errorf("relay LoadBalancer Service %s has no external address; run wirekubectl doctor: %w", name, err)
			}
		}
	}
	if options.Relay == RelayNodePort {
		entrypointService := "wirekube-relay"
		if options.RelayTransport == RelayTransportWSS {
			entrypointService = "wirekube-relay-ws"
		}
		serviceNames := []string{entrypointService}
		if options.RelayUDP {
			serviceNames = append(serviceNames, "wirekube-relay-udp")
		}
		for _, name := range serviceNames {
			if err := poll(ctx, 2*time.Second, func() (bool, error) {
				service := &corev1.Service{}
				if err := i.Client.Get(ctx, types.NamespacedName{Namespace: options.Namespace, Name: name}, service); err != nil {
					return false, err
				}
				return len(service.Spec.Ports) == 1 && service.Spec.Ports[0].NodePort > 0, nil
			}); err != nil {
				return fmt.Errorf("relay NodePort Service %s has no allocated node port; run wirekubectl doctor: %w", name, err)
			}
		}
	}
	return nil
}

func deploymentReady(deployment *appsv1.Deployment) bool {
	desired := int32(1)
	if deployment.Spec.Replicas != nil {
		desired = *deployment.Spec.Replicas
	}
	return desired > 0 &&
		deployment.Status.ObservedGeneration >= deployment.Generation &&
		deployment.Status.UpdatedReplicas == desired &&
		deployment.Status.ReadyReplicas == desired &&
		deployment.Status.AvailableReplicas == desired
}

func (i Installer) saveInventory(ctx context.Context, namespace string, inventory Inventory, allowLegacyOwnership bool) (applyOutcome, error) {
	data, err := json.Marshal(inventory)
	if err != nil {
		return applyOutcome{}, err
	}
	configMap := &corev1.ConfigMap{
		TypeMeta:   typeMeta("v1", "ConfigMap"),
		ObjectMeta: metav1.ObjectMeta{Name: InventoryName, Namespace: namespace, Labels: managedLabels(inventory.WireKubeVersion)},
		Data:       map[string]string{"inventory.json": string(data)},
	}
	setInstallationID(configMap, inventory.InstallationID)
	outcome, err := i.applyObject(ctx, configMap, false, inventory.InstallationID, allowLegacyOwnership)
	if err != nil {
		return applyOutcome{}, fmt.Errorf("write installation inventory: %w", err)
	}
	return outcome, nil
}

func (i Installer) LoadInventory(ctx context.Context, namespace string) (*Inventory, error) {
	configMap := &corev1.ConfigMap{}
	if err := i.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: InventoryName}, configMap); err != nil {
		return nil, err
	}
	inventory := &Inventory{}
	if err := json.Unmarshal([]byte(configMap.Data["inventory.json"]), inventory); err != nil {
		return nil, fmt.Errorf("decode installation inventory: %w", err)
	}
	return inventory, nil
}

func (i Installer) Uninstall(ctx context.Context, namespace string, purge bool) (*Inventory, error) {
	inventory, err := i.LoadInventory(ctx, namespace)
	if err != nil {
		return nil, err
	}
	for index := len(inventory.Resources) - 1; index >= 0; index-- {
		resource := inventory.Resources[index]
		if resource.Preserve {
			continue
		}
		if _, err := i.deleteManagedResource(ctx, resource, inventory.InstallationID); err != nil {
			return nil, err
		}
	}
	if purge {
		if err := i.deleteCustomResources(ctx); err != nil {
			return nil, err
		}
		for index := len(inventory.Resources) - 1; index >= 0; index-- {
			resource := inventory.Resources[index]
			if resource.Kind != "CustomResourceDefinition" {
				continue
			}
			if _, err := i.deleteManagedResource(ctx, resource, inventory.InstallationID); err != nil {
				return nil, err
			}
		}
	}
	configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: InventoryName, Namespace: namespace}}
	if err := i.Client.Delete(ctx, configMap); err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	return inventory, nil
}

func (i Installer) removeStaleResources(ctx context.Context, previous, current []Resource, installationID string) error {
	for _, resource := range staleResources(previous, current) {
		if _, err := i.deleteManagedResource(ctx, resource, installationID); err != nil {
			return err
		}
	}
	return nil
}

func staleResources(previous, current []Resource) []Resource {
	currentKeys := make(map[string]struct{}, len(current))
	for _, resource := range current {
		currentKeys[resourceIdentity(resource)] = struct{}{}
	}
	stale := make([]Resource, 0)
	for index := len(previous) - 1; index >= 0; index-- {
		resource := previous[index]
		if resource.Preserve {
			continue
		}
		if _, exists := currentKeys[resourceIdentity(resource)]; exists {
			continue
		}
		stale = append(stale, resource)
	}
	return stale
}

func (i Installer) deleteManagedResource(ctx context.Context, resource Resource, installationID string) (client.Object, error) {
	object := objectForResource(resource)
	err := i.Client.Get(ctx, client.ObjectKey{Namespace: resource.Namespace, Name: resource.Name}, object)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect %s %s before deletion: %w", resource.Kind, resourceName(resource), err)
	}
	if object.GetLabels()["app.kubernetes.io/managed-by"] != "wirekubectl" {
		return nil, fmt.Errorf("refusing to delete %s %s because it is not managed by wirekubectl", resource.Kind, resourceName(resource))
	}
	if object.GetLabels()[InstallationIDLabel] != installationID {
		return nil, fmt.Errorf("refusing to delete %s %s because it belongs to installation %q, not %q", resource.Kind, resourceName(resource), object.GetLabels()[InstallationIDLabel], installationID)
	}
	object.SetAPIVersion(resource.APIVersion)
	object.SetKind(resource.Kind)
	snapshot := object.DeepCopyObject().(client.Object)
	if err := i.Client.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("delete %s %s: %w", resource.Kind, resourceName(resource), err)
	}
	if resource.Kind == "DaemonSet" && resource.Name == "wirekube-agent" {
		if err := poll(ctx, time.Second, func() (bool, error) {
			current := objectForResource(resource)
			err := i.Client.Get(ctx, client.ObjectKey{Namespace: resource.Namespace, Name: resource.Name}, current)
			return apierrors.IsNotFound(err), client.IgnoreNotFound(err)
		}); err != nil {
			return nil, fmt.Errorf("wait for agent shutdown before removing RBAC: %w", err)
		}
	}
	return snapshot, nil
}

func objectForResource(resource Resource) *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetAPIVersion(resource.APIVersion)
	object.SetKind(resource.Kind)
	object.SetNamespace(resource.Namespace)
	object.SetName(resource.Name)
	return object
}

func resourceIdentity(resource Resource) string {
	return resource.APIVersion + "\x00" + resource.Kind + "\x00" + resource.Namespace + "\x00" + resource.Name
}

func resourceName(resource Resource) string {
	if resource.Namespace == "" {
		return resource.Name
	}
	return resource.Namespace + "/" + resource.Name
}

func (i Installer) deleteCustomResources(ctx context.Context) error {
	externalPeers := &wirekubev1alpha1.WireKubeExternalPeerList{}
	if err := i.Client.List(ctx, externalPeers); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	for index := range externalPeers.Items {
		if err := i.Client.Delete(ctx, &externalPeers.Items[index]); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	gateways := &wirekubev1alpha1.WireKubeGatewayList{}
	if err := i.Client.List(ctx, gateways); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	for index := range gateways.Items {
		if err := i.Client.Delete(ctx, &gateways.Items[index]); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	peers := &wirekubev1alpha1.WireKubePeerList{}
	if err := i.Client.List(ctx, peers); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	for index := range peers.Items {
		if err := i.Client.Delete(ctx, &peers.Items[index]); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	meshes := &wirekubev1alpha1.WireKubeMeshList{}
	if err := i.Client.List(ctx, meshes); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	for index := range meshes.Items {
		if err := i.Client.Delete(ctx, &meshes.Items[index]); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func Manifest(bundle *Bundle) ([]byte, error) {
	var output []byte
	objects := make([]runtime.Object, 0, len(bundle.CRDs)+len(bundle.Objects))
	for _, crd := range bundle.CRDs {
		objects = append(objects, crd)
	}
	objects = append(objects, bundle.Objects...)
	for index, object := range objects {
		jsonData, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		yamlData, err := yaml.JSONToYAML(jsonData)
		if err != nil {
			return nil, err
		}
		if index > 0 {
			output = append(output, []byte("---\n")...)
		}
		output = append(output, yamlData...)
	}
	return output, nil
}

func poll(ctx context.Context, interval time.Duration, condition func() (bool, error)) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ready, err := condition()
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
