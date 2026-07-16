package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	internalinstall "github.com/inerplat/wirekube/internal/install"
	internalconfig "github.com/inerplat/wirekube/internal/kubeconfig"
	internalversion "github.com/inerplat/wirekube/internal/version"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

type lifecycleFlags struct {
	relay              string
	relayEndpoint      string
	relayUDPEndpoint   string
	relayTransport     string
	relayUDP           bool
	relayUDPConfigured bool
	previousResources  []internalinstall.Resource
	meshCIDR           string
	nodeAddresses      string
	image              string
	excludeCIDRs       []string
	yes                bool
	dryRun             bool
	adopt              bool
}

type componentStatus struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Ready     bool   `json:"ready"`
	Desired   int32  `json:"desired,omitempty"`
	Available int32  `json:"available,omitempty"`
	Message   string `json:"message"`
}

type installationStatus struct {
	SchemaVersion     string            `json:"schemaVersion"`
	InstallationID    string            `json:"installationID"`
	WireKubeVersion   string            `json:"wireKubeVersion"`
	Image             string            `json:"image"`
	Ready             bool              `json:"ready"`
	ComponentsReady   bool              `json:"componentsReady"`
	ConnectivityReady bool              `json:"connectivityReady"`
	Components        []componentStatus `json:"components"`
	UpdatedAt         time.Time         `json:"updatedAt"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type doctorOutput struct {
	SchemaVersion string              `json:"schemaVersion"`
	Ready         bool                `json:"ready"`
	Checks        []doctorCheck       `json:"checks"`
	Installation  *installationStatus `json:"installation,omitempty"`
}

var relayReachabilityHTTPClient = http.DefaultClient

func installCmd() *cobra.Command {
	flags := &lifecycleFlags{}
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Plan and install WireKube without a source checkout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if options.output == "json" && !flags.yes && !flags.dryRun {
				return fmt.Errorf("--output=json requires --yes or --dry-run")
			}
			plan, normalized, installer, err := buildInstallationPlan(cmd, flags)
			if err != nil {
				return err
			}
			if flags.dryRun {
				return writePlan(cmd.OutOrStdout(), plan)
			}
			if options.output == "text" {
				writePlanText(cmd.OutOrStdout(), plan)
				if !flags.yes {
					confirmed, err := confirm(cmd.InOrStdin(), cmd.OutOrStdout(), "Install? [y/N] ")
					if err != nil {
						return err
					}
					if !confirmed {
						return fmt.Errorf("installation cancelled")
					}
				}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
			defer cancel()
			result, err := installer.Apply(ctx, plan, normalized, "install")
			if err != nil {
				return err
			}
			return writeLifecycleResult(cmd, result)
		},
	}
	addLifecycleFlags(cmd, flags)
	return cmd
}

func upgradeCmd() *cobra.Command {
	flags := &lifecycleFlags{}
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade resources owned by an existing wirekubectl installation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if options.output == "json" && !flags.yes && !flags.dryRun {
				return fmt.Errorf("--output=json requires --yes or --dry-run")
			}
			factory := kubeFactory()
			c, err := factory.Client()
			if err != nil {
				return err
			}
			installer := internalinstall.Installer{Client: c}
			inventory, err := installer.LoadInventory(cmd.Context(), options.namespace)
			if err != nil {
				return fmt.Errorf("load existing installation: %w", err)
			}
			flags.previousResources = inventory.Resources
			applyStoredLifecycleDefaults(cmd, flags, inventory.Options)
			plan, normalized, _, err := buildInstallationPlanWithClient(cmd, flags, c, factory, installer)
			if err != nil {
				return err
			}
			if flags.dryRun {
				return writePlan(cmd.OutOrStdout(), plan)
			}
			if options.output == "text" && !flags.yes {
				writePlanText(cmd.OutOrStdout(), plan)
				confirmed, err := confirm(cmd.InOrStdin(), cmd.OutOrStdout(), "Upgrade? [y/N] ")
				if err != nil || !confirmed {
					if err != nil {
						return err
					}
					return fmt.Errorf("upgrade cancelled")
				}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
			defer cancel()
			result, err := installer.Apply(ctx, plan, normalized, "upgrade")
			if err != nil {
				return err
			}
			return writeLifecycleResult(cmd, result)
		},
	}
	addLifecycleFlags(cmd, flags)
	return cmd
}

func manifestCmd() *cobra.Command {
	flags := &lifecycleFlags{}
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Render the exact installation resources without applying them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, normalized, _, err := buildInstallationPlan(cmd, flags)
			if err != nil {
				return err
			}
			bundle, err := internalinstall.Render(normalized)
			if err != nil {
				return err
			}
			if options.output == "json" {
				resources := make([]any, 0, len(bundle.CRDs)+len(bundle.Objects))
				for _, crd := range bundle.CRDs {
					resources = append(resources, crd)
				}
				for _, object := range bundle.Objects {
					resources = append(resources, object)
				}
				return writeJSON(cmd.OutOrStdout(), map[string]any{"schemaVersion": internalinstall.SchemaVersion, "plan": plan, "resources": resources})
			}
			data, err := internalinstall.Manifest(bundle)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	addLifecycleFlags(cmd, flags)
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show installation inventory and workload readiness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := kubeFactory().Client()
			if err != nil {
				return err
			}
			inventory, err := (internalinstall.Installer{Client: c}).LoadInventory(cmd.Context(), options.namespace)
			if err != nil {
				return fmt.Errorf("load installation inventory: %w", err)
			}
			status := inspectInstallation(cmd.Context(), c, inventory)
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), status)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Installation: %s\nVersion:      %s\nImage:        %s\nUpdated:      %s\nComponents:   %t\nConnectivity: %t\nReady:        %t\n", status.InstallationID, status.WireKubeVersion, status.Image, status.UpdatedAt.Format(time.RFC3339), status.ComponentsReady, status.ConnectivityReady, status.Ready)
			for _, component := range status.Components {
				state := "NOT READY"
				if component.Ready {
					state = "READY"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-10s %-9s %s\n", component.Name, state, component.Message)
			}
			return nil
		},
	}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Inspect common installation and readiness failures",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			factory := kubeFactory()
			result := doctorOutput{SchemaVersion: internalinstall.SchemaVersion, Ready: true}
			add := func(name string, ok bool, message string) {
				result.Checks = append(result.Checks, doctorCheck{Name: name, OK: ok, Message: message})
				result.Ready = result.Ready && ok
			}
			if discovery, err := factory.Discovery(); err != nil {
				add("api", false, err.Error())
			} else if version, err := discovery.ServerVersion(); err != nil {
				add("api", false, err.Error())
			} else {
				add("api", true, version.GitVersion)
			}
			c, err := factory.Client()
			if err != nil {
				add("client", false, err.Error())
				return writeDoctorResult(cmd, result)
			}
			inventory, err := (internalinstall.Installer{Client: c}).LoadInventory(cmd.Context(), options.namespace)
			add("inventory", err == nil, messageForError(err, "installation inventory found"))
			if err == nil {
				status := inspectInstallation(cmd.Context(), c, inventory)
				result.Installation = &status
				for _, component := range status.Components {
					add(component.Name, component.Ready, component.Message)
				}
				owned, message := checkInventoryOwnership(cmd.Context(), c, inventory)
				add("ownership", owned, message)
				if inventory.Options.Relay != internalinstall.RelayNone {
					reachable, message := checkRelayReachability(cmd.Context(), c, inventory)
					add("relay-reachability", reachable, message)
				}
			}
			return writeDoctorResult(cmd, result)
		},
	}
}

func inspectInstallation(ctx context.Context, c client.Client, inventory *internalinstall.Inventory) installationStatus {
	status := installationStatus{
		SchemaVersion:   internalinstall.SchemaVersion,
		InstallationID:  inventory.InstallationID,
		WireKubeVersion: inventory.WireKubeVersion,
		Image:           inventory.Image,
		ComponentsReady: true,
		UpdatedAt:       inventory.UpdatedAt,
	}
	addComponent := func(component componentStatus) {
		status.Components = append(status.Components, component)
		status.ComponentsReady = status.ComponentsReady && component.Ready
	}

	crdTotal, crdEstablished := 0, 0
	var crdFailures []string
	for _, resource := range inventory.Resources {
		if resource.Kind != "CustomResourceDefinition" {
			continue
		}
		crdTotal++
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := c.Get(ctx, client.ObjectKey{Name: resource.Name}, crd); err != nil {
			crdFailures = append(crdFailures, resource.Name+": "+messageForError(err, ""))
			continue
		}
		for _, condition := range crd.Status.Conditions {
			if condition.Type == apiextensionsv1.Established && condition.Status == apiextensionsv1.ConditionTrue {
				crdEstablished++
				break
			}
		}
	}
	crdMessage := fmt.Sprintf("%d/%d established", crdEstablished, crdTotal)
	if len(crdFailures) > 0 {
		crdMessage += "; " + strings.Join(crdFailures, "; ")
	}
	addComponent(componentStatus{Name: "crds", Kind: "CustomResourceDefinition", Ready: crdTotal > 0 && crdEstablished == crdTotal, Desired: int32(crdTotal), Available: int32(crdEstablished), Message: crdMessage})

	desiredAgents := int32(0)
	daemonSet := &appsv1.DaemonSet{}
	agentErr := c.Get(ctx, types.NamespacedName{Namespace: inventory.Options.Namespace, Name: "wirekube-agent"}, daemonSet)
	agent := componentStatus{Name: "agent", Kind: "DaemonSet", Message: messageForError(agentErr, "")}
	if agentErr == nil {
		desiredAgents = daemonSet.Status.DesiredNumberScheduled
		agent.Desired = desiredAgents
		agent.Available = daemonSet.Status.NumberReady
		agent.Ready = desiredAgents > 0 && daemonSet.Status.ObservedGeneration >= daemonSet.Generation && daemonSet.Status.UpdatedNumberScheduled == desiredAgents && daemonSet.Status.NumberReady == desiredAgents && daemonSet.Status.NumberAvailable == desiredAgents
		agent.Message = fmt.Sprintf("%d/%d ready, %d updated", daemonSet.Status.NumberReady, desiredAgents, daemonSet.Status.UpdatedNumberScheduled)
		if len(daemonSet.Spec.Template.Spec.Containers) == 0 || daemonSet.Spec.Template.Spec.Containers[0].Image != inventory.Image {
			agent.Ready = false
			actual := "missing"
			if len(daemonSet.Spec.Template.Spec.Containers) > 0 {
				actual = daemonSet.Spec.Template.Spec.Containers[0].Image
			}
			agent.Message += fmt.Sprintf("; image=%s, inventory=%s", actual, inventory.Image)
		}
	}
	addComponent(agent)

	mesh := &wirekubev1alpha1.WireKubeMesh{}
	meshErr := c.Get(ctx, client.ObjectKey{Name: "default"}, mesh)
	meshStatus := componentStatus{Name: "mesh", Kind: "WireKubeMesh", Message: messageForError(meshErr, "")}
	if meshErr == nil {
		meshStatus.Desired = desiredAgents
		meshStatus.Available = mesh.Status.TotalPeers
		meshStatus.Ready = desiredAgents > 0 && mesh.Status.TotalPeers >= desiredAgents && (desiredAgents == 1 || mesh.Status.ReadyPeers >= desiredAgents)
		meshStatus.Message = fmt.Sprintf("%d peers observed, %d ready", mesh.Status.TotalPeers, mesh.Status.ReadyPeers)
		if desiredAgents == 1 {
			meshStatus.Message += "; single-node mesh has no remote peers to connect"
		}
		for _, condition := range mesh.Status.Conditions {
			if condition.Status != metav1.ConditionTrue && condition.Message != "" {
				meshStatus.Message += "; " + condition.Type + ": " + condition.Message
			}
		}
	}
	status.Components = append(status.Components, meshStatus)
	status.ConnectivityReady = meshStatus.Ready

	if inventory.Options.Relay == internalinstall.RelayLoadBalancer || inventory.Options.Relay == internalinstall.RelayNodePort {
		deployment := &appsv1.Deployment{}
		deploymentErr := c.Get(ctx, types.NamespacedName{Namespace: inventory.Options.Namespace, Name: "wirekube-relay"}, deployment)
		relay := componentStatus{Name: "relay", Kind: "Deployment", Message: messageForError(deploymentErr, "")}
		if deploymentErr == nil {
			relay.Desired = desiredDeploymentReplicas(deployment)
			relay.Available = deployment.Status.ReadyReplicas
			relay.Ready = deploymentStatusReady(deployment)
			relay.Message = fmt.Sprintf("%d/%d ready, %d updated", deployment.Status.ReadyReplicas, relay.Desired, deployment.Status.UpdatedReplicas)
			if len(deployment.Spec.Template.Spec.Containers) == 0 || deployment.Spec.Template.Spec.Containers[0].Image != inventory.Image {
				relay.Ready = false
				actual := "missing"
				if len(deployment.Spec.Template.Spec.Containers) > 0 {
					actual = deployment.Spec.Template.Spec.Containers[0].Image
				}
				relay.Message += fmt.Sprintf("; image=%s, inventory=%s", actual, inventory.Image)
			}
		}
		addComponent(relay)

		if relayTransport(inventory.Options) == internalinstall.RelayTransportWSS {
			deployment := &appsv1.Deployment{}
			deploymentErr := c.Get(ctx, types.NamespacedName{Namespace: inventory.Options.Namespace, Name: "wirekube-relay-ws"}, deployment)
			gateway := componentStatus{Name: "relay-websocket", Kind: "Deployment", Message: messageForError(deploymentErr, "")}
			if deploymentErr == nil {
				gateway.Desired = desiredDeploymentReplicas(deployment)
				gateway.Available = deployment.Status.ReadyReplicas
				gateway.Ready = deploymentStatusReady(deployment)
				gateway.Message = fmt.Sprintf("%d/%d ready, %d updated", deployment.Status.ReadyReplicas, gateway.Desired, deployment.Status.UpdatedReplicas)
				if len(deployment.Spec.Template.Spec.Containers) == 0 || deployment.Spec.Template.Spec.Containers[0].Image != inventory.Image {
					gateway.Ready = false
					actual := "missing"
					if len(deployment.Spec.Template.Spec.Containers) > 0 {
						actual = deployment.Spec.Template.Spec.Containers[0].Image
					}
					gateway.Message += fmt.Sprintf("; image=%s, inventory=%s", actual, inventory.Image)
				}
			}
			addComponent(gateway)
			if inventory.Options.Relay == internalinstall.RelayNodePort {
				addComponent(inspectRelayService(ctx, c, inventory.Options.Namespace, "wirekube-relay-ws", "relay-websocket-backend", inventory.Options.Relay, corev1.ProtocolTCP))
			} else {
				addComponent(inspectClusterIPService(ctx, c, inventory.Options.Namespace, "wirekube-relay-ws", "relay-websocket-backend"))
			}
			endpoint := strings.TrimSpace(inventory.Options.RelayEndpoint)
			addComponent(componentStatus{Name: "relay-entrypoint", Kind: "External", Ready: endpoint != "", Message: "WSS control endpoint " + endpoint})
		} else {
			addComponent(inspectRelayService(ctx, c, inventory.Options.Namespace, "wirekube-relay", "relay-entrypoint", inventory.Options.Relay, corev1.ProtocolTCP))
		}
		if inventory.Options.RelayUDP {
			addComponent(inspectRelayService(ctx, c, inventory.Options.Namespace, "wirekube-relay-udp", "relay-udp-entrypoint", inventory.Options.Relay, corev1.ProtocolUDP))
		}
	} else if inventory.Options.Relay == internalinstall.RelayExternal {
		endpoint := strings.TrimSpace(inventory.Options.RelayEndpoint)
		addComponent(componentStatus{Name: "relay-entrypoint", Kind: "External", Ready: endpoint != "", Message: "external control endpoint " + endpoint})
	}

	status.Ready = status.ComponentsReady && status.ConnectivityReady
	return status
}

func checkRelayReachability(ctx context.Context, c client.Client, inventory *internalinstall.Inventory) (bool, string) {
	endpoint := strings.TrimSpace(inventory.Options.RelayEndpoint)
	if relayTransport(inventory.Options) == internalinstall.RelayTransportWSS {
		if endpoint == "" {
			return false, "WSS control endpoint is not configured"
		}
		httpsEndpoint := "https://" + strings.TrimPrefix(endpoint, "wss://")
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, httpsEndpoint, nil)
		if err != nil {
			return false, fmt.Sprintf("invalid WSS endpoint %s: %v", endpoint, err)
		}
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-WebSocket-Version", "13")
		request.Header.Set("Sec-WebSocket-Key", "d2lyZWt1YmUtZG9jdG9yIQ==")
		probeCtx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		request = request.WithContext(probeCtx)
		response, err := relayReachabilityHTTPClient.Do(request)
		if err != nil {
			return false, fmt.Sprintf("WSS connect to %s failed: %v", endpoint, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized || !strings.EqualFold(strings.TrimSpace(response.Header.Get("WWW-Authenticate")), "Bearer") {
			return false, fmt.Sprintf("WSS endpoint %s did not return the WireKube bearer authentication challenge (HTTP %d)", endpoint, response.StatusCode)
		}
		return true, fmt.Sprintf("WSS TLS connection to %s reached the authenticated relay gateway", endpoint)
	}
	if inventory.Options.Relay == internalinstall.RelayLoadBalancer {
		service := &corev1.Service{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: inventory.Options.Namespace, Name: "wirekube-relay"}, service); err != nil {
			return false, messageForError(err, "")
		}
		host := ""
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				host = ingress.IP
				break
			}
			if ingress.Hostname != "" {
				host = ingress.Hostname
				break
			}
		}
		port := int32(0)
		for _, servicePort := range service.Spec.Ports {
			if servicePort.Protocol == corev1.ProtocolTCP {
				port = servicePort.Port
				break
			}
		}
		if host == "" || port == 0 {
			return false, "relay TCP LoadBalancer endpoint is not assigned"
		}
		endpoint = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	}
	if endpoint == "" {
		return false, "relay control endpoint is not configured"
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", endpoint)
	if err != nil {
		return false, fmt.Sprintf("TCP connect to %s failed: %v", endpoint, err)
	}
	_ = connection.Close()
	return true, "TCP connect to " + endpoint + " succeeded"
}

func relayTransport(options internalinstall.Options) string {
	if strings.TrimSpace(options.RelayTransport) == "" {
		return internalinstall.RelayTransportTCP
	}
	return options.RelayTransport
}

func desiredDeploymentReplicas(deployment *appsv1.Deployment) int32 {
	if deployment.Spec.Replicas == nil {
		return 1
	}
	return *deployment.Spec.Replicas
}

func deploymentStatusReady(deployment *appsv1.Deployment) bool {
	desired := desiredDeploymentReplicas(deployment)
	return desired > 0 && deployment.Status.ObservedGeneration >= deployment.Generation && deployment.Status.UpdatedReplicas == desired && deployment.Status.ReadyReplicas == desired && deployment.Status.AvailableReplicas == desired
}

func inspectRelayService(ctx context.Context, c client.Client, namespace, serviceName, componentName, relayMode string, protocol corev1.Protocol) componentStatus {
	service := &corev1.Service{}
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: serviceName}, service)
	entrypoint := componentStatus{Name: componentName, Kind: "Service", Message: messageForError(err, "")}
	if err != nil {
		return entrypoint
	}
	if relayMode == internalinstall.RelayLoadBalancer {
		addresses := make([]string, 0, len(service.Status.LoadBalancer.Ingress))
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				addresses = append(addresses, ingress.IP)
			} else if ingress.Hostname != "" {
				addresses = append(addresses, ingress.Hostname)
			}
		}
		entrypoint.Ready = len(addresses) > 0
		entrypoint.Message = "LoadBalancer address pending"
		if entrypoint.Ready {
			entrypoint.Message = "LoadBalancer address " + strings.Join(addresses, ",")
		}
		return entrypoint
	}
	for _, port := range service.Spec.Ports {
		if port.Protocol == protocol && port.NodePort > 0 {
			entrypoint.Ready = true
			entrypoint.Message = fmt.Sprintf("%s NodePort %d", protocol, port.NodePort)
			return entrypoint
		}
	}
	entrypoint.Message = fmt.Sprintf("%s NodePort is not assigned", protocol)
	return entrypoint
}

func inspectClusterIPService(ctx context.Context, c client.Client, namespace, serviceName, componentName string) componentStatus {
	service := &corev1.Service{}
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: serviceName}, service)
	component := componentStatus{Name: componentName, Kind: "Service", Message: messageForError(err, "")}
	if err != nil {
		return component
	}
	component.Ready = service.Spec.ClusterIP != "" && service.Spec.ClusterIP != corev1.ClusterIPNone && len(service.Spec.Ports) == 1 && service.Spec.Ports[0].Port == 8081
	if component.Ready {
		component.Message = "HTTP WebSocket backend " + service.Spec.ClusterIP + ":8081"
	} else {
		component.Message = "HTTP WebSocket backend Service is not assigned"
	}
	return component
}

func checkInventoryOwnership(ctx context.Context, c client.Client, inventory *internalinstall.Inventory) (bool, string) {
	checked := 0
	var failures []string
	for _, resource := range inventory.Resources {
		if resource.Kind == "Namespace" {
			continue
		}
		checked++
		object := &unstructured.Unstructured{}
		object.SetAPIVersion(resource.APIVersion)
		object.SetKind(resource.Kind)
		err := c.Get(ctx, client.ObjectKey{Namespace: resource.Namespace, Name: resource.Name}, object)
		if err != nil {
			failures = append(failures, resource.Kind+" "+resourceDisplayName(resource)+": "+messageForError(err, ""))
			continue
		}
		if object.GetLabels()["app.kubernetes.io/managed-by"] != "wirekubectl" {
			failures = append(failures, resource.Kind+" "+resourceDisplayName(resource)+": managed-by label is missing")
		} else if object.GetLabels()[internalinstall.InstallationIDLabel] != inventory.InstallationID {
			failures = append(failures, resource.Kind+" "+resourceDisplayName(resource)+": installation ID does not match inventory")
		}
	}
	if len(failures) > 0 {
		return false, strings.Join(failures, "; ")
	}
	return true, fmt.Sprintf("%d inventory resources are owned by wirekubectl", checked)
}

func resourceDisplayName(resource internalinstall.Resource) string {
	if resource.Namespace == "" {
		return resource.Name
	}
	return resource.Namespace + "/" + resource.Name
}

func writeDoctorResult(cmd *cobra.Command, result doctorOutput) error {
	if options.output == "json" {
		if err := writeJSON(cmd.OutOrStdout(), result); err != nil {
			return err
		}
		if !result.Ready {
			return fmt.Errorf("doctor found failed checks")
		}
		return nil
	}
	for _, check := range result.Checks {
		state := "FAIL"
		if check.OK {
			state = "OK"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-4s %-18s %s\n", state, check.Name, check.Message)
	}
	if !result.Ready {
		return fmt.Errorf("doctor found failed checks")
	}
	return nil
}

func uninstallCmd() *cobra.Command {
	var purge, confirmPurge, yes bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove managed workloads while preserving CRDs and custom resources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if options.output == "json" && !yes {
				return fmt.Errorf("--output=json requires --yes")
			}
			if purge && !confirmPurge {
				return fmt.Errorf("--purge requires --confirm-purge; --yes does not imply destructive data deletion")
			}
			if !yes {
				prompt := "Uninstall managed workloads? [y/N] "
				if purge {
					prompt = "Permanently delete WireKube CRDs and all custom resources? [y/N] "
				}
				confirmed, err := confirm(cmd.InOrStdin(), cmd.OutOrStdout(), prompt)
				if err != nil || !confirmed {
					if err != nil {
						return err
					}
					return fmt.Errorf("uninstall cancelled")
				}
			}
			c, err := kubeFactory().Client()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
			defer cancel()
			inventory, err := (internalinstall.Installer{Client: c}).Uninstall(ctx, options.namespace, purge)
			if err != nil {
				return err
			}
			return writeResult(cmd, map[string]any{"operation": "uninstall", "purged": purge, "installationID": inventory.InstallationID}, fmt.Sprintf("WireKube installation %s removed (purge=%t)\n", inventory.InstallationID, purge))
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete all WireKube custom resources and CRDs")
	cmd.Flags().BoolVar(&confirmPurge, "confirm-purge", false, "explicitly authorize destructive CRD and custom-resource deletion")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the ordinary uninstall confirmation")
	return cmd
}

func addLifecycleFlags(cmd *cobra.Command, flags *lifecycleFlags) {
	cmd.Flags().StringVar(&flags.relay, "relay", "", "relay mode: none, load-balancer, node-port, or external")
	cmd.Flags().StringVar(&flags.relayEndpoint, "relay-endpoint", "", "relay control endpoint as HOST:PORT for TCP or wss://HOST/PATH for WSS")
	cmd.Flags().StringVar(&flags.relayUDPEndpoint, "relay-udp-endpoint", "", "raw WireGuard UDP endpoint for external peer invites as HOST:PORT")
	cmd.Flags().StringVar(&flags.relayTransport, "relay-transport", internalinstall.RelayTransportTCP, "agent relay transport: tcp or wss")
	cmd.Flags().BoolVar(&flags.relayUDP, "relay-udp", false, "create a separate UDP relay Service (defaults to true with load-balancer)")
	cmd.Flags().StringVar(&flags.meshCIDR, "mesh-cidr", "auto", "mesh CIDR or auto")
	cmd.Flags().StringVar(&flags.nodeAddresses, "node-addresses", "mesh-only", "node address exposure: mesh-only or internal-ip")
	cmd.Flags().StringVar(&flags.image, "image", internalversion.DefaultImage, "immutable WireKube image reference (IMAGE@sha256:DIGEST)")
	cmd.Flags().StringSliceVar(&flags.excludeCIDRs, "exclude-cidr", nil, "CIDR that automatic mesh selection must avoid; may be repeated")
	cmd.Flags().BoolVar(&flags.yes, "yes", false, "apply the displayed plan without prompting")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "inspect and print the plan without mutating the cluster")
	cmd.Flags().BoolVar(&flags.adopt, "adopt", false, "explicitly adopt conflicting existing resources")
}

func buildInstallationPlan(cmd *cobra.Command, flags *lifecycleFlags) (internalinstall.Plan, internalinstall.Options, internalinstall.Installer, error) {
	factory := kubeFactory()
	c, err := factory.Client()
	if err != nil {
		return internalinstall.Plan{}, internalinstall.Options{}, internalinstall.Installer{}, err
	}
	return buildInstallationPlanWithClient(cmd, flags, c, factory, internalinstall.Installer{Client: c})
}

func buildInstallationPlanWithClient(cmd *cobra.Command, flags *lifecycleFlags, c client.Client, factory *internalconfig.Factory, installer internalinstall.Installer) (internalinstall.Plan, internalinstall.Options, internalinstall.Installer, error) {
	discovery, err := factory.Discovery()
	if err != nil {
		return internalinstall.Plan{}, internalinstall.Options{}, installer, err
	}
	contextName, server, err := targetCluster(factory)
	if err != nil {
		return internalinstall.Plan{}, internalinstall.Options{}, installer, err
	}
	installOptions := internalinstall.Options{
		Namespace: options.namespace, Image: flags.image, Relay: flags.relay, RelayEndpoint: flags.relayEndpoint, RelayUDPEndpoint: flags.relayUDPEndpoint, RelayTransport: flags.relayTransport, RelayUDP: flags.relayUDP, RelayUDPConfigured: flags.relayUDPConfigured || cmd.Flags().Changed("relay-udp"), PreviousResources: flags.previousResources, MeshCIDR: flags.meshCIDR, NodeAddresses: flags.nodeAddresses, ExcludeCIDRs: flags.excludeCIDRs, Yes: flags.yes, DryRun: flags.dryRun, Adopt: flags.adopt, Timeout: options.timeout, Context: contextName, ClusterServer: server, WireKubeVersion: internalversion.Version,
	}
	plan, normalized, err := (internalinstall.Planner{Client: c, Discovery: discovery, AccessReviewer: internalinstall.SelfSubjectAccessReviewer{Client: c}}).Build(cmd.Context(), installOptions)
	return plan, normalized, installer, err
}

func kubeFactory() *internalconfig.Factory {
	return internalconfig.New(internalconfig.Options{Kubeconfig: options.kubeconfig, Context: options.context, Namespace: options.namespace, Timeout: options.timeout}, scheme)
}

func targetCluster(factory *internalconfig.Factory) (string, string, error) {
	raw, err := factory.RawConfig()
	if err != nil {
		return "", "", err
	}
	contextName := options.context
	if contextName == "" {
		contextName = raw.CurrentContext
	}
	contextConfig := raw.Contexts[contextName]
	if contextConfig == nil {
		return "", "", fmt.Errorf("context %q does not exist", contextName)
	}
	cluster := raw.Clusters[contextConfig.Cluster]
	if cluster == nil {
		return "", "", fmt.Errorf("cluster %q referenced by context %q does not exist", contextConfig.Cluster, contextName)
	}
	return contextName, cluster.Server, nil
}

func applyStoredLifecycleDefaults(cmd *cobra.Command, flags *lifecycleFlags, stored internalinstall.Options) {
	if !cmd.Flags().Changed("relay") {
		flags.relay = stored.Relay
	}
	if !cmd.Flags().Changed("relay-endpoint") {
		flags.relayEndpoint = stored.RelayEndpoint
	}
	if !cmd.Flags().Changed("relay-udp-endpoint") {
		flags.relayUDPEndpoint = stored.RelayUDPEndpoint
	}
	if !cmd.Flags().Changed("relay-transport") {
		flags.relayTransport = stored.RelayTransport
	}
	if !cmd.Flags().Changed("relay-udp") {
		flags.relayUDP = stored.RelayUDP
		flags.relayUDPConfigured = true
	}
	if !cmd.Flags().Changed("mesh-cidr") {
		flags.meshCIDR = stored.MeshCIDR
	}
	if !cmd.Flags().Changed("node-addresses") {
		flags.nodeAddresses = stored.NodeAddresses
	}
	if !cmd.Flags().Changed("image") && strings.TrimSpace(flags.image) == "" {
		flags.image = stored.Image
	}
}

func writePlan(out io.Writer, plan internalinstall.Plan) error {
	if options.output == "json" {
		return writeJSON(out, plan)
	}
	writePlanText(out, plan)
	return nil
}

func writePlanText(out io.Writer, plan internalinstall.Plan) {
	fmt.Fprintln(out, "WireKube installation plan")
	fmt.Fprintf(out, "\nCluster\n  Context:       %s\n  Kubernetes:    %s\n  Provider:      %s\n  CNI:           %s\n", plan.Context, plan.Detection.KubernetesVersion, plan.Detection.Provider, plan.Detection.CNI)
	fmt.Fprintf(out, "\nComponents\n  Resources:     %d\n  Agent:         privileged DaemonSet\n  Relay:         %s\n  Transport:     %s\n  Mesh CIDR:     %s\n  Image:         %s\n", len(plan.Resources), plan.Relay, plan.RelayTransport, plan.MeshCIDR, plan.Image)
	fmt.Fprintln(out, "\nInfrastructure impact")
	for _, impact := range plan.Impact {
		fmt.Fprintf(out, "  - %s\n", impact)
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(out, "  WARNING: %s\n", warning)
	}
}

func writeLifecycleResult(cmd *cobra.Command, result internalinstall.Result) error {
	if options.output == "json" {
		return writeJSON(cmd.OutOrStdout(), result)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "WireKube %s completed: installation=%s ready=%t\n", result.Operation, result.InstallationID, result.Ready)
	return nil
}

func confirm(in io.Reader, out io.Writer, prompt string) (bool, error) {
	fmt.Fprint(out, prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && len(line) == 0 {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func messageForError(err error, success string) string {
	if err == nil {
		return success
	}
	if apierrors.IsNotFound(err) {
		return "not found"
	}
	return err.Error()
}
