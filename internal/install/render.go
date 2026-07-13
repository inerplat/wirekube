package install

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	crdassets "github.com/inerplat/wirekube/config/crd"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

type Bundle struct {
	CRDs      []*apiextensionsv1.CustomResourceDefinition
	Objects   []runtime.Object
	Resources []Resource
}

func Render(options Options) (*Bundle, error) {
	if err := options.Normalize(); err != nil {
		return nil, err
	}
	crds, err := embeddedCRDs()
	if err != nil {
		return nil, err
	}
	labels := managedLabels(options.WireKubeVersion)
	for _, crd := range crds {
		crd.Labels = copyLabels(labels)
	}
	objects := []runtime.Object{
		&corev1.Namespace{TypeMeta: typeMeta("v1", "Namespace"), ObjectMeta: metav1.ObjectMeta{Name: options.Namespace, Labels: labels}},
		agentServiceAccount(options, labels),
		agentClusterRole(options, labels),
		agentClusterRoleBinding(options, labels),
		meshObject(options),
	}
	if options.Relay == RelayLoadBalancer || options.Relay == RelayNodePort {
		objects = append(objects, relayDeployment(options, labels), relayControlService(options, labels))
		if options.RelayTransport == RelayTransportWSS {
			objects = append(objects,
				relayServiceAccount(options, labels),
				relayClusterRole(labels),
				relayClusterRoleBinding(options, labels),
				relayWebSocketDeployment(options, labels),
				relayWebSocketService(options, labels),
			)
		} else {
			objects = append(objects, relayTCPService(options, labels))
		}
		if options.RelayUDP {
			objects = append(objects, relayUDPService(options, labels))
		}
	}
	objects = append(objects, agentDaemonSet(options, labels))

	bundle := &Bundle{CRDs: crds, Objects: objects}
	for _, crd := range crds {
		bundle.Resources = append(bundle.Resources, resourceFor(crd, true))
	}
	for _, object := range objects {
		preserve := false
		switch object.(type) {
		case *corev1.Namespace, *wirekubev1alpha1.WireKubeMesh:
			preserve = true
		}
		bundle.Resources = append(bundle.Resources, resourceFor(object.(metav1.Object), preserve))
	}
	return bundle, nil
}

func embeddedCRDs() ([]*apiextensionsv1.CustomResourceDefinition, error) {
	entries, err := fs.ReadDir(crdassets.Files, ".")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var crds []*apiextensionsv1.CustomResourceDefinition
	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) < 5 || entry.Name()[len(entry.Name())-5:] != ".yaml" {
			continue
		}
		data, err := crdassets.Files.ReadFile(entry.Name())
		if err != nil {
			return nil, err
		}
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(data, crd); err != nil {
			return nil, fmt.Errorf("decode embedded CRD %s: %w", entry.Name(), err)
		}
		crds = append(crds, crd)
	}
	if len(crds) == 0 {
		return nil, fmt.Errorf("no embedded CRDs found")
	}
	return crds, nil
}

func managedLabels(version string) map[string]string {
	if version == "" {
		version = "dev"
	}
	return map[string]string{
		"app.kubernetes.io/name":       "wirekube",
		"app.kubernetes.io/part-of":    "wirekube",
		"app.kubernetes.io/managed-by": "wirekubectl",
		"app.kubernetes.io/version":    version,
	}
}

func agentServiceAccount(options Options, labels map[string]string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{TypeMeta: typeMeta("v1", "ServiceAccount"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-agent", Namespace: options.Namespace, Labels: labels}}
}

func agentClusterRole(options Options, labels map[string]string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   typeMeta(rbacv1.SchemeGroupVersion.String(), "ClusterRole"),
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-agent", Labels: labels},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"nodes", "services"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "patch"}},
			{APIGroups: []string{"wirekube.io"}, Resources: []string{"wirekubepeers"}, Verbs: []string{"get", "list", "create", "patch", "update", "delete", "watch"}},
			{APIGroups: []string{"wirekube.io"}, Resources: []string{"wirekubepeers/status", "wirekubemeshes/status", "wirekubegateways/status", "wirekubeexternalpeers/status"}, Verbs: []string{"get", "patch", "update"}},
			{APIGroups: []string{"wirekube.io"}, Resources: []string{"wirekubemeshes", "wirekubegateways"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"wirekube.io"}, Resources: []string{"wirekubeexternalpeers"}, Verbs: []string{"get", "list", "watch", "update", "delete"}},
			{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
			{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create", "patch"}},
		},
	}
}

func agentClusterRoleBinding(options Options, labels map[string]string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   typeMeta(rbacv1.SchemeGroupVersion.String(), "ClusterRoleBinding"),
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-agent", Labels: labels},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "wirekube-agent"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "wirekube-agent", Namespace: options.Namespace}},
	}
}

func agentDaemonSet(options Options, labels map[string]string) *appsv1.DaemonSet {
	componentLabels := copyLabels(labels)
	componentLabels["app.kubernetes.io/component"] = "agent"
	selectorLabels := map[string]string{"app.kubernetes.io/name": "wirekube-agent"}
	podLabels := copyLabels(selectorLabels)
	podLabels["app.kubernetes.io/component"] = "agent"
	podLabels["app.kubernetes.io/part-of"] = "wirekube"
	podLabels["app.kubernetes.io/managed-by"] = "wirekubectl"
	return &appsv1.DaemonSet{
		TypeMeta:   typeMeta(appsv1.SchemeGroupVersion.String(), "DaemonSet"),
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-agent", Namespace: options.Namespace, Labels: componentLabels},
		Spec: appsv1.DaemonSetSpec{
			Selector:       &metav1.LabelSelector{MatchLabels: selectorLabels},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType, RollingUpdate: &appsv1.RollingUpdateDaemonSet{MaxUnavailable: intOrStringPtr(intstr.FromInt32(1))}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels, Annotations: map[string]string{"wirekube.io/relay-config-revision": relayConfigRevision(options)}},
				Spec: corev1.PodSpec{
					ServiceAccountName:            "wirekube-agent",
					HostNetwork:                   true,
					DNSPolicy:                     corev1.DNSDefault,
					PriorityClassName:             "system-node-critical",
					TerminationGracePeriodSeconds: int64Ptr(30),
					Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: "kubernetes.io/os", Operator: corev1.NodeSelectorOpIn, Values: []string{"linux"}},
							{Key: "wirekube.io/proxy-node", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"true"}},
						}}},
					}}},
					Containers: []corev1.Container{{
						Name:            "agent",
						Image:           options.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"wirekube-agent"},
						Args:            []string{"--node-name=$(NODE_NAME)"},
						Env: []corev1.EnvVar{
							{Name: "NODE_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
							{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
							{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}},
							{Name: "WIREKUBE_INTERFACE", Value: "wire_kube"},
							{Name: "WIREKUBE_RELAY_TOKEN_FILE", Value: "/var/run/secrets/wirekube-relay/token"},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:      boolPtr(true),
							AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
							Capabilities:    &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN", "SYS_MODULE"}},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "wireguard-keys", MountPath: "/var/lib/wirekube"},
							{Name: "host-proc-sys-net", MountPath: "/host/proc/sys/net"},
							{Name: "dev-net-tun", MountPath: "/dev/net/tun"},
							{Name: "relay-token", MountPath: "/var/run/secrets/wirekube-relay", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "wireguard-keys", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/wirekube", Type: hostPathTypePtr(corev1.HostPathDirectoryOrCreate)}}},
						{Name: "host-proc-sys-net", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/proc/sys/net", Type: hostPathTypePtr(corev1.HostPathDirectory)}}},
						{Name: "dev-net-tun", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/dev/net/tun", Type: hostPathTypePtr(corev1.HostPathCharDev)}}},
						{Name: "relay-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", Audience: "wirekube-relay", ExpirationSeconds: int64Ptr(3600)}}}}}},
					},
				},
			},
		},
	}
}

func relayConfigRevision(options Options) string {
	payload := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t", options.Relay, options.RelayTransport, options.RelayEndpoint, options.RelayUDPEndpoint, options.RelayUDP)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
}

func relayDeployment(options Options, labels map[string]string) *appsv1.Deployment {
	replicas := int32(1)
	componentLabels := copyLabels(labels)
	componentLabels["app.kubernetes.io/component"] = "relay"
	return &appsv1.Deployment{
		TypeMeta: typeMeta(appsv1.SchemeGroupVersion.String(), "Deployment"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Namespace: options.Namespace, Labels: componentLabels},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "wirekube-relay"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app.kubernetes.io/name": "wirekube-relay", "app.kubernetes.io/component": "relay", "app.kubernetes.io/part-of": "wirekube", "app.kubernetes.io/managed-by": "wirekubectl"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "relay", Image: options.Image, Command: []string{"wirekube-relay"}, Args: relayArgs(options), Ports: []corev1.ContainerPort{{Name: "relay-tcp", ContainerPort: 3478, Protocol: corev1.ProtocolTCP}, {Name: "relay-udp", ContainerPort: 3478, Protocol: corev1.ProtocolUDP}}}}}}},
	}
}

func relayServiceAccount(options Options, labels map[string]string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{TypeMeta: typeMeta("v1", "ServiceAccount"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Namespace: options.Namespace, Labels: labels}}
}

func relayClusterRole(labels map[string]string) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   typeMeta(rbacv1.SchemeGroupVersion.String(), "ClusterRole"),
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Labels: labels},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			{APIGroups: []string{"wirekube.io"}, Resources: []string{"wirekubepeers"}, Verbs: []string{"get"}},
		},
	}
}

func relayClusterRoleBinding(options Options, labels map[string]string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   typeMeta(rbacv1.SchemeGroupVersion.String(), "ClusterRoleBinding"),
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Labels: labels},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "wirekube-relay"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "wirekube-relay", Namespace: options.Namespace}},
	}
}

func relayWebSocketDeployment(options Options, labels map[string]string) *appsv1.Deployment {
	replicas := int32(2)
	componentLabels := copyLabels(labels)
	componentLabels["app.kubernetes.io/component"] = "relay"
	selectorLabels := map[string]string{"app.kubernetes.io/name": "wirekube-relay-ws"}
	podLabels := copyLabels(selectorLabels)
	podLabels["app.kubernetes.io/component"] = "relay"
	podLabels["app.kubernetes.io/part-of"] = "wirekube"
	podLabels["app.kubernetes.io/managed-by"] = "wirekubectl"
	return &appsv1.Deployment{
		TypeMeta:   typeMeta(appsv1.SchemeGroupVersion.String(), "Deployment"),
		ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay-ws", Namespace: options.Namespace, Labels: componentLabels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: selectorLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
				Spec: corev1.PodSpec{
					ServiceAccountName: "wirekube-relay",
					Affinity: &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
						Weight:          100,
						PodAffinityTerm: corev1.PodAffinityTerm{LabelSelector: &metav1.LabelSelector{MatchLabels: selectorLabels}, TopologyKey: "kubernetes.io/hostname"},
					}}}},
					Containers: []corev1.Container{{
						Name:    "relay-ws",
						Image:   options.Image,
						Command: []string{"wirekube-relay-ws"},
						Args: []string{
							"--addr=:8081",
							"--backend-addr=wirekube-relay-control." + options.Namespace + ".svc.cluster.local:3478",
							"--path=" + relayWebSocketPath(options.RelayEndpoint),
							"--audience=wirekube-relay",
							"--agent-service-account=" + options.Namespace + "/wirekube-agent",
						},
						Ports:          []corev1.ContainerPort{{Name: "http-websocket", ContainerPort: 8081, Protocol: corev1.ProtocolTCP}},
						ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(8081)}}, InitialDelaySeconds: 2, PeriodSeconds: 10},
						LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8081)}}, InitialDelaySeconds: 5, PeriodSeconds: 30, TimeoutSeconds: 3},
					}},
				},
			},
		},
	}
}

func relayWebSocketService(options Options, labels map[string]string) *corev1.Service {
	port := corev1.ServicePort{Name: "http-websocket", Port: 8081, TargetPort: intstr.FromInt32(8081), Protocol: corev1.ProtocolTCP}
	serviceType := corev1.ServiceTypeClusterIP
	if options.Relay == RelayNodePort {
		serviceType = corev1.ServiceTypeNodePort
		port.NodePort = 30478
	}
	return &corev1.Service{TypeMeta: typeMeta("v1", "Service"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay-ws", Namespace: options.Namespace, Labels: labels}, Spec: corev1.ServiceSpec{Type: serviceType, Selector: map[string]string{"app.kubernetes.io/name": "wirekube-relay-ws"}, Ports: []corev1.ServicePort{port}}}
}

func relayWebSocketPath(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Path == "" {
		return "/relay"
	}
	return parsed.Path
}

func relayArgs(options Options) []string {
	args := []string{"--addr=:3478"}
	if options.RelayUDP {
		args = append(args, "--external-wg-addr=:3478")
	}
	return args
}

func relayControlService(options Options, labels map[string]string) *corev1.Service {
	return &corev1.Service{TypeMeta: typeMeta("v1", "Service"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay-control", Namespace: options.Namespace, Labels: labels}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone, Selector: map[string]string{"app.kubernetes.io/name": "wirekube-relay"}, Ports: []corev1.ServicePort{{Name: "relay-control", Port: 3478, TargetPort: intstr.FromInt32(3478), Protocol: corev1.ProtocolTCP}}}}
}

func relayTCPService(options Options, labels map[string]string) *corev1.Service {
	serviceType := corev1.ServiceTypeLoadBalancer
	port := corev1.ServicePort{Name: "relay-tcp", Port: 3478, TargetPort: intstr.FromInt32(3478), Protocol: corev1.ProtocolTCP}
	if options.Relay == RelayNodePort {
		serviceType = corev1.ServiceTypeNodePort
		port.NodePort = 30478
	}
	return &corev1.Service{TypeMeta: typeMeta("v1", "Service"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay", Namespace: options.Namespace, Labels: labels}, Spec: corev1.ServiceSpec{Type: serviceType, Selector: map[string]string{"app.kubernetes.io/name": "wirekube-relay"}, Ports: []corev1.ServicePort{port}}}
}

func relayUDPService(options Options, labels map[string]string) *corev1.Service {
	serviceType := corev1.ServiceTypeLoadBalancer
	port := corev1.ServicePort{Name: "relay-udp", Port: 3478, TargetPort: intstr.FromInt32(3478), Protocol: corev1.ProtocolUDP}
	if options.Relay == RelayNodePort {
		serviceType = corev1.ServiceTypeNodePort
		port.NodePort = 30479
	}
	return &corev1.Service{TypeMeta: typeMeta("v1", "Service"), ObjectMeta: metav1.ObjectMeta{Name: "wirekube-relay-udp", Namespace: options.Namespace, Labels: labels}, Spec: corev1.ServiceSpec{Type: serviceType, Selector: map[string]string{"app.kubernetes.io/name": "wirekube-relay"}, Ports: []corev1.ServicePort{port}}}
}

func meshObject(options Options) *wirekubev1alpha1.WireKubeMesh {
	mesh := &wirekubev1alpha1.WireKubeMesh{TypeMeta: typeMeta(wirekubev1alpha1.GroupVersion.String(), "WireKubeMesh"), ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: managedLabels(options.WireKubeVersion)}, Spec: wirekubev1alpha1.WireKubeMeshSpec{ListenPort: 51820, InterfaceName: "wire_kube", MTU: 1420, MeshCIDR: options.MeshCIDR, STUNServers: []string{"stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"}}}
	if options.NodeAddresses == "internal-ip" {
		mesh.Spec.AutoAllowedIPs = &wirekubev1alpha1.AutoAllowedIPsSpec{IncludeNodeInternalIP: true}
	}
	switch options.Relay {
	case RelayNone:
		mesh.Spec.Relay = nil
	case RelayLoadBalancer:
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{Mode: "auto", Provider: "managed", Managed: &wirekubev1alpha1.ManagedRelaySpec{Replicas: 1, ServiceType: string(corev1.ServiceTypeLoadBalancer), Port: 3478, Image: options.Image, ControlEndpoint: options.RelayEndpoint, Transport: options.RelayTransport}}
	case RelayNodePort:
		external := &wirekubev1alpha1.ExternalRelaySpec{ControlEndpoint: options.RelayEndpoint, Transport: options.RelayTransport}
		if options.RelayUDP {
			if options.RelayTransport == RelayTransportWSS {
				external.Endpoint = options.RelayUDPEndpoint
			} else {
				host, _, _ := net.SplitHostPort(options.RelayEndpoint)
				external.Endpoint = net.JoinHostPort(host, "30479")
			}
		}
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{Mode: "auto", Provider: "external", External: external}
	case RelayExternal:
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{Mode: "auto", Provider: "external", External: &wirekubev1alpha1.ExternalRelaySpec{Endpoint: options.RelayUDPEndpoint, ControlEndpoint: options.RelayEndpoint, Transport: options.RelayTransport}}
	}
	return mesh
}

func typeMeta(apiVersion, kind string) metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: apiVersion, Kind: kind}
}
func boolPtr(v bool) *bool                                       { return &v }
func int64Ptr(v int64) *int64                                    { return &v }
func intOrStringPtr(v intstr.IntOrString) *intstr.IntOrString    { return &v }
func hostPathTypePtr(v corev1.HostPathType) *corev1.HostPathType { return &v }

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func resourceFor(object metav1.Object, preserve bool) Resource {
	gkv := object.(runtime.Object).GetObjectKind().GroupVersionKind()
	return Resource{APIVersion: gkv.GroupVersion().String(), Kind: gkv.Kind, Namespace: object.GetNamespace(), Name: object.GetName(), Preserve: preserve}
}
