package install

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Planner struct {
	Client         client.Client
	Discovery      discovery.DiscoveryInterface
	AccessReviewer AccessReviewer
}

type AccessRequirement struct {
	Group     string
	Resource  string
	Verb      string
	Namespace string
	Name      string
}

type AccessReviewer interface {
	Review(context.Context, []AccessRequirement) error
}

type SelfSubjectAccessReviewer struct {
	Client client.Client
}

func (r SelfSubjectAccessReviewer) Review(ctx context.Context, requirements []AccessRequirement) error {
	var denied []string
	for _, requirement := range requirements {
		review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group: requirement.Group, Resource: requirement.Resource, Verb: requirement.Verb, Namespace: requirement.Namespace, Name: requirement.Name,
		}}}
		if err := r.Client.Create(ctx, review); err != nil {
			return fmt.Errorf("review Kubernetes permission %s %s: %w", requirement.Verb, requirement.Resource, err)
		}
		if review.Status.Allowed {
			continue
		}
		target := requirement.Resource
		if requirement.Group != "" {
			target += "." + requirement.Group
		}
		if requirement.Namespace != "" {
			target = requirement.Namespace + "/" + target
		}
		if requirement.Name != "" {
			target += "/" + requirement.Name
		}
		if review.Status.Reason != "" {
			target += " (" + review.Status.Reason + ")"
		}
		denied = append(denied, requirement.Verb+" "+target)
	}
	if len(denied) > 0 {
		return fmt.Errorf("insufficient Kubernetes permissions: %s", strings.Join(denied, ", "))
	}
	return nil
}

func (p Planner) Build(ctx context.Context, options Options) (Plan, Options, error) {
	if options.MeshCIDR == "" {
		options.MeshCIDR = "auto"
	}
	if err := options.Normalize(); err != nil {
		return Plan{}, options, err
	}
	if p.AccessReviewer != nil {
		if err := p.AccessReviewer.Review(ctx, installationAccessRequirements(options)); err != nil {
			return Plan{}, options, err
		}
	}
	autoMeshCIDR := options.MeshCIDR == "auto"
	if autoMeshCIDR && options.Yes && !options.DryRun {
		return Plan{}, options, fmt.Errorf("--mesh-cidr must be explicit for non-interactive installation; automatic selection cannot inspect every VPC, corporate, or node route (use --exclude-cidr during dry-run to evaluate candidates)")
	}
	if options.MeshCIDR == "auto" {
		cidr, err := p.selectMeshCIDR(ctx, options.ExcludeCIDRs)
		if err != nil {
			return Plan{}, options, err
		}
		options.MeshCIDR = cidr
	} else {
		prefix, err := netip.ParsePrefix(options.MeshCIDR)
		if err != nil {
			return Plan{}, options, fmt.Errorf("invalid --mesh-cidr %q: %w", options.MeshCIDR, err)
		}
		occupied, err := p.occupiedPrefixes(ctx, options.ExcludeCIDRs)
		if err != nil {
			return Plan{}, options, err
		}
		if conflicts := overlappingPrefixes(prefix.Masked(), occupied); len(conflicts) > 0 {
			return Plan{}, options, fmt.Errorf("--mesh-cidr %s overlaps observed cluster or local network %s", prefix.Masked(), strings.Join(conflicts, ", "))
		}
		options.MeshCIDR = prefix.Masked().String()
	}
	bundle, err := Render(options)
	if err != nil {
		return Plan{}, options, err
	}
	detection, err := p.detect(ctx)
	if err != nil {
		return Plan{}, options, err
	}
	plan := Plan{
		SchemaVersion:    SchemaVersion,
		Context:          options.Context,
		ClusterServer:    options.ClusterServer,
		Detection:        detection,
		WireKubeVersion:  options.WireKubeVersion,
		Image:            options.Image,
		Namespace:        options.Namespace,
		Relay:            options.Relay,
		RelayEndpoint:    options.RelayEndpoint,
		RelayUDPEndpoint: options.RelayUDPEndpoint,
		RelayUDP:         options.RelayUDP,
		MeshCIDR:         options.MeshCIDR,
		NodeAddresses:    options.NodeAddresses,
		Resources:        bundle.Resources,
		Impact: []string{
			"privileged host-networked agent Pod on each selected Linux node",
			"WireGuard interface, host routes, and policy routing rules on each agent node",
		},
	}
	if autoMeshCIDR {
		plan.Warnings = append(plan.Warnings, "automatic mesh CIDR selection is best effort and cannot inspect every VPC, corporate, or node routing table; review the selected CIDR and provide --exclude-cidr for known routes")
	}
	switch options.Relay {
	case RelayLoadBalancer:
		plan.Impact = append(plan.Impact, "one public TCP LoadBalancer")
		plan.Warnings = append(plan.Warnings, "the selected relay creates a public LoadBalancer and may incur provider charges")
		if options.RelayUDP {
			plan.Impact = append(plan.Impact, "one separate public UDP LoadBalancer")
		}
	case RelayNodePort:
		plan.Impact = append(plan.Impact, "TCP NodePort 30478 on cluster nodes")
		if options.RelayUDP {
			plan.Impact = append(plan.Impact, "UDP NodePort 30479 on cluster nodes")
		}
	case RelayExternal:
		plan.Warnings = append(plan.Warnings, "the external relay endpoint is not provisioned or owned by this installation")
		if options.RelayUDPEndpoint == "" {
			plan.Warnings = append(plan.Warnings, "external peer invites remain Pending until --relay-udp-endpoint is configured")
		}
	case RelayNone:
		plan.Warnings = append(plan.Warnings, "peers that cannot establish a direct path will remain disconnected")
	}
	return plan, options, nil
}

func installationAccessRequirements(options Options) []AccessRequirement {
	requirements := []AccessRequirement{
		{Resource: "nodes", Verb: "list"},
		{Resource: "services", Verb: "list"},
		{Resource: "pods", Verb: "list", Namespace: "kube-system"},
		{Resource: "configmaps", Verb: "list"},
		{Resource: "namespaces", Verb: "get", Name: options.Namespace},
		{Resource: "namespaces", Verb: "patch", Name: options.Namespace},
		{Resource: "serviceaccounts", Verb: "get", Namespace: options.Namespace, Name: "wirekube-agent"},
		{Resource: "serviceaccounts", Verb: "patch", Namespace: options.Namespace, Name: "wirekube-agent"},
		{Resource: "serviceaccounts", Verb: "delete", Namespace: options.Namespace, Name: "wirekube-agent"},
		{Resource: "configmaps", Verb: "get", Namespace: options.Namespace, Name: InventoryName},
		{Resource: "configmaps", Verb: "patch", Namespace: options.Namespace, Name: InventoryName},
		{Resource: "configmaps", Verb: "delete", Namespace: options.Namespace, Name: InventoryName},
		{Group: "apps", Resource: "daemonsets", Verb: "get", Namespace: options.Namespace, Name: "wirekube-agent"},
		{Group: "apps", Resource: "daemonsets", Verb: "patch", Namespace: options.Namespace, Name: "wirekube-agent"},
		{Group: "apps", Resource: "daemonsets", Verb: "delete", Namespace: options.Namespace, Name: "wirekube-agent"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "get", Name: "wirekube-agent"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "patch", Name: "wirekube-agent"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "delete", Name: "wirekube-agent"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "get", Name: "wirekube-agent"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "patch", Name: "wirekube-agent"},
		{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "delete", Name: "wirekube-agent"},
		{Group: "wirekube.io", Resource: "wirekubemeshes", Verb: "get", Name: "default"},
		{Group: "wirekube.io", Resource: "wirekubemeshes", Verb: "patch", Name: "default"},
	}
	for _, name := range []string{"wirekubemeshes.wirekube.io", "wirekubepeers.wirekube.io", "wirekubegateways.wirekube.io", "wirekubeexternalpeers.wirekube.io"} {
		requirements = append(requirements,
			AccessRequirement{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions", Verb: "get", Name: name},
			AccessRequirement{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions", Verb: "patch", Name: name},
		)
	}
	if options.Relay == RelayLoadBalancer || options.Relay == RelayNodePort {
		requirements = append(requirements,
			AccessRequirement{Group: "apps", Resource: "deployments", Verb: "get", Namespace: options.Namespace, Name: "wirekube-relay"},
			AccessRequirement{Group: "apps", Resource: "deployments", Verb: "patch", Namespace: options.Namespace, Name: "wirekube-relay"},
			AccessRequirement{Group: "apps", Resource: "deployments", Verb: "delete", Namespace: options.Namespace, Name: "wirekube-relay"},
		)
		for _, name := range []string{"wirekube-relay-control", "wirekube-relay", "wirekube-relay-udp"} {
			requirements = append(requirements,
				AccessRequirement{Resource: "services", Verb: "get", Namespace: options.Namespace, Name: name},
				AccessRequirement{Resource: "services", Verb: "patch", Namespace: options.Namespace, Name: name},
				AccessRequirement{Resource: "services", Verb: "delete", Namespace: options.Namespace, Name: name},
			)
		}
	}
	return requirements
}

func (p Planner) detect(ctx context.Context) (Detection, error) {
	detection := Detection{Provider: "unknown", CNI: "unknown"}
	if p.Discovery != nil {
		version, err := p.Discovery.ServerVersion()
		if err != nil {
			return detection, fmt.Errorf("discover Kubernetes version: %w", err)
		}
		detection.KubernetesVersion = version.GitVersion
	}
	var nodes corev1.NodeList
	if err := p.Client.List(ctx, &nodes); err != nil {
		return detection, fmt.Errorf("list Nodes: %w", err)
	}
	for _, node := range nodes.Items {
		providerID := strings.ToLower(node.Spec.ProviderID)
		switch {
		case strings.HasPrefix(providerID, "aws://"):
			detection.Provider = "aws"
		case strings.HasPrefix(providerID, "gce://"):
			detection.Provider = "gcp"
		case strings.HasPrefix(providerID, "azure://"):
			detection.Provider = "azure"
		case strings.HasPrefix(providerID, "oci://"):
			detection.Provider = "oci"
		}
	}
	var pods corev1.PodList
	if err := p.Client.List(ctx, &pods, client.InNamespace("kube-system")); err == nil {
		for _, pod := range pods.Items {
			name := strings.ToLower(pod.Name)
			switch {
			case strings.Contains(name, "cilium"):
				detection.CNI = "cilium"
			case strings.Contains(name, "calico") && detection.CNI == "unknown":
				detection.CNI = "calico"
			case strings.Contains(name, "flannel") && detection.CNI == "unknown":
				detection.CNI = "flannel"
			}
		}
	}
	return detection, nil
}

func (p Planner) selectMeshCIDR(ctx context.Context, excluded []string) (string, error) {
	occupied, err := p.occupiedPrefixes(ctx, excluded)
	if err != nil {
		return "", err
	}
	candidates := []string{"100.96.0.0/11", "100.64.0.0/11", "10.240.0.0/16", "172.30.0.0/16", "198.18.0.0/16"}
	for _, candidate := range candidates {
		prefix := netip.MustParsePrefix(candidate)
		if !overlapsAny(prefix, occupied) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no safe mesh CIDR candidate remains; specify --mesh-cidr and use --exclude-cidr for known routes")
}

func (p Planner) occupiedPrefixes(ctx context.Context, excluded []string) ([]netip.Prefix, error) {
	var occupied []netip.Prefix
	add := func(value string) {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			occupied = append(occupied, prefix.Masked())
		} else if addr, err := netip.ParseAddr(value); err == nil {
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			occupied = append(occupied, netip.PrefixFrom(addr, bits))
		}
	}
	for _, value := range excluded {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid --exclude-cidr %q: %w", value, err)
		}
		occupied = append(occupied, prefix.Masked())
	}
	var nodes corev1.NodeList
	if err := p.Client.List(ctx, &nodes); err != nil {
		return nil, fmt.Errorf("list Nodes for mesh CIDR selection: %w", err)
	}
	for _, node := range nodes.Items {
		for _, cidr := range node.Spec.PodCIDRs {
			add(cidr)
		}
		for _, address := range node.Status.Addresses {
			add(address.Address)
		}
	}
	var services corev1.ServiceList
	if err := p.Client.List(ctx, &services); err != nil {
		return nil, fmt.Errorf("list Services for mesh CIDR selection: %w", err)
	}
	for _, service := range services.Items {
		for _, ip := range service.Spec.ClusterIPs {
			add(ip)
		}
		for _, ingress := range service.Status.LoadBalancer.Ingress {
			add(ingress.IP)
		}
	}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			add(address.String())
		}
	}
	sort.Slice(occupied, func(i, j int) bool { return occupied[i].String() < occupied[j].String() })
	return occupied, nil
}

func overlapsAny(candidate netip.Prefix, occupied []netip.Prefix) bool {
	for _, prefix := range occupied {
		if candidate.Addr().BitLen() != prefix.Addr().BitLen() {
			continue
		}
		if candidate.Contains(prefix.Addr()) || prefix.Contains(candidate.Addr()) {
			return true
		}
	}
	return false
}

func overlappingPrefixes(candidate netip.Prefix, occupied []netip.Prefix) []string {
	conflicts := make([]string, 0)
	seen := map[string]struct{}{}
	for _, prefix := range occupied {
		if candidate.Addr().BitLen() != prefix.Addr().BitLen() {
			continue
		}
		if !candidate.Contains(prefix.Addr()) && !prefix.Contains(candidate.Addr()) {
			continue
		}
		value := prefix.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		conflicts = append(conflicts, value)
	}
	sort.Strings(conflicts)
	return conflicts
}
