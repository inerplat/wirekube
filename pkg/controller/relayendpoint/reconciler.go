// Package relayendpoint syncs the managed relay Service's LoadBalancer
// ingress into WireKubeMesh.status.relayEndpoint. Agents on nodes without
// working cluster DNS (bootstrap nodes whose CNI is not up yet) cannot
// resolve the cluster-local relay control Service, so the leader agent
// publishes the relay's public address on the mesh status for every agent
// to dial directly.
package relayendpoint

import (
	"context"
	"net"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// relayServiceName is the managed relay's agent-facing TCP Service
// (rendered by internal/install as type LoadBalancer by default).
const relayServiceName = "wirekube-relay"

// defaultRelayPort mirrors the ManagedRelaySpec.Port kubebuilder default.
const defaultRelayPort = int32(3478)

// Reconciler keeps WireKubeMesh.status.relayEndpoint in sync with the
// wirekube-relay Service's LoadBalancer ingress. It only acts for the
// managed relay provider with a LoadBalancer Service; external relays,
// NodePort deployments, and wss transport resolve their endpoint from spec.
type Reconciler struct {
	client.Client
	// RelayNamespace is the namespace the managed relay Service lives in
	// (the agent pod's own namespace).
	RelayNamespace string
}

// SetupWithManager registers the reconciler with controller-runtime. Mesh
// edits enqueue directly; relay Service events map onto every WireKubeMesh
// (the mesh is a cluster-scoped singleton, normally named "default").
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapRelayService := func(ctx context.Context, obj client.Object) []reconcile.Request {
		if obj.GetName() != relayServiceName || obj.GetNamespace() != r.RelayNamespace {
			return nil
		}
		meshList := &wirekubev1alpha1.WireKubeMeshList{}
		if err := mgr.GetClient().List(ctx, meshList); err != nil {
			return nil
		}
		requests := make([]reconcile.Request, 0, len(meshList.Items))
		for i := range meshList.Items {
			requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: meshList.Items[i].Name}})
		}
		return requests
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&wirekubev1alpha1.WireKubeMesh{}).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(mapRelayService)).
		Complete(r)
}

// Reconcile publishes the relay Service's LoadBalancer ingress as
// status.relayEndpoint when the mesh uses the managed relay provider over a
// LoadBalancer Service.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	if err := r.Get(ctx, req.NamespacedName, mesh); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Mirror the agent's provider switch (initRelay): only the managed
	// provider dials the cluster-provisioned relay, so only it needs
	// LoadBalancer endpoint discovery.
	relay := mesh.Spec.Relay
	if relay == nil || relay.Provider != "managed" {
		return ctrl.Result{}, nil
	}
	managed := relay.Managed
	serviceType := ""
	transport := ""
	port := defaultRelayPort
	if managed != nil {
		serviceType = strings.TrimSpace(managed.ServiceType)
		transport = strings.ToLower(strings.TrimSpace(managed.Transport))
		if managed.Port != 0 {
			port = managed.Port
		}
	}
	// NodePort deployments have no LoadBalancer ingress to discover, and wss
	// agents dial managed.controlEndpoint directly. Empty ServiceType means
	// the kubebuilder default, LoadBalancer.
	if serviceType != "" && serviceType != string(corev1.ServiceTypeLoadBalancer) {
		return ctrl.Result{}, nil
	}
	if transport != "" && transport != "tcp" {
		return ctrl.Result{}, nil
	}

	svc := &corev1.Service{}
	if err := r.Get(ctx, client.ObjectKey{Name: relayServiceName, Namespace: r.RelayNamespace}, svc); err != nil {
		// A missing Service is transient (installer ordering, relay being
		// recreated); the Service watch re-triggers when it appears.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	host := ingressHost(svc)
	if host == "" {
		// NEVER clear a previously-set endpoint: during LoadBalancer
		// recreation the ingress list is briefly empty and agents must keep
		// dialing the last-known-good address instead of falling back to the
		// cluster-DNS name that bootstrap nodes cannot resolve.
		return ctrl.Result{}, nil
	}

	desired := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if desired == mesh.Status.RelayEndpoint {
		return ctrl.Result{}, nil
	}
	patch := client.MergeFrom(mesh.DeepCopy())
	mesh.Status.RelayEndpoint = desired
	return ctrl.Result{}, r.Status().Patch(ctx, mesh, patch)
}

// ingressHost returns the first usable LoadBalancer ingress address,
// preferring a stable DNS hostname over an IP within each entry.
func ingressHost(svc *corev1.Service) string {
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.Hostname != "" {
			return ing.Hostname
		}
		if ing.IP != "" {
			return ing.IP
		}
	}
	return ""
}
