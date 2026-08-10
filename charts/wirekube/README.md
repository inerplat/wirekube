# wirekube

Helm chart for [WireKube](https://github.com/inerplat/wirekube): a WireGuard mesh between Kubernetes nodes coordinated through CRDs.

## Install

```bash
helm install wirekube ./charts/wirekube \
  --namespace wirekube-system --create-namespace \
  --set mesh.meshCIDR=100.96.0.0/11
```

`mesh.meshCIDR` has no default on purpose: it must be a private range that does not overlap your VPC, Pod, or Service CIDRs. Every node receives a deterministic `/32` from this range.

One release per cluster. Component names (`wirekube-agent`, `wirekube-relay`, `wirekube-relay-control`, `wirekube-relay-udp`, `wirekube-relay-ws`) are fixed because the agent and the relay-endpoint reconciler resolve Services by name.

## Topologies

| Topology | Values |
|----------|--------|
| Cloud with LoadBalancer (default) | `relay.service.type=LoadBalancer` |
| Bare metal / no LB | `relay.service.type=NodePort`, `mesh.relay.controlEndpoint=<node-ip>:30478` (required; the mesh CR is rendered with provider `external` because NodePort has no LB ingress to discover) |
| WSS behind Gateway/Ingress | `relayWs.enabled=true`, `mesh.relay.transport=wss`, `mesh.relay.controlEndpoint=wss://relay.example.com/relay` (the raw TCP Service is not rendered; the unauthenticated control port stays private) |
| External relay you operate | `relay.enabled=false`, `mesh.relay.external.endpoint` / `mesh.relay.external.controlEndpoint` |
| No relay (direct-only) | `relay.enabled=false`, leave `mesh.relay.external.*` empty |

Invalid combinations (`wss` without `relayWs.enabled`, NodePort without `controlEndpoint`, `relay.replicas>1` without `relay.clusterKube`, non-loopback admin console without an auth Secret) fail at template time with an explanatory message.

## Node privileges

The agent DaemonSet runs with `hostNetwork: true`, `privileged: true`, unconfined AppArmor, and `NET_ADMIN`/`SYS_MODULE`, and mounts `/dev/net/tun`, `/proc/sys/net`, and `/var/lib/wirekube` from the host. This is required to create the WireGuard TUN device and manage routing on every node. On namespaces with Pod Security Admission enforcement, label the namespace `pod-security.kubernetes.io/enforce=privileged`.

## Key values

| Value | Default | Description |
|-------|---------|-------------|
| `image.repository` | `inerplat/wirekube` | Single image for agent, relay, relay-ws, admin-web |
| `image.tag` | chart `appVersion` | Image tag |
| `agent.interfaceName` | `wire_kube` | WireGuard interface name, also rendered into the mesh spec |
| `agent.kubeAPIServer` | `""` | Bootstrap-only apiserver override for nodes that cannot reach the in-cluster Service IP |
| `agent.metrics.serviceMonitor.enabled` | `false` | Prometheus Operator ServiceMonitor |
| `relay.enabled` | `true` | Deploy the managed relay |
| `relay.replicas` | `1` | Relay replicas (lease-backed peer registry keeps replicas coherent) |
| `relay.service.type` | `LoadBalancer` | `LoadBalancer` or `NodePort`; TCP and UDP are separate Services |
| `relay.service.udp.enabled` | `true` | UDP entry point for external WireGuard peers; disable to avoid a public UDP port |
| `relay.adminWeb.enabled` | `true` | Loopback-only external-peer console sidecar |
| `relay.adminWeb.existingAuthSecret` | `""` | Secret with `WIREKUBE_ADMIN_WEB_USERNAME` / `WIREKUBE_ADMIN_WEB_PASSWORD_HASH`; required before exposing the console |
| `relayWs.enabled` | `false` | Authenticated WebSocket front for wss transport |
| `mesh.create` | `true` | Create the `WireKubeMesh` CR |
| `mesh.meshCIDR` | (required) | Overlay CIDR |
| `mesh.relay.mode` | `auto` | `auto` / `always` / `never` |
| `mesh.relay.transport` | `tcp` | `tcp` or `wss` for the managed relay |

See [values.yaml](values.yaml) for the full list.

## CRDs

The four WireKube CRDs ship in `crds/` and are installed by Helm on first install. Helm does not upgrade or delete CRDs; on chart upgrades apply them manually when they changed:

```bash
kubectl apply -f charts/wirekube/crds/
```

## Uninstall

`helm uninstall` removes the workloads but keeps CRDs and, by design, the WireGuard kernel state on each node (the agent preserves it for zero-downtime restarts). To decommission a node completely, use [config/cleanup/cleanup-job.yaml](../../config/cleanup/cleanup-job.yaml).
