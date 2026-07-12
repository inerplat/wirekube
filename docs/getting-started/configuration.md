# Configuration

## WireKubeMesh

The `WireKubeMesh` resource defines global mesh settings. Typically one per cluster, named `default`.

```yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubeMesh
metadata:
  name: default
spec:
  listenPort: 51820
  interfaceName: wire_kube
  mtu: 1420
  meshCIDR: "172.31.240.0/20"          # example only; choose a non-overlapping private range
  autoAllowedIPs:
    includeNodeInternalIP: true         # optionally also publish each node's private IP
  stunServers:
    - stun.cloudflare.com:3478
    - stun.l.google.com:19302
  relay:
    mode: auto
    provider: managed
    handshakeTimeoutSeconds: 30
    directRetryIntervalSeconds: 120
    external:
      endpoint: "relay.example.com:3478"
      transport: tcp
    managed:
      replicas: 1
      serviceType: LoadBalancer
      port: 3478
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec.listenPort` | int | `51820` | WireGuard UDP listen port |
| `spec.interfaceName` | string | `wire_kube` | WireGuard network interface name |
| `spec.mtu` | int | `1420` | Interface MTU (1420 accounts for WireGuard overhead) |
| `spec.meshCIDR` | string | - | Private CIDR for the overlay. Each node is automatically assigned a stable `/32` within this range derived from `fnv32a(nodeName)`, and that IP becomes the peer's primary AllowedIPs entry. Choose a range that does not overlap with node, pod, service, VPC, proxy, or corporate networks. Leave empty to manage AllowedIPs entirely by hand. |
| `spec.autoAllowedIPs.includeNodeInternalIP` | bool | `false` | When `true`, also append the node's **private** address to its peer entry so legacy references by node IP still tunnel. The agent never publishes a public IP even if kubelet reports one as `Node.InternalIP` (common on Oracle Cloud / NCloud); set the `wirekube.io/internal-ip` annotation on the Node to force a specific private address. |
| `spec.stunServers` | []string | - | STUN servers for endpoint discovery. **Minimum 2 required** for Symmetric NAT detection (RFC 5780). |
| `spec.relay.mode` | string | `auto` | `auto`, `always`, or `never` |
| `spec.relay.provider` | string | - | `external` or `managed` |
| `spec.relay.handshakeTimeoutSeconds` | int | `30` | Retained API field. The current PathMonitor-based relay-first flow does not consume this value after initialization. |
| `spec.relay.directRetryIntervalSeconds` | int | `120` | How often to retry direct connection after falling back to relay |
| `spec.relay.external.endpoint` | string | - | External relay server address (`host:port`) |
| `spec.relay.external.controlEndpoint` | string | - | Agent-facing endpoint. Required as a `ws://` or `wss://` URL when the selected transport is WebSocket. |
| `spec.relay.external.transport` | string | `tcp` | Selects exactly one agent transport: `tcp`, `ws`, or `wss`. |
| `spec.relay.managed.replicas` | int | `1` | Desired relay replicas in the API shape. The current agent does not provision or scale the Deployment from this field. |
| `spec.relay.managed.serviceType` | string | `LoadBalancer` | Desired Service type in the API shape. The current agent does not create or mutate the Service from this field. |
| `spec.relay.managed.port` | int | `3478` | Relay service port |

### Relay Modes

| Mode | Behavior |
|------|----------|
| `auto` | Connect relay-first for immediate reachability, probe the direct path, and promote peers to direct when receive evidence is healthy. Periodically re-probe direct after demotion. |
| `always` | Always use relay (useful for testing or highly restrictive networks) |
| `never` | Never use relay; only direct P2P |

### Relay Providers

| Provider | Description |
|----------|-------------|
| `external` | User-provided relay endpoint. The agent selects `external.endpoint` or `external.controlEndpoint` according to `external.transport`. |
| `managed` | Relay deployed separately in the cluster. Agents connect through the cluster-local `wirekube-relay-control` Service; WireKube does not currently create the Deployment or Service from the CR. Use `external` with a public LB, NodePort, or WSS endpoint when cluster DNS/service routing is unavailable during bootstrap. |

## Node Labels and Annotations

### Labels

| Label | Description |
|-------|-------------|
| `wirekube.io/proxy-node=true` | Excludes the node from the standard DaemonSet and selects it for the dedicated HTTP-proxy DaemonSet example. |

### Annotations

| Annotation | Description |
|------------|-------------|
| `wirekube.io/endpoint` | Manual endpoint override (`ip:port`). Takes highest priority in endpoint discovery. |

Example:

```bash
kubectl annotate node my-node wirekube.io/endpoint="203.0.113.5:51820"
```

## Agent Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Node name (set via downward API in the DaemonSet) | Required |

## DaemonSet Details

### Security Context

The bundled userspace-WireGuard DaemonSet uses the following security context:

```yaml
securityContext:
  privileged: true
  appArmorProfile:
    type: Unconfined
  capabilities:
    add: ["NET_ADMIN", "SYS_MODULE"]
```

- **NET_ADMIN** — Create/delete WireGuard interfaces, manage routes and routing rules
- **SYS_MODULE** — Load the `wireguard` kernel module if not already loaded

`privileged: true` is currently enabled because common Ubuntu 24.04 and containerd configurations deny `/dev/net/tun` access with capabilities alone.

### DNS Policy

The bundled DaemonSet currently uses `dnsPolicy: Default`. If `provider: managed` is used, the node resolver must be able to resolve `wirekube-relay-control.<namespace>.svc.cluster.local`; otherwise change the policy to `ClusterFirstWithHostNet` or use an externally reachable relay endpoint.

### Cleanup and Reconciliation

The default DaemonSet does not include an initContainer. During graceful shutdown the agent removes the relay clients, routes, routing rules, and TUN interface. During startup and periodic sync it recreates or repairs required interface and routing state.

- Graceful shutdown removes the `wire_kube` interface and WireKube routes
- Routing rule reconciliation repairs missing or stale rules
- The separate cleanup Job is available for abandoned node state

### IPSec xfrm Bypass

On startup, the agent sets `disable_xfrm=1` and `disable_policy=1` on the WireGuard
interface via `/proc/sys/net/ipv4/conf/<iface>/`. This prevents IPSec xfrm policies
from intercepting WireGuard traffic — critical for environments with existing
site-to-site IPSec tunnels.

The DaemonSet mounts the host's `/proc/sys/net` to `/host/proc/sys/net` to write
these sysctl values, since the container's default `/proc/sys` is read-only.
