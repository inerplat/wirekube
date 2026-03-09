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
| `spec.stunServers` | []string | - | STUN servers for endpoint discovery. **Minimum 2 required** for Symmetric NAT detection (RFC 5780). |
| `spec.relay.mode` | string | `auto` | `auto`, `always`, or `never` |
| `spec.relay.provider` | string | - | `external` or `managed` |
| `spec.relay.handshakeTimeoutSeconds` | int | `30` | Seconds to wait for direct handshake before relay fallback |
| `spec.relay.directRetryIntervalSeconds` | int | `120` | How often to retry direct connection after falling back to relay |
| `spec.relay.external.endpoint` | string | - | External relay server address (`host:port`) |
| `spec.relay.external.transport` | string | `tcp` | Relay transport protocol |
| `spec.relay.managed.replicas` | int | `1` | Number of relay pods |
| `spec.relay.managed.serviceType` | string | `LoadBalancer` | Kubernetes Service type for the relay |
| `spec.relay.managed.port` | int | `3478` | Relay service port |

### Relay Modes

| Mode | Behavior |
|------|----------|
| `auto` | Try direct P2P first; fall back to relay after `handshakeTimeoutSeconds`. Periodically re-probe direct. |
| `always` | Always use relay (useful for testing or highly restrictive networks) |
| `never` | Never use relay; only direct P2P |

### Relay Providers

| Provider | Description |
|----------|-------------|
| `external` | User-provided relay endpoint. Agent connects to the configured `external.endpoint`. |
| `managed` | Relay deployed as Deployment + Service in the cluster. Agent auto-discovers the Service's external address (ExternalIP → LB Ingress → NodePort) so NAT'd nodes can connect without relying on CNI tunnels. Does **not** fall back to ClusterIP DNS. |

## Node Labels and Annotations

### Labels

| Label | Description |
|-------|-------------|
| `wirekube.io/vpn-enabled=true` | Node participates in the mesh |

### Annotations

| Annotation | Description |
|------------|-------------|
| `wirekube.io/endpoint` | Manual endpoint override (`ip:port`). Takes highest priority in endpoint discovery. |

Example:

```bash
kubectl label node my-node wirekube.io/vpn-enabled=true
kubectl annotate node my-node wirekube.io/endpoint="203.0.113.5:51820"
```

## Agent Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Node name (set via downward API in the DaemonSet) | Required |

## DaemonSet Details

### Security Context

The agent requires two capabilities:

```yaml
securityContext:
  capabilities:
    add: ["NET_ADMIN", "SYS_MODULE"]
```

- **NET_ADMIN** — Create/delete WireGuard interfaces, manage routes and routing rules
- **SYS_MODULE** — Load the `wireguard` kernel module if not already loaded

`privileged: true` is **not required**.

### DNS Policy

The DaemonSet uses `dnsPolicy: ClusterFirstWithHostNet`. Since the agent runs with
`hostNetwork: true`, this setting ensures it can resolve cluster-internal DNS names
for Kubernetes API and other services.

### initContainer Cleanup

The DaemonSet includes an `initContainer` that cleans up stale state from previous
agent runs (crashes, reboots):

- Removes the `wire_kube` interface if it exists
- Flushes the WireKube routing table (`22347` / `0x574B`)
- Removes stale `ip rule` entries for the WireKube fwmark

### IPSec xfrm Bypass

On startup, the agent sets `disable_xfrm=1` and `disable_policy=1` on the WireGuard
interface via `/proc/sys/net/ipv4/conf/<iface>/`. This prevents IPSec xfrm policies
from intercepting WireGuard traffic — critical for environments with existing
site-to-site IPSec tunnels.

The DaemonSet mounts the host's `/proc/sys/net` to `/host/proc/sys/net` to write
these sysctl values, since the container's default `/proc/sys` is read-only.
