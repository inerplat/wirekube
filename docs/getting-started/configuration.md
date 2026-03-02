# Configuration

## WireKubeMesh

The `WireKubeMesh` resource defines global mesh settings. Typically one per cluster.

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
    provider: external
    handshakeTimeoutSeconds: 30
    directRetryIntervalSeconds: 120
    external:
      endpoint: "relay.example.com:3478"
      transport: tcp
    managed:
      replicas: 1
      serviceType: LoadBalancer
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec.listenPort` | int | `51820` | WireGuard UDP listen port |
| `spec.interfaceName` | string | `wire_kube` | WireGuard network interface name |
| `spec.mtu` | int | `1420` | Interface MTU (1420 recommended for WireGuard) |
| `spec.stunServers` | []string | - | STUN servers for endpoint discovery |
| `spec.relay.mode` | string | `auto` | `auto`, `always`, or `never` |
| `spec.relay.provider` | string | - | `external` or `managed` |
| `spec.relay.handshakeTimeoutSeconds` | int | `30` | Seconds to wait for direct handshake before relay fallback |
| `spec.relay.directRetryIntervalSeconds` | int | `120` | How often to retry direct connection after falling back to relay |
| `spec.relay.external.endpoint` | string | - | External relay server address (`host:port`) |
| `spec.relay.external.transport` | string | `tcp` | Relay transport protocol |
| `spec.relay.managed.replicas` | int | `1` | Number of relay pods |
| `spec.relay.managed.serviceType` | string | `LoadBalancer` | Kubernetes Service type |

### Relay Modes

| Mode | Behavior |
|------|----------|
| `auto` | Try direct P2P first; fall back to relay after `handshakeTimeoutSeconds` |
| `always` | Always use relay (useful for testing or highly restrictive networks) |
| `never` | Never use relay; only direct P2P |

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
# Enable VPN on a node
kubectl label node my-node wirekube.io/vpn-enabled=true

# Override endpoint (e.g., for nodes behind a specific NAT/LB)
kubectl annotate node my-node wirekube.io/endpoint="203.0.113.5:51820"
```

## Agent Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WIREKUBE_KUBE_APISERVER` | API server URL | In-cluster config |
| `WIREKUBE_INTERFACE` | Override interface name | From WireKubeMesh |
| `NODE_NAME` | Node name (set via downward API) | Required |
| `KUBECONFIG` | Kubeconfig path (for out-of-cluster) | - |

## DaemonSet Security Context

The agent requires only two capabilities:

```yaml
securityContext:
  capabilities:
    add: ["NET_ADMIN", "SYS_MODULE"]
```

- **NET_ADMIN** — Create/delete WireGuard interfaces, manage routes
- **SYS_MODULE** — Load the `wireguard` kernel module if needed

`privileged: true` is **not required**.
