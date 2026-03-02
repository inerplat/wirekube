# CRD Reference

## WireKubeMesh

**API Version:** `wirekube.io/v1alpha1`
**Kind:** `WireKubeMesh`
**Scope:** Cluster

The WireKubeMesh resource defines the global mesh configuration. Typically
one instance named `default` exists per cluster.

### Spec

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

### Field Descriptions

#### `spec`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `listenPort` | int | No | `51820` | WireGuard UDP listen port on each node |
| `interfaceName` | string | No | `wire_kube` | Name of the WireGuard network interface |
| `mtu` | int | No | `1420` | Interface MTU. 1420 accounts for WireGuard overhead |
| `stunServers` | []string | No | - | STUN servers for public endpoint discovery |

#### `spec.relay`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | `auto` | `auto`: try direct first, fallback to relay. `always`: always relay. `never`: direct only |
| `provider` | string | No | - | `external`: user-provided relay. `managed`: operator-deployed |
| `handshakeTimeoutSeconds` | int | No | `30` | Seconds to wait for direct handshake before relay |
| `directRetryIntervalSeconds` | int | No | `120` | Seconds between attempts to re-establish direct P2P from relay |

#### `spec.relay.external`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `endpoint` | string | Yes (if external) | - | Relay server address (`host:port`) |
| `transport` | string | No | `tcp` | Transport protocol (`tcp`) |

#### `spec.relay.managed`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `replicas` | int | No | `1` | Number of relay pod replicas |
| `serviceType` | string | No | `LoadBalancer` | Kubernetes Service type |
| `port` | int | No | `3478` | Relay service port |

When `provider: managed`, the agent connects to `wirekube-relay.wirekube-system.svc.cluster.local:<port>`.
You must deploy the relay Deployment and Service separately (see `config/relay/`).

---

## WireKubePeer

**API Version:** `wirekube.io/v1alpha1`
**Kind:** `WireKubePeer`
**Scope:** Cluster

WireKubePeer resources are automatically created and managed by the agent.
One per mesh-participating node.

### Spec

```yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubePeer
metadata:
  name: node-my-node
  labels:
    wirekube.io/node: my-node
spec:
  publicKey: "base64-encoded-wireguard-public-key"
  endpoint: "1.2.3.4:51820"
  allowedIPs:
    - "172.20.1.6/32"
  persistentKeepalive: 25
```

### Field Descriptions

#### `spec`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `publicKey` | string | Yes | Base64-encoded WireGuard public key |
| `endpoint` | string | No | Public endpoint (`ip:port`) discovered by the agent |
| `allowedIPs` | []string | No | WireGuard AllowedIPs (typically `[nodeIP/32]`) |
| `persistentKeepalive` | int | No | WireGuard PersistentKeepalive interval (seconds) |

#### `status`

| Field | Type | Description |
|-------|------|-------------|
| `connected` | bool | Whether the WireGuard handshake has completed |
| `transportMode` | string | `direct` or `relay` |
| `endpointDiscoveryMethod` | string | How the endpoint was discovered (`stun`, `annotation`, `ipv6`, `aws-imds`, `upnp`, `internal`) |
| `lastHandshakeTime` | string | Timestamp of the last successful handshake |

### Labels

| Label | Description |
|-------|-------------|
| `wirekube.io/node` | Node name this peer represents |

### Naming Convention

Peer resources are named `node-<node-name>` (e.g., `node-my-node`).
