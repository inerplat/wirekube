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

### Field Descriptions

#### `spec`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `listenPort` | int | No | `51820` | WireGuard UDP listen port on each node |
| `interfaceName` | string | No | `wire_kube` | Name of the WireGuard network interface |
| `mtu` | int | No | `1420` | Interface MTU. 1420 accounts for WireGuard overhead (40B IPv6 or 20B IPv4 + 8B UDP + 32B WG) |
| `stunServers` | []string | No | - | STUN servers for public endpoint discovery. **Minimum 2 required** — the agent compares mapped ports across servers to detect Symmetric NAT (RFC 5780). |

#### `spec.relay`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | `auto` | `auto`: try direct first, fallback to relay. `always`: always relay. `never`: direct only |
| `provider` | string | No | - | `external`: user-provided relay. `managed`: deployed within the cluster |
| `handshakeTimeoutSeconds` | int | No | `30` | Seconds to wait for direct handshake before activating relay |
| `directRetryIntervalSeconds` | int | No | `120` | Seconds between attempts to upgrade a relayed peer back to direct P2P |

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

When `provider: managed`, the agent discovers the relay's externally reachable
address by querying the Service (ExternalIP → LB Ingress → NodePort). If no
external address is found, it falls back to `wirekube-relay.wirekube-system.svc.cluster.local:<port>`.

For multi-instance scaling, use a Headless Service. The relay pool re-resolves
DNS every 30s to track replica changes.

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
  endpoint: "203.0.113.5:51820"
  allowedIPs:
    - "10.0.0.5/32"
  persistentKeepalive: 25
```

### Field Descriptions

#### `spec`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `publicKey` | string | Yes | Base64-encoded WireGuard public key |
| `endpoint` | string | No | Public endpoint (`ip:port`) discovered by the agent. For Symmetric NAT nodes, this is the STUN-discovered public IP with the configured listen port. |
| `allowedIPs` | []string | No | WireGuard AllowedIPs (typically `[nodeIP/32]`). When empty, the agent enters passive mode — no routes or WireGuard peer config for this node. User-managed. |
| `persistentKeepalive` | int | No | WireGuard PersistentKeepalive interval (seconds) |

#### `status`

| Field | Type | Description |
|-------|------|-------------|
| `connected` | bool | Whether a recent WireGuard handshake has been observed |
| `natType` | string | Detected NAT mapping behavior: `cone`, `symmetric`, or empty (undetermined). Published by the agent so other peers can decide transport path. |
| `transportMode` | string | Aggregate transport state derived from `peerTransports`: `direct`, `relay`, or `mixed`. |
| `peerTransports` | map[string]string | Per-peer transport mode. Key is peer CRD name (e.g., `node-worker7`), value is `direct` or `relay`. |
| `endpointDiscoveryMethod` | string | How the endpoint was discovered: `stun`, `annotation`, `ipv6`, `aws-imds`, `upnp`, `internal` |
| `lastHandshake` | time | Timestamp of the last successful WireGuard handshake |

Transport mode values:

| Value | Meaning |
|-------|---------|
| `direct` | All peers connected via direct P2P |
| `relay` | All peers via relay |
| `mixed` | Some peers direct, some relayed |

The `natType` and `transportMode` fields are shown as `NAT` and `Mode` columns in `kubectl get wirekubepeers` output.

### Labels

| Label | Description |
|-------|-------------|
| `wirekube.io/node` | Node name this peer represents |

### Naming Convention

Peer resources are named `node-<node-name>` (e.g., `node-my-node`).
