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
  meshCIDR: "172.31.240.0/20"      # example only; choose a non-overlapping private range
  autoAllowedIPs:
    includeNodeInternalIP: true     # also publish each node's private IP (never public)
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
| `meshCIDR` | string | No | - | Private CIDR used for mesh overlay addresses. Each node gets a deterministic `/32` inside this range, derived from an FNV-1a hash of the node name. The overlay IP becomes the primary AllowedIPs entry and is assigned to the `wire_kube` TUN. Choose a range that does not overlap with node, pod, service, VPC, proxy, or corporate networks. When empty, peers use only manually managed AllowedIPs. |
| `autoAllowedIPs.includeNodeInternalIP` | bool | No | `false` | When `true`, the agent also appends the node's **private** address to `spec.allowedIPs` (resolved from `Node.status.addresses` first, then from local interfaces as a fallback). Public IPs are never auto-advertised — doing so would hijack SSH / apiserver routes on the next tunnel flap. Operators can override the picked address with the `wirekube.io/internal-ip` annotation on the Node. |
| `stunServers` | []string | No | - | STUN servers for public endpoint discovery. **Minimum 2 required** — the agent compares mapped ports across servers to detect Symmetric NAT (RFC 5780). |

#### `spec.relay`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | string | No | `auto` | `auto`: start with relay available and promote healthy peers to direct. `always`: always relay. `never`: direct only |
| `provider` | string | No | - | `external`: connect to a user-provided endpoint. `managed`: use the installed cluster-local TCP relay or its configured WSS gateway. |
| `handshakeTimeoutSeconds` | int | No | `30` | Retained API field. The current PathMonitor relay-first flow stores this value but does not use it for path transitions. |
| `directRetryIntervalSeconds` | int | No | `120` | Seconds between attempts to upgrade a relayed peer back to direct P2P |

#### `spec.relay.external`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `endpoint` | string | No | - | Raw UDP relay address (`host:port`) used for NAT probing and external WireGuard peers; it is also the TCP fallback when `controlEndpoint` is empty. |
| `transport` | string | No | `tcp` | Selects exactly one agent transport: `tcp`, `ws`, or `wss`. |
| `controlEndpoint` | string | Required for `ws`/`wss` | - | Agent-facing endpoint. It may be a separate raw address for `tcp` or a matching `ws://`/`wss://` URL. |
| `authSecretRef` | SecretKeyRef | No | - | Reserved authentication configuration. The current relay client does not read this Secret or send a relay credential. |

#### `spec.relay.managed`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `replicas` | int | No | `1` | Desired replicas in the API shape; no controller currently reconciles this into a Deployment. |
| `serviceType` | string | No | `LoadBalancer` | Desired Service type in the API shape; no controller currently reconciles this field. |
| `port` | int | No | `3478` | Port used when constructing the cluster-local managed relay endpoint. |
| `image` | string | No | - | Reserved deployment configuration; currently not reconciled. |
| `controlEndpoint` | string | Required for `wss` | - | Public `wss://HOST/PATH` URL used by agents when managed transport is WSS. |
| `transport` | string | No | `tcp` | Selects the managed agent transport: `tcp` or `wss`. |
| `resources` | RelayResources | No | - | Reserved deployment configuration; currently not reconciled. |

When `provider: managed`, TCP agents connect to the cluster-local `wirekube-relay-control` Service and WSS agents connect through `managed.controlEndpoint`. The agent does not reconcile Deployments or Services from this CR; `wirekubectl install` provisions the managed relay and WebSocket gateway resources. Nodes that cannot use cluster DNS or service routing during bootstrap can use `provider: external` with a reachable LoadBalancer, NodePort, or WSS endpoint.

For multi-instance scaling, use a Headless Service. The relay pool re-resolves DNS every 30s to track replica changes.

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
  name: my-node
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
| `connected` | bool | Whether the agent currently considers at least one usable transport path available |
| `natType` | string | Detected NAT mapping behavior: `open` (no NAT — public IP on NIC), `cone`, `port-restricted-cone`, `symmetric`, or empty (undetermined). Published by the agent so other peers can decide transport path. |
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

Agent-managed peer resources use the Kubernetes Node name directly (for example, Node `worker-a` owns WireKubePeer `worker-a`).

---

## WireKubeGateway

**API Version:** `wirekube.io/v1alpha1`
**Kind:** `WireKubeGateway`
**Scope:** Cluster
**Short Name:** `wkgw`

WireKubeGateway defines a virtual gateway that enables mesh nodes to reach
networks behind a designated gateway node. Similar to a VGW in AWS Site-to-Site
VPN. See [Virtual Gateway](../architecture/gateway.md) for the architecture.

### Spec

```yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubeGateway
metadata:
  name: vpc-b-gateway
spec:
  peerRefs:
    - node-b1
    - node-b2
  clientRefs:
    - node-a1
  routes:
    - cidr: "172.20.0.0/16"
      description: "VPC-B subnet"
  snat:
    enabled: true
    sourceIP: ""
  healthCheck:
    enabled: true
    target: "172.20.1.254:443"
    intervalSeconds: 30
    timeoutSeconds: 5
    failureThreshold: 3
```

### Field Descriptions

#### `spec`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `peerRefs` | []string | Yes | Ordered list of WireKubePeer names serving as gateway. First healthy peer is elected active (HA failover). Min 1. |
| `clientRefs` | []string | No | WireKubePeer names that should route through this gateway. If empty, all mesh peers (except gateway peers and same-CIDR peers) are clients. |
| `routes` | []GatewayRoute | Yes | CIDR ranges reachable through the gateway. Injected into active peer's AllowedIPs. Min 1. |
| `snat` | GatewaySNAT | No | Source NAT configuration for return traffic routing. |
| `healthCheck` | GatewayHealthCheck | No | Probe configuration for HA failover. |

#### `spec.routes[]`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cidr` | string | Yes | Network CIDR (e.g. `172.20.0.0/16`). Pattern: `^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$` |
| `description` | string | No | Human-readable label |

#### `spec.snat`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | Yes | - | Activates iptables MASQUERADE for forwarded traffic |
| `sourceIP` | string | No | (gateway's first AllowedIP) | Override SNAT source address |

#### `spec.healthCheck`

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | Yes | - | Activates periodic health checking |
| `target` | string | Yes | - | Probe address. TCP connect when port specified, ICMP otherwise. |
| `intervalSeconds` | int | No | `30` | Probe interval (min 5) |
| `timeoutSeconds` | int | No | `5` | Probe timeout (min 1) |
| `failureThreshold` | int | No | `3` | Consecutive failures before marking unhealthy (min 1) |

#### `status`

| Field | Type | Description |
|-------|------|-------------|
| `activePeer` | string | WireKubePeer currently serving as active gateway |
| `ready` | bool | Gateway is healthy and forwarding traffic |
| `routesInjected` | int | Number of CIDR routes injected into the active peer |
| `peerHealth` | map[string]string | Per-peerRef health status (`healthy` or `unhealthy`) |
| `lastHealthCheck` | time | Timestamp of last health probe |
| `conditions` | []Condition | Standard Kubernetes conditions (Ready) |

### Print Columns

```
NAME             ACTIVE      READY   ROUTES   AGE
vpc-b-gateway    node-b1     true    1        5m
```

---

## WireKubeExternalPeer

| Property | Value |
|----------|-------|
| API Version | `wirekube.io/v1alpha1` |
| Kind | `WireKubeExternalPeer` |
| Scope | Cluster |
| Short Name | `wkep` |

WireKubeExternalPeer authorizes an off-cluster host that runs a standard WireGuard client. The external-peer reconciler is embedded in every agent Pod and uses leader election so only one agent performs allocation.

### Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `displayName` | string | Yes | Stable human-readable identity used by the deterministic mesh-IP allocator. |
| `publicKey` | string | Yes | External client's 44-character base64 WireGuard public key. |
| `ttl` | duration | No | Optional lifetime after which the CR is deleted. |
| `allowedDestinations` | []string | No | CIDRs rendered into the external client's AllowedIPs. Defaults are resolved by the reconciler. |
| `mtu` | int | No | Client MTU override; the effective default is `1248`. |
| `ingressPeer` | string | No | Pins the client to a specific WireKubePeer; otherwise the reconciler selects an ingress peer. |

### Status

| Field | Description |
|-------|-------------|
| `assignedMeshIP` | Allocated overlay `/32`. |
| `relayEndpoint` | Shared raw-WireGuard UDP endpoint rendered into the client configuration. |
| `ingressPeerName` | Selected in-cluster ingress peer. |
| `ingressPublicKey` | WireGuard public key authenticated by the external client. |
| `allowedDestinations` | Effective AllowedIPs rendered for the client. |
| `mtu` | Effective client MTU. |
| `phase` | `Pending`, `Active`, `Revoked`, or `Failed`. |
| `connected`, `lastHandshake` | Reserved health fields; the allocation reconciler does not currently populate them. |
