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
| `addressAllocation` | string | No | `hash` | How a peer's `/32` is chosen: `hash` computes it from the peer name alone, `allocator` keeps the hash as the first choice and arbitrates conflicts through claims so a second claimant moves instead of advertising a duplicate. See [Mesh address allocation](#mesh-address-allocation). |
| `serviceCIDRs` | []string | No | - | Service ClusterIP range(s) advertised to external peers. When empty the controller discovers them from the cluster's `ServiceCIDR` objects (`networking.k8s.io`, tried newest group version first). Set this on clusters too old to serve that API, or to advertise a narrower range than the cluster allocates from. In-cluster peers do not use this: they reach ClusterIPs through their own node. |
| `autoAllowedIPs.includeNodeInternalIP` | bool | No | `false` | When `true`, the agent also appends the node's **private** address to `spec.allowedIPs` (resolved from `Node.status.addresses` first, then from local interfaces as a fallback). Public IPs are never auto-advertised — doing so would hijack SSH / apiserver routes on the next tunnel flap. Operators can override the picked address with the `wirekube.io/internal-ip` annotation on the Node. |
| `stunServers` | []string | No | - | STUN servers for public endpoint discovery. **Minimum 2 required** — the agent compares mapped ports across servers to detect Symmetric NAT (RFC 5780). |
| `routing.localSubnetPolicy` | string | No | `tunnel` | `tunnel` keeps same-segment traffic in the tunnel, encrypted. `bypass` drops the tunnel host route for a peer this node has confirmed is on its own segment, so that traffic takes the physical link unencrypted. The confirmation is two-sided: the address must resolve in this node's neighbour table to the same MAC the peer publishes in `status.linkAddresses` for the link it owns that address on. Containment in an attached prefix is never sufficient alone, so VPCs that reuse one private range keep their tunnel routes. The decision is recomputed every sync and follows the wiring. |
| `routing.excludeCIDRs` | []string | No | - | Destinations no agent may install into the WireKube table, regardless of reachability. Matching is by containment in route units; entries override gateway routes they fully contain, but can never suppress mesh overlay routes. Route installation only — inbound traffic admitted by AllowedIPs is unaffected. |

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
| `meshIP` | string | The `/32` this peer holds, in CIDR notation. It is a record, not a request: the agent reproduces it as `spec.allowedIPs[0]` instead of re-deriving the name hash, which is what lets an allocated address survive a restart. Empty means nothing was ever recorded and the hash is used. |
| `lastHandshake` | time | Timestamp of the last successful WireGuard handshake |
| `lastReportedAt` | time | When the peer's own agent last wrote this status. Failover treats a peer that has not reported for 90 seconds as down. |
| `sharedExternalIngress` | bool | The agent can serve external peers under the shared ingress identity; only such peers are given roaming external peers. |
| `gatewayElection` | bool | The agent follows the gateway election controller. The controller takes over a gateway once every live peer in its `peerRefs` reports this. |
| `gatewayProbes` | []object | This node's `healthCheck` result per gateway it is a peerRef of: `gateway`, `healthy`, `consecutiveFailures`, `checkedAt`, `message`. |

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

### Mesh address allocation

A peer's overlay `/32` is an FNV-1a hash of its name reduced into `meshCIDR`.
That needs no coordination — every agent computes the same answer — but it is
not injective: two names can land on the same address, and both peers then
advertise it. Widening `meshCIDR` moves the birthday bound, it does not remove
the case. For a `/24` the bound is around 16 names; for a `/10`, around 2048.

`spec.addressAllocation` selects what happens then.

| Value | Behaviour |
|-------|-----------|
| `hash` (default) | The hash is the address. A collision is not detected, and both peers advertise the same `/32`. |
| `allocator` | The hash is the first choice. Claiming it is a `Lease` create named after the address, so the API server arbitrates: exactly one peer wins, and the loser walks to its next candidate. |

Under `allocator`:

Turning it on renumbers nobody: the first candidate is the hashed address, and
a peer's existing `status.meshIP` is preferred over it. Allocation is sticky,
because a peer adopts the claim it already holds before anything is written, so
a restart cannot drift it onto an address that has since been freed.

Retries are bounded. After 32 probes the claims are listed once and the search
becomes exact, which keeps the last free address in a `/24` holding 253 claims
under 70 API calls instead of 253.

When every address is claimed, an agent's enrolment fails and an external peer
goes `Pending` with `MeshAddressesExhausted` and keeps retrying, since the
sweep frees addresses as peers go away. Neither recovers on its own if the
fleet is simply larger than the CIDR, so widen `meshCIDR`.

The winning candidate index is recorded in the `wirekube.io/attempt` annotation
on the claim. A fleet where that is routinely non-zero is running close enough
to full that the CIDR wants widening.

Claims are `Lease` objects in the namespace WireKube runs in, labelled
`wirekube.io/claim=address`:

```console
$ kubectl -n wirekube-system get leases -l wirekube.io/claim=address
NAME                             HOLDER    AGE
wirekube-default-198-18-18-74    master    31d
wirekube-default-198-18-18-83    worker1   31d
```

The namespace is where the agent runs; `wirekube-system` is only the default.

Claims carry no `ownerReference` on purpose: an enrolment tool claims an
address *before* the node that will advertise it exists, and garbage collection
would delete a claim whose owner is not there yet. A leader-elected sweep
collects them instead, once no peer has answered for the holder for 15 minutes
(or for `spec.leaseDurationSeconds`, if the claim sets one), or at once if
`meshCIDR` has moved out from under the address.

Going back to `hash` is safe and is not a rollback of the addresses: peers keep
what they were allocated, because the agent still honours `status.meshIP` over
the name hash. The claims are then no longer consulted, and the sweep collects
each one as its holder goes away.

#### Turning it on

The switch must not be flipped until every agent in the fleet honours
`WireKubePeer.status.meshIP`. An older agent recomputes the hash on every
upsert and would drag an allocated peer back onto the contested address.

```bash
kubectl get wirekubepeers -o custom-columns=NAME:.metadata.name,MESHIP:.status.meshIP
# every row populated → the rollout has converged
kubectl patch wirekubemesh default --type=merge -p '{"spec":{"addressAllocation":"allocator"}}'
```

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
| `peerRefs` | []string | Yes | WireKubePeer names serving as gateway, most preferred first. The gateway stays on an eligible active peer, fails over to the first eligible peer, and returns to a more preferred one after it has been eligible for 2 minutes (see [High Availability](../architecture/gateway.md#high-availability)). Min 1. |
| `clientRefs` | []string | No | WireKubePeer names that should route through this gateway. If empty, all mesh peers (except gateway peers and same-CIDR peers) are clients. |
| `routes` | []GatewayRoute | Yes | CIDR ranges reachable through the gateway. Injected into active peer's AllowedIPs. Min 1. |
| `snat` | GatewaySNAT | No | Source NAT configuration for return traffic routing. |
| `healthCheck` | GatewayHealthCheck | No | Target probe every peer in `peerRefs` runs; a peer failing it is not eligible. |

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
| `intervalSeconds` | int | No | `30` | Probe interval (min 5). Probes run at most once per agent sync. |
| `timeoutSeconds` | int | No | `5` | Probe timeout (min 1) |
| `failureThreshold` | int | No | `3` | Consecutive failures before marking unhealthy (min 1) |

#### `status`

| Field | Type | Description |
|-------|------|-------------|
| `activePeer` | string | WireKubePeer currently serving as active gateway. Written by the election controller; agents follow it. |
| `ready` | bool | Gateway is healthy and forwarding traffic |
| `routesInjected` | int | Number of CIDR routes injected into the active peer |
| `peerHealth` | map[string]string | Per-peerRef eligibility (`healthy` or `unhealthy`) |
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
| `allowedDestinations` | []string | No | CIDRs rendered into the external client's AllowedIPs. **Replaces** the defaults rather than adding to them, so an explicit list must name every range the peer needs. Leave empty to let the reconciler resolve them. |
| `mtu` | int | No | Client MTU override; the effective default is `1248`. |
| `ingressPeer` | string | No | Preferred ingress WireKubePeer. A peer issued under the shared ingress identity uses it while it is healthy and fails over while it is not (see [Ingress failover](#ingress-failover)); a peer issued under a node key is pinned to it. Otherwise the reconciler selects an ingress peer. |

### Status

| Field | Description |
|-------|-------------|
| `assignedMeshIP` | Allocated overlay `/32`. |
| `relayEndpoint` | Shared raw-WireGuard UDP endpoint rendered into the client configuration. |
| `ingressPeerName` | In-cluster ingress peer currently serving the client. Changes on failover for peers issued under the shared ingress identity. |
| `ingressPublicKey` | Server public key in the client configuration: the shared ingress identity, or for peers issued before it existed, the ingress node's own key. |
| `allowedDestinations` | Effective AllowedIPs rendered for the client. When `spec.allowedDestinations` is empty this is the mesh CIDR, every Node pod CIDR, the Service ClusterIP range(s) and every `WireKubeGateway` route, sorted. |
| `mtu` | Effective client MTU. |
| `phase` | `Pending`, `Active`, `Revoked`, or `Failed`. |
| `connected`, `lastHandshake` | Reserved health fields; the allocation reconciler does not currently populate them. |

### Ingress failover

Every external peer enters the cluster through one ingress node, which holds
the peer's WireGuard session. The client configuration names the server key it
expects, so which key that is decides whether the peer can move:

- **Shared ingress identity (default).** The controller keeps one WireGuard
  identity for external peers in the Secret `wirekube-external-ingress` in the
  WireKube namespace, creating it on first use, and every agent serves its
  external peers under that identity on a second in-process WireGuard device.
  Every peer issued since the identity exists carries it as its server key, so
  any node can serve it and the client configuration never changes:
  - The controller re-checks a peer's ingress every 30 seconds. When the node
    stops reporting for 90 seconds, or the relay can no longer reach it, the
    peer moves to the best healthy node.
  - With `spec.ingressPeer` set, the peer returns to that node once it has been
    healthy for 2 minutes. Without it, the peer stays where it moved.
  - If every node goes quiet at once, which points at status writes failing
    rather than every node dying, peers stay where they are and do not fail
    back to a node that was already down.
  - The client notices nothing beyond a re-handshake: the relay sends every
    WireGuard handshake initiation to all agents, and only the node now holding
    the peer answers.
  - Only nodes whose agent reports `status.sharedExternalIngress` on its
    WireKubePeer are eligible, so during a rolling upgrade peers are never
    handed to an agent that cannot serve the shared identity.
  - The key a peer was issued under is recorded in its
    `wirekube.io/issued-ingress-key` annotation. An older controller leading
    mid-upgrade may write a node key into `status.ingressPublicKey`; the
    annotation keeps the peer roaming, and the next reconcile restores status.
- **Node key (peers issued before the shared identity).** The configuration
  names that node's own key, which no other node holds, so the peer stays on
  that node. Re-issue it (`wirekubectl external invite`, or a new
  `wirekubectl connect` session) to move it to the shared identity.

Trade-offs of the shared identity:

- Every agent holds its private key, so an attacker with one node can
  impersonate the ingress to every external client, not only that node's own.
  Traffic between nodes is unaffected.
- Deleting the Secret rotates the identity. That cuts off every peer issued
  under the old one until it is re-issued. Those peers go `Pending` with reason
  `IngressIdentityRetired` rather than being given a key their client does
  not have.
- A relay started with `--external-wg-ingress-pubkey`, which sends all external
  traffic to one fixed node, cannot fail over. Leave it unset.

### Annotations

| Annotation | Description |
|------------|-------------|
| `wirekube.io/heartbeat` | Opts the peer into liveness tracking. A client holding a session open rewrites it with any new value while it runs; when the value has not changed for 5 minutes, timed on the controller's clock, the controller deletes the peer. Peers without it never expire this way. `wirekubectl connect` sets it. |
