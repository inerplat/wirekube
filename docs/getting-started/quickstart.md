# Quick Start

Get WireKube running on your Kubernetes cluster in 5 minutes.

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Kubernetes | 1.26+ |
| Linux Kernel | 5.6+ (built-in WireGuard) |
| `kubectl` access | Cluster admin |

## Step 1: Install CRDs

```bash
kubectl apply -f config/crd/
```

This creates two Custom Resource Definitions:

- **WireKubeMesh** — Global mesh configuration (listen port, STUN servers, relay settings)
- **WireKubePeer** — Per-node peer state (auto-managed by the agent)

## Step 2: Create a Mesh

```bash
kubectl apply -f config/examples/wirekubemesh-basic.yaml
```

Or create a custom mesh configuration:

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
    managed:
      replicas: 1
      serviceType: LoadBalancer
      port: 3478
```

!!! note "STUN Servers"
    At least two STUN servers are required. The agent compares mapped ports
    from multiple servers to detect Symmetric NAT (RFC 5780).

!!! note "Relay"
    If all nodes have public IPs or are in the same VPC, set `relay.mode: never`.
    For cross-VPC or multi-cloud deployments, `auto` with a managed or external
    relay is recommended.

## Step 3: Deploy the Agent

```bash
kubectl apply -f config/agent/daemonset.yaml
```

The agent DaemonSet runs on every labeled node with `hostNetwork: true` and
`dnsPolicy: ClusterFirstWithHostNet` (required for in-cluster DNS resolution).

## Step 4: Label Nodes

Only nodes with the `wirekube.io/vpn-enabled=true` label participate in the mesh:

```bash
kubectl label node <node-name> wirekube.io/vpn-enabled=true
```

## Step 5: (Optional) Deploy the Relay

For managed relay (in-cluster):

```bash
kubectl apply -f config/relay/deployment.yaml
```

For external relay on a public server:

```bash
wirekube-relay --addr :3478
```

See [Relay Architecture](../architecture/relay.md) for details on relay modes and scaling.

## Step 6: Set AllowedIPs

AllowedIPs are intentionally user-managed. Set each peer's node IP to enable routing:

```bash
kubectl patch wirekubepeer <peer-name> --type=merge \
  -p '{"spec":{"allowedIPs":["<node-ip>/32"]}}'
```

Without `allowedIPs`, the agent enters passive mode — no routes are added and
no WireGuard traffic flows for that peer.

## Step 7: Verify

```bash
kubectl get wirekubepeers -o wide
kubectl get wirekubemesh default -o yaml

# On any node
wg show wire_kube
ping <other-node-ip>
```

## What Happens

1. Each agent creates a WireGuard interface (`wire_kube`) and generates a key pair
2. The agent registers itself as a `WireKubePeer` CRD
3. STUN queries two servers to discover the public endpoint and detect NAT type
4. If mapped ports differ between STUN servers → Symmetric NAT detected
5. WireGuard handshakes are attempted with all discovered peers
6. If handshake times out (or Symmetric NAT detected), relay fallback activates
7. Routes are added: `<node-ip>/32 dev wire_kube metric 200`
8. Periodically, the agent re-probes relayed peers for direct connectivity upgrade

## Next Steps

- [Installation Guide](installation.md) — Detailed installation and build options
- [Configuration](configuration.md) — All configuration fields explained
- [NAT Traversal](../architecture/nat-traversal.md) — How WireKube handles NAT
- [Relay Design](../architecture/relay.md) — Protocol, failover, and scaling
