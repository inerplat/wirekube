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

## Step 2: Install RBAC

```bash
kubectl apply -f config/rbac/
```

## Step 3: Create a Mesh

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
    external:
      endpoint: "relay.example.com:3478"
      transport: tcp
```

```bash
kubectl apply -f config/operator/wirekubemesh-default.yaml
```

!!! note "Relay endpoint"
    Replace `relay.example.com:3478` with your actual relay server address.
    If all nodes have public IPs or are in the same VPC, you can set
    `relay.mode: never` to skip relay entirely.

## Step 4: Label Nodes

Only nodes with the `wirekube.io/vpn-enabled=true` label participate in the mesh:

```bash
kubectl label node node-1 wirekube.io/vpn-enabled=true
kubectl label node node-2 wirekube.io/vpn-enabled=true
```

## Step 5: Deploy the Agent

```bash
kubectl apply -f config/agent/daemonset.yaml
```

The agent DaemonSet runs on every labeled node with `hostNetwork: true`.

## Step 6: Verify

```bash
# Check peer status
kubectl get wirekubepeers -o wide

# On any node, verify WireGuard interface
wg show wire_kube

# Test connectivity
ping <other-node-ip>
```

## What Happens Next

1. Each agent creates a WireGuard interface and key pair
2. Agents register as WireKubePeer CRDs
3. STUN endpoint discovery runs to find public addresses
4. WireGuard handshakes establish between peers
5. If handshake times out (Symmetric NAT), relay fallback activates
6. Routes are added: `<node-ip>/32 dev wire_kube metric 200`

## Next Steps

- [Installation Guide](installation.md) — Detailed installation options
- [Configuration](configuration.md) — All configuration options explained
- [NAT Traversal](../architecture/nat-traversal.md) — How WireKube handles NAT
