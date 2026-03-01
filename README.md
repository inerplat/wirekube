# WireKube

Serverless P2P WireGuard mesh VPN between Kubernetes nodes.
Uses the Kubernetes API (CRD) as the coordination plane without a central VPN server.

```
node-1 (wg0: 10.100.0.1) ←──WireGuard──→ node-2 (wg0: 10.100.0.2)
         ↑                                          ↑
         └──────────────── node-3 ─────────────────┘
                      (wg0: 10.100.0.3)
```

## Features

- **Serverless** — No separate VPN server required; Kubernetes API handles coordination
- **CNI Compatible** — Works with existing CNIs (Cilium, AWS VPC CNI, etc.) unmodified; overlay approach (adds `wg0` interface)
- **NAT Traversal** — Supports home PCs and nodes behind firewalls (STUN → IPv6 → UPnP → Relay)
- **Partial Mesh** — Only some nodes participate in VPN; others connect via Gateway Pod
- **Multi-Cluster** — CLI-based peer exchange (`wirekubectl export/import`)

---

## Prerequisites

| Item | Minimum Version |
|------|-----------------|
| Kubernetes | 1.26+ |
| kubectl | Cluster access required |
| Linux kernel (nodes) | 5.6+ (WireGuard built-in) or wireguard-dkms |
| Architecture | amd64 / arm64 |

> **When using Cilium**: Cilium's built-in WireGuard (`--enable-wireguard=true`) must be disabled.
> Use only one of the two to avoid double encryption.

---

## Quick Start (Single Cluster)

### 1. Install CRD and RBAC

```bash
kubectl apply -f config/crd/
kubectl apply -f config/rbac/
```

Verify installed CRDs:

```bash
kubectl get crd | grep wirekube.io
# wirekubegateways.wirekube.io
# wirekubemeshes.wirekube.io
# wirekubepeers.wirekube.io
```

### 2. Deploy Operator

```bash
kubectl apply -f config/operator/deployment.yaml
kubectl -n wirekube-system rollout status deploy/wirekube-operator
```

### 3. Create WireKubeMesh

```bash
kubectl apply -f config/operator/wirekubemesh-default.yaml
```

Default settings (`meshCIDR: 10.100.0.0/24`, `mode: selective`):

```yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubeMesh
metadata:
  name: default
spec:
  meshCIDR: "10.100.0.0/24"   # One /32 per node
  mode: selective              # Only nodes with vpn-enabled label participate
  listenPort: 51820
  interfaceName: wg0
  mtu: 1420
  stunServers:
    - stun:stun.l.google.com:19302
    - stun:stun1.l.google.com:19302
    - stun:stun.cloudflare.com:3478
```

### 4. Label VPN-Participating Nodes

```bash
# Add label to desired nodes
kubectl label node <node-name> wirekube.io/vpn-enabled=true

# Example: label all worker nodes
kubectl get nodes -o name | grep worker | xargs -I{} kubectl label {} wirekube.io/vpn-enabled=true
```

### 5. Deploy Agent DaemonSet

```bash
kubectl apply -f config/agent/daemonset.yaml
kubectl -n wirekube-system rollout status ds/wirekube-agent
```

### 6. Verify Mesh Status

```bash
# Check peer list
kubectl get wirekubepeers
# NAME            NODEIP       MESHIP          ENDPOINT              CONNECTED
# node-worker-1   10.0.0.1     10.100.0.1/32   1.2.3.4:51820         true
# node-worker-2   10.0.0.2     10.100.0.2/32   5.6.7.8:51820         true

# Check WireGuard connection status (on node)
kubectl -n wirekube-system exec -it ds/wirekube-agent -- wg show

# Summary via CLI tool
./bin/wirekubectl peers
./bin/wirekubectl mesh status
```

---

## Scenario Guides

### Scenario 1: Partial Mesh (Only Some Nodes in VPN)

For pods on non-VPN nodes to communicate with the mesh, a Gateway Pod is required.

```
[VPN nodes] ←─ WireGuard tunnel ─→ [VPN nodes]
     ↑
  Gateway Pod (MASQUERADE)
     ↑
[Non-VPN node pods]
```

**1. Label VPN nodes** (see Quick Start above)

**2. Configure Gateway**:

```yaml
# config/gateway/gateway-deployment.yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubeGateway
metadata:
  name: default-gateway
spec:
  nodeName: worker-1          # VPN node to place Gateway Pod on
  masqueradeEnabled: true
  routedCIDRs:
    - 10.244.2.0/24           # Pod CIDR of non-VPN node
```

```bash
kubectl apply -f config/gateway/gateway-deployment.yaml

# Verify Gateway Pod
kubectl get wirekubegateways
kubectl -n wirekube-system get pods -l app=wirekube-gateway
```

---

### Scenario 2: Nodes Behind NAT / Home PC

Automatically discovers public endpoint via STUN and UPnP in NAT environments.

**Discovery order**:
1. `wirekube.io/endpoint` annotation (manual override)
2. Public IPv6 address
3. STUN (Google/Cloudflare STUN servers)
4. AWS EC2 IMDSv2/v1 (EIP lookup)
5. UPnP/NAT-PMP (router port forwarding)
6. Node ExternalIP → InternalIP

**Manual endpoint specification** (when auto-discovery fails or is inaccurate):

```bash
kubectl annotate node <node-name> wirekube.io/endpoint="<public-IP>:51820"
```

**NAT type behavior**:

| NAT Type | Behavior | Notes |
|----------|----------|-------|
| Full Cone | Auto-discovered via STUN | Ideal |
| Address Restricted | STUN + keepalive | PersistentKeepalive=25 set automatically |
| Port Restricted | Hole punching attempted | Other side must send packet first |
| Symmetric | Relay required | See relay configuration below |

**Relay configuration** (Symmetric NAT environments):

```yaml
# Add relay to WireKubeMesh
spec:
  relay:
    enabled: true
    endpoint: "relay.example.com:3478"   # Self-hosted relay server
```

---

### Scenario 3: Multi-Cluster

Connect nodes from different clusters (or AWS accounts) into a single mesh.
WireGuard establishes tunnels via public IP endpoints, so overlapping private IP ranges are not an issue.

**Requirement**: meshCIDR must not overlap between clusters.

```
cluster-1: meshCIDR 10.100.1.0/24   (clusterID: 1)
cluster-2: meshCIDR 10.100.2.0/24   (clusterID: 2)
```

**cluster-1 WireKubeMesh configuration**:

```yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubeMesh
metadata:
  name: default
spec:
  meshCIDR: "10.100.0.0/16"
  clusterMeshCIDR: "10.100.1.0/24"
  clusterID: 1
  mode: selective
```

**Peer exchange**:

```bash
# From cluster-1: export peer info
KUBECONFIG=~/.kube/cluster1 ./bin/wirekubectl export > cluster1-peers.yaml

# From cluster-2: import
KUBECONFIG=~/.kube/cluster2 ./bin/wirekubectl import cluster1-peers.yaml

# Perform reverse direction as well
KUBECONFIG=~/.kube/cluster2 ./bin/wirekubectl export > cluster2-peers.yaml
KUBECONFIG=~/.kube/cluster1 ./bin/wirekubectl import cluster2-peers.yaml
```

Imported peers receive the `remote=true` label, and each cluster's Agent automatically adds them as WireGuard peers.

---

## Traffic Flow (CNI Compatibility)

WireKube **does not modify Pod CIDR routes**. Instead, it routes node eth0 IPs via wg0.

```
Pod A (node-1) → Pod B (node-2):

1. Cilium DNAT: Service IP → Pod B IP (eBPF, eth0 TC hook works normally)
2. Routing: 10.244.1.0/24 via 10.0.0.2    ← Managed by Cilium (unchanged)
3. 10.0.0.2 lookup: dev wg0 (metric 200)  ← Inserted by WireKube (node eth0 IP)
4. WireGuard encrypt → node-2 decrypt → reach Pod B
```

**metric 200**: WireKube routes have higher metric than CNI routes (~100), so wg0 is preferred only for specific node IPs.

---

## Configuration Reference

### WireKubeMesh

```yaml
apiVersion: wirekube.io/v1alpha1
kind: WireKubeMesh
metadata:
  name: default
spec:
  meshCIDR: "10.100.0.0/24"        # Required: mesh IP pool (one /32 per node)
  mode: selective                   # selective | all
  listenPort: 51820                # WireGuard UDP port
  interfaceName: wg0               # Interface name
  mtu: 1420                        # WireGuard MTU (default 1420)
  stunServers:                     # STUN server list (NAT traversal)
    - stun:stun.l.google.com:19302
  # Multi-cluster
  clusterID: 1
  clusterMeshCIDR: "10.100.1.0/24"
  # Relay (for Symmetric NAT)
  relay:
    enabled: false
    endpoint: ""
```

### Node Annotations / Labels

```bash
# VPN participation (required in selective mode)
kubectl label node <node> wirekube.io/vpn-enabled=true

# Manual endpoint (takes precedence over NAT auto-discovery)
kubectl annotate node <node> wirekube.io/endpoint="1.2.3.4:51820"
```

### WireKubePeer Status

```bash
kubectl get wkpeer -o wide
kubectl describe wkpeer node-<node-name>
```

| Field | Description |
|-------|-------------|
| `spec.publicKey` | WireGuard public key (set automatically by Agent) |
| `spec.endpoint` | Public endpoint (`ip:port`) |
| `spec.meshIP` | Mesh VPN address (`10.100.0.x/32`) |
| `spec.nodeIP` | Node eth0 IP |
| `spec.allowedIPs` | `[meshIP/32, nodeIP/32]` |
| `status.connected` | Recent WireGuard handshake status |
| `status.lastHandshake` | Last handshake timestamp |

---

## Build (from Source)

```bash
# Dependencies
git clone https://github.com/wirekube/wirekube
cd wirekube

# Go 1.23+ required
go mod tidy
make build      # Creates operator, agent, gateway, wirekubectl in bin/

# Docker images
make docker-build VERSION=v0.1.0
make docker-push  VERSION=v0.1.0
```

---

## Removal

```bash
make undeploy
# Or
kubectl delete -f config/agent/    --ignore-not-found
kubectl delete -f config/operator/ --ignore-not-found
kubectl delete -f config/rbac/     --ignore-not-found
kubectl delete -f config/crd/      --ignore-not-found
```

> **Note**: Deleting CRDs will also remove all WireKubeMesh, WireKubePeer, and WireKubeGateway resources.

---

## Troubleshooting

### Peers Not Created

```bash
# Check Operator logs
kubectl -n wirekube-system logs deploy/wirekube-operator

# Check node labels (selective mode)
kubectl get nodes --show-labels | grep vpn-enabled

# Check WireKubeMesh status
kubectl describe wkmesh default
```

### WireGuard Not Connecting

```bash
# Check Agent logs
kubectl -n wirekube-system logs ds/wirekube-agent -c agent

# Check WireGuard status directly on node
kubectl -n wirekube-system exec -it ds/wirekube-agent -- wg show

# Check endpoint discovery method
kubectl get wkpeer node-<name> -o jsonpath='{.status.endpointDiscoveryMethod}'
```

### Node Behind NAT Not Connecting

```bash
# 1. Verify endpoint discovered via STUN
kubectl get wkpeer node-<name> -o jsonpath='{.spec.endpoint}'

# 2. If endpoint is wrong, specify manually
kubectl annotate node <name> wirekube.io/endpoint="<public-IP>:51820" --overwrite

# 3. Verify firewall allows UDP port 51820
```

### Conflict with Cilium

```bash
# Disable Cilium WireGuard if enabled
kubectl -n kube-system get cm cilium-config -o yaml | grep enable-wireguard

# Verify WireKube routes are inserted correctly (on node)
ip route show | grep wg0
# 10.0.0.x dev wg0 metric 200  ← Node IP via wg0, metric must be 200
```

---

## Architecture

```
Kubernetes API Server
        │ (CRD Watch)
  ┌─────┴──────┐
  │  Operator   │  ← WireKubeMesh/Peer management, IPAM (meshIP allocation)
  └─────┬──────┘
        │ (WireKubePeer CRD creation)
  ┌─────▼──────────────────────────────────┐
  │  WireKubePeer CRDs (one per node)      │
  │  publicKey, endpoint, meshIP, allowedIPs│
  └─────┬──────────────────────────────────┘
        │ (Watch)
  ┌─────▼──────┐     ┌────────────┐
  │  Agent      │     │  Agent     │  ← DaemonSet (vpn-enabled nodes)
  │ (node-1)   │◄────►(node-2)   │    Manages WireGuard via wgctrl
  │  wg0       │     │  wg0       │    Syncs peers every 30 seconds
  └─────┬──────┘     └────────────┘
        │
  Gateway Pod (optional) ← Connects non-VPN nodes to mesh
```

**Components**:

| Component | Role |
|-----------|------|
| `operator` | WireKubeMesh/Peer/Gateway reconciliation, IPAM |
| `agent` | Manages WireGuard interface (wg0) on each node, peer sync |
| `gateway` | Relays traffic between non-VPN nodes and mesh (iptables MASQUERADE) |
| `wirekubectl` | CLI: status queries, multi-cluster peer export/import |

---

## License

Apache 2.0
