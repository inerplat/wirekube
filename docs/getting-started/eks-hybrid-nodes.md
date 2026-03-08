# EKS Hybrid Nodes with WireKube

This guide covers deploying WireKube on an Amazon EKS cluster with
[Hybrid Nodes](https://docs.aws.amazon.com/eks/latest/userguide/hybrid-nodes-overview.html) —
external worker nodes (on-premises or other clouds) managed by an EKS control plane.

WireKube establishes a WireGuard mesh VPN across all nodes, enabling:

- **Encrypted node-to-node connectivity** over WireGuard tunnels
- **Cross-node pod networking** via Cilium VXLAN over WireGuard
- **kubectl exec/logs/port-forward** on hybrid nodes (via Virtual Gateway)
- **Automatic NAT traversal** with STUN + relay fallback

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│ AWS VPC                                                  │
│                                                          │
│  EKS Control Plane                                       │
│  ┌────────────┐                                          │
│  │ API Server  │──► ENI ──► VPC route ──► EC2 Node ──►   │
│  └────────────┘              (gateway)    WireGuard      │
│                                              │           │
│  ┌────────────────────────────────────────────┤          │
│  │ EC2 Managed Node                          │          │
│  │  • VPC CNI (aws-node)                     │          │
│  │  • wirekube-agent (VGW gateway peer)      │          │
│  │  • wirekube-relay (TCP relay server)      │          │
│  │  • IP forwarding + SNAT                   │          │
│  │  • Source/Dest Check: DISABLED            │          │
│  └────────────┬──────────────────────────────┘          │
│               │ LoadBalancer :3478                       │
└───────────────┼─────────────────────────────────────────┘
                │ Internet
  ┌─────────────┼──────────────────────────────────────┐
  │ On-Premises / External Cloud                       │
  │             │                                      │
  │  ┌──────────┴──────┐  ┌──────────────┐             │
  │  │ Hybrid Node A   │  │ Hybrid Node B│  ...        │
  │  │ • Cilium CNI    │  │ • Cilium CNI │             │
  │  │ • wirekube-agent│  │ • agent      │             │
  │  └─────────────────┘  └──────────────┘             │
  └────────────────────────────────────────────────────┘
```

### Four Network Planes

| Plane | Technology | Scope |
|-------|-----------|-------|
| Node-to-node | WireGuard (`wire_kube`) | All nodes ↔ All nodes |
| Pod-to-pod (hybrid ↔ hybrid) | Cilium VXLAN over WireGuard | Hybrid nodes only |
| Pod-to-pod (EC2 ↔ hybrid) | VPC CNI SNAT + WireGuard AllowedIPs | EC2 ↔ Hybrid |
| Control plane ↔ kubelet | VGW Gateway (WireKubeGateway) | kube-apiserver → Hybrid |

### Connection Strategy

1. **Direct P2P** — STUN discovers NAT-mapped endpoints; nodes connect
   directly when NAT allows it (Cone ↔ Cone, Cone ↔ Symmetric)
2. **Relay fallback** — After 30s handshake timeout, traffic flows through
   the TCP relay (WireGuard encryption preserved end-to-end)
3. **Birthday attack** — Optional port-prediction for Symmetric ↔ Symmetric
   NAT pairs behind CGNAT
4. **VGW gateway** — EC2 forwards VPC traffic to hybrid nodes through
   WireGuard, enabling kube-apiserver ↔ kubelet and EC2 ↔ hybrid pod routing

---

## Network Design

### CIDR Planning

Careful CIDR allocation prevents routing conflicts:

| Network | CIDR | Purpose |
|---------|------|---------|
| AWS VPC | `10.100.0.0/16` | EC2 nodes and VPC CNI pods |
| EKS Service | `172.16.0.0/16` | Kubernetes service ClusterIPs |
| Hybrid node subnet A | `172.20.0.0/16` | On-prem/external cloud network A |
| Hybrid node subnet B | `10.20.0.0/16` | On-prem/external cloud network B |
| Cilium Pod CIDR | `10.200.0.0/16` | Pods on hybrid nodes (RFC 1918) |

!!! critical "Cilium Pod CIDR must NOT overlap with VPC CIDR or cloud internal ranges"
    By default, Cilium's `cluster-pool` IPAM may use the same CIDR as the VPC
    (e.g., `10.100.0.0/16`). This causes routing conflicts — WireGuard routes
    for hybrid pod CIDRs would capture VPC-local traffic. Use a completely
    separate RFC 1918 range like `10.200.0.0/16`. Avoid CGNAT (100.64.0.0/10)
    as some cloud providers use it internally. EKS requires `remotePodNetworks`
    CIDRs to be RFC 1918 or CGNAT.

### Pod Networking Data Flow

#### Hybrid ↔ Hybrid Pods (Cilium VXLAN over WireGuard)

No additional WireKube configuration required. Cilium handles pod routing
natively through VXLAN tunneling, using node IPs as tunnel endpoints. Since
WireGuard routes node IPs, the VXLAN packets are automatically encrypted
and tunneled:

```
Pod A (198.18.0.149)
  → Cilium BPF (veth)
  → VXLAN encap (outer: nodeA:8472 → nodeB:8472)
  → kernel routing table 22347
  → wire_kube (WireGuard encrypts)
  → relay or direct
  → remote wire_kube (WireGuard decrypts)
  → VXLAN decap
  → Cilium BPF → Pod B (198.18.1.17)
```

#### EC2 → Hybrid Pods (WireGuard AllowedIPs)

Each hybrid node's WireKubePeer must include its Cilium pod CIDR in
`AllowedIPs`. The EC2 node then routes pod traffic through WireGuard to
the correct hybrid node:

```
EC2 Pod (10.100.0.200)
  → VPC CNI SNAT (src → 10.100.0.187)
  → kernel routing table 22347 (198.18.0.0/25 → wire_kube)
  → WireGuard → hybrid node
  → Cilium decap → Hybrid Pod (198.18.0.50)
```

VPC CNI automatically SNATs outbound traffic to non-VPC destinations
(`AWS_VPC_K8S_CNI_EXTERNALSNAT=false` by default). This ensures the
hybrid node sees the EC2 node IP as the source, which it can route back
through WireGuard.

#### Hybrid → EC2 Pods (WireKubeGateway routes)

Add the VPC subnets to the WireKubeGateway routes. Hybrid nodes route
VPC-destined traffic through WireGuard to the EC2 gateway peer:

```
Hybrid Pod (198.18.0.50)
  → Cilium BPF (masquerade: src → nodeIP)
  → kernel routing table 22347 (10.100.0.0/24 → wire_kube)
  → WireGuard → EC2 node
  → VPC forwarding → EC2 Pod (10.100.0.200)
```

---

## Prerequisites

### AWS

- EKS cluster with Hybrid Nodes feature enabled
- At least one managed EC2 nodegroup (hosts relay + gateway)
- VPC with subnets and internet gateway
- IAM Roles Anywhere or SSM hybrid activations configured

### Hybrid Nodes

- Linux servers joined to the EKS cluster via `nodeadm`
- Outbound internet access (STUN servers and relay LB)
- UDP port 51822 (WireGuard) — open for direct P2P if possible
- TCP port 3478 outbound (relay connection)
- WireGuard kernel module loaded

### Tools

- `kubectl` configured for the EKS cluster
- `helm` v3 (for Cilium)
- `aws` CLI (for VPC route and EC2 configuration)

---

## Step 1: Install CRDs

```bash
kubectl apply -f config/crd/
```

This installs three CRDs:

- **WireKubeMesh** — cluster-wide mesh configuration
- **WireKubePeer** — per-node state (auto-created by agent)
- **WireKubeGateway** — virtual gateway for cross-network routing

---

## Step 2: Install Cilium on Hybrid Nodes

Hybrid nodes require a CNI. AWS recommends Cilium for EKS Hybrid Nodes.

### Install from AWS Public ECR

```bash
helm upgrade --install cilium \
  oci://public.ecr.aws/eks/cilium/cilium \
  --version <VERSION> \
  --namespace kube-system \
  -f config/examples/eks-hybrid/cilium-values.yaml
```

Before installing, update `cilium-values.yaml`:

- Set `k8sServiceHost` to your EKS API endpoint
- Set `ipam.operator.clusterPoolIPv4PodCIDRList` to a non-overlapping CIDR

### Exclude kube-proxy from Hybrid Nodes

Cilium runs with `kubeProxyReplacement: true`, so exclude `kube-proxy`
from hybrid nodes:

```bash
kubectl patch ds kube-proxy -n kube-system --type merge -p '{
  "spec":{"template":{"spec":{"affinity":{"nodeAffinity":{
    "requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{
      "matchExpressions":[{
        "key":"eks.amazonaws.com/compute-type",
        "operator":"NotIn",
        "values":["hybrid"]
      }]
    }]}
  }}}}}}'
```

### Critical Cilium Settings

| Setting | Value | Reason |
|---------|-------|--------|
| `kubeProxyReplacement` | `"true"` | Replace kube-proxy with BPF service routing |
| `socketLB.enabled` | `true` | Safe to enable — agent auto-falls back to connected sockets on EPERM |
| `k8sServiceHost` | EKS API endpoint | Hybrid nodes cannot reach ClusterIP before CNI init |
| `ipam.operator.clusterPoolIPv4PodCIDRList` | `10.200.0.0/16` | RFC 1918 — must NOT overlap with VPC CIDR or cloud internal ranges |
| `affinity` | `eks.amazonaws.com/compute-type: hybrid` | Only schedule Cilium on hybrid nodes |

!!! note "socketLB and WireKube compatibility"
    Cilium's socket-level LB attaches BPF `sendmsg` hooks to the root
    cgroup, which can intercept `sendto(2)` syscalls from `hostNetwork`
    pods. In some Cilium versions this caused `EPERM` errors for the
    WireKube relay proxy's loopback UDP traffic. The agent handles this
    automatically by falling back to connected sockets (`write(2)` syscall),
    which bypasses the BPF hook. The fallback is transparent with at most
    one recoverable packet drop per peer. See
    [CNI Compatibility](../architecture/cni-compatibility.md) for details.

---

## Step 3: Deploy WireKube

### Namespace and RBAC

```bash
kubectl apply -f config/examples/eks-hybrid/namespace.yaml
kubectl apply -f config/examples/eks-hybrid/rbac.yaml
```

### Relay Server

```bash
kubectl apply -f config/examples/eks-hybrid/relay.yaml
```

The relay deploys on the EC2 managed nodegroup and is exposed via LoadBalancer.
Wait for the external endpoint:

```bash
kubectl get svc wirekube-relay -n wirekube-system -w
```

### Agent DaemonSet

Update `KUBERNETES_SERVICE_HOST` with your EKS API endpoint, then deploy:

```bash
EKS_ENDPOINT=$(aws eks describe-cluster --name <CLUSTER> \
  --query 'cluster.endpoint' --output text | sed 's|https://||')

echo "Set KUBERNETES_SERVICE_HOST to: ${EKS_ENDPOINT}"
kubectl apply -f config/examples/eks-hybrid/daemonset.yaml
```

!!! note "Why KUBERNETES_SERVICE_HOST?"
    Hybrid nodes cannot reach the Kubernetes service ClusterIP before CNI
    is ready. The agent needs API access at startup to create its
    WireKubePeer CRD. The EKS public endpoint bypasses this dependency.

### WireKubeMesh

```bash
RELAY_EP=$(kubectl get svc wirekube-relay -n wirekube-system \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'):3478

sed "s|REPLACE_WITH_RELAY_LB:3478|${RELAY_EP}|" \
  config/examples/eks-hybrid/wirekubemesh.yaml | kubectl apply -f -
```

### Verify Node Connectivity

```bash
kubectl get wirekubepeers \
  -o custom-columns='NAME:.metadata.name,CONNECTED:.status.connected,NAT:.status.natType'
```

All peers should show `CONNECTED=true`.

---

## Step 4: Enable VGW Gateway

EKS has no built-in Konnectivity service. The kube-apiserver reaches kubelet
via VPC ENIs, but hybrid nodes are outside the VPC. Without routing,
`kubectl exec`, `kubectl logs`, and `kubectl port-forward` fail on hybrid nodes.

The WireKubeGateway makes the EC2 node forward VPC traffic to hybrid nodes
through the WireGuard tunnel.

### AWS Setup

#### 1. Disable Source/Dest Check

```bash
EC2_INSTANCE_ID=<your-ec2-instance-id>

ENI_IDS=$(aws ec2 describe-network-interfaces \
  --filters "Name=attachment.instance-id,Values=${EC2_INSTANCE_ID}" \
  --query 'NetworkInterfaces[].NetworkInterfaceId' --output text)

for eni in $ENI_IDS; do
  aws ec2 modify-network-interface-attribute \
    --network-interface-id "$eni" --no-source-dest-check
done
```

#### 2. Add VPC Route Table Entries

Route hybrid node CIDRs to the EC2 instance's primary ENI in every route
table associated with VPC subnets:

```bash
EC2_ENI=<ec2-primary-eni-id>

VPC_ID=$(aws ec2 describe-instances --instance-ids ${EC2_INSTANCE_ID} \
  --query 'Reservations[0].Instances[0].VpcId' --output text)

RTB_IDS=$(aws ec2 describe-route-tables \
  --filters "Name=vpc-id,Values=${VPC_ID}" \
  --query 'RouteTables[].RouteTableId' --output text)

for rtb in $RTB_IDS; do
  for cidr in "<HYBRID_CIDR_A>" "<HYBRID_CIDR_B>"; do
    aws ec2 create-route --route-table-id "$rtb" \
      --destination-cidr-block "$cidr" \
      --network-interface-id "$EC2_ENI" 2>/dev/null \
    || aws ec2 replace-route --route-table-id "$rtb" \
      --destination-cidr-block "$cidr" \
      --network-interface-id "$EC2_ENI"
  done
done
```

### Deploy WireKubeGateway

Edit `config/examples/eks-hybrid/gateway.yaml` with your node name and CIDRs,
then apply:

```bash
kubectl apply -f config/examples/eks-hybrid/gateway.yaml
```

### Verify

```bash
kubectl get wirekubegateway hybrid-gateway -o jsonpath='{.status}'
kubectl exec <pod-on-hybrid-node> -- hostname
kubectl logs <pod-on-hybrid-node> --tail=5
```

---

## Step 5: Enable Cross-Cloud Pod Networking

After Steps 1–4, node-to-node connectivity and `kubectl exec/logs` work.
To enable full pod-to-pod communication across EC2 and hybrid nodes:

### 5a. Hybrid ↔ Hybrid Pods

This works automatically. Cilium's VXLAN tunneling uses node IPs as
endpoints, which are routed through WireGuard. No additional configuration
is needed — verify with:

```bash
kubectl exec <pod-on-hybrid-A> -- wget -qO- http://<pod-IP-on-hybrid-B>
```

### 5b. EC2 → Hybrid Pods

Add each hybrid node's Cilium pod CIDR to its WireKubePeer AllowedIPs:

```bash
# Get Cilium pod CIDRs
kubectl get ciliumnodes -o custom-columns='NAME:.metadata.name,POD_CIDR:.spec.ipam.podCIDRs'

# Patch each hybrid peer
kubectl patch wirekubepeer <hybrid-node-A> --type=json \
  -p='[{"op":"add","path":"/spec/allowedIPs/-","value":"<CILIUM_POD_CIDR_A>"}]'
kubectl patch wirekubepeer <hybrid-node-B> --type=json \
  -p='[{"op":"add","path":"/spec/allowedIPs/-","value":"<CILIUM_POD_CIDR_B>"}]'
```

This creates WireGuard routes on the EC2 node so pod traffic for each
hybrid pod CIDR is sent through the correct WireGuard tunnel. VPC CNI
automatically SNATs the source to the EC2 node IP.

### 5c. Hybrid → EC2 Pods

Add the VPC subnets to the WireKubeGateway routes:

```bash
kubectl patch wirekubegateway hybrid-gateway --type=json -p='[
  {"op":"add","path":"/spec/routes/-","value":{"cidr":"<VPC_SUBNET_A>","description":"VPC subnet A"}},
  {"op":"add","path":"/spec/routes/-","value":{"cidr":"<VPC_SUBNET_B>","description":"VPC subnet B"}}
]'
```

The gateway injects these CIDRs into the EC2 peer's AllowedIPs. Hybrid
nodes then route VPC-destined pod traffic through WireGuard to the EC2
node, which forwards it locally via VPC networking.

### Verify Full Pod Connectivity

```bash
# EC2 pod → hybrid pod
kubectl exec <ec2-pod> -- wget -qO- --timeout=5 http://<hybrid-pod-IP>

# Hybrid pod → EC2 pod
kubectl exec <hybrid-pod> -- wget -qO- --timeout=5 http://<ec2-pod-IP>

# Hybrid pod → hybrid pod (different node)
kubectl exec <hybrid-pod-A> -- wget -qO- --timeout=5 http://<hybrid-pod-B-IP>
```

---

## Routing Table Reference

### IP Rules (on hybrid nodes)

| Priority | Rule | Purpose |
|----------|------|---------|
| 9 | `fwmark 0x200/0xf00 → table 2004` | Cilium BPF socket redirect |
| 100 | `lookup local` | Loopback / local addresses |
| 100 | `fwmark 0x574b → lookup main` | WireGuard socket bypass (prevents route loop) |
| 200 | `lookup 22347` | WireGuard mesh routes |
| 32766 | `lookup main` | Default kernel routes |

### WireGuard Routing Table (22347)

| Route | Example | Source |
|-------|---------|--------|
| Remote node `/32` | `172.20.1.6 dev wire_kube` | `autoAllowedIPs: node-internal-ip` |
| Pod CIDR `/25` | `198.18.0.0/25 dev wire_kube` | Manual AllowedIPs patch |
| Gateway CIDR | `10.100.0.0/24 dev wire_kube` | WireKubeGateway routes |

### fwmark Design

WireGuard's kernel module marks its own encrypted UDP packets with
`fwmark 0x574b`. The ip rule at priority 100 sends these to the main
routing table, preventing them from re-entering the `wire_kube` interface
(which would create an infinite encryption loop).

---

## Troubleshooting

### Recommended Initial Setup Sequence

When deploying on freshly joined hybrid nodes, follow this exact order:

1. **Install Cilium** with `kubeProxyReplacement: true`
2. **Exclude kube-proxy** from hybrid nodes (nodeAffinity patch)
3. **⚠️ Reboot all hybrid nodes** (mandatory — see below)
4. **Deploy WireKube** (CRDs, RBAC, relay, agent, mesh)
5. If peers remain `connected: false`, delete WireKubePeer and restart agent

> **Important:** Hybrid nodes MUST be rebooted once after the initial Cilium
> installation and before deploying WireKube. Nodes that are freshly
> provisioned and join the cluster for the first time do NOT need a reboot.
> The reboot is only required when Cilium and kube-proxy state was established
> before WireKube's first deployment.

**Why reboot?** Three types of stale kernel state interfere with WireKube:

- **`KUBE-FIREWALL` iptables chain** — Created by kube-proxy before exclusion.
  Contains a DROP rule for non-local source packets to loopback
  (`!127.0.0.0/8 → 127.0.0.0/8`). This blocks WireGuard's relay proxy
  traffic even after kube-proxy pods are removed, because iptables rules
  persist in the kernel until flushed or rebooted.
- **Stale conntrack entries** — kube-proxy creates conntrack state for service
  routing. These entries survive pod removal and may cause connection tracking
  conflicts with new WireGuard/relay connections.
- **Cilium BPF `sendmsg` hook** — The EKS Cilium build attaches
  `cil_sock4_sendmsg` to the root cgroup. When the WireKube agent pod starts
  on a node where Cilium's BPF endpoint state is stale (from a previous
  agent pod), UDP sockets created during the registration gap receive
  persistent `EPERM` errors on `sendto()`. A reboot clears all BPF maps and
  cgroup attachments, allowing clean endpoint registration.

A reboot cleanly resets all three: iptables chains are rebuilt from scratch,
conntrack is emptied, and BPF programs are detached.

**After the initial reboot, subsequent agent updates (DaemonSet rolling
updates) work without rebooting** — the agent handles transient EPERM by
recreating the affected UDP socket after the BPF state settles.

### EPERM on relay proxy

**Symptom:** `relay-proxy: EPERM on port 51822, scheduling socket recreation`

**Cause:** Cilium's BPF `sendmsg` hook returns `EPERM` on `sendto(2)` when
the agent pod's UDP socket was created before Cilium finished BPF endpoint
registration. This typically happens on the first WireKube deployment before
the required reboot (see setup sequence above).

**Action:** The agent automatically detects EPERM and recreates the UDP socket
after a 3-second delay, binding to the same port. If EPERM persists after
recreation (indicating the node needs a reboot), reboot the hybrid node to
clear all BPF state.

### Cilium VXLAN pod-to-pod fails between hybrid nodes

**Symptom:** Pods on different hybrid nodes cannot reach each other.

**Diagnosis:**

```bash
# Check Cilium health (should show all nodes reachable)
kubectl exec -n kube-system <cilium-pod> -- cilium-health status

# Check WireGuard handshakes
kubectl exec -n wirekube-system <agent-pod> -- wg show wire_kube
```

**Possible causes:**

1. **WireGuard handshake not complete** — Cilium VXLAN requires working
   WireGuard tunnels as underlay. Restart the agent or delete/recreate the peer.
2. **CIDR overlap** — If Cilium cluster-pool overlaps with VPC CIDR, routing
   conflicts prevent VXLAN packets from reaching WireGuard. Change
   `clusterPoolIPv4PodCIDRList` to a non-overlapping range and restart Cilium.
3. **Stale CiliumNode** — After changing the cluster-pool CIDR, delete all
   CiliumNode resources and restart Cilium DaemonSet:
   ```bash
   kubectl delete ciliumnodes --all
   kubectl rollout restart ds/cilium -n kube-system
   ```

### kubectl exec/logs timeout on hybrid nodes

**Symptom:** `dial tcp <hybrid-IP>:10250: i/o timeout`

**Fix:** Deploy the WireKubeGateway (Step 4). Verify:

1. EC2 Source/Dest Check is disabled
2. VPC route tables have entries for hybrid CIDRs → EC2 ENI
3. `kubectl get wirekubegateway` shows `ready: true`
4. EC2 agent logs show `[gateway] MASQUERADE added`

### EC2 → hybrid pod traffic dropped

**Symptom:** EC2 pods cannot reach hybrid pods by IP.

**Fix:**

1. Ensure Cilium pod CIDRs are added to hybrid WireKubePeer AllowedIPs (Step 5b)
2. Verify routes exist on EC2: `ip route show table 22347` should show `198.18.x.x/25`
3. Check VPC CNI SNAT is active: `AWS_VPC_K8S_CNI_EXTERNALSNAT` should be `false`

### WireKubePeers show connected: false

**Possible causes:**

1. **Relay unreachable** — Verify relay LB endpoint in WireKubeMesh
2. **WireGuard module not loaded** — `lsmod | grep wireguard` on the node
3. **Firewall** — UDP 51822 and TCP 3478 outbound must be open
4. **Stale state** — Delete the WireKubePeer and restart the agent

---

## Reference Files

All example manifests are in `config/examples/eks-hybrid/`:

| File | Purpose |
|------|---------|
| `namespace.yaml` | WireKube namespace |
| `rbac.yaml` | ServiceAccount, ClusterRole, ClusterRoleBinding |
| `daemonset.yaml` | Agent DaemonSet (hostNetwork, init cleanup) |
| `relay.yaml` | Relay Deployment + LoadBalancer Service |
| `wirekubemesh.yaml` | WireKubeMesh CR (auto AllowedIPs, external relay) |
| `gateway.yaml` | WireKubeGateway CR (VGW for kubectl + pod routing) |
| `cilium-values.yaml` | Helm values for Cilium on hybrid nodes |
