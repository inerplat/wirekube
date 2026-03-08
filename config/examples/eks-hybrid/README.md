# EKS Hybrid Nodes — WireKube Reference Deployment

Complete, tested reference for deploying WireKube on EKS with Hybrid Nodes.

## File Overview

| File | Purpose |
|------|---------|
| `namespace.yaml` | WireKube namespace |
| `rbac.yaml` | ServiceAccount, ClusterRole, ClusterRoleBinding |
| `daemonset.yaml` | Agent DaemonSet (hostNetwork, init container for cleanup) |
| `relay.yaml` | Relay Deployment + LoadBalancer Service |
| `wirekubemesh.yaml` | WireKubeMesh CR (auto AllowedIPs, external relay, NAT traversal) |
| `gateway.yaml` | WireKubeGateway CR (VGW for kubectl exec/logs + pod routing) |
| `cilium-values.yaml` | Helm values for Cilium on hybrid nodes |

## Quick Start

```bash
# 1. Install CRDs
kubectl apply -f config/crd/

# 2. Install Cilium on hybrid nodes
#    Update cilium-values.yaml first:
#      k8sServiceHost → your EKS API endpoint
#      clusterPoolIPv4PodCIDRList → non-overlapping CIDR (e.g. 198.18.0.0/15)
helm upgrade --install cilium \
  oci://public.ecr.aws/eks/cilium/cilium \
  --version <VERSION> --namespace kube-system \
  -f config/examples/eks-hybrid/cilium-values.yaml

# 3. Exclude kube-proxy from hybrid nodes
kubectl patch ds kube-proxy -n kube-system --type merge -p '{
  "spec":{"template":{"spec":{"affinity":{"nodeAffinity":{
    "requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{
      "matchExpressions":[{"key":"eks.amazonaws.com/compute-type","operator":"NotIn","values":["hybrid"]}]
    }]}
  }}}}}}'

# 4. Deploy WireKube (update daemonset.yaml with EKS API endpoint first)
kubectl apply -f config/examples/eks-hybrid/namespace.yaml
kubectl apply -f config/examples/eks-hybrid/rbac.yaml
kubectl apply -f config/examples/eks-hybrid/relay.yaml
kubectl apply -f config/examples/eks-hybrid/daemonset.yaml

# 5. Wait for relay LB, then apply mesh config
kubectl get svc wirekube-relay -n wirekube-system -w
RELAY_EP=$(kubectl get svc wirekube-relay -n wirekube-system \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'):3478
sed "s|REPLACE_WITH_RELAY_LB:3478|${RELAY_EP}|" \
  config/examples/eks-hybrid/wirekubemesh.yaml | kubectl apply -f -

# 6. Verify peers
kubectl get wirekubepeers

# 7. Enable VGW gateway (update gateway.yaml with your values first)
#    Also run AWS setup: disable Source/Dest Check + add VPC routes
kubectl apply -f config/examples/eks-hybrid/gateway.yaml
```

## Pod Networking

After deploying the mesh, cross-node pod communication requires:

### Hybrid ↔ Hybrid Pods
Works automatically — Cilium VXLAN over WireGuard.

### EC2 → Hybrid Pods
Add each hybrid node's Cilium pod CIDR to its WireKubePeer `AllowedIPs`:
```bash
kubectl get ciliumnodes -o custom-columns='NAME:.metadata.name,POD_CIDR:.spec.ipam.podCIDRs'
kubectl patch wirekubepeer <node> --type=json \
  -p='[{"op":"add","path":"/spec/allowedIPs/-","value":"<POD_CIDR>"}]'
```

### Hybrid → EC2 Pods
Add VPC subnets to WireKubeGateway routes:
```bash
kubectl patch wirekubegateway hybrid-gateway --type=json -p='[
  {"op":"add","path":"/spec/routes/-","value":{"cidr":"<VPC_SUBNET>","description":"VPC pod subnet"}}
]'
```

## Full Documentation

See [EKS Hybrid Nodes Guide](../../docs/getting-started/eks-hybrid-nodes.md)
for detailed architecture, CIDR planning, routing design, and troubleshooting.
