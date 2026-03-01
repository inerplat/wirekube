# WireKube — Claude Agent Instructions

## Memory
Project memory (architecture decisions, design rationale, file map) is in:
**`.claude/MEMORY.md`** — read this first before starting any task.

## Project
WireKube is a Kubernetes operator that creates a serverless P2P WireGuard mesh between nodes.
No central VPN server required — Kubernetes API (CRDs) acts as the coordination plane.

## Environment
- Go binary: `/usr/local/go/bin/go` (add to PATH if not found)
- Module: `github.com/wirekube/wirekube`
- Build: `export PATH="$PATH:/usr/local/go/bin" && go mod tidy && make build`

## Critical Rules
1. **Never insert pod CIDR routes** through wg0 — breaks Cilium kube-proxy replacement.
   Route **node IPs** (/32) through wg0 instead (see MEMORY.md: CNI Compatibility).
2. Endpoint discovery priority: manual annotation → IPv6 → STUN → AWS metadata → UPnP → InternalIP
3. `WireKubePeer.spec.allowedIPs` = meshIP/32 + nodeIP/32 (not pod CIDRs)
4. WireKube route metric = 200 (higher than CNI ~100, so node IP routes win)
5. Agent DaemonSet must use `hostNetwork: true` and `NET_ADMIN` capability.

## Common Tasks
```bash
# Build all binaries
export PATH="$PATH:/usr/local/go/bin"
make build

# Install CRDs + deploy
make install-crds install-rbac
kubectl apply -f config/operator/wirekubemesh-default.yaml
kubectl label node <node> wirekube.io/vpn-enabled=true
make deploy

# Check mesh status
./bin/wirekubectl mesh status
./bin/wirekubectl peers
```
