# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WireKube is a serverless P2P WireGuard mesh VPN for Kubernetes. It uses Kubernetes CRDs as its coordination plane — no external etcd, relay, or coordination server is required by default. Nodes discover each other via `WireKubePeer` CRDs and establish direct WireGuard tunnels, falling back to TCP relay when NAT prevents direct P2P.

## Build & Test Commands

```bash
# Build
make build              # All binaries (operator, agent, relay, wirekubectl)
make build-operator
make build-agent
make build-relay
make build-wirekubectl

# Test & lint
make test               # go test ./... -v
make vet                # go vet ./...
make fmt                # go fmt ./...
make tidy               # go mod tidy

# Run a single test
go test ./pkg/agent/... -v -run TestEndpointDiscovery

# Code generation (after changing CRD types or +kubebuilder markers)
make generate           # Regenerate deepcopy functions
make manifests          # Regenerate CRD YAML from types.go

# Docker
make docker-build       # Multi-arch (amd64 + arm64)
make docker-push        # Build and push (IMG=inerplat/wirekube VERSION=v0.0.1)

# Kubernetes deployment
make install-crds       # kubectl apply config/crd/
make deploy-operator    # CRDs + RBAC + operator deployment
make deploy-agent       # DaemonSet
make deploy             # Full stack (operator + agent)
make undeploy
make label-node NODE_NAME=<name>   # Add wirekube.io/vpn-enabled=true label
make init-mesh          # Apply default WireKubeMesh CR
```

## Architecture

### Four Binaries

**Agent** (`cmd/agent/`) — DaemonSet, one per node (`hostNetwork: true`)
- Creates and manages the WireGuard interface (name from CR, default `wire_kube`)
- Generates keypair, stores private key at `/etc/wirekube/privatekey`
- Discovers public endpoint (STUN → AWS metadata → UPnP → annotation → internal IP)
- Creates/updates its own `WireKubePeer` CR; watches all peers and syncs to kernel WireGuard
- Adds `/32` node routes with metric 200 (higher than CNI, lower priority = less preferred)
- Falls back to TCP relay after 30s handshake timeout; retries direct every 120s
- ICE-like negotiation: evaluates NAT type combinations to choose optimal connectivity strategy
- Gateway: if elected as active gateway, enables IP forwarding + SNAT for cross-VPC routing
- Startup retry: exponential backoff loop (2s–60s) for API connectivity issues (e.g. CNI delay)
- Prometheus metrics on `:9090/metrics` (peer latency, traffic, connection state)

**Operator** (`cmd/operator/`) — Cluster-scoped deployment
- Reconciles `WireKubeMesh` (cluster config), `WireKubePeer` (per-node state/status), and `WireKubeGateway` (VGW)
- Default values: port 51820, interface `wire_kube`, MTU 1420, keepalive 25s
- Metrics on `:8080`, health probes on `:8081`

**Relay** (`cmd/relay/`) — Optional, single deployment
- Bridges WireGuard UDP over TCP when NAT blocks direct P2P
- Custom binary frame protocol: `[4B length][1B type][body]`
  - `0x01` Register (32B WG pubkey), `0x02` Data (32B dest pubkey + UDP payload), `0x03` Keepalive, `0xFF` Error
- Listens on port 3478 (override with `--addr` or `WIREKUBE_RELAY_ADDR`)

**WireKubeCTL** (`cmd/wirekubectl/`) — CLI for status and peer management

### Key Packages

| Package | Purpose |
|---|---|
| `pkg/api/v1alpha1/` | CRD type definitions (`WireKubeMesh`, `WireKubePeer`, `WireKubeGateway`) |
| `pkg/agent/` | Agent main logic, endpoint discovery, relay orchestration, ICE negotiation, metrics |
| `pkg/agent/nat/` | STUN (`stun.go`) and UPnP (`upnp.go`) endpoint discovery |
| `pkg/agent/relay/` | Relay TCP client (`client.go`), UDP proxy (`proxy.go`), multi-instance pool (`pool.go`) |
| `pkg/relay/` | Relay server and wire protocol |
| `pkg/wireguard/` | WireGuard kernel interface management and keypair I/O |
| `pkg/controller/` | Kubernetes controller-runtime reconcilers |

### CRDs

**WireKubeMesh** (cluster-scoped singleton) — cluster-wide VPN config including relay settings (`mode: auto|always|never`, `provider: external|managed`) and NAT traversal options (`natTraversal.birthdayAttack: enabled|disabled`).

**WireKubePeer** (cluster-scoped, one per node) — holds public key, endpoint, allowedIPs; status reflects `connected`, `lastHandshake`, `transportMode: direct|relay`.

**WireKubeGateway** (cluster-scoped) — Virtual Gateway for cross-VPC routing. Defines `peerRefs` (HA ordered list), `clientRefs` (authorized client peers), `routes` (CIDR ranges), SNAT and health check config. Agent-side election: first healthy peer becomes active, gets routes injected into AllowedIPs, enables IP forwarding + MASQUERADE.

### Routing Design

- Only `/32` node IPs are added as routes — pod CIDRs are never touched (CNI owns those)
- fwmark `0x574B` on WireGuard socket packets → main routing table (avoids WG route loop)
- All other packets → table 0x574B / 22347 (WG routes apply)
- Route metric 200 (above CNI default ~100, so node traffic prefers WG interface)

### NAT Traversal

Inspired by [Tailscale's NAT traversal](https://tailscale.com/blog/how-nat-traversal-works):

1. Direct P2P via STUN-discovered public endpoint
2. TCP relay after 30s handshake timeout (WireGuard encryption preserved end-to-end)
3. ICE-like negotiation with NAT type detection (cone vs symmetric)
4. Cone ↔ Cone: direct via stable STUN endpoints
5. Cone ↔ Symmetric: probe using cone side's stable endpoint
6. Symmetric ↔ Symmetric: birthday attack (disabled by default, configurable via `WireKubeMesh.spec.natTraversal.birthdayAttack` or per-peer annotation `wirekube.io/birthday-attack`)
7. Same-NAT detection: peers sharing the same public IP use host candidates (LAN IP) for direct communication
8. NAT endpoint reflection: once a direct connection succeeds, the CRD endpoint is updated to the actual NAT-mapped port
9. Relay auto-reconnect with exponential backoff (1s–30s)
10. Relay pool: DNS-based multi-instance discovery, agents register on all replicas

## Config Layout

```
config/
  crd/                        # Auto-generated CRD manifests (do not hand-edit)
  agent/                      # DaemonSet YAML (includes RBAC + ServiceMonitor)
  relay/                      # Relay Deployment + Service examples
  gateway/                    # WireKubeGateway example CRs
  grafana/                    # Grafana dashboard JSON
  wirekubemesh-default.yaml   # Example WireKubeMesh CR
```

## Code Generation Notes

After modifying any type in `pkg/api/v1alpha1/` (especially `+kubebuilder:` markers), always run:
```bash
make generate && make manifests
```
The generated files in `config/crd/` must be committed alongside type changes.

## Documentation

MkDocs Material theme. To preview locally:
```bash
pip install mkdocs-material
mkdocs serve
```
All comments and documentation must be written in English.
