# Architecture Overview

## Components

```mermaid
graph TD
    subgraph API["Kubernetes API Server"]
        Mesh[WireKubeMesh<br/>cluster-wide config]
        Peer[WireKubePeer x N<br/>per-node state]
    end
    subgraph Agents["Agent DaemonSet"]
        A1[Agent node-1<br/>wire_kube]
        A2[Agent node-2<br/>wire_kube]
        A3[Agent node-3<br/>wire_kube]
    end
    subgraph RelayPool["Relay Pool"]
        R1[relay-0]
        R2[relay-1]
    end
    API -->|Watch/Update| A1
    API -->|Watch/Update| A2
    API -->|Watch/Update| A3
    A1 <-->|WireGuard P2P or Relay| A2
    A2 <-->|Relay TCP| RelayPool
    A3 <-->|WireGuard P2P or Relay| A1
```

WireKube consists of four binaries:

| Component | Runs as | Purpose |
|-----------|---------|---------|
| **Agent** | DaemonSet (`hostNetwork: true`) | Manages WireGuard interface, discovers endpoints, syncs peers, handles relay failover, direct recovery, and gateway forwarding |
| **Operator** | Deployment | Reconciles `WireKubeMesh`, `WireKubePeer`, and `WireKubeGateway` CRDs, applies defaults |
| **Relay** | Deployment + Service | Bridges WireGuard UDP over TCP for peers behind Symmetric NAT |
| **wirekubectl** | CLI | Status inspection and peer management |

### Agent (DaemonSet)

The agent runs on every node labeled with `wirekube.io/vpn-enabled=true`
(`hostNetwork: true`, `privileged: true`, `appArmorProfile: Unconfined` —
required for TUN open on Ubuntu 24.04 + containerd ≥ 1.7). It is
responsible for:

1. **Userspace WireGuard** — Runs wireguard-go and owns a TUN named `wire_kube`. The kernel WireGuard backend has been removed; on upgrade from older versions the agent deletes any existing kernel `wire_kube` link and recreates it as a TUN.
2. **Custom `WireKubeBind`** — Sits between wireguard-go and the network and runs the bimodal warm-relay datapath (see [NAT Traversal](nat-traversal.md)). Also sends and receives `MsgBimodalHint` disco frames via the relay for asymmetric-failover recovery.
3. **Key management** — Generates and persists WireGuard key pairs
4. **Peer registration** — Creates/updates its own WireKubePeer CRD (including mesh overlay IP from `meshCIDR` and, optionally, the node's private address via `autoAllowedIPs`)
5. **Peer synchronization** — Watches all WireKubePeer CRDs and configures wireguard-go peers; the per-peer `PathMonitor` FSM commits `Direct/Warm/Relay` decisions into the Bind
6. **Endpoint discovery** — Determines the best reachable address via STUN, annotations, etc.
7. **NAT detection** — RFC 5780 multi-server STUN to classify `open` / `cone` / `port-restricted-cone` / `symmetric`
8. **Relay client** — Connects to the relay pool and stays connected (relay is always warm, not just a fallback)
9. **Relay auto-reconnect** — Exponential backoff (1s–30s) on TCP connection drops
10. **Route management** — Adds `/32` routes for peer node IPs with metric 200
11. **IPSec bypass** — Sets `disable_xfrm` and `disable_policy` on the WireGuard interface
12. **Crash recovery** — initContainer cleans stale interfaces, routes, and ip rules

### Relay Server

The relay server bridges WireGuard UDP packets over TCP for peers behind Symmetric NAT.
It is a stateless packet forwarder that:

- Accepts TCP connections from agents
- Maps WireGuard public keys to TCP connections
- Forwards framed UDP packets between agents
- Cannot decrypt traffic (no access to WireGuard private keys)
- Supports auto-reconnect from agents with exponential backoff
- Can be scaled horizontally via a Headless Service (relay pool)

### CRDs

**WireKubeMesh** — Singleton resource defining mesh-wide configuration:

- WireGuard listen port and interface name
- `meshCIDR` — private CIDR for the overlay. Each node gets a
  deterministic `/32` derived from its node name; that IP becomes the
  peer's primary AllowedIPs entry.
- `autoAllowedIPs.includeNodeInternalIP` — optional flag that also
  publishes each node's **private** address (never public) alongside
  the overlay IP for legacy references.
- STUN server list (minimum 2 for NAT detection)
- Relay configuration (mode, provider, endpoints, timeouts)

**WireKubePeer** — One per mesh-participating node:

- WireGuard public key
- Discovered endpoint (ip:port)
- AllowedIPs (typically the deterministic mesh IP `/32`, optionally
  augmented with the node's private IP)
- Status: connected, NAT type (`open`/`cone`/`port-restricted-cone`/
  `symmetric`), transport mode (`direct`/`relay`/`mixed`), per-peer
  `connections` map, discovery method

**WireKubeGateway** — Virtual gateway for cross-VPC routing:

- PeerRefs: ordered list of gateway peers (HA failover)
- ClientRefs: peers that route through this gateway
- Routes: CIDR ranges reachable through the gateway
- SNAT and health check configuration
- See [Virtual Gateway](gateway.md) for the full design.

## Traffic Flow

WireKube creates a **node-level mesh**, not a pod-level overlay.

### Route Strategy

```
                     CNI routes (metric ~100)
Pod A ---- pod CIDR ---- CNI (Cilium, etc.) ---- Pod B

                     WireKube routes (metric 200)
Node A ---- nodeIP/32 ---- wire_kube ---- Node B
```

WireKube inserts **only `/32` routes for node IPs** with metric 200.
Pod CIDR routes managed by the CNI are untouched (lower metric = higher priority).

!!! warning "Critical Design Rule"
    Never insert pod CIDR routes through `wire_kube`. This would break CNI
    functionality, especially with Cilium's kube-proxy replacement.

### Routing Internals

- **fwmark `0x574B`** on WireGuard socket packets → main routing table (avoids packet loop)
- **Custom routing table `22347`** (`0x574B`) isolates WireGuard routes from the main table
- **Route metric 200** (above CNI default ~100, so CNI takes precedence)
- **`disable_xfrm=1`** and **`disable_policy=1`** on wire_kube → bypasses IPSec xfrm policies

### Packet Path (Direct P2P)

```
1. Packet destined for remote node IP
2. Kernel routing: nodeIP/32 → dev wire_kube (table 22347)
3. WireGuard encrypts packet
4. UDP packet marked with fwmark 0x574B → uses main table → sent via physical interface
5. Peer's WireGuard decrypts
6. Delivered to local stack
```

### Packet Path (Relay)

```
1. Packet destined for remote node IP
2. Kernel routing: nodeIP/32 → dev wire_kube
3. WireGuard encrypts → UDP to local proxy (127.0.0.1:random)
4. UDP proxy reads packet → frames as [4B length][1B type=0x02][32B dest pubkey][payload]
5. Sends over TCP to relay server (via relay pool)
6. Relay forwards to destination agent's TCP connection
7. Destination proxy delivers UDP to local WireGuard (127.0.0.1:51820)
8. WireGuard decrypts
9. Delivered to local stack
```

## NAT Traversal Overview

Inspired by [Tailscale's approach](https://tailscale.com/blog/how-nat-traversal-works):

1. **STUN discovery** — Query 2+ STUN servers; compare mapped ports for NAT type detection
2. **Direct P2P** — Same VPC or Cone NAT nodes handshake directly
3. **Relay fallback** — Symmetric NAT or handshake timeout → TCP relay with auto-reconnect
4. **Direct recovery** — Periodic probing upgrades relayed peers back to direct when possible

See [NAT Traversal](nat-traversal.md) for the full strategy.

## Design Principles

1. **Cloud-agnostic** — No reliance on cloud-specific features (VPC peering, etc.)
2. **CNI-safe** — Only routes node IPs, never pod CIDRs
3. **Graceful degradation** — Direct P2P → relay fallback → direct recovery
4. **Minimal privileges** — `NET_ADMIN` + `SYS_MODULE` only, no `privileged: true`
5. **Structured direct upgrade** — Relayed peers are periodically probed; skips peers that self-report as relay-only (Symmetric NAT)
6. **Per-node status ownership** — Each agent updates only its own `transportMode` to prevent cross-agent status flapping
7. **IPSec coexistence** — xfrm bypass prevents conflicts with existing site-to-site tunnels
8. **Crash resilience** — initContainer cleanup + routing table isolation
