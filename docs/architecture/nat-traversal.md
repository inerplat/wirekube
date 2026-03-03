# NAT Traversal

WireKube implements a multi-stage NAT traversal strategy inspired by
[Tailscale's approach](https://tailscale.com/blog/how-nat-traversal-works).
The core idea: establish relay connectivity immediately, probe for direct paths
in parallel, and transparently upgrade when a better path is found.

## NAT Types

| NAT Type | Mapping Behavior | WireGuard P2P | WireKube Strategy |
|----------|-----------------|---------------|-------------------|
| Full Cone | Endpoint-Independent | Direct | STUN discovery |
| Restricted Cone | Endpoint-Independent | Direct (with keepalive) | STUN discovery |
| Port Restricted Cone | Endpoint-Independent | Usually works | STUN discovery |
| **Symmetric (EDM)** | **Endpoint-Dependent** | **Fails** | **Relay fallback** |

### Why Symmetric NAT Breaks WireGuard

```mermaid
flowchart TB
    subgraph Node["Node (private: 10.0.0.5:51820)"]
        WG[WireGuard]
    end
    subgraph NAT["NAT (Symmetric)"]
        N[src port changes per destination]
    end
    subgraph STUN["STUN Servers"]
        A[STUN Server A<br/>sees: 1.2.3.4:50001]
        B[STUN Server B<br/>sees: 1.2.3.4:50002]
    end
    WG --> NAT
    NAT --> A
    NAT --> B
```

In Symmetric NAT, the NAT gateway assigns a **different external port for each
destination**. STUN discovers `1.2.3.4:50001` when talking to server A, but a
peer trying to send to `1.2.3.4:50001` gets a different mapping — the packet
never arrives.

### Cloud Provider NAT Behavior

All major cloud NAT gateways use Symmetric NAT:

| Provider | NAT Product | NAT Type |
|----------|------------|----------|
| AWS | NAT Gateway | Symmetric |
| GCP | Cloud NAT | Symmetric |
| Azure | Azure NAT Gateway | Symmetric |
| OCI | NAT Gateway | Symmetric |

Most home/ISP routers use Cone NAT (STUN-based P2P works).

!!! info "When is relay needed?"
    Relay is needed only when **both** peers are behind Symmetric NAT. Cone ↔
    Symmetric pairs achieve direct P2P: the Symmetric side initiates a
    handshake to the Cone peer's stable STUN endpoint; the Cone NAT accepts
    the packet (Endpoint-Independent Filtering), and WireGuard responds to
    the actual source address. Each node publishes its `natType` in its
    WireKubePeer status, so peers can determine the optimal transport path.

## Traversal Strategy

```mermaid
graph TD
    A[Agent starts] --> B[Endpoint Discovery]
    B --> C{Manual annotation?}
    C -->|Yes| D[Use annotated endpoint]
    C -->|No| E[STUN binding to 2+ servers]
    E --> F{Same mapped port<br/>from all servers?}
    F -->|Yes: Cone NAT| G[Use STUN public IP:port]
    F -->|No: Symmetric NAT| H[Flag isSymmetricNAT=true<br/>Use STUN public IP with listen port]
    G --> I[Register WireKubePeer]
    D --> I
    H --> I
    I --> J[Configure WireGuard peers]
    J --> K{Symmetric NAT<br/>and peer also<br/>Symmetric?}
    K -->|Both Symmetric| L[Relay immediately]
    K -->|No / Cone peer| M{Handshake within<br/>timeout?}
    M -->|Yes| N[Direct P2P]
    M -->|No| L
    L --> O[Relay mode]
    O --> P[Periodic direct probe]
    P -->|Success| N
    P -->|Fail| O
```

### Stage 1: Endpoint Discovery

The agent runs through the discovery chain on startup:

1. **Manual annotation** (`wirekube.io/endpoint`) — Highest priority, no network calls
2. **STUN** — Binding request to 2+ configured STUN servers. If mapped ports differ between servers, the node is classified as Symmetric NAT.
3. **AWS IMDSv2** — EC2 metadata service for Elastic IP lookup
4. **UPnP / NAT-PMP** — Request port mapping from gateway router
5. **Node InternalIP** — Last resort fallback

For Symmetric NAT nodes, the agent uses the STUN-discovered public IP combined
with the configured WireGuard listen port as its registered endpoint. The port
won't match the actual NAT mapping, but it provides a valid public IP for peers
to attempt direct connections (which will fail, triggering relay).

### Stage 2: Direct P2P or Relay

After endpoint discovery:

- **Cone NAT / Public IP**: Agent configures WireGuard with the peer's discovered
  endpoint and waits for a handshake.
- **Symmetric NAT → Cone/Public peer**: Agent tries direct. The Symmetric side
  initiates a handshake to the Cone peer's stable endpoint. Cone NAT accepts
  the incoming packet, WireGuard responds to the actual source address, and a
  bidirectional tunnel is established.
- **Symmetric NAT → Symmetric NAT peer**: Relay is activated immediately (both
  sides change ports per destination — direct P2P is impossible without a birthday
  attack). The peer's `natType` field in its WireKubePeer status is used to make
  this decision.
- **Handshake timeout**: If any peer's handshake doesn't complete within
  `handshakeTimeoutSeconds` (default 30s), relay is activated for that peer.

### Stage 3: Relay Fallback

When relay is activated for a peer:

1. Agent connects to the relay server (or relay pool) via TCP
2. Registers its WireGuard public key with the relay
3. Creates a local UDP proxy (`127.0.0.1:random → 127.0.0.1:<wg-port>`)
4. Sets the peer's WireGuard endpoint to the proxy's local address
5. All subsequent WireGuard traffic for this peer routes through the relay

The relay connection auto-reconnects with exponential backoff (1s–30s) if the
TCP connection drops. Existing UDP proxies are preserved across reconnections.

### Stage 4: Direct Path Recovery

Every `directRetryIntervalSeconds` (default 120s), the agent probes relayed
peers to check if direct connectivity has become available:

1. Temporarily set the peer's WireGuard endpoint back to the direct address
2. Wait for the next sync cycle to check WireGuard stats
3. If a successful handshake is detected on the non-proxy endpoint → upgrade to direct
4. If no handshake → cancel probe, resume relay, wait for next retry interval

!!! note "Skipping futile probes"
    The agent skips direct probes for peers whose `WireKubePeer.Status.NATType`
    is `symmetric` when the local node is also Symmetric NAT. This prevents
    wasting cycles probing paths that cannot succeed (both sides use endpoint-
    dependent mapping).

## Transport Modes and NAT Type Reporting

Each agent publishes two transport-related fields in its WireKubePeer status:

**`natType`** — The node's detected NAT mapping behavior (`cone`, `symmetric`,
or empty if detection was inconclusive). Other agents use this to decide whether
direct P2P is possible.

**`peerTransports`** — A per-peer map recording the transport mode to each
remote peer (e.g., `{"node-worker1": "direct", "node-worker7": "relay"}`).
This gives full visibility into which paths use relay.

**`transportMode`** — Aggregate derived from `peerTransports`:

| Mode | Meaning |
|------|---------|
| `direct` | All peers connected via direct P2P |
| `relay` | All peers via relay |
| `mixed` | Some peers direct, some relayed |

Both `natType` and `transportMode` appear as kubectl print columns (`NAT`, `Mode`)
for quick inspection: `kubectl get wirekubepeers`.

Each agent only updates its **own** node's status. This prevents
conflicting updates from multiple agents and eliminates status flapping.

## Relay Protocol

See [Relay System](relay.md) for the full relay protocol specification.

## Performance

| Scenario | Typical Latency | Notes |
|----------|----------------|-------|
| Direct P2P (same VPC) | 0.5 – 2 ms | WireGuard overhead only |
| Relay (same region) | 1.5 – 3 ms | Added TCP hop through relay |
| Relay (cross-region) | 40 – 60 ms | Dominated by geographic distance |

The relay adds minimal latency within the same region because it only
introduces one additional TCP hop (agent ↔ relay ↔ agent).
