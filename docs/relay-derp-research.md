# Relay/DERP Research for WireKube

> **Context**: WireKube needs a relay fallback when direct WireGuard P2P fails (Symmetric NAT, restrictive firewalls). The relay **must** work with **kernel WireGuard** (UDP only).

**Key Requirement**: The solution must accept UDP WireGuard packets from a local proxy, forward them over TCP/HTTPS (or TURN) to the relay, and deliver them as UDP to the destination node's WireGuard.

---

## Executive Summary

| Solution | Kernel WG Compatible | License | Effort | Recommendation |
|----------|------------------------|---------|--------|----------------|
| **TURN (Coturn + pion/turn)** | ✅ Yes (native UDP relay) | BSD/MIT | Medium | **Best fit** |
| **Tailscale DERP** | ⚠️ Via UDP proxy adapter | BSD-3-Clause | High | Good if DERP preferred |
| **Netbird relay** | ✅ Yes | AGPLv3 (relay/) | High | Avoid (license) |
| **Headscale DERP** | ⚠️ Via adapter | BSD-3-Clause | High | Same as Tailscale |
| **rathole/frp/chisel** | ⚠️ Possible but awkward | MIT/Apache | High | Not designed for P2P |
| **boringtun/wireguard-go** | N/A (userspace) | MIT/BSD | Very High | Not applicable |
| **wgsd/wg-dynamic** | N/A | Various | N/A | No relay capability |

**Recommended approach**: Use **TURN** (Coturn server + pion/turn client) with a local UDP-to-TURN proxy in the WireKube agent. TURN natively relays UDP and is proven with kernel WireGuard (Netbird uses it).

---

## 1. Tailscale DERP

### Architecture

- **Protocol**: DERP (Designated Encrypted Relay for Packets)
- **Transport**: HTTPS (port 443), HTTP upgrade to bidirectional stream
- **Addressing**: Curve25519 public keys (WireGuard keys) as peer identifiers
- **Flow**: Client connects via HTTP → upgrades to DERP protocol → sends `frameSendPacket` (dest pubkey + packet bytes) → server delivers via `frameRecvPacket` to recipient
- **Packets relayed**: Encrypted WireGuard packets (opaque to DERP) + disco discovery messages

### Kernel WireGuard Compatibility

**Not direct.** Tailscale uses **magicsock** (userspace socket) + **wireguard-go** (userspace WireGuard). Magicsock is the `Bind` for WireGuard—it sits between the WireGuard crypto core and the network. DERP is designed for this stack.

For **kernel WireGuard**, you need a **UDP-to-DERP proxy**:

1. Local proxy binds to `127.0.0.1:RELAY_PORT` per relayed peer
2. Set peer's WireGuard endpoint to `127.0.0.1:RELAY_PORT`
3. Proxy receives UDP from kernel WG → wraps in DERP `frameSendPacket` → sends over HTTPS to DERP server
4. DERP server delivers to peer's DERP client
5. Peer's proxy receives from DERP → injects UDP to local kernel WireGuard

**Custom code required**: ~500–1000 LOC for the UDP↔DERP proxy per node.

### License

**BSD-3-Clause** — usable in commercial/proprietary projects.

### Library/Dependency

- `tailscale.com/derp` — core protocol
- `tailscale.com/derp/derphttp` — DERP-over-HTTP (WebSocket-like)
- Importable as Go modules; `go install tailscale.com/cmd/derper@latest` for server

### Standalone Usage

- **Yes**, you can run `derper` standalone: `derper --hostname=example.com`
- **Coordination**: DERP map (list of regions/servers) is typically distributed by Tailscale control or Headscale. For WireKube, you'd configure a static DERP map in CRD/config.
- **Verify-clients**: Optional; if used, derper validates clients via Tailscale/Headscale (requires coordination).

### Pros

- Battle-tested, used by millions
- Works over HTTPS (firewall-friendly)
- BSD-3-Clause
- Can use as library

### Cons

- Designed for magicsock, not kernel WG
- Requires UDP proxy adapter
- DERP map distribution (can be static for WireKube)

---

## 2. Netbird

### Architecture

- **Relay**: Custom WebSocket-based protocol (not DERP, not TURN)
- **Transport**: WebSocket (optionally TLS)
- **Components**: Relay server + relay client; signal service for candidate negotiation
- **NAT**: pion/ice for STUN/ICE; TURN (Coturn) or embedded relay for fallback
- **Kernel WG**: Uses kernel WireGuard on Linux; eBPF proxy for relay↔WireGuard

### Kernel WireGuard Compatibility

**Yes.** Netbird uses kernel WireGuard and has an eBPF-based proxy that connects the kernel WireGuard interface to the ICE/relay path for relayed connections.

### Relay Protocol

- Custom protocol over WebSocket
- Peers negotiate relay server via Signal service
- Relay server relays opaque packets between peers

### License

- **relay/**, **management/**, **signal/**: **AGPLv3**
- Rest: BSD-3-Clause

**AGPLv3** means any network use of the relay triggers source disclosure. Not suitable as a dependency for WireKube without relicensing or reimplementation.

### Library/Dependency

- Relay is part of the Netbird monorepo; not a standalone library
- Would require forking or reimplementing the protocol

### Pros

- Proven with kernel WireGuard
- Integrated STUN + relay

### Cons

- **AGPLv3** on relay — blocks direct use
- Tightly coupled to Netbird management/signal

---

## 3. Headscale

### Architecture

- Open-source Tailscale control server
- **Embedded DERP server**: Same DERP protocol as Tailscale
- DERP can be enabled with `derp.server.enabled: true`
- Ports: TCP/443 (HTTPS), UDP/3478 (STUN)

### Kernel WireGuard Compatibility

Same as Tailscale DERP. Headscale clients are Tailscale/Headscale clients (magicsock). For kernel WireGuard, you need the same UDP-to-DERP proxy adapter.

### License

BSD-3-Clause.

### Pros

- Self-hosted DERP
- No Tailscale SaaS dependency

### Cons

- Headscale is a full control server; DERP is one component
- Still requires UDP proxy for kernel WG

---

## 4. Rathole / FRP / Chisel

### Rathole

- **Type**: Reverse proxy for NAT traversal (Rust)
- **Protocols**: TCP, UDP
- **Model**: Client (behind NAT) ↔ Server (public IP) ↔ External user
- **License**: MIT

**WireGuard relay**: Not designed for P2P. You'd need each node as both client and server, with unique service names. Awkward for mesh.

### FRP

- **Type**: Reverse proxy (Go)
- **Protocols**: TCP, UDP
- **Model**: Same as rathole
- **License**: Apache 2.0

**WireGuard relay**: Same issues. UDP forwarding exists but P2P mesh would require custom orchestration.

### Chisel

- **Type**: TCP/UDP tunnel over HTTP (Go)
- **Model**: Client-server; supports UDP
- **License**: MIT

**WireGuard relay**: Could tunnel WireGuard UDP over HTTP, but again not P2P-oriented. Would need custom topology.

### Verdict

All three are **service exposure** tools, not **P2P relay** systems. Possible but high custom code and operational complexity.

---

## 5. Boringtun / wireguard-go

### Boringtun

- Userspace WireGuard in Rust (Cloudflare)
- **License**: BSD-3-Clause

### wireguard-go

- Official userspace WireGuard in Go
- **License**: MIT

**Relay mode**: Neither has built-in relay. You would need to implement a relay mode from scratch (e.g., run WireGuard in relay node, forward packets). This would be a large custom effort and would not use kernel WireGuard on end nodes.

**Verdict**: Not applicable for kernel WireGuard relay.

---

## 6. wgsd / wg-dynamic

### wgsd

- CoreDNS plugin for WireGuard peer discovery via DNS-SD
- **Purpose**: Endpoint discovery, NAT hole punching
- **Relay**: None

### wg-dynamic

- Dynamic IP assignment for WireGuard (DHCP-like over IPv6 link-local)
- **Purpose**: Address management
- **Relay**: None

**Verdict**: No relay capabilities.

---

## 7. TURN (Coturn / pion/turn)

### Architecture

- **TURN** (RFC 5766): Relay for UDP (and TCP) when direct P2P fails
- **Flow**: Client allocates relay address on TURN server → sends data via Send/Data indications → server relays to peer's relay address
- **Transport**: UDP, TCP, TLS, DTLS to TURN server; relay is UDP (or TCP)

### Kernel WireGuard Compatibility

**Yes.** TURN natively relays UDP. Each node runs a TURN client that:

1. Allocates a relay address on the TURN server
2. Runs a local UDP proxy: receives from kernel WireGuard → sends via TURN → receives from TURN → injects to kernel WireGuard

Netbird uses this model (pion/ice + Coturn) with kernel WireGuard.

### Coturn

- **Language**: C
- **License**: BSD-3-Clause
- **Use**: Standalone TURN/STUN server binary
- **Ports**: 3478 (STUN/TURN), 5349 (TURNS), 49152–65535 (UDP relay range)

### pion/turn

- **Language**: Go
- **License**: MIT
- **Use**: Library for TURN client and server
- **Import**: `github.com/pion/turn/v3`

### Pros

- Standard protocol (RFC 5766)
- Native UDP relay
- Proven with kernel WireGuard (Netbird)
- pion/turn is embeddable in Go
- Coturn is mature and widely deployed

### Cons

- Need to run Coturn (or pion TURN server) as relay
- TURN auth (long-term credentials or TURN REST API)
- Relay port range must be open on server

---

## 8. Other Options

### udp2raw

- Encapsulates UDP in raw TCP/ICMP to bypass UDP blocking
- **Use case**: Get UDP through when it's blocked; not a relay
- Not a substitute for relay when both peers are behind NAT

### Custom UDP-over-TCP/WebSocket

- Build a simple relay: accept UDP locally, forward over TCP/WebSocket, relay delivers as UDP
- **Effort**: Moderate (similar to DERP proxy)
- **Pros**: Full control, no external deps
- **Cons**: Reinventing the wheel; TURN/DERP already solve this

---

## Comparison Table

| Project | How it works | Kernel WG | License | Library/Dep | Pros | Cons | Custom code |
|---------|--------------|-----------|---------|-------------|------|------|-------------|
| **Tailscale DERP** | HTTPS relay, curve25519-addressed | Via UDP proxy | BSD-3 | Yes (derp, derphttp) | Battle-tested, firewall-friendly | Needs adapter | ~500–1000 LOC |
| **Netbird relay** | WebSocket custom protocol | Yes | AGPLv3 | No | Proven with kernel WG | AGPLv3, coupled | N/A (license) |
| **Headscale DERP** | Same as Tailscale | Via UDP proxy | BSD-3 | Via Headscale | Self-hosted | Same as DERP | ~500–1000 LOC |
| **rathole** | TCP/UDP reverse proxy | Via tunnel | MIT | No (binary) | UDP support | Not P2P, awkward | High |
| **frp** | TCP/UDP reverse proxy | Via tunnel | Apache | No | UDP support | Not P2P | High |
| **chisel** | TCP/UDP over HTTP | Via tunnel | MIT | Go pkg | UDP over HTTP | Not P2P | High |
| **boringtun** | Userspace WG | N/A | BSD-3 | Rust crate | — | No relay | Very high |
| **wireguard-go** | Userspace WG | N/A | MIT | Go module | — | No relay | Very high |
| **wgsd** | DNS-SD discovery | N/A | Apache | CoreDNS plugin | — | No relay | N/A |
| **wg-dynamic** | DHCP-like config | N/A | GPL | Daemons | — | No relay | N/A |
| **Coturn** | TURN/STUN server | Yes (with client) | BSD-3 | Binary | Mature, UDP relay | C, not Go | Server only |
| **pion/turn** | TURN client/server | Yes | MIT | Go module | Embeddable, UDP relay | — | ~300–500 LOC proxy |

---

## Recommendation

### Primary: TURN (Coturn + pion/turn)

1. **Coturn** as relay server (or pion TURN server if you prefer pure Go)
2. **pion/turn** client in WireKube agent
3. **UDP proxy** in agent: kernel WireGuard ↔ TURN client

**Why**:

- TURN is built for UDP relay; no protocol mismatch
- Netbird proves kernel WG + TURN works
- pion/turn is MIT, embeddable
- Coturn is BSD-3, widely used
- No dependency on Tailscale/Headscale control plane

**Implementation sketch**:

- Add `WireKubeMesh.spec.relay` (e.g. `turnURL`, `turnUsername`, `turnPassword` or shared secret)
- When direct P2P fails (e.g. no handshake after N seconds), mark peer as relay-needed
- For relayed peers: set endpoint to `127.0.0.1:RELAY_BASE+peerIndex`
- Relay proxy: bind to those ports, run TURN client, map peer ↔ TURN allocation
- Use `pion/ice` or raw `pion/turn` for client logic

### Alternative: Tailscale DERP

If you prefer DERP (HTTPS, curve25519 addressing):

1. Run `derper` (or Headscale with embedded DERP)
2. Add UDP-to-DERP proxy using `tailscale.com/derp/derphttp`
3. Configure static DERP map in WireKube CRD

**Trade-off**: More code (DERP protocol handling) but HTTPS may traverse more firewalls than TURN UDP.

---

## References

- [Tailscale DERP source](https://github.com/tailscale/tailscale/tree/main/derp)
- [Tailscale Custom DERP](https://tailscale.com/kb/1118/custom-derp-servers)
- [Netbird architecture](https://docs.netbird.io/about-netbird/how-netbird-works)
- [Headscale DERP](https://headscale.net/development/ref/derp/)
- [pion/turn](https://github.com/pion/turn)
- [Coturn](https://github.com/coturn/coturn)
- [RFC 5766 - TURN](https://tools.ietf.org/html/rfc5766)
