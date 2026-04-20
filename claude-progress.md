# WireKube wireguard-go Custom Bind Progress

## Branch: `feature/wireguard-go-custom-bind`
## PR: inerplat/wirekube#8

---

## Completed

### New Files (17)
| File | Purpose |
|------|---------|
| `pkg/wireguard/engine.go` | WGEngine interface (kernel/userspace abstraction) |
| `pkg/wireguard/kernel_engine.go` | Wraps existing Manager as WGEngine |
| `pkg/wireguard/userspace_engine.go` | wireguard-go UserspaceEngine |
| `pkg/wireguard/bind.go` | WireKubeBind (conn.Bind impl, path routing) |
| `pkg/wireguard/endpoint.go` | WireKubeEndpoint (conn.Endpoint with peerKey) |
| `pkg/wireguard/relay_transport.go` | RelayTransport interface |
| `pkg/wireguard/routes.go` | Shared routing (SyncRoutes, ip rule, fwmark) |
| `pkg/wireguard/tun.go` | Persistent TUN management |
| `pkg/wireguard/uapi.go` | UAPI helpers (IpcSet/IpcGet parsing) |
| `pkg/wireguard/bind_test.go` | Bind unit tests |
| `pkg/wireguard/endpoint_test.go` | Endpoint unit tests |
| `pkg/wireguard/engine_test.go` | Engine interface compliance tests |
| `cmd/agent/main_test.go` | selectEngine unit tests |
| `pkg/agent/apiserver_route_linux.go` | API server route (no-op) |
| `pkg/agent/apiserver_route_other.go` | Non-linux stub |

### Modified Files
| File | Changes |
|------|---------|
| `pkg/agent/agent.go` | wgMgr type → WGEngine, relay bind-delivery wiring, SetPeerPath in enableRelayForPeer |
| `pkg/agent/ice.go` | LastDirectReceive verification to prevent false direct upgrades, SetPeerPath API |
| `pkg/agent/relay/pool.go` | bindDelivery callback, handleData routing, relay forwarded log |
| `cmd/agent/main.go` | --wireguard-impl flag, selectEngine auto-detection |
| `pkg/api/v1alpha1/wirekubemesh_types.go` | Implementation field |
| `pkg/api/v1alpha1/wirekubepeer_types.go` | BindMode field |
| `config/crd/*.yaml` | Regenerated CRDs |
| `config/agent/daemonset.yaml` | /dev/net/tun volume mount |
| `test/kind_e2e/infra_test.go` | Agent/relay log dump on teardown |

### Bugs Fixed During Debugging
1. **peerKey in endpoint** — relay ReceiveFunc embeds peerKey so Send() can route relay responses
2. **Deadlock: TUN event reader vs IpcSet** — split IpcSet into private_key + Up() + listen_port/fwmark
3. **Lazy relay ReceiveFunc** — SetRelayTransport triggers BindUpdate to register relay ReceiveFunc
4. **LinkSetUp timing** — call LinkSetUp in Configure() after device is fully up
5. **enableRelayForPeer missing SetPeerPath** — Bind must know to route via relay
6. **filterRoutesForConnectedPeers** — defer route installation until handshake completes (protects API server traffic)
7. **SuppressPrefixlen ip rule** — fallthrough to main table when WK table has no matching route; delete stale rule before re-adding

---

## Open Issue: Relay-Only Handshake Failure

### Symptoms
- WG handshake fails when initiated **purely through relay** (`relay.mode=always`)
- Handshake works fine via direct UDP; relay fallback after direct also works (TestRelayFallback PASS)
- TestDataPlaneUnderRelay FAIL

### Confirmed Facts
- Relay server `WriteFrame+Flush` succeeds (`forwarded` log, `buffered=0`)
- But client's `readLoop` never reads data from `ReadFrame`
- Affects **all peer pairs** (not just ck-cp — w1↔w2 also fails)
- w1↔w2 keepalive worked previously because direct handshake completed first, then relay took over

### Data Flow Trace (Failure Path)
```
[w1 agent] Send(handshake_init) → bind.Send() → relay.SendToPeer()
    ↓ TCP write to relay server
[relay server] ReadFrame → ParseDataFrame → WriteFrame(dest.conn) + Flush → OK
    ↓ TCP write to w2's conn (Flush returns nil, buffered=0)
[w2 relay client] readLoop → ReadFrame(reader) → ??? blocks, data never arrives
```

### Possible Causes (Unverified)
1. **Relay server handleConn ReadFrame blocking** — relay server's reader goroutine and writer (forwarding) goroutine share the same conn; write may succeed to kernel buffer but TCP segment never reaches the peer
2. **Half-closed TCP connection** — relay server side conn is alive but receiver side is already closed; write succeeds until RST
3. **VPC isolation iptables** — relay TCP response should be allowed by ESTABLISHED rule, but Cilium BPF rule (priority 9) may interfere
4. **BindUpdate race** — SetRelayTransport → BindUpdate → Close() + Open() replaces relayCh; DeliverRelayPacket may write to old channel while new readLoop reads from new one

### Recommended Debugging Approaches
1. **tcpdump**: capture TCP packets between relay server and client to verify actual delivery
2. **goroutine dump**: `/debug/pprof/goroutine` or SIGQUIT to see where readLoop goroutine is blocked
3. **Unit test**: verify relay client→server→client bidirectional data delivery in a Go unit test (no e2e needed)

---

## e2e Test Results

| Test | Result | Notes |
|------|--------|-------|
| TestNATTypeDetected | PASS | |
| TestWireGuardTunnel | PASS | |
| TestRelayFallback | PASS | direct handshake first, then relay fallback |
| TestRelayModeAlways | PASS | |
| TestPeerCRDStatus | PASS | |
| TestAgentRestart | PASS | |
| TestMetricsEndpoint | PASS | |
| TestRelayReconnect | PASS | |
| TestDataPlaneUnderRelay | **FAIL** | relay-only handshake incomplete |

## Test Environment
- VM: `wirekube-e2e2` (multipass, arm64, Go 1.23.8, kind 0.31.0)
- CNI: cilium-kube-proxy (other 3 modes not yet tested)
- Image build: requires `docker build --no-cache` on VM when source changes (layer cache issue)
