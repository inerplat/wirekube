# Monitoring

## WireGuard Interface Status

```bash
wg show wire_kube
wg show wire_kube dump
```

Key fields to monitor:

| Field | Meaning | Healthy Value |
|-------|---------|---------------|
| `latest handshake` | Time since last successful handshake | < 2 minutes |
| `transfer` | Bytes received/sent | Non-zero if traffic flowing |
| `endpoint` | Peer's current endpoint | Public IP (direct) or 127.0.0.1:xxx (relay) |

## Kubernetes Resources

### Peer Status

```bash
kubectl get wirekubepeers -o custom-columns=\
  NAME:.metadata.name,\
  CONNECTED:.status.connected,\
  TRANSPORT:.status.transportMode,\
  METHOD:.status.endpointDiscoveryMethod,\
  ENDPOINT:.spec.endpoint
```

Example output:

```
NAME          CONNECTED  TRANSPORT  METHOD   ENDPOINT
node-a        true       direct     stun     203.0.113.5:51820
node-b        true       direct     internal 10.0.0.6:51820
node-c        true       relay      stun     198.51.100.10:51820
node-d        true       mixed      stun     192.0.2.20:51820
```

Transport mode values:

| Value | Meaning |
|-------|---------|
| `direct` | All peers connected via direct P2P |
| `relay` | Node behind Symmetric NAT, traffic routes via relay |
| `mixed` | Some peers direct, some relayed |

### Mesh Configuration

```bash
kubectl get wirekubemesh default -o yaml
```

## Agent Logs

```bash
kubectl logs -n wirekube-system -l app.kubernetes.io/name=wirekube-agent --tail=50
kubectl logs -n wirekube-system -l app.kubernetes.io/name=wirekube-agent \
  --field-selector spec.nodeName=<node-name> --tail=100
```

Key log messages:

| Log Pattern | Meaning |
|-------------|---------|
| `[stun] symmetric NAT detected` | STUN servers observed endpoint-dependent port mappings |
| `relay connected` | Agent initialized a relay pool endpoint |
| `relay-client: connected to` | A relay TCP client connected and registered |
| `path monitor: new peer, starting on warm` | New peer entered Warm (both legs) while the direct path is unproven |
| `path monitor: transition` | Direct/Warm/Relay change, with the age of the evidence that caused it |
| `upgraded to direct (relay proxy in standby)` | A direct path was proven and promoted |
| `active probe failed, reverting to relay` | Direct probing failed and relay remained active |
| `relay-client: reconnect failed` | Relay reconnect is backing off after a failure |
| `[wireguard] xfrm bypass enabled` | IPSec xfrm bypass was applied |

## Prometheus Metrics

The agent exposes Prometheus metrics on `:9090/metrics`. The provided Service selects Pods with `app.kubernetes.io/name=wirekube-agent`, including the standard and proxy-node DaemonSets, and the ServiceMonitor selects that Service by its `app=wirekube-agent` label.

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wirekube_peer_latency_seconds` | Gauge | source, peer, transport | ICMP RTT to peer |
| `wirekube_peer_bytes_sent_total` | Gauge | source, peer | Total bytes sent via WireGuard |
| `wirekube_peer_bytes_received_total` | Gauge | source, peer | Total bytes received via WireGuard |
| `wirekube_peer_connected` | Gauge | source, peer, nat_type | Connection status (1=connected, 0=disconnected) |
| `wirekube_peer_transport_mode` | Gauge | source, peer | Transport (1=direct, 2=relay) |
| `wirekube_peer_last_handshake_seconds` | Gauge | source, peer | Seconds since last WireGuard handshake |
| `wirekube_suppressed_routes` | Gauge | source, reason | Routes withheld from the WireKube table by routing policy (`local`, `excluded`) |
| `wirekube_peer_direct_rx_age_seconds` | Gauge | source, peer | Seconds since the last packet from this peer on the direct UDP socket (the watermark PathMonitor demotes on) |
| `wirekube_peer_endpoint_type` | Gauge | source, peer | Where the WG endpoint points (0=none, 1=direct address, 2=relay loopback proxy) |
| `wirekube_node_nat_type` | Gauge | node | NAT type (0=unknown, 1=cone, 2=symmetric, 3=port-restricted-cone, 4=open) |
| `wirekube_peers_total` | Gauge | — | Total WireKubePeer count |
| `wirekube_relayed_peers_total` | Gauge | — | Peers currently using relay |
| `wirekube_direct_peers_total` | Gauge | — | Peers currently using direct P2P |
| `wirekube_peer_ice_state` | Gauge | source, peer | ICE state (0=relay, 1=gathering, 2=checking, 3=connected, 4=birthday, 5=failed) |
| `wirekube_peer_send_packets_total` | Gauge | source, peer, leg | Packets sent to the peer by leg (`direct_only`, `dual`, `relay_only`). `dual` over the sum is the share this node mirrors onto the relay |
| `wirekube_peer_heartbeat_pongs_total` | Gauge | source, peer | Heartbeat pongs matched on the direct leg |
| `wirekube_peer_heartbeat_auth_failures_total` | Gauge | source, peer | Heartbeat frames claiming this peer that failed authentication |
| `wirekube_peer_heartbeat_replay_drops_total` | Gauge | source, peer | Heartbeat frames dropped as stale, unknown or already consumed |
| `wirekube_peer_direct_rtt_seconds` | Gauge | source, peer | Round-trip time of the last heartbeat pong |
| `wirekube_peer_direct_pong_age_seconds` | Gauge | source, peer | Seconds since the last pong. With `peer_last_handshake_seconds` this finds a path that answers pings while the session behind it is dead |
| `wirekube_peer_mtu_probe_stale` | Gauge | source, peer | 1 while MTU-sized probes go unanswered though small ones are answered, which forces dual-send |

### Relay Metrics

The relay exposes Prometheus metrics on `:9091/metrics` (`--metrics-addr`, env `WIREKUBE_RELAY_METRICS_ADDR`; empty disables) together with a trivial `/healthz`. The endpoint is published only through the cluster-local `wirekube-relay-metrics` Service (chart: `relay.metrics.*`), never through the relay's LoadBalancer Service: the `dest` label reveals peer key prefixes and traffic shape.

`dest` is the first 8 bytes of the destination's WireGuard public key in hex, the same prefix the relay logs print. It exists only for peers currently registered on that replica; the series are deleted when the peer disconnects, so cardinality follows connected clients. A destination key that a sender merely names is never used as a label. `class` is `ctrl` for WireGuard handshake initiation/response/cookie payloads and relay control frames (bimodal hint, NAT probe, relay probe), `data` for everything else; control frames have their own queue and are written ahead of data.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wirekube_relay_frames_forwarded_total` | Counter | class, dest | Frames enqueued for delivery to a registered local peer |
| `wirekube_relay_frames_dropped_total` | Counter | reason, class, dest | Frames not delivered to a registered local peer. `reason` is `queue_tail` (send queue full, newest frame dropped), `gone` (connection already closed), `write_error` (socket write or flush failed; every frame in the failed batch is counted) or `shutdown` (still queued when the connection tore down) |
| `wirekube_relay_frames_dropped_unknown_dest_total` | Counter | — | Data frames and bimodal hints whose destination key is registered on no replica |
| `wirekube_relay_clients` | Gauge | — | Peers currently registered on this replica |
| `wirekube_relay_queue_depth` | Gauge | class, dest | Frames waiting in a peer's send queue, sampled after each enqueue and dequeue (capacity 64 ctrl, 256 data) |

### Grafana Dashboard

Import the pre-built dashboard from `config/grafana/wirekube-dashboard.json`.
It includes:

- **Mesh Overview**: peer count, relayed peers, NAT type, connected peers
- **Peer Latency**: time-series graph with per-peer ICMP RTT
- **Transport Mode**: color-coded table (direct=green, relay=red, mixed=yellow)
- **Traffic**: send/receive byte rates per peer
- **Path Diagnostics**: direct-socket receive age, endpoint type (direct vs relay proxy), and bypass route suppression per node
- **Handshake & Health**: last handshake age and connection state timeline

### ServiceMonitor Setup

```bash
kubectl apply -f config/agent/servicemonitor.yaml
```

This creates a headless Service and ServiceMonitor for Prometheus Operator
to automatically scrape agent metrics.

## Network Diagnostics

### Route Table

```bash
ip route show dev wire_kube
ip route show table 22347
```

### Routing Rules

```bash
ip rule show | grep 0x574B
# Expected: 100: from all fwmark 0x574B lookup main
```

### IPSec xfrm Bypass

```bash
cat /proc/sys/net/ipv4/conf/wire_kube/disable_xfrm    # should be 1
cat /proc/sys/net/ipv4/conf/wire_kube/disable_policy   # should be 1
```

### Relay Connection

```bash
ss -tnp | grep 3478
```

### Connectivity Test

```bash
for ip in $(kubectl get wirekubepeers -o jsonpath='{.items[*].spec.allowedIPs[0]}' \
  | tr ' ' '\n' | sed 's|/32||'); do
  echo -n "$ip: "
  ping -c 3 -W 2 "$ip" 2>/dev/null | tail -1 || echo "unreachable"
done
```

## Health Check Script

```bash
#!/bin/bash
echo "=== WireKube Health Check ==="

echo -e "\n--- Interface ---"
wg show wire_kube 2>/dev/null || echo "ERROR: wire_kube interface not found"

echo -e "\n--- Routes ---"
ip route show dev wire_kube 2>/dev/null || echo "ERROR: no routes"

echo -e "\n--- Routing Table 22347 ---"
ip route show table 22347 2>/dev/null || echo "ERROR: table empty"

echo -e "\n--- fwmark Rule ---"
ip rule show | grep -q 0x574B && echo "OK: fwmark rule present" || echo "ERROR: fwmark rule missing"

echo -e "\n--- xfrm Bypass ---"
[ "$(cat /proc/sys/net/ipv4/conf/wire_kube/disable_xfrm 2>/dev/null)" = "1" ] \
  && echo "OK: disable_xfrm=1" || echo "WARN: disable_xfrm not set"
[ "$(cat /proc/sys/net/ipv4/conf/wire_kube/disable_policy 2>/dev/null)" = "1" ] \
  && echo "OK: disable_policy=1" || echo "WARN: disable_policy not set"

echo -e "\n--- Relay Connection ---"
ss -tnp 2>/dev/null | grep 3478 && echo "OK: relay connected" || echo "INFO: no relay connection"

echo -e "\n--- Peer Connectivity ---"
for peer in $(wg show wire_kube peers 2>/dev/null); do
  endpoint=$(wg show wire_kube endpoints | grep "$peer" | awk '{print $2}')
  handshake=$(wg show wire_kube latest-handshakes | grep "$peer" | awk '{print $2}')
  now=$(date +%s)
  age=$((now - handshake))
  if [ "$age" -lt 180 ]; then
    echo "  $peer ($endpoint): OK (handshake ${age}s ago)"
  else
    echo "  $peer ($endpoint): STALE (handshake ${age}s ago)"
  fi
done
```
