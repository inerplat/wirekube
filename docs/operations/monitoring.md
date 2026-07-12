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
| `path monitor: new peer, starting on relay` | New peer entered the safe relay-first path |
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
| `wirekube_node_nat_type` | Gauge | node | NAT type (0=unknown, 1=cone, 2=symmetric, 3=port-restricted-cone, 4=open) |
| `wirekube_peers_total` | Gauge | — | Total WireKubePeer count |
| `wirekube_relayed_peers_total` | Gauge | — | Peers currently using relay |
| `wirekube_direct_peers_total` | Gauge | — | Peers currently using direct P2P |
| `wirekube_peer_ice_state` | Gauge | source, peer | ICE state (0=relay, 1=gathering, 2=checking, 3=connected, 4=birthday, 5=failed) |

### Grafana Dashboard

Import the pre-built dashboard from `config/grafana/wirekube-dashboard.json`.
It includes:

- **Mesh Overview**: peer count, relayed peers, NAT type, connected peers
- **Peer Latency**: time-series graph with per-peer ICMP RTT
- **Transport Mode**: color-coded table (direct=green, relay=red, mixed=yellow)
- **Traffic**: send/receive byte rates per peer
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
