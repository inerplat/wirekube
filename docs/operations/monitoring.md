# Monitoring

## WireGuard Interface Status

```bash
# Show all peers and their status
wg show wire_kube

# Detailed dump (parseable format)
wg show wire_kube dump
```

Key fields to monitor:

| Field | Meaning | Healthy Value |
|-------|---------|---------------|
| `latest handshake` | Time since last successful handshake | < 2 minutes |
| `transfer` | Bytes received/sent | Non-zero if traffic flowing |
| `endpoint` | Peer's current endpoint | Public IP or 127.0.0.1:xxx (relay) |

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
node-cp       true       direct     stun     1.2.3.4:51820
node-w1       true       direct     internal 172.20.1.6:51820
node-w2       true       direct     stun     5.6.7.8:51820
node-w3       true       relay      stun     10.20.2.6:51820
```

### Mesh Configuration

```bash
kubectl get wirekubemesh default -o yaml
```

## Agent Logs

```bash
# All agents
kubectl logs -n kube-system -l app=wirekube-agent --tail=50

# Specific node
kubectl logs -n kube-system -l app=wirekube-agent \
  --field-selector spec.nodeName=node-1 --tail=100
```

Key log messages:

| Log Pattern | Meaning |
|-------------|---------|
| `endpoint discovered: X.X.X.X:51820 via stun` | STUN discovery succeeded |
| `peer handshake completed` | Direct P2P working |
| `handshake timeout, activating relay` | Falling back to relay |
| `relay connected` | TCP connection to relay established |
| `EPERM detected, switching to raw syscall.Write` | Cilium BPF bypass activated |

## Network Diagnostics

### Route Table

```bash
# Show WireKube routes
ip route show dev wire_kube

# Expected output:
# 172.20.1.6/32 dev wire_kube metric 200
# 10.20.2.6/32  dev wire_kube metric 200
```

### Connectivity Test

```bash
# Ping all mesh peers
for ip in $(kubectl get wirekubepeers -o jsonpath='{.items[*].spec.allowedIPs[0]}' \
  | tr ' ' '\n' | sed 's|/32||'); do
  echo -n "$ip: "
  ping -c 3 -W 2 "$ip" 2>/dev/null | tail -1 || echo "unreachable"
done
```

### Relay Connection

```bash
# Check if relay TCP connection is established
ss -tnp | grep 3478

# Check relay server health
nc -zv relay.example.com 3478
```

### fwmark Rules

```bash
# Verify anti-loop rule exists
ip rule show | grep 0x4000

# Expected:
# 100: from all fwmark 0x4000 lookup main
```

## Health Check Script

A comprehensive health check that validates the entire mesh:

```bash
#!/bin/bash
echo "=== WireKube Health Check ==="

echo -e "\n--- Interface ---"
wg show wire_kube 2>/dev/null || echo "ERROR: wire_kube interface not found"

echo -e "\n--- Routes ---"
ip route show dev wire_kube 2>/dev/null || echo "ERROR: no routes"

echo -e "\n--- fwmark Rule ---"
ip rule show | grep -q 0x4000 && echo "OK: fwmark rule present" || echo "ERROR: fwmark rule missing"

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
