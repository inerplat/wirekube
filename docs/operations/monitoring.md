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
kubectl logs -n wirekube-system -l app=wirekube-agent --tail=50
kubectl logs -n wirekube-system -l app=wirekube-agent \
  --field-selector spec.nodeName=<node-name> --tail=100
```

Key log messages:

| Log Pattern | Meaning |
|-------------|---------|
| `endpoint discovered: X.X.X.X:51820 via stun` | STUN discovery succeeded |
| `symmetric NAT detected` | Node behind Symmetric NAT |
| `peer handshake completed` | Direct P2P working |
| `handshake timeout, activating relay` | Falling back to relay |
| `relay connected` | TCP connection to relay established |
| `relay-pool: connected to new replica` | New relay instance joined pool |
| `peer X: upgraded to direct` | Relayed peer successfully probed for direct |
| `peer X: direct probe failed, staying on relay` | Direct probe attempt failed |
| `EPERM detected, switching to raw syscall.Write` | Cilium BPF bypass activated |
| `xfrm bypass enabled on wire_kube` | IPSec xfrm bypass set |

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
