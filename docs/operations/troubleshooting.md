# Troubleshooting

Detailed scenarios from real-world debugging sessions with solutions.

---

## Scenario 1: Handshake Never Completes

**Symptoms:**

```
wg show wire_kube
  peer: <pubkey>
    endpoint: 1.2.3.4:51820
    latest handshake: (none)
    transfer: 0 B received, 1.2 KiB sent
```

**Root Cause:** Both peers are behind Symmetric NAT. STUN-discovered endpoints
are unreliable because each new destination gets a different NAT mapping.

**Diagnosis:**

```bash
# Check NAT type (run on each node)
# If mapped ports differ -> Symmetric NAT
stun stun.cloudflare.com 3478
stun stun.l.google.com 19302

# Check firewall rules
nc -u -w3 <peer-ip> 51820 <<< "test"
```

**Fix:**

1. Ensure relay is configured: `kubectl get wirekubemesh default -o yaml | grep relay`
2. Set `relay.mode: auto` and verify `handshakeTimeoutSeconds`
3. Check relay connectivity: `nc -zv relay.example.com 3478`
4. Restart the agent: `kubectl rollout restart ds/wirekube-agent -n kube-system`

---

## Scenario 2: EPERM on UDP Write

**Symptoms:**

```
relay-proxy: write to wg: sendto: operation not permitted
```

**Root Cause:** Cilium's cgroup BPF program (`cil_sock4_sendmsg`) intercepts
`sendto()` calls and returns `EPERM`.

**Diagnosis:**

```bash
# Check BPF programs on the container's cgroup
bpftool cgroup show /sys/fs/cgroup/kubepods/... | grep sock

# Check agent logs for auto-detection
kubectl logs -n kube-system <agent-pod> | grep EPERM
```

**Fix:**

The adaptive proxy should auto-switch to `syscall.Write` mode. Verify with:

```
relay-proxy: EPERM detected, switching to raw syscall.Write mode
```

If not auto-switching:

- Update the agent to v0.0.1+ which includes the adaptive proxy
- Alternative: set Cilium `socketLB.hostNamespaceOnly: true`

---

## Scenario 3: Relay Connection Timeout

**Symptoms:**

```
relay-client: dial tcp relay.example.com:3478: i/o timeout
```

**Root Cause:** Relay server unreachable. Common causes:

1. Relay service not running
2. Firewall/security group blocking TCP 3478
3. NLB health check hasn't detected healthy relay yet

**Diagnosis:**

```bash
# 1. Verify relay is running
ssh relay-host 'ss -tlnp | grep 3478'

# 2. Test TCP connectivity from node
nc -zv relay.example.com 3478

# 3. Check security group / ACG rules
# Ensure TCP 3478 inbound is allowed

# 4. If behind NLB, check health check status
# NLB needs 60+ seconds to detect healthy targets
```

**Fix:**

```bash
# Add TCP 3478 to security group (example: NCloud ACG)
# Then wait for NLB health checks (60s+)
# Finally restart agents
kubectl rollout restart ds/wirekube-agent -n kube-system
```

!!! tip "NLB Timing"
    After fixing the relay server, wait at least 60 seconds for the NLB
    health checks to detect the healthy backend before restarting agents.

---

## Scenario 4: Relay Flip-Flop

**Symptoms:**

```
peer <pubkey>: switching to relay mode
peer <pubkey>: direct handshake detected, switching to direct
peer <pubkey>: handshake timeout, switching to relay mode
(repeats endlessly)
```

**Root Cause:** The agent misinterprets a successful handshake *through the relay*
as proof of direct reachability, then switches to direct mode where it fails again.

**Fix:**

Agent v0.0.1+ includes anti-flip-flop logic:

- Once a peer enters relay mode via handshake timeout, it stays in relay mode
- Relay-mediated handshakes are not counted as "direct connectivity"
- Update to the latest agent version

---

## Scenario 5: NAT Reflection Corrupts CRD

**Symptoms:**

```bash
kubectl get wirekubepeer node-xxx -o yaml
# spec.endpoint: "127.0.0.1:54321"  <- WRONG (relay proxy address)
```

**Root Cause:** The NAT endpoint reflection feature writes the relay proxy's
local loopback address back into the CRD, overwriting the real endpoint.

**Fix:**

Agent v0.0.1+ filters `127.0.0.1:*` from NAT reflection. To manually fix:

```bash
kubectl patch wirekubepeer node-xxx --type merge \
  -p '{"spec":{"endpoint":"<correct-public-ip>:51820"}}'
```

---

## Scenario 6: Same-VPC Nodes Cannot Communicate

**Symptoms:**

- Nodes in the same VPC/subnet fail to establish WireGuard handshake
- `wg show` shows packets sent but 0 received

**Root Cause:** Missing `fwmark` routing rule causes a WireGuard packet loop.
The encrypted packet's destination matches the `/32` route through `wire_kube`,
getting encrypted again infinitely.

**Diagnosis:**

```bash
ip rule show | grep 0x574B
# Should show: 100: from all fwmark 0x574B lookup main
```

**Fix:**

```bash
ip rule add fwmark 0x574B lookup main priority 100
```

The agent should create this rule automatically on startup. If missing,
check agent logs for errors during initialization.

---

## Scenario 7: WireGuard Interface Already Exists

**Symptoms:**

```
RTNETLINK answers: File exists
```

**Root Cause:** A previous agent instance crashed and left a stale `wire_kube` interface.

**Fix:**

The agent performs cleanup on startup. For manual intervention:

```bash
ip link del wire_kube 2>/dev/null
```

Then restart the agent pod.

---

## Scenario 8: AllowedIPs Empty for New Peers

**Symptoms:**

```bash
kubectl get wirekubepeer node-xxx -o jsonpath='{.spec.allowedIPs}'
# []
```

New node joined the mesh, peer CRD created, but no AllowedIPs → no routes → no traffic.

**Root Cause:** The agent's initial peer creation didn't populate AllowedIPs.

**Fix:**

```bash
# Find the node's internal IP
kubectl get node node-xxx -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'

# Patch the peer
kubectl patch wirekubepeer node-xxx --type merge \
  -p '{"spec":{"allowedIPs":["<internal-ip>/32"]}}'
```

---

## Scenario 9: High Latency Through Relay

**Symptoms:**

- Ping between relayed nodes: 40-60ms
- Direct P2P nodes: < 2ms

**Root Cause:** This is expected behavior. The relay path adds:

1. Agent → NAT → Relay TCP hop (geographic distance)
2. Relay → NAT → Agent TCP hop (geographic distance)

**Benchmark Reference:**

| Path | Mode | Latency |
|------|------|---------|
| Same VPC, private↔private | Direct | ~0.5ms |
| Cross VPC, private↔private | Relay | ~1.5-2ms |
| Private↔public (same region) | Direct | ~0.7ms |
| Cross region (e.g., Japan↔Korea) | Relay | ~42-54ms |

**Optimization:**

- Deploy relay geographically close to the majority of nodes
- Use public IP nodes as direct P2P anchor points
- For cross-region, consider deploying relay in each region (future feature)

---

## Scenario 10: Relay Service Flag Mismatch

**Symptoms:**

```
flag provided but not defined: -listen
```

**Root Cause:** The relay binary was started with `--listen :3478` instead
of the correct flag `--addr :3478`.

**Fix:**

```bash
# Correct systemd unit
ExecStart=/usr/local/bin/wirekube-relay --addr :3478
```

Always verify the relay binary's flags with:

```bash
wirekube-relay --help
```

---

## Diagnostic Commands Reference

| Command | Purpose |
|---------|---------|
| `wg show wire_kube` | WireGuard interface status |
| `wg show wire_kube dump` | Machine-parseable peer dump |
| `ip route show dev wire_kube` | Routes through WireGuard |
| `ip rule show` | Routing policy (check fwmark) |
| `ss -tnp \| grep 3478` | Relay TCP connection status |
| `kubectl get wirekubepeers -o wide` | All peer CRDs |
| `kubectl logs -n kube-system -l app=wirekube-agent` | Agent logs |
| `tcpdump -i wire_kube -n` | WireGuard decrypted traffic |
| `tcpdump -i eth0 udp port 51820` | WireGuard encrypted packets |
| `conntrack -L -p udp --dport 51820` | NAT connection tracking |
