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
# Check agent logs for NAT type
kubectl logs -n wirekube-system <agent-pod> | grep -i "symmetric\|nat type"

# Manual STUN check (run on the node)
stun stun.cloudflare.com 3478
stun stun.l.google.com 19302
# If mapped ports differ → Symmetric NAT
```

**Fix:**

1. Ensure relay is configured: `kubectl get wirekubemesh default -o yaml | grep relay`
2. Set `relay.mode: auto` and verify `handshakeTimeoutSeconds`
3. Check relay connectivity: `nc -zv <relay-endpoint> 3478`
4. Restart the agent: `kubectl rollout restart ds/wirekube-agent -n wirekube-system`

---

## Scenario 2: EPERM on UDP Write (Cilium)

**Symptoms:**

```
relay-proxy: write to wg: sendto: operation not permitted
```

**Root Cause:** Cilium's cgroup BPF program (`cil_sock4_sendmsg`) intercepts
`sendto()` calls and returns `EPERM`.

**Fix:**

The adaptive proxy auto-switches to `syscall.Write` mode. Check agent logs:

```
relay-proxy: EPERM detected, switching to raw syscall.Write mode
```

Alternative: set Cilium `socketLB.hostNamespaceOnly: true` to prevent BPF hooks
on `hostNetwork: true` pods.

See [CNI Compatibility](../architecture/cni-compatibility.md) for details.

---

## Scenario 3: Relay Connection Timeout

**Symptoms:**

```
relay-client: dial tcp relay.example.com:3478: i/o timeout
```

**Root Cause:** Relay server unreachable (firewall, service down, NLB health check).

**Diagnosis:**

```bash
# Test TCP connectivity from node
nc -zv <relay-endpoint> 3478

# Check relay pods
kubectl get pods -n wirekube-system -l app=wirekube-relay

# Check Service external address (for managed relay)
kubectl get svc wirekube-relay -n wirekube-system -o wide
```

**Fix:**

The relay client auto-reconnects with exponential backoff (1s–30s). If the relay
is persistently unreachable:

1. Check firewall / security group rules (TCP 3478 inbound)
2. For managed relay, verify the Service has an ExternalIP or LoadBalancer IP
3. After fixing, the agent reconnects automatically — no restart needed

---

## Scenario 4: IPSec xfrm Conflict

**Symptoms:**

- `ping` between nodes shows 100% packet loss
- `tcpdump -i wire_kube` shows both outgoing requests and incoming replies
- But `ping` still reports no packets received

**Root Cause:** Existing IPSec xfrm policies intercept traffic on the `wire_kube`
interface. The kernel applies xfrm policies to inbound packets and drops them
because they weren't encrypted with IPSec.

**Diagnosis:**

```bash
# Check if xfrm bypass is enabled
cat /proc/sys/net/ipv4/conf/wire_kube/disable_xfrm
cat /proc/sys/net/ipv4/conf/wire_kube/disable_policy
# Both should be 1

# Check for IPSec xfrm policies
ip xfrm policy show
```

**Fix:**

The agent sets `disable_xfrm=1` and `disable_policy=1` on the WireGuard interface
automatically. If these values are `0`:

1. Check that the DaemonSet mounts `/proc/sys/net` from the host
2. The volume `host-proc-sys-net` should mount hostPath `/proc/sys/net` to `/host/proc/sys/net`
3. Check agent logs for `xfrm bypass enabled` or sysctl warnings
4. Manual override: `echo 1 > /proc/sys/net/ipv4/conf/wire_kube/disable_xfrm`

---

## Scenario 5: Relay Proxy Address in CRD

**Symptoms:**

```bash
kubectl get wirekubepeer <name> -o yaml
# spec.endpoint: "127.0.0.1:54321"  ← relay proxy address, not real endpoint
```

**Root Cause:** The NAT endpoint reflection feature wrote the relay proxy's
local loopback address back into the CRD.

**Fix:**

The agent filters `127.0.0.1:*` from NAT reflection. To manually fix:

```bash
kubectl patch wirekubepeer <name> --type merge \
  -p '{"spec":{"endpoint":"<correct-public-ip>:51820"}}'
```

---

## Scenario 6: Same-VPC Nodes Cannot Communicate

**Symptoms:**

- Nodes in the same VPC/subnet fail to establish WireGuard handshake
- `wg show` shows packets sent but 0 received

**Root Cause:** Missing fwmark routing rule causes a WireGuard packet loop.

**Diagnosis:**

```bash
ip rule show | grep 0x574B
# Should show: 100: from all fwmark 0x574B lookup main
```

**Fix:**

```bash
ip rule add fwmark 0x574B lookup main priority 100
```

The agent creates this rule automatically on startup. The initContainer also
removes stale rules from previous runs.

---

## Scenario 7: Stale Interface After Crash

**Symptoms:**

```
RTNETLINK answers: File exists
```

**Root Cause:** A previous agent instance crashed and left a stale `wire_kube` interface.

**Fix:**

The DaemonSet's initContainer cleans up stale interfaces on startup. For manual fix:

```bash
ip link del wire_kube 2>/dev/null
ip rule del fwmark 0x574B 2>/dev/null
ip route flush table 22347 2>/dev/null
```

---

## Scenario 8: AllowedIPs Empty → No Traffic

**Symptoms:**

```bash
kubectl get wirekubepeer <name> -o jsonpath='{.spec.allowedIPs}'
# []
```

Peer CRD exists but no routes are added and no traffic flows.

**Root Cause:** AllowedIPs are intentionally user-managed. When empty, the agent
enters passive mode — no routes added for any peer.

**Fix:**

```bash
kubectl patch wirekubepeer <name> --type merge \
  -p '{"spec":{"allowedIPs":["<node-ip>/32"]}}'
```

---

## Scenario 9: Public Endpoint Overwritten with Private IP

**Symptoms:**

A node's CRD endpoint shows a private IP (e.g., `10.0.0.5:51820`) instead of
the STUN-discovered public IP.

**Root Cause:** Another agent's `reflectNATEndpoints` wrote a private IP from
its WireGuard kernel cache back to the CRD, overwriting the public endpoint.

**Fix:**

The agent's `reflectNATEndpoints` function prevents downgrading a public IP to
a private IP. If the CRD is already corrupted:

```bash
kubectl patch wirekubepeer <name> --type merge \
  -p '{"spec":{"endpoint":"<correct-public-ip>:51820"}}'
```

---

## Scenario 10: Managed Relay Unreachable (Chicken-and-Egg)

**Symptoms:**

NAT'd node cannot connect to the relay at `wirekube-relay.wirekube-system.svc.cluster.local:3478`
because the CNI tunnel (which provides ClusterIP routing) isn't up yet.

**Root Cause:** The node needs the relay to establish the mesh tunnel, but the
relay's ClusterIP is only reachable via the mesh tunnel.

**Fix:**

The agent auto-discovers the managed relay's external address by checking the
Service for ExternalIP, LoadBalancer Ingress, or NodePort. Ensure the relay
Service has an externally reachable address:

```bash
kubectl get svc wirekube-relay -n wirekube-system -o wide
```

If using `serviceType: LoadBalancer`, wait for the external IP to be assigned.
For `NodePort`, ensure at least one cluster node has an external IP.

---

## Diagnostic Commands Reference

| Command | Purpose |
|---------|---------|
| `wg show wire_kube` | WireGuard interface status |
| `wg show wire_kube dump` | Machine-parseable peer dump |
| `ip route show dev wire_kube` | Routes through WireGuard |
| `ip route show table 22347` | WireKube routing table |
| `ip rule show` | Routing policy (check fwmark 0x574B) |
| `ss -tnp \| grep 3478` | Relay TCP connection status |
| `kubectl get wirekubepeers -o wide` | All peer CRDs |
| `kubectl logs -n wirekube-system -l app=wirekube-agent` | Agent logs |
| `tcpdump -i wire_kube -n` | WireGuard decrypted traffic |
| `tcpdump -i eth0 udp port 51820` | WireGuard encrypted packets |
| `cat /proc/sys/net/ipv4/conf/wire_kube/disable_xfrm` | xfrm bypass status |
| `cat /proc/sys/net/ipv4/conf/wire_kube/disable_policy` | xfrm policy bypass status |
