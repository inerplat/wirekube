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

## Scenario 10: Managed Relay Unreachable

**Symptoms:**

Agent logs show `managed relay: no externally reachable address found on wirekube-relay Service`.

**Root Cause:** The managed relay Service does not have an ExternalIP, LoadBalancer
Ingress, or NodePort with a reachable node IP. The agent does **not** use
ClusterIP/CoreDNS for relay discovery because it may be unreachable on hybrid/NAT'd
nodes before the mesh tunnel is established.

**Fix:**

Ensure the relay Service has an externally reachable address:

```bash
kubectl get svc wirekube-relay -n wirekube-system -o wide
```

If using `serviceType: LoadBalancer`, wait for the external IP to be assigned.
For `NodePort`, ensure at least one cluster node has a public IP (ExternalIP or
a public InternalIP). The agent retries relay initialization with exponential
backoff, so it will connect once the external address becomes available.

---

## Scenario: Agent crashes with `creating TUN wire_kube: operation not permitted`

**Symptoms:** On Ubuntu 24.04 + kernel ≥ 6.14 hosts the agent loops with

```
ERROR   agent   setup failed, retrying
    {"error":"creating WireGuard interface: creating TUN wire_kube: operation not permitted"}
```

even though `CAP_NET_ADMIN` is granted and `/dev/net/tun` exists with `crw-rw-rw-`.

**Root cause:** containerd's default device cgroup denies write on
`/dev/net/tun` regardless of the granted Linux capabilities, and the
stock AppArmor profile (`cri-containerd.apparmor.d`) also blocks the
TUNSETIFF ioctl wireguard-go issues after opening the device. Older
distros (Ubuntu 22.04 / kernel 6.8) happen to have a more permissive
default and work with just `CAP_NET_ADMIN`, which is why the shipped
DaemonSet originally didn't set `privileged: true`.

**Fix:** The shipped `config/agent/daemonset.yaml` now enables
`privileged: true` and `appArmorProfile: Unconfined`. Re-apply or patch
an existing cluster:

```yaml
spec:
  template:
    spec:
      containers:
        - name: agent
          securityContext:
            privileged: true
            appArmorProfile:
              type: Unconfined
            capabilities:
              add: ["NET_ADMIN", "SYS_MODULE"]
```

The agent already runs with `hostNetwork: true`, so the added surface
from `privileged` is narrow — this is simply the only K8s-visible switch
that loosens the device cgroup enough for TUN creation.

---

## Scenario: Public IP appears in AllowedIPs and SSH breaks

**Symptoms:** After enabling `autoAllowedIPs.includeNodeInternalIP` on a
cloud provider whose kubelet exposes the public IP as `Node.InternalIP`
(Oracle Cloud, NCloud, etc.), SSH and kubelet traffic to other nodes
start timing out. `kubectl get wirekubepeer -o yaml` shows entries like
`[<meshIP>/32, <public-IP>/32]`.

**Root cause:** Older agent builds (≤ `v0.0.10-dev.5`) fell back to the
`Node.InternalIP` value even when it was a public address, which caused
the agent to add a `/32` route for that public IP onto `wire_kube`. The
next tunnel flap — or even just agent restart — then hijacked SSH,
kubelet, and apiserver traffic.

**Fix:** Upgrade to `v0.0.10-dev.6` or later. The agent now:

- Walks `Node.status.addresses` and uses only **private** (RFC1918 /
  CGNAT / loopback / link-local) entries.
- If none are present, scans local interfaces directly — cloud
  instances that hide a private secondary behind a kubelet-reported
  public InternalIP still get picked up this way.
- Never, under any code path, auto-publishes a public IP. Operators
  who want a specific non-standard private address can set the
  `wirekube.io/internal-ip` **node** annotation to override selection.

**Cleanup after upgrade:**

```bash
# Delete stale peer CRs so the next agent restart recreates them
# without the lingering public-IP entry.
kubectl delete wirekubepeer --all
kubectl -n wirekube-system rollout restart ds/wirekube-agent
```

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
