# CNI Compatibility

WireKube is designed to work alongside any CNI plugin without interference.
This page documents the specific compatibility considerations, especially
with Cilium.

## Route Isolation

WireKube only adds `/32` routes for node IPs with metric 200:

```
10.0.0.2/32 dev wire_kube metric 200   <- WireKube
10.244.0.0/24 dev cilium_host           <- CNI (lower metric = higher priority)
```

Pod CIDR routes are **never** inserted through `wire_kube`. This prevents
conflicts with CNI-managed routing, especially Cilium's kube-proxy replacement.

## Cilium BPF cgroup Hooks

### The Problem

Cilium attaches eBPF programs to cgroup socket operations:

| Hook | BPF Program | Trigger |
|------|------------|---------|
| `BPF_CGROUP_UDP4_SENDMSG` | `cil_sock4_sendmsg` | `sendto()` / `sendmsg()` with `msg_name` |
| `BPF_CGROUP_UDP4_RECVMSG` | `cil_sock4_recvmsg` | `recvfrom()` / `recvmsg()` |

These hooks implement Cilium's socket-level load balancing for services.
However, they can intercept UDP packets from the WireKube agent's relay proxy,
potentially returning `EPERM`.

### When Does This Happen?

The BPF hook triggers when:

1. The agent runs in a container (DaemonSet pod)
2. The container is in a cgroup that Cilium monitors
3. The agent calls `sendto()` or `sendmsg()` with a destination address (`msg_name` set)

The hook does **not** trigger when:

1. Using `write(2)` on a **connected** UDP socket (no `msg_name`)
2. The container runs in the host cgroup (some configurations)

### WireKube's Solution

The relay UDP proxy uses `net.DialUDP` to create a **connected** UDP socket:

```go
conn, _ := net.DialUDP("udp4", localAddr, remoteAddr)
```

On a connected socket, Go's `conn.Write()` translates to the `write(2)` syscall
(not `sendto(2)`). The `write(2)` syscall does **not** set `msg_name` in the
kernel's `msghdr`, so `BPF_CGROUP_UDP4_SENDMSG` is never triggered.

```
sendto(fd, buf, len, flags, dest_addr, addrlen)
  -> kernel: msghdr.msg_name = dest_addr
  -> triggers BPF_CGROUP_UDP4_SENDMSG
  -> Cilium cil_sock4_sendmsg runs -> may return EPERM

write(fd, buf, len)  [on connected socket]
  -> kernel: msghdr.msg_name = NULL (uses socket's connected address)
  -> does NOT trigger BPF_CGROUP_UDP4_SENDMSG
  -> bypasses Cilium entirely
```

### Adaptive Fallback

As an additional safety net, the proxy detects `EPERM` errors and switches
to raw `syscall.Write()` on a duplicated file descriptor:

```go
// Standard path
_, err := conn.Write(payload)
if errors.Is(err, syscall.EPERM) {
    // Switch to raw syscall.Write for all future writes
    rawMode.Store(true)
    syscall.Write(dupFD, payload)
}
```

This ensures compatibility even if future kernel or Cilium versions change
the BPF hook trigger conditions.

### Verification

In testing with Cilium (kube-proxy replacement mode) on Linux 5.15+:

- `net.DialUDP` + `conn.Write()` → **No EPERM** (confirmed: `write(2)` bypasses BPF)
- `net.ListenUDP` + `conn.WriteToUDP()` → **EPERM** (confirmed: `sendto(2)` triggers BPF)

### Alternative: Cilium Configuration

If you control the Cilium deployment, you can disable socket-level load
balancing for host namespace pods:

```yaml
# Cilium Helm values
socketLB:
  hostNamespaceOnly: true
```

This prevents `cil_sock4_sendmsg` from being attached to `hostNetwork: true`
pods, eliminating the issue at the source.

## fwmark Routing

WireKube uses `fwmark` 0x4000 to prevent WireGuard packet loops:

```bash
# WireGuard marks its own UDP packets with fwmark 0x4000
# This rule ensures marked packets use the main routing table
# (bypassing the wire_kube interface)
ip rule add fwmark 0x4000 lookup main priority 100
```

Without this, a WireGuard UDP packet destined for a peer's node IP would
match the `/32` route through `wire_kube`, get encrypted again, creating
an infinite loop.

## Tested CNI Plugins

| CNI | Status | Notes |
|-----|--------|-------|
| Cilium (kube-proxy replacement) | Verified | Connected socket bypass works |
| Cilium (with kube-proxy) | Expected to work | Same BPF hooks apply |
| Calico | Expected to work | No known socket BPF hooks |
| AWS VPC CNI | Expected to work | No known conflicts |
| Flannel | Expected to work | No known conflicts |
