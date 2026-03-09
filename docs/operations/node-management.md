# Node Management

## Agent Restart Behavior

The WireKube agent preserves the WireGuard kernel interface and routes across
pod restarts. Because WireGuard operates at the kernel level, direct P2P tunnels
continue forwarding traffic even while the agent process is restarting.

On startup, the agent validates the existing interface:

- **Key matches:** The interface is reused as-is. STUN discovery may fail
  (port already bound), but the existing CR endpoint is preserved.
- **Key mismatch:** The interface is torn down and recreated with the new key.

User-space resources (relay TCP connections, ICE negotiation, metrics) are
released on shutdown and re-established on the next startup. Relay connections
reconnect automatically with exponential backoff (1–30 seconds).

!!! info "Zero-downtime for direct tunnels"
    Pod restarts (rolling updates, OOM kills, node reboots) cause **no
    disruption** to direct WireGuard P2P tunnels. Relay-based connections
    experience a brief reconnection window (typically under 30 seconds).

---

## Removing a Node from the Mesh

When permanently removing a node from the WireKube mesh, two steps are required:

1. **Delete the WireKubePeer CR** so other nodes stop routing traffic to it.
2. **Run the cleanup job** on the target node to remove the WireGuard interface,
   routes, and key material.

### Step 1: Delete the WireKubePeer CR

```bash
kubectl delete wirekubepeer <node-name>
```

### Step 2: Run the Cleanup Job

```bash
# Replace TARGET_NODE_NAME with the actual node name
NODE=<node-name>
sed "s/TARGET_NODE_NAME/$NODE/g" config/cleanup/cleanup-job.yaml | kubectl apply -f -
```

The job runs on the target node and performs:

- Removes WireKube iptables rules
- Flushes all routes in the WireKube routing table (table 22347)
- Removes ip rules (fwmark and table lookup)
- Deletes the WireGuard interface (`wire_kube`)
- Removes key material from `/var/lib/wirekube`

### Step 3: Verify and Clean Up

```bash
# Check job logs
kubectl logs -n wirekube-system job/wirekube-cleanup-$NODE

# Remove the completed job
kubectl delete job -n wirekube-system wirekube-cleanup-$NODE
```

### One-liner

```bash
NODE=<node-name> && \
  kubectl delete wirekubepeer $NODE && \
  sed "s/TARGET_NODE_NAME/$NODE/g" config/cleanup/cleanup-job.yaml | kubectl apply -f -
```

!!! warning "DaemonSet label"
    If the `wirekube.io/vpn-enabled=true` label is still on the node, the
    DaemonSet will reschedule the agent after cleanup. Remove the label first:
    ```bash
    kubectl label node <node-name> wirekube.io/vpn-enabled-
    ```

---

## Manual Cleanup (SSH)

If Kubernetes access is unavailable, clean up directly on the node:

```bash
# Remove interface and routes
IFACE="wire_kube"
ip route flush table 22347
ip rule del prio 200 table 22347
ip link delete "$IFACE"

# Remove key material
rm -rf /var/lib/wirekube

# Clean up iptables (if KUBE-FIREWALL chain exists)
iptables -t filter -D KUBE-FIREWALL \
  -m mark --mark 0x574b -d 127.0.0.0/8 -j ACCEPT \
  -m comment --comment "wirekube: allow WG relay proxy on loopback" 2>/dev/null
```
