# Node Management

## Agent Restart Behavior

The current agent runs wireguard-go in userspace. A rolling restart or process failure interrupts direct and relay forwarding until the new agent process recreates or reattaches the TUN and restores peer state.

On startup, the agent validates the interface name and type:

- **Existing userspace TUN:** The engine attempts to reattach and configure it.
- **Legacy kernel WireGuard link:** The engine deletes it and migrates to a userspace TUN.
- **Foreign interface with the same name:** Startup fails rather than deleting an interface it does not own.

During graceful shutdown the agent closes relay connections, flushes WireKube routes, removes routing rules, and deletes the TUN interface. Relay connections reconnect with exponential backoff after the next startup.

!!! note "Restart impact"
    Restart duration depends on pod scheduling, Kubernetes API access, endpoint discovery, and relay availability. Treat agent restarts as a short network interruption and use rollout settings appropriate for the workload.

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

!!! warning "DaemonSet placement"
    The default DaemonSet targets every node except `wirekube.io/proxy-node=true` nodes. Before running the cleanup Job, change the DaemonSet affinity or otherwise prevent the standard agent Pod from being recreated on the target node.

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
