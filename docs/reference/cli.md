# CLI Reference

## wirekube-agent

The WireKube agent runs on each node as part of the DaemonSet.

### Usage

```bash
wirekube-agent --node-name <name> [flags]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--node-name` | Kubernetes node name (required) | - |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Alternative to `--node-name` flag | - |
| `WIREKUBE_INTERFACE` | Override WireGuard interface name | From WireKubeMesh |
| `KUBECONFIG` | Path to kubeconfig file | In-cluster config |

### Behavior

1. Reads WireKubeMesh `default` for configuration
2. Creates WireGuard interface and generates/loads key pair
3. Runs STUN endpoint discovery (2+ servers for NAT type detection)
4. Registers as a WireKubePeer CRD
5. Watches all WireKubePeer CRDs for changes
6. Configures WireGuard peers and routes
7. Connects to relay pool (if configured) with auto-reconnect
8. Monitors handshakes; activates relay fallback if needed
9. Periodically probes relayed peers for direct upgrade
10. Sets `disable_xfrm` and `disable_policy` on the WireGuard interface

---

## wirekube-relay

The WireKube relay server bridges WireGuard traffic over TCP.

### Usage

```bash
wirekube-relay --addr <listen-address>
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--addr` | TCP listen address | `:3478` |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WIREKUBE_RELAY_ADDR` | Alternative to `--addr` flag | `:3478` |

### Example

```bash
wirekube-relay --addr :3478
wirekube-relay --addr 10.0.0.1:3478
```

---

## wirekubectl

CLI tool for inspecting mesh status.

### Usage

```bash
wirekubectl mesh status
wirekubectl peers
wirekubectl peer <peer-name>
```
