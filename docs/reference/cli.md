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
| `WIREKUBE_KUBE_APISERVER` | API server URL (overrides in-cluster discovery) | - |
| `WIREKUBE_INTERFACE` | Override WireGuard interface name | From WireKubeMesh |
| `KUBECONFIG` | Path to kubeconfig file | In-cluster config |

### Behavior

1. Reads WireKubeMesh `default` for configuration
2. Creates WireGuard interface and generates/loads key pair
3. Registers as a WireKubePeer CRD
4. Watches all WireKubePeer CRDs for changes
5. Runs endpoint discovery (STUN, annotations, etc.)
6. Configures WireGuard peers and routes
7. Monitors handshakes; activates relay fallback if needed

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

### Example

```bash
# Listen on all interfaces, port 3478
wirekube-relay --addr :3478

# Listen on specific interface
wirekube-relay --addr 10.0.0.1:3478
```

---

## wirekubectl

CLI tool for inspecting mesh status.

### Usage

```bash
# Show mesh status
wirekubectl mesh status

# List all peers
wirekubectl peers

# Show peer details
wirekubectl peer node-my-node
```
