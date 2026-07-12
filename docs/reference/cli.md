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
| `--pod-name` | Agent Pod name used for metrics annotations | `POD_NAME` |
| `--pod-namespace` | Agent Pod namespace | `POD_NAMESPACE` |
| `--mesh-name` | WireKubeMesh resource name | `default` |
| `--interface` | WireGuard interface name override | `WIREKUBE_INTERFACE` or mesh value |
| `--listen-port` | WireGuard UDP listen port fallback | `51820` |
| `--mtu` | WireGuard interface MTU fallback | `1420` |
| `--kube-apiserver` | Kubernetes API server URL override | `WIREKUBE_KUBE_APISERVER` |
| `--metrics-addr` | Metrics and health HTTP listen address | `:9090` |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Alternative to `--node-name` flag | - |
| `POD_NAME` | Alternative to `--pod-name` | - |
| `POD_NAMESPACE` | Alternative to `--pod-namespace` | - |
| `WIREKUBE_INTERFACE` | Override WireGuard interface name | From WireKubeMesh |
| `WIREKUBE_KUBE_APISERVER` | Bootstrap Kubernetes API server URL | In-cluster configuration |
| `WIREKUBE_RELAY_PROXY` | Relay proxy policy (`environment` or `disabled`) | `disabled` |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Standard proxy environment used when relay proxy mode is enabled | - |
| `KUBECONFIG` | Path to kubeconfig file | In-cluster config |

### Behavior

1. Reads WireKubeMesh `default` for configuration
2. Creates WireGuard interface and generates/loads key pair
3. Runs STUN endpoint discovery (2+ servers for NAT type detection)
4. Registers as a WireKubePeer CRD
5. Watches all WireKubePeer CRDs for changes
6. Configures WireGuard peers and routes
7. Connects to relay pool (if configured) with auto-reconnect
8. Starts peers with relay availability when configured and monitors direct-path health
9. Promotes healthy direct paths and reverts stale paths to relay
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
| `--forwarder-port-low` | Lowest legacy external-peer UDP forwarder port | `0` (disabled) |
| `--forwarder-port-high` | Highest legacy external-peer UDP forwarder port | `0` (disabled) |
| `--external-wg-addr` | Shared raw-WireGuard UDP listener | empty (disabled) |
| `--external-wg-ingress-pubkey` | Fixed ingress WireGuard public key for the shared listener | empty (dynamic fanout) |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WIREKUBE_RELAY_ADDR` | Alternative to `--addr` flag | `:3478` |
| `WIREKUBE_FORWARDER_PORT_LOW` | Alternative to `--forwarder-port-low` | `0` |
| `WIREKUBE_FORWARDER_PORT_HIGH` | Alternative to `--forwarder-port-high` | `0` |
| `WIREKUBE_EXTERNAL_WG_ADDR` | Alternative to `--external-wg-addr` | empty |
| `WIREKUBE_EXTERNAL_WG_INGRESS_PUBKEY` | Alternative to `--external-wg-ingress-pubkey` | empty |

### Example

```bash
wirekube-relay --addr :3478
wirekube-relay --addr 10.0.0.1:3478
```

---

## wirekubectl

CLI tool for installing WireKube and managing mesh resources without requiring a source checkout.

### Usage

```bash
wirekubectl version
wirekubectl install [flags]
wirekubectl manifest [flags]
wirekubectl status
wirekubectl doctor
wirekubectl upgrade [flags]
wirekubectl uninstall [--purge --confirm-purge]
wirekubectl mesh status
wirekubectl peers
wirekubectl export
wirekubectl import <file>
wirekubectl token create
wirekubectl external list
wirekubectl external get <name>
wirekubectl external invite <display-name> [flags]
wirekubectl external revoke <display-name>
```

All commands accept `--kubeconfig`, `--context`, `--namespace`, `--timeout`, and `--output text|json`. `install --dry-run` performs cluster inspection and prints the installation plan without mutation. Non-interactive `install --yes` requires explicit `--relay` and `--mesh-cidr` selections and an image pinned as `IMAGE@sha256:DIGEST` unless the released CLI already contains its matching default image digest. `--exclude-cidr` records routes that best-effort automatic mesh CIDR selection must avoid.

`--relay-endpoint` is the TCP control endpoint for NodePort or external relay modes. `--relay-udp-endpoint` is a separate raw WireGuard endpoint for external peer invites and is valid with `--relay external`; NodePort derives UDP port `30479` when `--relay-udp` is enabled. TCP-only relay installations leave external peers Pending instead of publishing an unusable UDP configuration.

`status` reports component deployment readiness separately from mesh connectivity readiness, including CRD establishment, agent image and rollout state, ReadyPeers, relay readiness, and LoadBalancer or NodePort assignment. `doctor` adds API connectivity, installation-ID ownership, and relay TCP reachability checks, writes the complete text or JSON report, and exits non-zero when any check fails. JSON command failures use a stable `schemaVersion` and `error.code`/`error.message` envelope.

WireKube supports one installation per cluster because the mesh, CRDs, and RBAC are cluster-scoped. `--namespace` selects the workload and inventory namespace; install refuses an inventory in another namespace, and upgrade or uninstall refuses resources whose installation ID does not match.

`mesh init` creates the default mesh when it is absent. When the mesh already exists, it patches only flags explicitly provided on the command line and never replaces the complete spec.

`uninstall` preserves CRDs and custom resources by default. `--purge` is rejected unless `--confirm-purge` is also present, and `--yes` alone never authorizes purge.

`wirekubectl token create` is currently a placeholder that prints guidance and does not issue a token. The WSS relay uses Kubernetes `kubectl create token` and TokenReview instead.
