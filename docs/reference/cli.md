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
| `--enable-ipsec` | Terminate WireKubeGateway `spec.ipsec` tunnels through charon | `WIREKUBE_ENABLE_IPSEC` or off |
| `--ipsec-vici-socket` | charon's vici socket | `WIREKUBE_IPSEC_VICI_SOCKET` or `/var/run/charon.vici` |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Alternative to `--node-name` flag | - |
| `POD_NAME` | Alternative to `--pod-name` | - |
| `POD_NAMESPACE` | Alternative to `--pod-namespace` | - |
| `WIREKUBE_INTERFACE` | Override WireGuard interface name | From WireKubeMesh |
| `WIREKUBE_KUBE_APISERVER` | Bootstrap Kubernetes API server URL | Set by `install` from `--agent-apiserver` or the kubeconfig server; in-cluster configuration when neither is usable |
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
wirekubectl uninstall [--dry-run] [--purge --confirm-purge]
wirekubectl mesh status
wirekubectl peers
wirekubectl export
wirekubectl import <file>
wirekubectl token create
wirekubectl external list
wirekubectl external get <name>
wirekubectl external invite <display-name> [flags]
wirekubectl external revoke <display-name>
sudo wirekubectl connect [flags]
wirekubectl ipsec status [gateway]
wirekubectl ipsec remote-config <gateway> [--tunnel <name>]
```

All commands accept `--kubeconfig`, `--context`, `-n/--namespace`, `--timeout`, and `--output text|json`, plus kubectl's connection flags: `--cluster`, `--user`, `-s/--server`, `--token`, `--as`, `--as-group`, `--as-uid`, `--certificate-authority`, `--client-certificate`, `--client-key`, `--insecure-skip-tls-verify`, `--tls-server-name`, `--proxy-url`, `--disable-compression`, `--username` and `--password`. `KUBECONFIG` may list several files, as with kubectl. `--namespace` names WireKube's own namespace (default `wirekube-system`) rather than the kubeconfig context namespace, except for `connect`, where it selects the namespace whose Services resolve by short name. `--timeout` stands in for kubectl's `--request-timeout`. `install` prints the plan and applies it in one run; it never prompts, so use `--dry-run` (or `manifest`, which renders the same resources) to see a plan without mutating the cluster. An unset `--relay` defaults to `load-balancer` and an unset `--mesh-cidr` is selected automatically, so automation that cares about either should pass them. `--image` is required unless the released CLI embeds its matching default image. Tag references are accepted; a digest pin (`IMAGE@sha256:DIGEST`) is optional but recommended, and every plan warns when the image is a mutable tag. `--exclude-cidr` records routes that best-effort automatic mesh CIDR selection must avoid.

`--relay-transport` selects `tcp` or `wss` and defaults to `tcp`. `--relay-endpoint` is `HOST:PORT` for TCP NodePort/external relays and `wss://HOST/PATH` for WSS. Managed WSS installs deploy Service `wirekube-relay-ws` as the HTTP backend, while the user supplies the trusted TLS Gateway or Ingress represented by the WSS URL. `--relay-udp-endpoint` is the independent raw WireGuard endpoint for external peer invites; TCP NodePort derives `HOST:30479`, WSS NodePort requires an explicit `HOST:30479`, and external relay mode accepts any valid UDP `HOST:PORT`.

`connect` issues a short-lived external peer for the local machine, runs WireGuard in-process, routes the peer's allowed destinations through it and points the cluster domain at the cluster DNS until interrupted, then deletes the peer. It needs root (or `CAP_NET_ADMIN` on Linux) and runs on Linux and macOS. Installed as `kubectl-wirekube`, the binary also works as a kubectl plugin (`kubectl wirekube connect`). See [Connect from Your Machine](../guides/connect.md).

`--agent-apiserver` sets the apiserver URL the node agents dial, and defaults to the kubeconfig server. Agents self-register their own `WireKubePeer` before the node's CNI is ready, so they cannot reach the in-cluster `kubernetes` Service ClusterIP: that route only exists once the mesh carries pod traffic, and the mesh only forms after registration. `install` therefore injects `WIREKUBE_KUBE_APISERVER` into the agent DaemonSet. A kubeconfig server that nodes cannot dial — an in-cluster Service name, `localhost`, a loopback or link-local address — is skipped instead, leaving in-cluster discovery in place. Pass `--agent-apiserver in-cluster` to skip the injection deliberately. `upgrade` preserves the stored value unless the flag is supplied.

`--listen-port` sets the WireGuard UDP port shared by every agent. When the flag is omitted, `install` and `upgrade` inherit the existing mesh's port (or the stored installation option) before falling back to `51820`, so adopting a cluster whose mesh already runs on a custom port never rebinds the agents. Changing the port of a live mesh is disruptive and is called out as a plan warning: every agent re-binds and all peer endpoints must re-discover before traffic recovers.

`--image-pull-secret` (repeatable) attaches an existing Secret in the installation namespace to every rendered Pod — the agent DaemonSet and any managed relay Deployments — so a private `--image` registry can authenticate. wirekubectl never creates or reads the Secret; create it first with `kubectl create secret docker-registry`. `upgrade` preserves the stored list unless the flag is supplied; pass `--image-pull-secret=""` to remove every stored secret reference.

`--adopt` lets `install` take over same-named resources that wirekubectl did not create — a manifest-applied or hand-patched installation. It is consent to ownership transfer: server-side-apply field conflicts with the previous manager (kubectl apply, a GitOps controller, manual patches) are resolved in wirekubectl's favor for every field the installer renders. Fields the installer does not render keep their previous owner and value. When the conflict sits in an immutable field — most commonly a foreign workload's `spec.selector` — `--adopt` replaces the object: the predecessor is deleted with orphan propagation so its Pods keep serving, and the rendered object is created and adopts them into a gradual rollout. CRDs and Namespaces are never replaced. Review drift with `wirekubectl manifest` against the live objects before adopting.

`--relay load-balancer` enables the separate UDP LoadBalancer by default; pass `--relay-udp=false` to explicitly keep it disabled. Existing installations preserve their stored UDP choice during `upgrade` unless the flag is supplied. With WSS, load-balancer mode creates the UDP LoadBalancer plus a ClusterIP WebSocket backend and omits the unused public raw TCP LoadBalancer.

`status` reports component deployment readiness separately from mesh connectivity readiness, including CRD establishment, agent image and rollout state, ReadyPeers, relay readiness, and LoadBalancer or NodePort assignment. `doctor` adds API connectivity, installation-ID ownership, and relay TCP or authenticated WSS endpoint reachability checks, writes the complete text or JSON report, and exits non-zero when any check fails. JSON command failures use a stable `schemaVersion` and `error.code`/`error.message` envelope.

WireKube supports one installation per cluster because the mesh, CRDs, and RBAC are cluster-scoped. `--namespace` selects the workload and inventory namespace; install refuses an inventory in another namespace, and upgrade or uninstall refuses resources whose installation ID does not match.

`mesh init` creates the default mesh when it is absent. When the mesh already exists, it patches only flags explicitly provided on the command line and never replaces the complete spec.

`uninstall` preserves CRDs and custom resources by default. `--purge` is rejected unless `--confirm-purge` is also present. `uninstall --dry-run` lists what would be deleted and what would be kept without touching the cluster; it deletes nothing, so run it first when the installation is carrying traffic.

`--ipsec` turns on WireKubeGateway `spec.ipsec` tunnels. It deploys the `wirekube-charon` DaemonSet, enables IPsec in the agents, and lets the agent `get` Secrets in the installation namespace. Without `--ipsec` the agent can only read the shared external ingress identity Secret `wirekube-external-ingress`, and create it (see [Ingress failover](crds.md#ingress-failover)). `--charon-image` sets the charon image. By default a released CLI uses the charon image released with it, pinned by digest; otherwise the image is the `--image` repository with a `-charon` suffix and the same tag, and an `--image` without a tag needs `--charon-image`. `--charon-node-selector key=value,...` runs charon, and its UDP 500/4500 listeners, only on the labelled nodes, so label the `peerRefs` nodes of gateways with tunnels. `upgrade` keeps these settings unless they are given again, and derives the charon image again when the agent image changes. With IPsec on, `install` and `upgrade` also wait for the charon rollout and fail when the node selector matches no node, `status` and `doctor` report charon, and `doctor` fails while a tunnel is not established.

`ipsec status` lists the tunnels with their node, phase, carrier, dataplane, reason code and message. It warns when a gateway is active on a node without a ready charon pod. `ipsec remote-config` prints the settings for the remote IPsec gateway, per tunnel and gateway node. For the pre-shared key it prints the command that reads it, not the key. See [Site-to-Site IPsec](../architecture/ipsec.md).

`wirekubectl token create` is currently a placeholder that prints guidance and does not issue a token. The WSS relay uses Kubernetes `kubectl create token` and TokenReview instead.
