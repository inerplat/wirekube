# Installation

## Install with wirekubectl

Release assets contain standalone `wirekubectl` binaries for macOS and Linux on AMD64 and ARM64. Download the binary and checksum file for the version you want from the [GitHub Releases](https://github.com/inerplat/wirekube/releases) page, verify the checksum, and place the binary on your `PATH`. Each release also includes `wirekube-release.json` with the immutable container image digest embedded in that CLI.

```bash
VERSION=v0.0.14
curl -fLO "https://github.com/inerplat/wirekube/releases/download/${VERSION}/wirekubectl-linux-amd64"
curl -fLO "https://github.com/inerplat/wirekube/releases/download/${VERSION}/wirekubectl-checksums.txt"
sha256sum --check --ignore-missing wirekubectl-checksums.txt
chmod +x wirekubectl-linux-amd64
sudo install wirekubectl-linux-amd64 /usr/local/bin/wirekubectl
```

The released CLI contains the matching immutable container image digest. Interactive installation inspects the target cluster and prints the complete resource and infrastructure plan before making changes:

```bash
wirekubectl install --kubeconfig ~/.kube/config --context my-cluster
```

Non-interactive installation must explicitly select the relay topology, especially when it creates a public LoadBalancer:

```bash
wirekubectl install --kubeconfig ~/.kube/config --context my-cluster --relay load-balancer --mesh-cidr 100.96.0.0/11 --node-addresses internal-ip --yes --output json
```

Use `--dry-run` to inspect the same plan without creating the Namespace, CRDs, or any workloads. Automatic mesh CIDR selection is best effort because the CLI cannot inspect every VPC, corporate, or node route; add known routes with `--exclude-cidr`, review the selected candidate, and provide an explicit `--mesh-cidr` for non-interactive installation. Use `wirekubectl manifest` to render the exact resources selected by the plan.

`--relay-udp` creates a separate UDP Service instead of requiring a mixed-protocol LoadBalancer. With `--relay node-port`, agents use TCP NodePort `30478` while external WireGuard traffic uses UDP NodePort `30479`; supply the reachable node address as `--relay-endpoint HOST:30478`. A TCP-only relay does not provide a raw WireGuard endpoint, so external peer invites remain Pending until UDP is enabled. For `--relay external`, use `--relay-endpoint HOST:PORT` for the agent control connection and optionally use `--relay-udp-endpoint HOST:PORT` for raw WireGuard external peers.

WireKube is a cluster-wide singleton because its CRDs, mesh, and RBAC are cluster-scoped. `--namespace` chooses where workloads and inventory run; it does not permit a second installation in another namespace. Every managed resource is stamped with the inventory installation ID, and upgrade or uninstall refuses resources owned by a different installation.

## Lifecycle commands

```bash
wirekubectl status
wirekubectl doctor
wirekubectl upgrade
wirekubectl uninstall
```

`wirekubectl upgrade` keeps the stored topology unless flags override it and uses the immutable image digest embedded in the new released CLI. Upgrade snapshots existing objects and inventory before mutation; readiness, inventory, or stale-resource deletion failures restore the previous objects and inventory. Resources removed from the selected topology, such as a disabled UDP relay Service, are deleted only when their inventory ownership is still valid.

Default uninstall removes resources recorded in the installation inventory while preserving CRDs and WireKube custom resources. Destructive removal requires both `--purge` and `--confirm-purge`; ordinary `--yes` never implies data deletion.

## Container Image

The official multi-architecture container image supports `linux/amd64` and `linux/arm64`. Installation resources use the digest embedded in the matching `wirekubectl` release and do not use `latest` or development tags.

## Install from repository manifests

The repository manifests remain available for development and manual inspection. They are not the primary release installation contract because they may contain environment-specific examples and require a source checkout.

### 1. CRDs

```bash
kubectl apply -f config/crd/
```

Create the namespace used by the bundled manifests:

```bash
kubectl create namespace wirekube-system --dry-run=client -o yaml | kubectl apply -f -
```

### 2. WireKubeMesh Resource

Create a mesh configuration. See [Configuration](configuration.md) for all options.

```bash
kubectl apply -f config/examples/wirekubemesh-basic.yaml
```

### 3. Agent DaemonSet

RBAC and the DaemonSet are separate manifests:

```bash
kubectl apply -f config/agent/rbac.yaml
kubectl apply -f config/agent/daemonset.yaml
```

The DaemonSet runs with `hostNetwork: true`, `dnsPolicy: Default`, `privileged: true`, and `appArmorProfile: Unconfined`. It does not include an initContainer; the agent removes routes and the TUN interface during graceful shutdown and reconciles stale routing state during startup and periodic sync.

### 4. (Optional) Relay

For managed relay:

```bash
kubectl apply -f config/relay/deployment.yaml
```

The bundled relay Deployment has an EKS-specific `eks.amazonaws.com/nodegroup: relay-ng` node selector. Remove or replace it for other clusters.

See [Relay Architecture](../architecture/relay.md) for external relay, managed relay,
and scaling options.

## Build from Source

### Requirements

- Go 1.23+
- `wireguard-tools` (for `wg` CLI, testing)
- Linux kernel 5.6+ (or WireGuard backport module)
- `podman` or `docker` (for container images)

### Build Binaries

```bash
make build
```

Or individually:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o bin/wirekube-agent ./cmd/agent/

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o bin/wirekube-relay ./cmd/relay/
```

!!! note "Cross-Compilation"
    The agent uses Linux-specific `netlink` APIs. When building on macOS, always
    set `GOOS=linux` to avoid undefined symbol errors.

### Build Container Image (Multi-Arch)

```bash
make docker-build
```

Or manually with `podman`:

```bash
podman build --platform linux/amd64,linux/arm64 \
  --manifest inerplat/wirekube:latest .

podman manifest push inerplat/wirekube:latest \
  docker://docker.io/inerplat/wirekube:latest
```

## Relay Server Deployment

### Option A: In-Cluster (Managed)

Deploy as a Kubernetes Deployment + Service:

```bash
kubectl apply -f config/relay/deployment.yaml
```

Managed agents connect to the cluster-local `wirekube-relay-control` Service. Use an external provider endpoint when an agent must enter through the public LoadBalancer, NodePort, or an HTTP CONNECT proxy. See [Relay Entry Points](../guides/relay-entrypoints.md).

### Option B: External (Standalone)

On a server with a public IP:

```bash
wirekube-relay --addr :3478
```

Or as a systemd service:

```ini
[Unit]
Description=WireKube Relay Server
After=network.target

[Service]
ExecStart=/usr/local/bin/wirekube-relay --addr :3478
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Configure in WireKubeMesh:

```yaml
spec:
  relay:
    provider: external
    external:
      controlEndpoint: "relay.example.com:3478"
      endpoint: "relay.example.com:51820"
      transport: tcp
```

## Manual manifest uninstall

```bash
kubectl delete -f config/agent/ --ignore-not-found
kubectl delete -f config/relay/ --ignore-not-found
kubectl delete wirekubemesh --all
kubectl delete wirekubepeers --all
kubectl delete -f config/crd/ --ignore-not-found
```

!!! danger "CRD Deletion"
    Deleting CRDs removes all WireKubeMesh and WireKubePeer resources permanently.
