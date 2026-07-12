# Installation

## Container Image

The official multi-arch container image supports `linux/amd64` and `linux/arm64`:

```bash
docker pull inerplat/wirekube:latest
```

Tagged releases are built automatically via GitHub Actions on tag push (`v*`).

## Install from Manifests

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
      endpoint: "relay.example.com:3478"
      transport: tcp
```

## Uninstall

```bash
kubectl delete -f config/agent/ --ignore-not-found
kubectl delete -f config/relay/ --ignore-not-found
kubectl delete wirekubemesh --all
kubectl delete wirekubepeers --all
kubectl delete -f config/crd/ --ignore-not-found
```

!!! danger "CRD Deletion"
    Deleting CRDs removes all WireKubeMesh and WireKubePeer resources permanently.
