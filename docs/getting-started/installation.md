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

### 2. WireKubeMesh Resource

Create a mesh configuration. See [Configuration](configuration.md) for all options.

```bash
kubectl apply -f config/examples/wirekubemesh-basic.yaml
```

### 3. Agent DaemonSet

The DaemonSet manifest includes RBAC (ServiceAccount, ClusterRole, ClusterRoleBinding)
and the agent container definition. No separate RBAC step is needed.

```bash
kubectl apply -f config/agent/daemonset.yaml
```

The DaemonSet runs with `hostNetwork: true` and `dnsPolicy: ClusterFirstWithHostNet`.
An `initContainer` performs cleanup of stale WireGuard interfaces, routing rules, and
routing table entries from previous runs.

### 4. (Optional) Relay

For managed relay:

```bash
kubectl apply -f config/relay/deployment.yaml
```

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

The agent auto-discovers the relay's external address by checking the Service for
ExternalIP, LoadBalancer Ingress, or NodePort. This solves the bootstrap problem
where NAT'd nodes cannot reach ClusterIP before the mesh tunnel is up.

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
