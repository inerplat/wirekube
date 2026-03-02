# Installation

## Container Image

The official multi-arch container image supports both `amd64` and `arm64`:

```bash
docker pull inerplat/wirekube:v0.0.1
```

## Install from Manifests

### 1. CRDs

```bash
kubectl apply -f config/crd/wirekubemesh.yaml
kubectl apply -f config/crd/wirekubepeer.yaml
```

### 2. RBAC

```bash
kubectl apply -f config/rbac/
```

### 3. WireKubeMesh Resource

Create a mesh configuration. See [Configuration](configuration.md) for all options.

```bash
kubectl apply -f config/operator/wirekubemesh-default.yaml
```

### 4. Agent DaemonSet

```bash
kubectl apply -f config/agent/daemonset.yaml
```

!!! warning "API Server Endpoint"
    The DaemonSet manifest contains `WIREKUBE_KUBE_APISERVER` which must point
    to your cluster's API server. Update this before applying.

## Build from Source

### Requirements

- Go 1.23+
- `wireguard-tools` (for `wg` CLI)
- Linux kernel 5.6+ (or WireGuard backport module)

### Build Binaries

```bash
export PATH="$PATH:/usr/local/go/bin"
go mod tidy

# Agent
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/wirekube-agent ./cmd/agent/

# Relay server
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/wirekube-relay ./cmd/relay/
```

### Build Container Image (Multi-Arch)

```bash
podman build --platform linux/amd64,linux/arm64 \
  --manifest inerplat/wirekube:v0.0.1 .

podman manifest push inerplat/wirekube:v0.0.1 \
  docker://docker.io/inerplat/wirekube:v0.0.1
```

## Relay Server Deployment

### Option A: Systemd Service

On a server with a public IP (or behind a TCP load balancer):

```bash
# Copy binary
scp bin/wirekube-relay root@relay-host:/usr/local/bin/

# Create systemd unit
cat > /etc/systemd/system/wirekube-relay.service <<EOF
[Unit]
Description=WireKube Relay Server
After=network.target

[Service]
ExecStart=/usr/local/bin/wirekube-relay --addr :3478
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now wirekube-relay
```

### Option B: Kubernetes Deployment

```bash
kubectl apply -f config/relay/deployment.yaml
```

See [Relay Architecture](../architecture/relay.md) for details.

## Uninstall

```bash
kubectl delete -f config/agent/ --ignore-not-found
kubectl delete wirekubemesh --all
kubectl delete wirekubepeers --all
kubectl delete -f config/rbac/ --ignore-not-found
kubectl delete -f config/crd/ --ignore-not-found
```

!!! danger "CRD Deletion"
    Deleting CRDs removes all WireKubeMesh and WireKubePeer resources permanently.
