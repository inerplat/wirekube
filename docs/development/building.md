# Building

## Prerequisites

- Go 1.23+
- `wireguard-tools` (for testing)
- `podman` or `docker` (for container images)

## Build Binaries

```bash
make build
```

Or build individual components:

```bash
make build-agent
make build-relay
make build-wirekubectl
```

### Cross-Compilation

The agent uses Linux-specific `netlink` APIs. When building on macOS, always
cross-compile:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o bin/agent-linux-amd64 ./cmd/agent/

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -ldflags="-s -w" -o bin/agent-linux-arm64 ./cmd/agent/
```

`CGO_ENABLED=0` produces a fully static binary with no external dependencies.

## Build Container Image

### Multi-Architecture (Recommended)

```bash
make docker-build
```

Or manually:

```bash
podman build --platform linux/amd64,linux/arm64 \
  --manifest inerplat/wirekube:latest .

podman manifest push inerplat/wirekube:latest \
  docker://docker.io/inerplat/wirekube:latest
```

### Single Architecture

```bash
docker build -t inerplat/wirekube:latest .
docker push inerplat/wirekube:latest
```

### CI/CD

Images are built and pushed automatically via GitHub Actions on tag push (`v*`).
The workflow builds multi-arch images (amd64 + arm64) and pushes both the tagged
version and `latest`.

## Dockerfile

The multi-stage Dockerfile:

1. **Builder stage**: Go 1.23 Alpine, builds agent, relay, operator, and wirekubectl
2. **Runtime stage**: Alpine 3.21 with `wireguard-tools`, `iptables`, `iproute2`

## Run Tests

```bash
make test          # go test ./... -v
make vet           # go vet ./...
make fmt           # go fmt ./...

go test -v ./pkg/agent/...          # specific package
go test -v -run TestEndpointDiscovery ./pkg/agent/...  # specific test
```

## Code Generation

After modifying types in `pkg/api/v1alpha1/` (especially `+kubebuilder:` markers):

```bash
make generate      # deepcopy functions
make manifests     # CRD YAML from types
```

Generated files in `config/crd/` must be committed alongside type changes.

## Project Structure

```
wirekube/
├── cmd/
│   ├── agent/           # Agent entrypoint
│   ├── operator/        # Operator entrypoint
│   ├── relay/           # Relay server entrypoint
│   └── wirekubectl/     # CLI entrypoint
├── pkg/
│   ├── agent/           # Agent logic (endpoint discovery, peer sync)
│   │   ├── nat/         # STUN and UPnP endpoint discovery
│   │   └── relay/       # Relay client, UDP proxy, relay pool
│   │       ├── client.go   # TCP client with auto-reconnect
│   │       ├── proxy.go    # Per-peer UDP proxy (Sender interface)
│   │       └── pool.go     # Multi-instance relay pool
│   ├── api/v1alpha1/    # CRD types (WireKubeMesh, WireKubePeer)
│   ├── controller/      # Kubernetes controller-runtime reconcilers
│   ├── relay/           # Relay server and wire protocol
│   └── wireguard/       # WireGuard interface, routing, xfrm bypass
├── config/
│   ├── agent/           # DaemonSet manifest (includes RBAC)
│   ├── crd/             # CustomResourceDefinition YAMLs (generated)
│   ├── relay/           # Relay deployment + service examples
│   └── examples/         # WireKubeMesh and EKS Hybrid Node examples
├── docs/                # Documentation (MkDocs Material)
├── .github/workflows/   # CI (tag-triggered build + test)
├── Dockerfile
├── Makefile
├── mkdocs.yml
└── go.mod
```
