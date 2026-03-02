# Building

## Prerequisites

- Go 1.23+
- `wireguard-tools` (for testing)
- `podman` or `docker` (for container images)

## Build Binaries

```bash
export PATH="$PATH:/usr/local/go/bin"
go mod tidy

# Agent (native)
go build -o bin/wirekube-agent ./cmd/agent/

# Relay (native)
go build -o bin/wirekube-relay ./cmd/relay/
```

### Cross-Compilation

```bash
# Linux amd64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags="-s -w" -o bin/agent-linux-amd64 ./cmd/agent/

# Linux arm64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -ldflags="-s -w" -o bin/agent-linux-arm64 ./cmd/agent/
```

`CGO_ENABLED=0` produces a fully static binary with no external dependencies.

## Build Container Image

### Multi-Architecture (Recommended)

```bash
podman build --platform linux/amd64,linux/arm64 \
  --manifest inerplat/wirekube:v0.0.1 .

podman manifest push inerplat/wirekube:v0.0.1 \
  docker://docker.io/inerplat/wirekube:v0.0.1
```

### Single Architecture

```bash
docker build -t inerplat/wirekube:v0.0.1 .
docker push inerplat/wirekube:v0.0.1
```

## Dockerfile

The multi-stage Dockerfile:

1. **Builder stage**: Go 1.23 Alpine, builds both agent and relay binaries
2. **Runtime stage**: Alpine 3.21 with `wireguard-tools`, `iptables`, `iproute2`

```dockerfile
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
ARG TARGETOS TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/wirekube-agent ./cmd/agent/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/wirekube-relay ./cmd/relay/

FROM alpine:3.21
RUN apk add --no-cache wireguard-tools iptables ip6tables iproute2
COPY --from=builder /out/wirekube-agent /usr/local/bin/wirekube-agent
COPY --from=builder /out/wirekube-relay /usr/local/bin/wirekube-relay
ENTRYPOINT ["wirekube-agent"]
```

## Run Tests

```bash
# Unit tests
go test ./...

# With verbose output
go test -v ./...

# Specific package
go test -v ./pkg/wireguard/
go test -v ./pkg/agent/
go test -v ./pkg/relay/
```

## Project Structure

```
wirekube/
├── cmd/
│   ├── agent/          # Agent entrypoint
│   └── relay/          # Relay server entrypoint
├── pkg/
│   ├── agent/          # Agent logic (endpoint discovery, peer sync, relay client)
│   │   └── relay/      # Relay client + UDP proxy
│   ├── api/v1alpha1/   # CRD types (WireKubeMesh, WireKubePeer)
│   ├── relay/          # Relay protocol + server
│   └── wireguard/      # WireGuard interface management
├── config/
│   ├── agent/          # DaemonSet manifests
│   ├── crd/            # CustomResourceDefinition YAMLs
│   ├── operator/       # WireKubeMesh default configuration
│   ├── rbac/           # ServiceAccount, ClusterRole, ClusterRoleBinding
│   └── relay/          # Relay deployment manifests
├── docs/               # Documentation (MkDocs)
├── Dockerfile
├── Makefile
├── mkdocs.yml
└── go.mod
```
