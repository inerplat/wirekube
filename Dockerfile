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

# wirekubectl is baked into the same image so cluster admins can run
# `kubectl exec deploy/wirekube-agent -- wirekubectl invite alice`
# without installing any host-side binary. The CLI talks to the
# Kubernetes API via the agent's in-cluster ServiceAccount.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/wirekubectl ./cmd/wirekubectl/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/wirekube-admin-web ./cmd/admin-web/

FROM alpine:3.21
RUN apk add --no-cache wireguard-tools iptables ip6tables iproute2
COPY --from=builder /out/wirekube-agent /usr/local/bin/wirekube-agent
COPY --from=builder /out/wirekube-relay /usr/local/bin/wirekube-relay
COPY --from=builder /out/wirekubectl /usr/local/bin/wirekubectl
COPY --from=builder /out/wirekube-admin-web /usr/local/bin/wirekube-admin-web
ENTRYPOINT ["wirekube-agent"]
