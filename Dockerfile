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
