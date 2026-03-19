IMG ?= inerplat/wirekube
VERSION ?= v0.0.9-dev.1

GO = go

GOFLAGS = -ldflags="-s -w"

## ─── Build ───────────────────────────────────────────────────────────────────

.PHONY: build
build: build-agent build-relay build-wirekubectl build-stun-server

build-agent:
	$(GO) build $(GOFLAGS) -o bin/agent ./cmd/agent
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-agent-linux-amd64 ./cmd/agent/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-agent-linux-arm64 ./cmd/agent/

build-relay:
	$(GO) build $(GOFLAGS) -o bin/relay ./cmd/relay
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-relay-linux-amd64 ./cmd/relay/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-relay-linux-arm64 ./cmd/relay/

build-wirekubectl:
	$(GO) build $(GOFLAGS) -o bin/wirekubectl ./cmd/wirekubectl
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-wirekubectl-linux-amd64 ./cmd/wirekubectl/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-wirekubectl-linux-arm64 ./cmd/wirekubectl/

build-stun-server:
	$(GO) build $(GOFLAGS) -o bin/wirekube-stun ./cmd/stun-server
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-stun-linux-amd64 ./cmd/stun-server/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/wirekube-stun-linux-arm64 ./cmd/stun-server/

## ─── Generate ────────────────────────────────────────────────────────────────

.PHONY: generate
generate:
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./pkg/api/..."

.PHONY: manifests
manifests:
	controller-gen crd:generateEmbeddedObjectMeta=true \
		paths="./pkg/api/..." output:crd:dir=config/crd

## ─── Docker ──────────────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMG):$(VERSION) --load .

.PHONY: docker-push
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMG):$(VERSION) --push .

.PHONY: podman-build
podman-build:
	podman build --platform linux/amd64 -t $(IMG):$(VERSION)-linux-amd64 .
	podman build --platform linux/arm64 -t $(IMG):$(VERSION)-linux-arm64 .


.PHONY: podman-push
podman-push: podman-build
	podman manifest rm $(IMG):$(VERSION) 2>/dev/null || podman rmi $(IMG):$(VERSION) 2>/dev/null || true
	podman manifest create $(IMG):$(VERSION)
	podman manifest add $(IMG):$(VERSION) $(IMG):$(VERSION)-linux-amd64
	podman manifest add $(IMG):$(VERSION) $(IMG):$(VERSION)-linux-arm64
	podman manifest push --all $(IMG):$(VERSION) docker://$(IMG):$(VERSION)

## ─── Deploy ──────────────────────────────────────────────────────────────────

.PHONY: install-crds
install-crds:
	kubectl apply -f config/crd/

.PHONY: deploy-agent
deploy-agent: install-crds
	kubectl apply -f config/agent/

.PHONY: deploy-relay
deploy-relay:
	kubectl apply -f config/relay/

.PHONY: deploy
deploy: deploy-agent deploy-relay

.PHONY: undeploy
undeploy:
	kubectl delete -f config/agent/ --ignore-not-found
	kubectl delete -f config/relay/ --ignore-not-found
	kubectl delete -f config/crd/ --ignore-not-found

## ─── Quick start ─────────────────────────────────────────────────────────────

.PHONY: label-node
label-node:
	kubectl label node $(NODE_NAME) wirekube.io/vpn-enabled=true

.PHONY: init-mesh
init-mesh:
	kubectl apply -f config/examples/wirekubemesh-basic.yaml

## ─── Dev ─────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	$(GO) test ./... -v

# kind-e2e: run end-to-end tests with isolated container networks.
#
# Each node runs on a separate 172.x subnet using kindest/node images
# bootstrapped directly with kubeadm — no kind CLI required. CNI is
# Cilium (vxlan). Relay deploys on the control-plane node (taint removed).
#
# Prerequisites:
#   kubectl, helm installed
#   docker or podman
#   podman pull kindest/node:v1.31.0
#   podman build -t $(IMG):$(VERSION) .
#
# Optional overrides:
#   WIREKUBE_IMAGE=myrepo/wirekube:tag          # custom agent/relay image
#   WIREKUBE_KIND_NODE_IMG=kindest/node:v1.30.0 # custom node image
#   WIREKUBE_E2E_REUSE=1                        # skip teardown for re-runs
#   WIREKUBE_E2E_SKIP_SETUP=1                   # assume cluster is running
#   WIREKUBE_E2E_CNI_MODE=kube-proxy-vxlan      # (default) kube-proxy + Cilium vxlan
#   WIREKUBE_E2E_CNI_MODE=no-kube-proxy-vxlan   # Cilium kube-proxy replacement + vxlan
.PHONY: kind-e2e
kind-e2e:
	$(GO) test -tags kind_e2e -v ./test/kind_e2e/... -timeout 30m

.PHONY: kind-e2e-all
kind-e2e-all:
	WIREKUBE_E2E_CNI_MODE=kube-proxy-vxlan $(GO) test -tags kind_e2e -v ./test/kind_e2e/... -timeout 30m
	WIREKUBE_E2E_CNI_MODE=no-kube-proxy-vxlan $(GO) test -tags kind_e2e -v ./test/kind_e2e/... -timeout 30m

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: help
help:
	@echo "WireKube Makefile targets:"
	@echo "  build              Build all binaries"
	@echo "  generate           Regenerate deepcopy functions"
	@echo "  manifests          Regenerate CRD manifests"
	@echo "  docker-build       Build Docker image"
	@echo "  docker-push        Build and push Docker image"
	@echo "  install-crds       Install CRDs into the cluster"
	@echo "  deploy             Deploy operator + agent"
	@echo "  deploy-relay       Deploy relay server"
	@echo "  undeploy           Remove all WireKube resources"
	@echo "  label-node         Label a node: NODE_NAME=<name> make label-node"
	@echo "  init-mesh          Create default WireKubeMesh"
	@echo "  test               Run unit tests"
	@echo "  kind-e2e           Run kind-based e2e tests (Cilium CNI, no kind CLI needed)"
	@echo "  kind-e2e-all       Run e2e in both CNI modes (kube-proxy + no-kube-proxy)"
