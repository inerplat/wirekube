IMG ?= inerplat/wirekube
VERSION ?= v0.0.8-dev.15

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

# kind-e2e: run end-to-end tests in a local kind cluster.
#
# Prerequisites (one-time setup — requires internet access):
#   docker pull kindest/node:v1.31.0   # pre-pull kind node image
#   make docker-build                   # build WireKube image locally
#
# Optional overrides:
#   WIREKUBE_IMAGE=myrepo/wirekube:tag  # custom agent image
#   WIREKUBE_KIND_CLUSTER=my-cluster    # reuse an existing kind cluster
#   WIREKUBE_KIND_NODE_IMG=kindest/node:v1.30.0
.PHONY: kind-e2e
kind-e2e:
	$(GO) test -tags kind_e2e -v ./test/kind_e2e/... -timeout 20m

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
	@echo "  kind-e2e           Run kind-based e2e tests (requires pre-built image + kind CLI)"
