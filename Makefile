IMG_REGISTRY ?= ghcr.io/wirekube
VERSION ?= latest

OPERATOR_IMG = $(IMG_REGISTRY)/operator:$(VERSION)
AGENT_IMG    = $(IMG_REGISTRY)/agent:$(VERSION)
GATEWAY_IMG  = $(IMG_REGISTRY)/gateway:$(VERSION)

GO = go
GOFLAGS =

## ─── Build ───────────────────────────────────────────────────────────────────

.PHONY: build
build: build-operator build-agent build-wirekubectl build-gateway

build-operator:
	$(GO) build $(GOFLAGS) -o bin/operator ./cmd/operator

build-agent:
	$(GO) build $(GOFLAGS) -o bin/agent ./cmd/agent

build-wirekubectl:
	$(GO) build $(GOFLAGS) -o bin/wirekubectl ./cmd/wirekubectl

build-gateway:
	$(GO) build $(GOFLAGS) -o bin/gateway ./cmd/gateway

## ─── Generate ────────────────────────────────────────────────────────────────

.PHONY: generate
generate:
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./pkg/api/..."

.PHONY: manifests
manifests:
	controller-gen crd:generateEmbeddedObjectMeta=true rbac:roleName=wirekube-operator \
		paths="./pkg/..." output:crd:dir=config/crd

## ─── Docker ──────────────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build: docker-build-operator docker-build-agent docker-build-gateway

docker-build-operator:
	docker build -f Dockerfile.operator -t $(OPERATOR_IMG) .

docker-build-agent:
	docker build -f Dockerfile.agent -t $(AGENT_IMG) .

docker-build-gateway:
	docker build -f Dockerfile.gateway -t $(GATEWAY_IMG) .

docker-push: docker-build
	docker push $(OPERATOR_IMG)
	docker push $(AGENT_IMG)
	docker push $(GATEWAY_IMG)

## ─── Deploy ──────────────────────────────────────────────────────────────────

.PHONY: install-crds
install-crds:
	kubectl apply -f config/crd/

.PHONY: install-rbac
install-rbac:
	kubectl apply -f config/rbac/

.PHONY: deploy-operator
deploy-operator: install-crds install-rbac
	kubectl apply -f config/operator/

.PHONY: deploy-agent
deploy-agent:
	kubectl apply -f config/agent/

.PHONY: deploy
deploy: deploy-operator deploy-agent

.PHONY: undeploy
undeploy:
	kubectl delete -f config/agent/ --ignore-not-found
	kubectl delete -f config/operator/ --ignore-not-found
	kubectl delete -f config/rbac/ --ignore-not-found
	kubectl delete -f config/crd/ --ignore-not-found

## ─── Quick start ─────────────────────────────────────────────────────────────

# Label a node as VPN-enabled (replace NODE_NAME)
.PHONY: label-node
label-node:
	kubectl label node $(NODE_NAME) wirekube.io/vpn-enabled=true

# Create default WireKubeMesh
.PHONY: init-mesh
init-mesh:
	kubectl apply -f - <<'EOF'
	apiVersion: wirekube.io/v1alpha1
	kind: WireKubeMesh
	metadata:
	  name: default
	spec:
	  meshCIDR: "10.100.0.0/24"
	  mode: selective
	  listenPort: 51820
	  interfaceName: wg0
	  mtu: 1420
	  stunServers:
	    - stun:stun.l.google.com:19302
	    - stun:stun1.l.google.com:19302
	EOF

## ─── Dev ─────────────────────────────────────────────────────────────────────

.PHONY: test
test:
	$(GO) test ./... -v

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: run-operator
run-operator:
	$(GO) run ./cmd/operator

.PHONY: help
help:
	@echo "WireKube Makefile targets:"
	@echo "  build              Build all binaries"
	@echo "  generate           Regenerate deepcopy functions"
	@echo "  manifests          Regenerate CRD manifests"
	@echo "  docker-build       Build Docker images"
	@echo "  docker-push        Build and push Docker images"
	@echo "  install-crds       Install CRDs into the cluster"
	@echo "  deploy             Deploy operator + agent"
	@echo "  undeploy           Remove all WireKube resources"
	@echo "  label-node         Label a node: NODE_NAME=<name> make label-node"
	@echo "  init-mesh          Create default WireKubeMesh"
	@echo "  test               Run tests"
