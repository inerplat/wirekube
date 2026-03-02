IMG ?= inerplat/wirekube
VERSION ?= v0.0.1

GO = go
GOFLAGS =

## ─── Build ───────────────────────────────────────────────────────────────────

.PHONY: build
build: build-operator build-agent build-relay build-wirekubectl

build-operator:
	$(GO) build $(GOFLAGS) -o bin/operator ./cmd/operator

build-agent:
	$(GO) build $(GOFLAGS) -o bin/agent ./cmd/agent

build-relay:
	$(GO) build $(GOFLAGS) -o bin/relay ./cmd/relay

build-wirekubectl:
	$(GO) build $(GOFLAGS) -o bin/wirekubectl ./cmd/wirekubectl

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
docker-build:
	docker build -t $(IMG):$(VERSION) .

.PHONY: docker-push
docker-push: docker-build
	docker push $(IMG):$(VERSION)

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

.PHONY: deploy-relay
deploy-relay:
	kubectl apply -f config/relay/

.PHONY: deploy
deploy: deploy-operator deploy-agent

.PHONY: undeploy
undeploy:
	kubectl delete -f config/agent/ --ignore-not-found
	kubectl delete -f config/operator/ --ignore-not-found
	kubectl delete -f config/rbac/ --ignore-not-found
	kubectl delete -f config/crd/ --ignore-not-found

## ─── Quick start ─────────────────────────────────────────────────────────────

.PHONY: label-node
label-node:
	kubectl label node $(NODE_NAME) wirekube.io/vpn-enabled=true

.PHONY: init-mesh
init-mesh:
	kubectl apply -f config/operator/wirekubemesh-default.yaml

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
	@echo "  docker-build       Build Docker image"
	@echo "  docker-push        Build and push Docker image"
	@echo "  install-crds       Install CRDs into the cluster"
	@echo "  deploy             Deploy operator + agent"
	@echo "  deploy-relay       Deploy relay server"
	@echo "  undeploy           Remove all WireKube resources"
	@echo "  label-node         Label a node: NODE_NAME=<name> make label-node"
	@echo "  init-mesh          Create default WireKubeMesh"
	@echo "  test               Run tests"
