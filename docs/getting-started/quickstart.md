# Quick Start

This path installs WireKube from a released `wirekubectl` binary without a
source checkout. It does not assume a specific cloud provider or CNI.

## Prerequisites

| Requirement | Minimum |
| --- | --- |
| Kubernetes | 1.26+ |
| Linux kernel on participating nodes | 5.6+ |
| Cluster access | Permission to create cluster-scoped CRDs and RBAC |
| Local tools | Homebrew and a reachable kubeconfig |

## Install the CLI

```bash
brew install inerplat/tap/wirekube
wirekubectl version
```

Homebrew supports macOS and Linux on ARM64 and AMD64. Use the checksum-verified
GitHub Release path in the [installation guide](installation.md) when Homebrew
is unavailable.

## Inspect the cluster

Set the kubeconfig and context once for the remaining commands:

```bash
export WIREKUBE_KUBECONFIG="${HOME}/.kube/config"
export WIREKUBE_CONTEXT=my-cluster

kubectl --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}" \
  get nodes -o wide
```

Replace `my-cluster` before continuing.

## Choose a relay entry point

| Environment | Recommended choice |
| --- | --- |
| Cloud cluster with a reachable LoadBalancer | `--relay load-balancer` |
| Reachable node address, no LoadBalancer | `--relay node-port` |
| Existing HTTPS Gateway or Ingress | `--relay-transport wss` |
| Existing separately operated relay | `--relay external` |

The managed LoadBalancer path is the simplest default, but it can create public
TCP and UDP Services. Read the [relay entry point guide](../guides/relay-entrypoints.md)
before selecting NodePort, WSS, or an external relay.

## Preview the installation

Interactive dry run performs discovery and prints the exact plan without
creating resources:

```bash
wirekubectl install \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}" \
  --dry-run
```

Review the selected mesh CIDR, immutable image digest, agent placement, relay
Services, and any public entry points. Automatic CIDR selection is best effort;
provide `--mesh-cidr` when the CLI cannot know every routed network.

## Install WireKube

Run the same command without `--dry-run`. The interactive prompt is the final
approval boundary:

```bash
wirekubectl install \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}"
```

Automation must make infrastructure choices explicit:

```bash
wirekubectl install \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}" \
  --relay load-balancer \
  --mesh-cidr 100.96.0.0/11 \
  --node-addresses internal-ip \
  --yes \
  --output json
```

Choose a private mesh CIDR that does not overlap node, Pod, Service, VPC, VPN,
or corporate routes.

## Verify the mesh

```bash
wirekubectl status \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}"

wirekubectl doctor \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}"

kubectl --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}" \
  get wirekubemeshes,wirekubepeers -o wide
```

New peers may need time to publish endpoints and complete their first
handshake. `wirekubectl doctor` distinguishes agent, relay, route, and readiness
failures.

## Lifecycle

```bash
wirekubectl upgrade \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}"

wirekubectl uninstall \
  --kubeconfig "${WIREKUBE_KUBECONFIG}" \
  --context "${WIREKUBE_CONTEXT}"
```

Ordinary uninstall preserves CRDs and custom resources. Destructive removal
requires both `--purge` and `--confirm-purge`; use it only after proving that no
remaining node or external peer depends on WireKube.

## Next steps

- [Installation](installation.md): release binaries, topology details, and source builds
- [Configuration](configuration.md): mesh and agent settings
- [Relay entry points](../guides/relay-entrypoints.md): LoadBalancer, NodePort, WSS, and external relay
- [Troubleshooting](../operations/troubleshooting.md): readiness and connectivity failures
