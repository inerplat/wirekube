# WSL2 GPU Node: Windows PC to Kubernetes GPU Worker

This guide turns a freshly formatted Windows PC with an NVIDIA GPU into a
Kubernetes GPU worker node, connected to your existing cluster via WireKube.

```mermaid
flowchart LR
    subgraph cloud["Existing K8s Cluster"]
        CP["control-plane"]
        W1["worker-1"]
    end
    subgraph win["Windows PC (WSL2)"]
        GPU["NVIDIA GPU"]
        WSL["Ubuntu<br/>kubelet + wirekube-agent"]
    end
    CP <-->|"WireGuard tunnel<br/>via WireKube"| WSL
    W1 <-->|"WireGuard tunnel<br/>via WireKube"| WSL
    GPU -.->|"GPU passthrough"| WSL
```

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| Windows | 11 22H2+ or 10 22H2+ |
| NVIDIA GPU | Any CUDA-capable GPU |
| NVIDIA Driver | 535+ (Windows side — NOT in WSL2) |
| Existing K8s cluster | kubeadm, k3s, EKS, etc. with `kubectl` access |
| Network | Outbound internet from the Windows PC |

---

## Phase 1: Windows Setup

### 1.1 Install NVIDIA Driver (Windows Side)

Download and install the latest NVIDIA Game Ready or Studio driver from
[nvidia.com/drivers](https://www.nvidia.com/drivers). **Do NOT install a
driver inside WSL2** — the Windows driver provides GPU access to WSL2
automatically.

After installation, verify from PowerShell:

```powershell
nvidia-smi
```

### 1.2 Configure .wslconfig

Create `C:\Users\<USERNAME>\.wslconfig` in Notepad **before** installing WSL2:

```ini
[wsl2]
memory=16GB
swap=0
networkingMode=mirrored
kernelCommandLine=systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all

[experimental]
autoMemoryReclaim=gradual
```

!!! critical "kernelCommandLine is essential"
    `cgroup_no_v1=all` forces pure cgroup v2. Without this, Cilium's
    Socket LB (kube-proxy replacement) cannot intercept pod traffic,
    causing `dial tcp 10.96.0.1:443: i/o timeout` on all ClusterIP services.

!!! note "Why mirrored networking?"
    `networkingMode=mirrored` gives WSL2 the same IP as the Windows host,
    making NAT traversal simpler — WireKube's STUN sees the real router-mapped
    endpoint instead of a double-NAT (Windows NAT + router NAT).

### 1.3 Install WSL2

Open **PowerShell as Administrator**:

```powershell
# Check available distributions
wsl --list --online

# Install Ubuntu (pick the version shown in the list)
wsl --install -d Ubuntu-24.04
```

!!! tip "Distribution name varies by system"
    Run `wsl --list --online` first and use the name shown (e.g. `Ubuntu`,
    `Ubuntu-24.04`). `Ubuntu` installs the latest available LTS.

Reboot when prompted. After reboot, Ubuntu will launch and ask you to create
a username and password.

Verify:

```powershell
wsl --list --verbose
# Should show Ubuntu with VERSION 2
```

---

## Phase 2: WSL2 Environment Setup

All commands from here run **inside WSL2 (Ubuntu)**.

### 2.1 Verify cgroup v2 and GPU

```bash
# cgroup v2 — file MUST exist
stat /sys/fs/cgroup/cgroup.controllers

# GPU access
nvidia-smi
```

If `/sys/fs/cgroup/cgroup.controllers` does not exist, `.wslconfig`
`kernelCommandLine` was not applied. Double check the file path and
content, then `wsl --shutdown` from PowerShell and retry.

### 2.2 System Update

```bash
sudo apt update && sudo apt upgrade -y
```

### 2.3 Configure /etc/wsl.conf

```bash
sudo tee /etc/wsl.conf <<'EOF'
[boot]
systemd=true
command="mount --make-shared / && mkdir -p /var/run/netns && mount --bind /var/run/netns /var/run/netns && mount --make-shared /var/run/netns && ip link set eth0 mtu 1500"
EOF
```

Apply immediately (without restart):

```bash
sudo mount --make-shared /
sudo mkdir -p /var/run/netns
sudo mount --bind /var/run/netns /var/run/netns
sudo mount --make-shared /var/run/netns
sudo ip link set eth0 mtu 1500
```

!!! warning "Without shared mount propagation"
    CNI pods (Cilium, Flannel, etc.) will fail with:
    `path "/var/run/netns" is mounted on "/" but it is not a shared or slave mount`

### 2.4 Install containerd

```bash
sudo apt install -y containerd

# Generate default config
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml > /dev/null

# Enable SystemdCgroup
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml

sudo systemctl restart containerd
```

### 2.5 Install NVIDIA Container Toolkit

WSL2 uses the Windows host GPU driver, but the container runtime still needs
nvidia-container-toolkit to expose the GPU inside containers.

```bash
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt update
sudo apt install -y nvidia-container-toolkit

# Configure containerd to use nvidia runtime
sudo nvidia-ctk runtime configure --runtime=containerd

# Generate CDI spec (required for WSL2 — GPU is exposed via /dev/dxg, not /dev/nvidia*)
sudo mkdir -p /etc/cdi
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml

sudo systemctl restart containerd
```

### 2.5 Install WireGuard

```bash
sudo apt install -y wireguard-tools

# Verify kernel module (built-in on most WSL2 kernels)
sudo modprobe wireguard && echo "OK" || echo "FAIL"
```

!!! warning "WSL2 Kernel WireGuard Support"
    The default WSL2 kernel (5.15+) includes WireGuard. If `modprobe`
    fails, see [Custom WSL2 Kernel](#appendix-custom-wsl2-kernel-optional).

### 2.6 Install Kubernetes Components

```bash
sudo apt install -y apt-transport-https ca-certificates curl gpg

# IMPORTANT: Match the cluster's Kubernetes version
# Check your cluster version: kubectl version
K8S_VERSION=v1.34  # <-- change to match your cluster

sudo mkdir -p /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_VERSION}/deb/Release.key" \
  | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] \
  https://pkgs.k8s.io/core:/stable:/${K8S_VERSION}/deb/ /" \
  | sudo tee /etc/apt/sources.list.d/kubernetes.list

sudo apt update
sudo apt install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

### 2.7 Disable Swap

```bash
sudo swapoff -a
sudo sed -i '/swap/d' /etc/fstab
```

### 2.8 Enable Required Kernel Modules and sysctl

```bash
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo sysctl --system
```

---

## Phase 3: Join the Kubernetes Cluster

### Option A: kubeadm join (kubeadm-based clusters)

On your **existing cluster's control plane**, create a join token:

```bash
kubeadm token create --print-join-command
```

On the **WSL2 node**:

```bash
sudo systemctl enable --now kubelet

sudo kubeadm join <API_SERVER>:6443 \
  --token <TOKEN> \
  --discovery-token-ca-cert-hash sha256:<HASH> \
  --ignore-preflight-errors=all
```

!!! tip "kubeadm config version mismatch"
    If you get `cannot unmarshal object into Go struct field ... extraArgs`,
    the cluster's `kubeadm-config` ConfigMap uses v1beta3 map-style
    `extraArgs` but your kubeadm expects v1beta4 array-style. Either
    update the ConfigMap or use a JoinConfiguration file:

    ```bash
    cat <<EOF > /tmp/join-config.yaml
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: JoinConfiguration
    discovery:
      bootstrapToken:
        apiServerEndpoint: "<API_SERVER>:6443"
        token: "<TOKEN>"
        caCertHashes:
          - "sha256:<HASH>"
    EOF
    sudo kubeadm join --config /tmp/join-config.yaml
    ```

### Option B: k3s agent (k3s clusters)

```bash
K3S_URL="https://<K3S_SERVER>:6443"
K3S_TOKEN="<your-k3s-token>"

curl -sfL https://get.k3s.io | \
  INSTALL_K3S_EXEC="agent" \
  K3S_URL="${K3S_URL}" \
  K3S_TOKEN="${K3S_TOKEN}" \
  sh -
```

### Verify Node Joined

```bash
kubectl get nodes
# WSL2 node should appear (may be NotReady until CNI is set up)
```

---

## Phase 4: Deploy WireKube

WireKube must be deployed **before** the GPU Operator. The WSL2 node is
behind NAT and not directly reachable from the cluster — without WireKube
tunnels, the control plane cannot reach kubelet (port 10250), so
`kubectl exec/logs` and DaemonSet pod scheduling will fail.

### 4.1 Install WireKube on the Cluster

If WireKube is not already deployed on your cluster:

```bash
kubectl apply -f config/crd/
kubectl apply -f config/agent/rbac.yaml
kubectl create namespace wirekube-system --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f config/agent/daemonset.yaml
```

### 4.2 Create or Update WireKubeMesh

```bash
kubectl apply -f - <<'EOF'
apiVersion: wirekube.io/v1alpha1
kind: WireKubeMesh
metadata:
  name: default
spec:
  listenPort: 51822
  interfaceName: wire_kube
  mtu: 1420
  stunServers:
    - stun.cloudflare.com:3478
    - stun.l.google.com:19302
  autoAllowedIPs:
    strategy: node-internal-ip
  relay:
    mode: auto
    provider: managed
    handshakeTimeoutSeconds: 30
    directRetryIntervalSeconds: 120
EOF
```

!!! note "MTU"
    WSL2's default `eth0` MTU is 1420. The boot command in Phase 2.3
    raises it to 1500 so WireGuard MTU 1420 works without fragmentation.
    If you skip that step, set this to 1360.

### 4.3 Verify WireKube Connectivity

```bash
# Check all peers
kubectl get wirekubepeers -o wide

# Check WireGuard on WSL2 node
wg show wire_kube

# Ping a cluster node through the tunnel
ping -c 3 -I wire_kube <CLUSTER_NODE_IP>

# Verify kubectl exec works
kubectl exec <any-pod-on-wsl2-node> -- hostname
```

---

## Phase 5: GPU Operator

The [NVIDIA GPU Operator](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/index.html)
automates device plugin, GPU feature discovery, and DCGM metrics exporter.
WSL2 requires special handling for driver and toolkit components.

### 5.1 Install GPU Operator via Helm

```bash
helm repo add nvidia https://helm.ngc.nvidia.com/nvidia
helm repo update

helm install gpu-operator nvidia/gpu-operator \
  --namespace gpu-operator \
  --create-namespace \
  --set driver.enabled=false
```

### 5.2 Label the WSL2 Node for GPU Discovery

WSL2 has no PCI bus, so NFD (Node Feature Discovery) cannot auto-detect the
GPU. Add the NVIDIA PCI vendor label manually, and disable the toolkit
DaemonSet on this node (we installed nvidia-container-toolkit manually in
Phase 2.5 because the operator's toolkit fails on WSL2 — it tries to create
`/dev/nvidia*` device nodes which don't exist in WSL2):

```bash
NODE_NAME=<wsl2-node-name>

# NFD PCI label (triggers GPU Operator to deploy on this node)
kubectl label node ${NODE_NAME} feature.node.kubernetes.io/pci-10de.present=true

# Disable toolkit DaemonSet on WSL2 (already installed manually)
kubectl label node ${NODE_NAME} nvidia.com/gpu.deploy.container-toolkit=false --overwrite
```

### 5.3 Verify GPU Operator

```bash
# All pods on WSL2 node should be Running (except toolkit)
kubectl get pods -n gpu-operator -o wide --field-selector spec.nodeName=<wsl2-node-name>

# Check GPU is allocatable
kubectl describe node <wsl2-node-name> | grep -A5 "Allocatable" | grep nvidia
# Should show: nvidia.com/gpu: 1
```

---

## Phase 6: Test GPU Workload

GPU pods on WSL2 **must** use `runtimeClassName: nvidia`. Without it,
containers cannot find `nvidia-smi` or access the GPU — WSL2 exposes the
GPU via `/dev/dxg` and CDI mounts, not `/dev/nvidia*`.

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: gpu-test
spec:
  runtimeClassName: nvidia
  restartPolicy: Never
  containers:
  - name: cuda-test
    image: nvidia/cuda:12.6.2-base-ubuntu24.04
    command: ["nvidia-smi"]
    resources:
      limits:
        nvidia.com/gpu: 1
EOF

# Wait and check result
kubectl logs -f gpu-test
kubectl delete pod gpu-test
```

You should see `nvidia-smi` output showing your GPU from inside the
Kubernetes pod running on the WSL2 node.

### LLM Serving Test (Optional)

Deploy an LLM using vLLM to verify end-to-end GPU inference. For 8GB VRAM
GPUs, use an AWQ-quantized model to fit within memory:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: llm-test
  labels:
    app: llm-test
spec:
  runtimeClassName: nvidia
  restartPolicy: Never
  containers:
  - name: vllm
    image: vllm/vllm-openai:latest
    args:
      - "--model"
      - "Qwen/Qwen3-4B-AWQ"
      - "--quantization"
      - "awq"
      - "--max-model-len"
      - "4096"
      - "--gpu-memory-utilization"
      - "0.85"
      - "--enforce-eager"
    ports:
    - containerPort: 8000
    resources:
      limits:
        nvidia.com/gpu: 1
    env:
    - name: HF_HUB_CACHE
      value: /tmp/hf-cache
EOF
```

!!! tip "Model selection by VRAM"
    | VRAM | Recommended Model |
    |------|-------------------|
    | 8GB | `Qwen/Qwen3-4B-AWQ` (AWQ 4-bit, ~3GB) |
    | 16GB+ | `Qwen/Qwen2.5-7B-Instruct` (FP16) |

    `--enforce-eager` disables CUDA graph capture, reducing VRAM usage at the
    cost of some throughput. Remove it if you have enough memory headroom.

Wait for the model to load (~3-5 min for first pull):

```bash
kubectl logs -f llm-test
# Wait until you see "Application startup complete."
```

Test inference:

```bash
kubectl exec llm-test -- curl -s http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "Qwen/Qwen3-4B-AWQ",
    "messages": [{"role": "user", "content": "Hello, what can you do?"}],
    "max_tokens": 100
  }'
```

Clean up:

```bash
kubectl delete pod llm-test gpu-test
```

---

## WSL2 Auto-Start (Optional)

WSL2 does not start services automatically on Windows boot. Create a
scheduled task to start kubelet and containerd on login.

From **PowerShell as Admin**:

```powershell
$Action = New-ScheduledTaskAction -Execute "wsl" `
  -Argument "-d Ubuntu -u root -- bash -c 'systemctl start containerd && systemctl start kubelet'"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "WSL2-K8s-Start" -Action $Action -Trigger $Trigger `
  -Description "Start K8s services in WSL2" -RunLevel Highest
```

---

## Troubleshooting

### Pods cannot reach ClusterIP services (i/o timeout)

**Symptom:** `dial tcp 10.96.0.1:443: i/o timeout` from pods on WSL2 node.
hostNetwork pods work fine.

**Cause:** cgroup v1. Cilium's Socket LB needs cgroup v2 to attach BPF
programs to pod cgroups.

**Fix:** Ensure `.wslconfig` has:

```ini
kernelCommandLine=systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all
```

Then `wsl --shutdown` and verify `stat /sys/fs/cgroup/cgroup.controllers`.

### CNI pods fail: "not a shared or slave mount"

**Cause:** WSL2 defaults to private mount propagation.

**Fix:** See Phase 2.3 — `/etc/wsl.conf` `command=` with `mount --make-shared`.

### kubeadm join fails: extraArgs unmarshal error

**Cause:** Cluster kubeadm-config uses v1beta3 map-style `extraArgs` but
kubeadm v1.34+ expects v1beta4 array-style.

**Fix:** Either update the cluster's `kubeadm-config` ConfigMap to use
array-style `extraArgs`, or use a JoinConfiguration file (see Phase 3).

### Cilium iptables error: unknown option "--transparent"

**Symptom:** `iptables: unknown option "--transparent"` in cilium-agent logs.

**Cause:** WSL2 kernel lacks `xt_socket` module. This only affects Cilium's
L7 transparent proxy — basic networking and service routing still work via
BPF if cgroup v2 is enabled.

### MTU issues: large packets dropped

**Symptom:** Small pings work but `kubectl exec`, TLS, or large transfers fail.

**Cause:** WSL2's default `eth0` MTU is 1420. WireGuard adds ~60 bytes
overhead, so WireGuard MTU 1420 on a 1420 underlay causes fragmentation.

**Fix:** Ensure Phase 2.3 boot command includes `ip link set eth0 mtu 1500`.
Verify with `ip link show eth0`.

### nvidia-smi works in WSL2 but not in pods

**Cause:** Missing `runtimeClassName: nvidia` in pod spec. WSL2 exposes GPU
via `/dev/dxg` and CDI — without the nvidia RuntimeClass, containerd does not
mount the GPU devices into the container.

**Fix:** Add `runtimeClassName: nvidia` to the pod spec (see Phase 6).

### GPU Operator toolkit DaemonSet CrashLoopBackOff

**Symptom:** `nvidia-container-toolkit-daemonset` pod on WSL2 node is in
CrashLoopBackOff, trying to create `/dev/nvidia*` device nodes.

**Cause:** WSL2 does not have `/dev/nvidia*` — GPU access is via `/dev/dxg`.

**Fix:** Disable the toolkit DaemonSet on the WSL2 node and install
nvidia-container-toolkit manually (see Phase 2.5 and 5.2):

```bash
kubectl label node <wsl2-node-name> nvidia.com/gpu.deploy.container-toolkit=false
```

### Cilium not ready after WSL2 restart

**Symptom:** Cilium agent shows 0/1 ready after `wsl --shutdown` and restart.

**Cause:** `KUBE-FIREWALL` iptables chain may contain a DROP rule that blocks
loopback traffic needed by Cilium's health checks.

**Fix:**

```bash
sudo iptables -F KUBE-FIREWALL
sudo systemctl restart kubelet
```

### WireGuard module not found

**Cause:** WSL2 kernel too old or missing module.

```bash
uname -r
# Needs 5.15+ with CONFIG_WIREGUARD
```

See [Appendix: Custom WSL2 Kernel](#appendix-custom-wsl2-kernel-optional).

### NAT traversal: double NAT

If WireKube detects Symmetric NAT and cannot establish direct P2P:

1. Ensure `.wslconfig` has `networkingMode=mirrored`
2. Consider port-forwarding UDP 51822 on your router to the Windows PC
3. Deploy a WireKube relay if not already running
4. Check NAT type: `kubectl get wirekubepeer <node> -o jsonpath='{.status.natType}'`

---

## Appendix: Custom WSL2 Kernel (Optional)

Only needed if `modprobe wireguard` fails on the default kernel.

```bash
# Install build dependencies
sudo apt install -y build-essential flex bison libssl-dev libelf-dev \
  bc dwarves pahole

# Clone WSL2 kernel source
KERNEL_VERSION=$(uname -r | sed 's/-microsoft.*//')
git clone --depth 1 --branch linux-msft-wsl-${KERNEL_VERSION} \
  https://github.com/microsoft/WSL2-Linux-Kernel.git
cd WSL2-Linux-Kernel

# Use current config as base
zcat /proc/config.gz > .config

# Enable WireGuard
scripts/config --module CONFIG_WIREGUARD

# Build
make -j$(nproc)

# Install
sudo make modules_install
cp arch/x86/boot/bzImage /mnt/c/Users/<USERNAME>/wsl-kernel
```

Add to `C:\Users\<USERNAME>\.wslconfig`:

```ini
[wsl2]
kernel=C:\\Users\\<USERNAME>\\wsl-kernel
```

Restart WSL2: `wsl --shutdown`

---

## Next Steps

- [Configuration](../getting-started/configuration.md) — Relay modes, STUN servers, and mesh options
- [NAT Traversal](../architecture/nat-traversal.md) — How WireKube handles different NAT types
- [Monitoring](../operations/monitoring.md) — Prometheus metrics and Grafana dashboards
- [EKS Hybrid Nodes](eks-hybrid-nodes.md) — Production deployment with EKS
