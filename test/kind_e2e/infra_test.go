//go:build kind_e2e

package kind_e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

// ── Container runtime ────────────────────────────────────────────────────────

func containerRuntime() string {
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}
	return "podman"
}

func ctrExec(args ...string) (string, error) {
	return runCmd(containerRuntime(), args...)
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		combined := stdout.String() + stderr.String()
		return "", fmt.Errorf("%s %s: %w\n%s",
			name, strings.Join(args, " "), err, strings.TrimSpace(combined))
	}
	return stdout.String(), nil
}

func podmanMachineSSH(cmd string) (string, error) {
	return runCmd("podman", "machine", "ssh", cmd)
}

// hostIptables runs an iptables command on the Docker host's network namespace.
// On Linux, this runs iptables directly via sudo. On macOS (Docker Desktop),
// iptables must run inside the Linux VM via a privileged container.
func hostIptables(args ...string) (string, error) {
	if runtime.GOOS == "linux" {
		return runCmd("sudo", append([]string{"iptables"}, args...)...)
	}
	// macOS / Docker Desktop: run iptables inside the VM via a privileged container.
	// Use --entrypoint to bypass kindest/node's init and nsenter to enter PID 1's
	// namespaces so we manipulate the VM's real netfilter tables.
	ctrArgs := []string{
		"run", "--rm", "--privileged",
		"--net=host", "--pid=host",
		"--entrypoint", "nsenter",
		nodeImage(),
		"-t", "1", "-m", "-u", "-n", "-i", "--",
		"iptables",
	}
	ctrArgs = append(ctrArgs, args...)
	return ctrExec(ctrArgs...)
}

// ── Cluster lifecycle ────────────────────────────────────────────────────────

func setupCluster(_ context.Context) error {
	if os.Getenv("WIREKUBE_E2E_SKIP_SETUP") != "" {
		fmt.Println("e2e: skipping cluster setup (WIREKUBE_E2E_SKIP_SETUP)")
		return nil
	}

	if err := checkImageExists(wireKubeImage()); err != nil {
		return err
	}

	for _, n := range nodeConfigs {
		if err := createNetwork(n.network, n.subnet); err != nil {
			return fmt.Errorf("create network %s: %w", n.network, err)
		}
	}

	fmt.Println("e2e: disabling NAT masquerade between VPC subnets…")
	if err := disableInterVPCMasquerade(); err != nil {
		return fmt.Errorf("disable inter-VPC masquerade: %w", err)
	}

	for _, n := range nodeConfigs {
		if err := createNodeContainer(n); err != nil {
			return fmt.Errorf("create container %s: %w", n.name, err)
		}
	}

	for _, n := range nodeConfigs {
		fmt.Printf("e2e: waiting for containerd on %s…\n", n.name)
		if err := waitForContainerd(n.name, 2*time.Minute); err != nil {
			return err
		}
	}

	// Raise containerd memlock so Cilium (eBPF) can set RLIMIT_MEMLOCK in
	// pods. Without this, containerd inherits 8MB from systemd defaults,
	// which Cilium's agent cannot raise inside user namespaces.
	// Only Cilium needs this; Flannel and Calico do not.
	if !isFlannel() && !isCalico() {
		for _, n := range nodeConfigs {
			if err := raiseContainerdMemlock(n.name); err != nil {
				return fmt.Errorf("raise memlock on %s: %w", n.name, err)
			}
		}
		for _, n := range nodeConfigs {
			if err := waitForContainerd(n.name, 1*time.Minute); err != nil {
				return fmt.Errorf("containerd not ready after memlock fix on %s: %w", n.name, err)
			}
		}
	}

	fmt.Printf("e2e: kubeadm init (cni-mode=%s)…\n", cniMode())
	if err := kubeadmInit(); err != nil {
		return fmt.Errorf("kubeadm init: %w", err)
	}

	token, err := createJoinToken()
	if err != nil {
		return fmt.Errorf("create join token: %w", err)
	}
	fmt.Printf("e2e: join token: %s\n", token)

	for _, n := range nodeConfigs {
		if n.role != "worker" {
			continue
		}
		fmt.Printf("e2e: kubeadm join %s…\n", n.name)
		if err := kubeadmJoin(n, token); err != nil {
			return fmt.Errorf("kubeadm join %s: %w", n.name, err)
		}
	}

	// Wait for kube-proxy pods, patching only if they crash (conntrack issue
	// in user namespaces or Docker Desktop macOS where /proc/sys is read-only).
	if !skipKubeProxy() {
		if err := ensureKubeProxyReady(2 * time.Minute); err != nil {
			return fmt.Errorf("kube-proxy not ready: %w", err)
		}
	}

	switch {
	case isFlannel():
		fmt.Println("e2e: installing Flannel CNI…")
		if err := installFlannel(); err != nil {
			return fmt.Errorf("install Flannel: %w", err)
		}
	case isCalico():
		fmt.Println("e2e: installing Calico CNI…")
		if err := installCalico(); err != nil {
			return fmt.Errorf("install Calico: %w", err)
		}
	default:
		fmt.Println("e2e: installing Cilium CNI…")
		if err := installCilium(); err != nil {
			return fmt.Errorf("install Cilium: %w", err)
		}
	}

	fmt.Println("e2e: waiting for nodes Ready…")
	if err := waitForNodesReady(len(nodeConfigs), 3*time.Minute); err != nil {
		return err
	}

	fmt.Println("e2e: removing CP taint…")
	if err := removeCPTaint(); err != nil {
		return fmt.Errorf("remove taint: %w", err)
	}

	fmt.Println("e2e: deploying STUN servers on CP…")
	if err := buildAndDeploySTUN(); err != nil {
		return fmt.Errorf("stun: %w", err)
	}

	fmt.Println("e2e: loading wirekube image into nodes…")
	if err := loadImageToAllNodes(wireKubeImage()); err != nil {
		return err
	}

	fmt.Println("e2e: enforcing VPC isolation (iptables)…")
	if err := enforceVPCIsolation(); err != nil {
		return fmt.Errorf("enforce VPC isolation: %w", err)
	}

	return nil
}

// disableInterVPCMasquerade removes the MASQUERADE rules between VPC subnets.
// Both Podman (netavark) and Docker masquerade cross-subnet traffic by default,
// which causes STUN to reflect the gateway IP instead of the node's real IP.
// We insert accept rules in POSTROUTING to skip masquerade for inter-VPC traffic.
func disableInterVPCMasquerade() error {
	var subnets []string
	for _, n := range nodeConfigs {
		subnets = append(subnets, n.subnet)
	}

	rt := containerRuntime()
	if rt == "podman" {
		for _, src := range subnets {
			for _, dst := range subnets {
				if src == dst {
					continue
				}
				rule := fmt.Sprintf("insert rule inet netavark POSTROUTING ip saddr %s ip daddr %s accept", src, dst)
				if _, err := podmanMachineSSH("nft " + rule); err != nil {
					return fmt.Errorf("nft insert for %s→%s: %w", src, dst, err)
				}
			}
		}
	} else {
		// Docker >=29 drops cross-network packets in `raw PREROUTING` before they
		// reach the FORWARD chain.  We must insert ACCEPT rules in three places:
		//  1. raw PREROUTING — bypass the per-container "wrong bridge" drop
		//  2. filter DOCKER-USER — bypass the cross-bridge DROP in the DOCKER chain
		//  3. nat POSTROUTING — skip masquerade so STUN sees real IPs
		//
		// On macOS/Docker Desktop, iptables must run inside the Linux VM.
		// We use a privileged container with host networking to access the VM's netfilter.
		for _, src := range subnets {
			for _, dst := range subnets {
				if src == dst {
					continue
				}
				if _, err := hostIptables("-t", "raw", "-I", "PREROUTING",
					"-s", src, "-d", dst, "-j", "ACCEPT"); err != nil {
					return fmt.Errorf("raw insert for %s→%s: %w", src, dst, err)
				}
				if _, err := hostIptables("-I", "DOCKER-USER",
					"-s", src, "-d", dst, "-j", "ACCEPT"); err != nil {
					return fmt.Errorf("forward insert for %s→%s: %w", src, dst, err)
				}
				if _, err := hostIptables("-t", "nat", "-I", "POSTROUTING",
					"-s", src, "-d", dst, "-j", "ACCEPT"); err != nil {
					return fmt.Errorf("nat insert for %s→%s: %w", src, dst, err)
				}
			}
		}
	}
	fmt.Println("e2e: inter-VPC NAT masquerade disabled")
	return nil
}

// enforceVPCIsolation adds iptables rules on each node to block direct L3
// traffic between VPC subnets. Only WireGuard UDP, Relay TCP, API server, and
// STUN are allowed. This simulates separate VPCs where WireKube's WireGuard
// tunnels are required for node-to-node connectivity.
func enforceVPCIsolation() error {
	cp := cpNode()
	for _, self := range nodeConfigs {
		for _, other := range nodeConfigs {
			if self.name == other.name {
				continue
			}
			otherSubnet := other.subnet

			// Allow WireGuard UDP
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "INPUT",
				"-s", otherSubnet, "-p", "udp", "--dport", fmt.Sprintf("%d", wgPort), "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow WG INPUT on %s: %w", self.name, err)
			}
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
				"-d", otherSubnet, "-p", "udp", "--dport", fmt.Sprintf("%d", wgPort), "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow WG OUTPUT on %s: %w", self.name, err)
			}
		}

		// Allow Relay TCP (OUTPUT from workers, INPUT on CP)
		if self.name != cp.name {
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
				"-d", cp.ip, "-p", "tcp", "--dport", "3478", "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow relay on %s: %w", self.name, err)
			}
		}

		// Allow API server (OUTPUT from workers, INPUT on CP)
		if self.name != cp.name {
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
				"-d", cp.ip, "-p", "tcp", "--dport", "6443", "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow API on %s: %w", self.name, err)
			}
		}

		// Allow STUN (OUTPUT from all, INPUT on CP)
		for _, port := range []int{stunPort1, stunPort2} {
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
				"-d", cp.ip, "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"); err != nil {
				return fmt.Errorf("allow STUN on %s: %w", self.name, err)
			}
		}

		// On CP: accept incoming connections for shared services from all subnets
		if self.name == cp.name {
			for _, other := range nodeConfigs {
				if other.name == cp.name {
					continue
				}
				for _, svcPort := range []struct {
					proto string
					port  int
				}{
					{"tcp", 6443},
					{"tcp", 3478},
					{"udp", stunPort1},
					{"udp", stunPort2},
				} {
					if _, err := ctrExec("exec", cp.name, "iptables", "-A", "INPUT",
						"-s", other.subnet, "-p", svcPort.proto,
						"--dport", fmt.Sprintf("%d", svcPort.port), "-j", "ACCEPT"); err != nil {
						return fmt.Errorf("allow %s/%d INPUT on CP from %s: %w",
							svcPort.proto, svcPort.port, other.subnet, err)
					}
				}
			}
		}

		// Allow all traffic via the WireGuard tunnel interface.
		// This ensures that once WireKube establishes a tunnel, ping/TCP
		// between nodes works through the encrypted WG overlay.
		wgIface := "wire_kube"
		if _, err := ctrExec("exec", self.name, "iptables", "-A", "INPUT",
			"-i", wgIface, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("allow WG iface INPUT on %s: %w", self.name, err)
		}
		if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
			"-o", wgIface, "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("allow WG iface OUTPUT on %s: %w", self.name, err)
		}

		// Allow established/related connections (return traffic for allowed services)
		if _, err := ctrExec("exec", self.name, "iptables", "-A", "INPUT",
			"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("allow established INPUT on %s: %w", self.name, err)
		}
		if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
			"-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("allow established OUTPUT on %s: %w", self.name, err)
		}

		// Block all other traffic from/to other VPC subnets (on physical interfaces only)
		for _, other := range nodeConfigs {
			if self.name == other.name {
				continue
			}
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "INPUT",
				"-s", other.subnet, "!", "-i", wgIface, "-j", "DROP"); err != nil {
				return fmt.Errorf("block INPUT on %s: %w", self.name, err)
			}
			if _, err := ctrExec("exec", self.name, "iptables", "-A", "OUTPUT",
				"-d", other.subnet, "!", "-o", wgIface, "-j", "DROP"); err != nil {
				return fmt.Errorf("block OUTPUT on %s: %w", self.name, err)
			}
		}

		fmt.Printf("e2e: VPC isolation enforced on %s\n", self.name)
	}
	return nil
}

func teardownCluster() {
	fmt.Println("e2e: tearing down…")
	for i := len(nodeConfigs) - 1; i >= 0; i-- {
		ctrExec("rm", "-f", nodeConfigs[i].name) //nolint:errcheck
	}
	for _, n := range nodeConfigs {
		ctrExec("network", "rm", n.network) //nolint:errcheck
	}
}

func checkImageExists(image string) error {
	if _, err := ctrExec("image", "inspect", image); err != nil {
		return fmt.Errorf("image %s not found locally — build first:\n"+
			"  make podman-build  # or: podman build -t %s .", image, image)
	}
	return nil
}

func containerRunning(name string) bool {
	out, err := ctrExec("inspect", name, "--format", "{{.State.Running}}")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == "true"
}

func createNetwork(name, subnet string) error {
	if _, err := ctrExec("network", "inspect", name); err == nil {
		fmt.Printf("e2e: network %s exists\n", name)
		return nil
	}
	if _, err := ctrExec("network", "create", "--subnet", subnet, name); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}
	fmt.Printf("e2e: created network %s (%s)\n", name, subnet)
	return nil
}

func createNodeContainer(cfg nodeConfig) error {
	if containerRunning(cfg.name) {
		fmt.Printf("e2e: container %s already running\n", cfg.name)
		return nil
	}
	// Remove stale stopped container.
	ctrExec("rm", "-f", cfg.name) //nolint:errcheck

	rt := containerRuntime()
	args := []string{
		"run", "-d", "--privileged",
		"--name=" + cfg.name,
		"--hostname=" + cfg.name,
		"--tmpfs=/tmp", "--tmpfs=/run",
		"--volume=/var",
		"--volume=/lib/modules:/lib/modules:ro",
		"--volume=/sys/fs/bpf:/sys/fs/bpf:rw",
		"--ulimit=memlock=-1:-1",
		"--security-opt=seccomp=unconfined",
		"--cgroupns=private",
		"--tty",
	}

	if rt == "podman" {
		args = append(args, fmt.Sprintf("--network=%s:ip=%s", cfg.network, cfg.ip))
	} else {
		args = append(args, "--network="+cfg.network, "--ip="+cfg.ip)
	}

	if cfg.role == "control-plane" {
		args = append(args, "-p=6443:6443")
	}

	args = append(args, nodeImage())

	if _, err := ctrExec(args...); err != nil {
		return err
	}
	fmt.Printf("e2e: started %s on %s (%s)\n", cfg.name, cfg.network, cfg.ip)
	return nil
}

func waitForContainerd(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := ctrExec("exec", name, "crictl", "info"); err == nil {
			return nil
		}
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("containerd not ready on %s after %v", name, timeout)
}

func raiseContainerdMemlock(containerName string) error {
	override := `[Service]
LimitMEMLOCK=infinity
`
	if _, err := ctrExec("exec", containerName,
		"mkdir", "-p", "/etc/systemd/system/containerd.service.d"); err != nil {
		return err
	}
	if err := writeToContainer(containerName,
		"/etc/systemd/system/containerd.service.d/memlock.conf", override); err != nil {
		return err
	}
	if _, err := ctrExec("exec", containerName, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := ctrExec("exec", containerName, "systemctl", "restart", "containerd"); err != nil {
		return err
	}
	fmt.Printf("e2e: raised containerd memlock on %s\n", containerName)
	return nil
}

// ── kubeadm ──────────────────────────────────────────────────────────────────

func k8sVersionFromImage() string {
	img := nodeImage()
	if idx := strings.LastIndex(img, ":"); idx >= 0 {
		return img[idx+1:]
	}
	return "v1.34.0"
}

func gatewayIP(subnet string) string {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}
	gw := make(net.IP, len(ipNet.IP))
	copy(gw, ipNet.IP)
	gw[len(gw)-1] = 1
	return gw.String()
}

func isUserNamespace(containerName string) bool {
	out, _ := ctrExec("exec", containerName, "cat", "/proc/self/uid_map")
	// In initial user namespace: "0 0 4294967295"; otherwise it's remapped.
	return !strings.Contains(out, "4294967295")
}


func kubeadmInit() error {
	cp := cpNode()

	certSANs := fmt.Sprintf("    - %s\n    - 127.0.0.1\n    - localhost", cp.ip)
	for _, n := range nodeConfigs {
		if gw := gatewayIP(n.subnet); gw != "" {
			certSANs += "\n    - " + gw
		}
	}

	kubeletExtraArgs := fmt.Sprintf("  - name: node-ip\n    value: \"%s\"", cp.ip)
	if isUserNamespace(cp.name) {
		kubeletExtraArgs += "\n  - name: feature-gates\n    value: \"KubeletInUserNamespace=true\""
		fmt.Println("e2e: detected user namespace — enabling KubeletInUserNamespace")
	}

	config := fmt.Sprintf(`apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: %s
  bindPort: 6443
nodeRegistration:
  name: %s
  criSocket: unix:///run/containerd/containerd.sock
  kubeletExtraArgs:
%s
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
kubernetesVersion: %s
apiServer:
  certSANs:
%s
networking:
  podSubnet: 10.244.0.0/16
  serviceSubnet: 10.96.0.0/16
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
failSwapOn: false
`, cp.ip, cp.name, kubeletExtraArgs, k8sVersionFromImage(), certSANs)

	if err := writeToContainer(cp.name, "/tmp/kubeadm-init.yaml", config); err != nil {
		return fmt.Errorf("write init config: %w", err)
	}

	initArgs := []string{"exec", cp.name, "kubeadm", "init",
		"--config=/tmp/kubeadm-init.yaml",
		"--ignore-preflight-errors=all",
	}
	if skipKubeProxy() {
		initArgs = append(initArgs, "--skip-phases=addon/kube-proxy")
		fmt.Println("e2e: skipping kube-proxy addon phase (Cilium will replace it)")
	}
	_, err := ctrExec(initArgs...)
	return err
}

func createJoinToken() (string, error) {
	out, err := ctrExec("exec", cpNode().name,
		"kubeadm", "token", "create", "--ttl=0")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func kubeadmJoin(cfg nodeConfig, token string) error {
	cp := cpNode()

	kubeletExtraArgs := fmt.Sprintf("  - name: node-ip\n    value: \"%s\"", cfg.ip)
	if isUserNamespace(cfg.name) {
		kubeletExtraArgs += "\n  - name: feature-gates\n    value: \"KubeletInUserNamespace=true\""
	}

	config := fmt.Sprintf(`apiVersion: kubeadm.k8s.io/v1beta4
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: %s:6443
    token: %s
    unsafeSkipCAVerification: true
nodeRegistration:
  name: %s
  criSocket: unix:///run/containerd/containerd.sock
  kubeletExtraArgs:
%s
`, cp.ip, token, cfg.name, kubeletExtraArgs)

	if err := writeToContainer(cfg.name, "/tmp/kubeadm-join.yaml", config); err != nil {
		return fmt.Errorf("write join config: %w", err)
	}

	_, err := ctrExec("exec", cfg.name, "kubeadm", "join",
		"--config=/tmp/kubeadm-join.yaml",
		"--ignore-preflight-errors=all",
	)
	return err
}

func installCilium() error {
	if _, err := exec.LookPath("helm"); err != nil {
		return fmt.Errorf("helm not found — install helm first (https://helm.sh/docs/intro/install/)")
	}

	if _, err := runCmd("helm", "repo", "add", "cilium", "https://helm.cilium.io/"); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("helm repo add: %w", err)
		}
	}
	if _, err := runCmd("helm", "repo", "update"); err != nil {
		return fmt.Errorf("helm repo update: %w", err)
	}

	cp := cpNode()
	args := []string{
		"template", "cilium", "cilium/cilium",
		"--namespace=kube-system",
		"--set=routingMode=tunnel",
		"--set=tunnelProtocol=vxlan",
		"--set=ipam.mode=kubernetes",
		"--set=image.pullPolicy=IfNotPresent",
		"--set=operator.replicas=1",
	}

	// Always specify direct API server address so Cilium doesn't depend on
	// ClusterIP routing during initial bootstrap (kube-proxy may not be ready).
	// Disable BPF auto-mount since we bind-mount /sys/fs/bpf from the host VM.
	args = append(args,
		"--set=k8sServiceHost="+cp.ip,
		"--set=k8sServicePort=6443",
		"--set=bpf.autoMount.enabled=false",
	)

	if skipKubeProxy() {
		args = append(args, "--set=kubeProxyReplacement=true")
		fmt.Println("e2e: Cilium with kubeProxyReplacement=true")
	} else {
		args = append(args, "--set=kubeProxyReplacement=false")
		fmt.Println("e2e: Cilium with kube-proxy (kubeProxyReplacement=false)")
	}

	output, err := runCmd("helm", args...)
	if err != nil {
		return fmt.Errorf("helm template: %w", err)
	}

	tmp, err := os.CreateTemp("", "cilium-manifest-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(output); err != nil {
		return err
	}
	tmp.Close()

	// Apply from inside the CP container (kubeConfigPath not yet available).
	if err := writeToContainer(cpNode().name, "/tmp/cilium.yaml", output); err != nil {
		return fmt.Errorf("write cilium manifest: %w", err)
	}
	if _, err := kubectlInCP("apply", "--server-side", "--force-conflicts", "-f", "/tmp/cilium.yaml"); err != nil {
		return fmt.Errorf("kubectl apply cilium: %w", err)
	}

	fmt.Println("e2e: waiting for Cilium pods to be ready…")
	return waitForCiliumReady(5 * time.Minute)
}

const flannelManifestURL = "https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml"

func installFlannel() error {
	// Download the Flannel manifest on the host and copy it into the CP container.
	out, err := runCmd("curl", "-fsSL", flannelManifestURL)
	if err != nil {
		return fmt.Errorf("download flannel manifest: %w", err)
	}

	if err := writeToContainer(cpNode().name, "/tmp/flannel.yaml", out); err != nil {
		return fmt.Errorf("write flannel manifest: %w", err)
	}

	if _, err := kubectlInCP("apply", "-f", "/tmp/flannel.yaml"); err != nil {
		return fmt.Errorf("kubectl apply flannel: %w", err)
	}

	fmt.Println("e2e: waiting for Flannel pods to be ready…")
	return waitForFlannelReady(5 * time.Minute)
}

func waitForFlannelReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectlInCP("get", "pods", "-n", "kube-flannel",
			"-l", "app=flannel", "--no-headers")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
			time.Sleep(5 * time.Second)
			continue
		}
		allRunning := true
		for _, line := range lines {
			if !strings.Contains(line, "Running") || !strings.Contains(line, "1/1") {
				allRunning = false
				break
			}
		}
		if allRunning && len(lines) >= len(nodeConfigs) {
			fmt.Printf("e2e: Flannel ready (%d pods)\n", len(lines))
			return nil
		}
		fmt.Printf("e2e: Flannel pods: %d/%d ready…\n", countReady(lines), len(nodeConfigs))
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for Flannel pods")
}

const calicoManifestURL = "https://raw.githubusercontent.com/projectcalico/calico/v3.29.3/manifests/calico.yaml"

func installCalico() error {
	cp := cpNode().name

	// Download inside the container and patch for nested container environments:
	// 1. Swap IPIP=Always→Never and VXLAN=Never→Always (IPIP doesn't work in Docker)
	// 2. Set CALICO_IPV4POOL_CIDR to match kubeadm's podSubnet (10.244.0.0/16)
	//    Calico defaults to 192.168.0.0/16 which won't match node podCIDR allocations.
	dlCmd := fmt.Sprintf(
		`curl -fsSL %s | `+
			`sed -e '/CALICO_IPV4POOL_IPIP/{n;s/Always/Never/}' `+
			`    -e '/CALICO_IPV4POOL_VXLAN/{n;s/Never/Always/}' `+
			`    -e 's|# - name: CALICO_IPV4POOL_CIDR|- name: CALICO_IPV4POOL_CIDR|' `+
			`    -e 's|#   value: "192.168.0.0/16"|  value: "10.244.0.0/16"|' `+
			`> /tmp/calico.yaml`,
		calicoManifestURL)
	if _, err := ctrExec("exec", cp, "sh", "-c", dlCmd); err != nil {
		return fmt.Errorf("download calico manifest: %w", err)
	}

	if _, err := kubectlInCP("apply", "-f", "/tmp/calico.yaml"); err != nil {
		return fmt.Errorf("kubectl apply calico: %w", err)
	}

	fmt.Println("e2e: waiting for Calico pods to be ready…")
	return waitForCalicoReady(5 * time.Minute)
}

func waitForCalicoReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectlInCP("get", "pods", "-n", "kube-system",
			"-l", "k8s-app=calico-node", "--no-headers")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
			time.Sleep(5 * time.Second)
			continue
		}
		allRunning := true
		for _, line := range lines {
			if !strings.Contains(line, "Running") || !strings.Contains(line, "1/1") {
				allRunning = false
				break
			}
		}
		if allRunning && len(lines) >= len(nodeConfigs) {
			fmt.Printf("e2e: Calico ready (%d pods)\n", len(lines))
			return nil
		}
		ready := countReady(lines)
		fmt.Printf("e2e: Calico pods: %d/%d ready…\n", ready, len(nodeConfigs))
		// Print pod details on first iteration and periodically to aid debugging.
		if ready == 0 && time.Until(deadline) > 4*time.Minute {
			for _, line := range lines {
				fmt.Printf("e2e:   %s\n", line)
			}
		}
		time.Sleep(5 * time.Second)
	}
	// Dump final pod state for debugging before returning error.
	if out, err := kubectlInCP("get", "pods", "-n", "kube-system",
		"-l", "k8s-app=calico-node", "-o", "wide"); err == nil {
		fmt.Printf("e2e: Calico final pod state:\n%s\n", out)
	}
	if out, err := kubectlInCP("describe", "pods", "-n", "kube-system",
		"-l", "k8s-app=calico-node"); err == nil {
		// Only print last 60 lines to avoid noise.
		descLines := strings.Split(out, "\n")
		if len(descLines) > 60 {
			descLines = descLines[len(descLines)-60:]
		}
		fmt.Printf("e2e: Calico pod describe (tail):\n%s\n", strings.Join(descLines, "\n"))
	}
	return fmt.Errorf("timed out waiting for Calico pods")
}

func waitForCiliumReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectlInCP("get", "pods", "-n", "kube-system",
			"-l", "k8s-app=cilium", "--no-headers")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
			time.Sleep(5 * time.Second)
			continue
		}
		allRunning := true
		for _, line := range lines {
			if !strings.Contains(line, "Running") || !strings.Contains(line, "1/1") {
				allRunning = false
				break
			}
		}
		if allRunning && len(lines) >= len(nodeConfigs) {
			fmt.Printf("e2e: Cilium ready (%d pods)\n", len(lines))
			return nil
		}
		fmt.Printf("e2e: Cilium pods: %d/%d ready…\n", countReady(lines), len(nodeConfigs))
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for Cilium pods")
}

func countReady(lines []string) int {
	n := 0
	for _, line := range lines {
		if strings.Contains(line, "Running") && strings.Contains(line, "1/1") {
			n++
		}
	}
	return n
}

func patchKubeProxy() error {
	// Set conntrack.maxPerCore=0 in the kube-proxy ConfigMap to skip
	// conntrack sysctl writes that fail in user namespaces and Docker
	// Desktop macOS where /proc/sys is read-only.
	// We get the full ConfigMap as YAML, sed the value, and re-apply.
	// This preserves all other keys (kubeconfig.conf etc.).
	cp := cpNode().name

	patchCmd := `kubectl --kubeconfig=/etc/kubernetes/admin.conf ` +
		`get configmap kube-proxy -n kube-system -o yaml ` +
		`| sed 's/maxPerCore: null/maxPerCore: 0/' ` +
		`| kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f -`
	if _, err := ctrExec("exec", cp, "sh", "-c", patchCmd); err != nil {
		return fmt.Errorf("patch kube-proxy configmap: %w", err)
	}

	// Delete existing pods so they pick up the ConfigMap change.
	_, err := kubectlInCP("delete", "pods", "-n", "kube-system", "-l", "k8s-app=kube-proxy")
	return err
}

// ensureKubeProxyReady waits for kube-proxy pods to become ready.
// If pods enter CrashLoopBackOff (typically conntrack sysctl permission error),
// it patches the kube-proxy ConfigMap (maxPerCore: 0) and restarts pods.
func ensureKubeProxyReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	patched := false
	for time.Now().Before(deadline) {
		out, err := kubectlInCP("get", "pods", "-n", "kube-system",
			"-l", "k8s-app=kube-proxy", "--no-headers")
		if err == nil {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			allRunning := len(lines) > 0 && lines[0] != ""
			hasCrash := false
			for _, line := range lines {
				if strings.Contains(line, "CrashLoopBackOff") || strings.Contains(line, "Error") {
					hasCrash = true
				}
				if !strings.Contains(line, "Running") || !strings.Contains(line, "1/1") {
					allRunning = false
				}
			}
			if allRunning {
				fmt.Printf("e2e: kube-proxy ready (%d pods)\n", len(lines))
				return nil
			}
			if hasCrash && !patched {
				fmt.Println("e2e: kube-proxy crashing, patching ConfigMap (maxPerCore: 0)…")
				if err := patchKubeProxy(); err != nil {
					return fmt.Errorf("patch kube-proxy: %w", err)
				}
				patched = true
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for kube-proxy pods")
}

func removeCPTaint() error {
	_, err := kubectlInCP("taint", "nodes", cpNode().name,
		"node-role.kubernetes.io/control-plane:NoSchedule-")
	if err != nil && strings.Contains(err.Error(), "not found") {
		return nil
	}
	return err
}

func waitForNodesReady(count int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := kubectlInCP("get", "nodes", "--no-headers")
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		ready := 0
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line == "" {
				continue
			}
			if strings.Contains(line, " Ready") && !strings.Contains(line, "NotReady") {
				ready++
			}
		}
		if ready >= count {
			fmt.Printf("e2e: %d/%d nodes Ready\n", ready, count)
			return nil
		}
		fmt.Printf("e2e: %d/%d nodes Ready…\n", ready, count)
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %d Ready nodes", count)
}

// ── Kubeconfig ───────────────────────────────────────────────────────────────

func extractKubeConfig() (*rest.Config, string, error) {
	tmpFile := filepath.Join(os.TempDir(), "wk-e2e-kubeconfig")

	if _, err := ctrExec("cp", cpNode().name+":/etc/kubernetes/admin.conf", tmpFile); err != nil {
		return nil, "", fmt.Errorf("copy kubeconfig: %w", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, "", err
	}

	modified := strings.ReplaceAll(string(data),
		"https://"+cpNode().ip+":6443",
		"https://127.0.0.1:6443")
	if err := os.WriteFile(tmpFile, []byte(modified), 0600); err != nil {
		return nil, "", err
	}

	config, err := clientcmd.BuildConfigFromFlags("", tmpFile)
	if err != nil {
		return nil, "", err
	}
	return config, tmpFile, nil
}

// ── Image management ─────────────────────────────────────────────────────────

func loadImageToAllNodes(image string) error {
	tarPath := filepath.Join(os.TempDir(), "wk-e2e-image.tar")

	if _, err := ctrExec("save", "-o", tarPath, image); err != nil {
		return fmt.Errorf("save image %s: %w", image, err)
	}
	defer os.Remove(tarPath)

	// Use /var/tmp instead of /tmp because Docker's --tmpfs=/tmp
	// causes docker cp to write to the overlay layer which is invisible
	// from inside the container's tmpfs mount.
	const ctrTarPath = "/var/tmp/image.tar"
	for _, n := range nodeConfigs {
		if _, err := ctrExec("cp", tarPath, n.name+":"+ctrTarPath); err != nil {
			return fmt.Errorf("copy tar to %s: %w", n.name, err)
		}
		if _, err := ctrExec("exec", n.name,
			"ctr", "-n=k8s.io", "images", "import", "--all-platforms", ctrTarPath,
		); err != nil {
			return fmt.Errorf("import image on %s: %w", n.name, err)
		}
		dockerRef := "docker.io/" + image
		ctrExec("exec", n.name,
			"ctr", "-n=k8s.io", "images", "tag", "localhost/"+image, dockerRef) //nolint:errcheck
		ctrExec("exec", n.name, "rm", ctrTarPath) //nolint:errcheck
		fmt.Printf("e2e: loaded %s into %s\n", image, n.name)
	}
	return nil
}

// ── STUN servers ─────────────────────────────────────────────────────────────

func buildAndDeploySTUN() error {
	arch := runtime.GOARCH
	tmpBin := filepath.Join(os.TempDir(), "wirekube-stun-linux-"+arch)

	cmd := exec.Command("go", "build", "-o", tmpBin, "./cmd/stun-server/")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Dir = repoRoot()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build stun: %w\n%s", err, out)
	}
	defer os.Remove(tmpBin)

	cp := cpNode()
	if _, err := ctrExec("cp", tmpBin, cp.name+":/usr/local/bin/wirekube-stun"); err != nil {
		return fmt.Errorf("copy stun binary: %w", err)
	}
	if _, err := ctrExec("exec", cp.name, "chmod", "+x", "/usr/local/bin/wirekube-stun"); err != nil {
		return fmt.Errorf("chmod stun: %w", err)
	}

	for _, port := range []int{stunPort1, stunPort2} {
		addr := fmt.Sprintf(":%d", port)
		if _, err := ctrExec("exec", "-d", cp.name,
			"/usr/local/bin/wirekube-stun", addr,
		); err != nil {
			return fmt.Errorf("start stun on %s: %w", addr, err)
		}
		fmt.Printf("e2e: STUN server on %s%s\n", cp.name, addr)
	}
	return nil
}

// ── WireKube deployment ──────────────────────────────────────────────────────

func deployWireKubeCRDs(_ context.Context) error {
	if err := kubectlApply("config/crd"); err != nil {
		return fmt.Errorf("apply CRDs: %w", err)
	}

	if _, err := kubectl("create", "namespace", agentNamespace); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("create namespace: %w", err)
		}
	}

	if err := kubectlApply("config/agent/rbac.yaml"); err != nil {
		return fmt.Errorf("apply RBAC: %w", err)
	}

	return nil
}

func deployWireKubeAgents(_ context.Context) error {
	image := wireKubeImage()

	if err := applyDaemonSet(image); err != nil {
		return fmt.Errorf("apply DaemonSet: %w", err)
	}

	if err := deployRelay(image); err != nil {
		return fmt.Errorf("deploy relay: %w", err)
	}

	return nil
}

func applyDaemonSet(image string) error {
	raw, err := os.ReadFile("config/agent/daemonset.yaml")
	if err != nil {
		return err
	}

	content := string(raw)

	// Override image.
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "image:") {
			indent := strings.Repeat(" ", len(line)-len(strings.TrimLeft(line, " ")))
			lines[i] = indent + "image: " + image
		}
	}
	content = strings.Join(lines, "\n")

	// Inject direct API server address. Required for no-kube-proxy mode
	// (Cilium kube-proxy replacement) and also avoids conntrack issues
	// in kube-proxy mode when running under user namespaces.
	apiEnv := fmt.Sprintf(`            - name: KUBERNETES_SERVICE_HOST
              value: "%s"
            - name: KUBERNETES_SERVICE_PORT
              value: "6443"
            - name: WIREKUBE_SYNC_INTERVAL_SECONDS
              value: "5"`, cpNode().ip)
	content = strings.Replace(content,
		"            - name: WIREKUBE_INTERFACE",
		apiEnv+"\n            - name: WIREKUBE_INTERFACE", 1)

	tmp, err := os.CreateTemp("", "wk-ds-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		return err
	}
	tmp.Close()

	return kubectlApply(tmp.Name())
}

func deployRelay(image string) error {
	yaml := fmt.Sprintf(`---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wirekube-relay
  namespace: %s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wirekube-relay
  template:
    metadata:
      labels:
        app: wirekube-relay
    spec:
      hostNetwork: true
      dnsPolicy: Default
      tolerations:
        - operator: Exists
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: Exists
      containers:
        - name: relay
          image: %s
          command: ["wirekube-relay"]
          args: ["--addr=:3478"]
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 200m
              memory: 64Mi
`, agentNamespace, image)

	tmp, err := os.CreateTemp("", "wk-relay-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(yaml); err != nil {
		return err
	}
	tmp.Close()

	return kubectlApply(tmp.Name())
}

func applyWireKubeMeshCR(ctx context.Context, stunServers []string, relayEndpoint string) error {
	mesh := &wirekubev1alpha1.WireKubeMesh{}
	mesh.Name = meshName
	mesh.Spec.ListenPort = wgPort
	mesh.Spec.STUNServers = stunServers
	mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{
		Mode:     "auto",
		Provider: "external",
		External: &wirekubev1alpha1.ExternalRelaySpec{
			Endpoint:  relayEndpoint,
			Transport: "tcp",
		},
		HandshakeTimeoutSeconds:    15,
		DirectRetryIntervalSeconds: 30,
	}
	mesh.Spec.NATTraversal = &wirekubev1alpha1.NATTraversalSpec{
		HandshakeValidWindowSeconds:  10,
		HealthProbeTimeoutSeconds:    5,
		DirectConnectedWindowSeconds: 45,
	}
	mesh.Spec.AutoAllowedIPs = &wirekubev1alpha1.AutoAllowedIPsSpec{
		Strategy: "node-internal-ip",
	}

	existing := &wirekubev1alpha1.WireKubeMesh{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, existing); err != nil {
		return k8sClient.Create(ctx, mesh)
	}
	patch := client.MergeFrom(existing.DeepCopy())
	existing.Spec = mesh.Spec
	return k8sClient.Patch(ctx, existing, patch)
}

func waitForAgents(ctx context.Context, minCount int) error {
	fmt.Printf("e2e: waiting for %d agents…\n", minCount)
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var list corev1.PodList
		if err := k8sClient.List(ctx, &list,
			client.InNamespace(agentNamespace),
			client.MatchingLabels{"app": "wirekube-agent"},
		); err == nil {
			ready := 0
			for _, pod := range list.Items {
				if pod.Status.Phase == corev1.PodRunning {
					ready++
				}
			}
			if ready >= minCount {
				fmt.Printf("e2e: %d agents running\n", ready)
				time.Sleep(10 * time.Second)
				return nil
			}
			fmt.Printf("e2e: %d/%d agents…\n", ready, minCount)
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %d agents", minCount)
}

// ── CLI helpers ──────────────────────────────────────────────────────────────

func kubectl(args ...string) (string, error) {
	fullArgs := append([]string{"--kubeconfig", kubeConfigPath}, args...)
	return runCmd("kubectl", fullArgs...)
}

func kubectlInCP(args ...string) (string, error) {
	execArgs := []string{"exec", cpNode().name, "kubectl",
		"--kubeconfig=/etc/kubernetes/admin.conf"}
	execArgs = append(execArgs, args...)
	return ctrExec(execArgs...)
}

func kubectlApply(path string) error {
	_, err := kubectl("apply", "-f", path)
	return err
}

func writeToContainer(containerName, destPath, content string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	cmd := fmt.Sprintf("echo '%s' | base64 -d > %s", encoded, destPath)
	_, err := ctrExec("exec", containerName, "sh", "-c", cmd)
	return err
}

func eventually(t *testing.T, fn func() bool, timeout, interval time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timed out after %s: %s", timeout, msg)
}

// ── Pod execution ────────────────────────────────────────────────────────────

func agentPodForNode(ctx context.Context, t *testing.T, nodeName string) corev1.Pod {
	t.Helper()
	var list corev1.PodList
	if err := k8sClient.List(ctx, &list,
		client.InNamespace(agentNamespace),
		client.MatchingLabels{"app": "wirekube-agent"},
	); err != nil {
		t.Fatalf("list agent pods: %v", err)
	}
	for _, pod := range list.Items {
		if pod.Spec.NodeName == nodeName {
			return pod
		}
	}
	t.Fatalf("no agent pod on node %q", nodeName)
	return corev1.Pod{}
}

func execInPod(ctx context.Context, t *testing.T, pod corev1.Pod, container string, cmd []string) (string, error) {
	t.Helper()

	execOpts := &corev1.PodExecOptions{
		Container: container,
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
	}
	rc, err := rest.RESTClientFor(&rest.Config{
		Host:            restConfig.Host,
		TLSClientConfig: restConfig.TLSClientConfig,
		BearerToken:     restConfig.BearerToken,
		BearerTokenFile: restConfig.BearerTokenFile,
		APIPath:         "/api",
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &corev1.SchemeGroupVersion,
			NegotiatedSerializer: clientgoscheme.Codecs.WithoutConversion(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("rest client: %w", err)
	}

	req := rc.Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(execOpts, clientgoscheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("spdy executor: %w", err)
	}

	var buf bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &buf,
		Stderr: &buf,
	})
	return buf.String(), err
}

// ── Fault injection ──────────────────────────────────────────────────────────

func blockWireGuardUDP(t *testing.T, nodeName string) func() {
	t.Helper()
	if _, err := ctrExec("exec", nodeName,
		"iptables", "-I", "INPUT", "1",
		"-p", "udp", "--dport", fmt.Sprintf("%d", wgPort),
		"-j", "DROP",
	); err != nil {
		t.Fatalf("block WG UDP on %s: %v", nodeName, err)
	}
	t.Logf("blocked WG UDP on %s", nodeName)

	return func() {
		if _, err := ctrExec("exec", nodeName,
			"iptables", "-D", "INPUT",
			"-p", "udp", "--dport", fmt.Sprintf("%d", wgPort),
			"-j", "DROP",
		); err != nil {
			t.Logf("warning: unblock WG UDP on %s: %v", nodeName, err)
		}
	}
}

func patchMeshRelayMode(ctx context.Context, t *testing.T, newMode string) func() {
	t.Helper()

	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Fatalf("get WireKubeMesh: %v", err)
	}
	originalMode := ""
	if mesh.Spec.Relay != nil {
		originalMode = mesh.Spec.Relay.Mode
	}

	patch := client.MergeFrom(mesh.DeepCopy())
	if mesh.Spec.Relay == nil {
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
	}
	mesh.Spec.Relay.Mode = newMode
	if err := k8sClient.Patch(ctx, &mesh, patch); err != nil {
		t.Fatalf("patch relay.mode=%s: %v", newMode, err)
	}
	t.Logf("patched relay.mode=%s (was %q)", newMode, originalMode)

	return func() {
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var m wirekubev1alpha1.WireKubeMesh
		if err := k8sClient.Get(rctx, types.NamespacedName{Name: meshName}, &m); err != nil {
			t.Logf("warning: restore relay.mode: %v", err)
			return
		}
		p := client.MergeFrom(m.DeepCopy())
		if m.Spec.Relay == nil {
			m.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
		}
		m.Spec.Relay.Mode = originalMode
		if err := k8sClient.Patch(rctx, &m, p); err != nil {
			t.Logf("warning: restore relay.mode=%q: %v", originalMode, err)
		}
	}
}

func relayEndpointFromMesh(ctx context.Context, t *testing.T) string {
	t.Helper()
	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Fatalf("get WireKubeMesh: %v", err)
	}
	if mesh.Spec.Relay != nil && mesh.Spec.Relay.External != nil {
		return mesh.Spec.Relay.External.Endpoint
	}
	return ""
}

func setRelayEndpoint(ctx context.Context, t *testing.T, endpoint string) {
	t.Helper()
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var mesh wirekubev1alpha1.WireKubeMesh
	if err := k8sClient.Get(tctx, types.NamespacedName{Name: meshName}, &mesh); err != nil {
		t.Logf("warning: get WireKubeMesh: %v", err)
		return
	}
	p := client.MergeFrom(mesh.DeepCopy())
	if mesh.Spec.Relay == nil {
		mesh.Spec.Relay = &wirekubev1alpha1.RelaySpec{}
	}
	if mesh.Spec.Relay.External == nil {
		mesh.Spec.Relay.External = &wirekubev1alpha1.ExternalRelaySpec{}
	}
	mesh.Spec.Relay.External.Endpoint = endpoint
	if err := k8sClient.Patch(tctx, &mesh, p); err != nil {
		t.Logf("warning: patch relay endpoint to %s: %v", endpoint, err)
	}
}
