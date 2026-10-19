package main

import (
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	internalconfig "github.com/inerplat/wirekube/internal/kubeconfig"
	"github.com/inerplat/wirekube/pkg/connect"
)

// connectCmd joins this machine to the cluster as a short-lived external
// peer, so pod, Service and gateway addresses are reachable from local tools
// for as long as the command runs.
func connectCmd() *cobra.Command {
	var opts connect.Options
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Reach cluster pods and Services from this machine",
		Long: `Issue a WireKubeExternalPeer for this machine, bring up a local WireGuard
tunnel to the cluster, and route the mesh, pod, Service and gateway ranges
through it. Names under the cluster domain resolve through the cluster DNS.

The command runs in the foreground; Ctrl-C tears down the tunnel and deletes
the peer. A peer left behind by a crashed session is replaced on the next
run. Creating the tunnel needs root, so run it with sudo; under sudo the
invoking user's kubeconfig is used.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := connect.Supported(); err != nil {
				return err
			}
			if opts.MTU != 0 && (opts.MTU < 576 || opts.MTU > 1420) {
				return fmt.Errorf("--mtu must be between 576 and 1420")
			}
			useInvokingUserKubeconfig()
			c, err := k8sClient()
			if err != nil {
				return err
			}
			host, _ := os.Hostname()
			opts.Host = host
			if opts.Name == "" {
				opts.Name = connect.DefaultName(invokingUser(), host)
			}
			if opts.SearchNamespace == "" {
				// As with kubectl, -n picks the namespace, else the context's. The
				// global default is WireKube's own namespace, not one to resolve in.
				if cmd.Flags().Changed("namespace") {
					opts.SearchNamespace = options.namespace
				} else {
					opts.SearchNamespace = kubeconfigNamespace()
				}
			}
			opts.Out = cmd.ErrOrStderr()

			ctx, stop := signal.NotifyContext(cmd.Context(), stopSignals()...)
			defer stop()
			return connect.Run(ctx, c, opts)
		},
	}
	cmd.Flags().StringVar(&opts.Name, "name", "", "external peer name (default: connect-<user>-<host>)")
	cmd.Flags().DurationVar(&opts.TTL, "ttl", 0, "hard limit on the session: the controller deletes the peer this long after issuing it; 0 = no limit")
	cmd.Flags().StringSliceVar(&opts.Allowed, "allow", nil, "CIDR(s) to route; replaces the controller defaults (mesh, pod, service and gateway CIDRs)")
	cmd.Flags().StringVar(&opts.IngressPeer, "ingress-peer", "", "pin to a specific WireKubePeer by name (default: controller auto-selects)")
	cmd.Flags().Int32Var(&opts.MTU, "mtu", 0, "tunnel MTU (default: controller-recommended 1248)")
	cmd.Flags().DurationVar(&opts.WaitActive, "wait", 60*time.Second, "how long to wait for the controller to activate the peer")
	cmd.Flags().StringVar(&opts.InterfaceName, "interface", connect.DefaultInterfaceName, "tunnel interface name")
	cmd.Flags().BoolVar(&opts.DNS, "dns", true, "resolve the cluster domain through the cluster DNS")
	cmd.Flags().StringVar(&opts.DNSServer, "dns-server", "", "cluster DNS server address (default: kube-system/kube-dns ClusterIP)")
	cmd.Flags().StringVar(&opts.ClusterDomain, "cluster-domain", "cluster.local", "cluster DNS domain")
	cmd.Flags().StringVar(&opts.SearchNamespace, "search-namespace", "", "namespace whose Services resolve by short name (default: -n, else the kubeconfig context namespace)")
	return cmd
}

// useInvokingUserKubeconfig points a sudo'd session at the invoking user's
// kubeconfig. sudo commonly resets HOME to root's, where there is none, and
// the cluster credentials the user meant are theirs.
func useInvokingUserKubeconfig() {
	if options.kubeconfig != "" || os.Getenv("KUBECONFIG") != "" {
		return
	}
	name := os.Getenv("SUDO_USER")
	if name == "" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	path := filepath.Join(u.HomeDir, ".kube", "config")
	if _, err := os.Stat(path); err == nil {
		options.kubeconfig = path
	}
}

func invokingUser() string {
	if name := os.Getenv("SUDO_USER"); name != "" {
		return name
	}
	if u, err := user.Current(); err == nil {
		// Windows reports DOMAIN\user.
		return filepath.Base(filepath.ToSlash(u.Username))
	}
	return "user"
}

func kubeconfigNamespace() string {
	factory := internalconfig.New(internalconfig.Options{
		Kubeconfig: options.kubeconfig,
		Context:    options.context,
		Overrides:  &options.overrides,
	}, scheme)
	ns, err := factory.Namespace()
	if err != nil || ns == "" {
		return "default"
	}
	return ns
}

// stopSignals lists the signals that end a session cleanly, including the SIGHUP
// of a closed terminal, which would otherwise kill it before cleanup. Under nohup
// SIGHUP is left ignored, since subscribing to it would undo that.
func stopSignals() []os.Signal {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	return sigs
}
