// wirekubectl is the WireKube CLI tool.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	internalconfig "github.com/inerplat/wirekube/internal/kubeconfig"
	internalversion "github.com/inerplat/wirekube/internal/version"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/externalpeer"
	"github.com/inerplat/wirekube/pkg/wireguard"
)

var scheme = runtime.NewScheme()

type globalOptions struct {
	kubeconfig string
	context    string
	namespace  string
	timeout    time.Duration
	output     string
	client     func() (client.Client, error)
}

var options = &globalOptions{}

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(scheme))
}

func main() {
	root := newRootCommand()
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	if err := root.ExecuteContext(context.Background()); err != nil {
		if options.output == "json" {
			_ = writeJSON(os.Stderr, map[string]any{
				"schemaVersion": "v1alpha1",
				"error": map[string]string{
					"code":    "command_failed",
					"message": err.Error(),
				},
			})
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "wirekubectl",
		Short:         "Manage and install WireKube",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			switch options.output {
			case "text", "json":
				return nil
			default:
				return fmt.Errorf("unsupported output format %q: use text or json", options.output)
			}
		},
	}
	root.PersistentFlags().StringVar(&options.kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	root.PersistentFlags().StringVar(&options.context, "context", "", "kubeconfig context to use")
	root.PersistentFlags().StringVar(&options.namespace, "namespace", "wirekube-system", "namespace for WireKube workloads")
	root.PersistentFlags().DurationVar(&options.timeout, "timeout", 5*time.Minute, "timeout for Kubernetes operations")
	root.PersistentFlags().StringVar(&options.output, "output", "text", "output format: text or json")

	root.AddCommand(
		versionCmd(),
		installCmd(),
		statusCmd(),
		doctorCmd(),
		upgradeCmd(),
		uninstallCmd(),
		manifestCmd(),
		meshCmd(),
		peersCmd(),
		exportCmd(),
		importCmd(),
		tokenCmd(),
		externalCmd(),
		inviteCmd(),
		revokeCmd(),
	)
	return root
}

func k8sClient() (client.Client, error) {
	if options.client != nil {
		return options.client()
	}
	factory := internalconfig.New(internalconfig.Options{
		Kubeconfig: options.kubeconfig,
		Context:    options.context,
		Namespace:  options.namespace,
		Timeout:    options.timeout,
	}, scheme)
	return factory.Client()
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show wirekubectl build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := internalversion.Current()
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), info)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Version:       %s\n", info.Version)
			fmt.Fprintf(cmd.OutOrStdout(), "Commit:        %s\n", info.Commit)
			fmt.Fprintf(cmd.OutOrStdout(), "Build date:    %s\n", info.BuildDate)
			fmt.Fprintf(cmd.OutOrStdout(), "Default image: %s\n", valueOrDash(info.DefaultImage))
			return nil
		},
	}
}

// mesh
func meshCmd() *cobra.Command {
	var (
		listenPort  int32
		stunServers []string
	)

	cmd := &cobra.Command{
		Use:   "mesh",
		Short: "Manage WireKubeMesh configuration",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create the default WireKubeMesh or patch explicitly supplied fields",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			mesh := &wirekubev1alpha1.WireKubeMesh{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: wirekubev1alpha1.WireKubeMeshSpec{
					ListenPort:  listenPort,
					STUNServers: append([]string(nil), stunServers...),
				},
			}
			ctx := cmd.Context()
			existing := &wirekubev1alpha1.WireKubeMesh{}
			err = c.Get(ctx, client.ObjectKey{Name: "default"}, existing)
			if apierrors.IsNotFound(err) {
				if err := c.Create(ctx, mesh); err != nil {
					return fmt.Errorf("create WireKubeMesh: %w", err)
				}
				return writeResult(cmd, map[string]any{"name": "default", "operation": "created"}, "WireKubeMesh 'default' created\n")
			}
			if err != nil {
				return fmt.Errorf("get WireKubeMesh: %w", err)
			}

			patch := client.MergeFrom(existing.DeepCopy())
			changed := false
			if cmd.Flags().Changed("port") && existing.Spec.ListenPort != listenPort {
				existing.Spec.ListenPort = listenPort
				changed = true
			}
			if cmd.Flags().Changed("stun-server") && !stringSlicesEqual(existing.Spec.STUNServers, stunServers) {
				existing.Spec.STUNServers = append([]string(nil), stunServers...)
				changed = true
			}
			if changed {
				if err := c.Patch(ctx, existing, patch); err != nil {
					return fmt.Errorf("patch WireKubeMesh: %w", err)
				}
				return writeResult(cmd, map[string]any{"name": "default", "operation": "patched"}, "WireKubeMesh 'default' patched\n")
			}
			return writeResult(cmd, map[string]any{"name": "default", "operation": "unchanged"}, "WireKubeMesh 'default' already exists; no fields were changed\n")
		},
	}
	initCmd.Flags().Int32Var(&listenPort, "port", 51820, "WireGuard listen port")
	initCmd.Flags().StringSliceVar(&stunServers, "stun-server", []string{"stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"}, "STUN server; may be repeated")
	cmd.AddCommand(initCmd)

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show WireKubeMesh status",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			mesh := &wirekubev1alpha1.WireKubeMesh{}
			if err := c.Get(cmd.Context(), client.ObjectKey{Name: "default"}, mesh); err != nil {
				return fmt.Errorf("get WireKubeMesh: %w", err)
			}
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), mesh)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Name:        %s\n", mesh.Name)
			fmt.Fprintf(cmd.OutOrStdout(), "Listen Port: %d\n", mesh.Spec.ListenPort)
			fmt.Fprintf(cmd.OutOrStdout(), "Interface:   %s\n", mesh.Spec.InterfaceName)
			fmt.Fprintf(cmd.OutOrStdout(), "MTU:         %d\n", mesh.Spec.MTU)
			fmt.Fprintf(cmd.OutOrStdout(), "Ready Peers: %d / %d\n", mesh.Status.ReadyPeers, mesh.Status.TotalPeers)
			return nil
		},
	}
	cmd.AddCommand(statusCmd)

	return cmd
}

// peers list
func peersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "peers",
		Short: "List all WireKubePeers and their connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			peerList := &wirekubev1alpha1.WireKubePeerList{}
			if err := c.List(cmd.Context(), peerList); err != nil {
				return err
			}
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), peerList.Items)
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tENDPOINT\tALLOWED-IPS\tCONNECTED\tLAST HANDSHAKE")
			for _, p := range peerList.Items {
				lastHS := "-"
				if p.Status.LastHandshake != nil {
					lastHS = formatDuration(time.Since(p.Status.LastHandshake.Time))
				}
				allowedIPs := strings.Join(p.Spec.AllowedIPs, ",")
				if allowedIPs == "" {
					allowedIPs = "(none)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n",
					p.Name,
					p.Spec.Endpoint,
					allowedIPs,
					p.Status.Connected,
					lastHS,
				)
			}
			return w.Flush()
		},
	}
}

// export peers for cross-cluster sharing
func exportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export local peers as YAML for import into another cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			peerList := &wirekubev1alpha1.WireKubePeerList{}
			if err := c.List(cmd.Context(), peerList); err != nil {
				return err
			}
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), peerList.Items)
			}

			for i, p := range peerList.Items {
				exportPeer := wirekubev1alpha1.WireKubePeer{
					TypeMeta: metav1.TypeMeta{
						APIVersion: wirekubev1alpha1.GroupVersion.String(),
						Kind:       "WireKubePeer",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: p.Name,
					},
					Spec: wirekubev1alpha1.WireKubePeerSpec{
						PublicKey:           p.Spec.PublicKey,
						Endpoint:            p.Spec.Endpoint,
						AllowedIPs:          p.Spec.AllowedIPs,
						PersistentKeepalive: p.Spec.PersistentKeepalive,
					},
				}
				b, err := marshalYAML(exportPeer)
				if err != nil {
					return err
				}
				if i > 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "---")
				}
				fmt.Fprint(cmd.OutOrStdout(), string(b))
			}
			return nil
		},
	}
	return cmd
}

// import peers from another cluster
func importCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import [file]",
		Short: "Import peers from a YAML file (produced by 'wirekubectl export')",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}

			docs := splitYAMLDocs(data)
			c, err := k8sClient()
			if err != nil {
				return err
			}

			for _, doc := range docs {
				peer := &wirekubev1alpha1.WireKubePeer{}
				if err := yaml.Unmarshal(doc, peer); err != nil {
					return fmt.Errorf("parsing peer YAML: %w", err)
				}
				if peer.Name == "" {
					continue
				}

				existing := &wirekubev1alpha1.WireKubePeer{}
				err := c.Get(cmd.Context(), client.ObjectKey{Name: peer.Name}, existing)
				if err != nil {
					if err := c.Create(cmd.Context(), peer); err != nil {
						return fmt.Errorf("creating peer %s: %w", peer.Name, err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "created peer %s\n", peer.Name)
				} else {
					patch := client.MergeFrom(existing.DeepCopy())
					existing.Spec = peer.Spec
					if err := c.Patch(cmd.Context(), existing, patch); err != nil {
						return fmt.Errorf("updating peer %s: %w", peer.Name, err)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "updated peer %s\n", peer.Name)
				}
			}
			return nil
		},
	}
}

// token create (bootstrap tokens for new node enrollment)
func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage bootstrap tokens for node enrollment",
	}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new bootstrap token for enrolling a node",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "# Bootstrap token creation not yet implemented.")
			fmt.Fprintln(cmd.OutOrStdout(), "# Use kubeadm token create or manually create a ServiceAccount for the agent.")
			return nil
		},
	}
	cmd.AddCommand(createCmd)
	return cmd
}

// externalCmd groups external WireGuard client lifecycle commands. The
// top-level invite/revoke commands remain for compatibility with earlier
// examples, while this group gives operators a discoverable place to list,
// inspect, issue, and remove off-cluster clients.
func externalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "external",
		Aliases: []string{"external-peer", "external-peers", "externals"},
		Short:   "Manage external WireGuard clients",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return listExternalPeers(cmd.Context(), cmd.OutOrStdout())
		},
	}
	cmd.AddCommand(
		externalListCmd(),
		externalGetCmd(),
		externalRemoveCmd(),
		inviteCmd(),
	)
	return cmd
}

func externalListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List external WireGuard clients",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return listExternalPeers(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

func externalGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "get <name>",
		Aliases: []string{"show", "describe"},
		Short:   "Show one external WireGuard client",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			cr := &wirekubev1alpha1.WireKubeExternalPeer{}
			if err := c.Get(cmd.Context(), client.ObjectKey{Name: args[0]}, cr); err != nil {
				return fmt.Errorf("get external peer: %w", err)
			}
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), cr)
			}
			writeExternalPeerDetail(cmd.OutOrStdout(), cr)
			return nil
		},
	}
}

func externalRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Aliases: []string{"delete", "rm", "revoke"},
		Short:   "Remove an external WireGuard client",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			if err := removeExternalPeer(cmd.Context(), c, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed external peer %s\n", args[0])
			return nil
		},
	}
}

func listExternalPeers(ctx context.Context, out io.Writer) error {
	c, err := k8sClient()
	if err != nil {
		return err
	}
	peerList := &wirekubev1alpha1.WireKubeExternalPeerList{}
	if err := c.List(ctx, peerList); err != nil {
		return err
	}
	if options.output == "json" {
		return writeJSON(out, peerList.Items)
	}
	return writeExternalPeerTable(out, peerList.Items, time.Now())
}

func writeExternalPeerTable(out io.Writer, peers []wirekubev1alpha1.WireKubeExternalPeer, now time.Time) error {
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Name < peers[j].Name
	})
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDISPLAY\tPHASE\tMESH-IP\tENDPOINT\tINGRESS\tMTU\tAGE")
	for _, p := range peers {
		phase := string(p.Status.Phase)
		if phase == "" {
			phase = "-"
		}
		age := "-"
		if !p.CreationTimestamp.IsZero() {
			age = formatDuration(now.Sub(p.CreationTimestamp.Time))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			p.Name,
			valueOrDash(p.Spec.DisplayName),
			phase,
			valueOrDash(p.Status.AssignedMeshIP),
			valueOrDash(p.Status.RelayEndpoint),
			valueOrDash(p.Status.IngressPeerName),
			externalpeer.EffectiveMTU(&p),
			age,
		)
	}
	return w.Flush()
}

func writeExternalPeerDetail(out io.Writer, cr *wirekubev1alpha1.WireKubeExternalPeer) {
	fmt.Fprintf(out, "Name:                 %s\n", cr.Name)
	fmt.Fprintf(out, "Display Name:         %s\n", valueOrDash(cr.Spec.DisplayName))
	fmt.Fprintf(out, "Phase:                %s\n", valueOrDash(string(cr.Status.Phase)))
	fmt.Fprintf(out, "Assigned Mesh IP:     %s\n", valueOrDash(cr.Status.AssignedMeshIP))
	fmt.Fprintf(out, "Relay Endpoint:       %s\n", valueOrDash(cr.Status.RelayEndpoint))
	fmt.Fprintf(out, "Ingress Peer:         %s\n", valueOrDash(cr.Status.IngressPeerName))
	fmt.Fprintf(out, "Ingress Public Key:   %s\n", valueOrDash(cr.Status.IngressPublicKey))
	fmt.Fprintf(out, "Public Key:           %s\n", valueOrDash(cr.Status.PublicKey))
	fmt.Fprintf(out, "MTU:                  %d\n", externalpeer.EffectiveMTU(cr))
	fmt.Fprintf(out, "Allowed Destinations: %s\n", valueOrDash(strings.Join(cr.Status.AllowedDestinations, ", ")))
	if len(cr.Status.Conditions) > 0 {
		cond := cr.Status.Conditions[len(cr.Status.Conditions)-1]
		fmt.Fprintf(out, "Last Condition:       %s/%s: %s\n", cond.Type, cond.Reason, cond.Message)
	}
}

func removeExternalPeer(ctx context.Context, c client.Client, name string) error {
	return externalpeer.Delete(ctx, c, name)
}

// inviteCmd creates a WireKubeExternalPeer, waits for the controller to
// allocate resources, and prints a self-contained WireGuard conf the user
// can paste into the official WireGuard client. The X25519 keypair is
// generated client-side so the private half never leaves this process.
func inviteCmd() *cobra.Command {
	var (
		ttl        time.Duration
		allowed    []string
		ingress    string
		waitFor    time.Duration
		printQR    bool
		outputFile string
		mtu        int32
	)
	cmd := &cobra.Command{
		Use:   "invite <displayName>",
		Short: "Issue a new external-peer WireGuard conf",
		Long: `Generate an X25519 keypair locally, create a WireKubeExternalPeer
custom resource, wait for the cluster controller to allocate a mesh /32
and shared relay endpoint, and print a ready-to-import WireGuard conf
to stdout. The private key is generated and printed only here; the
cluster never sees it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			displayName := args[0]
			c, err := k8sClient()
			if err != nil {
				return err
			}
			if mtu != 0 && (mtu < 576 || mtu > 1420) {
				return fmt.Errorf("--mtu must be between 576 and 1420")
			}

			kp, err := wireguard.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generate keypair: %w", err)
			}

			cr := &wirekubev1alpha1.WireKubeExternalPeer{
				TypeMeta: metav1.TypeMeta{
					APIVersion: wirekubev1alpha1.GroupVersion.String(),
					Kind:       "WireKubeExternalPeer",
				},
				ObjectMeta: metav1.ObjectMeta{Name: displayName},
				Spec: wirekubev1alpha1.WireKubeExternalPeerSpec{
					DisplayName:         displayName,
					PublicKey:           kp.PublicKeyBase64(),
					AllowedDestinations: allowed,
					IngressPeer:         ingress,
				},
			}
			if ttl > 0 {
				cr.Spec.TTL = &metav1.Duration{Duration: ttl}
			}
			if mtu > 0 {
				cr.Spec.MTU = mtu
			}

			ctx := cmd.Context()
			if err := c.Create(ctx, cr); err != nil {
				return fmt.Errorf("create WireKubeExternalPeer: %w", err)
			}

			active, err := externalpeer.WaitForActive(ctx, c, displayName, waitFor)
			if err != nil {
				return err
			}

			conf := externalpeer.RenderConfig(kp.PrivateKeyBase64(), active)
			if outputFile != "" {
				if err := os.WriteFile(outputFile, []byte(conf), 0o600); err != nil {
					return fmt.Errorf("write conf: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote conf to %s\n", outputFile)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), conf)
			}
			if printQR {
				qr, err := qrcode.New(conf, qrcode.Low)
				if err != nil {
					return fmt.Errorf("encode QR: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout())
				fmt.Fprintln(cmd.OutOrStdout(), qr.ToSmallString(false))
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "auto-delete this peer after TTL (e.g. 24h); 0 = no expiry")
	cmd.Flags().StringSliceVar(&allowed, "allow", nil, "extra CIDR(s) to add to AllowedIPs (defaults to mesh + pod CIDRs at the controller)")
	cmd.Flags().StringVar(&ingress, "ingress-peer", "", "pin to a specific WireKubePeer by name (default: controller auto-selects)")
	cmd.Flags().Int32Var(&mtu, "mtu", 0, "WireGuard interface MTU for the external client (default: controller-recommended 1248)")
	cmd.Flags().DurationVar(&waitFor, "wait", 60*time.Second, "how long to wait for Phase=Active before failing")
	cmd.Flags().BoolVar(&printQR, "qr", true, "print an ASCII QR code of the conf for mobile import")
	cmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "write the conf to this file instead of stdout (still prints QR if --qr)")
	return cmd
}

// revokeCmd deletes an external peer CR. The next agent sync drops the peer
// from the ingress WireGuard interface.
func revokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <displayName>",
		Short: "Revoke an external peer (deletes the CR)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			if err := removeExternalPeer(cmd.Context(), c, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", args[0])
			return nil
		},
	}
	return cmd
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeResult(cmd *cobra.Command, value any, text string) error {
	if options.output == "json" {
		return writeJSON(cmd.OutOrStdout(), value)
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), text)
	return err
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func marshalYAML(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return yaml.JSONToYAML(b)
}

func splitYAMLDocs(data []byte) [][]byte {
	var docs [][]byte
	var current []byte
	for _, line := range splitLines(data) {
		if string(line) == "---" {
			if len(current) > 0 {
				docs = append(docs, current)
			}
			current = nil
		} else {
			current = append(current, line...)
			current = append(current, '\n')
		}
	}
	if len(current) > 0 {
		docs = append(docs, current)
	}
	return docs
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
