// wirekubectl is the WireKube CLI tool.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	wirekubev1alpha1 "github.com/wirekube/wirekube/pkg/api/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(wirekubev1alpha1.AddToScheme(scheme))
	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stderr)))
}

func main() {
	root := &cobra.Command{
		Use:   "wirekubectl",
		Short: "WireKube CLI — manage your Kubernetes WireGuard mesh",
	}

	root.AddCommand(
		meshCmd(),
		peersCmd(),
		exportCmd(),
		importCmd(),
		tokenCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func k8sClient() (client.Client, error) {
	return client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
}

// mesh
func meshCmd() *cobra.Command {
	var listenPort int32

	cmd := &cobra.Command{
		Use:   "mesh",
		Short: "Manage WireKubeMesh configuration",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create or update the WireKubeMesh resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			mesh := &wirekubev1alpha1.WireKubeMesh{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: wirekubev1alpha1.WireKubeMeshSpec{
					ListenPort: listenPort,
					STUNServers: []string{
						"stun:stun.l.google.com:19302",
						"stun:stun1.l.google.com:19302",
					},
				},
			}
			ctx := context.Background()
			existing := &wirekubev1alpha1.WireKubeMesh{}
			err = c.Get(ctx, client.ObjectKey{Name: "default"}, existing)
			if err != nil {
				if err := c.Create(ctx, mesh); err != nil {
					return err
				}
				fmt.Println("WireKubeMesh 'default' created")
			} else {
				patch := client.MergeFrom(existing.DeepCopy())
				existing.Spec = mesh.Spec
				if err := c.Patch(ctx, existing, patch); err != nil {
					return err
				}
				fmt.Println("WireKubeMesh 'default' updated")
			}
			return nil
		},
	}
	initCmd.Flags().Int32Var(&listenPort, "port", 51820, "WireGuard listen port")
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
			if err := c.Get(context.Background(), client.ObjectKey{Name: "default"}, mesh); err != nil {
				return err
			}
			fmt.Printf("Name:        %s\n", mesh.Name)
			fmt.Printf("Listen Port: %d\n", mesh.Spec.ListenPort)
			fmt.Printf("Interface:   %s\n", mesh.Spec.InterfaceName)
			fmt.Printf("MTU:         %d\n", mesh.Spec.MTU)
			fmt.Printf("Ready Peers: %d / %d\n", mesh.Status.ReadyPeers, mesh.Status.TotalPeers)
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
			if err := c.List(context.Background(), peerList); err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
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
			if err := c.List(context.Background(), peerList); err != nil {
				return err
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
					fmt.Println("---")
				}
				fmt.Print(string(b))
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
				err := c.Get(context.Background(), client.ObjectKey{Name: peer.Name}, existing)
				if err != nil {
					if err := c.Create(context.Background(), peer); err != nil {
						return fmt.Errorf("creating peer %s: %w", peer.Name, err)
					}
					fmt.Printf("created peer %s\n", peer.Name)
				} else {
					patch := client.MergeFrom(existing.DeepCopy())
					existing.Spec = peer.Spec
					if err := c.Patch(context.Background(), existing, patch); err != nil {
						return fmt.Errorf("updating peer %s: %w", peer.Name, err)
					}
					fmt.Printf("updated peer %s\n", peer.Name)
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
			fmt.Println("# Bootstrap token creation not yet implemented.")
			fmt.Println("# Use kubeadm token create or manually create a ServiceAccount for the agent.")
			return nil
		},
	}
	cmd.AddCommand(createCmd)
	return cmd
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
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
