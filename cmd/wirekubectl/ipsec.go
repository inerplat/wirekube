package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	internalinstall "github.com/inerplat/wirekube/internal/install"
	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

// charonPodLabel selects the charon pods of both the chart and wirekubectl
// installations.
const charonPodLabel = "app.kubernetes.io/name"

func ipsecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ipsec",
		Short: "Inspect gateway IPsec tunnels and configure their remote side",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIPsecStatus(cmd, "")
		},
	}
	cmd.AddCommand(ipsecStatusCmd(), ipsecRemoteConfigCmd())
	return cmd
}

func ipsecStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [gateway]",
		Short: "Show the IPsec tunnels of every gateway, or of one",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			return runIPsecStatus(cmd, name)
		},
	}
}

func ipsecRemoteConfigCmd() *cobra.Command {
	var tunnel string
	cmd := &cobra.Command{
		Use:   "remote-config <gateway>",
		Short: "Print the settings the remote IPsec gateway needs for each tunnel",
		Long: `Print, for each tunnel of the gateway and each of its peerRefs, the values
to enter on the remote IPsec gateway. Every gateway node presents its own
public address, so the remote side needs one tunnel per node for failover.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := k8sClient()
			if err != nil {
				return err
			}
			configs, err := remoteConfigs(cmd.Context(), c, args[0], tunnel)
			if err != nil {
				return err
			}
			if options.output == "json" {
				return writeJSON(cmd.OutOrStdout(), configs)
			}
			writeRemoteConfigs(cmd.OutOrStdout(), configs)
			return nil
		},
	}
	cmd.Flags().StringVar(&tunnel, "tunnel", "", "only this tunnel")
	return cmd
}

type ipsecTunnelRow struct {
	Gateway string                                    `json:"gateway"`
	Node    string                                    `json:"node"`
	Remote  string                                    `json:"remoteAddress"`
	Status  wirekubev1alpha1.GatewayIPsecTunnelStatus `json:"status"`
}

type ipsecStatusOutput struct {
	Tunnels  []ipsecTunnelRow `json:"tunnels"`
	Warnings []string         `json:"warnings,omitempty"`
}

func runIPsecStatus(cmd *cobra.Command, name string) error {
	c, err := k8sClient()
	if err != nil {
		return err
	}
	out, err := collectIPsecStatus(cmd.Context(), c, name)
	if err != nil {
		return err
	}
	if options.output == "json" {
		return writeJSON(cmd.OutOrStdout(), out)
	}
	if len(out.Tunnels) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No gateway defines IPsec tunnels.")
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "GATEWAY\tTUNNEL\tREMOTE\tNODE\tPHASE\tCARRIER\tDATAPLANE\tCHILD-SAS\tSINCE\tMESSAGE")
	for _, r := range out.Tunnels {
		since := "-"
		if t := r.Status.LastTransitionTime; t != nil {
			since = formatDuration(time.Since(t.Time))
		}
		phase := string(r.Status.Phase)
		if phase == "" {
			phase = "Unknown"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.Gateway, r.Status.Name, r.Remote, dash(r.Node), phase, yesNo(r.Status.Carrier),
			dash(string(r.Status.Dataplane)), r.Status.InstalledChildSAs, since, dash(r.Status.Message))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, warning := range out.Warnings {
		fmt.Fprintf(cmd.OutOrStdout(), "Warning: %s\n", warning)
	}
	return nil
}

func collectIPsecStatus(ctx context.Context, c client.Client, name string) (ipsecStatusOutput, error) {
	var gateways []wirekubev1alpha1.WireKubeGateway
	if name != "" {
		gw := &wirekubev1alpha1.WireKubeGateway{}
		if err := c.Get(ctx, client.ObjectKey{Name: name}, gw); err != nil {
			return ipsecStatusOutput{}, fmt.Errorf("get gateway %s: %w", name, err)
		}
		gateways = append(gateways, *gw)
	} else {
		list := &wirekubev1alpha1.WireKubeGatewayList{}
		if err := c.List(ctx, list); err != nil {
			return ipsecStatusOutput{}, fmt.Errorf("list gateways: %w", err)
		}
		gateways = list.Items
		sort.Slice(gateways, func(i, j int) bool { return gateways[i].Name < gateways[j].Name })
	}

	charonNodes, charonErr := readyCharonNodes(ctx, c)
	out := ipsecStatusOutput{Tunnels: []ipsecTunnelRow{}}
	for _, gw := range gateways {
		if len(gw.Spec.IPsec) == 0 {
			continue
		}
		reported := map[string]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
		for _, st := range gw.Status.IPsec {
			reported[st.Name] = st
		}
		for _, t := range gw.Spec.IPsec {
			st, ok := reported[t.Name]
			if !ok {
				st = wirekubev1alpha1.GatewayIPsecTunnelStatus{Name: t.Name, Message: "no status reported yet"}
			}
			out.Tunnels = append(out.Tunnels, ipsecTunnelRow{Gateway: gw.Name, Node: gw.Status.ActivePeer, Remote: t.RemoteAddress, Status: st})
		}
		if node := gw.Status.ActivePeer; node != "" && charonErr == nil && !charonNodes[node] {
			out.Warnings = append(out.Warnings, fmt.Sprintf("gateway %s is active on %s, which runs no ready charon pod; enable IPsec (chart agent.ipsec.enabled=true, wirekubectl upgrade --ipsec) and include the node in the charon node selector", gw.Name, node))
		}
	}
	if charonErr != nil && len(out.Tunnels) > 0 {
		out.Warnings = append(out.Warnings, "could not list charon pods in namespace "+options.namespace+": "+charonErr.Error())
	}
	return out, nil
}

func readyCharonNodes(ctx context.Context, c client.Client) (map[string]bool, error) {
	pods := &corev1.PodList{}
	if err := c.List(ctx, pods, client.InNamespace(options.namespace), client.MatchingLabels{charonPodLabel: "wirekube-charon"}); err != nil {
		return nil, err
	}
	nodes := map[string]bool{}
	for _, p := range pods.Items {
		for _, cond := range p.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				nodes[p.Spec.NodeName] = true
			}
		}
	}
	return nodes, nil
}

// remoteConfig is what the remote gateway needs for one tunnel toward one
// gateway node. "Local" and "remote" are from the remote gateway's side.
type remoteConfig struct {
	Gateway        string   `json:"gateway"`
	Tunnel         string   `json:"tunnel"`
	Node           string   `json:"node"`
	Active         bool     `json:"active"`
	PeerAddress    string   `json:"peerAddress"`
	PeerID         string   `json:"peerID"`
	LocalID        string   `json:"localID"`
	LocalNetworks  []string `json:"localNetworks"`
	RemoteNetworks []string `json:"remoteNetworks"`
	PreSharedKey   string   `json:"preSharedKey"`
	IKEVersion     int      `json:"ikeVersion"`
	IKEProposals   []string `json:"ikeProposals"`
	IKELifetime    int      `json:"ikeLifetimeSeconds"`
	ESPProposals   []string `json:"espProposals"`
	ESPLifetime    int      `json:"espLifetimeSeconds"`
	DPDDelay       int      `json:"dpdDelaySeconds"`
	NATTraversal   string   `json:"natTraversal"`
	Problems       []string `json:"problems,omitempty"`
}

func remoteConfigs(ctx context.Context, c client.Client, name, only string) ([]remoteConfig, error) {
	gw := &wirekubev1alpha1.WireKubeGateway{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, gw); err != nil {
		return nil, fmt.Errorf("get gateway %s: %w", name, err)
	}
	if len(gw.Spec.IPsec) == 0 {
		return nil, fmt.Errorf("gateway %s defines no IPsec tunnels (spec.ipsec)", name)
	}
	meshes := &wirekubev1alpha1.WireKubeMeshList{}
	if err := c.List(ctx, meshes); err != nil {
		return nil, fmt.Errorf("list meshes: %w", err)
	}
	meshCIDR := ""
	if len(meshes.Items) > 0 {
		meshCIDR = meshes.Items[0].Spec.MeshCIDR
	}

	var out []remoteConfig
	found := false
	for i := range gw.Spec.IPsec {
		spec := &gw.Spec.IPsec[i]
		if only != "" && spec.Name != only {
			continue
		}
		found = true
		for _, node := range gw.Spec.PeerRefs {
			var problems []string
			address := ""
			peer := &wirekubev1alpha1.WireKubePeer{}
			switch err := c.Get(ctx, client.ObjectKey{Name: node}, peer); {
			case apierrors.IsNotFound(err):
				problems = append(problems, "node "+node+" has no WireKubePeer; it cannot be elected")
			case err != nil:
				return nil, fmt.Errorf("get peer %s: %w", node, err)
			default:
				address = ipsec.EndpointHost(peer.Spec.Endpoint)
				if address == "" {
					problems = append(problems, "the WireKubePeer endpoint of "+node+" holds no IP address; enter the node's public address by hand")
				}
			}
			t := ipsec.FromSpec(gw, spec, meshCIDR, address)
			peerID := t.LocalID
			localID := t.RemoteID
			if localID == "" {
				localID = t.RemoteAddress
			}
			nat := "the remote sees the node's address as sent; if the node is behind NAT, enable NAT traversal on the remote"
			if t.ForceEncap {
				nat = "required: forceEncapsulation sends ESP in UDP 4500"
			}
			out = append(out, remoteConfig{
				Gateway: gw.Name, Tunnel: spec.Name, Node: node, Active: gw.Status.ActivePeer == node,
				PeerAddress: dash(address), PeerID: dash(peerID), LocalID: localID,
				LocalNetworks: t.RemoteTS, RemoteNetworks: t.LocalTS,
				PreSharedKey: fmt.Sprintf("kubectl -n %s get secret %s -o jsonpath='{.data.%s}' | base64 -d",
					options.namespace, spec.PreSharedKeyRef.Name, strings.ReplaceAll(pskKey(spec.PreSharedKeyRef), ".", "\\.")),
				IKEVersion: t.IKEVersion, IKEProposals: t.IKEProposals, IKELifetime: t.IKELifetime,
				ESPProposals: t.ESPProposals, ESPLifetime: t.ESPLifetime, DPDDelay: t.DPDDelay,
				NATTraversal: nat, Problems: problems,
			})
		}
	}
	if !found {
		return nil, fmt.Errorf("gateway %s has no tunnel %q", name, only)
	}
	return out, nil
}

func pskKey(ref wirekubev1alpha1.IPsecSecretKeyRef) string {
	if ref.Key != "" {
		return ref.Key
	}
	return ipsec.DefaultPreSharedKeyID
}

func writeRemoteConfigs(w io.Writer, configs []remoteConfig) {
	for i, rc := range configs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		role := "standby"
		if rc.Active {
			role = "active"
		}
		fmt.Fprintf(w, "# Tunnel %s/%s toward node %s (%s)\n", rc.Gateway, rc.Tunnel, rc.Node, role)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		row := func(k, v string) { fmt.Fprintf(tw, "%s\t%s\n", k, v) }
		row("Peer address", rc.PeerAddress)
		row("Peer IKE ID", rc.PeerID)
		row("Local IKE ID", rc.LocalID)
		row("Local networks", strings.Join(rc.LocalNetworks, ", "))
		row("Remote networks", strings.Join(rc.RemoteNetworks, ", "))
		row("Pre-shared key (read with)", rc.PreSharedKey)
		row("IKE version", fmt.Sprintf("IKEv%d", rc.IKEVersion))
		for _, p := range rc.IKEProposals {
			d := ipsec.DescribeProposal(p)
			row("IKE (phase 1) proposal", describe(d, false))
		}
		row("IKE lifetime", fmt.Sprintf("%d s", rc.IKELifetime))
		for _, p := range rc.ESPProposals {
			d := ipsec.DescribeProposal(p)
			row("ESP (phase 2) proposal", describe(d, true))
		}
		row("ESP lifetime", fmt.Sprintf("%d s", rc.ESPLifetime))
		row("DPD interval", fmt.Sprintf("%d s", rc.DPDDelay))
		row("NAT traversal", rc.NATTraversal)
		row("Route on the remote side", strings.Join(rc.RemoteNetworks, ", ")+" through this tunnel")
		_ = tw.Flush()
		for _, p := range rc.Problems {
			fmt.Fprintf(w, "Problem: %s\n", p)
		}
	}
}

func describe(d ipsec.ProposalParts, esp bool) string {
	parts := []string{"encryption " + d.Encryption}
	if d.Integrity != "" {
		parts = append(parts, "integrity "+d.Integrity)
	}
	switch {
	case d.DHGroup != "" && esp:
		parts = append(parts, "PFS "+d.DHGroup)
	case d.DHGroup != "":
		parts = append(parts, "DH "+d.DHGroup)
	case esp:
		parts = append(parts, "PFS off")
	}
	return strings.Join(parts, ", ")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// inspectCharon reports the charon DaemonSet. It may cover fewer nodes than
// the agent (--charon-node-selector), but at least one.
func inspectCharon(ctx context.Context, c client.Client, inventory *internalinstall.Inventory) componentStatus {
	ds := &appsv1.DaemonSet{}
	err := c.Get(ctx, types.NamespacedName{Namespace: inventory.Options.Namespace, Name: internalinstall.CharonDaemonSetName}, ds)
	status := componentStatus{Name: "charon", Kind: "DaemonSet", Message: messageForError(err, "")}
	if err != nil {
		return status
	}
	desired := ds.Status.DesiredNumberScheduled
	status.Desired = desired
	status.Available = ds.Status.NumberReady
	status.Ready = desired > 0 && ds.Status.ObservedGeneration >= ds.Generation && ds.Status.UpdatedNumberScheduled == desired && ds.Status.NumberReady == desired
	status.Message = fmt.Sprintf("%d/%d ready, %d updated", ds.Status.NumberReady, desired, ds.Status.UpdatedNumberScheduled)
	if desired == 0 {
		status.Message = "no node matches the charon node selector; label the gateway nodes or change --charon-node-selector"
	}
	return status
}

// checkIPsecTunnels is the doctor check; it is relevant only when some
// gateway defines tunnels.
func checkIPsecTunnels(ctx context.Context, c client.Client) (bool, string, bool) {
	out, err := collectIPsecStatus(ctx, c, "")
	if err != nil {
		return false, err.Error(), true
	}
	if len(out.Tunnels) == 0 {
		return true, "", false
	}
	var problems []string
	established := 0
	for _, r := range out.Tunnels {
		if r.Status.Phase == wirekubev1alpha1.IPsecTunnelPhaseEstablished {
			established++
			continue
		}
		problems = append(problems, fmt.Sprintf("%s/%s %s: %s", r.Gateway, r.Status.Name, dash(string(r.Status.Phase)), dash(r.Status.Message)))
	}
	problems = append(problems, out.Warnings...)
	message := fmt.Sprintf("%d/%d tunnels established", established, len(out.Tunnels))
	if len(problems) > 0 {
		message += "; " + strings.Join(problems, "; ") + "; see wirekubectl ipsec status"
	}
	return len(problems) == 0, message, true
}
