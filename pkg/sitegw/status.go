package sitegw

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// Summary is the kubectl get column, e.g. "1/2 Established".
func Summary(tunnels []wirekubev1alpha1.GatewayIPsecTunnelStatus) string {
	if len(tunnels) == 0 {
		return ""
	}
	established := 0
	same := true
	for _, t := range tunnels {
		if t.Phase == wirekubev1alpha1.IPsecTunnelPhaseEstablished {
			established++
		}
		same = same && t.Phase == tunnels[0].Phase
	}
	if established == 0 && same {
		return string(tunnels[0].Phase)
	}
	return fmt.Sprintf("%d/%d Established", established, len(tunnels))
}

// KeepTransitionTimes copies each tunnel's LastTransitionTime from prev while
// its phase is unchanged, and stamps now otherwise.
func KeepTransitionTimes(prev, next []wirekubev1alpha1.GatewayIPsecTunnelStatus, now time.Time) {
	byName := map[string]wirekubev1alpha1.GatewayIPsecTunnelStatus{}
	for _, st := range prev {
		byName[st.Name] = st
	}
	stamp := metav1.NewTime(now)
	for i := range next {
		old, ok := byName[next[i].Name]
		if ok && old.Phase == next[i].Phase && old.LastTransitionTime != nil {
			next[i].LastTransitionTime = old.LastTransitionTime
		} else {
			t := stamp
			next[i].LastTransitionTime = &t
		}
	}
}

// StatusesEqual compares the fields worth a status write. IKEState and
// InstalledChildSAs are left out: they move with every rekey and retry
// without changing what the tunnel can do, and comparing them would turn
// each attempt against an unanswering peer into a write.
func StatusesEqual(a, b []wirekubev1alpha1.GatewayIPsecTunnelStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Name != y.Name || x.Phase != y.Phase || x.Reason != y.Reason || x.Message != y.Message || x.Carrier != y.Carrier ||
			x.Dataplane != y.Dataplane || x.InterfaceName != y.InterfaceName || x.InterfaceID != y.InterfaceID ||
			x.LocalID != y.LocalID ||
			!equalStrings(x.LocalTrafficSelectors, y.LocalTrafficSelectors) ||
			!equalStrings(x.RemoteTrafficSelectors, y.RemoteTrafficSelectors) {
			return false
		}
		if (x.LastTransitionTime == nil) != (y.LastTransitionTime == nil) ||
			(x.LastTransitionTime != nil && !x.LastTransitionTime.Equal(y.LastTransitionTime)) {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
