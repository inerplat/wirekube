package failover

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

func healthySet(names ...string) func(string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(n string) bool { return set[n] }
}

func TestChoose(t *testing.T) {
	t0 := time.Unix(1000, 0)
	for _, tc := range []struct {
		name    string
		choice  Choice
		healthy func(string) bool
		want    string
	}{
		{"first assignment takes the top preference", Choice{Preferred: []string{"a", "b"}}, healthySet("a", "b"), "a"},
		{"a healthy holder stays", Choice{Preferred: []string{"a", "b"}, Current: "b"}, healthySet("a", "b"), "b"},
		{"an unhealthy holder moves to the best preference", Choice{Preferred: []string{"a", "b", "c"}, Current: "a"}, healthySet("b", "c"), "b"},
		{"fallback only without a healthy preference", Choice{Preferred: []string{"p"}, Fallback: []string{"x", "y"}}, healthySet("y"), "y"},
		{"fallback holders are not rebalanced", Choice{Fallback: []string{"x", "y"}, Current: "y"}, healthySet("x", "y"), "y"},
		{"nothing healthy", Choice{Preferred: []string{"a"}, Fallback: []string{"b"}, Current: "a"}, healthySet(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.choice.Healthy = tc.healthy
			var tr Tracker
			if got := tr.Choose(tc.choice, t0); got != tc.want {
				t.Fatalf("Choose = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChooseFailsBackAfterSettling(t *testing.T) {
	var tr Tracker
	t0 := time.Unix(1000, 0)
	c := Choice{Preferred: []string{"a", "b"}, Current: "b"}

	c.Healthy = healthySet("b")
	if got := tr.Choose(c, t0); got != "b" {
		t.Fatalf("Choose = %q", got)
	}
	c.Healthy = healthySet("a", "b")
	if got := tr.Choose(c, t0.Add(time.Second)); got != "b" {
		t.Fatal("failed back before a settled")
	}
	if got := tr.Choose(c, t0.Add(time.Second+FailbackDelay)); got != "a" {
		t.Fatalf("Choose = %q, want a failback to a", got)
	}

	// A blip resets the clock.
	c.Current = "b"
	c.Healthy = healthySet("b")
	tr.Choose(c, t0.Add(10*time.Minute))
	c.Healthy = healthySet("a", "b")
	if got := tr.Choose(c, t0.Add(10*time.Minute+FailbackDelay/2)); got != "b" {
		t.Fatal("a flap did not restart the settling clock")
	}
}

func TestLive(t *testing.T) {
	now := time.Unix(10000, 0)
	at := func(d time.Duration) *metav1.Time { v := metav1.NewTime(now.Add(-d)); return &v }
	peer := func(name string, reported *metav1.Time) wirekubev1alpha1.WireKubePeer {
		p := wirekubev1alpha1.WireKubePeer{}
		p.Name = name
		p.Status.LastReportedAt = reported
		return p
	}

	live := Live([]wirekubev1alpha1.WireKubePeer{peer("fresh", at(time.Second)), peer("stale", at(time.Hour)), peer("silent", nil)}, now, LivenessThreshold, "stale")
	if !live("fresh") || live("stale") || live("silent") {
		t.Fatal("liveness misjudged with some peers reporting")
	}
	quiet := []wirekubev1alpha1.WireKubePeer{peer("a", at(time.Hour)), peer("b", nil)}
	if held := Live(quiet, now, LivenessThreshold, "b"); !held("b") || held("a") {
		t.Fatal("with nobody reporting, only the current holder may count as alive")
	}
	if fresh := Live(quiet, now, LivenessThreshold, ""); !fresh("a") || !fresh("b") {
		t.Fatal("with nobody reporting and no holder, everyone must count as alive")
	}
}

// TestNoFailbackOntoADeadNodeWhenEveryoneGoesQuiet covers a role that moved
// off a dead node: when the node it moved to stops reporting too, the dead
// node must not look alive again and draw the role back.
func TestNoFailbackOntoADeadNodeWhenEveryoneGoesQuiet(t *testing.T) {
	now := time.Unix(10000, 0)
	at := func(d time.Duration) *metav1.Time { v := metav1.NewTime(now.Add(-d)); return &v }
	peers := []wirekubev1alpha1.WireKubePeer{{}, {}}
	peers[0].Name, peers[0].Status.LastReportedAt = "a", at(time.Hour)
	peers[1].Name, peers[1].Status.LastReportedAt = "b", at(10*time.Minute)

	var tr Tracker
	c := Choice{Preferred: []string{"a", "b"}, Current: "b", Healthy: Live(peers, now, LivenessThreshold, "b")}
	for i := 0; i < 10; i++ {
		if got := tr.Choose(c, now.Add(time.Duration(i)*time.Minute)); got != "b" {
			t.Fatalf("minute %d: role moved to %q while nobody reports", i, got)
		}
	}
}
