// Package failover decides which node holds a one-holder role, such as fronting
// an external peer or serving a gateway: it stays on a healthy holder, moves to
// the most preferred healthy node, and fails back only after FailbackDelay.
package failover

import (
	"sync"
	"time"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

const (
	// LivenessThreshold is how stale a node's self-report may get before
	// it stops counting as alive for a role it can move away from. Agents
	// report every 30s, so this is three missed reports.
	LivenessThreshold = 90 * time.Second

	// FailbackDelay is how long a more preferred node must stay healthy
	// before a role returns to it.
	FailbackDelay = 2 * time.Minute
)

// Live returns which peers reported within threshold. If none did, only the
// current holder counts, since mass silence points at status writes failing and
// the role must not fail back onto a dead node; with no holder, everyone counts.
func Live(peers []wirekubev1alpha1.WireKubePeer, now time.Time, threshold time.Duration, current string) func(name string) bool {
	live := map[string]bool{}
	for i := range peers {
		p := &peers[i]
		if p.Status.LastReportedAt != nil && now.Sub(p.Status.LastReportedAt.Time) < threshold {
			live[p.Name] = true
		}
	}
	switch {
	case len(live) > 0:
		return func(name string) bool { return live[name] }
	case current != "":
		return func(name string) bool { return name == current }
	default:
		return func(string) bool { return true }
	}
}

// Choice describes one role's candidates.
type Choice struct {
	// Preferred lists nodes in order of preference. The role returns to a
	// node earlier in this list once it has been healthy for FailbackDelay.
	Preferred []string
	// Fallback lists further nodes, best first, used only while no
	// preferred node is healthy. The role never moves between them just
	// because a better one appears.
	Fallback []string
	// Current is the node holding the role now; empty if none.
	Current string
	// Healthy reports whether a node can hold the role right now.
	Healthy func(name string) bool
}

// Tracker remembers since when each node has been continuously healthy, on
// the caller's clock. It lives in memory: a restart restarts every node's
// clock, which can only delay a failback.
type Tracker struct {
	mu    sync.Mutex
	since map[string]time.Time
}

// Choose returns the node that should hold the role, or "" when no node is
// healthy. It also records the health it was given, so call it on every
// evaluation, not just when something changed.
func (t *Tracker) Choose(c Choice, now time.Time) string {
	t.observe(c, now)

	rank := func(name string) int {
		for i, n := range c.Preferred {
			if n == name {
				return i
			}
		}
		return len(c.Preferred)
	}
	best := ""
	for _, n := range c.Preferred {
		if c.Healthy(n) {
			best = n
			break
		}
	}

	if c.Current != "" && c.Healthy(c.Current) {
		if best != "" && best != c.Current && rank(best) < rank(c.Current) && t.healthyFor(best, now) >= FailbackDelay {
			return best
		}
		return c.Current
	}
	if best != "" {
		return best
	}
	for _, n := range c.Fallback {
		if c.Healthy(n) {
			return n
		}
	}
	return ""
}

func (t *Tracker) observe(c Choice, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.since == nil {
		t.since = map[string]time.Time{}
	}
	seen := map[string]bool{}
	for _, list := range [][]string{c.Preferred, c.Fallback, {c.Current}} {
		for _, n := range list {
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			if !c.Healthy(n) {
				delete(t.since, n)
			} else if _, ok := t.since[n]; !ok {
				t.since[n] = now
			}
		}
	}
}

func (t *Tracker) healthyFor(name string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	since, ok := t.since[name]
	if !ok {
		return 0
	}
	return now.Sub(since)
}
