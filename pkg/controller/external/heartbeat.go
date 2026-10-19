package external

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// heartbeatTracker records when this controller first saw each peer's heartbeat
// value, timing on its own clock so client skew cannot expire a peer early. It is
// in memory: a restart can only delay an expiry.
type heartbeatTracker struct {
	mu   sync.Mutex
	seen map[types.UID]heartbeatSeen
}

type heartbeatSeen struct {
	value string
	at    time.Time
}

// observe records value for uid and returns when it was first seen.
func (t *heartbeatTracker) observe(uid types.UID, value string, now time.Time) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == nil {
		t.seen = map[types.UID]heartbeatSeen{}
	}
	if prev, ok := t.seen[uid]; ok && prev.value == value {
		return prev.at
	}
	t.seen[uid] = heartbeatSeen{value: value, at: now}
	return now
}

func (t *heartbeatTracker) forget(uid types.UID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, uid)
}

// heartbeatDeadline reports how long until a heartbeating peer expires, or
// that it already has. A peer without the annotation returns zero and never
// expires.
func (r *Reconciler) heartbeatDeadline(cr *wirekubev1alpha1.WireKubeExternalPeer) (time.Duration, bool) {
	value, ok := cr.Annotations[wirekubev1alpha1.ExternalPeerHeartbeatAnnotation]
	if !ok {
		r.heartbeats.forget(cr.UID)
		return 0, false
	}
	now := r.now()
	left := r.heartbeats.observe(cr.UID, value, now).Add(wirekubev1alpha1.ExternalPeerHeartbeatTimeout).Sub(now)
	if left <= 0 {
		r.heartbeats.forget(cr.UID)
		return 0, true
	}
	return left, false
}
