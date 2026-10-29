package sitegw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// Snapshot is a site gateway's report of its tunnels. A reader keeps the
// newest (BootID, Seq) it saw: Seq grows within one BootID, and a new
// BootID means the process restarted.
type Snapshot struct {
	PodUID        string `json:"podUID,omitempty"`
	ConnectionUID string `json:"connectionUID,omitempty"`
	BootID        string `json:"bootID"`
	// Seq grows when a field worth a status write changes; IKEState and
	// InstalledChildSAs alone do not move it.
	Seq uint64 `json:"seq"`
	// AppliedConfigHash is the hash of the config the tunnels below were
	// built from; empty until one was read.
	AppliedConfigHash string `json:"appliedConfigHash,omitempty"`
	// ConfigError is why the current config file could not be applied. The
	// tunnels of the last good config stay as they were.
	ConfigError     string                                      `json:"configError,omitempty"`
	CharonReachable bool                                        `json:"charonReachable"`
	Tunnels         []wirekubev1alpha1.GatewayIPsecTunnelStatus `json:"tunnels"`
	// ObservedAt is when the gateway built this snapshot, for display only:
	// a reader judges freshness by when it received the snapshot.
	ObservedAt time.Time `json:"observedAt"`
}

// changed reports whether b differs from a in a field worth a status write.
func changed(a, b *Snapshot) bool {
	return a.AppliedConfigHash != b.AppliedConfigHash || a.ConfigError != b.ConfigError ||
		a.CharonReachable != b.CharonReachable || !StatusesEqual(a.Tunnels, b.Tunnels)
}

// Publisher holds the latest snapshot and wakes long-polling readers when it
// changes.
type Publisher struct {
	// Stale, when set, makes /v1/status answer 503 with the snapshot while
	// it reports true: a stalled sync loop must not look like a live one.
	Stale func() bool

	mu      sync.Mutex
	current Snapshot
	wake    chan struct{}
}

// NewPublisher starts at Seq 0 under a random BootID.
func NewPublisher(podUID, connectionUID string) *Publisher {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &Publisher{
		current: Snapshot{PodUID: podUID, ConnectionUID: connectionUID, BootID: hex.EncodeToString(b[:]), Tunnels: []wirekubev1alpha1.GatewayIPsecTunnelStatus{}},
		wake:    make(chan struct{}),
	}
}

// Publish replaces the snapshot. Seq, BootID and the identities are the
// publisher's; LastTransitionTime is carried over while a phase holds.
func (p *Publisher) Publish(next Snapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	next.PodUID, next.BootID, next.Seq = p.current.PodUID, p.current.BootID, p.current.Seq
	if next.ConnectionUID == "" {
		next.ConnectionUID = p.current.ConnectionUID
	}
	if next.Tunnels == nil {
		next.Tunnels = []wirekubev1alpha1.GatewayIPsecTunnelStatus{}
	}
	KeepTransitionTimes(p.current.Tunnels, next.Tunnels, next.ObservedAt)
	if changed(&p.current, &next) || next.ConnectionUID != p.current.ConnectionUID {
		next.Seq++
		close(p.wake)
		p.wake = make(chan struct{})
	}
	p.current = next
}

// Current returns the latest snapshot.
func (p *Publisher) Current() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

// wait returns the snapshot once its Seq passes since under the same BootID,
// or when the BootID differs, or when ctx ends.
func (p *Publisher) wait(ctx context.Context, bootID string, since uint64) Snapshot {
	for {
		p.mu.Lock()
		cur, wake := p.current, p.wake
		p.mu.Unlock()
		if cur.BootID != bootID || cur.Seq > since {
			return cur
		}
		select {
		case <-ctx.Done():
			return p.Current()
		case <-wake:
		}
	}
}

// MaxWait bounds a long poll.
const MaxWait = 60 * time.Second

// ServeStatus answers GET /v1/status. With since=<seq> and wait=<duration>
// it holds the request until a snapshot newer than since exists, or wait
// passes; bootID=<id> makes a restarted gateway answer at once.
func (p *Publisher) ServeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	snap := p.Current()
	if s := q.Get("since"); s != "" {
		since, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, "since: not a number", http.StatusBadRequest)
			return
		}
		wait := 25 * time.Second
		if v := q.Get("wait"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 {
				http.Error(w, "wait: not a duration", http.StatusBadRequest)
				return
			}
			wait = min(d, MaxWait)
		}
		bootID := q.Get("bootID")
		if bootID == "" {
			bootID = snap.BootID
		}
		ctx, cancel := context.WithTimeout(r.Context(), wait)
		defer cancel()
		snap = p.wait(ctx, bootID, since)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if p.Stale != nil && p.Stale() {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(snap)
}
