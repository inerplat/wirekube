package sitegw

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
	"github.com/inerplat/wirekube/pkg/ipsec"
)

// Runner syncs a standalone site gateway from its config file and publishes
// the result.
type Runner struct {
	Engine     *Engine
	Publisher  *Publisher
	ConfigPath string
	KeyDir     string
	Interval   time.Duration
	Log        logr.Logger
	// OwnAddresses are the gateway's own uplink addresses; nil skips the
	// check that no local selector covers them.
	OwnAddresses func() ([]netip.Addr, error)
	Metrics      *Metrics
	Now          func() time.Time

	mu       sync.Mutex
	lastSync time.Time
	health   error
	cfg      *Config
	hash     string
}

// Run syncs every Interval until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for ctx.Err() == nil {
		r.Sync()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sync applies the config once. An unreadable config keeps the tunnels of
// the last good one, since tearing them down on a bad edit would cut a
// working site off.
func (r *Runner) Sync() {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	cfg, hash, err := LoadConfig(r.ConfigPath)
	configErr := ""
	if err != nil {
		configErr = err.Error()
		r.Log.Error(err, "reading site gateway config; keeping the last good one")
		cfg, hash = r.cfg, r.hash
	} else {
		r.cfg, r.hash = cfg, hash
	}
	snap := Snapshot{ConfigError: configErr, ObservedAt: now()}
	var health error
	if cfg == nil {
		health = fmt.Errorf("no usable config yet: %s", configErr)
	} else {
		plans := cfg.Plans(r.KeyDir)
		if r.OwnAddresses != nil {
			own, err := r.OwnAddresses()
			if err != nil {
				health = fmt.Errorf("reading the uplink addresses: %w", err)
			}
			RefuseOwnAddresses(plans, own)
		}
		if ip := net.ParseIP(cfg.RouteSource); ip != nil {
			r.Engine.RouteSource = func() net.IP { return ip }
		} else {
			r.Engine.RouteSource = nil
		}
		res := r.Engine.Sync(plans)
		snap.Tunnels = res.Statuses
		snap.AppliedConfigHash = hash
		snap.ConnectionUID = cfg.ConnectionUID
		// Probed on its own: with no tunnels the engine does not
		// treat an unreachable charon as an error.
		charonErr := res.CharonErr
		if charonErr == nil {
			_, charonErr = r.Engine.Charon.ListConns()
		}
		snap.CharonReachable = charonErr == nil
		if charonErr != nil {
			health = fmt.Errorf("IKE daemon: %w", charonErr)
		}
	}
	// Recorded before publishing: a reader woken by Publish checks Stale.
	r.mu.Lock()
	r.lastSync, r.health = now(), health
	r.mu.Unlock()
	r.Publisher.Publish(snap)
	if r.Metrics != nil {
		r.Metrics.record(snap.Tunnels)
	}
}

// Stale reports whether the sync loop has not completed within two
// intervals, so the published snapshot may no longer hold.
func (r *Runner) Stale() bool {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	r.mu.Lock()
	last := r.lastSync
	r.mu.Unlock()
	return last.IsZero() || now().Sub(last) > 2*r.Interval+5*time.Second
}

// ServeHealth answers the readiness probe: the sync loop ran within two
// intervals and charon answered. Tunnel states do not count: a gateway whose
// peer is down is still a working gateway.
func (r *Runner) ServeHealth(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	health := r.health
	r.mu.Unlock()
	switch {
	case r.Stale():
		http.Error(w, "sync loop stalled or not run yet", http.StatusServiceUnavailable)
	case health != nil:
		http.Error(w, health.Error(), http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

// Metrics are a site gateway's Prometheus series. They carry the live
// values the snapshot leaves out of Seq.
type Metrics struct {
	established, childSAs, carrier *prometheus.GaugeVec
	guardDropped                   *prometheus.GaugeVec
	seen                           map[string]bool
	guarded                        map[ipsec.SelectorPair]bool
}

// NewMetrics registers the series on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		established: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "wirekube", Subsystem: "sitegw", Name: "tunnel_established",
			Help: "1 when the tunnel has an installed CHILD_SA, else 0."}, []string{"tunnel"}),
		childSAs: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "wirekube", Subsystem: "sitegw", Name: "tunnel_child_sas",
			Help: "Installed CHILD_SAs of the tunnel."}, []string{"tunnel"}),
		carrier: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "wirekube", Subsystem: "sitegw", Name: "tunnel_carrier",
			Help: "1 when the remote networks are routed into this tunnel."}, []string{"tunnel"}),
		guardDropped: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "wirekube", Subsystem: "sitegw", Name: "guard_dropped_packets",
			Help: "Packets the plaintext guard dropped because no IPsec SA covered them."}, []string{"local", "remote"}),
		seen:    map[string]bool{},
		guarded: map[ipsec.SelectorPair]bool{},
	}
	reg.MustRegister(m.established, m.childSAs, m.carrier, m.guardDropped)
	return m
}

func (m *Metrics) record(tunnels []wirekubev1alpha1.GatewayIPsecTunnelStatus) {
	now := map[string]bool{}
	for _, t := range tunnels {
		e, c := 0.0, 0.0
		if t.InstalledChildSAs > 0 {
			e = 1
		}
		if t.Carrier {
			c = 1
		}
		m.established.WithLabelValues(t.Name).Set(e)
		m.childSAs.WithLabelValues(t.Name).Set(float64(t.InstalledChildSAs))
		m.carrier.WithLabelValues(t.Name).Set(c)
		now[t.Name] = true
	}
	for name := range m.seen {
		if !now[name] {
			m.established.DeleteLabelValues(name)
			m.childSAs.DeleteLabelValues(name)
			m.carrier.DeleteLabelValues(name)
		}
	}
	m.seen = now
}

// RecordGuard is an Engine.OnGuard hook. Series are replaced in place, so a
// scrape never finds them missing; a failed read keeps the last values.
func (m *Metrics) RecordGuard(dp Dataplane, pairs []ipsec.SelectorPair) {
	drops := map[ipsec.SelectorPair]uint64{}
	if len(pairs) > 0 {
		var err error
		if drops, err = dp.GuardDrops(); err != nil {
			return
		}
	}
	for p, n := range drops {
		m.guardDropped.WithLabelValues(p.Local, p.Remote).Set(float64(n))
	}
	for p := range m.guarded {
		if _, ok := drops[p]; !ok {
			m.guardDropped.DeleteLabelValues(p.Local, p.Remote)
		}
	}
	m.guarded = map[ipsec.SelectorPair]bool{}
	for p := range drops {
		m.guarded[p] = true
	}
}
