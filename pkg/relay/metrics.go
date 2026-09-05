package relay

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Relay metrics.
//
// The dest label is the same 8-byte key prefix the relay logs print, so a
// series and a log line about one peer can be matched by eye. It exists ONLY
// for peers currently registered on this replica: series are created when a
// peer registers and deleted when it deregisters, so cardinality tracks
// connected clients rather than everything the relay has ever seen.
// Registration is unauthenticated, but it does cost the remote side a TCP
// session, which bounds what it can inflate.
//
// Destination keys named inside a frame (the MsgData dest slot, the bimodal
// hint target) are attacker-controlled and never become a label; a miss on
// them is counted on the label-free unknown-dest counter instead.
var (
	relayFramesDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "wirekube",
		Subsystem: "relay",
		Name:      "frames_dropped_total",
		Help:      "Frames the relay could not deliver to a registered local peer, by reason (queue_tail=send queue full, gone=connection already closed, write_error=socket write failed), frame class and destination key prefix.",
	}, []string{"reason", "class", "dest"})

	relayFramesDroppedUnknownDest = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "wirekube",
		Subsystem: "relay",
		Name:      "frames_dropped_unknown_dest_total",
		Help:      "Frames addressed to a destination key that is registered on no replica. Unlabelled on purpose: the key is chosen by the sender.",
	})

	relayFramesForwarded = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "wirekube",
		Subsystem: "relay",
		Name:      "frames_forwarded_total",
		Help:      "Frames enqueued for delivery to a registered local peer, by frame class and destination key prefix.",
	}, []string{"class", "dest"})

	relayClients = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Subsystem: "relay",
		Name:      "clients",
		Help:      "Peers currently registered on this relay replica.",
	})

	relayQueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wirekube",
		Subsystem: "relay",
		Name:      "queue_depth",
		Help:      "Frames waiting in a registered local peer's send queue, sampled after each enqueue and dequeue, by frame class and destination key prefix.",
	}, []string{"class", "dest"})
)

// dropReason is the reason label of relayFramesDropped.
type dropReason uint8

const (
	dropQueueTail dropReason = iota
	dropGone
	dropWriteError
	dropShutdown
	dropReasonCount
)

func (r dropReason) String() string {
	switch r {
	case dropQueueTail:
		return "queue_tail"
	case dropGone:
		return "gone"
	case dropWriteError:
		return "write_error"
	case dropShutdown:
		return "shutdown"
	default:
		return "unknown"
	}
}

// destLabel renders a peer key the way the relay logs do (%x of the first 8
// bytes), so metrics and log lines about one peer line up.
func destLabel(pubKey [PubKeySize]byte) string {
	return fmt.Sprintf("%x", pubKey[:8])
}

// connMetrics holds one registered peer's label children, resolved once at
// registration so the per-frame path does no label hashing. The children stay
// valid after deleteDestMetrics removes them from their vectors: a late
// increment on a deregistered peer then lands on an orphan and cannot
// resurrect the series.
type connMetrics struct {
	forwarded [frameClassCount]prometheus.Counter
	depth     [frameClassCount]prometheus.Gauge
	dropped   [frameClassCount][dropReasonCount]prometheus.Counter
}

func newConnMetrics(dest string) *connMetrics {
	m := &connMetrics{}
	for class := frameClass(0); class < frameClassCount; class++ {
		m.forwarded[class] = relayFramesForwarded.WithLabelValues(class.String(), dest)
		m.depth[class] = relayQueueDepth.WithLabelValues(class.String(), dest)
		for reason := dropReason(0); reason < dropReasonCount; reason++ {
			m.dropped[class][reason] = relayFramesDropped.WithLabelValues(reason.String(), class.String(), dest)
		}
	}
	return m
}

// deleteDestMetrics removes every series carrying dest. Callers hold s.mu so
// this cannot interleave with a reconnecting peer's newConnMetrics for the
// same key and delete the fresh children.
func deleteDestMetrics(dest string) {
	labels := prometheus.Labels{"dest": dest}
	relayFramesDropped.DeletePartialMatch(labels)
	relayFramesForwarded.DeletePartialMatch(labels)
	relayQueueDepth.DeletePartialMatch(labels)
}
