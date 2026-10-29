package ipsec

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/strongswan/govici/vici"

	wirekubev1alpha1 "github.com/inerplat/wirekube/pkg/api/v1alpha1"
)

// Failure is the most recent reason charon logged for a connection not
// coming up.
type Failure struct {
	// Code classifies the failure.
	Code wirekubev1alpha1.IPsecTunnelReason
	// Reason is a short, actionable explanation.
	Reason string
	// Log is the charon log line it was derived from.
	Log  string
	Time time.Time
}

// failurePatterns map charon log messages to explanations a user can act on.
// Matching is by substring and the first match wins.
var failurePatterns = []struct {
	substr string
	code   wirekubev1alpha1.IPsecTunnelReason
	reason string
}{
	{"NO_PROPOSAL_CHOSEN", wirekubev1alpha1.IPsecReasonProposalMismatch, "the remote gateway rejected the proposals: make the encryption, integrity and DH group match on both sides"},
	{"proposals unacceptable", wirekubev1alpha1.IPsecReasonProposalMismatch, "the remote gateway's proposals are not accepted here: make the encryption, integrity and DH group match on both sides"},
	{"INVALID_KE_PAYLOAD", wirekubev1alpha1.IPsecReasonDHGroupMismatch, "the DH groups differ: set the same DH group on both sides"},
	{"AUTHENTICATION_FAILED", wirekubev1alpha1.IPsecReasonAuthenticationFailed, "authentication failed: check the pre-shared key and the local and remote IDs"},
	{"MAC mismatched", wirekubev1alpha1.IPsecReasonAuthenticationFailed, "authentication failed: the pre-shared keys differ"},
	{"no shared key found", wirekubev1alpha1.IPsecReasonAuthenticationFailed, "authentication failed: no pre-shared key matches the remote ID"},
	{"TS_UNACCEPTABLE", wirekubev1alpha1.IPsecReasonTrafficSelectorMismatch, "the remote gateway rejected the traffic selectors: its local network must equal the remote selectors here and its remote network the local selectors"},
	{"no acceptable traffic selectors", wirekubev1alpha1.IPsecReasonTrafficSelectorMismatch, "the traffic selectors do not match the remote gateway's networks"},
	{"giving up after", wirekubev1alpha1.IPsecReasonPeerUnreachable, "the remote gateway does not answer: check remoteAddress, and that UDP 500, UDP 4500 and ESP are allowed both ways"},
	{"peer not responding", wirekubev1alpha1.IPsecReasonPeerUnreachable, "the remote gateway does not answer: check remoteAddress, and that UDP 500, UDP 4500 and ESP are allowed both ways"},
}

// ClassifyLog returns the explanation for a charon log message, or "".
func ClassifyLog(msg string) string {
	_, reason := Classify(msg)
	return reason
}

// Classify returns the code and explanation for a charon log message, or
// empty strings.
func Classify(msg string) (wirekubev1alpha1.IPsecTunnelReason, string) {
	for _, p := range failurePatterns {
		if strings.Contains(msg, p.substr) {
			return p.code, p.reason
		}
	}
	return "", ""
}

// FailureWatcher subscribes to charon's log events and remembers, per
// connection, the last line that explains a failed negotiation. Charon only
// logs these; neither list-sas nor the connection state carries them.
type FailureWatcher struct {
	Socket string

	mu   sync.Mutex
	last map[string]Failure
}

// Run consumes log events until ctx ends, reconnecting when charon goes
// away.
func (w *FailureWatcher) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		w.consume(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (w *FailureWatcher) consume(ctx context.Context) {
	socket := w.Socket
	if socket == "" {
		socket = DefaultViciSocket
	}
	s, err := vici.NewSession(vici.WithSocketPath(socket))
	if err != nil {
		return
	}
	defer s.Close()
	events := make(chan vici.Event, 64)
	s.NotifyEvents(events)
	if err := s.Subscribe("log"); err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			w.Observe(ev.Message, ev.Timestamp)
		}
	}
}

// Observe records a log event if it explains a failure of a WireKube
// connection.
func (w *FailureWatcher) Observe(m *vici.Message, at time.Time) {
	if m == nil {
		return
	}
	conn, _ := m.Get("ikesa-name").(string)
	if _, ok := KeyOfConn(conn); !ok {
		return
	}
	msg, _ := m.Get("msg").(string)
	code, reason := Classify(msg)
	if reason == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.last == nil {
		w.last = map[string]Failure{}
	}
	w.last[conn] = Failure{Code: code, Reason: reason, Log: msg, Time: at}
}

// Last returns the most recent failure of a connection newer than since.
func (w *FailureWatcher) Last(conn string, since time.Time) (Failure, bool) {
	if w == nil {
		return Failure{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	f, ok := w.last[conn]
	if !ok || f.Time.Before(since) {
		return Failure{}, false
	}
	return f, true
}

// Forget drops a connection's failure, for example once it is established.
func (w *FailureWatcher) Forget(conn string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.last, conn)
}
