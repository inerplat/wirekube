package ipsec

import (
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

func logEvent(conn, msg string) *vici.Message {
	m := vici.NewMessage()
	if conn != "" {
		_ = m.Set("ikesa-name", conn)
	}
	_ = m.Set("msg", msg)
	return m
}

func TestFailureWatcherKeepsTheLastExplainedFailure(t *testing.T) {
	const conn = "wk-site/vpn@0123abcd"
	w := &FailureWatcher{}
	t0 := time.Now()
	w.Observe(logEvent(conn, "received NO_PROPOSAL_CHOSEN notify error"), t0)
	w.Observe(logEvent(conn, "sending retransmit 1 of request message ID 0, seq 1"), t0.Add(time.Second))
	w.Observe(logEvent("site-to-hq", "received AUTHENTICATION_FAILED notify error"), t0)
	w.Observe(logEvent("", "no IKE config found for 10.0.0.1...10.0.0.2"), t0)

	f, ok := w.Last(conn, t0.Add(-time.Minute))
	if !ok || !strings.Contains(f.Reason, "DH group") || f.Log != "received NO_PROPOSAL_CHOSEN notify error" {
		t.Fatalf("Last = %+v, %v", f, ok)
	}
	if _, ok := w.Last(conn, t0.Add(time.Minute)); ok {
		t.Errorf("a failure older than since was returned")
	}
	if _, ok := w.Last("site-to-hq", t0.Add(-time.Minute)); ok {
		t.Errorf("a connection WireKube does not own was recorded")
	}
	w.Forget(conn)
	if _, ok := w.Last(conn, t0.Add(-time.Minute)); ok {
		t.Errorf("Forget kept the failure")
	}
}

func TestNilFailureWatcherIsInert(t *testing.T) {
	var w *FailureWatcher
	if _, ok := w.Last("wk-a/b@01234567", time.Time{}); ok {
		t.Fatal("nil watcher reported a failure")
	}
	w.Forget("wk-a/b@01234567")
}

func TestClassifyLog(t *testing.T) {
	cases := map[string]string{
		"received AUTHENTICATION_FAILED notify error":                        "pre-shared key",
		"giving up after 5 retransmits":                                      "does not answer",
		"received TS_UNACCEPTABLE notify, no CHILD_SA built":                 "traffic selectors",
		"CHILD_SA wk-site/vpn{1} established with SPIs c1_i c2_o and TS ...": "",
	}
	for msg, want := range cases {
		got := ClassifyLog(msg)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("ClassifyLog(%q) = %q; want it to mention %q", msg, got, want)
		}
	}
}

func TestDescribeProposal(t *testing.T) {
	cases := map[string]ProposalParts{
		"aes256-sha256-modp2048":      {Encryption: "AES-256-CBC", Integrity: "SHA2-256", DHGroup: "group 14 (MODP 2048)"},
		"aes256gcm16-ecp384":          {Encryption: "AES-256-GCM", DHGroup: "group 20 (ECP 384)"},
		"AES128-SHA1":                 {Encryption: "AES-128-CBC", Integrity: "SHA-1"},
		"camellia256-sha256-modp2048": {Encryption: "camellia256", Integrity: "SHA2-256", DHGroup: "group 14 (MODP 2048)"},
	}
	for in, want := range cases {
		if got := DescribeProposal(in); got != want {
			t.Errorf("DescribeProposal(%q) = %+v; want %+v", in, got, want)
		}
	}
}
