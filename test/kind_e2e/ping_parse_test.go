package kind_e2e

import "testing"

func TestExtractPingSeq(t *testing.T) {
	tests := []struct {
		line string
		want int
		ok   bool
	}{
		{line: "64 bytes from 172.20.0.2: icmp_seq=5 ttl=64 time=1.23 ms", want: 5, ok: true},
		{line: "64 bytes from 100.127.248.215: seq=7 ttl=64 time=0.463 ms", want: 7, ok: true},
		{line: "PING 100.127.248.215 (100.127.248.215): 56 data bytes", want: 0, ok: false},
	}

	for _, tt := range tests {
		got, ok := extractPingSeq(tt.line)
		if ok != tt.ok {
			t.Fatalf("extractPingSeq(%q) ok = %v, want %v", tt.line, ok, tt.ok)
		}
		if got != tt.want {
			t.Fatalf("extractPingSeq(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
}

func TestLongestPingSeqGap(t *testing.T) {
	out := `PING 100.127.248.215 (100.127.248.215): 56 data bytes
64 bytes from 100.127.248.215: seq=0 ttl=64 time=0.677 ms
64 bytes from 100.127.248.215: seq=1 ttl=64 time=0.419 ms
64 bytes from 100.127.248.215: seq=4 ttl=64 time=2.028 ms
64 bytes from 100.127.248.215: seq=5 ttl=64 time=0.463 ms
64 bytes from 100.127.248.215: seq=9 ttl=64 time=1.311 ms
`

	if got := longestPingSeqGap(out); got != 3 {
		t.Fatalf("longestPingSeqGap() = %d, want 3", got)
	}
}

func TestLongestPingSeqGapIncludesTrailingLoss(t *testing.T) {
	out := `PING 100.127.248.215 (100.127.248.215): 56 data bytes
64 bytes from 100.127.248.215: seq=0 ttl=64 time=0.677 ms
64 bytes from 100.127.248.215: seq=1 ttl=64 time=0.419 ms
64 bytes from 100.127.248.215: seq=2 ttl=64 time=0.651 ms

--- 100.127.248.215 ping statistics ---
300 packets transmitted, 3 packets received, 99% packet loss
`

	if got := longestPingSeqGap(out); got != 297 {
		t.Fatalf("longestPingSeqGap() = %d, want 297", got)
	}
}
