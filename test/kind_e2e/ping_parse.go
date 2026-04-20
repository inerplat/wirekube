package kind_e2e

import (
	"fmt"
	"strings"
)

// longestPingSeqGap parses ping output and returns the longest consecutive run
// of missing sequence numbers. It supports both iputils-style "icmp_seq=N"
// output and BusyBox-style "seq=N" output.
func longestPingSeqGap(out string) int {
	seqs := parsePingSeqs(out)
	if len(seqs) == 0 {
		return 0
	}

	received := make(map[int]bool, len(seqs))
	minSeq, maxSeq := seqs[0], seqs[0]
	for _, s := range seqs {
		received[s] = true
		if s < minSeq {
			minSeq = s
		}
		if s > maxSeq {
			maxSeq = s
		}
	}
	if transmitted, ok := parsePingTransmitted(out); ok && transmitted > 0 {
		lastTransmittedSeq := transmitted - 1
		if lastTransmittedSeq > maxSeq {
			maxSeq = lastTransmittedSeq
		}
	}

	maxGap, curGap := 0, 0
	for i := minSeq; i <= maxSeq; i++ {
		if received[i] {
			if curGap > maxGap {
				maxGap = curGap
			}
			curGap = 0
			continue
		}
		curGap++
	}
	if curGap > maxGap {
		maxGap = curGap
	}
	return maxGap
}

func parsePingSeqs(out string) []int {
	var seqs []int
	for _, line := range strings.Split(out, "\n") {
		seq, ok := extractPingSeq(line)
		if ok {
			seqs = append(seqs, seq)
		}
	}
	return seqs
}

func extractPingSeq(line string) (int, bool) {
	for _, marker := range []string{"icmp_seq=", "seq="} {
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(marker):]
		var seq int
		if _, err := fmt.Sscanf(rest, "%d", &seq); err == nil {
			return seq, true
		}
	}
	return 0, false
}

func parsePingTransmitted(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		var transmitted int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d packets transmitted,", &transmitted); err == nil {
			return transmitted, true
		}
	}
	return 0, false
}
