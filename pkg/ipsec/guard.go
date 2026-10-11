package ipsec

import (
	"fmt"
	"sort"
	"strings"
)

// GuardChain holds the rules that stop tunnel traffic from leaving in
// plaintext when no SA covers it.
const GuardChain = "WIREKUBE-IPSEC-GUARD"

// guardCommentPrefix tags every guard rule with the selector pair it covers,
// so reconciliation can tell its own rules apart and match them to pairs.
const guardCommentPrefix = "wk-ipsec:"

// SelectorPair is one local-to-remote traffic selector combination of a
// tunnel.
type SelectorPair struct {
	Local  string
	Remote string
}

// Pairs returns every local-to-remote selector combination of a tunnel.
func (t *Tunnel) Pairs() []SelectorPair {
	var out []SelectorPair
	for _, l := range t.LocalTS {
		for _, r := range t.RemoteTS {
			out = append(out, SelectorPair{Local: l, Remote: r})
		}
	}
	return out
}

func (p SelectorPair) comment() string { return guardCommentPrefix + p.Local + ">" + p.Remote }

// GuardRuleArgs is the iptables rule body for a pair: drop a packet from
// Local to Remote that IPsec will not process, unless it leaves through a
// WireKube XFRM interface, which encrypts inside the interface itself and
// therefore carries no policy at this point.
//
// Policy-based tunnels need this most: their kernel policies exist only while
// a CHILD_SA is installed, so before the first negotiation, during a DPD
// restart, or while failover moves the tunnel, forwarded mesh traffic would
// otherwise follow the default route out of the underlay in plaintext.
func GuardRuleArgs(p SelectorPair) []string {
	return []string{
		"-s", p.Local, "-d", p.Remote,
		"!", "-o", InterfacePrefix + "+",
		"-m", "policy", "--dir", "out", "--pol", "none",
		"-m", "comment", "--comment", p.comment(),
		"-j", "DROP",
	}
}

// guardDiff compares the comments of existing guard rules with the wanted
// pairs. It returns the pairs to add and the comments to remove.
func guardDiff(existing []string, wanted []SelectorPair) (add []SelectorPair, remove []string) {
	have := map[string]bool{}
	for _, c := range existing {
		have[c] = true
	}
	want := map[string]bool{}
	for _, p := range wanted {
		c := p.comment()
		if want[c] {
			continue
		}
		want[c] = true
		if !have[c] {
			add = append(add, p)
		}
	}
	for c := range have {
		if !want[c] {
			remove = append(remove, c)
		}
	}
	sort.Strings(remove)
	return add, remove
}

// parseGuardRules extracts guard comments, with each rule's full argument
// list, from "iptables -S GuardChain" output.
func parseGuardRules(out string) map[string][]string {
	rules := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A "+GuardChain+" ") {
			continue
		}
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "--comment" {
				c := strings.Trim(fields[i+1], "\"")
				if strings.HasPrefix(c, guardCommentPrefix) {
					// iptables -S quotes the comment; -D needs it unquoted.
					args := make([]string, 0, len(fields)-2)
					for _, f := range fields[2:] {
						args = append(args, strings.Trim(f, "\""))
					}
					rules[c] = args
				}
			}
		}
	}
	return rules
}

// parseGuardCounters extracts per-pair drop counters from
// "iptables -nvxL GuardChain" output, keyed by the rule comment.
func parseGuardCounters(out string) map[string]uint64 {
	counters := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "/* "+guardCommentPrefix)
		if i < 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var n uint64
		if _, err := fmt.Sscan(fields[0], &n); err != nil {
			continue
		}
		c := strings.TrimSuffix(strings.TrimSpace(line[i+3:]), "*/")
		counters[strings.TrimSpace(c)] = n
	}
	return counters
}

// PairOfComment parses a guard rule comment back into its selector pair.
func PairOfComment(c string) (SelectorPair, bool) {
	body, ok := strings.CutPrefix(c, guardCommentPrefix)
	if !ok {
		return SelectorPair{}, false
	}
	l, r, ok := strings.Cut(body, ">")
	return SelectorPair{Local: l, Remote: r}, ok
}
