//go:build linux

package ipsec

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// guardHooks are the built-in chains that jump to GuardChain: FORWARD for
// mesh traffic the gateway relays, OUTPUT for traffic it originates.
var guardHooks = []string{"FORWARD", "OUTPUT"}

func iptables(args ...string) (string, error) {
	out, err := exec.Command("iptables", append([]string{"-w"}, args...)...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("iptables %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}

// SyncGuard makes GuardChain hold exactly one drop rule per pair. New rules
// are added before stale ones are removed, so a selector never goes
// unguarded during a change. With no pairs the chain and its jumps are
// removed.
func SyncGuard(pairs []SelectorPair) error {
	if len(pairs) == 0 {
		RemoveGuard()
		return nil
	}
	if _, err := iptables("-S", GuardChain); err != nil {
		if _, err := iptables("-N", GuardChain); err != nil {
			return err
		}
	}
	for _, hook := range guardHooks {
		if _, err := iptables("-C", hook, "-j", GuardChain); err != nil {
			if _, err := iptables("-I", hook, "1", "-j", GuardChain); err != nil {
				return err
			}
		}
	}
	out, err := iptables("-S", GuardChain)
	if err != nil {
		return err
	}
	current := parseGuardRules(out)
	existing := make([]string, 0, len(current))
	for c := range current {
		existing = append(existing, c)
	}
	add, remove := guardDiff(existing, pairs)
	var errs []error
	for _, p := range add {
		if _, err := iptables(append([]string{"-A", GuardChain}, GuardRuleArgs(p)...)...); err != nil {
			errs = append(errs, err)
		}
	}
	for _, c := range remove {
		if _, err := iptables(append([]string{"-D", GuardChain}, current[c]...)...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RemoveGuard deletes the jumps and the chain. Missing pieces are fine.
func RemoveGuard() {
	for _, hook := range guardHooks {
		for i := 0; i < 8; i++ {
			if _, err := iptables("-D", hook, "-j", GuardChain); err != nil {
				break
			}
		}
	}
	_, _ = iptables("-F", GuardChain)
	_, _ = iptables("-X", GuardChain)
}

// GuardDrops returns the packets each guard rule dropped, keyed by its
// selector pair.
func GuardDrops() (map[SelectorPair]uint64, error) {
	out, err := iptables("-nvxL", GuardChain)
	if err != nil {
		return nil, err
	}
	drops := map[SelectorPair]uint64{}
	for c, n := range parseGuardCounters(out) {
		if p, ok := PairOfComment(c); ok {
			drops[p] = n
		}
	}
	return drops, nil
}
