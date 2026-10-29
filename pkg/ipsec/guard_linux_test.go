//go:build linux

package ipsec

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestSyncGuardHooksOnlyTheChainsGiven(t *testing.T) {
	orig := iptables
	defer func() { iptables = orig }()
	var calls []string
	iptables = func(args ...string) (string, error) {
		c := strings.Join(args, " ")
		calls = append(calls, c)
		if args[0] == "-C" {
			return "", errors.New("no such rule")
		}
		return "", nil
	}
	pairs := []SelectorPair{{Local: "192.168.10.0/24", Remote: "10.20.0.0/16"}}
	if err := SyncGuard(pairs, []string{"FORWARD"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(calls, "-I FORWARD 1 -j "+GuardChain) || slices.Contains(calls, "-I OUTPUT 1 -j "+GuardChain) ||
		!slices.Contains(calls, "-D OUTPUT -j "+GuardChain) {
		t.Fatalf("iptables calls = %q", calls)
	}
}
