// Package meship deterministically derives a /32 mesh-overlay IP from a
// stable name (a node name, an external-peer displayName) within a given
// IPv4 mesh CIDR.
//
// The mapping is a 32-bit FNV-1a hash of the name, modulo the usable host
// range of the CIDR (skipping the .0 network address and the .max
// broadcast address). This avoids any central allocator: every caller
// computes the same /32 for the same inputs.
//
// Collision probability is negligible for clusters smaller than the
// birthday bound (sqrt(usableSize)) — for a /10 CIDR (~4 M usable hosts)
// the bound is ~2048 names. The package intentionally does NOT detect
// collisions; callers operating beyond the birthday bound need a different
// allocator.
//
// The package is pure-Go with no Kubernetes dependencies and no build
// tags so it can be reused by both the agent (node naming) and the
// external-peer reconciler (displayName naming).
package meship

import (
	"fmt"
	"net"
)

// IPForName deterministically derives a /32 overlay IP within meshCIDR for
// the given name using a 32-bit FNV-1a hash. The returned string is in
// CIDR notation (e.g. "100.64.42.7/32"). The mapping is stable across
// processes, restarts, and Go versions.
//
// Errors:
//   - meshCIDR is not a parseable CIDR.
//   - meshCIDR is not IPv4.
//   - meshCIDR is smaller than /30 (no usable host range).
func IPForName(name, meshCIDR string) (string, error) {
	_, ipnet, err := net.ParseCIDR(meshCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid meshCIDR %q: %w", meshCIDR, err)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return "", fmt.Errorf("meshCIDR must be an IPv4 CIDR")
	}
	ones, bits := ipnet.Mask.Size()
	// A non-IPv4 mask would have already been rejected by To4 above; bits
	// is therefore 32 here. Compute the address-space size guarded against
	// overflow when ones == 0.
	size := uint32(1) << uint(bits-ones)
	if size < 4 {
		return "", fmt.Errorf("meshCIDR too small (need at least /30)")
	}

	// FNV-1a hash of the name for uniform distribution across the range.
	h := fnv32a(name)
	// Usable range: skip .0 (network) and .size-1 (broadcast).
	// offset ∈ [1, size-2].
	offset := (h%(size-2) + 1)

	baseInt := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	ipInt := baseInt + offset
	ip := net.IP{byte(ipInt >> 24), byte(ipInt >> 16), byte(ipInt >> 8), byte(ipInt)}
	return ip.String() + "/32", nil
}

// fnv32a is an inline FNV-1a 32-bit hash. Inlined to avoid pulling in
// hash/fnv (the function is one-shot, byte-by-byte, and benefits from
// being heap-free).
func fnv32a(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}
