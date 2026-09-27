// Package meship deterministically derives a /32 mesh-overlay IP from a
// stable name (a node name, an external-peer displayName) within a given
// IPv4 mesh CIDR.
//
// The mapping is a 32-bit FNV-1a hash of the name, modulo the usable host
// range of the CIDR (skipping the .0 network address and the .max
// broadcast address). This avoids any central allocator: every caller
// computes the same /32 for the same inputs.
//
// The first choice is not collision-free — the hash is reduced into the
// mesh CIDR, so two names can land on the same address. Rather than detect
// collisions here, the package exposes a deterministic *sequence* of
// candidates per name: IPForNameAttempt walks the usable range in a
// name-specific order that visits every address exactly once. A caller that
// arbitrates claims (see pkg/meshalloc) can therefore step to the next
// candidate on a conflict and still be reproducible from the name alone.
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
// It is exactly IPForNameAttempt(name, meshCIDR, 0).
//
// Errors:
//   - meshCIDR is not a parseable CIDR.
//   - meshCIDR is not IPv4.
//   - meshCIDR is smaller than /30 (no usable host range).
func IPForName(name, meshCIDR string) (string, error) {
	return IPForNameAttempt(name, meshCIDR, 0)
}

// IPForNameAttempt returns the attempt'th candidate address for name within
// meshCIDR. Attempt 0 is the historical IPForName result and must stay
// bit-identical: peers that already hold their hashed address keep it.
//
// Successive attempts walk the usable host range as a permutation — start at
// the hashed offset and advance by a name-specific step chosen coprime to the
// range size. Over Capacity(meshCIDR) attempts that visits every usable
// address exactly once, so a caller probing for a free address never retries
// one it has already seen and is guaranteed to find a free address if one
// exists. Attempts beyond the capacity wrap around.
//
// A negative attempt is rejected rather than silently normalised.
func IPForNameAttempt(name, meshCIDR string, attempt int) (string, error) {
	if attempt < 0 {
		return "", fmt.Errorf("attempt must not be negative, got %d", attempt)
	}
	base, size, err := parseMesh(meshCIDR)
	if err != nil {
		return "", err
	}

	// Usable range: skip .0 (network) and .size-1 (broadcast), so the
	// offset added to the network address is in [1, size-2].
	usable := size - 2
	// FNV-1a hash of the name for uniform distribution across the range.
	start := fnv32a(name) % usable
	index := start
	if attempt > 0 {
		step := stepForName(name, usable)
		// uint64 keeps the multiplication from wrapping before the modulo.
		index = uint32((uint64(start) + uint64(step)*uint64(uint32(attempt))%uint64(usable)) % uint64(usable))
	}

	ipInt := base + index + 1
	ip := net.IP{byte(ipInt >> 24), byte(ipInt >> 16), byte(ipInt >> 8), byte(ipInt)}
	return ip.String() + "/32", nil
}

// Capacity is the number of addresses IPForNameAttempt can return for
// meshCIDR, which is the count of distinct attempts before the walk repeats.
func Capacity(meshCIDR string) (int, error) {
	_, size, err := parseMesh(meshCIDR)
	if err != nil {
		return 0, err
	}
	return int(size - 2), nil
}

// Contains reports whether address is a host address that meshCIDR can hand
// out — the inverse question to IPForNameAttempt, and the check every caller
// needs before honouring a recorded or requested address.
//
// It is stricter than net.IPNet.Contains: the network and broadcast addresses
// are inside the CIDR but are not assignable, and IPForNameAttempt never
// returns them, so an address landing on either did not come from here and
// must not be treated as though it had.
func Contains(address, meshCIDR string) bool {
	ip, ipnet, err := net.ParseCIDR(address)
	if err != nil {
		return false
	}
	if ones, bits := ipnet.Mask.Size(); ones != 32 || bits != 32 {
		return false
	}
	base, size, err := parseMesh(meshCIDR)
	if err != nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	value := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	return value > base && value < base+size-1
}

// parseMesh validates meshCIDR and returns its network address as a 32-bit
// integer along with the size of its address space.
func parseMesh(meshCIDR string) (base, size uint32, err error) {
	_, ipnet, err := net.ParseCIDR(meshCIDR)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid meshCIDR %q: %w", meshCIDR, err)
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("meshCIDR must be an IPv4 CIDR")
	}
	ones, bits := ipnet.Mask.Size()
	// A non-IPv4 mask would have already been rejected by To4 above; bits
	// is therefore 32 here. Compute the address-space size guarded against
	// overflow when ones == 0.
	size = uint32(1) << uint(bits-ones)
	if size < 4 {
		return 0, 0, fmt.Errorf("meshCIDR too small (need at least /30)")
	}
	base = uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	return base, size, nil
}

// stepForName picks the stride of the permutation walk for name: a value in
// [1, usable-1] that is coprime to usable, so repeatedly adding it modulo
// usable cycles through every offset before repeating. The candidate comes
// from a second hash so two names that share a starting offset still diverge
// on their first retry; it is then advanced to the next coprime value.
//
// usable must be at least 2, which parseMesh guarantees.
func stepForName(name string, usable uint32) uint32 {
	if usable < 3 {
		// The only stride in [1, usable-1] is 1, and gcd(1, 2) == 1.
		return 1
	}
	step := fnv32a("step\x00"+name)%(usable-1) + 1
	for gcd(step, usable) != 1 {
		step++
		if step >= usable {
			step = 1
		}
	}
	return step
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
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
