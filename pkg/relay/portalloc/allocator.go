// Package portalloc provides a thread-safe UDP port allocator over a
// configured port range. Each relay replica owns one Allocator and hands
// out free ports to the external-peer reconciler.
package portalloc

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// DefaultMin and DefaultMax are the default port range bounds (inclusive) for
// a relay replica's per-peer UDP port pool.
const (
	DefaultMin uint16 = 32768
	DefaultMax uint16 = 40959
)

// ErrExhausted is returned by Allocate when all ports in the range are in use.
var ErrExhausted = errors.New("portalloc: pool exhausted")

// ErrInUse is returned by Reserve when a specific port is already reserved.
var ErrInUse = errors.New("portalloc: port already in use")

// Allocator is a thread-safe pool of UDP port numbers in the inclusive
// range [min, max]. Methods are safe to call concurrently.
type Allocator struct {
	min uint16
	max uint16

	mu     sync.Mutex
	inUse  map[uint16]struct{}
	cursor uint16 // next port to consider; rotates through the range
}

// New returns a new Allocator covering the inclusive range [min, max].
// Returns an error if min > max or min == 0.
func New(min, max uint16) (*Allocator, error) {
	if min == 0 {
		return nil, fmt.Errorf("portalloc: min must be > 0")
	}
	if min > max {
		return nil, fmt.Errorf("portalloc: min (%d) > max (%d)", min, max)
	}
	return &Allocator{
		min:    min,
		max:    max,
		inUse:  make(map[uint16]struct{}),
		cursor: min,
	}, nil
}

// Capacity returns the total number of ports in the pool.
func (a *Allocator) Capacity() int {
	return int(a.max-a.min) + 1
}

// Allocate reserves and returns the next free port in the range.
// Returns ErrExhausted if no ports remain. The allocator scans forward
// from an internal cursor (with wraparound) so reuse is delayed —
// freed ports are not immediately handed back, which matches the typical
// UDP-port reuse hygiene expected by clients.
func (a *Allocator) Allocate() (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.inUse) >= a.Capacity() {
		return 0, ErrExhausted
	}

	// Scan forward from cursor with wraparound. Capacity is bounded so this
	// terminates in at most Capacity() iterations.
	span := a.Capacity()
	p := a.cursor
	for i := 0; i < span; i++ {
		if _, taken := a.inUse[p]; !taken {
			a.inUse[p] = struct{}{}
			// Advance cursor past the just-allocated port for next call.
			a.cursor = a.next(p)
			return p, nil
		}
		p = a.next(p)
	}
	// Shouldn't reach here given the capacity check above, but be defensive.
	return 0, ErrExhausted
}

// Release returns a port to the pool. It is a no-op if the port is not
// currently in use or is outside the configured range — callers can safely
// invoke Release without first checking allocation state.
func (a *Allocator) Release(port uint16) {
	if port < a.min || port > a.max {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.inUse, port)
}

// Reserve marks a specific port as in-use. It is used when a controller has
// already chosen a global port and needs every relay replica to bind that same
// value rather than asking each replica to allocate independently.
func (a *Allocator) Reserve(port uint16) error {
	if port < a.min || port > a.max {
		return fmt.Errorf("portalloc: port %d outside range [%d,%d]", port, a.min, a.max)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.inUse[port]; ok {
		return ErrInUse
	}
	a.inUse[port] = struct{}{}
	return nil
}

// InUse returns a sorted snapshot of currently allocated ports.
// Equivalent to Snapshot; provided as a more descriptive name for
// observability use cases (e.g. metrics).
func (a *Allocator) InUse() []uint16 {
	return a.Snapshot()
}

// Snapshot returns a sorted slice of currently allocated ports.
// Intended to be persisted (e.g. to a CRD status) before relay restart so
// that a new Allocator can be reseeded with Restore.
func (a *Allocator) Snapshot() []uint16 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint16, 0, len(a.inUse))
	for p := range a.inUse {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Restore reseeds the allocator with a previously captured snapshot.
// Ports outside the configured range are silently ignored (the snapshot may
// have been taken under different bounds). Returns an error if any port
// would push the pool above capacity.
//
// Restore is intended for use immediately after New, before any Allocate
// calls; calling it after allocations is permitted but the union of states
// must still fit in the pool.
func (a *Allocator) Restore(ports []uint16) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Build the prospective set so we can validate before mutating.
	prospective := make(map[uint16]struct{}, len(a.inUse)+len(ports))
	for p := range a.inUse {
		prospective[p] = struct{}{}
	}
	for _, p := range ports {
		if p < a.min || p > a.max {
			continue
		}
		prospective[p] = struct{}{}
	}
	if len(prospective) > a.Capacity() {
		return fmt.Errorf("portalloc: restore would exceed capacity (%d > %d)",
			len(prospective), a.Capacity())
	}
	a.inUse = prospective
	return nil
}

// next returns p+1 with wraparound to a.min when p == a.max.
func (a *Allocator) next(p uint16) uint16 {
	if p >= a.max {
		return a.min
	}
	return p + 1
}
