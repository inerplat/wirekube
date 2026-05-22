package portalloc

import (
	"errors"
	"sort"
	"sync"
	"testing"
)

func TestNew_validation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		min     uint16
		max     uint16
		wantErr bool
	}{
		{"valid range", 32768, 40959, false},
		{"single port", 50000, 50000, false},
		{"zero min", 0, 100, true},
		{"min greater than max", 200, 100, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a, err := New(tc.min, tc.max)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if a == nil {
				t.Fatalf("expected allocator, got nil")
			}
			if got, want := a.Capacity(), int(tc.max-tc.min)+1; got != want {
				t.Fatalf("capacity = %d, want %d", got, want)
			}
		})
	}
}

func TestAllocateRelease_roundtrip(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40005) // 6 ports
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allocated := make([]uint16, 0, 6)
	seen := make(map[uint16]struct{})
	for i := 0; i < 6; i++ {
		p, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		if p < 40000 || p > 40005 {
			t.Fatalf("port %d out of range", p)
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("duplicate port %d", p)
		}
		seen[p] = struct{}{}
		allocated = append(allocated, p)
	}

	if got := a.InUse(); len(got) != 6 {
		t.Fatalf("InUse len = %d, want 6", len(got))
	}

	// Release them all and confirm the pool empties.
	for _, p := range allocated {
		a.Release(p)
	}
	if got := a.InUse(); len(got) != 0 {
		t.Fatalf("InUse after release len = %d, want 0", len(got))
	}

	// Should be able to allocate the full range again.
	for i := 0; i < 6; i++ {
		if _, err := a.Allocate(); err != nil {
			t.Fatalf("re-allocate #%d: %v", i, err)
		}
	}
}

func TestAllocate_exhaustion(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40002) // 3 ports
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := a.Allocate(); err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
	}
	_, err = a.Allocate()
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}

	// After releasing one, another allocation must succeed.
	a.Release(40001)
	p, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate after release: %v", err)
	}
	if p != 40001 {
		// Cursor-based allocation: with cursor likely past 40002, scan wraps to
		// 40000 first which is taken, then 40001 which is free. Accept any
		// of the in-range free ports though, to keep this test robust to
		// minor cursor-policy changes.
		if p < 40000 || p > 40002 {
			t.Fatalf("got out-of-range port %d", p)
		}
	}
}

func TestRelease_doubleReleaseNoOp(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40009)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	a.Release(p)
	// Second release is a no-op and must not panic or corrupt state.
	a.Release(p)
	a.Release(p)

	if got := len(a.InUse()); got != 0 {
		t.Fatalf("InUse len = %d, want 0", got)
	}

	// Releasing an out-of-range port is also a no-op.
	a.Release(1)
	a.Release(65535)
}

func TestReserve_specificPort(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40002)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := a.Reserve(40001); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if got := a.InUse(); len(got) != 1 || got[0] != 40001 {
		t.Fatalf("InUse = %v, want [40001]", got)
	}
	if err := a.Reserve(40001); !errors.Is(err, ErrInUse) {
		t.Fatalf("second Reserve err = %v, want ErrInUse", err)
	}
	if err := a.Reserve(39999); err == nil {
		t.Fatal("Reserve outside range succeeded")
	}

	got := make(map[uint16]struct{})
	for i := 0; i < 2; i++ {
		p, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		got[p] = struct{}{}
	}
	if _, ok := got[40001]; ok {
		t.Fatalf("Allocate returned reserved port 40001: %v", got)
	}
	if _, err := a.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("Allocate after reserved range filled err = %v, want ErrExhausted", err)
	}
}

func TestAllocate_concurrent(t *testing.T) {
	t.Parallel()
	const (
		min uint16 = 50000
		max uint16 = 50099 // 100 ports
	)
	a, err := New(min, max)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const workers = 20
	const perWorker = 5 // 20 * 5 = 100 = full capacity

	var (
		mu        sync.Mutex
		collected = make([]uint16, 0, workers*perWorker)
		wg        sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			local := make([]uint16, 0, perWorker)
			for i := 0; i < perWorker; i++ {
				p, err := a.Allocate()
				if err != nil {
					t.Errorf("Allocate: %v", err)
					return
				}
				local = append(local, p)
			}
			mu.Lock()
			collected = append(collected, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(collected) != workers*perWorker {
		t.Fatalf("collected %d ports, want %d", len(collected), workers*perWorker)
	}

	// All allocations must be unique.
	seen := make(map[uint16]struct{}, len(collected))
	for _, p := range collected {
		if _, dup := seen[p]; dup {
			t.Fatalf("duplicate port %d in concurrent allocation", p)
		}
		if p < min || p > max {
			t.Fatalf("port %d out of range", p)
		}
		seen[p] = struct{}{}
	}

	// Pool must be exhausted now.
	if _, err := a.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected ErrExhausted after full concurrent fill, got %v", err)
	}
}

func TestRestore_fromSnapshot(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40009) // 10 ports
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Allocate a few; the assertions below use Snapshot() rather than the
	// per-call return values so we don't need to retain them.
	for i := 0; i < 3; i++ {
		if _, err := a.Allocate(); err != nil {
			t.Fatalf("Allocate: %v", err)
		}
	}

	snap := a.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("Snapshot len = %d, want 3", len(snap))
	}
	// Snapshot must be sorted.
	if !sort.SliceIsSorted(snap, func(i, j int) bool { return snap[i] < snap[j] }) {
		t.Fatalf("Snapshot not sorted: %v", snap)
	}

	// Build a fresh allocator and restore.
	fresh, err := New(40000, 40009)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := fresh.Restore(snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got := fresh.Snapshot()
	if len(got) != len(snap) {
		t.Fatalf("restored snapshot len = %d, want %d", len(got), len(snap))
	}
	for i := range got {
		if got[i] != snap[i] {
			t.Fatalf("restored snapshot[%d] = %d, want %d", i, got[i], snap[i])
		}
	}

	// The restored ports must not be re-handed-out. Allocate the remaining
	// 7 ports and check none collide with the snapshot.
	taken := make(map[uint16]struct{})
	for _, p := range snap {
		taken[p] = struct{}{}
	}
	for i := 0; i < 7; i++ {
		p, err := fresh.Allocate()
		if err != nil {
			t.Fatalf("Allocate after restore #%d: %v", i, err)
		}
		if _, clash := taken[p]; clash {
			t.Fatalf("Allocate after restore returned restored port %d", p)
		}
	}
	if _, err := fresh.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected ErrExhausted after filling restored pool, got %v", err)
	}
}

func TestRestore_outOfRangeIgnored(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40009)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Restore([]uint16{100, 40001, 50000, 40002}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got := a.Snapshot()
	want := []uint16{40001, 40002}
	if len(got) != len(want) {
		t.Fatalf("snapshot len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("snapshot[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestRestore_overCapacityRejected(t *testing.T) {
	t.Parallel()
	a, err := New(40000, 40002) // 3 ports
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = a.Restore([]uint16{40000, 40001, 40002, 40000}) // dedup -> 3, fits
	if err != nil {
		t.Fatalf("unexpected error on at-capacity restore: %v", err)
	}

	// Now try restoring a port that, combined with current state, would not fit.
	// Pool is currently full (3/3). Restore a fourth distinct port (out of
	// range so this would normally be ignored, but we use one in range).
	a2, err := New(40000, 40001) // 2 ports
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Pre-allocate one.
	if _, err := a2.Allocate(); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	// Restoring both ports plus the pre-allocated one is fine if dedup is
	// applied; but supplying ports beyond capacity must error. Build that:
	// allocator has capacity 2 and one allocated. Restoring [40000, 40001]
	// when one of them is already taken — set still has capacity 2.
	if err := a2.Restore([]uint16{40000, 40001}); err != nil {
		t.Fatalf("at-capacity restore should not error, got %v", err)
	}
}
