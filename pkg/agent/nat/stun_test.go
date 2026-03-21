package nat

import (
	"testing"
)

func TestBuildPortPrediction_Sequential(t *testing.T) {
	ports := []int{10000, 10002, 10004, 10006}
	pp := buildPortPrediction(ports)

	if pp.BasePort != 10006 {
		t.Errorf("BasePort: got %d, want 10006", pp.BasePort)
	}
	if pp.Increment != 2 {
		t.Errorf("Increment: got %d, want 2", pp.Increment)
	}
	if pp.Jitter != 0 {
		t.Errorf("Jitter: got %d, want 0", pp.Jitter)
	}
}

func TestBuildPortPrediction_WithJitter(t *testing.T) {
	ports := []int{10000, 10003, 10005, 10008}
	pp := buildPortPrediction(ports)

	if pp.BasePort != 10008 {
		t.Errorf("BasePort: got %d, want 10008", pp.BasePort)
	}
	// Deltas: 3, 2, 3 → avg=2, jitter=1
	if pp.Increment != 2 {
		t.Errorf("Increment: got %d, want 2", pp.Increment)
	}
	if pp.Jitter != 1 {
		t.Errorf("Jitter: got %d, want 1", pp.Jitter)
	}
}

func TestBuildPortPrediction_SinglePort(t *testing.T) {
	pp := buildPortPrediction([]int{5000})
	if pp.BasePort != 5000 {
		t.Errorf("BasePort: got %d, want 5000", pp.BasePort)
	}
	if pp.Increment != 0 {
		t.Errorf("Increment should be 0 for single port")
	}
}

func TestGenerateCandidates_Sequential(t *testing.T) {
	pp := PortPrediction{
		BasePort:    10000,
		Increment:   2,
		Jitter:      1,
		SamplePorts: []int{9996, 9998, 10000},
	}

	candidates := pp.GenerateCandidates(5)
	if len(candidates) != 5 {
		t.Fatalf("got %d candidates, want 5", len(candidates))
	}

	// First candidate should be BasePort + Increment = 10002
	if candidates[0] != 10002 {
		t.Errorf("first candidate: got %d, want 10002", candidates[0])
	}
}

func TestGenerateCandidates_Random(t *testing.T) {
	pp := PortPrediction{
		BasePort:    40000,
		Increment:   0,
		Jitter:      100,
		SamplePorts: []int{39900, 40100},
	}

	candidates := pp.GenerateCandidates(100)
	if len(candidates) != 100 {
		t.Fatalf("got %d candidates, want 100", len(candidates))
	}

	// All ports should be valid
	for _, p := range candidates {
		if p <= 0 || p >= 65536 {
			t.Errorf("invalid port: %d", p)
		}
	}
}

func TestGenerateCandidates_EdgeCases(t *testing.T) {
	pp := PortPrediction{BasePort: 10000, Increment: 1}

	if got := pp.GenerateCandidates(0); len(got) != 0 {
		t.Errorf("n=0: got %d, want 0", len(got))
	}
	if got := pp.GenerateCandidates(-1); got != nil {
		t.Errorf("n=-1: got %v, want nil", got)
	}
}

func TestAbs(t *testing.T) {
	tests := []struct {
		input, expected int
	}{
		{5, 5},
		{-5, 5},
		{0, 0},
		{-1, 1},
	}
	for _, tt := range tests {
		if got := abs(tt.input); got != tt.expected {
			t.Errorf("abs(%d) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestResolveSTUNAddr(t *testing.T) {
	tests := []struct {
		server  string
		wantErr bool
	}{
		{"stun:stun.l.google.com:19302", false},
		{"stun.l.google.com:19302", false},
		{"stun:invalid:::port", true},
	}

	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			addr, err := resolveSTUNAddr(tt.server)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveSTUNAddr(%q) error = %v, wantErr %v", tt.server, err, tt.wantErr)
			}
			if !tt.wantErr && addr == nil {
				t.Error("expected non-nil addr")
			}
		})
	}
}

func TestKeyLess(t *testing.T) {
	a := [32]byte{0}
	b := [32]byte{1}

	if !keyLess(a, b) {
		t.Error("expected a < b")
	}
	if keyLess(b, a) {
		t.Error("expected !(b < a)")
	}
	if keyLess(a, a) {
		t.Error("expected !(a < a)")
	}
}

func TestProbeToken_Commutative(t *testing.T) {
	a := [32]byte{1, 2, 3}
	b := [32]byte{4, 5, 6}

	if ProbeToken(a, b) != ProbeToken(b, a) {
		t.Error("ProbeToken should be commutative")
	}
}
