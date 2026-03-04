package controller

import (
	"testing"
)

func TestParseCSV(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"172.20.0.0/16", []string{"172.20.0.0/16"}},
		{"172.20.0.0/16,10.0.0.0/8", []string{"172.20.0.0/16", "10.0.0.0/8"}},
		{"a,,b", []string{"a", "b"}},
	}
	for _, tt := range tests {
		got := parseCSV(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseCSV(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseCSV(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestJoinCSV(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b", "c"}, "a,b,c"},
	}
	for _, tt := range tests {
		got := joinCSV(tt.input)
		if got != tt.want {
			t.Errorf("joinCSV(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestToSet(t *testing.T) {
	s := toSet([]string{"a", "b", "c"})
	if !s["a"] || !s["b"] || !s["c"] || s["d"] {
		t.Errorf("toSet unexpected: %v", s)
	}
}

func TestSliceEqual(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a", "b"}, []string{"a"}, false},
	}
	for _, tt := range tests {
		if got := sliceEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("sliceEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
