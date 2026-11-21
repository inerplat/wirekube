package agent

import "testing"

func TestRoamedDirectEndpoint(t *testing.T) {
	cases := []struct {
		name, recorded, actual, want string
	}{
		{"same address", "203.0.113.7:51822", "203.0.113.7:51822", ""},
		{"NAT rebound the port", "203.0.113.7:51822", "203.0.113.7:1071", "203.0.113.7:1071"},
		{"device has no endpoint", "203.0.113.7:51822", "", ""},
		{"relay synthetic", "203.0.113.7:51822", "127.0.0.1:40000", ""},
		{"different host is not a rebound", "203.0.113.7:51822", "198.51.100.9:51822", ""},
		{"port zero", "203.0.113.7:51822", "203.0.113.7:0", ""},
		{"nothing recorded", "", "203.0.113.7:1071", ""},
		{"unparseable actual", "203.0.113.7:51822", "not-an-endpoint", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := roamedDirectEndpoint(tc.recorded, tc.actual); got != tc.want {
				t.Fatalf("roamedDirectEndpoint(%q, %q) = %q, want %q", tc.recorded, tc.actual, got, tc.want)
			}
		})
	}
}
