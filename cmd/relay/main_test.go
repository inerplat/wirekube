package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsMuxServesRelayMetricsAndHealth(t *testing.T) {
	srv := httptest.NewServer(newMetricsMux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", resp.StatusCode)
	}
	var body strings.Builder
	buf := make([]byte, 64*1024)
	for {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	// The relay package registers its collectors at init; the unlabelled
	// gauge and counter are present even with no clients connected.
	for _, want := range []string{"wirekube_relay_clients", "wirekube_relay_frames_dropped_unknown_dest_total"} {
		if !strings.Contains(body.String(), want) {
			t.Errorf("/metrics missing %s", want)
		}
	}
}

// The manifests disable the metrics endpoint by setting the variable to an
// empty string, which only works if an explicitly empty value beats the flag
// default. An unset variable must leave the flag alone.
func TestResolveMetricsAddr(t *testing.T) {
	cases := []struct {
		name    string
		flagVal string
		env     map[string]string
		want    string
	}{
		{"unset keeps the flag default", ":9091", nil, ":9091"},
		{"empty disables", ":9091", map[string]string{"WIREKUBE_RELAY_METRICS_ADDR": ""}, ""},
		{"set overrides", ":9091", map[string]string{"WIREKUBE_RELAY_METRICS_ADDR": "127.0.0.1:9999"}, "127.0.0.1:9999"},
		{"unset keeps a non-default flag", "127.0.0.1:1234", nil, "127.0.0.1:1234"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(k string) (string, bool) {
				v, ok := tc.env[k]
				return v, ok
			}
			if got := resolveMetricsAddr(tc.flagVal, lookup); got != tc.want {
				t.Fatalf("resolveMetricsAddr(%q) = %q, want %q", tc.flagVal, got, tc.want)
			}
		})
	}
}
