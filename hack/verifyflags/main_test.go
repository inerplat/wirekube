package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitImage(t *testing.T) {
	tests := []struct {
		name  string
		image string
		repo  string
		ref   string
		ok    bool
	}{
		{"tag", "inerplat/wirekube:v0.0.16", "inerplat/wirekube", "v0.0.16", true},
		{"mutable tag", "inerplat/wirekube:latest", "inerplat/wirekube", "latest", true},
		{
			"digest",
			"inerplat/wirekube@sha256:9a74bdd6000000000000000000000000000000000000000000000000000000aa",
			"inerplat/wirekube",
			"sha256:9a74bdd6000000000000000000000000000000000000000000000000000000aa",
			true,
		},
		{"registry port", "registry.example.com:5000/inerplat/wirekube:v1", "registry.example.com:5000/inerplat/wirekube", "v1", true},
		{"registry port no tag", "registry.example.com:5000/inerplat/wirekube", "", "", false},
		{"no tag", "inerplat/wirekube", "", "", false},
		{"empty tag", "inerplat/wirekube:", "inerplat/wirekube", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, ref, ok := splitImage(tt.image)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if repo != tt.repo || ref != tt.ref {
				t.Errorf("got (%q, %q), want (%q, %q)", repo, ref, tt.repo, tt.ref)
			}
		})
	}
}

// TestCollectNesting pins the workload kinds the tool must see through. A kind
// missing from manifest yields no output at all rather than an error, so the
// coverage has to be asserted directly.
func TestCollectNesting(t *testing.T) {
	const doc = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dep
spec:
  template:
    spec:
      initContainers:
        - name: dep-init
          image: inerplat/wirekube:v1
          command: ["wirekube-agent"]
      containers:
        - name: dep-main
          image: inerplat/wirekube:v1
          command: ["wirekube-relay"]
---
apiVersion: v1
kind: Pod
metadata:
  name: bare
spec:
  containers:
    - name: bare-main
      image: inerplat/wirekube:v1
      command: ["wirekube-agent"]
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cron
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: cron-main
              image: inerplat/wirekube:v1
              command: ["wirekube-agent"]
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: no-command
spec:
  template:
    spec:
      containers:
        - name: entrypoint-default
          image: inerplat/wirekube:v1
          args: ["--node-name=n"]
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: mutable
spec:
  template:
    spec:
      containers:
        - name: mutable-main
          image: inerplat/wirekube:latest
          command: ["wirekube-agent"]
---
apiVersion: v1
kind: Pod
metadata:
  name: other-repo
spec:
  containers:
    - name: sidecar
      image: alpine:3.21
      command: ["sh"]
`

	dir := t.TempDir()
	path := filepath.Join(dir, "manifests.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, skipped, err := collect(path)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	got := map[string]bool{}
	for _, tg := range targets {
		got[tg.container.Name] = true
	}
	// entrypoint-default has no command: the image ENTRYPOINT supplies it,
	// so it is checkable and must not be dropped.
	want := []string{"dep-init", "dep-main", "bare-main", "cron-main", "entrypoint-default"}
	for _, name := range want {
		if !got[name] {
			t.Errorf("container %q not collected", name)
		}
	}
	if len(targets) != len(want) {
		t.Errorf("collected %d containers, want %d: %v", len(targets), len(want), got)
	}

	// The mutable tag is skipped out loud; the foreign image is not ours to
	// report on at all.
	if len(skipped) != 1 {
		t.Fatalf("skipped = %v, want exactly the mutable tag", skipped)
	}
	if !strings.Contains(skipped[0], "mutable-main") || !strings.Contains(skipped[0], "mutable tag") {
		t.Errorf("skip line %q does not name the container and reason", skipped[0])
	}
}

func TestMatchLine(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		needles []string
		want    string
	}{
		{
			"go flag package",
			"some log\nflag provided but not defined: -relay-id\nUsage of x:",
			undefinedFlagMarkers,
			"flag provided but not defined: -relay-id",
		},
		{
			"pflag",
			"Error: unknown flag: --cluster-kube",
			undefinedFlagMarkers,
			"Error: unknown flag: --cluster-kube",
		},
		{"no match", "Usage of wirekube-relay:", undefinedFlagMarkers, ""},
		{
			"registry miss",
			"Error response from daemon: manifest unknown",
			unavailableMarkers,
			"Error response from daemon: manifest unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchLine(tt.out, tt.needles); got != tt.want {
				t.Errorf("matchLine = %q, want %q", got, tt.want)
			}
		})
	}
}
