// Command verifyflags checks that every wirekube image pinned in a manifest
// actually accepts the flags that manifest passes to it.
//
// Manifests and code move together in a feature commit, but an image tag can
// later be re-pinned to an older release on its own. When that happens the
// container starts, the Go flag parser rejects a flag the older binary never
// defined, and the pod CrashLoopBackOffs. Nothing else in CI notices, because
// the e2e suite overrides the image with the one it just built.
//
// Usage:
//
//	go run ./hack/verifyflags config/relay/deployment.yaml ...
//	helm template ... | go run ./hack/verifyflags -
//
// Each pinned container is run as `<command> <args...> --help`. The flag
// package reports an undefined flag before it reaches -help, so an unknown
// flag is distinguishable from a clean parse by stderr alone.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// imageRepo is the only image this tool knows how to introspect. Sidecars from
// other repositories are skipped rather than guessed at.
const imageRepo = "inerplat/wirekube"

// undefinedFlag is the fixed prefix the standard flag package writes to stderr
// for an unrecognised flag.
const undefinedFlag = "flag provided but not defined"

type container struct {
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	Command []string `json:"command"`
	Args    []string `json:"args"`
}

type podSpec struct {
	Containers     []container `json:"containers"`
	InitContainers []container `json:"initContainers"`
}

// manifest covers both the bare pod spec of a Pod and the nested one every
// workload controller wraps in a template.
type manifest struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Containers     []container `json:"containers"`
		InitContainers []container `json:"initContainers"`
		Template       struct {
			Spec podSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

type target struct {
	source    string
	workload  string
	container container
}

func main() {
	paths := os.Args[1:]
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: verifyflags <manifest.yaml|-> ...")
		os.Exit(2)
	}

	var targets []target
	for _, path := range paths {
		found, err := collect(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		targets = append(targets, found...)
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no pinned wirekube containers found; check the paths")
		os.Exit(1)
	}

	failed := 0
	for _, t := range targets {
		label := fmt.Sprintf("%s %s/%s (%s)", t.source, t.workload, t.container.Name, t.container.Image)
		if err := verify(t.container); err != nil {
			fmt.Printf("FAIL %s\n     %v\n", label, err)
			failed++
			continue
		}
		fmt.Printf("ok   %s\n", label)
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d of %d pinned containers reject their own manifest args\n", failed, len(targets))
		os.Exit(1)
	}
	fmt.Printf("\nall %d pinned containers accept their manifest args\n", len(targets))
}

// collect reads one YAML stream and returns every container worth checking.
func collect(path string) ([]target, error) {
	var in io.Reader = os.Stdin
	source := "stdin"
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		in = f
		source = path
	}

	var targets []target
	dec := k8syaml.NewYAMLOrJSONDecoder(in, 4096)
	for {
		var m manifest
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		workload := m.Kind + "/" + m.Metadata.Name
		all := append(append([]container{}, m.Spec.Containers...), m.Spec.InitContainers...)
		all = append(all, m.Spec.Template.Spec.Containers...)
		all = append(all, m.Spec.Template.Spec.InitContainers...)
		for _, c := range all {
			if !checkable(c) {
				continue
			}
			targets = append(targets, target{source: source, workload: workload, container: c})
		}
	}
	return targets, nil
}

// checkable reports whether a container is a wirekube container pinned to an
// immutable tag with an explicit command. A `latest` tag names whatever the
// registry currently holds, so there is no stable contract to verify; the
// example manifests use it deliberately.
func checkable(c container) bool {
	repo, tag, ok := strings.Cut(c.Image, ":")
	if !ok || repo != imageRepo || tag == "latest" {
		return false
	}
	return len(c.Command) > 0
}

// engine returns the container CLI to shell out to. CI has docker; a local
// checkout may only have podman.
func engine() string {
	if e := os.Getenv("CONTAINER_ENGINE"); e != "" {
		return e
	}
	return "docker"
}

// verify runs the container's own command and args against the pinned image.
func verify(c container) error {
	args := []string{"run", "--rm", "--entrypoint", c.Command[0], c.Image}
	args = append(args, c.Command[1:]...)
	args = append(args, c.Args...)
	args = append(args, "--help")

	cmd := exec.Command(engine(), args...)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// -help makes the flag package print usage and exit non-zero, so a
	// non-zero status on its own says nothing. Only the undefined-flag
	// message distinguishes a stale image from a healthy one.
	if line := findLine(stderr.String(), undefinedFlag); line != "" {
		return fmt.Errorf("%s\n     the pinned image predates this flag; release a newer tag or drop the arg", line)
	}
	if strings.Contains(stderr.String(), "flag: help requested") || strings.Contains(stderr.String(), "Usage of") {
		return nil
	}
	if runErr != nil {
		return fmt.Errorf("docker run failed: %v\n%s", runErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func findLine(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
