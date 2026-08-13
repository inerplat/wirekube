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
//	go run ./hack/verifyflags -strict ...
//
// Each pinned container runs as `<command> <args...> --help`. Flag parsing
// happens before anything else in these binaries, and an undefined flag is
// reported before the parser reaches -help, so an unknown flag is
// distinguishable from a clean parse without starting the real workload.
//
// A pin can name a tag that does not exist yet: the commit that prepares a
// release pins the tag whose image the release itself will publish. Without
// -strict that is reported as PENDING and does not fail the run, which is
// what pre-merge CI wants. The release pipeline runs with -strict after the
// image is published, where an unresolvable pin is a genuine failure.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// imageRepo is the only image this tool knows how to introspect. Containers
// from other repositories are skipped rather than guessed at.
const imageRepo = "inerplat/wirekube"

const (
	// runTimeout bounds a single container. --help returns in well under a
	// second; anything near this bound means flag parsing never terminated.
	runTimeout = 60 * time.Second
	// pullTimeout covers a multi-arch manifest fetch on a cold runner.
	pullTimeout = 5 * time.Minute
	// pullAttempts absorbs Docker Hub rate limiting and transient DNS
	// failures, which would otherwise be indistinguishable from a bad pin.
	pullAttempts = 3
)

// undefinedFlagMarkers are what an argument parser prints when it is handed a
// flag it does not define. The first is the standard library's flag package;
// the others are pflag, which cobra binaries in this image use.
var undefinedFlagMarkers = []string{
	"flag provided but not defined",
	"unknown flag:",
	"unknown shorthand flag:",
}

// usageMarkers are what a parser prints once it reaches -help, which is only
// possible after every preceding argument parsed cleanly. Seeing one of these
// is the positive evidence this tool requires; absence is never treated as
// success.
var usageMarkers = []string{
	"Usage of ",
	"Usage:",
	"flag: help requested",
}

// unavailableMarkers identify a pin the registry cannot resolve, as opposed to
// a binary that rejected its arguments.
var unavailableMarkers = []string{
	"manifest unknown",
	"manifest for",
	"not found",
	"pull access denied",
	"repository does not exist",
	"unauthorized",
	"toomanyrequests",
	"rate limit",
}

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

type podTemplate struct {
	Spec podSpec `json:"spec"`
}

// manifest covers the bare pod spec of a Pod, the template every workload
// controller wraps one in, and the extra level of nesting a CronJob adds.
type manifest struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Containers     []container `json:"containers"`
		InitContainers []container `json:"initContainers"`
		Template       podTemplate `json:"template"`
		JobTemplate    struct {
			Spec struct {
				Template podTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

type target struct {
	source    string
	workload  string
	container container
}

type outcome int

const (
	outcomeOK outcome = iota
	outcomeFlagRejected
	outcomeUnavailable
	outcomeInconclusive
)

type result struct {
	outcome outcome
	detail  string
}

func main() {
	strict := flag.Bool("strict", false,
		"treat an unresolvable image pin as a failure instead of PENDING; use after the release publishes its image")
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "usage: verifyflags [-strict] <manifest.yaml|-> ...")
		os.Exit(2)
	}

	var targets []target
	for _, path := range paths {
		found, skipped, err := collect(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		// A silently skipped container is how a verifier quietly stops
		// verifying, so every skip is reported with its reason.
		for _, s := range skipped {
			fmt.Println("skip " + s)
		}
		targets = append(targets, found...)
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no checkable wirekube containers found; check the paths")
		os.Exit(1)
	}

	pullAll(targets)

	// The three failure modes are counted apart so the summary never blames
	// a registry outage on a binary that rejected its arguments.
	var rejected, missing, unknown, pending int
	for _, t := range targets {
		label := fmt.Sprintf("%s %s/%s (%s)", t.source, t.workload, t.container.Name, t.container.Image)
		r := verify(t.container)
		switch r.outcome {
		case outcomeOK:
			fmt.Printf("ok      %s\n", label)
		case outcomeFlagRejected:
			fmt.Printf("REJECT  %s\n        %s\n", label, r.detail)
			fmt.Printf("        the pinned image predates this flag; pin a newer release or drop the arg\n")
			rejected++
		case outcomeUnavailable:
			if *strict {
				fmt.Printf("MISSING %s\n        %s\n", label, r.detail)
				missing++
				continue
			}
			fmt.Printf("PENDING %s\n        %s\n", label, r.detail)
			fmt.Printf("        image not in the registry yet; the release that publishes it verifies with -strict\n")
			pending++
		case outcomeInconclusive:
			fmt.Printf("UNKNOWN %s\n        %s\n", label, r.detail)
			unknown++
		}
	}

	fmt.Printf("\n%d checked: %d rejected their args, %d unresolvable pins, %d inconclusive, %d pending\n",
		len(targets), rejected, missing, unknown, pending)
	if rejected+missing+unknown > 0 {
		os.Exit(1)
	}
}

// collect reads one YAML stream and returns the containers worth checking plus
// a description of every wirekube container it declined to check.
func collect(path string) (targets []target, skipped []string, err error) {
	var in io.Reader = os.Stdin
	source := "stdin"
	if path != "-" {
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil, nil, oerr
		}
		defer f.Close()
		in = f
		source = path
	}

	dec := k8syaml.NewYAMLOrJSONDecoder(in, 4096)
	for {
		var m manifest
		if derr := dec.Decode(&m); derr != nil {
			if errors.Is(derr, io.EOF) {
				break
			}
			return nil, nil, derr
		}

		workload := m.Kind + "/" + m.Metadata.Name
		for _, c := range m.containers() {
			repo, ref, ok := splitImage(c.Image)
			if !ok || repo != imageRepo {
				continue
			}
			// A mutable tag names whatever the registry holds right
			// now, so there is no fixed contract to check. The example
			// manifests use one deliberately.
			if ref == "latest" {
				skipped = append(skipped,
					fmt.Sprintf("%s %s/%s (%s): mutable tag", source, workload, c.Name, c.Image))
				continue
			}
			targets = append(targets, target{source: source, workload: workload, container: c})
		}
	}
	return targets, skipped, nil
}

// containers returns every container the manifest declares, at whichever depth
// its kind nests the pod spec.
func (m manifest) containers() []container {
	specs := []podSpec{
		{Containers: m.Spec.Containers, InitContainers: m.Spec.InitContainers},
		m.Spec.Template.Spec,
		m.Spec.JobTemplate.Spec.Template.Spec,
	}
	var all []container
	for _, s := range specs {
		all = append(all, s.Containers...)
		all = append(all, s.InitContainers...)
	}
	return all
}

// splitImage separates an image reference into repository and version, where
// the version is either a tag or a digest. A colon inside a registry host's
// port must not be mistaken for the tag separator, and a digest reference
// carries a colon of its own.
func splitImage(image string) (repo, ref string, ok bool) {
	if repo, digest, found := strings.Cut(image, "@"); found {
		return repo, digest, digest != ""
	}
	i := strings.LastIndex(image, ":")
	if i < 0 || i < strings.LastIndex(image, "/") {
		return image, "", false
	}
	return image[:i], image[i+1:], image[i+1:] != ""
}

// engine returns the container CLI to shell out to. CI has docker; a local
// checkout may only have podman.
func engine() string {
	if e := os.Getenv("CONTAINER_ENGINE"); e != "" {
		return e
	}
	return "docker"
}

// pullAll fetches each distinct image once, with retries. Doing this up front
// keeps a rate-limited or flaky registry from being reported as a binary that
// rejected its arguments.
func pullAll(targets []target) {
	seen := map[string]bool{}
	for _, t := range targets {
		if seen[t.container.Image] {
			continue
		}
		seen[t.container.Image] = true

		for attempt := 1; attempt <= pullAttempts; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), pullTimeout)
			out, err := exec.CommandContext(ctx, engine(), "pull", t.container.Image).CombinedOutput()
			cancel()
			if err == nil {
				break
			}
			// An image that genuinely is not there will not appear on a
			// retry, and saying so early keeps the log readable.
			if matchAny(string(out), unavailableMarkers) != "" {
				break
			}
			if attempt < pullAttempts {
				time.Sleep(time.Duration(attempt) * 2 * time.Second)
			}
		}
	}
}

// verify runs the container's own command and args against the pinned image,
// with -help appended so parsing terminates without starting the workload.
func verify(c container) result {
	// --help is only reached if every preceding argument parsed, so a clean
	// parse and a rejected flag are told apart by output alone. The sandbox
	// flags cost nothing here and keep manifest-controlled argv from
	// reaching the network or the runner's filesystem.
	run := []string{"run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL"}
	if len(c.Command) > 0 {
		run = append(run, "--entrypoint", c.Command[0])
	}
	run = append(run, c.Image)
	if len(c.Command) > 1 {
		run = append(run, c.Command[1:]...)
	}
	run = append(run, c.Args...)
	run = append(run, "--help")

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, engine(), run...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	// Help output goes to stderr under the flag package and to stdout under
	// cobra, so neither stream can be discarded.
	out := stdout.String() + "\n" + stderr.String()

	if line := matchLine(out, undefinedFlagMarkers); line != "" {
		return result{outcome: outcomeFlagRejected, detail: line}
	}
	if matchAny(out, usageMarkers) != "" {
		return result{outcome: outcomeOK}
	}
	if line := matchLine(out, unavailableMarkers); line != "" {
		return result{outcome: outcomeUnavailable, detail: line}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return result{
			outcome: outcomeInconclusive,
			detail:  fmt.Sprintf("no usage output after %s; flag parsing never terminated", runTimeout),
		}
	}
	// Reaching here means the run neither rejected a flag nor proved it
	// parsed one. Passing on that would let a container that never reached
	// --help count as verified.
	detail := fmt.Sprintf("could not confirm flag parsing (%s run: %v)", engine(), runErr)
	if trimmed := strings.TrimSpace(out); trimmed != "" {
		detail += "\n        " + firstLines(trimmed, 3)
	}
	return result{outcome: outcomeInconclusive, detail: detail}
}

func matchAny(out string, needles []string) string {
	for _, n := range needles {
		if strings.Contains(out, n) {
			return n
		}
	}
	return ""
}

func matchLine(out string, needles []string) string {
	for _, line := range strings.Split(out, "\n") {
		if matchAny(line, needles) != "" {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n        ")
}
