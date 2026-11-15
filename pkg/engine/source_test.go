package engine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
)

func writeNamedEngine(t *testing.T, binaryName, script string) *engine.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), binaryName)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatalf("write fake %s: %v", binaryName, err)
	}
	return &engine.Engine{BinaryPath: path}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

// dockerScript behaves like the docker CLI: it has no `image exists`, answers
// `image inspect` with exit 1 and "No such image" for absent images and with a
// different message when the daemon is unreachable.
const dockerScript = `
log() { printf '%s\n' "$*" >> "$FAKE_CALL_LOG"; }
case "$1:$2" in
  image:exists)
    log "image exists $3"
    echo "docker: 'exists' is not a docker image command." >&2
    exit 1 ;;
  image:inspect)
    log "image inspect $*"
    case "$FAKE_DOCKER_STATE" in
      present) echo "sha256:abc"; exit 0 ;;
      absent) echo "Error response from daemon: No such image: x" >&2; exit 1 ;;
      down) echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1 ;;
    esac ;;
esac
case "$1" in
  pull) log "pull $*"; exit 0 ;;
esac
log "unexpected $*"
exit 99
`

func TestDockerHasNoImageExistsSoItFallsBackToInspect(t *testing.T) {
	cases := []struct {
		name       string
		state      string
		wantPulled bool
		wantPull   bool
		wantErr    bool
	}{
		{name: "present image is not pulled and not owned", state: "present"},
		{name: "absent image is pulled and owned", state: "absent", wantPulled: true, wantPull: true},
		{name: "unreachable daemon is an error, never a pull", state: "down", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			callLog := filepath.Join(t.TempDir(), "calls")
			t.Setenv("FAKE_CALL_LOG", callLog)
			t.Setenv("FAKE_DOCKER_STATE", tc.state)
			eng := writeNamedEngine(t, "docker", dockerScript)

			pulled, err := eng.EnsureImageForPlatform(context.Background(), "alpine:3", "linux/amd64")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, tc.wantErr)
			}
			if pulled != tc.wantPulled {
				t.Errorf("pulled = %t, want %t (the ownership flag must be accurate)", pulled, tc.wantPulled)
			}
			calls := readLog(t, callLog)
			if strings.Contains(calls, "image exists") {
				t.Errorf("docker has no `image exists` subcommand, calls:\n%s", calls)
			}
			if got := strings.Contains(calls, "pull --platform linux/amd64 alpine:3"); got != tc.wantPull {
				t.Errorf("pull with explicit platform called = %t, want %t, calls:\n%s", got, tc.wantPull, calls)
			}
		})
	}
}

func TestPullPassesPlatformOnlyWhenGiven(t *testing.T) {
	callLog := filepath.Join(t.TempDir(), "calls")
	t.Setenv("FAKE_CALL_LOG", callLog)
	eng := writeNamedEngine(t, "podman", `printf '%s\n' "$*" >> "$FAKE_CALL_LOG"; exit 0`)
	if err := eng.Pull(context.Background(), "alpine:3", "linux/arm64/v8"); err != nil {
		t.Fatal(err)
	}
	if err := eng.Pull(context.Background(), "alpine:3", ""); err != nil {
		t.Fatal(err)
	}
	calls := readLog(t, callLog)
	if !strings.Contains(calls, "pull --platform linux/arm64/v8 alpine:3\n") || !strings.Contains(calls, "pull alpine:3\n") {
		t.Errorf("unexpected pull invocations:\n%s", calls)
	}
}

func TestInspectPlatformFlagIsDockerOnlyAndFallsBack(t *testing.T) {
	const inspectJSON = `[{"Id":"sha256:abc","Os":"linux","Architecture":"amd64","RepoDigests":["docker.io/library/alpine@sha256:def"]}]`
	t.Run("podman has no --platform on image inspect", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls")
		t.Setenv("FAKE_CALL_LOG", callLog)
		eng := writeNamedEngine(t, "podman", `printf '%s\n' "$*" >> "$FAKE_CALL_LOG"; echo '`+inspectJSON+`'`)
		inspect, err := eng.InspectImageForPlatform(context.Background(), "alpine:3", "linux/amd64")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(readLog(t, callLog), "--platform") {
			t.Errorf("podman rejects --platform on image inspect:\n%s", readLog(t, callLog))
		}
		if len(inspect.RepoDigests) != 1 || inspect.RepoDigests[0] != "docker.io/library/alpine@sha256:def" {
			t.Errorf("RepoDigests not parsed from inspect output: %+v", inspect.RepoDigests)
		}
	})
	t.Run("docker gets --platform", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls")
		t.Setenv("FAKE_CALL_LOG", callLog)
		eng := writeNamedEngine(t, "docker", `printf '%s\n' "$*" >> "$FAKE_CALL_LOG"; echo '`+inspectJSON+`'`)
		if _, err := eng.InspectImageForPlatform(context.Background(), "alpine:3", "linux/amd64"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(readLog(t, callLog), "image inspect --platform linux/amd64 alpine:3") {
			t.Errorf("docker must receive --platform:\n%s", readLog(t, callLog))
		}
	})
	t.Run("an older docker that rejects the flag is retried without it", func(t *testing.T) {
		callLog := filepath.Join(t.TempDir(), "calls")
		t.Setenv("FAKE_CALL_LOG", callLog)
		eng := writeNamedEngine(t, "docker", `printf '%s\n' "$*" >> "$FAKE_CALL_LOG"
case "$*" in
  *--platform*) echo "unknown flag: --platform" >&2; exit 125 ;;
esac
echo '`+inspectJSON+`'`)
		if _, err := eng.InspectImageForPlatform(context.Background(), "alpine:3", "linux/amd64"); err != nil {
			t.Fatalf("inspect must retry without the unsupported flag: %v", err)
		}
	})
}

func TestSaveImageUsesEngineSpecificFormatAndVerifiesTheArchive(t *testing.T) {
	const script = `printf '%s\n' "$*" >> "$FAKE_CALL_LOG"
dest=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then dest="$2"; fi; shift; done
if [ "$FAKE_WRITE" = "yes" ]; then echo archive > "$dest"; fi
exit 0`
	for _, tc := range []struct {
		binary string
		want   string
		absent string
	}{
		{"podman", "save --format docker-archive -o ", ""},
		{"docker", "save -o ", "--format"},
	} {
		t.Run(tc.binary, func(t *testing.T) {
			callLog := filepath.Join(t.TempDir(), "calls")
			t.Setenv("FAKE_CALL_LOG", callLog)
			t.Setenv("FAKE_WRITE", "yes")
			eng := writeNamedEngine(t, tc.binary, script)
			dest := filepath.Join(t.TempDir(), "image.tar")
			if err := eng.SaveImage(context.Background(), "sha256:abc", dest); err != nil {
				t.Fatal(err)
			}
			calls := readLog(t, callLog)
			if !strings.Contains(calls, tc.want) || !strings.HasSuffix(strings.TrimSpace(calls), "sha256:abc") {
				t.Errorf("unexpected save invocation:\n%s", calls)
			}
			if tc.absent != "" && strings.Contains(calls, tc.absent) {
				t.Errorf("%s must not receive %s:\n%s", tc.binary, tc.absent, calls)
			}
		})
	}

	t.Run("success without an archive is an error", func(t *testing.T) {
		t.Setenv("FAKE_CALL_LOG", filepath.Join(t.TempDir(), "calls"))
		t.Setenv("FAKE_WRITE", "no")
		eng := writeNamedEngine(t, "podman", script)
		if err := eng.SaveImage(context.Background(), "sha256:abc", filepath.Join(t.TempDir(), "image.tar")); err == nil {
			t.Fatal("an engine that reports success but writes nothing must not be trusted")
		}
	})
	t.Run("rejects flag-like references", func(t *testing.T) {
		eng := writeNamedEngine(t, "podman", "exit 0")
		if err := eng.SaveImage(context.Background(), "--privileged", filepath.Join(t.TempDir(), "x.tar")); err == nil {
			t.Fatal("expected a security error")
		}
	})
}

func TestPullFailuresBecomeTypedErrorsAtTheEngineBoundary(t *testing.T) {
	pullFailing := func(t *testing.T, stderr string) *engine.Engine {
		t.Setenv("FAKE_STDERR", stderr)
		return writeNamedEngine(t, "podman", `
case "$1:$2" in image:exists) exit 1;; esac
if [ "$1" = "pull" ]; then printf '%s\n' "$FAKE_STDERR" >&2; exit 125; fi
exit 99`)
	}

	rateLimited := []struct {
		name   string
		stderr string
		after  time.Duration
	}{
		{"toomanyrequests", "Error: reading manifest 3 in docker.io/library/alpine: toomanyrequests: You have reached your pull rate limit.", 0},
		{"pull rate limit text", "Error: copying image: You have reached your pull rate limit. You may increase the limit by authenticating", 0},
		{"http 429", "Error: unexpected status code 429 Too Many Requests", 0},
		{"retry-after header text", "Error: toomanyrequests, Retry-After: 17", 17 * time.Second},
		{"try again in", "Error: too many requests, try again in 2 minutes", 2 * time.Minute},
	}
	for _, tc := range rateLimited {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pullFailing(t, tc.stderr).EnsureImageForPlatform(context.Background(), "alpine:3", "")
			var rate *engine.RateLimitError
			if !errors.As(err, &rate) {
				t.Fatalf("error = %v, want *engine.RateLimitError", err)
			}
			if rate.RetryAfter() != tc.after {
				t.Errorf("RetryAfter = %s, want %s", rate.RetryAfter(), tc.after)
			}
		})
	}

	for _, stderr := range []string{
		"Error: initializing source docker://nope:1: reading manifest 1 in docker.io/library/nope: manifest unknown",
		"Error: pull access denied, repository does not exist or may require authorization",
		"Error: name unknown: repository name not known to registry",
	} {
		_, err := pullFailing(t, stderr).EnsureImageForPlatform(context.Background(), "nope:1", "")
		var missing *engine.NotFoundError
		if !errors.As(err, &missing) {
			t.Errorf("stderr %q: error = %v, want *engine.NotFoundError", stderr, err)
		}
	}

	_, err := pullFailing(t, "Error: dial tcp: lookup registry: no such host").EnsureImageForPlatform(context.Background(), "alpine:3", "")
	var rate *engine.RateLimitError
	var missing *engine.NotFoundError
	if err == nil || errors.As(err, &rate) || errors.As(err, &missing) {
		t.Errorf("a network failure must stay an untyped error, got %v", err)
	}
}

func TestKilledPullReportsTheContextError(t *testing.T) {
	eng := writeNamedEngine(t, "podman", `
case "$1:$2" in image:exists) exit 1;; esac
exec sleep 5`)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := eng.EnsureImageForPlatform(ctx, "alpine:3", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want one wrapping context.DeadlineExceeded", err)
	}
}

func TestEngineKindDetection(t *testing.T) {
	cases := []struct {
		binary  string
		version string
		want    engine.Kind
	}{
		{"podman", "", engine.KindPodman},
		{"docker", "", engine.KindDocker},
		{"custom-engine", "echo 'podman version 5.2.0'", engine.KindPodman},
		{"custom-engine", "echo 'Docker version 27.0.1, build abc'", engine.KindDocker},
		{"custom-engine", "echo something else", engine.KindUnknown},
		{"custom-engine", "exit 3", engine.KindUnknown},
	}
	for _, tc := range cases {
		eng := writeNamedEngine(t, tc.binary, tc.version)
		if got := eng.Kind(); got != tc.want {
			t.Errorf("Kind(%s, %q) = %q, want %q", tc.binary, tc.version, got, tc.want)
		}
	}
}

func TestInspectNormalizationHelpers(t *testing.T) {
	inspect := &engine.ImageInspect{
		ID: "ABCDEF",
		RepoDigests: []string{
			"docker.io/library/alpine@sha256:AAA",
			"docker.io/library/alpine@sha256:bbb",
		},
	}
	if got := inspect.NormalizedID(); got != "sha256:abcdef" {
		t.Errorf("NormalizedID = %q", got)
	}
	set := inspect.RepoDigestSet()
	if _, ok := set["sha256:aaa"]; !ok || len(set) != 2 {
		t.Errorf("RepoDigestSet = %v", set)
	}
}
