package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubEngine writes a shell script that behaves like a minimal container
// engine. It logs its arguments and answers from environment variables, so the
// production EngineRunner can be tested without any container engine.
func stubEngine(t *testing.T) (binary, logFile string) {
	t.Helper()
	dir := t.TempDir()
	logFile = filepath.Join(dir, "calls.log")
	script := `#!/usr/bin/env bash
echo "$@" >> "$STUB_LOG"
case "$1" in
  run)
    if [ "$STUB_RUN" = fail ]; then echo "Error: crun: no such file" >&2; exit 126; fi
    echo "0123456789abcdef"
    ;;
  container)
    if [ -n "$STUB_INSPECT_WARN" ]; then echo "$STUB_INSPECT_WARN" >&2; fi
    cat "$STUB_STATE_FILE"
    ;;
  logs)
    echo "first line"
    echo "chown: /data: Operation not permitted"
    ;;
  rm) ;;
  image)
    [ "$STUB_IMAGE" = absent ] && exit 1
    echo "sha256:abc"
    ;;
  pull)
    if [ "$STUB_PULL" = fail ]; then echo "manifest unknown" >&2; exit 1; fi
    ;;
esac
exit 0
`
	binary = filepath.Join(dir, "engine")
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_LOG", logFile)
	state := filepath.Join(dir, "state")
	t.Setenv("STUB_STATE_FILE", state)
	return binary, logFile
}

func setState(t *testing.T, s string) {
	t.Helper()
	if err := os.WriteFile(os.Getenv("STUB_STATE_FILE"), []byte(s+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readCalls(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestEngineRunnerRunningContainerSurvivesTheWindow(t *testing.T) {
	bin, logFile := stubEngine(t)
	setState(t, "running 0")
	r := &EngineRunner{Binary: bin, Poll: 10 * time.Millisecond}
	start := time.Now()
	obs := r.Observe(context.Background(), RunSpec{Image: "img:1", Flags: fullFlags("--cap-drop=ALL"), Window: 120 * time.Millisecond})
	if !obs.Survived() || obs.State != StateRunning {
		t.Fatalf("observation = %+v", obs)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Error("the container must be observed for the whole window")
	}
	calls := readCalls(t, logFile)
	if !strings.HasPrefix(calls[0], "run -d --name con-unit-attr-") {
		t.Fatalf("first call = %q", calls[0])
	}
	for _, want := range []string{"--network=none", "--pids-limit=256", "-e POSTGRES_PASSWORD=conunit_test_password", "--cap-drop=ALL", "-- img:1"} {
		if !strings.Contains(calls[0], want) {
			t.Errorf("run call lacks %q: %s", want, calls[0])
		}
	}
	if !strings.HasSuffix(calls[0], "-- img:1") {
		t.Errorf("the image must follow --: %s", calls[0])
	}
	last := calls[len(calls)-1]
	if !strings.HasPrefix(last, "rm -f -t 0 con-unit-attr-") {
		t.Errorf("the container must be removed at the end, last call = %q", last)
	}
	inspects := 0
	for _, c := range calls {
		if strings.HasPrefix(c, "container inspect -f {{.State.Status}} {{.State.ExitCode}} con-unit-attr-") {
			inspects++
		}
	}
	if inspects < 2 {
		t.Errorf("the state must be polled during the window, inspects = %d", inspects)
	}
}

func TestEngineRunnerExitedContainerReportsCodeAndLogs(t *testing.T) {
	bin, logFile := stubEngine(t)
	setState(t, "exited 1")
	r := &EngineRunner{Binary: bin, Poll: 10 * time.Millisecond}
	start := time.Now()
	obs := r.Observe(context.Background(), RunSpec{Image: "img", Flags: fullFlags(), Window: 5 * time.Second})
	if time.Since(start) > 2*time.Second {
		t.Error("an exited container must not wait for the end of the window")
	}
	if obs.State != StateExited || obs.ExitCode == nil || *obs.ExitCode != 1 || obs.Survived() {
		t.Fatalf("observation = %+v", obs)
	}
	if !strings.Contains(obs.LogTail, "Operation not permitted") {
		t.Errorf("log tail = %q", obs.LogTail)
	}
	calls := readCalls(t, logFile)
	if !strings.HasPrefix(calls[len(calls)-1], "rm -f -t 0") {
		t.Errorf("last call = %q", calls[len(calls)-1])
	}
}

func TestEngineRunnerExitZeroIsDistinguished(t *testing.T) {
	bin, _ := stubEngine(t)
	setState(t, "exited 0")
	r := &EngineRunner{Binary: bin, Poll: 10 * time.Millisecond}
	obs := r.Observe(context.Background(), RunSpec{Image: "img", Window: time.Second})
	if obs.State != StateExited || obs.ExitCode == nil || *obs.ExitCode != 0 {
		t.Errorf("observation = %+v", obs)
	}
}

func TestEngineRunnerStartFailure(t *testing.T) {
	bin, logFile := stubEngine(t)
	t.Setenv("STUB_RUN", "fail")
	r := &EngineRunner{Binary: bin}
	obs := r.Observe(context.Background(), RunSpec{Image: "img", Window: time.Second})
	if obs.State != StateStartFailed || !strings.Contains(obs.LogTail, "no such file") || obs.Survived() {
		t.Errorf("observation = %+v", obs)
	}
	calls := readCalls(t, logFile)
	if !strings.HasPrefix(calls[len(calls)-1], "rm -f") {
		t.Errorf("a container that failed to start must still be removed: %v", calls)
	}
}

func TestEngineRunnerUnparseableStateIsUnknown(t *testing.T) {
	bin, _ := stubEngine(t)
	setState(t, "garbage")
	r := &EngineRunner{Binary: bin, Poll: 10 * time.Millisecond}
	obs := r.Observe(context.Background(), RunSpec{Image: "img", Window: time.Second})
	if obs.State != StateUnknown || obs.Err == "" {
		t.Errorf("observation = %+v", obs)
	}
}

// Podman 4.9 writes this line to stderr of `container inspect` when a tmpfs
// destination is a symlink in the image (alpine: /var/run -> /run). It made
// the seeded case writes-outside-tmp end in an engine error on the evaluation
// host, while the same tool ran fine on Podman 5.
const podmanVolumeWarning = `time="2026-11-15T20:46:26Z" level=warning msg="Could not find mount at destination \"/var/run\" when parsing user volumes for container d222f0b010b7"`

func TestEngineRunnerIgnoresWarningsOnStderr(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		wantState   string
		wantExit    int
	}{
		{"running", "running 0", StateRunning, -1},
		{"exited", "exited 1", StateExited, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := stubEngine(t)
			setState(t, tc.state)
			t.Setenv("STUB_INSPECT_WARN", podmanVolumeWarning)
			r := &EngineRunner{Binary: bin, Poll: 10 * time.Millisecond}
			obs := r.Observe(context.Background(), RunSpec{Image: "img", Window: 120 * time.Millisecond})
			if obs.State != tc.wantState || obs.Err != "" {
				t.Fatalf("observation = %+v, want state %s without an engine error", obs, tc.wantState)
			}
			if tc.wantExit >= 0 && (obs.ExitCode == nil || *obs.ExitCode != tc.wantExit) {
				t.Errorf("exit code = %v, want %d", obs.ExitCode, tc.wantExit)
			}
		})
	}
}

func TestEngineRunnerImagePresentAndPull(t *testing.T) {
	bin, logFile := stubEngine(t)
	r := &EngineRunner{Binary: bin}
	ok, err := r.ImagePresent(context.Background(), "img")
	if err != nil || !ok {
		t.Fatalf("present = %t, err %v", ok, err)
	}
	t.Setenv("STUB_IMAGE", "absent")
	ok, err = r.ImagePresent(context.Background(), "img")
	if err != nil || ok {
		t.Fatalf("absent image: present = %t, err %v", ok, err)
	}
	if err := r.Pull(context.Background(), "img"); err != nil {
		t.Errorf("pull: %v", err)
	}
	t.Setenv("STUB_PULL", "fail")
	if err := r.Pull(context.Background(), "img"); err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Errorf("failed pull = %v", err)
	}
	calls := readCalls(t, logFile)
	if !strings.HasPrefix(calls[0], "image inspect --format {{.Id}} img") {
		t.Errorf("presence check = %q (image exists is podman only)", calls[0])
	}
}

func TestEngineRunnerEndToEndWithAttribution(t *testing.T) {
	// The engine always reports exited 1 for containers started with
	// --cap-drop, which the stub cannot tell apart, so the whole flow ends
	// with BASELINE_FAILED. The point is that the production runner plugs into
	// the algorithm and the engine is called with the profile.
	bin, logFile := stubEngine(t)
	setState(t, "exited 1")
	r := &EngineRunner{Binary: bin, Poll: 5 * time.Millisecond}
	a := attributeOne(context.Background(), r, Config{Window: time.Second}, Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusBaselineFailed || len(a.Attempts) != 1 {
		t.Errorf("attribution = %s with %d attempts", a.Status, len(a.Attempts))
	}
	calls := readCalls(t, logFile)
	if !strings.HasPrefix(calls[0], "image inspect") || !strings.HasPrefix(calls[1], "run -d --name") {
		t.Errorf("calls = %v", calls)
	}
}

func TestTailKeepsTheEndAtALineBoundary(t *testing.T) {
	long := strings.Repeat("a", 50) + "\n" + strings.Repeat("b", 50) + "\nlast"
	got := tail(long, 60)
	if !strings.HasSuffix(got, "last") || strings.HasPrefix(got, "a") || len(got) > 60 {
		t.Errorf("tail = %q", got)
	}
	if tail("short", 100) != "short" {
		t.Error("short text is kept")
	}
}
