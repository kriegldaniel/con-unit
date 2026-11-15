package engine_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
)

// probeScript emulates the container CLI with files in $FAKE_DIR:
//
//	baseline.seq and treatment.seq hold one "<status> <exitcode>" line per
//	`container inspect` call, the last line is sticky. A run whose arguments
//	contain $FAKE_TREATMENT_MARKER uses treatment.seq, any other run uses
//	baseline.seq. after-kill.seq replaces the sequence once `kill` is called.
//	run.exit (optional) makes `run` fail with that exit code and run.out.
//	logs.txt is printed by `logs`.
const probeScript = `
D="$FAKE_DIR"
log() { printf '%s\n' "$*" >> "$D/calls.log"; }
case "$1" in
  --version) echo "podman version 5.0.0"; exit 0 ;;
  run)
    log "$*"
    name=""; prev=""
    for a in "$@"; do if [ "$prev" = "--name" ]; then name="$a"; fi; prev="$a"; done
    seq="$D/baseline.seq"
    if [ -n "$FAKE_TREATMENT_MARKER" ]; then
      case "$*" in *"$FAKE_TREATMENT_MARKER"*) seq="$D/treatment.seq" ;; esac
    fi
    if [ -f "$D/run.exit" ]; then
      cat "$D/run.out" >&2
      exit "$(cat "$D/run.exit")"
    fi
    cp "$seq" "$D/$name.seq"
    echo 0 > "$D/$name.n"
    echo "0123456789abcdef"
    exit 0 ;;
  container)
    log "$*"
    if [ -f "$D/inspect.exit" ]; then echo "inspect failed" >&2; exit "$(cat "$D/inspect.exit")"; fi
    name="$5"
    n=$(cat "$D/$name.n"); n=$((n+1)); echo $n > "$D/$name.n"
    line=$(sed -n "${n}p" "$D/$name.seq")
    if [ -z "$line" ]; then line=$(tail -n 1 "$D/$name.seq"); fi
    if [ -f "$D/inspect.warn" ]; then cat "$D/inspect.warn" >&2; fi
    echo "$line"
    exit 0 ;;
  logs) log "$*"; cat "$D/logs.txt" 2>/dev/null; exit 0 ;;
  rm) log "$*"; exit 0 ;;
  kill)
    log "$*"
    name="$3"
    if [ -f "$D/kill.exit" ]; then echo "kill failed" >&2; exit "$(cat "$D/kill.exit")"; fi
    if [ -f "$D/after-kill.seq" ]; then cp "$D/after-kill.seq" "$D/$name.seq"; echo 0 > "$D/$name.n"; fi
    exit 0 ;;
esac
log "unexpected $*"
exit 99
`

type probeFake struct {
	t   *testing.T
	dir string
	eng *engine.Engine
}

func newProbeFake(t *testing.T, binaryName string) *probeFake {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FAKE_DIR", dir)
	t.Setenv("FAKE_TREATMENT_MARKER", "")
	f := &probeFake{t: t, dir: dir}
	path := filepath.Join(dir, binaryName)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+probeScript), 0o700); err != nil {
		t.Fatal(err)
	}
	f.eng = &engine.Engine{BinaryPath: path}
	return f
}

func (f *probeFake) write(name string, lines ...string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *probeFake) calls() string {
	data, _ := os.ReadFile(filepath.Join(f.dir, "calls.log"))
	return string(data)
}

func (f *probeFake) callsStarting(prefix string) []string {
	var matched []string
	for _, line := range strings.Split(f.calls(), "\n") {
		if strings.HasPrefix(line, prefix) {
			matched = append(matched, line)
		}
	}
	return matched
}

const testWindow = 300 * time.Millisecond

func intValue(t *testing.T, p *int) int {
	t.Helper()
	if p == nil {
		t.Fatal("expected an exit code, got none")
	}
	return *p
}

func TestObserveContainerRunningAtTheEndOfTheWindow(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "running 0")
	started := time.Now()
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
	if err != nil {
		t.Fatalf("ObserveContainer: %v", err)
	}
	if obs.State != engine.StateRunning || obs.ExitCode != nil || obs.LogTail != "" {
		t.Errorf("observation = %+v, want a running container without exit code or log tail", obs)
	}
	if elapsed := time.Since(started); elapsed < testWindow {
		t.Errorf("a running container must be observed for the whole window, decided after %s", elapsed)
	}
	if len(f.callsStarting("logs")) != 0 {
		t.Error("the log tail is only collected for containers that are not running")
	}
	if rm := f.callsStarting("rm"); len(rm) != 1 || !strings.HasPrefix(rm[0], "rm -f -t 0 con-unit-probe-") {
		t.Errorf("the probe container must be force removed without a stop timeout, got %v", rm)
	}
}

func TestObserveContainerRunArgumentsAreTheBaselineProfile(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "running 0")
	if _, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", engine.ReadOnlyRootfsFlags(), testWindow); err != nil {
		t.Fatal(err)
	}
	run := f.callsStarting("run")
	if len(run) != 1 {
		t.Fatalf("run calls = %v", run)
	}
	for _, want := range []string{"run -d --name con-unit-probe-", "--network=none", "--pids-limit=256", "-e POSTGRES_PASSWORD=conunit_test_password", "-e ARANGO_NO_AUTH=1", "--read-only", "--tmpfs /tmp:rw,nosuid,size=65536k", " -- sha256:abc"} {
		if !strings.Contains(run[0], want) {
			t.Errorf("run arguments lack %q:\n%s", want, run[0])
		}
	}
	if strings.Contains(run[0], "--entrypoint") {
		t.Errorf("contract probes run the image's own entrypoint and must not override it:\n%s", run[0])
	}
	if strings.Contains(run[0], "noexec") {
		t.Errorf("the read-only treatment must not add a noexec restriction on /tmp:\n%s", run[0])
	}
	if strings.Index(run[0], "--read-only") > strings.Index(run[0], " -- ") {
		t.Errorf("treatment flags must precede the image separator:\n%s", run[0])
	}
}

func TestObserveContainerDecidesAtTheEndNotAtTheFirstPoll(t *testing.T) {
	f := newProbeFake(t, "podman")
	// Running at the first polls, dead before the window ends.
	f.write("baseline.seq", "created 0", "running 0", "running 0", "exited 7")
	f.write("logs.txt", "starting up", "fatal: cannot write /var/lib/app: Read-only file system")
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, 2*time.Second)
	if err != nil {
		t.Fatalf("ObserveContainer: %v", err)
	}
	if obs.State != engine.StateExitedNonZero || intValue(t, obs.ExitCode) != 7 {
		t.Fatalf("observation = %+v, want exited_nonzero with code 7", obs)
	}
	if !strings.Contains(obs.LogTail, "Read-only file system") {
		t.Errorf("log tail = %q", obs.LogTail)
	}
	if obs.Elapsed >= 2*time.Second {
		t.Errorf("an exit is final and must be reported without waiting for the rest of the window, took %s", obs.Elapsed)
	}
	if logs := f.callsStarting("logs"); len(logs) != 1 || !strings.Contains(logs[0], "--tail=50") {
		t.Errorf("logs calls = %v, want one call with --tail=50", logs)
	}
}

// podmanVolumeWarning is the line that Podman 4.9 writes to stderr of
// `container inspect` when a tmpfs destination is a symlink in the image
// (alpine: /var/run -> /run). It made the container state unparseable on the
// evaluation host while the same tool ran fine on Podman 5.
const podmanVolumeWarning = `time="2026-11-15T20:46:26Z" level=warning msg="Could not find mount at destination \"/var/run\" when parsing user volumes for container d222f0b010b7"`

func TestObserveContainerIgnoresEngineWarningsOnStderr(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("inspect.warn", podmanVolumeWarning)
	f.write("baseline.seq", "running 0")
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", engine.ReadOnlyRootfsFlags(), testWindow)
	if err != nil {
		t.Fatalf("a warning on stderr must not break the state read: %v", err)
	}
	if obs.State != engine.StateRunning {
		t.Errorf("observation = %+v, want running", obs)
	}
}

func TestObserveContainerExitedWithAWarningOnStderr(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("inspect.warn", podmanVolumeWarning)
	f.write("baseline.seq", "exited 7")
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, 5*time.Second)
	if err != nil {
		t.Fatalf("a warning on stderr must not break the state read: %v", err)
	}
	if obs.State != engine.StateExitedNonZero || intValue(t, obs.ExitCode) != 7 {
		t.Errorf("observation = %+v, want exited_nonzero with code 7", obs)
	}
}

func TestObserveContainerExitZeroIsReportedAsSuch(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "exited 0")
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if obs.State != engine.StateExitedZero || intValue(t, obs.ExitCode) != 0 {
		t.Fatalf("observation = %+v, want exited0", obs)
	}
	if obs.Elapsed > time.Second {
		t.Errorf("an early exit must not wait for the window, took %s", obs.Elapsed)
	}
}

func TestObserveContainerStartFailure(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "running 0")
	f.write("run.exit", "126")
	f.write("run.out", "Error: crun: executable file `/entrypoint.sh` not found: No such file or directory")
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
	if err != nil {
		t.Fatalf("a container that cannot start is a result, not an error: %v", err)
	}
	if obs.State != engine.StateStartFailed || intValue(t, obs.ExitCode) != 126 {
		t.Fatalf("observation = %+v, want start_failed with exit code 126", obs)
	}
	if !strings.Contains(obs.LogTail, "executable file") {
		t.Errorf("the engine output must be kept as evidence, got %q", obs.LogTail)
	}
	if len(f.callsStarting("container")) != 0 {
		t.Error("no state may be inspected for a container that never started")
	}
	if len(f.callsStarting("rm")) != 1 {
		t.Errorf("a failed run can leave a created container behind, so cleanup must still run: %v", f.callsStarting("rm"))
	}
}

func TestObserveContainerNeverReachingAnObservableStateIsATimeout(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "created 0")
	_, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
	var timeout *engine.ProbeTimeoutError
	if !errors.As(err, &timeout) || !strings.Contains(timeout.LastState, "created") {
		t.Fatalf("error = %v, want a *engine.ProbeTimeoutError naming the last state", err)
	}
	if len(f.callsStarting("rm")) != 1 {
		t.Errorf("cleanup must run after a timeout: %v", f.callsStarting("rm"))
	}
}

func TestObserveContainerEngineFailuresAreProbeErrors(t *testing.T) {
	t.Run("inspect command fails", func(t *testing.T) {
		f := newProbeFake(t, "podman")
		f.write("baseline.seq", "running 0")
		f.write("inspect.exit", "17")
		_, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
		var probeErr *engine.ProbeError
		if !errors.As(err, &probeErr) {
			t.Fatalf("error = %v, want *engine.ProbeError", err)
		}
		if len(f.callsStarting("rm")) != 1 {
			t.Error("cleanup must run after an inspect failure")
		}
	})
	for _, bad := range []string{"unknown", "running invalid", "running -1", "running 0 extra"} {
		t.Run("unparseable "+bad, func(t *testing.T) {
			f := newProbeFake(t, "podman")
			f.write("baseline.seq", bad)
			_, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
			var probeErr *engine.ProbeError
			if !errors.As(err, &probeErr) {
				t.Fatalf("error = %v, want *engine.ProbeError", err)
			}
		})
	}
	t.Run("missing engine binary", func(t *testing.T) {
		eng := &engine.Engine{BinaryPath: filepath.Join(t.TempDir(), "missing-engine")}
		_, err := eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
		var probeErr *engine.ProbeError
		if !errors.As(err, &probeErr) {
			t.Fatalf("error = %v, want *engine.ProbeError", err)
		}
	})
	t.Run("flag-like image reference", func(t *testing.T) {
		f := newProbeFake(t, "podman")
		_, err := f.eng.ObserveContainer(context.Background(), "--privileged", nil, testWindow)
		var probeErr *engine.ProbeError
		if !errors.As(err, &probeErr) || len(f.callsStarting("run")) != 0 {
			t.Fatalf("error = %v, run calls = %v; an unsafe reference must be rejected before any engine call", err, f.callsStarting("run"))
		}
	})
}

func TestObserveContainerContextDeadlineIsATimeoutAndCleanupStillRuns(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "running 0")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := f.eng.ObserveContainer(ctx, "sha256:abc", nil, 5*time.Second)
	var timeout *engine.ProbeTimeoutError
	if !errors.As(err, &timeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want a *engine.ProbeTimeoutError wrapping the deadline", err)
	}
	if len(f.callsStarting("rm")) != 1 {
		t.Errorf("cleanup runs with its own bounded context after the caller's context ended: %v", f.callsStarting("rm"))
	}
}

func TestLogTailKeepsTheLastFiftyLines(t *testing.T) {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", "exited 1")
	var lines []string
	for i := 1; i <= 120; i++ {
		lines = append(lines, fmt.Sprintf("line %03d", i))
	}
	f.write("logs.txt", lines...)
	obs, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(obs.LogTail, "\n")
	if len(got) != 50 || got[0] != "line 071" || got[49] != "line 120" {
		t.Fatalf("log tail has %d lines from %q to %q, want the last 50 (071 to 120)", len(got), got[0], got[len(got)-1])
	}
}

func TestDockerCleanupHasNoStopTimeoutFlag(t *testing.T) {
	f := newProbeFake(t, "docker")
	f.write("baseline.seq", "running 0")
	if _, err := f.eng.ObserveContainer(context.Background(), "sha256:abc", nil, testWindow); err != nil {
		t.Fatal(err)
	}
	rm := f.callsStarting("rm")
	if len(rm) != 1 || strings.Contains(rm[0], "-t") || !strings.HasPrefix(rm[0], "rm -f con-unit-probe-") {
		t.Errorf("docker rm has no -t flag, got %v", rm)
	}
}

func TestTreatmentFlagHelpers(t *testing.T) {
	if got := strings.Join(engine.MemoryLimitFlags("256m", 0), " "); got != "--memory=256m" {
		t.Errorf("memory flags = %q, the baseline PID limit must stay in force", got)
	}
	if got := strings.Join(engine.MemoryLimitFlags("256m", 100), " "); got != "--memory=256m --pids-limit=100" {
		t.Errorf("memory and pids flags = %q", got)
	}
	if got := strings.Join(engine.UserFlags(0), " "); got != "--user 10001:10001" {
		t.Errorf("default user flags = %q", got)
	}
	pss := strings.Join(engine.PSSRestrictedFlags(), " ")
	for _, want := range []string{"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--user 10001:10001"} {
		if !strings.Contains(pss, want) {
			t.Errorf("PSS flags %q lack %q", pss, want)
		}
	}
}

func sigtermFake(t *testing.T, before string, afterKill string) *probeFake {
	f := newProbeFake(t, "podman")
	f.write("baseline.seq", before)
	if afterKill != "" {
		f.write("after-kill.seq", afterKill)
	}
	return f
}

func TestObserveSigterm(t *testing.T) {
	t.Run("clean exit with code 0", func(t *testing.T) {
		f := sigtermFake(t, "running 0", "exited 0")
		obs, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", testWindow, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !obs.TerminatedBySigterm() || intValue(t, obs.ExitCode) != 0 || obs.Before.State != engine.StateRunning {
			t.Errorf("observation = %+v", obs)
		}
		kill := f.callsStarting("kill")
		if len(kill) != 1 || !strings.HasPrefix(kill[0], "kill --signal=SIGTERM con-unit-sigterm-") {
			t.Errorf("SIGTERM must be sent directly with kill, got %v", kill)
		}
	})
	t.Run("exit code 143 counts as terminated by SIGTERM", func(t *testing.T) {
		f := sigtermFake(t, "running 0", "exited 143")
		obs, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", testWindow, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !obs.TerminatedBySigterm() || intValue(t, obs.ExitCode) != 143 {
			t.Errorf("observation = %+v, want terminated with 143", obs)
		}
	})
	t.Run("other exit code is not a clean termination", func(t *testing.T) {
		f := sigtermFake(t, "running 0", "exited 137")
		f.write("logs.txt", "killed")
		obs, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", testWindow, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if obs.TerminatedBySigterm() || !obs.Exited || intValue(t, obs.ExitCode) != 137 || obs.LogTail == "" {
			t.Errorf("observation = %+v, want an exit with code 137 and a log tail", obs)
		}
	})
	t.Run("container that ignores the signal keeps running until the timeout", func(t *testing.T) {
		f := sigtermFake(t, "running 0", "running 0")
		obs, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", testWindow, 300*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if obs.TerminatedBySigterm() || obs.Exited || !obs.Sent || obs.Elapsed < 300*time.Millisecond {
			t.Errorf("observation = %+v, want a signal sent and no exit within the timeout", obs)
		}
	})
	t.Run("a container not running at the end of the window is never signalled", func(t *testing.T) {
		f := sigtermFake(t, "exited 0", "")
		obs, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", 5*time.Second, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if obs.Sent || obs.Before.State != engine.StateExitedZero {
			t.Errorf("observation = %+v", obs)
		}
		if len(f.callsStarting("kill")) != 0 {
			t.Error("kill must not run when no running state was observed")
		}
	})
	t.Run("signal delivery failure is a probe error", func(t *testing.T) {
		f := sigtermFake(t, "running 0", "exited 0")
		f.write("kill.exit", "17")
		_, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", testWindow, time.Second)
		var probeErr *engine.ProbeError
		if !errors.As(err, &probeErr) {
			t.Fatalf("error = %v, want *engine.ProbeError", err)
		}
		if len(f.callsStarting("rm")) != 1 {
			t.Error("cleanup must run after a failed signal")
		}
	})
	t.Run("start failure", func(t *testing.T) {
		f := sigtermFake(t, "running 0", "")
		f.write("run.exit", "125")
		f.write("run.out", "Error: cannot start")
		obs, err := f.eng.ObserveSigterm(context.Background(), "sha256:abc", testWindow, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if obs.Before.State != engine.StateStartFailed || obs.Sent {
			t.Errorf("observation = %+v", obs)
		}
	})
}

func TestObserveContainerAgainstARealEngine(t *testing.T) {
	if os.Getenv("CONUNIT_INTEGRATION") != "1" {
		t.Skip("set CONUNIT_INTEGRATION=1 to run container-engine integration tests")
	}
	eng, err := engine.DetectEngine("auto")
	if err != nil {
		t.Skip("no container engine available")
	}
	ctx := context.Background()
	const image = "alpine:latest"
	if err := eng.EnsureImage(ctx, image); err != nil {
		t.Fatalf("EnsureImage: %v", err)
	}
	// alpine's default command is a shell that exits at once with code 0, the
	// typical image whose behavior cannot be observed over a window.
	obs, err := eng.ObserveContainer(ctx, image, nil, 2*time.Second)
	if err != nil {
		t.Fatalf("ObserveContainer: %v", err)
	}
	if obs.State != engine.StateExitedZero {
		t.Errorf("alpine baseline state = %q, want %q", obs.State, engine.StateExitedZero)
	}
}
