package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Observed container states, as recorded in spec.Evidence.
const (
	StateRunning       = "running"
	StateExitedZero    = "exited0"
	StateExitedNonZero = "exited_nonzero"
	StateStartFailed   = "start_failed"
)

const (
	// DefaultProbeWindow is the Tier 3 observation window W. Tier 3 latency
	// is bounded below by W by design, so it is not a performance result.
	DefaultProbeWindow = 3 * time.Second

	// LogTailLines is the number of container log lines kept as evidence.
	LogTailLines    = 50
	logTailMaxBytes = 16 * 1024

	probePollInterval   = 100 * time.Millisecond
	probeStartTimeout   = 60 * time.Second
	probeInspectTimeout = 10 * time.Second
	probeCleanupTimeout = 15 * time.Second
)

// probeMockEnv is the fixed mock environment given to every Tier 3 container so
// that database images start instead of exiting on missing credentials. It is
// part of the documented profile and identical for baseline and treatments.
var probeMockEnv = []string{
	"POSTGRES_PASSWORD=conunit_test_password",
	"POSTGRES_HOST_AUTH_METHOD=trust",
	"MYSQL_ROOT_PASSWORD=conunit_test_password",
	"MARIADB_ROOT_PASSWORD=conunit_test_password",
	"ARANGO_NO_AUTH=1",
}

// Observation is what was seen of one probe container at the end of the
// observation window (or earlier, when the container had already exited).
type Observation struct {
	// State is StateRunning, StateExitedZero, StateExitedNonZero or
	// StateStartFailed.
	State string
	// ExitCode is set for exited states and, when the engine reported one,
	// for a start failure.
	ExitCode *int
	// Window is the observation window that was applied.
	Window time.Duration
	// Elapsed is the time from container start until the state was decided.
	Elapsed time.Duration
	// LogTail is the last LogTailLines lines of the container log, collected
	// for every state except running. For a start failure it holds the
	// engine's own output.
	LogTail string
}

// ProbeTimeoutError means the engine did not reach an observable state in
// time: a command or the container start exceeded its bound, or the container
// was still being created when the window ended. Callers report PROBE_TIMEOUT.
type ProbeTimeoutError struct {
	Phase     string
	LastState string
	Err       error
}

func (e *ProbeTimeoutError) Error() string {
	msg := fmt.Sprintf("contract probe timed out during %s", e.Phase)
	if e.LastState != "" {
		msg += fmt.Sprintf(" (last observed: %s)", e.LastState)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ProbeTimeoutError) Unwrap() error { return e.Err }

// ProbeError means an engine invocation failed or produced output that could
// not be interpreted. Callers report PROBE_ERROR.
type ProbeError struct {
	Phase string
	Err   error
}

func (e *ProbeError) Error() string {
	return fmt.Sprintf("contract probe failed during %s: %v", e.Phase, e.Err)
}

func (e *ProbeError) Unwrap() error { return e.Err }

// Treatment flags. Each is added to the defensive flags and the mock
// environment of the baseline, so a treatment differs from its baseline by
// exactly these flags.

// ReadOnlyRootfsFlags makes the root filesystem read-only and provides a
// writable 64 MiB tmpfs at /tmp, the usual companion of a read-only root.
func ReadOnlyRootfsFlags() []string {
	return []string{"--read-only", "--tmpfs", "/tmp:rw,nosuid,size=65536k"}
}

// DropAllCapabilitiesFlags drops every Linux capability.
func DropAllCapabilitiesFlags() []string { return []string{"--cap-drop=ALL"} }

// NoNewPrivilegesFlags blocks gaining privileges through setuid binaries.
func NoNewPrivilegesFlags() []string { return []string{"--security-opt=no-new-privileges:true"} }

// MemoryLimitFlags limits memory. A pids value above zero also overrides the
// defensive PID limit; zero keeps the defensive limit of the baseline.
func MemoryLimitFlags(memory string, pids int) []string {
	flags := []string{fmt.Sprintf("--memory=%s", memory)}
	if pids > 0 {
		flags = append(flags, fmt.Sprintf("--pids-limit=%d", pids))
	}
	return flags
}

// UserFlags forces an arbitrary unprivileged UID and GID.
func UserFlags(uid int) []string {
	if uid <= 0 {
		uid = 10001
	}
	return []string{"--user", fmt.Sprintf("%d:%d", uid, uid)}
}

// PSSRestrictedFlags approximates the Kubernetes Pod Security Standard
// Restricted profile: read-only root, no capabilities, no new privileges and
// an arbitrary non-root UID.
func PSSRestrictedFlags() []string {
	flags := ReadOnlyRootfsFlags()
	flags = append(flags, DropAllCapabilitiesFlags()...)
	flags = append(flags, NoNewPrivilegesFlags()...)
	return append(flags, UserFlags(10001)...)
}

// probeContainer is a started probe container. The image's own entrypoint
// runs; no --entrypoint override is ever given to a contract probe.
type probeContainer struct {
	e     *Engine
	name  string
	start time.Time
}

// removeContainerArgs forcefully removes a container without waiting for the
// default stop timeout. Docker's `rm` has no -t flag, and `rm -f` already
// kills immediately there.
func (e *Engine) removeContainerArgs(ctx context.Context, name string) []string {
	if e.KindFor(ctx) == KindDocker {
		return []string{"rm", "-f", name}
	}
	return []string{"rm", "-f", "-t", "0", name}
}

// cleanupContainer removes the named container. It uses its own bounded
// context so cleanup still runs after the caller's context has ended, and it
// never fails the probe: a container that does not exist is not an error.
func (e *Engine) cleanupContainer(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), probeCleanupTimeout)
	defer cancel()
	_ = e.Command(ctx, e.removeContainerArgs(ctx, name)...).Run()
}

func (pc *probeContainer) cleanup() { pc.e.cleanupContainer(pc.name) }

func newProbeName(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, os.Getpid(), time.Now().UnixNano())
}

func (e *Engine) probeRunArgs(name string, flags []string, image string) []string {
	args := []string{"run", "-d", "--name", name}
	args = append(args, e.DefensiveRunFlags()...)
	for _, env := range probeMockEnv {
		args = append(args, "-e", env)
	}
	args = append(args, flags...)
	return append(args, "--", image)
}

// startProbeContainer starts a detached container. A container that cannot be
// started yields an Observation with StateStartFailed and no error: that is a
// property of the image under the given flags. A missing engine binary or an
// exceeded bound is an error.
func (e *Engine) startProbeContainer(ctx context.Context, prefix, image string, flags []string) (*probeContainer, *Observation, error) {
	if err := ValidateImageRef(image); err != nil {
		return nil, nil, &ProbeError{Phase: "validation", Err: err}
	}
	name := newProbeName(prefix)
	startCtx, cancel := context.WithTimeout(ctx, probeStartTimeout)
	defer cancel()
	out, err := e.Command(startCtx, e.probeRunArgs(name, flags, image)...).CombinedOutput()
	if err != nil {
		// A failed `run` may still have created the container.
		e.cleanupContainer(name)
		if startCtx.Err() != nil {
			return nil, nil, &ProbeTimeoutError{Phase: "container start", Err: startCtx.Err()}
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, nil, &ProbeError{Phase: "container start", Err: err}
		}
		code := exitErr.ExitCode()
		return nil, &Observation{
			State:    StateStartFailed,
			ExitCode: &code,
			LogTail:  tailLines(strings.TrimSpace(string(out)), LogTailLines),
		}, nil
	}
	return &probeContainer{e: e, name: name, start: time.Now()}, nil, nil
}

// inspectProbeState reads the state and exit code of the container.
func (pc *probeContainer) inspectState(ctx context.Context) (string, int, error) {
	inspectCtx, cancel := context.WithTimeout(ctx, probeInspectTimeout)
	defer cancel()
	// The state is read from stdout only. Engines write warnings to stderr that say
	// nothing about the state. Podman 4.9 reports a tmpfs destination that is a
	// symlink in the image (alpine: /var/run -> /run) with "Could not find mount at
	// destination", and merging that line into the answer made the state unparseable.
	cmd := pc.e.Command(inspectCtx, "container", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", pc.name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if inspectCtx.Err() != nil {
			return "", 0, &ProbeTimeoutError{Phase: "state inspection", Err: inspectCtx.Err()}
		}
		return "", 0, &ProbeError{Phase: "state inspection", Err: fmt.Errorf("%s (%w)", strings.TrimSpace(stderr.String()+stdout.String()), err)}
	}
	out := strings.TrimSpace(stdout.String())
	parts := strings.Fields(out)
	if len(parts) != 2 {
		return "", 0, &ProbeError{Phase: "state inspection", Err: fmt.Errorf("unparseable container state %q", out)}
	}
	code, parseErr := strconv.Atoi(parts[1])
	if parseErr != nil || code < 0 {
		return "", 0, &ProbeError{Phase: "state inspection", Err: fmt.Errorf("unparseable exit code %q in container state %q", parts[1], out)}
	}
	return parts[0], code, nil
}

func isTerminalState(status string) bool {
	switch status {
	case "exited", "dead", "stopped":
		return true
	}
	return false
}

// logTail returns the last LogTailLines lines of the container log. A failing
// log command yields an empty tail, never an error: the tail is evidence, and
// its absence must not change the outcome.
func (pc *probeContainer) logTail(ctx context.Context) string {
	logCtx, cancel := context.WithTimeout(ctx, probeInspectTimeout)
	defer cancel()
	out, err := pc.e.Command(logCtx, "logs", fmt.Sprintf("--tail=%d", LogTailLines), pc.name).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return tailLines(strings.TrimSpace(string(out)), LogTailLines)
}

// observe watches the container for the window and decides its state at the
// end of the window. A container that exits earlier is decided immediately,
// because an exit is final; a running container is decided only once the
// window has elapsed, never from the first poll.
func (pc *probeContainer) observe(ctx context.Context, window time.Duration) (*Observation, error) {
	deadline := pc.start.Add(window)
	last := "no state observed"
	finish := func(state string, code *int) *Observation {
		obs := &Observation{State: state, ExitCode: code, Window: window, Elapsed: time.Since(pc.start)}
		if state != StateRunning {
			obs.LogTail = pc.logTail(ctx)
		}
		return obs
	}
	for {
		wait := time.Until(deadline)
		if wait > probePollInterval {
			wait = probePollInterval
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, &ProbeTimeoutError{Phase: "observation window", LastState: last, Err: ctx.Err()}
			case <-timer.C:
			}
		}
		status, code, err := pc.inspectState(ctx)
		if err != nil {
			var timeout *ProbeTimeoutError
			if errors.As(err, &timeout) {
				timeout.LastState = last
			}
			return nil, err
		}
		last = fmt.Sprintf("%s (exit code %d)", status, code)
		switch {
		case isTerminalState(status):
			state := StateExitedNonZero
			if code == 0 {
				state = StateExitedZero
			}
			return finish(state, &code), nil
		case status == "running":
			if !time.Now().Before(deadline) {
				return finish(StateRunning, nil), nil
			}
		default:
			if !time.Now().Before(deadline) {
				return nil, &ProbeTimeoutError{Phase: "observation window", LastState: last}
			}
		}
	}
}

// ObserveContainer starts the image with the defensive flags, the mock
// environment and the given extra flags, observes it for the window and
// removes it again on every path. Passing no extra flags observes the
// baseline. The image's own entrypoint runs.
func (e *Engine) ObserveContainer(ctx context.Context, image string, flags []string, window time.Duration) (*Observation, error) {
	if window <= 0 {
		window = DefaultProbeWindow
	}
	pc, failed, err := e.startProbeContainer(ctx, "con-unit-probe", image, flags)
	if err != nil {
		return nil, err
	}
	if failed != nil {
		failed.Window = window
		return failed, nil
	}
	defer pc.cleanup()
	return pc.observe(ctx, window)
}

// SigtermObservation is the outcome of a SIGTERM probe.
type SigtermObservation struct {
	// Before is the container state at the end of the window, before the
	// signal. The signal is only sent when it is StateRunning.
	Before *Observation
	// Sent reports that SIGTERM was delivered.
	Sent bool
	// Exited reports that the container had exited when the timeout ended.
	Exited bool
	// ExitCode is the exit code after the signal, when the container exited.
	ExitCode *int
	// Elapsed is the time from the signal until the exit was observed, or the
	// full timeout when the container kept running.
	Elapsed time.Duration
	Timeout time.Duration
	// LogTail is collected when the container did not terminate cleanly.
	LogTail string
}

// TerminatedBySigterm reports whether the container exited with code 0 (a
// handled SIGTERM) or 143 (128 plus SIGTERM, the default action) within the
// timeout.
func (s *SigtermObservation) TerminatedBySigterm() bool {
	return s.Sent && s.Exited && s.ExitCode != nil && (*s.ExitCode == 0 || *s.ExitCode == 143)
}

// ObserveSigterm starts the baseline configuration, waits until it has been
// observed running at the end of the window, sends SIGTERM and watches for
// the exit until the timeout. The signal is sent directly so that a stop
// command cannot report success for a container that already exited.
func (e *Engine) ObserveSigterm(ctx context.Context, image string, window, timeout time.Duration) (*SigtermObservation, error) {
	if window <= 0 {
		window = DefaultProbeWindow
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	pc, failed, err := e.startProbeContainer(ctx, "con-unit-sigterm", image, nil)
	if err != nil {
		return nil, err
	}
	if failed != nil {
		failed.Window = window
		return &SigtermObservation{Before: failed, Timeout: timeout}, nil
	}
	defer pc.cleanup()

	before, err := pc.observe(ctx, window)
	if err != nil {
		return nil, err
	}
	result := &SigtermObservation{Before: before, Timeout: timeout}
	if before.State != StateRunning {
		return result, nil
	}

	signalCtx, cancel := context.WithTimeout(ctx, probeInspectTimeout)
	out, killErr := e.Command(signalCtx, "kill", "--signal=SIGTERM", pc.name).CombinedOutput()
	signalExpired := signalCtx.Err() != nil
	cancel()
	if killErr != nil {
		if signalExpired {
			return nil, &ProbeTimeoutError{Phase: "SIGTERM delivery", Err: signalCtx.Err()}
		}
		return nil, &ProbeError{Phase: "SIGTERM delivery", Err: fmt.Errorf("%s (%w)", strings.TrimSpace(string(out)), killErr)}
	}
	result.Sent = true

	signalAt := time.Now()
	deadline := signalAt.Add(timeout)
	for {
		wait := time.Until(deadline)
		if wait > probePollInterval {
			wait = probePollInterval
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, &ProbeTimeoutError{Phase: "SIGTERM wait", Err: ctx.Err()}
			case <-timer.C:
			}
		}
		status, code, err := pc.inspectState(ctx)
		if err != nil {
			return nil, err
		}
		if isTerminalState(status) {
			result.Exited = true
			result.ExitCode = &code
			result.Elapsed = time.Since(signalAt)
			if !result.TerminatedBySigterm() {
				result.LogTail = pc.logTail(ctx)
			}
			return result, nil
		}
		if !time.Now().Before(deadline) {
			result.Elapsed = timeout
			result.LogTail = pc.logTail(ctx)
			return result, nil
		}
	}
}

// tailLines keeps the last n lines of text and at most logTailMaxBytes bytes.
func tailLines(text string, n int) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	tail := strings.Join(lines, "\n")
	if len(tail) > logTailMaxBytes {
		tail = tail[len(tail)-logTailMaxBytes:]
		if i := strings.IndexByte(tail, '\n'); i >= 0 && i < len(tail)-1 {
			tail = tail[i+1:]
		}
	}
	return tail
}
