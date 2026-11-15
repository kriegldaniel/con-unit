package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Container states recorded in an Observation.
const (
	StateRunning     = "running"      // still running when the window ended
	StateExited      = "exited"       // exited before the window ended
	StateStartFailed = "start_failed" // the engine could not create or start the container
	StateUnknown     = "unknown"      // the state could not be read, see Observation.Err
)

// RunSpec describes one container start.
type RunSpec struct {
	Image string
	// Flags are all engine run flags between "run -d --name <n>" and the
	// image: defensive flags, mock environment, treatment and candidates.
	Flags []string
	// Window is the observation window W.
	Window time.Duration
}

// Observation is what was seen of one container run.
type Observation struct {
	State    string `json:"state"`
	ExitCode *int   `json:"exit_code,omitempty"`
	LogTail  string `json:"log_tail,omitempty"`
	// Err is set when the engine itself misbehaved (state unreadable).
	Err string `json:"error,omitempty"`
}

// Survived reports whether the container was still running when the window
// ended. This is the survival criterion of docs/CONTRACT.md section 6.
func (o Observation) Survived() bool { return o.State == StateRunning }

// ContainerRunner starts containers and observes them. The production
// implementation shells out to the engine binary. Tests use a fake.
type ContainerRunner interface {
	// Observe starts a detached container, watches it for the window and
	// removes it. It never returns an error: problems become the state.
	Observe(ctx context.Context, spec RunSpec) Observation
	// ImagePresent reports whether the image is in the local store.
	ImagePresent(ctx context.Context, image string) (bool, error)
	// Pull fetches the image into the local store.
	Pull(ctx context.Context, image string) error
}

// lookPath finds an engine binary on PATH. A variable so tests can replace it.
var lookPath = exec.LookPath

// EngineRunner runs containers through a podman or docker binary.
type EngineRunner struct {
	Binary string
	// Poll is the interval between state checks. Zero means 100 ms.
	Poll time.Duration
}

func (e *EngineRunner) poll() time.Duration {
	if e.Poll > 0 {
		return e.Poll
	}
	return 100 * time.Millisecond
}

func (e *EngineRunner) command(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, e.Binary, args...)
}

// Observe implements ContainerRunner.
func (e *EngineRunner) Observe(ctx context.Context, rs RunSpec) Observation {
	name := fmt.Sprintf("con-unit-attr-%d", time.Now().UnixNano())
	args := append([]string{"run", "-d", "--name", name}, rs.Flags...)
	args = append(args, "--", rs.Image)
	out, err := e.command(ctx, args...).CombinedOutput()
	if err != nil {
		// The engine may have created the container before failing to start it.
		e.remove(name)
		return Observation{State: StateStartFailed, LogTail: tail(string(out), 600), Err: err.Error()}
	}
	defer e.remove(name)

	deadline := time.Now().Add(rs.Window)
	for {
		state, code, ierr := e.state(ctx, name)
		if ierr != nil {
			return Observation{State: StateUnknown, Err: ierr.Error()}
		}
		if state != StateRunning {
			return Observation{State: StateExited, ExitCode: &code, LogTail: e.logs(name)}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return Observation{State: StateRunning}
		}
		wait := e.poll()
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return Observation{State: StateUnknown, Err: ctx.Err().Error()}
		case <-time.After(wait):
		}
	}
}

// state reads the engine state of a container. Anything that is not running
// is reported as exited, which covers created, stopped, exited and dead.
func (e *EngineRunner) state(ctx context.Context, name string) (string, int, error) {
	// Stdout only: Podman 4.9 warns on stderr about a tmpfs destination that is a
	// symlink in the image (the candidate mount /var/run), and that line must not
	// become part of the state.
	cmd := e.command(ctx, "container", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("inspecting container state: %s (%w)", strings.TrimSpace(stderr.String()+stdout.String()), err)
	}
	out := strings.TrimSpace(stdout.String())
	parts := strings.Fields(out)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("unparseable container state %q", out)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 0 {
		return "", 0, fmt.Errorf("unparseable exit code %q", parts[1])
	}
	if parts[0] == "running" {
		return StateRunning, code, nil
	}
	return StateExited, code, nil
}

func (e *EngineRunner) logs(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, _ := e.command(ctx, "logs", "--tail=20", name).CombinedOutput()
	return tail(string(out), 600)
}

func (e *EngineRunner) remove(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = e.command(ctx, "rm", "-f", "-t", "0", name).Run()
}

// ImagePresent implements ContainerRunner. `image inspect` exists in podman
// and docker, unlike `image exists`.
func (e *EngineRunner) ImagePresent(ctx context.Context, image string) (bool, error) {
	cmd := e.command(ctx, "image", "inspect", "--format", "{{.Id}}", image)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Pull implements ContainerRunner.
func (e *EngineRunner) Pull(ctx context.Context, image string) error {
	out, err := e.command(ctx, "pull", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pull %s: %s (%w)", image, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// tail returns the last max bytes of s, cut at a line boundary when possible.
func tail(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	cut := s[len(s)-max:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return cut
}
