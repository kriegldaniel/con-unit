package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ImageInspect represents the parsed OCI/Docker container inspection output
type ImageInspect struct {
	ID       string   `json:"Id"`
	RepoTags []string `json:"RepoTags"`
	// RepoDigests lists the registry digests the engine associates with the
	// image, for example docker.io/library/alpine@sha256:<digest>. It is how a
	// digest-pinned request is verified against what the engine really holds.
	RepoDigests []string    `json:"RepoDigests"`
	Size        int64       `json:"Size"`
	Config      ImageConfig `json:"Config"`
	// Healthcheck is where Podman reports the image HEALTHCHECK: at the top
	// level of the inspect document, while its Config is the plain OCI config
	// and has no such key. Docker reports it as Config.Healthcheck.
	// InspectImageForPlatform copies it into Config.Healthcheck, so that every
	// reader looks in one place.
	Healthcheck  *HealthConfig `json:"Healthcheck"`
	Architecture string        `json:"Architecture"`
	Os           string        `json:"Os"`
	Variant      string        `json:"Variant"`
}

// NormalizeDigest lower-cases a digest and ensures the algorithm prefix, so a
// podman style bare hex image ID compares equal to "sha256:<hex>".
func NormalizeDigest(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if !strings.Contains(value, ":") {
		return "sha256:" + value
	}
	return value
}

// NormalizedID returns the image ID as "sha256:<hex>".
func (i *ImageInspect) NormalizedID() string { return NormalizeDigest(i.ID) }

// RepoDigestSet returns the normalized digests of all RepoDigests entries.
func (i *ImageInspect) RepoDigestSet() map[string]struct{} {
	digests := make(map[string]struct{}, len(i.RepoDigests))
	for _, entry := range i.RepoDigests {
		_, digest, found := strings.Cut(strings.TrimSpace(entry), "@")
		if !found {
			digest = entry
		}
		if digest = NormalizeDigest(digest); digest != "" {
			digests[digest] = struct{}{}
		}
	}
	return digests
}

// ImageConfig contains runtime metadata. Volumes holds the paths of the VOLUME
// declarations of the image (SPEC-12).
type ImageConfig struct {
	User         string              `json:"User"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	Env          []string            `json:"Env"`
	Entrypoint   []string            `json:"Entrypoint"`
	Cmd          []string            `json:"Cmd"`
	WorkingDir   string              `json:"WorkingDir"`
	Labels       map[string]string   `json:"Labels"`
	Healthcheck  *HealthConfig       `json:"Healthcheck"`
	Volumes      map[string]struct{} `json:"Volumes"`
}

// HealthConfig represents image HEALTHCHECK metadata from an image inspect response.
type HealthConfig struct {
	Test          []string      `json:"Test"`
	Interval      time.Duration `json:"Interval"`
	Timeout       time.Duration `json:"Timeout"`
	StartPeriod   time.Duration `json:"StartPeriod"`
	StartInterval time.Duration `json:"StartInterval"`
	Retries       int           `json:"Retries"`
}

// Engine wraps container runtime commands (podman or docker)
type Engine struct {
	BinaryPath string
	ExtraArgs  []string

	kindMu    sync.Mutex
	kindKnown bool
	kind      Kind
}

// Kind identifies the container engine family behind a binary.
type Kind string

const (
	KindUnknown Kind = ""
	KindPodman  Kind = "podman"
	KindDocker  Kind = "docker"
)

// Kind detects the engine family. See KindFor.
func (e *Engine) Kind() Kind { return e.KindFor(context.Background()) }

// KindFor detects the engine family once. The binary name decides first; for
// other names `--version` is consulted, bounded by ctx. A podman binary that
// is installed under the name docker is treated as docker, which only costs
// it the podman specific `image exists` shortcut. An answer obtained while
// ctx was ending is not cached.
func (e *Engine) KindFor(ctx context.Context) Kind {
	e.kindMu.Lock()
	defer e.kindMu.Unlock()
	if e.kindKnown {
		return e.kind
	}
	detected := KindUnknown
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(e.BinaryPath)), ".exe") {
	case "podman":
		detected = KindPodman
	case "docker":
		detected = KindDocker
	default:
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if out, err := e.Command(probeCtx, "--version").CombinedOutput(); err == nil {
			switch lower := strings.ToLower(string(out)); {
			case strings.Contains(lower, "podman"):
				detected = KindPodman
			case strings.Contains(lower, "docker"):
				detected = KindDocker
			}
		}
	}
	if ctx.Err() == nil {
		e.kind = detected
		e.kindKnown = true
	}
	return detected
}

// ValidateImageRef rejects unsafe image strings (e.g. starting with '-' to prevent CLI flag injection)
func ValidateImageRef(image string) error {
	trimmed := strings.TrimSpace(image)
	if trimmed == "" {
		return fmt.Errorf("image reference cannot be empty")
	}
	if strings.HasPrefix(trimmed, "-") {
		return fmt.Errorf("security violation: image reference '%s' starts with a hyphen (potential flag injection)", image)
	}
	return nil
}

// DefensiveRunFlags returns standard host sandboxing options to safely execute untrusted containers
// Note: Sets network isolation and process ceiling without confounding independent test variables
func (e *Engine) DefensiveRunFlags() []string {
	return []string{
		"--network=none",
		"--pids-limit=256",
	}
}
func observedProbeResult(start time.Time, exitCode int, message string) *ExecResult {
	return &ExecResult{
		Stdout:           message,
		ExitCode:         exitCode,
		Duration:         time.Since(start),
		EvidenceComplete: true,
	}
}

// Command constructs an exec.Cmd with configured binary and global extra arguments (e.g. --root)
func (e *Engine) Command(ctx context.Context, args ...string) *exec.Cmd {
	allArgs := append([]string{}, e.ExtraArgs...)
	allArgs = append(allArgs, args...)
	return exec.CommandContext(ctx, e.BinaryPath, allArgs...)
}

// DetectEngine finds an available container engine (prefers podman on this system)
func DetectEngine(preferred string) (*Engine, error) {
	candidates := []string{}
	if preferred != "" && preferred != "auto" {
		candidates = append(candidates, preferred)
	} else {
		candidates = append(candidates, "podman", "docker")
	}

	for _, c := range candidates {
		path, err := exec.LookPath(c)
		if err == nil {
			return &Engine{BinaryPath: path}, nil
		}
	}
	return nil, fmt.Errorf("no OCI container engine found (checked: %v)", candidates)
}

// EnsureImage checks if image is present or pulls it
func (e *Engine) EnsureImage(ctx context.Context, image string) error {
	_, err := e.EnsureImageWithOwnership(ctx, image)
	return err
}

// EnsureImageWithOwnership checks for an image and pulls it only when the
// engine reports it absent. pulled is true only when that pull succeeds.
func (e *Engine) EnsureImageWithOwnership(ctx context.Context, image string) (bool, error) {
	return e.EnsureImageForPlatform(ctx, image, "")
}

// EnsureImageForPlatform is EnsureImageWithOwnership with an explicit
// platform (for example linux/amd64) passed to the pull.
func (e *Engine) EnsureImageForPlatform(ctx context.Context, image, platform string) (bool, error) {
	present, err := e.HasImage(ctx, image)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	if err := e.Pull(ctx, image, platform); err != nil {
		return false, err
	}
	return true, nil
}

// absentImagePattern recognizes the engines' "no such image" answers when the
// exit code alone is ambiguous (docker returns 1 for absent images and for an
// unreachable daemon).
var absentImagePattern = regexp.MustCompile(`(?i)no such image|image not known|no such object`)

// HasImage reports whether the image is present in the engine's local store.
// Podman answers with the exit code of `image exists`. Docker has no such
// subcommand, so it falls back to `image inspect` and recognizes absence by
// the engine's own message, while every other failure stays an error.
func (e *Engine) HasImage(ctx context.Context, image string) (bool, error) {
	if e.KindFor(ctx) == KindDocker {
		out, err := e.Command(ctx, "image", "inspect", "--format", "{{.Id}}", image).CombinedOutput()
		if err == nil {
			return true, nil
		}
		if ctx.Err() == nil && absentImagePattern.Match(out) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check whether image %s exists: %s (%w)", image, strings.TrimSpace(string(out)), wrapContextError(ctx, err))
	}
	_, err := e.Command(ctx, "image", "exists", image).CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		return false, fmt.Errorf("failed to check whether image %s exists: %w", image, wrapContextError(ctx, err))
	}
	return false, nil
}

// Pull pulls the image into the engine's local store, for the given platform
// when one is supplied. Throttling and missing images surface as typed errors.
func (e *Engine) Pull(ctx context.Context, image, platform string) error {
	args := []string{"pull"}
	if platform != "" {
		args = append(args, "--platform", platform)
	}
	args = append(args, image)
	out, err := e.Command(ctx, args...).CombinedOutput()
	if err != nil {
		return classifyPullFailure(ctx, "pull", image, string(out), err)
	}
	return nil
}

// InspectImage retrieves OCI manifest configuration
func (e *Engine) InspectImage(ctx context.Context, image string) (*ImageInspect, error) {
	return e.InspectImageForPlatform(ctx, image, "")
}

// InspectImageForPlatform inspects the image. Docker accepts --platform on
// `image inspect` to choose among the platforms in the store; podman does not
// have the flag, so the caller verifies the reported platform instead. An
// engine that rejects the flag is retried without it.
func (e *Engine) InspectImageForPlatform(ctx context.Context, image, platform string) (*ImageInspect, error) {
	args := []string{"image", "inspect"}
	usePlatformFlag := platform != "" && e.KindFor(ctx) == KindDocker
	if usePlatformFlag {
		args = append(args, "--platform", platform)
	}
	args = append(args, image)
	out, err := e.Command(ctx, args...).CombinedOutput()
	if err != nil && usePlatformFlag && strings.Contains(strings.ToLower(string(out)), "unknown flag") {
		out, err = e.Command(ctx, "image", "inspect", image).CombinedOutput()
	}
	if err != nil {
		return nil, fmt.Errorf("engine inspect failed: %s (%w)", string(out), wrapContextError(ctx, err))
	}

	var inspects []ImageInspect
	if err := json.Unmarshal(out, &inspects); err != nil {
		return nil, fmt.Errorf("failed to parse inspect JSON: %w", err)
	}
	if len(inspects) == 0 {
		return nil, fmt.Errorf("inspect output empty for %s", image)
	}
	inspect := inspects[0]
	// The OCI config is authoritative. The engine specific top-level key is
	// used only when the config has no healthcheck.
	if inspect.Config.Healthcheck == nil && inspect.Healthcheck != nil {
		inspect.Config.Healthcheck = inspect.Healthcheck
	}
	return &inspect, nil
}

// SaveImage exports the image from the engine's local store into a
// docker-archive file. It is how ConUnit reads layer content from the store
// without a Docker-compatible socket. The destination must not exist yet.
func (e *Engine) SaveImage(ctx context.Context, image, destPath string) error {
	if err := ValidateImageRef(image); err != nil {
		return err
	}
	args := []string{"save"}
	if e.KindFor(ctx) != KindDocker {
		args = append(args, "--format", "docker-archive")
	}
	args = append(args, "-o", destPath, image)
	out, err := e.Command(ctx, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to export image %s from the engine store: %s (%w)", image, strings.TrimSpace(string(out)), wrapContextError(ctx, err))
	}
	info, statErr := os.Stat(destPath)
	if statErr != nil || info.Size() == 0 {
		return fmt.Errorf("engine reported success exporting image %s but wrote no archive to %s", image, destPath)
	}
	return nil
}

// ExecResult contains execution outputs
type ExecResult struct {
	Stdout           string
	Stderr           string
	ExitCode         int
	Duration         time.Duration
	EvidenceComplete bool
}

func failedProbeResult(start time.Time, message string) *ExecResult {
	return &ExecResult{
		Stdout:   message,
		ExitCode: 1,
		Duration: time.Since(start),
	}
}

// RunProbe executes a one-off probe command inside the container
func (e *Engine) RunProbe(ctx context.Context, image string, args []string) (*ExecResult, error) {
	if err := ValidateImageRef(image); err != nil {
		return nil, err
	}
	start := time.Now()
	baseArgs := []string{"run", "--rm", "--entrypoint="}
	baseArgs = append(baseArgs, e.DefensiveRunFlags()...)
	baseArgs = append(baseArgs, "--", image)
	baseArgs = append(baseArgs, args...)

	cmd := e.Command(ctx, baseArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

// TestHTTPContract starts container, maps ephemeral port, and asserts HTTP status within timeout
func (e *Engine) TestHTTPContract(ctx context.Context, image string, containerPort int, path string, expectedStatus int, timeoutSec int) (*ExecResult, error) {
	if err := ValidateImageRef(image); err != nil {
		return nil, err
	}
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	start := time.Now()

	// 1. Allocate free host port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed allocating ephemeral host port: %w", err)
	}
	hostPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	// 2. Start container detached with port mapping and defensive resource limits
	name := fmt.Sprintf("con-unit-http-%d", time.Now().UnixNano())
	portMap := fmt.Sprintf("127.0.0.1:%d:%d", hostPort, containerPort)
	createArgs := []string{
		"run", "-d", "--name", name,
		"-p", portMap,
		"--pids-limit=128",
		"--memory=512m",
		"--security-opt=no-new-privileges:true",
		"--", image,
	}
	// The container may exist even when `run` fails, so cleanup is registered first.
	defer e.cleanupContainer(name)
	createCmd := e.Command(ctx, createArgs...)
	out, err := createCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed starting container for HTTP contract test: %s (%w)", string(out), wrapContextError(ctx, err))
	}

	// 3. Poll HTTP endpoint until success or deadline
	client := &http.Client{Timeout: 1 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d%s", hostPort, path)
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	var lastErr error
	var lastStatus int

	for time.Now().Before(deadline) {
		req, reqErr := http.NewRequestWithContext(ctx, "GET", url, nil)
		if reqErr != nil {
			lastErr = reqErr
			break
		}

		resp, respErr := client.Do(req)
		if respErr == nil {
			lastStatus = resp.StatusCode
			_ = resp.Body.Close()
			if lastStatus == expectedStatus {
				return &ExecResult{
					Stdout:           fmt.Sprintf("HTTP endpoint '%s' returned expected status %d within %v", path, expectedStatus, time.Since(start).Round(time.Millisecond)),
					ExitCode:         0,
					Duration:         time.Since(start),
					EvidenceComplete: true,
				}, nil
			}
		} else {
			lastErr = respErr
		}
		time.Sleep(250 * time.Millisecond)
	}

	message := fmt.Sprintf("HTTP endpoint '%s' failed to respond with %d within %ds (last status: %d, last error: %v)", path, expectedStatus, timeoutSec, lastStatus, lastErr)
	if lastStatus != 0 {
		return observedProbeResult(start, 1, message), nil
	}
	return failedProbeResult(start, message), nil
}

// CheckFileExistsInImage runs a probe to check if a specific path exists
func (e *Engine) CheckPathExists(ctx context.Context, image, path string) (bool, error) {
	// Pass the path as a distinct argv value; never interpolate it into a shell command.
	cmdArgs := []string{"test", "-e", path}
	res, err := e.RunProbe(ctx, image, cmdArgs)
	if err != nil {
		return false, fmt.Errorf("path existence probe for %q failed: %w", path, err)
	}
	if res == nil {
		return false, fmt.Errorf("path existence probe for %q returned no result", path)
	}
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1:
		if detail := strings.TrimSpace(res.Stderr + " " + res.Stdout); detail != "" {
			return false, fmt.Errorf("path existence probe for %q failed with exit code 1: %s", path, detail)
		}
		return false, nil
	default:
		detail := strings.TrimSpace(res.Stderr + " " + res.Stdout)
		return false, fmt.Errorf("path existence probe for %q failed with exit code %d: %s", path, res.ExitCode, detail)
	}
}

// FindSuidBinaries probes the image for SUID / SGID binaries
func (e *Engine) FindSuidBinaries(ctx context.Context, image string) ([]string, error) {
	shArgs := []string{"/bin/sh", "-c", "find / -perm /6000 -type f"}
	res, err := e.RunProbe(ctx, image, shArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to run SUID/SGID scan: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("SUID/SGID scan returned no result")
	}
	if res.ExitCode != 0 {
		detail := strings.TrimSpace(res.Stderr + " " + res.Stdout)
		return nil, fmt.Errorf("SUID/SGID scan failed with exit code %d: %s", res.ExitCode, detail)
	}
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	var suids []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			suids = append(suids, trimmed)
		}
	}
	return suids, nil
}
