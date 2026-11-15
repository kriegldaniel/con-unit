package conunit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/con-unit/con-unit/pkg/spec"
)

type syftSBOMDocument struct {
	Artifacts []syftPackage `json:"artifacts"`
}

type syftPackage struct {
	Name     string            `json:"name"`
	Licenses []json.RawMessage `json:"licenses"`
}

// SyftUnavailableError means the Syft executable could not be found or
// started, as opposed to Syft running and failing. Callers report
// TOOL_UNAVAILABLE for it.
type SyftUnavailableError struct {
	Err error
}

func (e *SyftUnavailableError) Error() string { return "Syft is unavailable: " + e.Err.Error() }
func (e *SyftUnavailableError) Unwrap() error { return e.Err }

// sbomReason maps an error of the inventory step to the reason of an
// UNVERIFIED result.
func sbomReason(err error) spec.Reason {
	var unavailable *SyftUnavailableError
	if errors.As(err, &unavailable) {
		return spec.ReasonToolUnavailable
	}
	return spec.ReasonEvidenceIncomplete
}

// maxSyftStderr bounds the Syft diagnostics that are copied into an error.
const maxSyftStderr = 2048

// generateSyftSBOM runs Syft on the image and returns its package inventory.
// Only standard output is parsed. Syft prints warnings and progress to
// standard error, and mixing the two streams would turn a successful run with
// a warning into invalid JSON.
func generateSyftSBOM(ctx context.Context, image string) ([]syftPackage, error) {
	syftPath, err := exec.LookPath("syft")
	if err != nil {
		return nil, &SyftUnavailableError{Err: err}
	}
	cmd := exec.CommandContext(ctx, syftPath, image, "-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) && ctx.Err() == nil {
			// The process could not be started at all.
			return nil, &SyftUnavailableError{Err: err}
		}
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > maxSyftStderr {
			detail = detail[len(detail)-maxSyftStderr:]
		}
		return nil, fmt.Errorf("Syft failed: %w: %s", err, detail)
	}
	var document syftSBOMDocument
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		return nil, fmt.Errorf("Syft returned invalid JSON: %w", err)
	}
	if document.Artifacts == nil {
		return nil, fmt.Errorf("Syft JSON is missing the artifacts array")
	}
	for i, pkg := range document.Artifacts {
		if strings.TrimSpace(pkg.Name) == "" {
			return nil, fmt.Errorf("Syft artifact %d is missing a package name", i)
		}
	}
	return document.Artifacts, nil
}

// SBOMCache holds the Syft package inventory of one image so that SUP-01 and
// SUP-03 run Syft once. The outcome, including a failure, is computed once.
type SBOMCache struct {
	mu       sync.Mutex
	done     bool
	packages []syftPackage
	err      error
	runs     int
}

// Runs returns how many times Syft was started for this cache.
func (s *SBOMCache) Runs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs
}

func (s *SBOMCache) load(ctx context.Context, image string, generate func(context.Context, string) ([]syftPackage, error)) ([]syftPackage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.runs++
		s.packages, s.err = generate(ctx, image)
		// A run that ended because the context ended says nothing about the
		// image, so it is not remembered.
		s.done = ctx.Err() == nil
	}
	return s.packages, s.err
}

func (c *Container) sbomCache() *SBOMCache {
	if c.SBOM == nil {
		c.SBOM = &SBOMCache{}
	}
	return c.SBOM
}

// sbomPackages returns the package inventory of the image, running Syft at
// most once per cache.
func (c *Container) sbomPackages() ([]syftPackage, error) {
	return c.sbomCache().load(c.context(), c.Image, generateSyftSBOM)
}
