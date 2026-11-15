package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
)

// The Dockle comparison answers a cost question: what does it take to analyze
// the same image with Dockle on the same host? Dockle reads a docker-archive
// file, so its cost has two parts that are timed apart: exporting the archive
// from the local store of the engine (the export ConUnit itself does for an
// image of the local store) and running Dockle on the archive. The comparison
// uses the images, the host and the trials of the ConUnit benchmark. After every
// warm-up and timed trial of ConUnit that succeeded, the same image is exported
// and analyzed once more, and both durations are recorded in the trial.

// dockleArgs are the arguments of the Dockle run after the binary, with the
// path of the archive: JSON output and exit code 0 whatever the findings
// (docs/INTERFACE_V2.md section 4). The output is discarded, only the time and
// the exit status are used.
func dockleArgs(archive string) []string {
	return []string{"--input", archive, "--format", "json", "--exit-code", "0"}
}

// DockleTiming holds the two durations of one comparison.
type DockleTiming struct {
	Export time.Duration
	Run    time.Duration
}

// Comparator times a second tool on one image. The production implementation
// is DockleRunner, tests use a fake.
type Comparator interface {
	// Time exports and analyzes the image once. On failure the timing holds the
	// phases that finished, and the error is a *ComparatorError.
	Time(ctx context.Context, image string) (DockleTiming, error)
}

// Phases of a comparison.
const (
	PhaseExport   = "export"
	PhaseAnalysis = "analysis"
)

// ComparatorError says which phase of a comparison failed.
type ComparatorError struct {
	Phase string
	Err   error
}

func (e *ComparatorError) Error() string { return fmt.Sprintf("dockle %s: %v", e.Phase, e.Err) }
func (e *ComparatorError) Unwrap() error { return e.Err }

// DockleRunner times Dockle through the engine and the Dockle binary.
type DockleRunner struct {
	Engine *engine.Engine
	Binary string
	// TempDir is the parent of the temporary archive directories. Empty means
	// the default temporary directory.
	TempDir string
}

// Time implements Comparator. The archive lives in a private temporary
// directory that is removed on every path, and the removal is not timed.
func (d *DockleRunner) Time(ctx context.Context, image string) (DockleTiming, error) {
	var timing DockleTiming
	dir, err := os.MkdirTemp(d.TempDir, "conunit-rq3-dockle-*")
	if err != nil {
		return timing, &ComparatorError{Phase: PhaseExport, Err: fmt.Errorf("creating a temporary directory: %w", err)}
	}
	defer os.RemoveAll(dir)
	archive := filepath.Join(dir, "image.tar")

	start := time.Now()
	err = d.Engine.SaveImage(ctx, image, archive)
	timing.Export = time.Since(start)
	if err != nil {
		return timing, &ComparatorError{Phase: PhaseExport, Err: err}
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, d.Binary, dockleArgs(archive)...)
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	start = time.Now()
	err = cmd.Run()
	timing.Run = time.Since(start)
	if err != nil {
		detail := strings.Join(strings.Fields(stderr.String()), " ")
		if len(detail) > 300 {
			detail = detail[:300]
		}
		if detail != "" {
			err = fmt.Errorf("%w: %s", err, detail)
		}
		return timing, &ComparatorError{Phase: PhaseAnalysis, Err: err}
	}
	return timing, nil
}

// dockleVersionTimeout bounds the version probe.
const dockleVersionTimeout = 15 * time.Second

// PrepareDockle resolves the Dockle binary and reads its version. A binary
// that cannot print its version cannot analyze an image either, so that is an
// error. The version is the first line of `dockle --version`, verbatim.
func PrepareDockle(binary string) (path, version string, err error) {
	path, err = exec.LookPath(binary)
	if err != nil {
		return "", "", fmt.Errorf("dockle binary %q not found: %w", binary, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockleVersionTimeout)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("%s --version failed: %w", path, err)
	}
	version = strings.TrimSpace(strings.SplitN(strings.TrimSpace(out.String()), "\n", 2)[0])
	if version == "" {
		return "", "", errors.New(path + " --version printed nothing")
	}
	return path, version, nil
}

// ValidateDockleOptions rejects option combinations in which the comparison
// would not measure what it claims to.
func ValidateDockleOptions(dockle, imageSource string) error {
	if dockle == "" {
		return nil
	}
	if imageSource == "registry" {
		return errors.New("-dockle exports the image from the local store of the engine, which -image-source registry does not use")
	}
	return nil
}

// timeDockle runs the comparison for one finished trial and records the
// result in it. It runs only for a trial of ConUnit that succeeded, so the two
// tools are compared on the same trials. The comparison has its own deadline,
// the trial timeout.
func timeDockle(ctx context.Context, c Comparator, rec *TrialRecord, timeout time.Duration) {
	if c == nil || !rec.OK() {
		return
	}
	cctx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	timing, err := c.Time(cctx, rec.Image)
	var ce *ComparatorError
	switch {
	case err == nil:
		rec.DockleExportMs, rec.DockleRunMs = ms(timing.Export), ms(timing.Run)
	case errors.As(err, &ce) && ce.Phase == PhaseAnalysis:
		// The export finished, so its time is real. The run failed and has none.
		rec.DockleExportMs = ms(timing.Export)
		rec.DockleError = err.Error()
	default:
		rec.DockleError = err.Error()
	}
}

// ms converts a duration to milliseconds with microsecond resolution.
func ms(d time.Duration) *float64 {
	v := float64(d.Microseconds()) / 1000
	return &v
}
