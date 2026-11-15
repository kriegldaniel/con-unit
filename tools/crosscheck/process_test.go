package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// fakeExporter writes a docker-archive whose config is configs[ref]. It
// records every archive path it was given.
type fakeExporter struct {
	t       *testing.T
	configs map[string]string
	errs    map[string]error
	// garbage makes the archive unreadable.
	garbage map[string]bool
	// block makes Export wait for the context.
	block map[string]bool
	info  ExportInfo
	paths []string
	calls int
	// platforms and refs record what Export was asked for.
	platforms []string
	refs      []string
}

func (f *fakeExporter) Export(ctx context.Context, ref, platform, dest string) (ExportInfo, error) {
	f.calls++
	f.paths = append(f.paths, dest)
	f.platforms = append(f.platforms, platform)
	f.refs = append(f.refs, ref)
	if f.block[ref] {
		<-ctx.Done()
		return ExportInfo{}, fmt.Errorf("export of %s: %w", ref, ctx.Err())
	}
	if err := f.errs[ref]; err != nil {
		return ExportInfo{}, err
	}
	if f.garbage[ref] {
		if err := os.WriteFile(dest, []byte("not a tar archive"), 0o644); err != nil {
			f.t.Fatal(err)
		}
		return f.info, nil
	}
	cfg := f.configs[ref]
	name := strings.TrimPrefix(sha(cfg), "sha256:") + ".json"
	writeTarAt(f.t, dest, []tarEntry{
		{name: name, data: cfg},
		{name: "manifest.json", data: `[{"Config":"` + name + `","Layers":[]}]`},
	})
	return f.info, nil
}

func (f *fakeExporter) Describe(context.Context) string { return "fakeengine version 1.0.0" }

// fakeDockle returns stdout for every archive and records the archives.
type fakeDockle struct {
	t        *testing.T
	out      RunOutput
	err      error
	version  string
	archives []string
	// existed records whether the archive existed while Dockle ran.
	existed []bool
}

func (f *fakeDockle) Version(context.Context) (string, error) {
	if f.version == "" {
		return VerifiedDockleVersion, nil
	}
	return f.version, nil
}

func (f *fakeDockle) Run(_ context.Context, archive string) (RunOutput, error) {
	f.archives = append(f.archives, archive)
	_, err := os.Stat(archive)
	f.existed = append(f.existed, err == nil)
	return f.out, f.err
}

// stepClock advances by step on every call.
func stepClock(step time.Duration) func() time.Time {
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	return func() time.Time {
		t := now
		now = now.Add(step)
		return t
	}
}

func intp(n int) *int { return &n }

func record(ref, cfg string) *spec.SuiteResult {
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, ConfigDigest: sha(cfg), Status: spec.StatusCompleted}
}

const (
	imgA   = "index.docker.io/library/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfgA   = `{"os":"linux","config":{"User":"nginx"},"rootfs":{"type":"layers"}}`
	cfgOth = `{"os":"linux","config":{"User":"other"},"rootfs":{"type":"layers"}}`
)

func TestProcess(t *testing.T) {
	cases := []struct {
		name       string
		rec        func() *spec.SuiteResult
		exporter   func(f *fakeExporter)
		dockle     func(f *fakeDockle)
		wantStatus ImageStatus
		wantError  string
		wantRuns   int
		// wantExports is the number of exports that must have been started; nil
		// means one.
		wantExports *int
		check       func(t *testing.T, r *ImageRecord)
	}{
		{
			name:       "a matching archive and a report give an OK record",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA; f.info = ExportInfo{ExportSeconds: 1.5} },
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte(cleanReport)} },
			wantStatus: ImageOK, wantRuns: 1,
			check: func(t *testing.T, r *ImageRecord) {
				if r.ExportSeconds != 1.5 || r.DockleSeconds != 2 {
					t.Errorf("export %.2fs, dockle %.2fs; want 1.5 and 2 (timed separately)", r.ExportSeconds, r.DockleSeconds)
				}
				if r.ConfigDigestArchive != sha(cfgA) || r.DockleStdout != cleanReport {
					t.Errorf("record = %+v", r)
				}
			},
		},
		{
			name: "a pull is recorded apart from the export",
			rec:  func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter: func(f *fakeExporter) {
				f.configs[imgA] = cfgA
				f.info = ExportInfo{Pulled: true, PullSeconds: 9, ExportSeconds: 1}
			},
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte(cleanReport)} },
			wantStatus: ImageOK, wantRuns: 1,
			check: func(t *testing.T, r *ImageRecord) {
				if !r.Pulled || r.PullSeconds != 9 || r.ExportSeconds != 1 {
					t.Errorf("pull %v %.1fs export %.1fs", r.Pulled, r.PullSeconds, r.ExportSeconds)
				}
			},
		},
		{
			name: "a study digest without the prefix is accepted",
			rec: func() *spec.SuiteResult {
				r := record(imgA, cfgA)
				r.ConfigDigest = strings.TrimPrefix(r.ConfigDigest, "sha256:")
				return r
			},
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA },
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte(cleanReport)} },
			wantStatus: ImageOK, wantRuns: 1,
		},
		{
			name:       "a digest mismatch is an error and Dockle never runs",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgOth },
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte(cleanReport)} },
			wantStatus: ImageDigestMismatch, wantRuns: 0,
			wantError: "differs from the study config digest",
			check: func(t *testing.T, r *ImageRecord) {
				if r.ConfigDigestArchive != sha(cfgOth) || r.ConfigDigestStudy != sha(cfgA) {
					t.Errorf("both digests must be recorded: %+v", r)
				}
				if r.DockleStdout != "" || r.DockleSeconds != 0 {
					t.Errorf("no Dockle result may exist for a mismatch: %+v", r)
				}
				if !strings.Contains(r.Error, sha(cfgOth)) || !strings.Contains(r.Error, sha(cfgA)) {
					t.Errorf("the error names both digests: %s", r.Error)
				}
			},
		},
		{
			name:       "an export error is recorded",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.errs[imgA] = errors.New("engine save failed") },
			wantStatus: ImageExportError, wantRuns: 0, wantError: "engine save failed",
		},
		{
			name:       "an unreadable archive is an archive error",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.garbage[imgA] = true },
			wantStatus: ImageArchiveError, wantRuns: 0,
		},
		{
			name: "a study record without a config digest cannot be verified",
			rec: func() *spec.SuiteResult {
				r := record(imgA, cfgA)
				r.ConfigDigest = " "
				return r
			},
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA },
			wantStatus: ImageNoStudyDigest, wantRuns: 0, wantError: "no config_digest", wantExports: intp(0),
			check: func(t *testing.T, r *ImageRecord) {
				if r.ExportSeconds != 0 {
					t.Error("nothing is exported when the archive cannot be verified")
				}
			},
		},
		{
			name:       "a failing Dockle exit code is a Dockle error",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA },
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte("FATAL boom"), ExitCode: 1} },
			wantStatus: ImageDockleError, wantRuns: 1, wantError: "exited with code 1",
		},
		{
			name:       "a Dockle that cannot run is a Dockle error",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA },
			dockle:     func(f *fakeDockle) { f.err = errors.New("dockle was cut off: context deadline exceeded") },
			wantStatus: ImageDockleError, wantRuns: 1, wantError: "cut off",
		},
		{
			name:       "output that is not a report is a parse error",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA },
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte("hello")} },
			wantStatus: ImageParseError, wantRuns: 1, wantError: "no JSON report",
		},
		{
			name:       "a report without details is a parse error, not a clean image",
			rec:        func() *spec.SuiteResult { return record(imgA, cfgA) },
			exporter:   func(f *fakeExporter) { f.configs[imgA] = cfgA },
			dockle:     func(f *fakeDockle) { f.out = RunOutput{Stdout: []byte(`{"summary":{}}`)} },
			wantStatus: ImageParseError, wantRuns: 1, wantError: "no details array",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			exp := &fakeExporter{t: t, configs: map[string]string{}, errs: map[string]error{}, garbage: map[string]bool{}, block: map[string]bool{}}
			if tc.exporter != nil {
				tc.exporter(exp)
			}
			dk := &fakeDockle{t: t}
			if tc.dockle != nil {
				tc.dockle(dk)
			}
			p := &Pipeline{Exporter: exp, Dockle: dk, Platform: "linux/amd64", TempDir: tmp, Now: stepClock(2 * time.Second)}
			got := p.Process(context.Background(), tc.rec())

			if got.Status != tc.wantStatus {
				t.Fatalf("status = %s (%s), want %s", got.Status, got.Error, tc.wantStatus)
			}
			if tc.wantError != "" && !strings.Contains(got.Error, tc.wantError) {
				t.Errorf("error = %q, want it to contain %q", got.Error, tc.wantError)
			}
			if len(dk.archives) != tc.wantRuns {
				t.Errorf("Dockle ran %d times, want %d", len(dk.archives), tc.wantRuns)
			}
			wantExports := 1
			if tc.wantExports != nil {
				wantExports = *tc.wantExports
			}
			if exp.calls != wantExports {
				t.Errorf("%d exports started, want %d", exp.calls, wantExports)
			}
			for i, existed := range dk.existed {
				if !existed {
					t.Errorf("the archive %s did not exist while Dockle ran", dk.archives[i])
				}
			}
			// The archive is deleted on every path, and so is its directory.
			for _, p := range append(append([]string{}, exp.paths...), dk.archives...) {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Errorf("the archive %s still exists", p)
				}
			}
			if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
				t.Errorf("the temporary directory still holds %d entries", len(entries))
			}
			if strings.Contains(got.Error, tmp) || strings.Contains(got.DockleStderr, tmp) {
				t.Errorf("the temporary path leaked into the record: %q", got.Error)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestProcessScrubsTemporaryPath(t *testing.T) {
	tmp := t.TempDir()
	exp := &scrubExporter{}
	p := &Pipeline{Exporter: exp, Dockle: &fakeDockle{t: t}, TempDir: tmp}
	got := p.Process(context.Background(), record(imgA, cfgA))
	if got.Status != ImageExportError {
		t.Fatalf("status = %s", got.Status)
	}
	if strings.Contains(got.Error, tmp) || !strings.Contains(got.Error, "<tmp>") {
		t.Errorf("error = %q, want the temporary directory replaced by <tmp>", got.Error)
	}
}

type scrubExporter struct{}

func (scrubExporter) Export(_ context.Context, _, _, dest string) (ExportInfo, error) {
	return ExportInfo{}, fmt.Errorf("cannot write %s: disk full", dest)
}
func (scrubExporter) Describe(context.Context) string { return "" }

func TestProcessTimeoutCutsAnExportOff(t *testing.T) {
	tmp := t.TempDir()
	exp := &fakeExporter{t: t, configs: map[string]string{}, errs: map[string]error{}, garbage: map[string]bool{}, block: map[string]bool{imgA: true}}
	dk := &fakeDockle{t: t}
	p := &Pipeline{Exporter: exp, Dockle: dk, TempDir: tmp, Timeout: 100 * time.Millisecond}
	start := time.Now()
	got := p.Process(context.Background(), record(imgA, cfgA))
	if got.Status != ImageExportError || !strings.Contains(got.Error, "deadline exceeded") {
		t.Errorf("status = %s, error = %q; want a timeout recorded as an export error", got.Status, got.Error)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("the timeout did not cut the export off")
	}
	if len(dk.archives) != 0 {
		t.Error("Dockle must not run after a failed export")
	}
}

func TestProcessKeepsTheStderrOfDockle(t *testing.T) {
	tmp := t.TempDir()
	exp := &fakeExporter{t: t, configs: map[string]string{imgA: cfgA}, errs: map[string]error{}, garbage: map[string]bool{}, block: map[string]bool{}}
	dk := &fakeDockle{t: t, out: RunOutput{Stdout: []byte(cleanReport), Stderr: []byte("warning: slow registry")}}
	p := &Pipeline{Exporter: exp, Dockle: dk, TempDir: tmp}
	got := p.Process(context.Background(), record(imgA, cfgA))
	if got.Status != ImageOK || got.DockleStderr != "warning: slow registry" {
		t.Errorf("record = %+v", got)
	}
}

func TestExcerptTextBoundsLargeOutput(t *testing.T) {
	long := strings.Repeat("x", maxExcerpt+50)
	got := excerptText(long)
	if len(got) > maxExcerpt+20 || !strings.HasSuffix(got, "[truncated]") {
		t.Errorf("excerpt length %d, want it bounded and marked", len(got))
	}
	if excerptText("short") != "short" {
		t.Error("short text must stay unchanged")
	}
}

func TestPipelineUsesSystemTempDirByDefault(t *testing.T) {
	exp := &fakeExporter{t: t, configs: map[string]string{imgA: cfgA}, errs: map[string]error{}, garbage: map[string]bool{}, block: map[string]bool{}}
	dk := &fakeDockle{t: t, out: RunOutput{Stdout: []byte(cleanReport)}}
	p := &Pipeline{Exporter: exp, Dockle: dk}
	if got := p.Process(context.Background(), record(imgA, cfgA)); got.Status != ImageOK {
		t.Fatalf("status = %s (%s)", got.Status, got.Error)
	}
	// The archive is in a fresh directory of the system temporary directory.
	if len(exp.paths) != 1 || filepath.Dir(filepath.Dir(exp.paths[0])) != filepath.Clean(os.TempDir()) {
		t.Errorf("archive path %v is not in a directory below %s", exp.paths, os.TempDir())
	}
}
