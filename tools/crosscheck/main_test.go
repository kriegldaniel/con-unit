package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// runEnv is a study on disk plus the fakes that newDeps hands out.
type runEnv struct {
	t      *testing.T
	dir    string
	study  string
	out    string
	export *fakeExporter
	dockle *fakeDockle
	// order of the images, as keys.
	keys []string
}

const (
	keyNginx  = "index.docker.io/library/nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111"
	keyRedis  = "index.docker.io/library/redis@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	keyPython = "index.docker.io/library/python@sha256:3333333333333333333333333333333333333333333333333333333333333333"
	cfgNginx  = `{"os":"linux","config":{"User":""}}`
	cfgRedis  = `{"os":"linux","config":{"User":"redis"}}`
	cfgPython = `{"os":"linux","config":{"User":"py"}}`
)

func newRunEnv(t *testing.T) *runEnv {
	t.Helper()
	dir := t.TempDir()
	e := &runEnv{t: t, dir: dir, study: filepath.Join(dir, "lint", "empirical_study.json"), out: filepath.Join(dir, "crosscheck")}
	e.keys = []string{keyNginx, keyRedis, keyPython}
	mk := func(key, cfg string, results ...spec.TestResult) *spec.SuiteResult {
		r := cuImage(key, results...)
		r.ConfigDigest = sha(cfg)
		return r
	}
	study := spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run: spec.RunMetadata{
			ConUnitVersion: "0.9.0-test", Pack: "lint", PackID: "PACK-IMAGE-LINT", Platform: "linux/amd64",
			ImageSource: "auto", EngineName: "podman", EngineVersion: "5.8.1", StartedAt: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
		},
		Images: []*spec.SuiteResult{
			mk(keyNginx, cfgNginx, goldenChecks(map[string]spec.TestResult{"SPEC-01": fail("SPEC-01", "root")})...),
			mk(keyRedis, cfgRedis, goldenChecks(nil)...),
			mk(keyPython, cfgPython, goldenChecks(nil)...),
			{ImageName: "x@sha256:9", RequestedRef: "x@sha256:9", Status: spec.StatusTimeout},
		},
	}
	if err := os.MkdirAll(filepath.Dir(e.study), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(study)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.study, data, 0o644); err != nil {
		t.Fatal(err)
	}

	e.export = &fakeExporter{
		t: t, errs: map[string]error{}, garbage: map[string]bool{}, block: map[string]bool{},
		configs: map[string]string{keyNginx: cfgNginx, keyRedis: cfgRedis, keyPython: cfgPython},
		info:    ExportInfo{ExportSeconds: 1},
	}
	// Every image gets a clean report. nginx fails SPEC-01 in the study, so it
	// is the one discordance (ConUnit only); the other images agree.
	e.dockle = &fakeDockle{t: t, out: RunOutput{Stdout: []byte(reportJSON())}}
	old := newDeps
	newDeps = func(config) (deps, error) { return deps{Exporter: e.export, Dockle: e.dockle}, nil }
	t.Cleanup(func() { newDeps = old })
	return e
}

func (e *runEnv) run(extra ...string) (code int, stdout, stderr string) {
	e.t.Helper()
	args := append([]string{"-study", e.study, "-out-dir", e.out}, extra...)
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func (e *runEnv) read(rel string) string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.out, rel))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func TestRunWritesEverythingAndExitsZero(t *testing.T) {
	e := newRunEnv(t)
	code, stdout, stderr := e.run()
	if code != spec.ExitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, name := range []string{fileJSON, fileDiscordances, fileTable, fileDiscTable, fileMacros, fileCoverage, "raw/run.json"} {
		if _, err := os.Stat(filepath.Join(e.out, name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
	// One raw record per completed image, none for the timeout.
	raws, _ := os.ReadDir(filepath.Join(e.out, "raw"))
	if len(raws) != 4 { // run.json and three records
		t.Errorf("raw/ holds %d files, want run.json and one record per completed image", len(raws))
	}
	macros := e.read(fileMacros)
	for _, want := range []string{
		`\newcommand{\ConUnitXchkImages}{3}`,
		`\newcommand{\ConUnitXchkBothSPECZeroOne}{0}`,
		`\newcommand{\ConUnitXchkOnlyConUnitSPECZeroOne}{1}`,
		`\newcommand{\ConUnitXchkNeitherSPECZeroOne}{2}`,
		`\newcommand{\ConUnitXchkAgreeSPECZeroOne}{66.7\%}`,
		`\newcommand{\ConUnitXchkDiscordant}{1}`,
		`\newcommand{\ConUnitXchkAgreeSPECOneThree}{n/a}`,
		`\newcommand{\ConUnitXchkResolved}{n/a}`,
		`\newcommand{\ConUnitXchkDockleVersion}{0.4.15}`,
	} {
		if !strings.Contains(macros, want) {
			t.Errorf("macros lack %s", want)
		}
	}
	// The export got the platform of the study run.
	for _, p := range e.export.platforms {
		if p != "linux/amd64" {
			t.Errorf("platform = %q, want the one of the study run", p)
		}
	}
	if e.export.calls != 3 || len(e.dockle.archives) != 3 {
		t.Errorf("exports = %d, Dockle runs = %d, want 3 each", e.export.calls, len(e.dockle.archives))
	}
	if !strings.Contains(stdout, "Result per check") || !strings.Contains(stdout, "not comparable") {
		t.Errorf("console summary missing:\n%s", stdout)
	}
}

func TestOutputsHoldNoHostPath(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run(); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	err := filepath.WalkDir(e.out, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		for _, secret := range []string{e.dir, os.TempDir()} {
			if secret != "" && secret != "/" && strings.Contains(string(b), secret) {
				t.Errorf("%s contains the host path %s", path, secret)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	js := e.read(fileJSON)
	if !strings.Contains(js, `"file": "empirical_study.json"`) {
		t.Errorf("the study is named by its base name only:\n%s", js[:400])
	}
}

func TestRunWithADigestMismatchWritesOutputsAndExitsWithIncomplete(t *testing.T) {
	e := newRunEnv(t)
	e.export.configs[keyRedis] = cfgPython // the engine hands out another image
	code, _, stderr := e.run()
	if code != spec.ExitIncomplete {
		t.Fatalf("exit %d, want %d (outputs written, one image without a Dockle result)\nstderr:\n%s", code, spec.ExitIncomplete, stderr)
	}
	if !strings.Contains(stderr, "DIGEST_MISMATCH 1") {
		t.Errorf("stderr must name the status:\n%s", stderr)
	}
	macros := e.read(fileMacros)
	for _, want := range []string{`\newcommand{\ConUnitXchkImages}{2}`, `\newcommand{\ConUnitXchkDockleErrorSPECZeroOne}{1}`} {
		if !strings.Contains(macros, want) {
			t.Errorf("macros lack %s", want)
		}
	}
	// No result for the mismatching image exists anywhere in the comparison.
	var rep Report
	if err := json.Unmarshal([]byte(e.read(fileJSON)), &rep); err != nil {
		t.Fatal(err)
	}
	for _, ir := range rep.Images {
		if ir.Image != keyRedis {
			continue
		}
		if ir.Status != ImageDigestMismatch || len(ir.DockleDetails) != 0 {
			t.Errorf("image = %+v", ir)
		}
		for _, c := range ir.Checks {
			want := CellDockleError
			if c.Check == "SPEC-13" {
				want = CellNotComparable // never compared, whatever the image
			}
			if c.Cell != want {
				t.Errorf("%s of the mismatching image is in cell %s, want %s", c.Check, c.Cell, want)
			}
		}
	}
	if len(e.dockle.archives) != 2 {
		t.Errorf("Dockle ran %d times, want 2 (not on the mismatching image)", len(e.dockle.archives))
	}
}

func TestRunSelectsImages(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantCode  int
		wantRefs  []string
		wantStder string
	}{
		{"by repository name", []string{"-images", "redis"}, 0, []string{keyRedis}, ""},
		{"by full reference and name", []string{"-images", keyNginx + ", python"}, 0, []string{keyNginx, keyPython}, ""},
		{"limit takes the first in sorted order", []string{"-limit", "2"}, 0, []string{keyNginx, keyPython}, ""},
		{"limit larger than the study", []string{"-limit", "50"}, 0, []string{keyNginx, keyPython, keyRedis}, ""},
		{"a name that matches nothing is a usage error", []string{"-images", "redis,nosuchimage"}, spec.ExitUsage, nil, "nosuchimage"},
		{"an image that did not complete cannot be selected", []string{"-images", "x@sha256:9"}, spec.ExitUsage, nil, "x@sha256:9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRunEnv(t)
			code, _, stderr := e.run(tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, tc.wantCode, stderr)
			}
			if tc.wantStder != "" && !strings.Contains(stderr, tc.wantStder) {
				t.Errorf("stderr lacks %q:\n%s", tc.wantStder, stderr)
			}
			if tc.wantRefs != nil {
				got := append([]string(nil), e.export.refs...)
				if strings.Join(got, ",") != strings.Join(tc.wantRefs, ",") {
					t.Errorf("exported %v, want %v", got, tc.wantRefs)
				}
			} else if e.export.calls != 0 {
				t.Errorf("nothing may be exported on a usage error, got %d exports", e.export.calls)
			}
		})
	}
}

func TestSubsetRunAnalyzesOnlyTheSelection(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run("-images", "redis"); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if got := e.read(fileMacros); !strings.Contains(got, `\newcommand{\ConUnitXchkImages}{1}`) {
		t.Errorf("a subset run reports its own images:\n%s", got[:300])
	}
	if !strings.Contains(e.read(fileJSON), "covers 1 of 3 completed images") {
		t.Error("the report must say that it covers a subset")
	}
}

func TestAnalyzeOnlyRebuildsTheOutputsWithoutRunningAnything(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run(); code != spec.ExitOK {
		t.Fatalf("first run: exit %d: %s", code, stderr)
	}
	first := map[string]string{}
	for _, name := range []string{fileJSON, fileDiscordances, fileTable, fileDiscTable, fileMacros, fileCoverage} {
		first[name] = e.read(name)
		if err := os.Remove(filepath.Join(e.out, name)); err != nil {
			t.Fatal(err)
		}
	}
	// Nothing may run: no engine and no Dockle.
	newDeps = func(config) (deps, error) {
		return deps{}, errors.New("analyze-only must not build the exporter or the runner")
	}
	code, stdout, stderr := e.run("-analyze-only")
	if code != spec.ExitOK {
		t.Fatalf("analyze-only: exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "3 raw records read") {
		t.Errorf("stdout:\n%s", stdout)
	}
	for name, want := range first {
		if got := e.read(name); got != want {
			t.Errorf("%s differs after -analyze-only", name)
		}
	}
}

func TestAnalyzeOnlyNeedsTheRawDirectory(t *testing.T) {
	e := newRunEnv(t)
	code, _, stderr := e.run("-analyze-only")
	if code != spec.ExitFindings || !strings.Contains(stderr, "run.json") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestAnalyzeOnlyCountsAMissingRawRecordAsAnError(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run(); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(e.out, rawDir, rawName(keyPython))); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run("-analyze-only")
	if code != spec.ExitIncomplete || !strings.Contains(stderr, "NO_RAW_RECORD 1") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestAnalyzeOnlyWarnsAboutAnUnreadableRawRecord(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run(); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if err := os.WriteFile(filepath.Join(e.out, rawDir, rawName(keyPython)), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run("-analyze-only")
	if code != spec.ExitIncomplete || !strings.Contains(stderr, "raw record of") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestRunFillsTheResolutionFromTheAdjudicationSheet(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run(); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var rep Report
	if err := json.Unmarshal([]byte(e.read(fileJSON)), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Discordances) == 0 {
		t.Fatal("the study should have one discordance: SPEC-01 fails on nginx in the study and Dockle reports nothing")
	}
	d := rep.Discordances[0]
	sheet := filepath.Join(e.dir, "adjudication.csv")
	content := sheetHeader + "x," + d.Image + "," + d.Check + ",crosscheck,e,TP,TP,\n"
	if err := os.WriteFile(sheet, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run("-analyze-only", "-adjudication", sheet)
	if code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if got := e.read(fileMacros); !strings.Contains(got, `\newcommand{\ConUnitXchkResolved}{1}`) {
		t.Errorf("the resolved count is missing:\n%s", got[len(got)-300:])
	}
	if csv := e.read(fileDiscordances); !strings.Contains(csv, "agreed") {
		t.Errorf("discordances.csv must carry the resolution:\n%s", csv)
	}
}

func TestRunRejectsABrokenAdjudicationSheet(t *testing.T) {
	e := newRunEnv(t)
	sheet := filepath.Join(e.dir, "bad.csv")
	if err := os.WriteFile(sheet, []byte(sheetHeader+"a,b,FS-10,crosscheck,e,MAYBE,TP,\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run("-adjudication", sheet)
	if code != spec.ExitFindings || !strings.Contains(stderr, "want TP, FP or UNDECIDABLE") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
	if e.export.calls != 0 {
		t.Error("a broken sheet must stop the run before any export")
	}
	code, _, stderr = e.run("-adjudication", filepath.Join(e.dir, "absent.csv"))
	if code != spec.ExitFindings || !strings.Contains(stderr, "adjudication sheet") {
		t.Errorf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestRunWarnsAboutAnUnverifiedDockleVersion(t *testing.T) {
	e := newRunEnv(t)
	e.dockle.version = "0.4.14"
	code, _, stderr := e.run()
	if code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "0.4.14 differs from "+VerifiedDockleVersion) {
		t.Errorf("stderr lacks the version warning:\n%s", stderr)
	}
	var rep Report
	if err := json.Unmarshal([]byte(e.read(fileJSON)), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Tools.Dockle.Version != "0.4.14" || rep.Tools.Dockle.VersionVerified || rep.Tools.Dockle.SchemaVerifiedAt != VerifiedDockleVersion {
		t.Errorf("dockle info = %+v", rep.Tools.Dockle)
	}
	if !strings.Contains(strings.Join(rep.Warnings, "\n"), "0.4.14 differs") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
}

func TestRunRecordsToolVersionsAndTheEngine(t *testing.T) {
	e := newRunEnv(t)
	if code, _, stderr := e.run(); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var rep Report
	if err := json.Unmarshal([]byte(e.read(fileJSON)), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Tools.Dockle.Version != VerifiedDockleVersion || !rep.Tools.Dockle.VersionVerified ||
		rep.Tools.Engine != "fakeengine version 1.0.0" || rep.Tools.Platform != "linux/amd64" {
		t.Errorf("tools = %+v", rep.Tools)
	}
	if rep.Tools.Dockle.Command != "dockle --input <archive> --format json --exit-code 0" {
		t.Errorf("command = %q", rep.Tools.Dockle.Command)
	}
	if len(rep.ExcludedDockleCodes) != 2 || len(rep.DockleWithoutCounterpart) != 5 || len(rep.Mapping) != 16 {
		t.Errorf("excluded %d, without counterpart %d, mapping %d", len(rep.ExcludedDockleCodes), len(rep.DockleWithoutCounterpart), len(rep.Mapping))
	}
	if rep.Study.File != "empirical_study.json" || len(rep.Study.SHA256) != 64 || rep.Study.PackID != "PACK-IMAGE-LINT" {
		t.Errorf("study = %+v", rep.Study)
	}
}

func TestRunFailures(t *testing.T) {
	t.Run("a dependency that cannot be built", func(t *testing.T) {
		e := newRunEnv(t)
		newDeps = func(config) (deps, error) { return deps{}, errors.New("no OCI container engine found") }
		code, _, stderr := e.run()
		if code != spec.ExitFindings || !strings.Contains(stderr, "no OCI container engine") {
			t.Errorf("exit %d, stderr:\n%s", code, stderr)
		}
	})
	t.Run("a Dockle without a version", func(t *testing.T) {
		e := newRunEnv(t)
		newDeps = func(config) (deps, error) { return deps{Exporter: e.export, Dockle: failingVersion{}}, nil }
		code, _, stderr := e.run()
		if code != spec.ExitFindings || !strings.Contains(stderr, "Dockle version") {
			t.Errorf("exit %d, stderr:\n%s", code, stderr)
		}
	})
	t.Run("a study that is missing", func(t *testing.T) {
		e := newRunEnv(t)
		e.study = filepath.Join(e.dir, "absent.json")
		code, _, stderr := e.run()
		if code != spec.ExitFindings || !strings.Contains(stderr, "cannot load the study") {
			t.Errorf("exit %d, stderr:\n%s", code, stderr)
		}
	})
	t.Run("a study without a completed image", func(t *testing.T) {
		e := newRunEnv(t)
		empty := spec.Study{SchemaVersion: spec.SchemaVersion, Images: []*spec.SuiteResult{{ImageName: "x@sha256:9", RequestedRef: "x@sha256:9", Status: spec.StatusTimeout}}}
		data, _ := json.Marshal(empty)
		if err := os.WriteFile(e.study, data, 0o644); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := e.run()
		if code != spec.ExitIncomplete || !strings.Contains(stderr, "no COMPLETED image") {
			t.Errorf("exit %d, stderr:\n%s", code, stderr)
		}
		if _, err := os.Stat(filepath.Join(e.out, fileMacros)); err != nil {
			t.Errorf("the outputs are still written: %v", err)
		}
	})
}

type failingVersion struct{}

func (failingVersion) Version(context.Context) (string, error) {
	return "", errors.New("exec: not found")
}
func (failingVersion) Run(context.Context, string) (RunOutput, error) {
	return RunOutput{}, errors.New("must not run")
}

func TestUsage(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, spec.ExitUsage},
		{"no study", []string{"-out-dir", "x"}, spec.ExitUsage},
		{"a stray argument", []string{"-study", "s.json", "extra"}, spec.ExitUsage},
		{"a negative limit", []string{"-study", "s.json", "-limit", "-1"}, spec.ExitUsage},
		{"a negative timeout", []string{"-study", "s.json", "-timeout", "-1s"}, spec.ExitUsage},
		{"an unknown flag", []string{"-study", "s.json", "-nope"}, spec.ExitUsage},
		{"help", []string{"-h"}, spec.ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := run(tc.args, &out, &errb); got != tc.want {
				t.Errorf("exit %d, want %d\n%s", got, tc.want, errb.String())
			}
		})
	}
}

func TestRawNameIsReadableAndUnique(t *testing.T) {
	a, b := rawName(keyNginx), rawName(keyRedis)
	if a == b || !strings.HasPrefix(a, "nginx_") && !strings.HasPrefix(a, "nginx-") && !strings.HasPrefix(a, "nginx@") {
		t.Errorf("names = %q, %q", a, b)
	}
	if strings.ContainsAny(a, "/:@ ") {
		t.Errorf("%q is not a safe file name", a)
	}
	// Two references that look alike keep apart.
	if rawName("a/b@sha256:1") == rawName("a_b@sha256:1") {
		t.Error("different references must not share a file name")
	}
}

func TestCoverageSubcommand(t *testing.T) {
	dir := t.TempDir()
	md, tx := filepath.Join(dir, "docs", "COVERAGE_MATRIX.md"), filepath.Join(dir, "table_coverage.tex")
	var out, errb bytes.Buffer
	if code := run([]string{"coverage", "-md", md, "-tex", tx}, &out, &errb); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	gotMD, _ := os.ReadFile(md)
	gotTex, _ := os.ReadFile(tx)
	if string(gotMD) != RenderCoverageMarkdown() || string(gotTex) != RenderCoverageTable() {
		t.Error("the subcommand must write what the generators render")
	}
	if code := run([]string{"coverage"}, &out, &errb); code != spec.ExitUsage {
		t.Errorf("coverage without a target: exit %d, want usage error", code)
	}
}

func TestSelectImages(t *testing.T) {
	l := loadedStudy(
		cuImage("index.docker.io/library/b@sha256:2"), cuImage("index.docker.io/library/a@sha256:1"),
		&spec.SuiteResult{ImageName: "c@sha256:3", RequestedRef: "c@sha256:3", Status: spec.StatusRateLimited},
	)
	keys, unmatched := selectImages(l, "", 0)
	if len(keys) != 2 || keys[0] != "index.docker.io/library/a@sha256:1" || len(unmatched) != 0 {
		t.Errorf("keys = %v, unmatched = %v", keys, unmatched)
	}
	keys, unmatched = selectImages(l, " a , a ,, zzz", 0)
	if len(keys) != 1 || len(unmatched) != 1 || unmatched[0] != "zzz" {
		t.Errorf("duplicates and blanks: keys = %v, unmatched = %v", keys, unmatched)
	}
	keys, _ = selectImages(l, "", 1)
	if len(keys) != 1 {
		t.Errorf("limit 1 = %v", keys)
	}
}
