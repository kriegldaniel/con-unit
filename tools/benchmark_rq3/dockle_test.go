package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

// fakeComparator answers Time from a function of the image and the number of the
// call for that image, and records the calls.
type fakeComparator struct {
	timing    func(image string, n int) (DockleTiming, error)
	calls     []string
	perImage  map[string]int
	deadlines []bool
}

func (f *fakeComparator) Time(ctx context.Context, image string) (DockleTiming, error) {
	if f.perImage == nil {
		f.perImage = map[string]int{}
	}
	f.perImage[image]++
	f.calls = append(f.calls, image)
	_, hasDeadline := ctx.Deadline()
	f.deadlines = append(f.deadlines, hasDeadline)
	return f.timing(image, f.perImage[image])
}

func fixedTiming(export, run time.Duration) func(string, int) (DockleTiming, error) {
	return func(string, int) (DockleTiming, error) { return DockleTiming{Export: export, Run: run}, nil }
}

func dockleCfg(c Comparator) BenchConfig {
	cfg := baseCfg()
	cfg.Dockle = c
	return cfg
}

func TestDockleIsTimedAfterEveryWarmupAndTimedTrial(t *testing.T) {
	h := newFake(map[string][]step{"img": okSteps(time.Second)})
	c := &fakeComparator{timing: fixedTiming(400*time.Millisecond, 600*time.Millisecond)}
	cfg := dockleCfg(c)
	cfg.ColdTrials = 2
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())

	if got, want := len(c.calls), cfg.Warmup+cfg.Iterations; got != want {
		t.Fatalf("comparator calls = %d, want %d (warm-up and timed trials, no cold trial)", got, want)
	}
	for _, tr := range append(append([]TrialRecord{}, res.Warmup...), res.Trials...) {
		if !tr.DockleDone() || *tr.DockleExportMs != 400 || *tr.DockleRunMs != 600 || tr.DockleError != "" {
			t.Errorf("%s %d: dockle = %v %v %q", tr.Kind, tr.Iteration, tr.DockleExportMs, tr.DockleRunMs, tr.DockleError)
		}
	}
	if len(res.Cold) != 2 {
		t.Fatalf("cold trials = %d", len(res.Cold))
	}
	for _, tr := range res.Cold {
		if tr.DockleExportMs != nil || tr.DockleRunMs != nil || tr.DockleError != "" {
			t.Errorf("a cold trial must not be compared: %+v", tr)
		}
	}
	for i, has := range c.deadlines {
		if !has {
			t.Errorf("call %d had no deadline, the comparison needs the trial timeout", i)
		}
	}
	d := res.Stats.Dockle
	if d == nil || d.Total.N != cfg.Iterations || d.Total.Median != 1000 || d.Export.Median != 400 || d.Run.Median != 600 || d.Total.Unit != "ms" {
		t.Fatalf("dockle stats = %+v", d)
	}
}

func TestWarmupDockleTimesDoNotEnterTheStatistics(t *testing.T) {
	h := newFake(map[string][]step{"img": okSteps(time.Second)})
	// The first call is the warm-up with an absurd value.
	c := &fakeComparator{timing: func(_ string, n int) (DockleTiming, error) {
		if n == 1 {
			return DockleTiming{Export: time.Hour, Run: time.Hour}, nil
		}
		return DockleTiming{Export: 100 * time.Millisecond, Run: 200 * time.Millisecond}, nil
	}}
	res := BenchmarkImage(context.Background(), h, &memSink{}, dockleCfg(c), "img", discard())
	if d := res.Stats.Dockle; d == nil || d.Total.Max != 300 || d.Total.N != 5 {
		t.Errorf("dockle stats = %+v, the warm-up must not be counted", d)
	}
}

func TestDockleIsNotTimedWithoutAComparatorOrForAFailedTrial(t *testing.T) {
	// No comparator: no field, no statistics.
	h := newFake(map[string][]step{"img": okSteps(time.Second)})
	res := BenchmarkImage(context.Background(), h, &memSink{}, baseCfg(), "img", discard())
	if res.Stats.Dockle != nil {
		t.Error("no dockle statistics without -dockle")
	}
	data, _ := json.Marshal(res.Trials[0])
	if strings.Contains(string(data), "dockle") {
		t.Errorf("a trial without a comparison must not mention dockle: %s", data)
	}

	// A failed trial of ConUnit is not compared.
	// The warm-up and the first timed trial succeed, the second timed trial fails.
	steps := []step{{res: okResult(time.Second)}, {res: okResult(time.Second)}, {err: errors.New("engine inspect failed")}, {res: okResult(time.Second)}, {res: okResult(time.Second)}, {res: okResult(time.Second)}}
	c := &fakeComparator{timing: fixedTiming(time.Millisecond, time.Millisecond)}
	out := BenchmarkImage(context.Background(), newFake(map[string][]step{"img": steps}), &memSink{}, dockleCfg(c), "img", discard())
	if out.Trials[0].OK() != true || out.Trials[0].DockleDone() != true {
		t.Errorf("trial 1 = %+v", out.Trials[0])
	}
	failed := out.Trials[0]
	for _, tr := range out.Trials {
		if !tr.OK() {
			failed = tr
		}
	}
	if failed.OK() || failed.DockleDone() || failed.DockleError != "" {
		t.Errorf("the failed trial must stay without a comparison: %+v", failed)
	}
	if len(c.calls) != 5 {
		t.Errorf("comparator calls = %d, want the 5 successful trials of the 6", len(c.calls))
	}
}

func TestDockleFailuresAreRecordedPerPhase(t *testing.T) {
	h := newFake(map[string][]step{"img": okSteps(time.Second)})
	c := &fakeComparator{timing: func(_ string, n int) (DockleTiming, error) {
		switch n {
		case 2: // the analysis fails after a real export
			return DockleTiming{Export: 50 * time.Millisecond, Run: 10 * time.Millisecond}, &ComparatorError{Phase: PhaseAnalysis, Err: errors.New("exit status 1")}
		case 3: // the export fails
			return DockleTiming{Export: 5 * time.Millisecond}, &ComparatorError{Phase: PhaseExport, Err: errors.New("no space left")}
		case 4: // an error of another kind
			return DockleTiming{}, errors.New("unexpected")
		}
		return DockleTiming{Export: 100 * time.Millisecond, Run: 300 * time.Millisecond}, nil
	}}
	cfg := dockleCfg(c)
	cfg.Warmup = 0
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())
	tr := res.Trials
	if !tr[0].DockleDone() {
		t.Errorf("trial 1 = %+v", tr[0])
	}
	if tr[1].DockleExportMs == nil || *tr[1].DockleExportMs != 50 || tr[1].DockleRunMs != nil || !strings.Contains(tr[1].DockleError, "dockle analysis") {
		t.Errorf("analysis failure: %+v", tr[1])
	}
	if tr[2].DockleExportMs != nil || tr[2].DockleRunMs != nil || !strings.Contains(tr[2].DockleError, "dockle export: no space left") {
		t.Errorf("export failure: %+v", tr[2])
	}
	if tr[3].DockleError != "unexpected" || tr[3].DockleDone() {
		t.Errorf("other failure: %+v", tr[3])
	}
	for i := range tr {
		if !tr[i].OK() {
			t.Errorf("trial %d: a failure of the comparison must not fail the ConUnit trial", i+1)
		}
	}
	// Only trials with both durations enter the statistics.
	if d := res.Stats.Dockle; d == nil || d.Total.N != 2 || d.Total.Median != 400 {
		t.Errorf("dockle stats = %+v, want the 2 trials with both durations", d)
	}
	if res.Stats.Total.N != 5 {
		t.Errorf("ConUnit statistics must keep all 5 trials, got %d", res.Stats.Total.N)
	}
}

func TestDockleStatsAreAbsentWhenNoTrialHasBothDurations(t *testing.T) {
	h := newFake(map[string][]step{"img": okSteps(time.Second)})
	c := &fakeComparator{timing: func(string, int) (DockleTiming, error) {
		return DockleTiming{}, &ComparatorError{Phase: PhaseExport, Err: errors.New("boom")}
	}}
	res := BenchmarkImage(context.Background(), h, &memSink{}, dockleCfg(c), "img", discard())
	if res.Stats.Dockle != nil {
		t.Errorf("dockle stats = %+v", res.Stats.Dockle)
	}
}

func TestTimeDockleUnit(t *testing.T) {
	ok := TrialRecord{Image: "img", Status: spec.StatusCompleted}
	bad := TrialRecord{Image: "img", Status: spec.StatusTimeout}
	c := &fakeComparator{timing: fixedTiming(1500*time.Microsecond, 2*time.Millisecond)}

	timeDockle(context.Background(), nil, &ok, time.Second)
	if ok.DockleDone() {
		t.Error("a nil comparator must record nothing")
	}
	timeDockle(context.Background(), c, &bad, time.Second)
	if bad.DockleDone() || len(c.calls) != 0 {
		t.Error("a failed trial must not be compared")
	}
	timeDockle(context.Background(), c, &ok, 0)
	if !ok.DockleDone() || *ok.DockleExportMs != 1.5 || *ok.DockleRunMs != 2 {
		t.Errorf("record = %v %v", ok.DockleExportMs, ok.DockleRunMs)
	}
	if c.deadlines[0] {
		t.Error("a zero timeout means no deadline")
	}
}

func TestMillisecondsKeepMicrosecondResolution(t *testing.T) {
	cases := map[time.Duration]float64{0: 0, time.Microsecond: 0.001, 1234567 * time.Nanosecond: 1.234, 2 * time.Second: 2000}
	for d, want := range cases {
		if got := *ms(d); got != want {
			t.Errorf("ms(%s) = %v, want %v", d, got, want)
		}
	}
}

func TestDockleArgumentsAreThoseOfTheContract(t *testing.T) {
	got := strings.Join(dockleArgs("/tmp/a.tar"), " ")
	if got != "--input /tmp/a.tar --format json --exit-code 0" {
		t.Errorf("args = %q, docs/INTERFACE_V2.md section 4 fixes them", got)
	}
}

func TestValidateDockleOptions(t *testing.T) {
	cases := []struct {
		name, dockle, source string
		wantErr              bool
	}{
		{"off", "", "registry", false},
		{"on with auto", "dockle", "auto", false},
		{"on with local", "dockle", "local", false},
		{"on with registry", "dockle", "registry", true},
	}
	for _, tc := range cases {
		if err := ValidateDockleOptions(tc.dockle, tc.source); (err != nil) != tc.wantErr {
			t.Errorf("%s: error = %v", tc.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Across images and the macros

func imageWith(key string, exportMs, runMs float64, n int) ImageResult {
	var trials []TrialRecord
	for i := 1; i <= n; i++ {
		e, r := exportMs, runMs
		trials = append(trials, TrialRecord{Image: key, Kind: KindTimed, Iteration: i, Status: spec.StatusCompleted, TotalNs: int64(time.Second), DockleExportMs: &e, DockleRunMs: &r})
	}
	return ImageResult{Ref: key, Repository: key, MacroKey: key, Status: ImageCompleted, Trials: trials, Stats: computePhaseStats(trials)}
}

func TestDockleAcrossImagesUsesMediansOfMediansInSeconds(t *testing.T) {
	images := []ImageResult{
		imageWith("a", 400, 600, 3),     // 1.0 s in total
		imageWith("b", 1000, 3000, 3),   // 4.0 s
		imageWith("c", 2000, 6000, 3),   // 8.0 s
		{Ref: "d", Status: ImageFailed}, // no statistics
	}
	s := Summarize(images, 4)
	if s.Dockle == nil || s.Dockle.Images != 3 {
		t.Fatalf("dockle summary = %+v", s.Dockle)
	}
	if s.Dockle.Total.Median != 4 || s.Dockle.Export.Median != 1 || s.Dockle.Run.Median != 3 || s.Dockle.Total.Unit != "s" {
		t.Errorf("medians = %v %v %v", s.Dockle.Total.Median, s.Dockle.Export.Median, s.Dockle.Run.Median)
	}
	if s := Summarize([]ImageResult{{Ref: "x", Status: ImageFailed}}, 1); s.Dockle != nil {
		t.Error("no dockle summary without data")
	}
}

var macroLine = regexp.MustCompile(`(?m)^\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}$`)

func macrosOf(t *testing.T, text string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range macroLine.FindAllStringSubmatch(text, -1) {
		if _, dup := out[m[1]]; dup {
			t.Errorf("macro %s defined twice", m[1])
		}
		out[m[1]] = m[2]
	}
	return out
}

func telemetryWith(t *testing.T, images []ImageResult, treatments []string, windowMs int64) *Telemetry {
	t.Helper()
	run := testRun()
	run.ProbeWindowMs = windowMs
	return &Telemetry{
		SchemaVersion: TelemetrySchemaVersion, Run: run,
		Protocol: Protocol{Pack: "cis", TimedTrials: 3, Tier3Treatments: treatments},
		Summary:  Summarize(images, len(images)), Images: images,
	}
}

func TestDockleMacros(t *testing.T) {
	images := []ImageResult{imageWith("a", 400, 600, 3), imageWith("b", 1000, 3000, 3), imageWith("c", 2000, 6000, 3)}
	text := RenderMacros(telemetryWith(t, images, []string{"EXEC-01"}, 3000))
	got := macrosOf(t, text)
	want := map[string]string{
		"ConUnitRqThreeDockleMedian": "4.000", "ConUnitRqThreeDockleExportMedian": "1.000", "ConUnitRqThreeDockleRunMedian": "3.000",
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %q, want %q", name, got[name], v)
		}
	}
	if !strings.Contains(text, "plain numbers without a unit") {
		t.Error("the macro comment must state that the values are plain numbers in seconds")
	}
}

func TestDockleMacrosPrintNotAvailableWithoutDockle(t *testing.T) {
	images := []ImageResult{{Ref: "a", Repository: "a", MacroKey: "a", Status: ImageCompleted, Stats: computePhaseStats([]TrialRecord{{Status: spec.StatusCompleted, TotalNs: 1}})}}
	got := macrosOf(t, RenderMacros(telemetryWith(t, images, []string{"EXEC-01"}, 3000)))
	for _, name := range []string{"ConUnitRqThreeDockleMedian", "ConUnitRqThreeDockleExportMedian", "ConUnitRqThreeDockleRunMedian"} {
		if got[name] != "n/a" {
			t.Errorf("%s = %q, want n/a: a missing comparison must not read as zero", name, got[name])
		}
	}
}

func TestDockleTimesReachTheTelemetryAndTheOutputs(t *testing.T) {
	images := []string{"index.docker.io/library/alpine@sha256:aaaa", "index.docker.io/library/nginx@sha256:bbbb"}
	h := newFake(map[string][]step{images[0]: okSteps(time.Second), images[1]: okSteps(time.Second)})
	s := testSetup(t, images, 0)
	c := &fakeComparator{timing: func(image string, _ int) (DockleTiming, error) {
		if strings.Contains(image, "nginx") {
			return DockleTiming{Export: 3 * time.Second, Run: time.Second}, nil
		}
		return DockleTiming{Export: time.Second, Run: time.Second}, nil
	}}
	s.Bench.Dockle = c
	s.Protocol.Tier3Treatments = []string{"EXEC-01", "EXEC-02"}
	s.Protocol.Tier3FloorNote = tier3FloorNote
	s.Protocol.DockleBinary, s.Protocol.DockleVersion, s.Protocol.DockleNote = "/usr/bin/dockle", "dockle version 0.4.15", methodDockle
	if _, err := RunAll(context.Background(), h, &memSink{}, s); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(s.OutDir, telemetryFile))
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	trial := back["images"].([]any)[0].(map[string]any)["trials"].([]any)[0].(map[string]any)
	if trial["dockle_export_ms"] == nil || trial["dockle_run_ms"] == nil {
		t.Errorf("a timed trial lacks the dockle fields of the contract: %v", trial)
	}
	macros := macrosOf(t, readOut(t, s.OutDir, macrosFile))
	if macros["ConUnitRqThreeDockleMedian"] != "3.000" || macros["ConUnitRqThreeDockleExportMedian"] != "2.000" || macros["ConUnitRqThreeDockleRunMedian"] != "1.000" {
		t.Errorf("macros = %v", macros)
	}
	md := readOut(t, s.OutDir, markdownFile)
	if !strings.Contains(md, "## Dockle comparison") || !strings.Contains(md, "dockle version 0.4.15") || !strings.Contains(md, "Tier 3 floor in seconds") {
		t.Errorf("RQ3_PERFORMANCE.md lacks the Dockle section or the method statements:\n%s", md)
	}
}

func readOut(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ---------------------------------------------------------------------------
// The production comparator against fake binaries

// fakeToolchain writes an engine that is named podman and a dockle binary. The
// engine writes an archive for `save`, dockle checks that the archive exists.
func fakeToolchain(t *testing.T) (enginePath, docklePath, logFile string) {
	t.Helper()
	dir := t.TempDir()
	logFile = filepath.Join(dir, "calls.log")
	enginePath = filepath.Join(dir, "podman")
	engineScript := `#!/usr/bin/env bash
echo "podman $*" >> "$FAKE_LOG"
if [ "$1" = save ]; then
  [ "$FAKE_SAVE" = fail ] && { echo "Error: no such image" >&2; exit 125; }
  out=""
  while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
  [ "$FAKE_SAVE" = empty ] && { : > "$out"; exit 0; }
  sleep 0.05
  echo "archive" > "$out"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(enginePath, []byte(engineScript), 0o755); err != nil {
		t.Fatal(err)
	}
	docklePath = filepath.Join(dir, "dockle")
	dockleScript := `#!/usr/bin/env bash
echo "dockle $*" >> "$FAKE_LOG"
if [ "$1" = "--version" ]; then
  case "$FAKE_VERSION" in
    fail) exit 3 ;;
    empty) exit 0 ;;
  esac
  echo "dockle version 0.4.15"
  echo "second line"
  exit 0
fi
input=""
while [ $# -gt 0 ]; do [ "$1" = "--input" ] && input="$2"; shift; done
[ -s "$input" ] || { echo "archive missing" >&2; exit 2; }
[ "$FAKE_DOCKLE" = fail ] && { echo "FATAL   - failed to analyze   the   image" >&2; exit 1; }
sleep 0.05
echo '{"summary":{}}'
exit 0
`
	if err := os.WriteFile(docklePath, []byte(dockleScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_LOG", logFile)
	return enginePath, docklePath, logFile
}

func leftoverArchives(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestDockleRunnerTimesExportAndAnalysisApart(t *testing.T) {
	enginePath, docklePath, logFile := fakeToolchain(t)
	tmp := t.TempDir()
	d := &DockleRunner{Engine: &engine.Engine{BinaryPath: enginePath}, Binary: docklePath, TempDir: tmp}
	timing, err := d.Time(context.Background(), "localhost/img:1")
	if err != nil {
		t.Fatal(err)
	}
	if timing.Export < 40*time.Millisecond || timing.Run < 40*time.Millisecond {
		t.Errorf("timing = %+v, each fake tool sleeps 50 ms", timing)
	}
	data, _ := os.ReadFile(logFile)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "podman save --format docker-archive -o ") || !strings.HasSuffix(lines[0], " localhost/img:1") {
		t.Fatalf("engine call = %v", lines)
	}
	if !strings.Contains(lines[1], "--format json --exit-code 0") || !strings.HasPrefix(lines[1], "dockle --input ") {
		t.Errorf("dockle call = %q", lines[1])
	}
	if left := leftoverArchives(t, tmp); len(left) != 0 {
		t.Errorf("the temporary archive must be removed, left %v", left)
	}
}

func TestDockleRunnerFailures(t *testing.T) {
	cases := []struct {
		name, env, value string
		phase            string
		contains         string
		exportKept       bool
	}{
		{"the engine cannot save", "FAKE_SAVE", "fail", PhaseExport, "no such image", false},
		{"the engine writes an empty archive", "FAKE_SAVE", "empty", PhaseExport, "wrote no archive", false},
		{"dockle fails", "FAKE_DOCKLE", "fail", PhaseAnalysis, "failed to analyze the image", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enginePath, docklePath, _ := fakeToolchain(t)
			t.Setenv(tc.env, tc.value)
			tmp := t.TempDir()
			d := &DockleRunner{Engine: &engine.Engine{BinaryPath: enginePath}, Binary: docklePath, TempDir: tmp}
			timing, err := d.Time(context.Background(), "img")
			var ce *ComparatorError
			if !errors.As(err, &ce) || ce.Phase != tc.phase || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error = %v, want phase %s containing %q", err, tc.phase, tc.contains)
			}
			if tc.exportKept && timing.Export <= 0 {
				t.Errorf("a failed analysis keeps the export time: %+v", timing)
			}
			if tc.phase == PhaseExport && timing.Run != 0 {
				t.Errorf("no analysis ran, timing = %+v", timing)
			}
			if left := leftoverArchives(t, tmp); len(left) != 0 {
				t.Errorf("temporary files left behind: %v", left)
			}
		})
	}
}

func TestDockleRunnerMissingBinaryAndCancellation(t *testing.T) {
	enginePath, _, _ := fakeToolchain(t)
	d := &DockleRunner{Engine: &engine.Engine{BinaryPath: enginePath}, Binary: filepath.Join(t.TempDir(), "nope"), TempDir: t.TempDir()}
	_, err := d.Time(context.Background(), "img")
	var ce *ComparatorError
	if !errors.As(err, &ce) || ce.Phase != PhaseAnalysis {
		t.Errorf("a missing dockle binary is an analysis failure, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Time(ctx, "img"); err == nil {
		t.Error("a cancelled context must fail the comparison")
	}
}

func TestPrepareDockle(t *testing.T) {
	_, docklePath, _ := fakeToolchain(t)
	path, version, err := PrepareDockle(docklePath)
	if err != nil || path != docklePath || version != "dockle version 0.4.15" {
		t.Errorf("path %q, version %q, err %v: the version is the first line, verbatim", path, version, err)
	}
	if _, _, err := PrepareDockle(filepath.Join(t.TempDir(), "nope")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing binary: %v", err)
	}
	t.Setenv("FAKE_VERSION", "fail")
	if _, _, err := PrepareDockle(docklePath); err == nil || !strings.Contains(err.Error(), "--version failed") {
		t.Errorf("failing version probe: %v", err)
	}
	t.Setenv("FAKE_VERSION", "empty")
	if _, _, err := PrepareDockle(docklePath); err == nil || !strings.Contains(err.Error(), "printed nothing") {
		t.Errorf("silent version probe: %v", err)
	}
}
