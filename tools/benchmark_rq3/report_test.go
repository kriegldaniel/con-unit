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

	"github.com/con-unit/con-unit/pkg/spec"
)

func boolPtr(b bool) *bool { return &b }

// testRun is a RunMetadata like the one runenv.Detect fills on the AWS host.
func testRun() spec.RunMetadata {
	return spec.RunMetadata{
		ConUnitVersion: "dev",
		Commit:         "0123456789abcdef",
		GoVersion:      "go1.26",
		Pack:           "cis",
		PackID:         "PACK-CONUNIT-HARDENING",
		Platform:       "linux/amd64",
		ProbeWindowMs:  3000,
		EngineName:     "podman",
		EngineVersion:  "5.8.1",
		Rootless:       boolPtr(false),
		CgroupVersion:  "v2",
		HostOS:         "linux",
		HostArch:       "amd64",
		LinuxKernel:    "6.8.0-1018-aws",
		CPUModel:       "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz & friends 100%",
		VCPUs:          8,
		MemoryBytes:    16 << 30,
		Virtualization: "aws-nitro-kvm",
		ExecutionMode:  "Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2",
		CloudProvider:  "aws",
		InstanceType:   "c6i.2xlarge",
		StartedAt:      time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC),
	}
}

func testSetup(t *testing.T, images []string, cold int) Setup {
	t.Helper()
	arch, err := LoadArchetypes("testdata/archetypes.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := baseCfg()
	cfg.ColdTrials = cold
	return Setup{
		Images: images,
		Bench:  cfg,
		Protocol: Protocol{
			Pack: "cis", PackID: "PACK-CONUNIT-HARDENING", TimedTrials: cfg.Iterations, WarmupTrials: cfg.Warmup, ColdTrials: cold,
			ArchetypesFile: "testdata/archetypes.json", ArchetypesLoaded: true,
			QuantileMethod: methodQuantiles, CIMethod: methodCI, Tier3Note: methodTier3, ColdNote: methodCold,
			MemoryNote: methodMemory, CPUNote: methodCPU,
		},
		Run:        testRun(),
		Archetypes: arch,
		OutDir:     t.TempDir(),
		Log:        discard(),
	}
}

func okSteps(base time.Duration) []step {
	var steps []step
	for i := 0; i < 6; i++ {
		steps = append(steps, step{res: okResult(base + time.Duration(i)*time.Millisecond)})
	}
	return steps
}

// TestRunAllWithPartialFailures runs three images where one always fails and
// one fails in some trials. The run continues, every output is written and
// the failures are visible in all of them.
func TestRunAllWithPartialFailures(t *testing.T) {
	images := []string{
		"index.docker.io/library/alpine@sha256:aaaa",
		"index.docker.io/library/nginx@sha256:bbbb",
		"index.docker.io/library/python:3.12-alpine",
	}
	flaky := okSteps(2 * time.Second)
	flaky[3] = step{err: errors.New("engine inspect failed")}
	h := newFake(map[string][]step{
		images[0]: okSteps(time.Second),
		images[1]: {{err: errors.New("manifest unknown")}},
		images[2]: flaky,
	})
	s := testSetup(t, images, 0)
	sink := &memSink{}
	tel, err := RunAll(context.Background(), h, sink, s)
	if err != nil {
		t.Fatal(err)
	}

	if len(tel.Images) != 3 {
		t.Fatalf("images = %d, the failing image must stay in the record", len(tel.Images))
	}
	status := map[string]string{}
	for _, img := range tel.Images {
		status[img.Repository] = img.Status
	}
	if status["alpine"] != ImageCompleted || status["nginx"] != ImageFailed || status["python"] != ImagePartial {
		t.Errorf("statuses = %v", status)
	}
	if tel.Summary.ImagesCompleted != 1 || tel.Summary.ImagesFailed != 1 || tel.Summary.ImagesPartial != 1 || tel.Summary.ImagesRequested != 3 {
		t.Errorf("summary = %+v", tel.Summary)
	}
	if !tel.Complete || tel.Run.FinishedAt.IsZero() {
		t.Errorf("complete %t finished %v", tel.Complete, tel.Run.FinishedAt)
	}

	// Archetypes come from the table, not from the name.
	for _, img := range tel.Images {
		if img.Repository == "python" && (img.Archetype != "language-runtime" || img.BaseFamily != "debian") {
			t.Errorf("python image archetype = %s/%s", img.Archetype, img.BaseFamily)
		}
	}

	for _, name := range []string{telemetryFile, markdownFile, tableFile, macrosFile} {
		info, err := os.Stat(filepath.Join(s.OutDir, name))
		if err != nil || info.Size() == 0 {
			t.Errorf("output %s missing or empty: %v", name, err)
		}
	}
	entries, _ := os.ReadDir(s.OutDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}

	// The telemetry JSON carries the run block and the per-image trials.
	data, err := os.ReadFile(filepath.Join(s.OutDir, telemetryFile))
	if err != nil {
		t.Fatal(err)
	}
	var back Telemetry
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Run.Virtualization != "aws-nitro-kvm" || back.Run.EngineVersion != "5.8.1" || back.SchemaVersion != TelemetrySchemaVersion {
		t.Errorf("run block lost: %+v", back.Run)
	}
	for _, img := range back.Images {
		if img.Repository == "nginx" {
			if len(img.Trials) == 0 || img.Trials[0].Error != "manifest unknown" || img.Trials[0].Status != spec.StatusExecutionError {
				t.Errorf("failed image trials = %+v", img.Trials)
			}
		}
	}
	if strings.Contains(string(data), "Bare-Metal") {
		t.Error("the telemetry must not contain the old hard-coded environment label")
	}

	md, _ := os.ReadFile(filepath.Join(s.OutDir, markdownFile))
	if !strings.Contains(string(md), "manifest unknown") || !strings.Contains(string(md), "FAILED") || !strings.Contains(string(md), "PARTIAL") {
		t.Errorf("failures must appear in the markdown report:\n%s", md)
	}
}

func TestRunAllInterruptedStillWritesOutputs(t *testing.T) {
	images := []string{"alpine", "nginx", "redis"}
	h := newFake(map[string][]step{"alpine": okSteps(time.Second), "nginx": okSteps(time.Second), "redis": okSteps(time.Second)})
	ctx, cancel := context.WithCancel(context.Background())
	h.onRun = func(image string, n int) {
		if image == "nginx" && n == 2 {
			cancel()
		}
	}
	s := testSetup(t, images, 0)
	tel, err := RunAll(ctx, h, &memSink{}, s)
	if err != nil {
		t.Fatal(err)
	}
	if tel.Complete {
		t.Error("an interrupted run must not be marked complete")
	}
	if len(tel.Images) != 2 {
		t.Errorf("images = %d, want alpine and the interrupted nginx", len(tel.Images))
	}
	if !tel.Images[1].Interrupted {
		t.Error("nginx must be flagged interrupted")
	}
	found := false
	for _, w := range tel.Protocol.Warnings {
		if strings.Contains(w, "interrupted") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v", tel.Protocol.Warnings)
	}
	md, err := os.ReadFile(filepath.Join(s.OutDir, markdownFile))
	if err != nil || !strings.Contains(string(md), "did not finish") {
		t.Errorf("markdown of an interrupted run must say so: %v", err)
	}
}

func TestRunAllWritesSnapshotAfterEveryImage(t *testing.T) {
	images := []string{"alpine", "nginx"}
	h := newFake(map[string][]step{"alpine": okSteps(time.Second), "nginx": okSteps(time.Second)})
	s := testSetup(t, images, 0)
	h.onRun = func(image string, n int) {
		if image == "nginx" && n == 1 {
			// While the second image runs, the first one is already on disk.
			data, err := os.ReadFile(filepath.Join(s.OutDir, telemetryFile))
			if err != nil {
				t.Errorf("no snapshot while image 2 runs: %v", err)
				return
			}
			var snap Telemetry
			if err := json.Unmarshal(data, &snap); err != nil || len(snap.Images) != 1 || snap.Complete {
				t.Errorf("snapshot = %d images, complete %t, err %v", len(snap.Images), snap.Complete, err)
			}
		}
	}
	if _, err := RunAll(context.Background(), h, &memSink{}, s); err != nil {
		t.Fatal(err)
	}
}

func TestRunAllWritesOutputsBeforeRepanicking(t *testing.T) {
	h := newFake(map[string][]step{"alpine": okSteps(time.Second), "nginx": okSteps(time.Second)})
	s := testSetup(t, []string{"alpine", "nginx"}, 0)
	h.onRun = func(image string, n int) {
		if image == "nginx" {
			panic("simulated crash")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic must propagate after the outputs are written")
			}
		}()
		_, _ = RunAll(context.Background(), h, &memSink{}, s)
	}()
	data, err := os.ReadFile(filepath.Join(s.OutDir, telemetryFile))
	if err != nil {
		t.Fatalf("telemetry missing after a panic: %v", err)
	}
	var snap Telemetry
	if err := json.Unmarshal(data, &snap); err != nil || len(snap.Images) != 1 || snap.Complete {
		t.Errorf("snapshot = %d images complete %t err %v", len(snap.Images), snap.Complete, err)
	}
	if len(snap.Protocol.Warnings) == 0 || !strings.Contains(snap.Protocol.Warnings[len(snap.Protocol.Warnings)-1], "panic") {
		t.Errorf("warnings = %v", snap.Protocol.Warnings)
	}
}

var (
	macroDef  = regexp.MustCompile(`(?m)^\\newcommand\{\\([^}]*)\}\{(.*)\}$`)
	macroName = regexp.MustCompile(`^[A-Za-z]+$`)
)

func TestMacrosArePerImageAndLettersOnly(t *testing.T) {
	images := []string{
		"index.docker.io/library/alpine@sha256:aaaa",
		"index.docker.io/library/nginx@sha256:bbbb",
		"docker.io/library/python:3.12-alpine",
	}
	h := newFake(map[string][]step{images[0]: okSteps(time.Second), images[1]: okSteps(2 * time.Second), images[2]: okSteps(3 * time.Second)})
	s := testSetup(t, images, 1)
	tel, err := RunAll(context.Background(), h, &memSink{}, s)
	if err != nil {
		t.Fatal(err)
	}
	tex := RenderMacros(tel)
	defs := macroDef.FindAllStringSubmatch(tex, -1)
	if len(defs) == 0 {
		t.Fatal("no macros generated")
	}
	seen := map[string]bool{}
	for _, d := range defs {
		name := d[1]
		if !macroName.MatchString(name) {
			t.Errorf("macro name %q must contain letters only", name)
		}
		if seen[name] {
			t.Errorf("macro %s defined twice", name)
		}
		seen[name] = true
	}

	// Per-image macros exist for every image and carry the image key.
	for _, key := range []string{"Alpine", "Nginx", "PythonThreeOneTwoAlpine"} {
		for _, metric := range []string{"TotalMedianMs", "TierThreeMedianMs", "StreamIndexMedianMs", "TotalIQRMs", "TotalMeanMs", "TotalCIHalfMs", "NTrials", "Status", "ColdTotalMedianMs"} {
			name := "ConUnitRQThree" + metric + key
			if !seen[name] {
				t.Errorf("missing macro %s", name)
			}
		}
	}
	// The old global macros took the first image only and must be gone.
	for _, old := range []string{"ConUnitMeanDurationMs", "ConUnitStdDevMs", "ConUnitMedianDurationMs", "ConUnitCIHalfWidthMs", "ConUnitPeakRSSMB", "ConUnitColdSpeedup", "ConUnitBenchmarkRepetitions"} {
		if seen[old] {
			t.Errorf("legacy global macro %s must not exist", old)
		}
	}
	// Values differ per image: the macro is not a first-image shortcut.
	values := map[string]string{}
	for _, d := range defs {
		values[d[1]] = d[2]
	}
	if values["ConUnitRQThreeTotalMedianMsAlpine"] == values["ConUnitRQThreeTotalMedianMsNginx"] {
		t.Error("per-image medians must differ for different images")
	}
	if values["ConUnitRQThreeTotalMedianMsAlpine"] != "1003.000" {
		t.Errorf("alpine median = %s, want 1003.000 (median of 1001..1005 ms, the 1000 ms warm-up is discarded)", values["ConUnitRQThreeTotalMedianMsAlpine"])
	}
	if values["ConUnitRQThreeNImages"] != "3" || values["ConUnitRQThreeTimedTrials"] != "5" {
		t.Errorf("global macros = %v %v", values["ConUnitRQThreeNImages"], values["ConUnitRQThreeTimedTrials"])
	}
	// Environment macros are LaTeX-escaped.
	if got := values["ConUnitRQThreeEnvCPU"]; !strings.Contains(got, `\&`) || !strings.Contains(got, `100\%`) || strings.Contains(got, "( ") {
		t.Errorf("CPU macro value not escaped: %s", got)
	}
	if values["ConUnitRQThreeEnvVirt"] != "aws-nitro-kvm" || values["ConUnitRQThreeEnvInstanceType"] != "c6i.2xlarge" {
		t.Errorf("environment macros = %v / %v", values["ConUnitRQThreeEnvVirt"], values["ConUnitRQThreeEnvInstanceType"])
	}
	if values["ConUnitRQThreeEnvDate"] != "2026-11-14" {
		t.Errorf("date macro = %s", values["ConUnitRQThreeEnvDate"])
	}
	if values["ConUnitRQThreeProbeWindowMs"] != "3000" {
		t.Errorf("probe window macro = %s", values["ConUnitRQThreeProbeWindowMs"])
	}
	// Across-image macros are present.
	if !seen["ConUnitRQThreeAcrossTotalMedianMs"] || !seen["ConUnitRQThreeAcrossTierThreeMaxMs"] {
		t.Error("across-image macros missing")
	}
}

func TestMacrosForImageWithoutStatistics(t *testing.T) {
	h := newFake(map[string][]step{"nginx": {{err: errors.New("down")}}})
	s := testSetup(t, []string{"nginx"}, 0)
	tel, err := RunAll(context.Background(), h, &memSink{}, s)
	if err != nil {
		t.Fatal(err)
	}
	tex := RenderMacros(tel)
	if !strings.Contains(tex, `\newcommand{\ConUnitRQThreeStatusNginx}{FAILED}`) || !strings.Contains(tex, `\newcommand{\ConUnitRQThreeNTrialsNginx}{0}`) {
		t.Errorf("a failed image needs status and count macros:\n%s", tex)
	}
	if strings.Contains(tex, "TotalMedianMsNginx") {
		t.Error("no timing macros without successful trials")
	}
}

func TestReportsContainNoConclusionsAndLabelNetworkDependence(t *testing.T) {
	h := newFake(map[string][]step{"alpine": okSteps(time.Second)})
	s := testSetup(t, []string{"alpine"}, 1)
	tel, err := RunAll(context.Background(), h, &memSink{}, s)
	if err != nil {
		t.Fatal(err)
	}
	md := RenderMarkdown(tel)
	table := RenderTable(tel)
	macros := RenderMacros(tel)

	for _, banned := range []string{"Scientific Discussion", "Discussion", "speedup", "Speedup", "Zero-Bloat", "Bare-Metal", "sub-second", "confirming", "demonstrat", "inferArchetype"} {
		for name, doc := range map[string]string{"markdown": md, "table": table, "macros": macros} {
			if strings.Contains(doc, banned) {
				t.Errorf("%s contains %q", name, banned)
			}
		}
	}
	for _, want := range []string{
		"network dependent", "bounded below", "type 7", "Student's t", "ConUnit process only", "Batch peak RSS",
		"aws-nitro-kvm", "c6i.2xlarge", "Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	// Per-image peak RSS is not reported anywhere.
	if strings.Contains(strings.ToLower(md), "peak rss |") || strings.Contains(table, "RSS") {
		t.Error("per-image peak RSS must not be reported")
	}
}

func TestTableLabelAndStructure(t *testing.T) {
	h := newFake(map[string][]step{"alpine": okSteps(time.Second)})
	s := testSetup(t, []string{"alpine"}, 0)
	tel, err := RunAll(context.Background(), h, &memSink{}, s)
	if err != nil {
		t.Fatal(err)
	}
	table := RenderTable(tel)
	for _, want := range []string{`\label{tab:rq3_trials}`, `\toprule`, `\bottomrule`, `\dag`, `\texttt{alpine}`, `base-os`, "bounded below by the probe window of 3000 ms"} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q\n%s", want, table)
		}
	}
	if strings.Contains(table, "tab:rq3_performance") {
		t.Error("the old table label must be gone")
	}
	for name, doc := range map[string]string{"table": table, "macros": RenderMacros(tel)} {
		if open, closeB := strings.Count(doc, "{"), strings.Count(doc, "}"); open != closeB {
			t.Errorf("%s has unbalanced braces: %d open, %d close", name, open, closeB)
		}
	}
	// Tabular rows have the same number of cells as the header.
	var cols int
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, `\textbf{Image}`) {
			cols = strings.Count(line, "&")
		}
		if strings.HasPrefix(line, `\texttt{`) && strings.Count(line, "&") != cols {
			t.Errorf("row has %d separators, header %d: %s", strings.Count(line, "&"), cols, line)
		}
	}
	if cols == 0 {
		t.Error("header row not found")
	}
}

func TestCPUColumnsAppearOnlyWhenReported(t *testing.T) {
	r := okResult(time.Second)
	r.Resources.SelfCPUSeconds, r.Resources.ChildCPUSeconds = 0.4, 2.5
	h := newFake(map[string][]step{"alpine": {{res: r}}})
	s := testSetup(t, []string{"alpine"}, 0)
	tel, err := RunAll(context.Background(), h, &memSink{}, s)
	if err != nil {
		t.Fatal(err)
	}
	table, md, macros := RenderTable(tel), RenderMarkdown(tel), RenderMacros(tel)
	if !strings.Contains(table, "CPU self") || !strings.Contains(table, "0.400 & 2.500") {
		t.Errorf("CPU columns missing:\n%s", table)
	}
	if !strings.Contains(md, "| `alpine` | 0.400 | 2.500 |") {
		t.Errorf("CPU section missing in markdown")
	}
	if !strings.Contains(macros, `\newcommand{\ConUnitRQThreeSelfCPUMedianSecAlpine}{0.400}`) || !strings.Contains(macros, `\newcommand{\ConUnitRQThreeChildCPUMedianSecAlpine}{2.500}`) {
		t.Error("CPU macros missing")
	}

	h2 := newFake(map[string][]step{"alpine": okSteps(time.Second)})
	tel2, _ := RunAll(context.Background(), h2, &memSink{}, testSetup(t, []string{"alpine"}, 0))
	if strings.Contains(RenderTable(tel2), "CPU self") || !strings.Contains(RenderMarkdown(tel2), "Not reported") {
		t.Error("without CPU data the report must say so and omit the columns")
	}
}

func TestUnappliedOptionsAreNotRecordedAsApplied(t *testing.T) {
	opts := EvalOptions{Platform: "linux/amd64", ImageSource: "local", ProbeWindow: 3 * time.Second}
	var none Applied
	got := opts.Unsupported(none, true)
	if strings.Join(got, ",") != "platform,image-source,probe-window" {
		t.Errorf("unsupported = %v", got)
	}
	// Defaults do not trigger a refusal.
	def := EvalOptions{ImageSource: "auto", ProbeWindow: 3 * time.Second}
	if got := def.Unsupported(none, false); len(got) != 0 {
		t.Errorf("defaults reported as unsupported: %v", got)
	}
	// Applied options are accepted.
	applied := Applied{Platform: "linux/amd64", ImageSource: "local", ProbeWindow: 3 * time.Second}
	if got := opts.Unsupported(applied, true); len(got) != 0 {
		t.Errorf("applied options reported as unsupported: %v", got)
	}
	warnings := unappliedWarnings(def, none)
	if len(warnings) != 2 {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestWindowPhraseNeverPrintsANonNumber(t *testing.T) {
	if got := windowPhrase(0); strings.Contains(got, " ms") || !strings.Contains(got, "not recorded") {
		t.Errorf("windowPhrase(0) = %q", got)
	}
	if got := windowPhrase(3000); got != "the probe window of 3000 ms" {
		t.Errorf("windowPhrase(3000) = %q", got)
	}
}

// TestNoLegacyCodeRemains guards the removals the protocol requires.
func TestNoLegacyCodeRemains(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(data)
		for _, banned := range []string{"Bare-Metal", "detectEnvironment", "inferArchetype", "SpeedupRatio", "Scientific Discussion", "d.Milliseconds()", "Duration.Milliseconds"} {
			if strings.Contains(src, banned) {
				t.Errorf("%s still contains %q", f, banned)
			}
		}
	}
}

func TestCollectImages(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "images.txt")
	if err := os.WriteFile(file, []byte("# comment\nalpine\n\nnginx\nalpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := collectImages(file, "redis, nginx", "busybox")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "alpine,nginx,redis,busybox" {
		t.Errorf("images = %v", got)
	}
	if _, err := collectImages(filepath.Join(dir, "missing.txt"), "", ""); err == nil {
		t.Error("a missing -file must be an error")
	}
}
