package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

func res(id, name string, out spec.Outcome, reason spec.Reason) spec.TestResult {
	return spec.TestResult{TestID: id, TestName: name, Tier: spec.TierSpec, Outcome: out, Reason: reason}
}

func synth() spec.Study {
	img := func(name string, status string, d time.Duration, rs ...spec.TestResult) *spec.SuiteResult {
		ref := "index.docker.io/library/" + name + "@sha256:" + strings.Repeat("a", 64)
		return &spec.SuiteResult{
			ImageName: ref, RequestedRef: ref, Status: status, Duration: d, Results: rs,
			Phases:    spec.PhaseBreakdown{StreamDuration: 400 * time.Millisecond, Tier3Duration: 3 * time.Second, ProbeWindow: 3 * time.Second},
			Resources: spec.ResourceTelemetry{LayerCount: 4, UncompressedBytes: 80 << 20, PeakRSSMB: 120},
		}
	}
	return spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run:           spec.RunMetadata{InstanceType: "c6i.2xlarge", EngineName: "podman", EngineVersion: "5.0.2", ProbeWindowMs: 3000},
		Images: []*spec.SuiteResult{
			img("alpine", spec.StatusCompleted, 4*time.Second,
				res("SPEC-01", "Non-Root", spec.OutcomeFail, ""), res("FS-04", "SUID", spec.OutcomePass, ""),
				res("SUP-02", "Signature", spec.OutcomeUnverified, spec.ReasonNoTrustPolicy)),
			img("nginx", spec.StatusCompleted, 6*time.Second,
				res("SPEC-01", "Non-Root", spec.OutcomePass, ""), res("FS-04", "SUID", spec.OutcomeFail, ""),
				res("EXEC-01", "Read-Only", spec.OutcomeUnverified, spec.ReasonBaselineFailed),
				res("SUP-02", "Signature", spec.OutcomeUnverified, spec.ReasonNoTrustPolicy)),
			img("<script>", spec.StatusRateLimited, 0),
		},
	}
}

func analyzeSynth(t *testing.T) *analysis.Analysis {
	t.Helper()
	b, err := json.Marshal(synth())
	if err != nil {
		t.Fatal(err)
	}
	l, err := studyfile.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return analysis.Analyze(l, analysis.Options{
		Classification: &analysis.Classification{Headline: []string{"SPEC-01", "FS-04"}, Exploratory: []string{"EXEC-01"}, Excluded: []string{"SUP-02"}},
		Archetypes:     analysis.Archetypes{"alpine": {Archetype: "base-os", BaseFamily: "alpine"}},
		Source:         "empirical_study.json",
	})
}

func TestRenderHTMLShowsPrevalenceWithIntervalsAndNoPassRate(t *testing.T) {
	a := analyzeSynth(t)
	out := renderHTML(a)
	for _, want := range []string{"<svg", "SPEC-01", "Wilson 95%", "alpine", "base-os", "Not completed", "RATE_LIMITED"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	for _, banned := range []string{"Pass Rate", "pass rate", "Mean Pass", "Peak RSS Memory", "compliant"} {
		if strings.Contains(out, banned) {
			t.Errorf("HTML still contains removed statistic %q", banned)
		}
	}
	if strings.Contains(out, "SUP-02") && strings.Contains(out, "SUP-02 (exploratory)") {
		t.Error("excluded check must not be drawn as a prevalence bar")
	}
	if strings.Contains(out, "<script>") {
		t.Error("image names must be HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("escaped image name missing from the table")
	}
	if !strings.Contains(out, "bounded below by the probe window") {
		t.Error("Tier 3 window caveat missing")
	}
}

func TestDashboardSeparatesClassesAndOmitsExcludedPrevalence(t *testing.T) {
	a := analyzeSynth(t)
	var buf bytes.Buffer
	printDashboard(&buf, a)
	out := buf.String()
	for _, want := range []string{"HEADLINE CHECKS", "EXPLORATORY CHECKS", "EXCLUDED CHECKS: no prevalence reported", "SD ", "Wilson 95%", "probe window 3.0 s"} {
		if !strings.Contains(out, want) {
			t.Errorf("dashboard lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SUP-02") && strings.Contains(line, "%") && !strings.Contains(line, "unverified of") {
			t.Errorf("excluded check shows a prevalence: %q", line)
		}
	}
	if strings.Contains(strings.ToLower(out), "pass rate") {
		t.Errorf("dashboard still prints a pass rate:\n%s", out)
	}
}

func TestFailureHistogram(t *testing.T) {
	a := analyzeSynth(t)
	bins := failureHistogram(a)
	// alpine and nginx each have exactly one confirmed headline failure.
	if len(bins) != 2 || bins[0].images != 0 || bins[1].images != 2 {
		t.Errorf("histogram = %+v", bins)
	}
}

func TestRunWritesPreviewAndFailsClearlyOnMissingStudy(t *testing.T) {
	dir := t.TempDir()
	b, _ := json.Marshal(synth())
	if err := os.WriteFile(filepath.Join(dir, "empirical_study.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	headline := filepath.Join(dir, "headline.json")
	if err := os.WriteFile(headline, []byte(`{"headline":["SPEC-01","FS-04"],"exploratory":["EXEC-01"],"excluded":["SUP-02"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"-dir", dir, "-headline", headline, "-archetypes", filepath.Join(dir, "none.json")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "preview.html")); err != nil {
		t.Errorf("preview.html missing: %v", err)
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"-dir", filepath.Join(dir, "missing")}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "empirical_study.json") {
		t.Errorf("missing study must fail with a clear message, code %d: %s", code, errb.String())
	}
}
