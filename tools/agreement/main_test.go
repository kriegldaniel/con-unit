package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func res(id string, tier spec.Tier, out spec.Outcome) spec.TestResult {
	r := spec.TestResult{TestID: id, TestName: id + " property_name", Tier: tier, Outcome: out}
	if out == spec.OutcomeUnverified {
		r.Reason = spec.ReasonEvidenceIncomplete
	}
	return r
}

func image(ref, status string, results ...spec.TestResult) *spec.SuiteResult {
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, Status: status, Results: results}
}

func study(sha string, imgs ...*spec.SuiteResult) spec.Study {
	return spec.Study{SchemaVersion: spec.SchemaVersion,
		Run:    spec.RunMetadata{ConUnitVersion: "t", InstanceType: "c6i.2xlarge", DatasetSHA256: sha, StartedAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)},
		Images: imgs}
}

func load(t *testing.T, st spec.Study) *studyfile.Loaded {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	l, err := studyfile.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func verdict(pass bool) spec.Outcome {
	if pass {
		return spec.OutcomePass
	}
	return spec.OutcomeFail
}

// twoRuns builds the classic 2x2 table for SPEC-01 over 50 images (both pass
// 20, A pass and B fail 5, A fail and B pass 10, both fail 15), a stable
// FS-04, an EXEC-01 that is verified in different images, and extra images
// that exist in only one run.
func twoRuns(t *testing.T) (*studyfile.Loaded, *studyfile.Loaded) {
	t.Helper()
	var ia, ib []*spec.SuiteResult
	n := 0
	add := func(aPass, bPass bool, count int) {
		for i := 0; i < count; i++ {
			ref := fmt.Sprintf("img%02d@sha256:%d", n, n)
			n++
			ia = append(ia, image(ref, spec.StatusCompleted, res("SPEC-01", spec.TierSpec, verdict(aPass)), res("FS-04", spec.TierFilesystem, spec.OutcomePass)))
			ib = append(ib, image(ref, spec.StatusCompleted, res("SPEC-01", spec.TierSpec, verdict(bPass)), res("FS-04", spec.TierFilesystem, spec.OutcomePass)))
		}
	}
	add(true, true, 20)
	add(true, false, 5)
	add(false, true, 10)
	add(false, false, 15)
	// EXEC-01: image 0 verified in both (PASS, PASS); image 1 verified in A only;
	// image 2 verified in B only; image 3 unverified in both.
	setExec := func(imgs []*spec.SuiteResult, idx int, out spec.Outcome) {
		imgs[idx].Results = append(imgs[idx].Results, res("EXEC-01", spec.TierContract, out))
	}
	setExec(ia, 0, spec.OutcomePass)
	setExec(ib, 0, spec.OutcomePass)
	setExec(ia, 1, spec.OutcomeFail)
	setExec(ib, 1, spec.OutcomeUnverified)
	setExec(ia, 2, spec.OutcomeUnverified)
	setExec(ib, 2, spec.OutcomeFail)
	setExec(ia, 3, spec.OutcomeUnverified)
	setExec(ib, 3, spec.OutcomeUnverified)
	// Images that exist in one run only, or did not complete in one run.
	ia = append(ia, image("onlyA@sha256:a", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass)))
	ib = append(ib, image("onlyB@sha256:b", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeFail)))
	ia = append(ia, image("flaky@sha256:f", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass)))
	ib = append(ib, image("flaky@sha256:f", spec.StatusRateLimited))
	return load(t, study("dataset-1", ia...)), load(t, study("dataset-1", ib...))
}

func check(t *testing.T, rep *Report, rule string) CheckAgreement {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Rule == rule {
			return c
		}
	}
	t.Fatalf("no check %s", rule)
	return CheckAgreement{}
}

func TestAgreementOverImagesVerifiedInBoth(t *testing.T) {
	a, b := twoRuns(t)
	rep := Compare(a, b, "a.json", "b.json", nil)

	spec01 := check(t, rep, "SPEC-01")
	if spec01.VerifiedBoth != 50 || spec01.Agree != 35 {
		t.Fatalf("SPEC-01 both = %d agree = %d", spec01.VerifiedBoth, spec01.Agree)
	}
	if spec01.PercentAgreement == nil || !near(*spec01.PercentAgreement, 0.7) {
		t.Errorf("percent agreement = %v, want 0.7", spec01.PercentAgreement)
	}
	if spec01.PassPass != 20 || spec01.PassFail != 5 || spec01.FailPass != 10 || spec01.FailFail != 15 {
		t.Errorf("matrix = %+v", spec01)
	}
	// onlyA is verified in A, absent from B; flaky is verified in A but not completed in B;
	// onlyB is verified in B only.
	if spec01.VerifiedOnlyA != 2 || spec01.VerifiedOnlyB != 1 {
		t.Errorf("only A = %d, only B = %d; want 2 and 1", spec01.VerifiedOnlyA, spec01.VerifiedOnlyB)
	}
	if spec01.Flipped != 15 || len(spec01.FlippedImages) != 15 {
		t.Errorf("flipped images = %d (%d listed), want 15", spec01.Flipped, len(spec01.FlippedImages))
	}
	for i := 1; i < len(spec01.FlippedImages); i++ {
		if spec01.FlippedImages[i-1] >= spec01.FlippedImages[i] {
			t.Error("flipped images must be sorted")
		}
	}
}

func TestStableCheckHasFullAgreementAndNoFlips(t *testing.T) {
	a, b := twoRuns(t)
	fs04 := check(t, Compare(a, b, "a", "b", nil), "FS-04")
	if fs04.VerifiedBoth != 50 || fs04.PercentAgreement == nil || !near(*fs04.PercentAgreement, 1) {
		t.Errorf("FS-04 = %+v", fs04)
	}
	if fs04.Flipped != 0 || len(fs04.FlippedImages) != 0 {
		t.Errorf("no flipped images expected: %v", fs04.FlippedImages)
	}
}

func TestOnlyUnverifiedOutcomesAreNeverCompared(t *testing.T) {
	a, b := twoRuns(t)
	exec1 := check(t, Compare(a, b, "a", "b", nil), "EXEC-01")
	if exec1.VerifiedBoth != 1 || exec1.Agree != 1 {
		t.Errorf("EXEC-01 both = %d agree = %d, want 1 and 1", exec1.VerifiedBoth, exec1.Agree)
	}
	if exec1.VerifiedOnlyA != 1 || exec1.VerifiedOnlyB != 1 {
		t.Errorf("EXEC-01 only A/B = %d/%d, want 1/1 (UNVERIFIED is not verified)", exec1.VerifiedOnlyA, exec1.VerifiedOnlyB)
	}
}

func TestNoCommonVerifiedImageGivesNullAgreement(t *testing.T) {
	a := load(t, study("d", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass))))
	b := load(t, study("d", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeUnverified))))
	rep := Compare(a, b, "a", "b", nil)
	c := check(t, rep, "SPEC-01")
	if c.VerifiedBoth != 0 || c.PercentAgreement != nil || c.VerifiedOnlyA != 1 {
		t.Errorf("check = %+v", c)
	}
	if rep.PooledAgreement != nil {
		t.Errorf("pooled agreement must be null without overlap: %v", *rep.PooledAgreement)
	}
	data, _ := json.Marshal(rep)
	if !strings.Contains(string(data), `"percent_agreement":null`) {
		t.Errorf("undefined values must serialize as null: %s", data)
	}
	if rep.Flipped.Count != 0 {
		t.Errorf("a verdict that is UNVERIFIED in one run is not a flip: %+v", rep.Flipped)
	}
}

func TestImageOverlapAndRunInfo(t *testing.T) {
	a, b := twoRuns(t)
	rep := Compare(a, b, "a.json", "b.json", nil)
	// 50 images plus flaky are records in both; onlyA and onlyB are in one run.
	if rep.Images.InBoth != 51 || rep.Images.OnlyInA != 1 || rep.Images.OnlyInB != 1 {
		t.Errorf("overlap = %+v", rep.Images)
	}
	// flaky completed in A only, so 50 images completed in both.
	if rep.Images.CompletedBoth != 50 {
		t.Errorf("completed in both = %d, want 50", rep.Images.CompletedBoth)
	}
	if rep.RunA.Attempted != 52 || rep.RunA.Completed != 52 || rep.RunB.Attempted != 52 || rep.RunB.Completed != 51 {
		t.Errorf("run info = %+v %+v", rep.RunA, rep.RunB)
	}
	if rep.RunA.InstanceType != "c6i.2xlarge" || rep.RunA.StartedAt != "2026-11-14T10:00:00Z" || len(rep.RunA.SHA256) != 64 {
		t.Errorf("run A identity = %+v", rep.RunA)
	}
	if rep.PooledAgreement == nil {
		t.Error("pooled agreement missing")
	}
}

func TestChecksAreOrderedByTierThenNaturalID(t *testing.T) {
	a, b := twoRuns(t)
	var order []string
	for _, c := range Compare(a, b, "a", "b", nil).Checks {
		order = append(order, c.Rule)
	}
	if strings.Join(order, ",") != "SPEC-01,FS-04,EXEC-01" {
		t.Errorf("order = %v", order)
	}
}

func TestWarnings(t *testing.T) {
	a := load(t, study("dataset-A", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass))))
	b := load(t, study("dataset-B", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass))))
	rep := Compare(a, b, "a", "b", nil)
	joined := strings.Join(rep.Warnings, "\n")
	if !strings.Contains(joined, "different datasets") {
		t.Errorf("dataset mismatch must warn: %v", rep.Warnings)
	}
	same := Compare(a, a, "a", "a", nil)
	if !strings.Contains(strings.Join(same.Warnings, "\n"), "same file") {
		t.Errorf("identical inputs must warn: %v", same.Warnings)
	}
}

func TestLegacyFormatIsAccepted(t *testing.T) {
	legacy := []spec.SuiteResult{{ImageName: "x", Results: []spec.TestResult{{TestID: "SPEC-01", TestName: "n", Passed: true}}}}
	b, _ := json.Marshal(legacy)
	l, err := studyfile.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	rep := Compare(l, l, "a", "b", nil)
	if c := check(t, rep, "SPEC-01"); c.VerifiedBoth != 1 {
		t.Errorf("legacy input: %+v", c)
	}
}

func TestTableAndRoles(t *testing.T) {
	a, b := twoRuns(t)
	class := &analysis.Classification{Headline: []string{"SPEC-01", "FS-04"}, Exploratory: []string{"EXEC-01"}}
	rep := Compare(a, b, "a", "b", class)
	if check(t, rep, "SPEC-01").Role != "headline" || check(t, rep, "EXEC-01").Role != "exploratory" {
		t.Errorf("roles not set: %+v", rep.Checks)
	}
	table := RenderTable(rep)
	for _, want := range []string{
		`\label{tab:agreement}`, `\toprule`, `\resizebox{\textwidth}{!}{`, `\textbf{Role}`,
		`\textbf{Flipped}`,
		`\texttt{SPEC-01} & headline & SPEC-01 property\_name & 50 & 70.0\% & 15 & 2 & 1 \\`,
		`\texttt{FS-04} & headline & FS-04 property\_name & 50 & 100.0\% & 0 & 0 & 0 \\`,
		`\texttt{EXEC-01} & exploratory & EXEC-01 property\_name & 1 & 100.0\% & 0 & 1 & 1 \\`,
	} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
	plain := RenderTable(Compare(a, b, "a", "b", nil))
	if strings.Contains(plain, `\textbf{Role}`) {
		t.Error("without a classification there is no role column")
	}
	empty := RenderTable(&Report{})
	if !strings.Contains(empty, "no checks") {
		t.Error("an empty report still renders a valid table")
	}
}

func writeStudy(t *testing.T, path string, l *studyfile.Loaded) {
	t.Helper()
	b, err := json.Marshal(l.Study)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCommandWritesJSONAndTable(t *testing.T) {
	dir := t.TempDir()
	a, b := twoRuns(t)
	pa, pb := filepath.Join(dir, "runA", "empirical_study.json"), filepath.Join(dir, "runB", "empirical_study.json")
	writeStudy(t, pa, a)
	writeStudy(t, pb, b)
	out := filepath.Join(dir, "out")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-a", pa, "-b", pb, "-out-dir", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(out, "agreement.json"))
	if err != nil {
		t.Fatalf("agreement.json missing: %v", err)
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("agreement.json invalid: %v", err)
	}
	if len(rep.Checks) != 3 || rep.SchemaVersion != SchemaVersion || SchemaVersion != "2" {
		t.Errorf("report = %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(out, "table_agreement.tex")); err != nil {
		t.Errorf("table_agreement.tex missing: %v", err)
	}
	if !strings.Contains(stdout.String(), "Run agreement") || !strings.Contains(stdout.String(), "flipped  15") {
		t.Errorf("console summary missing:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(out, "macros_agreement.tex")); err != nil {
		t.Errorf("macros_agreement.tex missing: %v", err)
	}

	// The default output directory is the directory of run A.
	if code := run([]string{"-a", pa, "-b", pb}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "runA", "agreement.json")); err != nil {
		t.Errorf("default output next to run A missing: %v", err)
	}
}

func TestCommandErrors(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != spec.ExitUsage {
		t.Errorf("no arguments: exit %d", code)
	}
	if code := run([]string{"-a", "x.json"}, &out, &errb); code != spec.ExitUsage {
		t.Errorf("missing -b: exit %d", code)
	}
	if code := run([]string{"-a", filepath.Join(dir, "no.json"), "-b", filepath.Join(dir, "no2.json")}, &out, &errb); code != spec.ExitFindings || !strings.Contains(errb.String(), "run A") {
		t.Errorf("missing file: exit %d %s", code, errb.String())
	}
	// No image verified in both runs: outputs are written, exit code 3.
	a := load(t, study("d", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass))))
	b := load(t, study("d", image("y@sha256:2", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass))))
	pa, pb := filepath.Join(dir, "a", "s.json"), filepath.Join(dir, "b", "s.json")
	writeStudy(t, pa, a)
	writeStudy(t, pb, b)
	errb.Reset()
	if code := run([]string{"-a", pa, "-b", pb}, &out, &errb); code != spec.ExitIncomplete || !strings.Contains(errb.String(), "agreement is undefined") {
		t.Errorf("disjoint runs: exit %d %s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "agreement.json")); err != nil {
		t.Errorf("outputs must be written even when agreement is undefined: %v", err)
	}
}
