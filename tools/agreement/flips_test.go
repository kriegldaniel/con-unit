package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
)

// update rewrites the golden files: go test ./tools/agreement -run Golden -update
var update = flag.Bool("update", false, "rewrite golden files in tools/agreement/testdata/golden")

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden %s\n--- got ---\n%s\n--- want ---\n%s", name, path, got, string(want))
	}
}

// flipRuns builds two runs over four images:
//
//	x: SPEC-01 PASS to FAIL and FS-04 FAIL to PASS (two flips on one image)
//	y: FS-04 PASS to FAIL (one flip)
//	z: SPEC-01 PASS to UNVERIFIED (not a flip, verified in one run only)
//	w: no change
func flipRuns(t *testing.T) (a, b spec.Study) {
	t.Helper()
	a = study("d",
		image("w@sha256:4", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomeFail)),
		image("z@sha256:3", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomePass)),
		image("y@sha256:2", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomePass)),
		image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomeFail)),
	)
	b = study("d",
		image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeFail), res("FS-04", spec.TierFilesystem, spec.OutcomePass)),
		image("y@sha256:2", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomeFail)),
		image("z@sha256:3", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeUnverified), res("FS-04", spec.TierFilesystem, spec.OutcomePass)),
		image("w@sha256:4", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomeFail)),
	)
	return a, b
}

func TestFlippedImageList(t *testing.T) {
	a, b := flipRuns(t)
	rep := Compare(load(t, a), load(t, b), "a", "b", nil)

	if rep.Flipped.Count != 2 || rep.Flipped.Pairs != 3 {
		t.Fatalf("flipped = %d images, %d pairs; want 2 and 3", rep.Flipped.Count, rep.Flipped.Pairs)
	}
	want := []FlippedImage{
		{Image: "x@sha256:1", Checks: []Flip{{"SPEC-01", "PASS", "FAIL"}, {"FS-04", "FAIL", "PASS"}}},
		{Image: "y@sha256:2", Checks: []Flip{{"FS-04", "PASS", "FAIL"}}},
	}
	got, _ := json.Marshal(rep.Flipped.Images)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) {
		t.Errorf("flipped images = %s\n want %s", got, exp)
	}
	// Per check counts agree with the list.
	if c := check(t, rep, "SPEC-01"); c.Flipped != 1 || c.VerifiedBoth != 3 || c.VerifiedOnlyA != 1 || c.VerifiedOnlyB != 0 {
		t.Errorf("SPEC-01 = %+v, want 1 flip over 3 verified in both and z verified in A only", c)
	}
	if c := check(t, rep, "FS-04"); c.Flipped != 2 || c.VerifiedBoth != 4 {
		t.Errorf("FS-04 = %+v, want 2 flips over 4", c)
	}
}

func TestNoFlipsGivesEmptyListNotNull(t *testing.T) {
	a, _ := flipRuns(t)
	rep := Compare(load(t, a), load(t, a), "a", "b", nil)
	if rep.Flipped.Count != 0 || rep.Flipped.Pairs != 0 {
		t.Errorf("flipped = %+v, want none", rep.Flipped)
	}
	data, _ := json.Marshal(rep.Flipped)
	if !strings.Contains(string(data), `"images":[]`) {
		t.Errorf("an empty flip list must serialize as [], got %s", data)
	}
}

func TestFlippedOnlyCountsImagesCompletedInBothRuns(t *testing.T) {
	a := study("d",
		image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass)),
		image("gone@sha256:2", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeFail)))
	b := study("d",
		image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeFail)),
		image("gone@sha256:2", spec.StatusTimeout))
	rep := Compare(load(t, a), load(t, b), "a", "b", nil)
	if rep.Flipped.Count != 1 || rep.Flipped.Images[0].Image != "x@sha256:1" {
		t.Errorf("flipped = %+v, want only x (gone did not complete in run B)", rep.Flipped)
	}
}

func TestRunToRunOutputsHaveNoChanceCorrectedStatistic(t *testing.T) {
	dir := t.TempDir()
	a, b := twoRuns(t)
	pa, pb := filepath.Join(dir, "a", "s.json"), filepath.Join(dir, "b", "s.json")
	writeStudy(t, pa, a)
	writeStudy(t, pb, b)
	out := filepath.Join(dir, "out")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-a", pa, "-b", pb, "-out-dir", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, name := range []string{"agreement.json", "table_agreement.tex", "macros_agreement.tex"} {
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(data)), "kappa") {
			t.Errorf("%s mentions kappa", name)
		}
	}
	if strings.Contains(strings.ToLower(stdout.String()), "kappa") {
		t.Errorf("console output mentions kappa:\n%s", stdout.String())
	}
}

func TestRenderMacros(t *testing.T) {
	a, b := twoRuns(t)
	noOverlap := Compare(
		load(t, study("d", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass)))),
		load(t, study("d", image("y@sha256:2", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass)))),
		"a", "b", nil)
	unverifiedInOne := Compare(
		load(t, study("d", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomePass), res("FS-04", spec.TierFilesystem, spec.OutcomePass)))),
		load(t, study("d", image("x@sha256:1", spec.StatusCompleted, res("SPEC-01", spec.TierSpec, spec.OutcomeUnverified), res("FS-04", spec.TierFilesystem, spec.OutcomePass)))),
		"a", "b", nil)
	cases := []struct {
		name string
		rep  *Report
		want []string
	}{
		{
			name: "two runs with flips",
			rep:  Compare(a, b, "a", "b", nil),
			want: []string{
				`\newcommand{\ConUnitAgrImages}{50}`,
				`\newcommand{\ConUnitAgrFlipped}{15}`,
				`\newcommand{\ConUnitAgrPctSPECZeroOne}{70.0\%}`,
				`\newcommand{\ConUnitAgrPctFSZeroFour}{100.0\%}`,
				`\newcommand{\ConUnitAgrPctEXECZeroOne}{100.0\%}`,
			},
		},
		{
			name: "no image verified in both runs is not available, not zero",
			rep:  noOverlap,
			want: []string{
				`\newcommand{\ConUnitAgrImages}{0}`,
				`\newcommand{\ConUnitAgrFlipped}{n/a}`,
				`\newcommand{\ConUnitAgrPctSPECZeroOne}{n/a}`,
			},
		},
		{
			name: "a check verified in both runs for no image reads n/a next to one that is defined",
			rep:  unverifiedInOne,
			want: []string{
				`\newcommand{\ConUnitAgrImages}{1}`,
				`\newcommand{\ConUnitAgrFlipped}{0}`,
				`\newcommand{\ConUnitAgrPctSPECZeroOne}{n/a}`,
				`\newcommand{\ConUnitAgrPctFSZeroFour}{100.0\%}`,
			},
		},
		{
			name: "empty report",
			rep:  &Report{},
			want: []string{`\newcommand{\ConUnitAgrImages}{0}`, `\newcommand{\ConUnitAgrFlipped}{n/a}`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderMacros(tc.rep)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("macros lack %s:\n%s", w, got)
				}
			}
			if strings.Contains(got, "NaN") || strings.Contains(got, "[pending]") {
				t.Errorf("macros contain NaN or a placeholder:\n%s", got)
			}
		})
	}
}

func TestRenderMacrosRejectsCollidingKeys(t *testing.T) {
	// Two rule IDs that reduce to the same letters-only key must not produce
	// two definitions of one macro.
	rep := &Report{Checks: []CheckAgreement{{Rule: "A-1"}, {Rule: "A1"}}}
	if _, err := RenderMacros(rep); err == nil || !strings.Contains(err.Error(), "defined twice") {
		t.Errorf("err = %v, want a duplicate macro error", err)
	}
}

func TestMacroNamesAreLettersOnlyForLintChecks(t *testing.T) {
	rep := &Report{}
	for _, id := range []string{"SPEC-09", "SPEC-13", "FS-10", "FS-12", "CIS-4.6"} {
		rep.Checks = append(rep.Checks, CheckAgreement{Rule: id})
	}
	got, err := RenderMacros(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ConUnitAgrPctSPECZeroNine", "ConUnitAgrPctSPECOneThree", "ConUnitAgrPctFSOneZero", "ConUnitAgrPctFSOneTwo", "ConUnitAgrPctCISFourSix"} {
		if !strings.Contains(got, `\`+want+`}`) {
			t.Errorf("missing macro %s:\n%s", want, got)
		}
	}
}

func TestGoldenOutputs(t *testing.T) {
	a, b := twoRuns(t)
	class := &analysis.Classification{Headline: []string{"SPEC-01", "FS-04"}, Exploratory: []string{"EXEC-01"}}
	rep := Compare(a, b, "runA/empirical_study.json", "runB/empirical_study.json", class)
	macros, err := RenderMacros(rep)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "macros_agreement.tex", macros)
	assertGolden(t, "table_agreement.tex", RenderTable(rep))
	assertGolden(t, "agreement.json", string(data)+"\n")

	fa, fb := flipRuns(t)
	flips := Compare(load(t, fa), load(t, fb), "runA/empirical_study.json", "runB/empirical_study.json", nil)
	fm, err := RenderMacros(flips)
	if err != nil {
		t.Fatal(err)
	}
	fdata, _ := json.MarshalIndent(flips, "", "  ")
	assertGolden(t, "flips_macros_agreement.tex", fm)
	assertGolden(t, "flips_agreement.json", string(fdata)+"\n")
}
