package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// update rewrites the golden files: go test ./tools/reliability -run Golden -update
var update = flag.Bool("update", false, "rewrite golden files in tools/reliability/testdata/golden")

const goldenRoot = "testdata/golden"

func assertGolden(t *testing.T, scenario, name, got string) {
	t.Helper()
	path := filepath.Join(goldenRoot, scenario, name)
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

// ---------------------------------------------------------------------------
// Synthetic studies

type checkDef struct {
	id, name string
	tier     spec.Tier
}

// checkDefs are the checks of the synthetic studies. A grid row holds one letter
// per check in this order.
var checkDefs = []checkDef{
	{"SPEC-01", "Non-Root Execution Identity", spec.TierSpec},
	{"FS-04", "SUID/SGID Privilege Escalation Vectors", spec.TierFilesystem},
	{"EXEC-01", "Read-Only Root Filesystem Conformance", spec.TierContract},
	{"EXEC-02", "Dropped Linux Capabilities Conformance", spec.TierContract},
	{"EXEC-04", "No-New-Privileges Kernel Contract", spec.TierContract},
	{"SUP-02", "Cryptographic Image Provenance and Signature", spec.TierSupplyChain},
}

// grid maps an image to its outcomes: P pass, F fail, U unverified, - no result.
type grid map[string]string

func result(c checkDef, code byte) (spec.TestResult, bool) {
	r := spec.TestResult{TestID: c.id, TestName: c.name, Tier: c.tier}
	switch code {
	case 'P':
		r.Outcome, r.Passed = spec.OutcomePass, true
	case 'F':
		r.Outcome = spec.OutcomeFail
	case 'U':
		r.Outcome, r.Reason = spec.OutcomeUnverified, spec.ReasonEvidenceIncomplete
		if c.tier == spec.TierContract {
			r.Reason = spec.ReasonBaselineFailed
		}
	default:
		return r, false
	}
	return r, true
}

// mkStudy builds a study. statuses overrides the COMPLETED status of an image.
// The run is started minute minutes after a fixed time, so that two studies
// with the same results are still different files.
func mkStudy(windowMs int64, minute int, g grid, statuses map[string]string) spec.Study {
	st := spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run: spec.RunMetadata{
			ProbeWindowMs: windowMs, EngineName: "podman", EngineVersion: "5.0", Commit: "0123456789abcdef",
			DatasetSHA256: strings.Repeat("ab", 32),
			StartedAt:     time.Date(2026, 11, 15, 10, minute, 0, 0, time.UTC),
		},
	}
	names := make([]string, 0, len(g))
	for n := range g {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		img := &spec.SuiteResult{ImageName: n, RequestedRef: n, Status: spec.StatusCompleted}
		if s, ok := statuses[n]; ok {
			img.Status = s
		}
		for i, c := range checkDefs {
			if i >= len(g[n]) {
				break
			}
			if r, ok := result(c, g[n][i]); ok {
				img.Results = append(img.Results, r)
			}
		}
		st.Images = append(st.Images, img)
	}
	return st
}

func load(t *testing.T, label string, st spec.Study) *Run {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	l, err := studyfile.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return &Run{Label: label, Path: label + "/" + studyFileName, Loaded: l}
}

// repeats builds runs r1, r2, ... at W of 3 s from grids.
func repeats(t *testing.T, grids ...grid) []*Run {
	t.Helper()
	var runs []*Run
	for i, g := range grids {
		runs = append(runs, load(t, fmt.Sprintf("r%d", i+1), mkStudy(3000, i, g, nil)))
	}
	return runs
}

func mustBuild(t *testing.T, runs, windows []*Run) *Report {
	t.Helper()
	rep, err := Build(runs, windows)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return rep
}

// ---------------------------------------------------------------------------
// Repeats

func TestFlipLogic(t *testing.T) {
	stable := grid{"a": "PPPFPU", "b": "PFPPFU"}
	cases := []struct {
		name string
		runs []grid
		// want
		images, pairs, flipped, flippedImages, unverified, missing int
		tier3Pairs, tier3Flipped, tier3FlippedImages               int
	}{
		{name: "identical repeats", runs: []grid{stable, stable, stable},
			images: 2, pairs: 10, flipped: 0, flippedImages: 0, unverified: 2, tier3Pairs: 6},
		{name: "one flip in one repeat", runs: []grid{stable, {"a": "PPFFPU", "b": "PFPPFU"}, stable},
			images: 2, pairs: 10, flipped: 1, flippedImages: 1, unverified: 2, tier3Pairs: 6, tier3Flipped: 1, tier3FlippedImages: 1},
		{name: "a flip in the last repeat only", runs: []grid{stable, stable, {"a": "PPPFPU", "b": "PFFPFU"}},
			images: 2, pairs: 10, flipped: 1, flippedImages: 1, unverified: 2, tier3Pairs: 6, tier3Flipped: 1, tier3FlippedImages: 1},
		{name: "two flips in one image count once as an image", runs: []grid{stable, {"a": "PPFPPU", "b": "PFPPFU"}, stable},
			images: 2, pairs: 10, flipped: 2, flippedImages: 1, unverified: 2, tier3Pairs: 6, tier3Flipped: 2, tier3FlippedImages: 1},
		{name: "flips in two images", runs: []grid{stable, {"a": "PPFFPU", "b": "PFPFFU"}, stable},
			images: 2, pairs: 10, flipped: 2, flippedImages: 2, unverified: 2, tier3Pairs: 6, tier3Flipped: 2, tier3FlippedImages: 2},
		{name: "a flip of a static check is counted but not as Tier 3", runs: []grid{stable, {"a": "FPPFPU", "b": "PFPPFU"}, stable},
			images: 2, pairs: 10, flipped: 1, flippedImages: 1, unverified: 2, tier3Pairs: 6},
		{name: "a verdict that is UNVERIFIED in one repeat is in neither number", runs: []grid{stable, {"a": "PPPFUU", "b": "PFPPFU"}, stable},
			images: 2, pairs: 9, flipped: 0, flippedImages: 0, unverified: 3, tier3Pairs: 5},
		{name: "PASS and UNVERIFIED and FAIL is no flip between verified verdicts", runs: []grid{{"a": "PPPFPU"}, {"a": "PPUFPU"}, {"a": "PPFFPU"}},
			images: 1, pairs: 4, flipped: 0, flippedImages: 0, unverified: 2, tier3Pairs: 2},
		{name: "UNVERIFIED in all repeats", runs: []grid{{"a": "PPUFPU"}, {"a": "PPUFPU"}, {"a": "PPUFPU"}},
			images: 1, pairs: 4, flipped: 0, flippedImages: 0, unverified: 2, tier3Pairs: 2},
		{name: "a check that one repeat lacks", runs: []grid{stable, {"a": "PPPFP-", "b": "PFPPFU"}, stable},
			images: 2, pairs: 10, flipped: 0, flippedImages: 0, unverified: 1, missing: 1, tier3Pairs: 6},
		{name: "two repeats only", runs: []grid{stable, {"a": "PPFFPU", "b": "PFPPFU"}},
			images: 2, pairs: 10, flipped: 1, flippedImages: 1, unverified: 2, tier3Pairs: 6, tier3Flipped: 1, tier3FlippedImages: 1},
		{name: "four repeats, a flip only in the third", runs: []grid{stable, stable, {"a": "PPPFFU", "b": "PFPPFU"}, stable},
			images: 2, pairs: 10, flipped: 1, flippedImages: 1, unverified: 2, tier3Pairs: 6, tier3Flipped: 1, tier3FlippedImages: 1},
		{name: "a pair that changes back is still a flip", runs: []grid{{"a": "PPPFPU"}, {"a": "PPFFPU"}, {"a": "PPPFPU"}},
			images: 1, pairs: 5, flipped: 1, flippedImages: 1, unverified: 1, tier3Pairs: 3, tier3Flipped: 1, tier3FlippedImages: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustBuild(t, repeats(t, tc.runs...), nil)
			d := rep.RepeatDetail
			got := []int{rep.Images, rep.Pairs, rep.FlippedChecks, rep.FlippedImages, rep.PairsUnverifiedInSomeRepeat, d.MissingInSomeRepeat, d.TierThreePairs, d.TierThreeFlippedPairs, d.TierThreeFlippedImages}
			want := []int{tc.images, tc.pairs, tc.flipped, tc.flippedImages, tc.unverified, tc.missing, tc.tier3Pairs, tc.tier3Flipped, tc.tier3FlippedImages}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("images, pairs, flipped checks, flipped images, unverified, missing, tier3 pairs, tier3 flipped, tier3 flipped images\n got %v\nwant %v", got, want)
			}
			if rep.Repeats != len(tc.runs) || len(d.Flipped) != tc.flipped {
				t.Errorf("repeats %d, listed flips %d", rep.Repeats, len(d.Flipped))
			}
			if rep.FlippedChecks > rep.Pairs {
				t.Error("the flips must be counted over the pairs of the denominator")
			}
			if rep.Incomplete() {
				t.Error("every image completed everywhere")
			}
		})
	}
}

func TestFlippedPairsListTheirVerdictsPerRepeat(t *testing.T) {
	rep := mustBuild(t, repeats(t, grid{"a": "PPPFPU"}, grid{"a": "PPFFPU"}, grid{"a": "PPPFPU"}), nil)
	if len(rep.RepeatDetail.Flipped) != 1 {
		t.Fatalf("flipped = %+v", rep.RepeatDetail.Flipped)
	}
	f := rep.RepeatDetail.Flipped[0]
	if f.Image != "a" || f.Check != "EXEC-01" || f.Tier != 3 || f.Verdicts["r1"] != "PASS" || f.Verdicts["r2"] != "FAIL" || f.Verdicts["r3"] != "PASS" {
		t.Errorf("flip = %+v", f)
	}
	un := rep.RepeatDetail.UnverifiedPairs
	if len(un) != 1 || un[0].Check != "SUP-02" {
		t.Errorf("unverified pairs = %+v", un)
	}
}

func TestImagesThatDidNotCompleteEverywhereAreExcludedAndReported(t *testing.T) {
	stable := grid{"a": "PPPFPU", "b": "PFPPFU", "c": "PPPPPU"}
	runs := []*Run{
		load(t, "r1", mkStudy(3000, 0, stable, nil)),
		load(t, "r2", mkStudy(3000, 1, stable, map[string]string{"b": spec.StatusTimeout})),
		load(t, "r3", mkStudy(3000, 2, grid{"a": "PPPFPU", "b": "PFPPFU"}, nil)), // c has no record
	}
	rep := mustBuild(t, runs, nil)
	if rep.Images != 1 || rep.Pairs != 5 || !rep.Incomplete() {
		t.Fatalf("images %d, pairs %d, incomplete %t", rep.Images, rep.Pairs, rep.Incomplete())
	}
	got := map[string]string{}
	for _, ex := range rep.RepeatDetail.Excluded {
		got[ex.Image] = ex.Detail
	}
	if !strings.Contains(got["b"], "r2 is TIMEOUT") || !strings.Contains(got["c"], "r3 has no record") {
		t.Errorf("excluded = %v", got)
	}
	warned := strings.Join(rep.Warnings, "\n")
	if !strings.Contains(warned, "skips image b") || !strings.Contains(warned, "skips image c") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
}

func TestEveryPairIsAccountedFor(t *testing.T) {
	// verified pairs plus unverified plus missing equal the pairs of the
	// completed images.
	g1 := grid{"a": "PPPFPU", "b": "PFUUFU", "c": "PPPPPP"}
	g2 := grid{"a": "PPFFPU", "b": "PFUPFU", "c": "PPPPP-"}
	g3 := grid{"a": "PPPFPU", "b": "PFPPFU", "c": "PPPPPP"}
	rep := mustBuild(t, repeats(t, g1, g2, g3), nil)
	d := rep.RepeatDetail
	total := rep.Pairs + d.UnverifiedInSomeRepeat + d.MissingInSomeRepeat
	if total != rep.Images*len(checkDefs) {
		t.Errorf("pairs %d + unverified %d + missing %d = %d, want %d", rep.Pairs, d.UnverifiedInSomeRepeat, d.MissingInSomeRepeat, total, rep.Images*len(checkDefs))
	}
	perCheck := 0
	for _, c := range rep.Checks {
		perCheck += c.Pairs + c.UnverifiedInSomeRepeat + c.MissingInSomeRepeat
	}
	if perCheck != total {
		t.Errorf("per check counts add up to %d, want %d", perCheck, total)
	}
}

// legacyRun builds a run in the array format of old study files, which has no
// run metadata and no status. Two of them differ by the timestamp.
func legacyRun(t *testing.T, label string, minute int, g grid) *Run {
	t.Helper()
	st := mkStudy(0, 0, g, nil)
	records := make([]spec.SuiteResult, 0, len(st.Images))
	for _, img := range st.Images {
		img.Status = ""
		img.Timestamp = time.Date(2026, 11, 15, 10, minute, 0, 0, time.UTC)
		records = append(records, *img)
	}
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	l, err := studyfile.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return &Run{Label: label, Path: label + "/" + studyFileName, Loaded: l}
}

func TestStatusOfRecords(t *testing.T) {
	// A legacy record without a status counts as completed.
	g := grid{"a": "PPPFPU"}
	rep := mustBuild(t, []*Run{legacyRun(t, "r1", 0, g), legacyRun(t, "r2", 1, grid{"a": "PPFFPU"})}, nil)
	if rep.Images != 1 || rep.FlippedChecks != 1 {
		t.Errorf("legacy runs: images %d, flips %d", rep.Images, rep.FlippedChecks)
	}
	// An envelope record without a status is a defect of the writer, never a
	// completed image.
	st := mkStudy(3000, 0, g, nil)
	st.Images[0].Status = ""
	rep = mustBuild(t, []*Run{load(t, "r1", st), load(t, "r2", mkStudy(3000, 1, g, nil))}, nil)
	if rep.Images != 0 || len(rep.RepeatDetail.Excluded) != 1 || !strings.Contains(rep.RepeatDetail.Excluded[0].Detail, "UNSPECIFIED") {
		t.Errorf("envelope record without a status: images %d, excluded %+v", rep.Images, rep.RepeatDetail.Excluded)
	}
}

// ---------------------------------------------------------------------------
// Windows

func windowRuns(t *testing.T, g3, g10, g30 grid) []*Run {
	t.Helper()
	return []*Run{
		load(t, "w3", mkStudy(3000, 10, g3, nil)),
		load(t, "w10", mkStudy(10000, 11, g10, nil)),
		load(t, "w30", mkStudy(30000, 12, g30, nil)),
	}
}

func TestWindowLogic(t *testing.T) {
	base := grid{"a": "PPPFPU", "b": "PFPPFU"}
	cases := []struct {
		name                                     string
		g3, g10, g30                             grid
		pairs, changed, verified, withUnverified int
		tier3Changed                             int
	}{
		{"nothing changes", base, base, base, 12, 0, 0, 0, 0},
		{"a verdict changes at the middle window and stays", base, grid{"a": "PPPFPU", "b": "PFFPFU"}, grid{"a": "PPPFPU", "b": "PFFPFU"}, 12, 1, 1, 0, 1},
		{"a verdict changes only at the longest window", base, base, grid{"a": "PPFFPU", "b": "PFPPFU"}, 12, 1, 1, 0, 1},
		{"a change and a change back is a change", base, grid{"a": "PPFFPU", "b": "PFPPFU"}, base, 12, 1, 1, 0, 1},
		{"a verdict that turns UNVERIFIED at a longer window", base, base, grid{"a": "PPPFUU", "b": "PFPPFU"}, 12, 1, 0, 1, 1},
		{"UNVERIFIED at every window is no change", grid{"a": "PPUFPU"}, grid{"a": "PPUFPU"}, grid{"a": "PPUFPU"}, 6, 0, 0, 0, 0},
		{"a static check that changes", base, grid{"a": "FPPFPU", "b": "PFPPFU"}, base, 12, 1, 1, 0, 0},
		{"a check that one window lacks is not compared", base, grid{"a": "PPPFP-", "b": "PFPPFU"}, base, 11, 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := mustBuild(t, repeats(t, base, base, base), windowRuns(t, tc.g3, tc.g10, tc.g30))
			w := rep.WindowDetail
			got := []int{w.Pairs, w.Changed, w.ChangedVerified, w.ChangedWithUnverified, w.TierThreeChanged}
			want := []int{tc.pairs, tc.changed, tc.verified, tc.withUnverified, tc.tier3Changed}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("pairs, changed, verified, with unverified, tier3 changed\n got %v\nwant %v", got, want)
			}
			if w.Changed != w.ChangedVerified+w.ChangedWithUnverified || w.Pairs != w.Changed+w.Unchanged {
				t.Errorf("counts do not add up: %+v", w)
			}
			if len(w.Changes) != tc.changed {
				t.Errorf("listed changes = %d", len(w.Changes))
			}
			if rep.WindowChanged == nil || *rep.WindowChanged != tc.changed {
				t.Errorf("WindowChanged = %v, want %d", rep.WindowChanged, tc.changed)
			}
		})
	}
}

func TestWindowChangeListsTheVerdictPerWindow(t *testing.T) {
	base := grid{"a": "PPPFPU"}
	rep := mustBuild(t, repeats(t, base, base), windowRuns(t, base, grid{"a": "PPFFPU"}, grid{"a": "PPUFPU"}))
	ch := rep.WindowDetail.Changes
	if len(ch) != 1 || ch[0].Check != "EXEC-01" || ch[0].Verdicts["w3"] != "PASS" || ch[0].Verdicts["w10"] != "FAIL" || ch[0].Verdicts["w30"] != "UNVERIFIED" {
		t.Errorf("changes = %+v", ch)
	}
}

func TestWindowImagesMustCompleteAtEveryWindow(t *testing.T) {
	base := grid{"a": "PPPFPU", "b": "PFPPFU"}
	windows := []*Run{
		load(t, "w3", mkStudy(3000, 10, base, nil)),
		load(t, "w10", mkStudy(10000, 11, base, map[string]string{"b": spec.StatusRateLimited})),
		load(t, "w30", mkStudy(30000, 12, base, nil)),
	}
	rep := mustBuild(t, repeats(t, base, base), windows)
	if rep.WindowDetail.Images != 1 || rep.WindowDetail.Pairs != 6 || len(rep.WindowDetail.Excluded) != 1 || !rep.Incomplete() {
		t.Errorf("window detail = %+v", rep.WindowDetail)
	}
}

func TestWindowValues(t *testing.T) {
	cases := []struct {
		name            string
		ms              []int64
		short, mid, lng string
	}{
		{"3, 10 and 30 s", []int64{3000, 10000, 30000}, "3", "10", "30"},
		{"given out of order", []int64{30000, 3000, 10000}, "3", "10", "30"},
		{"a fraction of a second", []int64{2500, 10000, 30000}, "2.5", "10", "30"},
		{"two windows have no middle one", []int64{3000, 30000}, "3", "n/a", "30"},
		{"four windows have no middle one", []int64{1000, 3000, 10000, 30000}, "1", "n/a", "30"},
		{"one window is no comparison", []int64{3000}, "n/a", "n/a", "n/a"},
		{"no windows", nil, "n/a", "n/a", "n/a"},
		{"an unknown window makes all unknown", []int64{0, 10000, 30000}, "n/a", "n/a", "n/a"},
	}
	for _, tc := range cases {
		s, m, l := windowValues(tc.ms)
		if s != tc.short || m != tc.mid || l != tc.lng {
			t.Errorf("%s: %s, %s, %s want %s, %s, %s", tc.name, s, m, l, tc.short, tc.mid, tc.lng)
		}
	}
}

func TestWindowValuesAreReadFromTheStudiesNotTheLabels(t *testing.T) {
	base := grid{"a": "PPPFPU"}
	windows := []*Run{
		load(t, "short", mkStudy(2000, 10, base, nil)),
		load(t, "mid", mkStudy(8000, 11, base, nil)),
		load(t, "long", mkStudy(20000, 12, base, nil)),
	}
	rep := mustBuild(t, repeats(t, base, base), windows)
	if rep.WindowShortS != "2" || rep.WindowMidS != "8" || rep.WindowLongS != "20" {
		t.Errorf("windows = %s %s %s", rep.WindowShortS, rep.WindowMidS, rep.WindowLongS)
	}
}

// ---------------------------------------------------------------------------
// Validation

func TestBuildRejectsInconsistentInput(t *testing.T) {
	base := grid{"a": "PPPFPU"}
	cases := []struct {
		name    string
		runs    func() []*Run
		windows func() []*Run
		wantErr string
	}{
		{"a single repeat", func() []*Run { return repeats(t, base) }, nil, "at least two repeats"},
		{"the same file as two repeats", func() []*Run {
			r := repeats(t, base, base)
			r[1] = &Run{Label: "r2", Path: "x", Loaded: r[0].Loaded}
			return r
		}, nil, "same study file"},
		{"repeats at different windows", func() []*Run {
			return []*Run{load(t, "r1", mkStudy(3000, 0, base, nil)), load(t, "r2", mkStudy(10000, 1, base, nil))}
		}, nil, "different windows"},
		{"two windows with the same length", func() []*Run { return repeats(t, base, base) }, func() []*Run {
			return []*Run{load(t, "wa", mkStudy(10000, 5, base, nil)), load(t, "wb", mkStudy(10000, 6, base, nil))}
		}, "both run with a window of 10000 ms"},
		{"the same file as two windows", func() []*Run { return repeats(t, base, base) }, func() []*Run {
			w := load(t, "w3", mkStudy(3000, 5, base, nil))
			return []*Run{w, {Label: "w10", Path: "y", Loaded: w.Loaded}}
		}, "same study file"},
		{"a label that contradicts the recorded window", func() []*Run { return repeats(t, base, base) }, func() []*Run {
			return []*Run{load(t, "w3", mkStudy(3000, 5, base, nil)), load(t, "w10", mkStudy(30000, 6, base, nil))}
		}, "not 10 s as its label says"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var windows []*Run
			if tc.windows != nil {
				windows = tc.windows()
			}
			_, err := Build(tc.runs(), windows)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestAWindowRunMayBeOneOfTheRepeats(t *testing.T) {
	base := grid{"a": "PPPFPU"}
	r := repeats(t, base, grid{"a": "PPFFPU"}, base)
	w3 := &Run{Label: "w3", Path: r[0].Path, Loaded: r[0].Loaded} // the first repeat doubles as the 3 s window
	windows := []*Run{w3, load(t, "w10", mkStudy(10000, 11, base, nil)), load(t, "w30", mkStudy(30000, 12, base, nil))}
	if _, err := Build(r, windows); err != nil {
		t.Errorf("a repeat may serve as a window run: %v", err)
	}
}

func TestWarningsForMixedDatasetsAndUnknownWindows(t *testing.T) {
	base := grid{"a": "PPPFPU"}
	r1 := mkStudy(0, 0, base, nil)
	r2 := mkStudy(0, 1, base, nil)
	r2.Run.DatasetSHA256 = strings.Repeat("cd", 32)
	rep := mustBuild(t, []*Run{load(t, "r1", r1), load(t, "r2", r2)}, nil)
	joined := strings.Join(rep.Warnings, "\n")
	if !strings.Contains(joined, "different datasets") || !strings.Contains(joined, "no probe window") {
		t.Errorf("warnings = %v", rep.Warnings)
	}
	if strings.Count(joined, "different datasets") != 1 {
		t.Errorf("the dataset warning must appear once: %v", rep.Warnings)
	}
}

func TestNaturalOrderOfChecks(t *testing.T) {
	ids := []string{"FS-10", "FS-2", "EXEC-01", "SPEC-09", "CIS-4.6", "FS-1"}
	want := []string{"CIS-4.6", "EXEC-01", "FS-1", "FS-2", "FS-10", "SPEC-09"}
	sortedByNatural := append([]string(nil), ids...)
	for i := 1; i < len(sortedByNatural); i++ {
		for j := i; j > 0 && naturalLess(sortedByNatural[j], sortedByNatural[j-1]); j-- {
			sortedByNatural[j], sortedByNatural[j-1] = sortedByNatural[j-1], sortedByNatural[j]
		}
	}
	if fmt.Sprint(sortedByNatural) != fmt.Sprint(want) {
		t.Errorf("order = %v, want %v", sortedByNatural, want)
	}
}

// ---------------------------------------------------------------------------
// Outputs

// fullReport is the report of the golden scenarios: three repeats with two
// flips and an unverified pair, and three windows with two changed pairs.
func fullRuns(t *testing.T) (runs, windows []*Run) {
	runs = repeats(t,
		grid{"a": "PPPFPU", "b": "PFPPFU", "c": "PPFFPU", "d": "PPPPPU"},
		grid{"a": "PPFFPU", "b": "PFPPFU", "c": "PPFFUU", "d": "PPPPPU"},
		grid{"a": "PPPFPU", "b": "PFPFFU", "c": "PPFFPU", "d": "PPPPPU"},
	)
	windows = windowRuns(t,
		grid{"a": "PPPFPU", "b": "PFPPFU", "c": "PPFFPU", "d": "PPPPPU"},
		grid{"a": "PPPFPU", "b": "PFPFFU", "c": "PPFFPU", "d": "PPPPUU"},
		grid{"a": "PPPFPU", "b": "PFPFFU", "c": "PPFFPU", "d": "PPPPUU"},
	)
	return runs, windows
}

func TestGoldenFull(t *testing.T) {
	runs, windows := fullRuns(t)
	rep := mustBuild(t, runs, windows)
	assertGolden(t, "full", macrosFile, RenderMacros(rep))
	assertGolden(t, "full", tableFile, RenderTable(rep))
}

func TestGoldenWithoutWindows(t *testing.T) {
	runs, _ := fullRuns(t)
	rep := mustBuild(t, runs, nil)
	assertGolden(t, "no_windows", macrosFile, RenderMacros(rep))
	assertGolden(t, "no_windows", tableFile, RenderTable(rep))
}

func TestGoldenWithoutAComparableImage(t *testing.T) {
	g := grid{"a": "PPPFPU"}
	runs := []*Run{
		load(t, "r1", mkStudy(3000, 0, g, nil)),
		load(t, "r2", mkStudy(3000, 1, g, map[string]string{"a": spec.StatusTimeout})),
	}
	rep := mustBuild(t, runs, nil)
	assertGolden(t, "no_pairs", macrosFile, RenderMacros(rep))
	assertGolden(t, "no_pairs", tableFile, RenderTable(rep))
}

var macroLine = regexp.MustCompile(`(?m)^\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}$`)

func macroValues(t *testing.T, text string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range macroLine.FindAllStringSubmatch(text, -1) {
		if _, dup := out[m[1]]; dup {
			t.Errorf("macro %s defined twice", m[1])
		}
		out[m[1]] = m[2]
	}
	if got := strings.Count(text, `\newcommand`); got != len(out) {
		t.Errorf("%d \\newcommand lines, %d parsed", got, len(out))
	}
	return out
}

func TestMacrosOfTheFullScenario(t *testing.T) {
	runs, windows := fullRuns(t)
	rep := mustBuild(t, runs, windows)
	text := RenderMacros(rep)
	got := macroValues(t, text)
	want := map[string]string{
		"ConUnitRelRepeats": "3", "ConUnitRelImages": "4",
		// 4 images x 6 checks = 24 pairs. SUP-02 is UNVERIFIED everywhere (4 pairs) and EXEC-04 of c in one repeat (1 pair).
		"ConUnitRelPairs": "19", "ConUnitRelFlippedImages": "2", "ConUnitRelFlippedChecks": "2",
		// Tier 3: EXEC-01, EXEC-02 and EXEC-04 on 4 images give 12 pairs, minus EXEC-04 of c (UNVERIFIED in one repeat).
		"ConUnitRelPairsTierThree": "11", "ConUnitRelFlippedChecksTierThree": "2",
		"ConUnitRelWindowChanged": "2", "ConUnitRelWindowShort": "3", "ConUnitRelWindowMid": "10", "ConUnitRelWindowLong": "30",
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %q, want %q", name, got[name], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d macros, want exactly the %d of the contract and the denominator", len(got), len(want))
	}
	if rep.PairsUnverifiedInSomeRepeat != 5 {
		t.Errorf("pairs unverified in some repeat = %d, want 5", rep.PairsUnverifiedInSomeRepeat)
	}
	// The rule of the analysis plan: flips over verified Tier 3 pairs.
	if d := rep.RepeatDetail; d.TierThreePairs != 11 || d.TierThreeFlippedPairs != 2 {
		t.Errorf("tier 3: %d pairs, %d flipped", d.TierThreePairs, d.TierThreeFlippedPairs)
	}
	for _, name := range []string{"ConUnitRelWindowShort", "ConUnitRelWindowMid", "ConUnitRelWindowLong"} {
		if !strings.Contains(text, "A plain number without a unit") {
			t.Errorf("the comment of %s must state that the value has no unit", name)
		}
	}
	if !strings.Contains(text, "pairs_unverified_in_some_repeat") || !strings.Contains(text, "denominator") {
		t.Error("the macro comments must define the denominator and name the field of the unverified pairs")
	}
}

func TestMacrosWithoutAnyPairPrintNotAvailable(t *testing.T) {
	g := grid{"a": "PPPFPU"}
	runs := []*Run{load(t, "r1", mkStudy(3000, 0, g, nil)), load(t, "r2", mkStudy(3000, 1, g, map[string]string{"a": spec.StatusTimeout}))}
	rep := mustBuild(t, runs, nil)
	got := macroValues(t, RenderMacros(rep))
	if got["ConUnitRelImages"] != "0" || got["ConUnitRelPairs"] != "0" {
		t.Errorf("images and pairs are counts: %v", got)
	}
	for _, name := range []string{"ConUnitRelFlippedImages", "ConUnitRelFlippedChecks", "ConUnitRelPairsTierThree", "ConUnitRelFlippedChecksTierThree", "ConUnitRelWindowChanged", "ConUnitRelWindowShort", "ConUnitRelWindowMid", "ConUnitRelWindowLong"} {
		if got[name] != "n/a" {
			t.Errorf("%s = %q, a flip count over no pair must not read as zero", name, got[name])
		}
	}
	if !strings.Contains(RenderMacros(rep), "WARNING") {
		t.Error("an image that could not be compared must be marked")
	}
}

func TestTierThreeMacrosCountOnlyTheExecRules(t *testing.T) {
	cases := []struct {
		name                 string
		runs                 []grid
		pairs, flipped       string
		allPairs, allFlipped string
	}{
		// A flip of a static check does not count for Tier 3.
		{"static flip only", []grid{{"a": "PPPFPU"}, {"a": "FPPFPU"}, {"a": "PPPFPU"}}, "3", "0", "5", "1"},
		// A flip of an EXEC rule counts for both.
		{"exec flip", []grid{{"a": "PPPFPU"}, {"a": "PPFFPU"}, {"a": "PPPFPU"}}, "3", "1", "5", "1"},
		// UNVERIFIED in one repeat takes the pair out of both numbers.
		{"exec unverified in one repeat", []grid{{"a": "PPPFPU"}, {"a": "PPPFUU"}, {"a": "PPPFPU"}}, "2", "0", "4", "0"},
		// No Tier 3 verdict at all: n/a, never zero.
		{"no tier 3 pair", []grid{{"a": "PP"}, {"a": "PP"}}, "n/a", "n/a", "2", "0"},
	}
	for _, tc := range cases {
		rep := mustBuild(t, repeats(t, tc.runs...), nil)
		got := macroValues(t, RenderMacros(rep))
		if got["ConUnitRelPairsTierThree"] != tc.pairs || got["ConUnitRelFlippedChecksTierThree"] != tc.flipped ||
			got["ConUnitRelPairs"] != tc.allPairs || got["ConUnitRelFlippedChecks"] != tc.allFlipped {
			t.Errorf("%s: tier 3 pairs %s, tier 3 flipped %s, pairs %s, flipped %s; want %s, %s, %s, %s", tc.name,
				got["ConUnitRelPairsTierThree"], got["ConUnitRelFlippedChecksTierThree"], got["ConUnitRelPairs"], got["ConUnitRelFlippedChecks"],
				tc.pairs, tc.flipped, tc.allPairs, tc.allFlipped)
		}
	}
}

func TestTableLabelAndStructure(t *testing.T) {
	runs, windows := fullRuns(t)
	table := RenderTable(mustBuild(t, runs, windows))
	if strings.Count(table, `\label{tab:reliability}`) != 1 || strings.Count(table, `\caption{`) != 1 {
		t.Errorf("label or caption count wrong:\n%s", table)
	}
	if strings.Count(table, `\begin{tabular}`) != 1 || strings.Count(table, `\end{tabular}`) != 1 {
		t.Error("unbalanced tabular")
	}
	for _, id := range []string{"EXEC-01", "EXEC-02", "EXEC-04"} {
		if !strings.Contains(table, `\texttt{`+id+`}`) {
			t.Errorf("Tier 3 check %s needs its own row", id)
		}
	}
	if strings.Contains(table, `\texttt{SPEC-01}`) || !strings.Contains(table, "Tier 1, 1 check") {
		t.Error("checks of other tiers are summed per tier")
	}
	if !strings.Contains(table, "All checks & 19 & 2 & 5 & 2/24") {
		t.Errorf("total row missing:\n%s", table)
	}
}

// ---------------------------------------------------------------------------
// Command line

func writeRun(t *testing.T, dir string, st spec.Study) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, studyFileName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cli(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCommandWritesTheThreeOutputs(t *testing.T) {
	root := t.TempDir()
	g := []grid{
		{"a": "PPPFPU", "b": "PFPPFU"}, {"a": "PPFFPU", "b": "PFPPFU"}, {"a": "PPPFPU", "b": "PFPPFU"},
	}
	var runs []string
	for i, grid := range g {
		runs = append(runs, fmt.Sprintf("r%d=%s", i+1, writeRun(t, filepath.Join(root, fmt.Sprintf("r%d", i+1)), mkStudy(3000, i, grid, nil))))
	}
	windows := []string{
		"w3=" + filepath.Join(root, "r1"),
		"w10=" + writeRun(t, filepath.Join(root, "w10"), mkStudy(10000, 5, g[0], nil)),
		"w30=" + writeRun(t, filepath.Join(root, "w30"), mkStudy(30000, 6, grid{"a": "PPPFPU", "b": "PFPFFU"}, nil)),
	}
	out := filepath.Join(root, "out")
	code, stdout, stderr := cli(t, "-runs", strings.Join(runs, ","), "-windows", strings.Join(windows, ","), "-out-dir", out)
	if code != spec.ExitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, name := range []string{jsonFile, tableFile, macrosFile} {
		if st, err := os.Stat(filepath.Join(out, name)); err != nil || st.Size() == 0 {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	var rep map[string]any
	data, _ := os.ReadFile(filepath.Join(out, jsonFile))
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"repeats", "images", "pairs", "flipped_images", "flipped_checks", "pairs_unverified_in_some_repeat", "window_changed", "window_short_s", "window_mid_s", "window_long_s", "method"} {
		if _, ok := rep[field]; !ok {
			t.Errorf("reliability.json lacks the field %s", field)
		}
	}
	if rep["pairs"].(float64) != 10 || rep["flipped_checks"].(float64) != 1 || rep["pairs_unverified_in_some_repeat"].(float64) != 2 {
		t.Errorf("fields = %v", rep)
	}
	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}
	if !strings.Contains(stdout, "flip") {
		t.Errorf("a flip must be visible in the log:\n%s", stdout)
	}
}

func TestCommandAcceptsStudyFilesAndReportsIncompleteComparisons(t *testing.T) {
	root := t.TempDir()
	g := grid{"a": "PPPFPU", "b": "PFPPFU"}
	r1 := writeRun(t, filepath.Join(root, "r1"), mkStudy(3000, 0, g, nil))
	r2 := writeRun(t, filepath.Join(root, "r2"), mkStudy(3000, 1, g, map[string]string{"b": spec.StatusTimeout}))
	out := filepath.Join(root, "out")
	code, _, stderr := cli(t, "-runs", "r1="+filepath.Join(r1, studyFileName)+",r2="+r2, "-out-dir", out)
	if code != spec.ExitIncomplete {
		t.Errorf("exit %d, want %d for an image that did not complete everywhere", code, spec.ExitIncomplete)
	}
	if !strings.Contains(stderr, "skips image b") {
		t.Errorf("stderr:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(out, macrosFile)); err != nil {
		t.Error("the outputs are written for an incomplete comparison too")
	}
}

func TestCommandUsageErrors(t *testing.T) {
	root := t.TempDir()
	r1 := writeRun(t, filepath.Join(root, "r1"), mkStudy(3000, 0, grid{"a": "PPPFPU"}, nil))
	r2 := writeRun(t, filepath.Join(root, "r2"), mkStudy(3000, 1, grid{"a": "PPPFPU"}, nil))
	out := filepath.Join(root, "out")
	two := "r1=" + r1 + ",r2=" + r2
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no out-dir", []string{"-runs", two}, "-out-dir is required"},
		{"no runs", []string{"-out-dir", out}, "at least two repeats"},
		{"one run", []string{"-runs", "r1=" + r1, "-out-dir", out}, "at least two repeats"},
		{"bad pair", []string{"-runs", "r1," + "r2=" + r2, "-out-dir", out}, "not label=directory"},
		{"bad label", []string{"-runs", "r 1=" + r1 + ",r2=" + r2, "-out-dir", out}, "not a usable label"},
		{"duplicate label", []string{"-runs", "r1=" + r1 + ",r1=" + r2, "-out-dir", out}, "given twice"},
		{"a single window", []string{"-runs", two, "-windows", "w3=" + r1, "-out-dir", out}, "at least two runs"},
		{"missing study file", []string{"-runs", "r1=" + r1 + ",r2=" + filepath.Join(root, "nope"), "-out-dir", out}, "run r2"},
		{"extra argument", []string{"-runs", two, "-out-dir", out, "extra"}, "unexpected argument"},
		{"the same run twice", []string{"-runs", "r1=" + r1 + ",r2=" + r1, "-out-dir", out}, "same study file"},
	}
	for _, tc := range cases {
		code, _, stderr := cli(t, tc.args...)
		if code != spec.ExitUsage || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q, want exit %d containing %q", tc.name, code, stderr, spec.ExitUsage, tc.want)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("nothing may be written when the input is invalid")
	}
}

func TestParseLabeled(t *testing.T) {
	got, err := parseLabeled(" r1=a/b , r2=c ,, w10=d ")
	if err != nil || len(got) != 3 || got[0] != (labeled{"r1", "a/b"}) || got[2] != (labeled{"w10", "d"}) {
		t.Errorf("got %v, err %v", got, err)
	}
	if none, err := parseLabeled(""); err != nil || len(none) != 0 {
		t.Errorf("empty list: %v, %v", none, err)
	}
}

func TestSecondsFormatting(t *testing.T) {
	for ms, want := range map[int64]string{3000: "3", 10000: "10", 2500: "2.5", 500: "0.5", 1: "0.001"} {
		if got := seconds(ms); got != want {
			t.Errorf("seconds(%d) = %q, want %q", ms, got, want)
		}
	}
	if _, err := strconv.ParseFloat(seconds(1234), 64); err != nil {
		t.Error(err)
	}
}
