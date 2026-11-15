package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// ---------------------------------------------------------------------------
// Builders

func reportJSON(details ...DockleDetail) string {
	if details == nil {
		details = []DockleDetail{}
	}
	b, err := json.MarshalIndent(map[string]any{"summary": DockleSummary{Pass: 1}, "details": details}, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func finding(code, level string, alerts ...string) DockleDetail {
	return DockleDetail{Code: code, Title: code, Level: level, Alerts: alerts}
}

func okRecord(key string, details ...DockleDetail) *ImageRecord {
	return &ImageRecord{
		Image: key, Status: ImageOK, ExportSeconds: 1, DockleSeconds: 2,
		ConfigDigestStudy: "sha256:x", ConfigDigestArchive: "sha256:x", DockleStdout: reportJSON(details...),
	}
}

func errRecord(key string, status ImageStatus) *ImageRecord {
	return &ImageRecord{Image: key, Status: status, Error: "boom", ConfigDigestStudy: "sha256:x"}
}

func cuResult(id string, out spec.Outcome) spec.TestResult {
	r := spec.TestResult{TestID: id, TestName: id + " name", Outcome: out, Passed: out == spec.OutcomePass}
	if out == spec.OutcomeUnverified {
		r.Reason = spec.ReasonEvidenceIncomplete
	}
	return r
}

func cuImage(key string, results ...spec.TestResult) *spec.SuiteResult {
	return &spec.SuiteResult{
		ImageName: key, RequestedRef: key, ConfigDigest: "sha256:x", Status: spec.StatusCompleted, Results: results,
	}
}

func loadedStudy(images ...*spec.SuiteResult) *studyfile.Loaded {
	l := &studyfile.Loaded{Study: spec.Study{SchemaVersion: spec.SchemaVersion, Images: images}}
	l.Records = append(l.Records, images...)
	return l
}

func checkOf(t *testing.T, res *Result, image, check string) CheckResult {
	t.Helper()
	for _, ir := range res.Images {
		if ir.Image != image {
			continue
		}
		for _, c := range ir.Checks {
			if c.Check == check {
				return c
			}
		}
	}
	t.Fatalf("no result for %s on %s", check, image)
	return CheckResult{}
}

func summaryOf(t *testing.T, res *Result, check string) CheckSummary {
	t.Helper()
	for _, c := range res.Checks {
		if c.Check == check {
			return c
		}
	}
	t.Fatalf("no summary for %s", check)
	return CheckSummary{}
}

func analyze1(t *testing.T, img *spec.SuiteResult, rec *ImageRecord) *Result {
	t.Helper()
	records := map[string]*ImageRecord{}
	if rec != nil {
		records[img.RequestedRef] = rec
	}
	return Analyze(loadedStudy(img), records, Options{Run: RunInfo{DockleVersion: VerifiedDockleVersion}})
}

// ---------------------------------------------------------------------------
// Cells

func TestCellOfOnePair(t *testing.T) {
	const key = "img@sha256:1"
	skip := finding("DKL-LI-0002", "SKIP", "failed to detect etc/passwd", "failed to detect etc/group")
	dup := finding("DKL-LI-0002", "FATAL", "duplicate UID 1000 : username b")
	cases := []struct {
		name    string
		results []spec.TestResult
		rec     *ImageRecord
		want    Cell
	}{
		{"FAIL and a finding", []spec.TestResult{cuResult("FS-10", spec.OutcomeFail)}, okRecord(key, dup), CellBoth},
		{"FAIL and no entry", []spec.TestResult{cuResult("FS-10", spec.OutcomeFail)}, okRecord(key), CellOnlyConUnit},
		{"PASS and a finding", []spec.TestResult{cuResult("FS-10", spec.OutcomePass)}, okRecord(key, dup), CellOnlyDockle},
		{"PASS and no entry", []spec.TestResult{cuResult("FS-10", spec.OutcomePass)}, okRecord(key), CellNeither},
		{"a finding at level INFO counts", []spec.TestResult{cuResult("FS-10", spec.OutcomePass)}, okRecord(key, finding("DKL-LI-0002", "INFO", "x")), CellOnlyDockle},
		{"UNVERIFIED with a finding", []spec.TestResult{cuResult("FS-10", spec.OutcomeUnverified)}, okRecord(key, dup), CellConUnitUnverified},
		{"UNVERIFIED with no entry", []spec.TestResult{cuResult("FS-10", spec.OutcomeUnverified)}, okRecord(key), CellConUnitUnverified},
		{"FAIL and a skipped checkpoint", []spec.TestResult{cuResult("FS-10", spec.OutcomeFail)}, okRecord(key, skip), CellDockleNotEvaluated},
		{"PASS and a skipped checkpoint", []spec.TestResult{cuResult("FS-10", spec.OutcomePass)}, okRecord(key, skip), CellDockleNotEvaluated},
		{"UNVERIFIED comes before a skipped checkpoint", []spec.TestResult{cuResult("FS-10", spec.OutcomeUnverified)}, okRecord(key, skip), CellConUnitUnverified},
		{"a skip entry with a real alert is a finding", []spec.TestResult{cuResult("FS-10", spec.OutcomeFail)},
			okRecord(key, finding("DKL-LI-0002", "SKIP", "duplicate UID 1000 : username b", "failed to detect etc/group")), CellBoth},
		{"an export error of the image", []spec.TestResult{cuResult("FS-10", spec.OutcomeFail)}, errRecord(key, ImageExportError), CellDockleError},
		{"a digest mismatch of the image", []spec.TestResult{cuResult("FS-10", spec.OutcomePass)}, errRecord(key, ImageDigestMismatch), CellDockleError},
		{"a Dockle error comes before ConUnit UNVERIFIED", []spec.TestResult{cuResult("FS-10", spec.OutcomeUnverified)}, errRecord(key, ImageDockleError), CellDockleError},
		{"no raw record", []spec.TestResult{cuResult("FS-10", spec.OutcomePass)}, nil, CellDockleError},
		{"no ConUnit result for the check", []spec.TestResult{cuResult("FS-04", spec.OutcomePass)}, okRecord(key), CellNotInStudy},
		{"no ConUnit result, and a Dockle error", nil, errRecord(key, ImageExportError), CellNotInStudy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze1(t, cuImage(key, tc.results...), tc.rec)
			if got := checkOf(t, res, key, "FS-10").Cell; got != tc.want {
				t.Errorf("cell = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestLatestTagPairIsNeverComparable(t *testing.T) {
	const key = "img@sha256:1"
	cases := []struct {
		name string
		out  spec.Outcome
		rec  *ImageRecord
	}{
		{"PASS on a digest-pinned image, as in the study", spec.OutcomePass, okRecord(key)},
		{"FAIL with a Dockle entry that cannot occur for an archive", spec.OutcomeFail, okRecord(key, finding("DKL-DI-0006", "WARN", "Avoid 'latest' tag"))},
		{"UNVERIFIED", spec.OutcomeUnverified, okRecord(key)},
		{"a Dockle error", spec.OutcomePass, errRecord(key, ImageExportError)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze1(t, cuImage(key, cuResult("SPEC-13", tc.out)), tc.rec)
			if got := checkOf(t, res, key, "SPEC-13"); got.Cell != CellNotComparable || got.DockleState != "NOT_COMPARABLE" {
				t.Errorf("cell = %s, state = %s; want not_comparable", got.Cell, got.DockleState)
			}
			s := summaryOf(t, res, "SPEC-13")
			if s.Comparable || s.NotComparable != 1 || s.Table != 0 || s.PercentAgreement != nil || s.NotComparableReason == "" {
				t.Errorf("summary = %+v", s)
			}
			if s.Both+s.OnlyConUnit+s.OnlyDockle+s.Neither != 0 {
				t.Error("a not comparable check must never reach the 2x2 table")
			}
			if len(res.Discordances) != 0 {
				t.Errorf("a not comparable pair must never be a discordance: %+v", res.Discordances)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The 2x2 table

func TestTwoByTwoCountsAndAgreement(t *testing.T) {
	dup := finding("DKL-LI-0002", "FATAL", "duplicate UID 5 : username b")
	skip := finding("DKL-LI-0002", "SKIP", "failed to detect etc/passwd")
	type img struct {
		out spec.Outcome
		rec func(key string) *ImageRecord
	}
	withFinding := func(k string) *ImageRecord { return okRecord(k, dup) }
	clear := func(k string) *ImageRecord { return okRecord(k) }
	skipped := func(k string) *ImageRecord { return okRecord(k, skip) }
	errored := func(k string) *ImageRecord { return errRecord(k, ImageDigestMismatch) }
	inputs := []img{
		{"FAIL", withFinding}, {"FAIL", withFinding}, {"FAIL", withFinding}, // both: 3
		{"PASS", clear}, {"PASS", clear}, {"PASS", clear}, {"PASS", clear}, {"PASS", clear}, // neither: 5
		{"FAIL", clear},                                    // only ConUnit: 1
		{"PASS", withFinding},                              // only Dockle: 1
		{"UNVERIFIED", clear}, {"UNVERIFIED", withFinding}, // unverified: 2
		{"PASS", skipped},                                             // not evaluated: 1
		{"FAIL", errored}, {"PASS", errored}, {"UNVERIFIED", errored}, // dockle error: 3
	}
	var images []*specImage
	records := map[string]*ImageRecord{}
	for i, s := range inputs {
		key := fmt.Sprintf("img%02d@sha256:%d", i, i)
		images = append(images, &specImage{key: key, out: s.out})
		records[key] = s.rec(key)
	}
	res := Analyze(buildStudy(images), records, Options{Run: RunInfo{DockleVersion: "0.4.15"}})
	s := summaryOf(t, res, "FS-10")
	got := [9]int{s.Both, s.OnlyConUnit, s.OnlyDockle, s.Neither, s.ConUnitUnverif, s.DockleError, s.DockleNotEvaluated, s.Table, s.Images}
	want := [9]int{3, 1, 1, 5, 2, 3, 1, 10, 16}
	if got != want {
		t.Errorf("both/onlyC/onlyD/neither/unverified/dockleErr/notEval/table/images = %v, want %v", got, want)
	}
	if s.PercentAgreement == nil || math.Abs(*s.PercentAgreement-0.8) > 1e-12 || s.Agree != 8 {
		t.Errorf("agreement = %v (agree %d), want 0.8 over 10 images", s.PercentAgreement, s.Agree)
	}
	if s.Discordant != 2 || len(res.Discordances) != 2 {
		t.Errorf("discordant = %d, rows = %d, want 2", s.Discordant, len(res.Discordances))
	}
	if res.Totals.ImagesCompleted != 16 || res.Totals.ImagesAnalyzed != 13 || res.Totals.ImagesWithError != 3 {
		t.Errorf("totals = %+v", res.Totals)
	}
	if res.Totals.ErrorsByStatus[string(ImageDigestMismatch)] != 3 {
		t.Errorf("errors by status = %v", res.Totals.ErrorsByStatus)
	}
}

type specImage struct {
	key string
	out spec.Outcome
}

func buildStudy(images []*specImage) *studyfile.Loaded {
	var out []*spec.SuiteResult
	for _, im := range images {
		out = append(out, cuImage(im.key, cuResult("FS-10", im.out)))
	}
	return loadedStudy(out...)
}

func TestCellsOfEveryCheckPartitionTheCompletedImages(t *testing.T) {
	dup := finding("DKL-LI-0002", "FATAL", "duplicate UID 5 : username b")
	var images []*spec.SuiteResult
	records := map[string]*ImageRecord{}
	outcomes := []spec.Outcome{spec.OutcomePass, spec.OutcomeFail, spec.OutcomeUnverified}
	for i := 0; i < 12; i++ {
		key := fmt.Sprintf("img%02d@sha256:%d", i, i)
		var results []spec.TestResult
		for j, m := range Mappings() {
			if (i+j)%7 == 0 {
				continue // the study has no result of this check for this image
			}
			results = append(results, cuResult(m.Check, outcomes[(i+j)%3]))
		}
		images = append(images, cuImage(key, results...))
		switch i % 4 {
		case 0:
			records[key] = errRecord(key, ImageExportError)
		case 1:
			records[key] = okRecord(key, dup)
		default:
			records[key] = okRecord(key)
		}
	}
	res := Analyze(loadedStudy(images...), records, Options{})
	for _, s := range res.Checks {
		sum := s.Both + s.OnlyConUnit + s.OnlyDockle + s.Neither + s.ConUnitUnverif + s.DockleError + s.DockleNotEvaluated + s.NotComparable + s.NotInStudy
		if sum != 12 || s.Images != 12 {
			t.Errorf("%s: the cells sum to %d (images %d), want the 12 completed images", s.Check, sum, s.Images)
		}
		if s.Table != s.Both+s.OnlyConUnit+s.OnlyDockle+s.Neither {
			t.Errorf("%s: table = %d", s.Check, s.Table)
		}
	}
	// Every check of the mapping has a summary, in the order of the mapping.
	for i, m := range Mappings() {
		if res.Checks[i].Check != m.Check {
			t.Errorf("summary %d is %s, want %s", i, res.Checks[i].Check, m.Check)
		}
	}
}

func TestAgreementIsUndefinedWithoutImagesInTheTable(t *testing.T) {
	const key = "img@sha256:1"
	res := analyze1(t, cuImage(key, cuResult("FS-10", spec.OutcomeUnverified)), okRecord(key))
	s := summaryOf(t, res, "FS-10")
	if s.PercentAgreement != nil || s.Table != 0 {
		t.Errorf("agreement = %v over %d, want none", s.PercentAgreement, s.Table)
	}
	data, _ := json.Marshal(s)
	if !strings.Contains(string(data), `"percent_agreement":null`) {
		t.Errorf("an undefined agreement must serialize as null: %s", data)
	}
}

func TestNoImagesAtAll(t *testing.T) {
	res := Analyze(loadedStudy(), nil, Options{})
	if res.Totals.ImagesCompleted != 0 || len(res.Images) != 0 || len(res.Checks) != len(Mappings()) {
		t.Errorf("result = %+v", res.Totals)
	}
	for _, c := range res.Checks {
		if c.PercentAgreement != nil || c.Images != 0 {
			t.Errorf("%s = %+v", c.Check, c)
		}
	}
}

func TestOnlyCompletedImagesAreCompared(t *testing.T) {
	done := cuImage("done@sha256:1", cuResult("FS-10", spec.OutcomePass))
	timeout := &spec.SuiteResult{ImageName: "t@sha256:2", RequestedRef: "t@sha256:2", Status: spec.StatusTimeout}
	limit := &spec.SuiteResult{ImageName: "l@sha256:3", RequestedRef: "l@sha256:3", Status: spec.StatusIndexLimit}
	res := Analyze(loadedStudy(done, timeout, limit), map[string]*ImageRecord{"done@sha256:1": okRecord("done@sha256:1")}, Options{})
	if res.Totals.ImagesCompleted != 1 || len(res.Images) != 1 {
		t.Errorf("totals = %+v, images = %d; only the completed image is compared", res.Totals, len(res.Images))
	}
}

func TestOnlyOptionRestrictsTheAnalysisAndWarns(t *testing.T) {
	a := cuImage("a@sha256:1", cuResult("FS-10", spec.OutcomePass))
	b := cuImage("b@sha256:2", cuResult("FS-10", spec.OutcomePass))
	records := map[string]*ImageRecord{"a@sha256:1": okRecord("a@sha256:1")}
	res := Analyze(loadedStudy(a, b), records, Options{Only: []string{"a@sha256:1"}})
	if res.Totals.ImagesCompleted != 1 || res.Totals.ImagesWithError != 0 {
		t.Errorf("totals = %+v", res.Totals)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "covers 1 of 2 completed images") {
		t.Errorf("a subset run must say so: %v", res.Warnings)
	}
	all := Analyze(loadedStudy(a, b), records, Options{})
	if all.Totals.ImagesCompleted != 2 || all.Totals.ImagesWithError != 1 || all.Totals.ErrorsByStatus[string(ImageNoRawRecord)] != 1 {
		t.Errorf("without Only, the image without a record is an error: %+v", all.Totals)
	}
}

func TestImagesAreInSortedOrderWhateverTheStudyOrder(t *testing.T) {
	var images []*spec.SuiteResult
	records := map[string]*ImageRecord{}
	for _, k := range []string{"c@sha256:3", "a@sha256:1", "b@sha256:2"} {
		images = append(images, cuImage(k, cuResult("FS-10", spec.OutcomePass)))
		records[k] = okRecord(k)
	}
	res := Analyze(loadedStudy(images...), records, Options{})
	var got []string
	for _, ir := range res.Images {
		got = append(got, ir.Image)
	}
	if strings.Join(got, ",") != "a@sha256:1,b@sha256:2,c@sha256:3" {
		t.Errorf("order = %v", got)
	}
}

func TestStoredRecordThatDoesNotParseIsAParseError(t *testing.T) {
	const key = "img@sha256:1"
	rec := okRecord(key)
	rec.DockleStdout = "{ this is not a report"
	res := analyze1(t, cuImage(key, cuResult("FS-10", spec.OutcomeFail)), rec)
	if res.Totals.ImagesAnalyzed != 0 || res.Totals.ErrorsByStatus[string(ImageParseError)] != 1 {
		t.Errorf("totals = %+v", res.Totals)
	}
	if got := checkOf(t, res, key, "FS-10").Cell; got != CellDockleError {
		t.Errorf("cell = %s, want dockle_error", got)
	}
}

// ---------------------------------------------------------------------------
// Two codes of one check

func TestFS01UsesBothDockleCodes(t *testing.T) {
	const key = "img@sha256:1"
	apt := finding("DKL-DI-0005", "FATAL", "Use 'rm -rf /var/lib/apt/lists' after 'apt-get install|update' : x")
	apk := finding("DKL-DI-0004", "FATAL", "Use --no-cache option if use 'apk add': y")

	res := analyze1(t, cuImage(key, cuResult("FS-01", spec.OutcomePass)), okRecord(key, apt))
	c := checkOf(t, res, key, "FS-01")
	if c.Cell != CellOnlyDockle || len(c.DockleCodes) != 1 || c.DockleCodes[0] != "DKL-DI-0005" {
		t.Errorf("finding in the second code only: %+v", c)
	}
	if res.Discordances[0].DockleCode != "DKL-DI-0005" {
		t.Errorf("the discordance names the code that fired: %s", res.Discordances[0].DockleCode)
	}

	res = analyze1(t, cuImage(key, cuResult("FS-01", spec.OutcomeFail)), okRecord(key, apt, apk))
	if c := checkOf(t, res, key, "FS-01"); c.Cell != CellBoth || len(c.DockleCodes) != 2 {
		t.Errorf("findings in both codes: %+v", c)
	}

	res = analyze1(t, cuImage(key, cuResult("FS-01", spec.OutcomeFail)), okRecord(key))
	if d := res.Discordances[0]; d.Kind != CellOnlyConUnit || d.DockleCode != "DKL-DI-0004+DKL-DI-0005" {
		t.Errorf("ConUnit only names both mapped codes: %+v", d)
	}
}

// ---------------------------------------------------------------------------
// Shared code CIS-DI-0010

func TestFacetsOfTheSharedCode(t *testing.T) {
	const key = "img@sha256:1"
	envAlert := "Suspicious ENV key found : DB_PASSWORD on /bin/sh -c #(nop) ENV DB_PASSWORD=******* (You can suppress it with --accept-key)"
	fileAlert := "Suspicious filename found : app/id_rsa (You can suppress it with \"-af id_rsa\")"
	odd := "A message from a later Dockle release"
	fixtureAlert := "Suspicious filename found : lib/tests/id_rsa (You can suppress it with \"-af id_rsa\")"
	cases := []struct {
		name          string
		check         string
		out           spec.Outcome
		alerts        []string
		wantCell      Cell
		wantMismatch  int
		wantShortText string
	}{
		{"ENV check, ENV alert", "SPEC-03", spec.OutcomeFail, []string{envAlert}, CellBoth, 0, ""},
		{"ENV check, file alert only, agreement is not real", "SPEC-03", spec.OutcomeFail, []string{fileAlert}, CellBoth, 1, ""},
		{"ENV check, both kinds of alert", "SPEC-03", spec.OutcomeFail, []string{fileAlert, envAlert}, CellBoth, 0, ""},
		{"file check, ENV alert only, agreement is not real", "FS-06", spec.OutcomeFail, []string{envAlert}, CellBoth, 1, ""},
		{"file check, file alert", "FS-12", spec.OutcomeFail, []string{fileAlert}, CellBoth, 0, ""},
		{"an alert of an unknown kind never claims a mismatch", "FS-06", spec.OutcomeFail, []string{odd}, CellBoth, 0, ""},
		{"ENV check passes, only a file alert: the other part", "SPEC-03", spec.OutcomePass, []string{fileAlert}, CellOnlyDockle, 0, "other part of CIS-DI-0010"},
		{"file check passes, only an ENV alert: the other part", "FS-06", spec.OutcomePass, []string{envAlert}, CellOnlyDockle, 0, "other part of CIS-DI-0010"},
		{"file check passes, a file alert outside any fixture path: no known difference", "FS-12", spec.OutcomePass, []string{fileAlert}, CellOnlyDockle, 0, ""},
		{"file check passes, a file alert below a fixture path: the design difference of the check", "FS-12", spec.OutcomePass, []string{fixtureAlert}, CellOnlyDockle, 0, "fixture-like path"},
		{"ENV check passes and the unknown alert gives the plain explanation", "SPEC-03", spec.OutcomePass, []string{odd}, CellOnlyDockle, 0, "NAME=value words in build commands"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze1(t, cuImage(key, cuResult(tc.check, tc.out)), okRecord(key, finding("CIS-DI-0010", "FATAL", tc.alerts...)))
			if got := checkOf(t, res, key, tc.check).Cell; got != tc.wantCell {
				t.Fatalf("cell = %s, want %s", got, tc.wantCell)
			}
			if s := summaryOf(t, res, tc.check); s.BothFacetMismatch != tc.wantMismatch {
				t.Errorf("both facet mismatch = %d, want %d", s.BothFacetMismatch, tc.wantMismatch)
			}
			if tc.wantCell == CellOnlyDockle {
				if len(res.Discordances) != 1 || res.Discordances[0].IntendedShort != tc.wantShortText {
					t.Errorf("discordances = %+v, want the short text %q", res.Discordances, tc.wantShortText)
				}
				if d := res.Discordances[0]; (d.IntendedDifference == "") != (tc.wantShortText == "") {
					t.Errorf("the full text %q and the short text %q must both be set or both be empty", d.IntendedDifference, d.IntendedShort)
				}
			}
		})
	}
}

func TestFacetsAreOnlyRecordedForFindings(t *testing.T) {
	const key = "img@sha256:1"
	res := analyze1(t, cuImage(key, cuResult("SPEC-03", spec.OutcomePass)), okRecord(key))
	if c := checkOf(t, res, key, "SPEC-03"); len(c.DockleFacets) != 0 || c.DockleState != "CLEAR" {
		t.Errorf("check = %+v", c)
	}
}

// ---------------------------------------------------------------------------
// Discordance rows

func TestDiscordanceFields(t *testing.T) {
	const key = "index.docker.io/library/app@sha256:1"
	r := cuResult("SPEC-10", spec.OutcomeFail)
	r.Message = "sudo found in\nthe build history"
	r.Evidence = &spec.Evidence{Paths: []string{"p1", "p2", "p3", "p4", "p5", "p6", "p7"}, FixtureCandidates: []string{"f1"}}
	sudo := finding("DKL-DI-0001", "FATAL", "Avoid sudo in container : /bin/sh -c apt-get install sudo")
	res := Analyze(loadedStudy(
		cuImage(key, r, cuResult("SPEC-11", spec.OutcomePass)),
	), map[string]*ImageRecord{key: okRecord(key, sudo, finding("DKL-DI-0003", "WARN", "Avoid dist-upgrade in container : x"))}, Options{})

	// SPEC-10 FAIL with a Dockle finding is a both cell, SPEC-11 PASS with a
	// finding is a Dockle only cell, so exactly one discordance exists.
	if len(res.Discordances) != 1 {
		t.Fatalf("discordances = %+v, want exactly one", res.Discordances)
	}
	var onlyDockle *Discordance
	for i := range res.Discordances {
		if res.Discordances[i].Check == "SPEC-11" {
			onlyDockle = &res.Discordances[i]
		}
	}
	if onlyDockle == nil {
		t.Fatalf("no discordance for SPEC-11: %+v", res.Discordances)
	}
	m, _ := MappingFor("SPEC-11")
	want := Discordance{
		Image: key, Check: "SPEC-11", Kind: CellOnlyDockle, DockleCode: "DKL-DI-0003", ConUnitOutcome: "PASS", DockleFinding: true,
		ConUnitEvidence: "", DockleAlert: "DKL-DI-0003 WARN: Avoid dist-upgrade in container : x",
		IntendedDifference: m.OnlyDockle.Text, IntendedShort: m.OnlyDockle.Short,
	}
	if *onlyDockle != want {
		t.Errorf("discordance = %+v\n want %+v", *onlyDockle, want)
	}
	if onlyDockle.Resolution != "" || onlyDockle.ResolvedBy != "" {
		t.Error("a discordance starts unresolved")
	}

	// The evidence of the ConUnit side is one line and lists at most five paths.
	ev := conunitEvidence(r)
	if strings.Contains(ev, "\n") || !strings.Contains(ev, "sudo found in the build history") ||
		!strings.Contains(ev, "p5") || strings.Contains(ev, "p6") || !strings.Contains(ev, "(+2 more)") || !strings.Contains(ev, "fixture candidates: 1") {
		t.Errorf("evidence = %q", ev)
	}
}

func TestOnlyConUnitDiscordance(t *testing.T) {
	const key = "img@sha256:1"
	r := cuResult("SPEC-12", spec.OutcomeFail)
	r.Message = "volume /proc/self declared"
	res := analyze1(t, cuImage(key, r), okRecord(key))
	var d *Discordance
	for i := range res.Discordances {
		if res.Discordances[i].Check == "SPEC-12" {
			d = &res.Discordances[i]
		}
	}
	if d == nil {
		t.Fatalf("no discordance: %+v", res.Discordances)
	}
	m, _ := MappingFor("SPEC-12")
	if d.Kind != CellOnlyConUnit || d.DockleFinding || d.ConUnitOutcome != "FAIL" || d.DockleCode != "DKL-DI-0002" ||
		d.DockleAlert != "" || d.IntendedDifference != m.OnlyConUnit.Text || !strings.Contains(d.ConUnitEvidence, "/proc/self") {
		t.Errorf("discordance = %+v", *d)
	}
}

func TestConUnitEvidenceCases(t *testing.T) {
	long := strings.Repeat("x", 2*maxEvidenceChars)
	cases := []struct {
		name string
		in   spec.TestResult
		want func(string) bool
	}{
		{"message only", spec.TestResult{Message: "a  b"}, func(s string) bool { return s == "a b" }},
		{"reason of an UNVERIFIED result", spec.TestResult{Message: "m", Reason: spec.ReasonEvidenceIncomplete}, func(s string) bool { return s == "m; reason: EVIDENCE_INCOMPLETE" }},
		{"five paths are listed completely", spec.TestResult{Evidence: &spec.Evidence{Paths: []string{"1", "2", "3", "4", "5"}}}, func(s string) bool { return s == "paths: 1, 2, 3, 4, 5" }},
		{"nothing recorded", spec.TestResult{}, func(s string) bool { return s == "" }},
		{"a long message is cut", spec.TestResult{Message: long}, func(s string) bool { return len(s) <= maxEvidenceChars+4 && strings.HasSuffix(s, " ...") }},
	}
	for _, tc := range cases {
		if got := conunitEvidence(tc.in); !tc.want(got) {
			t.Errorf("%s: evidence = %q", tc.name, got)
		}
	}
}

func TestDockleAlertsAreBounded(t *testing.T) {
	long := strings.Repeat("y", 3*maxAlertChars)
	got := dockleAlerts([]DockleDetail{finding("DKL-DI-0001", "FATAL", long), finding("DKL-DI-0003", "warn", "a", "b")})
	if len(got) > maxAlertChars+4 || !strings.HasPrefix(got, "DKL-DI-0001 FATAL: ") {
		t.Errorf("alerts = %q", got)
	}
	short := dockleAlerts([]DockleDetail{finding("DKL-DI-0003", "warn", "a\n b", "c")})
	if short != "DKL-DI-0003 WARN: a b | c" {
		t.Errorf("alerts = %q", short)
	}
}

// ---------------------------------------------------------------------------
// Codes that no check maps to, and excluded codes

func TestUnmappedAndExcludedCodes(t *testing.T) {
	const key = "img@sha256:1"
	rec := okRecord(key,
		finding("CIS-DI-0005", "INFO", "export DOCKER_CONTENT_TRUST=1 before docker pull/build"),
		finding("ZZZ-0001", "WARN", "a code of a later release"),
		finding("CIS-DI-0001", "WARN", "Last user should not be root"),
	)
	res := analyze1(t, cuImage(key, cuResult("SPEC-01", spec.OutcomeFail)), rec)
	if len(res.ExcludedSeen) != 1 || res.ExcludedSeen[0].Code != "CIS-DI-0005" || res.ExcludedSeen[0].Images != 1 {
		t.Errorf("excluded codes seen = %+v", res.ExcludedSeen)
	}
	if len(res.UnmappedCodes) != 1 || res.UnmappedCodes[0].Code != "ZZZ-0001" || res.UnmappedCodes[0].Known {
		t.Errorf("unmapped codes seen = %+v", res.UnmappedCodes)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "ZZZ-0001") {
		t.Errorf("an unknown code must be warned about: %v", res.Warnings)
	}
	ir := res.Images[0]
	if len(ir.ExcludedCodes) != 1 || len(ir.UnmappedCodes) != 1 {
		t.Errorf("image result = %+v", ir)
	}
	// The excluded code never changes a comparison.
	if checkOf(t, res, key, "SPEC-01").Cell != CellBoth {
		t.Error("CIS-DI-0001 still counts")
	}
}

func TestNoDockleCodeIsExcludedFromTheComparisonByMistake(t *testing.T) {
	const key = "img@sha256:1"
	// CIS-DI-0005 is on every image unless the scanning host sets
	// DOCKER_CONTENT_TRUST. No mapped check may read it.
	res := analyze1(t, cuImage(key), okRecord(key, finding("CIS-DI-0005", "INFO", "export DOCKER_CONTENT_TRUST=1")))
	for _, c := range res.Images[0].Checks {
		if c.DockleState == "FINDING" {
			t.Errorf("%s reads a finding from CIS-DI-0005", c.Check)
		}
	}
}

func TestTimingsAreSeparate(t *testing.T) {
	var images []*spec.SuiteResult
	records := map[string]*ImageRecord{}
	for i, ex := range []float64{1, 2, 3} {
		key := fmt.Sprintf("img%d@sha256:%d", i, i)
		images = append(images, cuImage(key, cuResult("FS-10", spec.OutcomePass)))
		rec := okRecord(key)
		rec.ExportSeconds, rec.DockleSeconds = ex, ex*10
		records[key] = rec
	}
	images = append(images, cuImage("bad@sha256:9", cuResult("FS-10", spec.OutcomePass)))
	records["bad@sha256:9"] = &ImageRecord{Image: "bad@sha256:9", Status: ImageDigestMismatch, ExportSeconds: 4}
	res := Analyze(loadedStudy(images...), records, Options{})
	if res.Timings.Export.N != 4 || res.Timings.Export.Median != 2.5 {
		t.Errorf("export timings = %+v", res.Timings.Export)
	}
	if res.Timings.Dockle.N != 3 || res.Timings.Dockle.Median != 20 {
		t.Errorf("dockle timings = %+v, only images where Dockle ran count", res.Timings.Dockle)
	}
	if res.Timings.Total.N != 3 || res.Timings.Total.Median != 22 {
		t.Errorf("total timings = %+v", res.Timings.Total)
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	build := func() *Result {
		var images []*spec.SuiteResult
		records := map[string]*ImageRecord{}
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("img%d@sha256:%d", i, i)
			images = append(images, cuImage(key, cuResult("FS-10", spec.OutcomeFail), cuResult("SPEC-12", spec.OutcomePass)))
			records[key] = okRecord(key, finding("DKL-DI-0002", "FATAL", "Avoid mounting sensitive dirs : /proc"))
		}
		return Analyze(loadedStudy(images...), records, Options{})
	}
	a, _ := json.Marshal(build())
	b, _ := json.Marshal(build())
	if string(a) != string(b) {
		t.Error("two analyses of the same input differ")
	}
}

// TestIntendedDifferenceNeedsSupportingEvidence checks that a documented design
// difference is only stated when the recorded evidence supports it. A Dockle
// finding that ConUnit misses and that the difference cannot explain has no
// known intended difference: it is the case that needs a look.
func TestIntendedDifferenceNeedsSupportingEvidence(t *testing.T) {
	const key = "img@sha256:1"
	cases := []struct {
		name      string
		check     string
		dockle    DockleDetail
		explained bool
		short     string
	}{
		{"a Dockerfile below node_modules", "FS-11", finding("DKL-LI-0003", "INFO", "unnecessary file : app/node_modules/x/Dockerfile "), true, "files below node_modules or vendor"},
		{"a Dockerfile in an ordinary directory", "FS-11", finding("DKL-LI-0003", "INFO", "unnecessary file : app/Dockerfile "), false, ""},
		{"a real ADD instruction", "SPEC-07", finding("CIS-DI-0009", "FATAL", "Use COPY : /bin/sh -c #(nop) ADD file:abc in /f"), false, ""},
		{"a RUN line that holds the words", "SPEC-07", finding("CIS-DI-0009", "FATAL", "Use COPY : /bin/sh -c echo ADD in x"), true, "tokens ADD and in in any command"},
		{"a candidate that the evidence cannot decide is stated", "SPEC-10", finding("DKL-DI-0001", "FATAL", "Avoid sudo in container : /bin/sh -c apt-get install sudo"), true, "sudo as an argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := analyze1(t, cuImage(key, cuResult(tc.check, spec.OutcomePass)), okRecord(key, tc.dockle))
			if len(res.Discordances) != 1 {
				t.Fatalf("discordances = %+v", res.Discordances)
			}
			d := res.Discordances[0]
			if (d.IntendedDifference != "") != tc.explained || d.IntendedShort != tc.short {
				t.Errorf("intended difference = %q (short %q), want explained=%v short=%q", d.IntendedDifference, d.IntendedShort, tc.explained, tc.short)
			}
		})
	}
	// ConUnit only: SPEC-07 has a difference without an applicability check.
	res := analyze1(t, cuImage(key, cuResult("SPEC-07", spec.OutcomeFail)), okRecord(key))
	if d := res.Discordances[0]; d.IntendedShort != "only the base rootfs ADD is exempt" {
		t.Errorf("ConUnit only SPEC-07 = %+v", d)
	}
}
