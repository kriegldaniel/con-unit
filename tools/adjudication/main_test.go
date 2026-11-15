package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/stats"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

func intp(n int) *int { return &n }

func result(id string, out spec.Outcome, ev *spec.Evidence) spec.TestResult {
	return spec.TestResult{TestID: id, TestName: id + " name", Outcome: out, Evidence: ev}
}

func synthStudy() spec.Study {
	execFail := result("EXEC-01", spec.OutcomeFail, &spec.Evidence{
		BaselineState: "running", TreatmentState: "exited_nonzero", TreatmentExitCode: intp(1),
		WindowMillis: 3000, LogTail: "touch: /var/run/x: Read-only file system\n",
	})
	execFail.Hint = "looks like a read-only write"
	execFail.Message = "did not survive the window"
	spec07 := result("SPEC-07", spec.OutcomeFail, &spec.Evidence{Paths: []string{"layer 3: ADD ./app /app"}})
	spec07.Message = "ADD instruction found in author layers"
	return spec.Study{SchemaVersion: spec.SchemaVersion, Images: []*spec.SuiteResult{
		{ImageName: "a", RequestedRef: "a@sha256:1", Status: spec.StatusCompleted, Results: []spec.TestResult{
			result("FS-06", spec.OutcomeFail, &spec.Evidence{
				Paths:             []string{"/etc/ssl/private/server.key", "/app/id_rsa"},
				FixtureCandidates: []string{"/usr/share/x/testdata/key.pem"},
			}),
			result("FS-07", spec.OutcomePass, &spec.Evidence{FixtureCandidates: []string{"/opt/lib/tests/conftest.py"}}),
			spec07, execFail,
			result("EXEC-02", spec.OutcomePass, nil),
			result("SPEC-01", spec.OutcomeFail, nil),
		}},
		{ImageName: "b", RequestedRef: "b@sha256:2", Status: spec.StatusCompleted, Results: []spec.TestResult{
			result("FS-06", spec.OutcomePass, nil),
			result("FS-07", spec.OutcomeFail, nil), // FAIL without any path
			result("SPEC-07", spec.OutcomePass, nil),
			result("EXEC-01", spec.OutcomeFail, &spec.Evidence{TreatmentState: "exited_nonzero"}),
			result("EXEC-04", spec.OutcomeFail, nil),
		}},
		{ImageName: "c", RequestedRef: "c@sha256:3", Status: spec.StatusRateLimited, Results: []spec.TestResult{
			result("FS-06", spec.OutcomeFail, &spec.Evidence{Paths: []string{"/never/counted.key"}}),
			result("EXEC-01", spec.OutcomeFail, nil),
		}},
	}}
}

func writeStudy(t *testing.T, dir string) string {
	t.Helper()
	b, err := json.Marshal(synthStudy())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "empirical_study.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadSynth(t *testing.T) *studyfile.Loaded {
	t.Helper()
	b, _ := json.Marshal(synthStudy())
	l, err := studyfile.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestExportListsEveryFlaggedFinding(t *testing.T) {
	rows := buildRows(loadSynth(t), exportOptions{})
	type key struct{ image, rule, category string }
	count := map[key]int{}
	for _, r := range rows {
		count[key{r.Image, r.Rule, r.Category}]++
		if r.RaterA != "" || r.RaterB != "" || r.Consensus != "" {
			t.Errorf("template rows must have empty rating columns: %+v", r)
		}
		if len(r.ID) != 12 {
			t.Errorf("finding id %q must be 12 hex characters", r.ID)
		}
	}
	want := map[key]int{
		{"a@sha256:1", "FS-06", CategoryFinding}:          2, // both non-fixture paths
		{"a@sha256:1", "FS-06", CategoryFixtureCandidate}: 1,
		{"a@sha256:1", "FS-07", CategoryFixtureCandidate}: 1, // fixture-only candidates stay visible
		{"a@sha256:1", "SPEC-07", CategoryFailure}:        1,
		{"a@sha256:1", "EXEC-01", CategoryFailure}:        1,
		{"b@sha256:2", "FS-07", CategoryFinding}:          1, // a FAIL is never dropped, even without a path
		{"b@sha256:2", "EXEC-01", CategoryFailure}:        1,
		{"b@sha256:2", "EXEC-04", CategoryFailure}:        1,
	}
	for k, n := range want {
		if count[k] != n {
			t.Errorf("%+v: %d rows, want %d", k, count[k], n)
		}
	}
	for k := range count {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected rows for %+v", k)
		}
	}
	for _, r := range rows {
		switch r.Rule {
		case "SPEC-01", "EXEC-02":
			t.Errorf("rule %s must not be exported", r.Rule)
		}
		if strings.HasPrefix(r.Image, "c@") {
			t.Errorf("non-completed image exported: %+v", r)
		}
	}
}

func TestExportEvidenceIsComplete(t *testing.T) {
	rows := buildRows(loadSynth(t), exportOptions{})
	var exec1 Row
	for _, r := range rows {
		if r.Rule == "EXEC-01" && strings.HasPrefix(r.Image, "a@") {
			exec1 = r
		}
	}
	for _, want := range []string{"baseline: running", "treatment: exited_nonzero (exit 1)", "window: 3000 ms", "log tail:", "Read-only file system", "message: did not survive the window"} {
		if !strings.Contains(exec1.Evidence, want) {
			t.Errorf("EXEC evidence lacks %q:\n%s", want, exec1.Evidence)
		}
	}
	if strings.Contains(exec1.Evidence, "read-only write") {
		t.Error("the keyword hint must not be shown to the raters")
	}
	for _, r := range rows {
		if r.Rule == "FS-06" && r.Category == CategoryFinding && !strings.Contains(r.Evidence, "path: /") {
			t.Errorf("finding row lacks its path: %+v", r)
		}
		if r.Rule == "SPEC-07" && !strings.Contains(r.Evidence, "ADD instruction found") {
			t.Errorf("SPEC-07 row lacks its message: %+v", r)
		}
	}
}

func TestExportIsDeterministicAndOrdered(t *testing.T) {
	a := buildRows(loadSynth(t), exportOptions{})
	b := buildRows(loadSynth(t), exportOptions{})
	if len(a) != len(b) {
		t.Fatal("row counts differ between runs")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("row %d differs between runs", i)
		}
	}
	// Rule order is natural (EXEC-01 before EXEC-04 before FS-06), image next.
	order := []string{}
	for _, r := range a {
		order = append(order, r.Rule)
	}
	want := []string{"EXEC-01", "EXEC-01", "EXEC-04", "FS-06", "FS-06", "FS-06", "FS-07", "FS-07", "SPEC-07"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("rule order = %v, want %v", order, want)
	}
}

func TestExecSampleIsDeterministicAndKeepsOtherRules(t *testing.T) {
	st := synthStudy()
	for i := 0; i < 40; i++ {
		img := &spec.SuiteResult{ImageName: "x", RequestedRef: "x" + string(rune('A'+i%26)) + string(rune('a'+i/26)), Status: spec.StatusCompleted,
			Results: []spec.TestResult{result("EXEC-02", spec.OutcomeFail, &spec.Evidence{TreatmentState: "exited_nonzero"})}}
		st.Images = append(st.Images, img)
	}
	b, _ := json.Marshal(st)
	l, err := studyfile.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	all := buildRows(l, exportOptions{})
	s1 := buildRows(l, exportOptions{ExecSample: 30, Seed: "seed"})
	s2 := buildRows(l, exportOptions{ExecSample: 30, Seed: "seed"})
	s3 := buildRows(l, exportOptions{ExecSample: 30, Seed: "other"})
	countExec := func(rows []Row) int {
		n := 0
		for _, r := range rows {
			if strings.HasPrefix(r.Rule, "EXEC-") {
				n++
			}
		}
		return n
	}
	if countExec(all) != 43 || countExec(s1) != 30 {
		t.Errorf("EXEC rows: all %d, sample %d; want 43 and 30", countExec(all), countExec(s1))
	}
	if len(all)-countExec(all) != len(s1)-countExec(s1) {
		t.Error("the sample must keep every non-EXEC row")
	}
	same := func(a, b []Row) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	if !same(s1, s2) {
		t.Error("the same seed must give the same sample")
	}
	if same(s1, s3) {
		t.Error("a different seed should give a different sample")
	}
	// A sample larger than the population keeps everything.
	if all2 := buildRows(l, exportOptions{ExecSample: 500}); len(all2) != len(all) {
		t.Errorf("oversized sample dropped rows: %d vs %d", len(all2), len(all))
	}
}

func TestExportCommandWritesTemplateThatScoringCanRead(t *testing.T) {
	dir := t.TempDir()
	study := writeStudy(t, dir)
	var out, errb bytes.Buffer
	if code := run([]string{"export", "-study", study}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	tmpl := filepath.Join(dir, "adjudication_template.csv")
	data, err := os.ReadFile(tmpl)
	if err != nil {
		t.Fatalf("template not written next to the study: %v", err)
	}
	if !strings.HasPrefix(string(data), "finding_id,image,rule,category,evidence,rater_a,rater_b,consensus\n") {
		t.Errorf("unexpected header:\n%s", firstLine(string(data)))
	}
	rows, err := ReadRows(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("the template must be readable: %v", err)
	}
	if len(rows) != 9 {
		t.Errorf("rows = %d, want 9", len(rows))
	}
	// Multi-line evidence survives the CSV round trip.
	found := false
	for _, r := range rows {
		if strings.Contains(r.Evidence, "log tail:\ntouch:") {
			found = true
		}
	}
	if !found {
		t.Error("multi-line log tail lost in the CSV round trip")
	}
	if code := run([]string{"export", "-study", filepath.Join(dir, "none.json")}, &out, &errb); code == 0 {
		t.Error("a missing study must fail")
	}
}

func firstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

// ---------------------------------------------------------------------------
// Scoring

func mkRows(rule, category string, a, b, consensus string, n int) []Row {
	rows := make([]Row, n)
	for i := range rows {
		rows[i] = Row{ID: rule + category + a + b + consensus + string(rune('a'+i%26)) + string(rune('a'+i/26)), Image: "img", Rule: rule, Category: category, RaterA: a, RaterB: b, Consensus: consensus}
	}
	return rows
}

func find(t *testing.T, s *Summary, rule string) CheckSummary {
	t.Helper()
	for _, c := range s.Checks {
		if c.Rule == rule {
			return c
		}
	}
	t.Fatalf("no summary for %s", rule)
	return CheckSummary{}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestScoreKappaPrecisionAndWilson(t *testing.T) {
	// FS-06 follows the classic 2x2 table: TP/TP 20, TP/FP 5, FP/TP 10, FP/FP 15.
	// Its 15 disagreements are resolved by consensus: 9 TP and 6 FP.
	var rows []Row
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelTP, LabelTP, "", 20)...)
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelFP, LabelFP, "", 15)...)
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelTP, LabelFP, LabelTP, 3)...)
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelTP, LabelFP, LabelFP, 2)...)
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelFP, LabelTP, LabelTP, 6)...)
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelFP, LabelTP, LabelFP, 4)...)
	// EXEC-01: ten agreed TPs, one category only, so kappa is undefined.
	rows = append(rows, mkRows("EXEC-01", CategoryFailure, LabelTP, LabelTP, "", 10)...)
	// SPEC-07: two TP, one FP, two UNDECIDABLE, all agreed.
	rows = append(rows, mkRows("SPEC-07", CategoryFailure, LabelTP, LabelTP, "", 2)...)
	rows = append(rows, mkRows("SPEC-07", CategoryFailure, LabelFP, LabelFP, "", 1)...)
	rows = append(rows, mkRows("SPEC-07", CategoryFailure, LabelUndecidable, LabelUndecidable, "", 2)...)

	s := Score(rows, "x.csv", "abc", DefaultThreshold)

	fs06 := find(t, s, "FS-06")
	if fs06.Agreement.Rated != 50 || fs06.Agreement.Agree != 35 || fs06.Agreement.Agreement == nil || !near(*fs06.Agreement.Agreement, 0.7) {
		t.Errorf("FS-06 agreement = %+v", fs06.Agreement)
	}
	if fs06.Agreement.Kappa == nil || !near(*fs06.Agreement.Kappa, 0.4) {
		t.Errorf("FS-06 kappa = %v, want 0.4", fs06.Agreement.Kappa)
	}
	// Resolved: 20 agreed TP + 9 consensus TP, 15 agreed FP + 6 consensus FP.
	if fs06.TP != 29 || fs06.FP != 21 || fs06.Resolved != 50 || fs06.Unresolved != 0 {
		t.Errorf("FS-06 resolution = %+v", fs06)
	}
	lo, hi, _ := stats.Wilson(29, 50)
	if fs06.Precision == nil || !near(fs06.Precision.Estimate, 0.58) || !near(fs06.Precision.Lo, lo) || !near(fs06.Precision.Hi, hi) {
		t.Errorf("FS-06 precision = %+v, want 0.58 [%v, %v]", fs06.Precision, lo, hi)
	}
	if fs06.MeetsThreshold {
		t.Error("precision 0.58 must not meet the 0.8 threshold")
	}

	exec1 := find(t, s, "EXEC-01")
	if exec1.Agreement.Kappa != nil {
		t.Errorf("single-category agreement must leave kappa undefined, got %v", *exec1.Agreement.Kappa)
	}
	if exec1.Agreement.Agreement == nil || !near(*exec1.Agreement.Agreement, 1) {
		t.Errorf("EXEC-01 agreement = %+v", exec1.Agreement)
	}
	if exec1.Precision == nil || !near(exec1.Precision.Estimate, 1) || !near(exec1.Precision.Hi, 1) || math.Abs(exec1.Precision.Lo-0.7225) > 5e-4 {
		t.Errorf("EXEC-01 precision = %+v, want 1.0 with lower bound about 0.7225", exec1.Precision)
	}
	if !exec1.MeetsThreshold {
		t.Error("precision 1.0 must meet the threshold")
	}

	spec07 := find(t, s, "SPEC-07")
	if spec07.TP != 2 || spec07.FP != 1 || spec07.Undecid != 2 || spec07.Resolved != 3 {
		t.Errorf("SPEC-07 resolution = %+v", spec07)
	}
	if spec07.Precision == nil || !near(spec07.Precision.Estimate, 2.0/3.0) {
		t.Errorf("UNDECIDABLE rows must stay out of precision: %+v", spec07.Precision)
	}
	if s.Rows != len(rows) || s.Unrated != 0 || s.Overall.Rated != len(rows) {
		t.Errorf("overall = rows %d unrated %d rated %d", s.Rows, s.Unrated, s.Overall.Rated)
	}
	if s.Overall.Kappa == nil {
		t.Error("overall kappa must be defined with several categories")
	}
	// Checks are listed in natural rule order.
	var order []string
	for _, c := range s.Checks {
		order = append(order, c.Rule)
	}
	if strings.Join(order, ",") != "EXEC-01,FS-06,SPEC-07" {
		t.Errorf("check order = %v", order)
	}
}

func TestScoreUnratedUnresolvedAndNoPrecision(t *testing.T) {
	var rows []Row
	rows = append(rows, mkRows("FS-07", CategoryFinding, LabelTP, "", "", 2)...)               // only rater A: unrated and unresolved
	rows = append(rows, mkRows("FS-07", CategoryFinding, LabelTP, LabelFP, "", 3)...)          // disagree, no consensus: unresolved
	rows = append(rows, mkRows("FS-07", CategoryFinding, LabelUndecidable, "", LabelFP, 1)...) // consensus without raters resolves
	rows = append(rows, mkRows("EXEC-04", CategoryFailure, LabelUndecidable, LabelUndecidable, "", 4)...)
	s := Score(rows, "x.csv", "abc", DefaultThreshold)
	fs07 := find(t, s, "FS-07")
	if fs07.Unrated != 3 || fs07.Unresolved != 5 || fs07.FP != 1 || fs07.TP != 0 {
		t.Errorf("FS-07 = %+v", fs07)
	}
	if fs07.Agreement.Rated != 3 {
		t.Errorf("only doubly rated rows enter kappa: rated = %d", fs07.Agreement.Rated)
	}
	if fs07.Precision == nil || fs07.Precision.Estimate != 0 || fs07.Precision.Lo != 0 {
		t.Errorf("0 TP of 1 resolved gives precision 0: %+v", fs07.Precision)
	}
	exec4 := find(t, s, "EXEC-04")
	if exec4.Precision != nil || exec4.MeetsThreshold || exec4.Resolved != 0 {
		t.Errorf("a check with nothing resolved as TP or FP has no precision: %+v", exec4)
	}
	if s.Unrated != 3 {
		t.Errorf("unrated = %d", s.Unrated)
	}
}

func TestScoreFixtureCandidatesAreSeparate(t *testing.T) {
	var rows []Row
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelTP, LabelTP, "", 8)...)
	rows = append(rows, mkRows("FS-06", CategoryFinding, LabelFP, LabelFP, "", 2)...)
	// Exempted candidates: 1 real leak wrongly exempted, 3 correctly exempted.
	rows = append(rows, mkRows("FS-06", CategoryFixtureCandidate, LabelTP, LabelTP, "", 1)...)
	rows = append(rows, mkRows("FS-06", CategoryFixtureCandidate, LabelFP, LabelFP, "", 3)...)
	s := Score(rows, "x.csv", "abc", DefaultThreshold)
	c := find(t, s, "FS-06")
	if c.TP != 8 || c.FP != 2 || !near(c.Precision.Estimate, 0.8) || !c.MeetsThreshold {
		t.Errorf("fixture candidates leaked into precision: %+v", c)
	}
	f := c.FixtureCandidates
	if f == nil || f.Rows != 4 || f.TP != 1 || f.FP != 3 || f.WronglyExempted == nil || !near(f.WronglyExempted.Estimate, 0.25) {
		t.Errorf("fixture summary = %+v", f)
	}
	if find(t, Score(mkRows("EXEC-01", CategoryFailure, LabelTP, LabelTP, "", 1), "x", "y", 0.8), "EXEC-01").FixtureCandidates != nil {
		t.Error("rules without fixture rows have no fixture summary")
	}
}

func TestReadRowsValidation(t *testing.T) {
	header := "finding_id,image,rule,category,evidence,rater_a,rater_b,consensus\n"
	rows, err := ReadRows(strings.NewReader(header + "id1,img,FS-06,finding,\"line one\nline two\",tp, fp ,\nid2,img,EXEC-01,failure,e,,,undecidable\n"))
	if err != nil {
		t.Fatalf("ReadRows: %v", err)
	}
	if rows[0].RaterA != LabelTP || rows[0].RaterB != LabelFP || rows[0].Evidence != "line one\nline two" {
		t.Errorf("lowercase and padded labels must normalise: %+v", rows[0])
	}
	if rows[1].Consensus != LabelUndecidable {
		t.Errorf("consensus = %q", rows[1].Consensus)
	}
	bad := map[string]string{
		"unknown label":  header + "id1,img,FS-06,finding,e,MAYBE,TP,\n",
		"missing column": "finding_id,image,rule\nid1,img,FS-06\n",
		"no rule":        header + "id1,img,,finding,e,TP,TP,\n",
		"empty":          "",
	}
	for name, content := range bad {
		if _, err := ReadRows(strings.NewReader(content)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	_, err = ReadRows(strings.NewReader(header + "id1,img,FS-06,finding,e,MAYBE,TP,\n"))
	if err == nil || !strings.Contains(err.Error(), "row 2") || !strings.Contains(err.Error(), "rater_a") {
		t.Errorf("error must name the row and column: %v", err)
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		row   Row
		label string
		how   string
	}{
		{Row{RaterA: LabelTP, RaterB: LabelTP}, LabelTP, ResolvedAgreed},
		{Row{RaterA: LabelTP, RaterB: LabelFP, Consensus: LabelFP}, LabelFP, ResolvedConsensus},
		{Row{RaterA: LabelTP, RaterB: LabelTP, Consensus: LabelFP}, LabelFP, ResolvedConsensus},
		{Row{RaterA: LabelTP, RaterB: LabelFP}, "", Unresolved},
		{Row{RaterA: LabelTP}, "", Unresolved},
		{Row{}, "", Unresolved},
	}
	for _, c := range cases {
		label, how := Resolve(c.row)
		if label != c.label || how != c.how {
			t.Errorf("Resolve(%+v) = %q, %q; want %q, %q", c.row, label, how, c.label, c.how)
		}
	}
}

func TestScoreCommandWritesSummaryJSON(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "adjudication.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	_ = w.Write(csvHeader)
	for _, r := range append(mkRows("FS-06", CategoryFinding, "TP", "TP", "", 4), mkRows("EXEC-01", CategoryFailure, "TP", "FP", "TP", 2)...) {
		_ = w.Write([]string{r.ID, r.Image, r.Rule, r.Category, "evidence", r.RaterA, r.RaterB, r.Consensus})
	}
	w.Flush()
	f.Close()

	var out, errb bytes.Buffer
	if code := run([]string{"score", "-csv", csvPath, "-threshold", "0.9"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, "adjudication_summary.json"))
	if err != nil {
		t.Fatalf("summary not written next to the CSV: %v", err)
	}
	var doc struct {
		Threshold float64 `json:"precision_threshold"`
		Source    string  `json:"source"`
		SHA       string  `json:"source_sha256"`
		Rows      int     `json:"rows"`
		Checks    []struct {
			Rule      string `json:"rule"`
			Agreement struct {
				Kappa *float64 `json:"kappa"`
			} `json:"agreement"`
			Precision *struct {
				Estimate float64 `json:"estimate"`
				Lo       float64 `json:"wilson_lo"`
			} `json:"precision"`
			Meets bool `json:"meets_threshold"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("summary is not valid JSON: %v", err)
	}
	if doc.Threshold != 0.9 || doc.Source != "adjudication.csv" || len(doc.SHA) != 64 || doc.Rows != 6 || len(doc.Checks) != 2 {
		t.Errorf("summary header = %+v", doc)
	}
	// EXEC-01: rater A always TP, rater B always FP. Chance agreement is 0, so
	// kappa is defined and equals 0; consensus resolves both rows to TP.
	if doc.Checks[0].Rule != "EXEC-01" || doc.Checks[0].Agreement.Kappa == nil || *doc.Checks[0].Agreement.Kappa != 0 {
		t.Errorf("EXEC-01 kappa = %+v, want 0", doc.Checks[0])
	}
	// FS-06: both raters use one label only, so kappa is undefined (null).
	if doc.Checks[1].Rule != "FS-06" || doc.Checks[1].Agreement.Kappa != nil {
		t.Errorf("FS-06 kappa must be undefined: %+v", doc.Checks[1])
	}
	if !strings.Contains(string(data), `"kappa": null`) {
		t.Errorf("undefined kappa must serialize as null:\n%s", data)
	}
	if doc.Checks[1].Precision == nil || !doc.Checks[1].Meets {
		t.Errorf("FS-06 with 4 of 4 TP and threshold 0.9: %+v", doc.Checks[1])
	}
	if !strings.Contains(out.String(), "Adjudication summary") {
		t.Errorf("console summary missing:\n%s", out.String())
	}

	// Bad input fails clearly.
	bad := filepath.Join(dir, "bad.csv")
	if err := os.WriteFile(bad, []byte("finding_id,image,rule,category,evidence,rater_a,rater_b,consensus\nx,i,FS-06,finding,e,NOPE,,\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run([]string{"score", "-csv", bad}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "rater_a") {
		t.Errorf("an invalid label must fail with the column named: code %d %s", code, errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != spec.ExitUsage {
		t.Errorf("no subcommand: exit %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errb); code != spec.ExitUsage {
		t.Errorf("unknown subcommand: exit %d", code)
	}
	if code := run([]string{"export", "-exec-sample", "-3"}, &out, &errb); code != spec.ExitUsage {
		t.Errorf("negative sample: exit %d", code)
	}
}
