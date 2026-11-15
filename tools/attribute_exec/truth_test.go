package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// contractTruth is the example of docs/INTERFACE_V2.md section 4.
const contractTruth = `{
  "schema_version": 1,
  "image_prefix": "localhost/conunit-rq1",
  "cases": [
    {"case": "needs-setuid-setgid-defect", "rule": "EXEC-02", "expected_minimal": ["CAP_SETGID", "CAP_SETUID"], "manifests": true},
    {"case": "writes-outside-tmp-defect", "rule": "EXEC-01", "expected_minimal": ["/var/lib"], "manifests": true},
    {"case": "nonroot-privileged-port-defect", "rule": "EXEC-02", "expected_minimal": ["CAP_NET_BIND_SERVICE"], "manifests": false}
  ]
}`

func TestParseTruth(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string // substring, empty for success
	}{
		{"the contract example", contractTruth, ""},
		{"extra fields written by the corpus authors are ignored", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true,"property":"x","note":"n"}],"generated_by":"y"}`, ""},
		{"a case that does not manifest may have no expected set", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":[],"manifests":false}]}`, ""},
		{"wrong schema version", `{"schema_version":2,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true}]}`, "schema_version 2"},
		{"missing schema version", `{"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true}]}`, "schema_version 0"},
		{"no cases", `{"schema_version":1,"image_prefix":"p","cases":[]}`, "no cases"},
		{"manifests missing, which would drop the case from the denominator", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"]}]}`, "no manifests field"},
		{"manifests misspelled", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifest":true}]}`, "no manifests field"},
		{"unknown rule", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-04","expected_minimal":["CAP_CHOWN"],"manifests":true}]}`, "cannot be attributed"},
		{"a case that manifests needs an expected set", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":[],"manifests":true}]}`, "non-empty expected_minimal"},
		{"duplicate case", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true},{"case":"a","rule":"EXEC-01","expected_minimal":["/var/lib"],"manifests":true}]}`, "appears twice"},
		{"duplicate element", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a","rule":"EXEC-02","expected_minimal":["CAP_CHOWN","CAP_CHOWN"],"manifests":true}]}`, "twice"},
		{"case name with a slash", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"a/b","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true}]}`, "not a usable case name"},
		{"empty case name", `{"schema_version":1,"image_prefix":"p","cases":[{"case":"","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true}]}`, "not a usable case name"},
		{"not json", `{"schema_version":`, "parsing truth file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTruth([]byte(tc.in), "truth.json")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(got.SHA256) != 64 || got.Path != "truth.json" {
					t.Errorf("identity not recorded: %+v", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestContractTruthIsReadAsWritten(t *testing.T) {
	truth, err := ParseTruth([]byte(contractTruth), "t.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(truth.Cases) != 3 || truth.Cases[2].Manifests || !truth.Cases[0].Manifests {
		t.Fatalf("cases = %+v", truth.Cases)
	}
	if truth.Cases[0].Rule != RuleDropCaps || truth.Cases[1].Rule != RuleReadOnly {
		t.Errorf("rules = %s, %s", truth.Cases[0].Rule, truth.Cases[1].Rule)
	}
}

func TestImageFor(t *testing.T) {
	truth := &TruthFile{ImagePrefix: "localhost/conunit-rq1"}
	c := TruthCase{Case: "needs-setuid-setgid-defect"}
	cases := []struct{ name, prefix, file, want string }{
		{"prefix of the file", "", "localhost/conunit-rq1", "localhost/conunit-rq1/needs-setuid-setgid-defect:rq1"},
		{"flag overrides the file", "cu-tier3-test", "localhost/conunit-rq1", "cu-tier3-test/needs-setuid-setgid-defect:rq1"},
		{"trailing slash is dropped", "cu-x/", "ignored", "cu-x/needs-setuid-setgid-defect:rq1"},
	}
	for _, tc := range cases {
		truth.ImagePrefix = tc.file
		if got := truth.ImageFor(tc.prefix, c); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func resolvedAs(status string, set ...string) Attribution {
	return Attribution{Status: status, MinimalSet: set}
}

func TestJudge(t *testing.T) {
	setuidSetgid := TruthCase{Case: "gosu", Rule: RuleDropCaps, ExpectedMinimal: []string{"CAP_SETGID", "CAP_SETUID"}, Manifests: true}
	varLib := TruthCase{Case: "lib", Rule: RuleReadOnly, ExpectedMinimal: []string{"/var/lib"}, Manifests: true}
	port := TruthCase{Case: "port", Rule: RuleDropCaps, ExpectedMinimal: []string{"CAP_NET_BIND_SERVICE"}, Manifests: false}
	cases := []struct {
		name string
		c    TruthCase
		a    Attribution
		want string
	}{
		{"same set", setuidSetgid, resolvedAs(StatusResolvedMinimal, "CAP_SETGID", "CAP_SETUID"), VerdictExact},
		{"same set in another order", setuidSetgid, resolvedAs(StatusResolvedMinimal, "CAP_SETUID", "CAP_SETGID"), VerdictExact},
		{"single that equals the expected one", varLib, resolvedAs(StatusResolvedSingle, "/var/lib"), VerdictExact},
		{"one more element", setuidSetgid, resolvedAs(StatusResolvedMinimal, "CAP_CHOWN", "CAP_SETGID", "CAP_SETUID"), VerdictSuperset},
		{"two more elements", varLib, resolvedAs(StatusResolvedMinimal, "/run", "/var/lib", "/var/log"), VerdictSuperset},
		{"a strict subset does not contain the expected cause", setuidSetgid, resolvedAs(StatusResolvedSingle, "CAP_SETUID"), VerdictWrong},
		{"disjoint set", setuidSetgid, resolvedAs(StatusResolvedSingle, "CAP_CHOWN"), VerdictWrong},
		{"partial overlap", setuidSetgid, resolvedAs(StatusResolvedMinimal, "CAP_CHOWN", "CAP_SETUID"), VerdictWrong},
		{"a mount where a capability was expected", setuidSetgid, resolvedAs(StatusResolvedSingle, "/var/lib"), VerdictWrong},
		{"resolved but no set named", varLib, resolvedAs(StatusResolvedSingle), VerdictWrong},
		{"only the union resolved", setuidSetgid, resolvedAs(StatusResolvedUnion), VerdictWrong},
		{"unresolved", setuidSetgid, resolvedAs(StatusUnresolved), VerdictWrong},
		{"the defect did not reproduce although the truth says it manifests", setuidSetgid, resolvedAs(StatusNotReproduced), VerdictWrong},
		{"the baseline failed", setuidSetgid, resolvedAs(StatusBaselineFailed), VerdictWrong},
		{"not observable", setuidSetgid, resolvedAs(StatusNotObservable), VerdictWrong},
		{"image absent is no verdict", setuidSetgid, resolvedAs(StatusImageAbsent), VerdictIncomplete},
		{"engine error is no verdict", setuidSetgid, resolvedAs(StatusError), VerdictIncomplete},
		{"manifests false stays not manifested although the set matches", port, resolvedAs(StatusResolvedSingle, "CAP_NET_BIND_SERVICE"), VerdictNotManifested},
		{"manifests false and the failure did not reproduce", port, resolvedAs(StatusNotReproduced), VerdictNotManifested},
		{"manifests false and the image is absent", port, resolvedAs(StatusImageAbsent), VerdictNotManifested},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := Judge(tc.c, tc.a)
			if got != tc.want {
				t.Errorf("verdict = %s (%s), want %s", got, detail, tc.want)
			}
			if detail == "" {
				t.Error("a verdict must say why")
			}
		})
	}
}

func TestSummarizeSeededExcludesNotManifestedFromTheDenominator(t *testing.T) {
	results := []SeededResult{
		{Verdict: VerdictExact}, {Verdict: VerdictExact}, {Verdict: VerdictSuperset}, {Verdict: VerdictWrong},
		{Verdict: VerdictNotManifested}, {Verdict: VerdictNotManifested}, {Verdict: VerdictIncomplete},
	}
	s := SummarizeSeeded(results)
	want := SeededSummary{N: 4, Exact: 2, Superset: 1, Wrong: 1, NotManifested: 2, Incomplete: 1}
	if s != want {
		t.Errorf("summary = %+v, want %+v", s, want)
	}
	if empty := SummarizeSeeded(nil); empty != (SeededSummary{}) {
		t.Errorf("empty summary = %+v", empty)
	}
}

// scriptRunner is a fake engine that answers per image.
type scriptRunner struct {
	behave map[string]func(RunSpec) Observation
	absent map[string]bool
	calls  []RunSpec
}

func (s *scriptRunner) Observe(_ context.Context, rs RunSpec) Observation {
	s.calls = append(s.calls, rs)
	if f, ok := s.behave[rs.Image]; ok {
		return f(rs)
	}
	return running()
}

func (s *scriptRunner) ImagePresent(_ context.Context, image string) (bool, error) {
	return !s.absent[image], nil
}

func (s *scriptRunner) Pull(context.Context, string) error { return nil }

// needsMounts survives --read-only only with the given extra mounts.
func needsMounts(mounts ...string) func(RunSpec) Observation {
	return func(rs RunSpec) Observation {
		if !has(rs.Flags, "--read-only") {
			return running()
		}
		m := tmpfsMounts(rs.Flags)
		for _, p := range mounts {
			if _, ok := m[p]; !ok {
				return exited(1)
			}
		}
		return running()
	}
}

func seededRunner() *scriptRunner {
	const p = "localhost/conunit-rq1/"
	return &scriptRunner{behave: map[string]func(RunSpec) Observation{
		p + "needs-setuid-setgid-defect:rq1":     needsCaps("CAP_SETUID", "CAP_SETGID"),
		p + "writes-outside-tmp-defect:rq1":      needsMounts("/var/lib"),
		p + "nonroot-privileged-port-defect:rq1": func(RunSpec) Observation { return running() }, // the defect does not manifest
	}}
}

func TestRunSeededContractExample(t *testing.T) {
	truth, err := ParseTruth([]byte(contractTruth), "t.json")
	if err != nil {
		t.Fatal(err)
	}
	r := seededRunner()
	var snapshots int
	results := RunSeeded(context.Background(), r, minCfg(), truth, "", discard(), func(done []SeededResult) { snapshots++ })
	if len(results) != 3 || snapshots != 3 {
		t.Fatalf("results %d, snapshots %d", len(results), snapshots)
	}
	want := []struct{ verdict, set string }{
		{VerdictExact, "CAP_SETGID + CAP_SETUID"},
		{VerdictExact, "/var/lib"},
		{VerdictNotManifested, ""},
	}
	for i, w := range want {
		if results[i].Verdict != w.verdict || setLabel(results[i].MinimalSet) != w.set {
			t.Errorf("%s: verdict %s, set %q, want %s and %q (%s)", results[i].Case, results[i].Verdict, setLabel(results[i].MinimalSet), w.verdict, w.set, results[i].Detail)
		}
	}
	if s := SummarizeSeeded(results); s.N != 2 || s.Exact != 2 || s.NotManifested != 1 || s.Wrong != 0 {
		t.Errorf("summary = %+v", s)
	}
	// Seeded images are addressed by <prefix>/<case>:rq1 and run under the profile.
	for _, c := range r.calls {
		if !strings.HasPrefix(c.Image, "localhost/conunit-rq1/") || !strings.HasSuffix(c.Image, ":rq1") {
			t.Errorf("unexpected image %s", c.Image)
		}
		if !has(c.Flags, "--network=none") {
			t.Errorf("run without the defensive profile: %v", c.Flags)
		}
	}
}

func TestRunSeededScoresWrongAndSupersetAndPrefixOverride(t *testing.T) {
	truth, err := ParseTruth([]byte(`{"schema_version":1,"image_prefix":"ignored","cases":[
	  {"case":"wrong","rule":"EXEC-02","expected_minimal":["CAP_SETGID","CAP_SETUID"],"manifests":true},
	  {"case":"superset","rule":"EXEC-02","expected_minimal":["CAP_SETGID","CAP_SETUID"],"manifests":true},
	  {"case":"exact","rule":"EXEC-01","expected_minimal":["/var/lib","/var/log"],"manifests":true}
	]}`), "t.json")
	if err != nil {
		t.Fatal(err)
	}
	r := &scriptRunner{behave: map[string]func(RunSpec) Observation{
		"cu-tier3-t/wrong:rq1":    needsCaps("CAP_CHOWN"),
		"cu-tier3-t/superset:rq1": needsCaps("CAP_SETUID", "CAP_SETGID", "CAP_CHOWN"),
		"cu-tier3-t/exact:rq1":    needsMounts("/var/lib", "/var/log"),
	}}
	results := RunSeeded(context.Background(), r, minCfg(), truth, "cu-tier3-t", discard(), nil)
	got := []string{results[0].Verdict, results[1].Verdict, results[2].Verdict}
	if strings.Join(got, ",") != "WRONG,SUPERSET,EXACT" {
		t.Errorf("verdicts = %v (%s | %s | %s)", got, results[0].Detail, results[1].Detail, results[2].Detail)
	}
	if s := SummarizeSeeded(results); s.N != 3 || s.Exact != 1 || s.Superset != 1 || s.Wrong != 1 {
		t.Errorf("summary = %+v", s)
	}
}

func TestRunSeededWithoutMinimizationCannotNameATwoElementSet(t *testing.T) {
	truth, _ := ParseTruth([]byte(contractTruth), "t.json")
	r := seededRunner()
	results := RunSeeded(context.Background(), r, cfg(), truth, "", discard(), nil) // Minimize off
	if results[0].Verdict != VerdictWrong || !strings.Contains(results[0].Detail, "no minimal set") {
		t.Errorf("gosu case = %s (%s)", results[0].Verdict, results[0].Detail)
	}
	if results[1].Verdict != VerdictExact {
		t.Errorf("the single mount is found without minimization, got %s", results[1].Verdict)
	}
}

func TestRunSeededAbsentImageIsIncompleteNotWrong(t *testing.T) {
	truth, _ := ParseTruth([]byte(contractTruth), "t.json")
	r := seededRunner()
	r.absent = map[string]bool{"localhost/conunit-rq1/writes-outside-tmp-defect:rq1": true}
	results := RunSeeded(context.Background(), r, minCfg(), truth, "", discard(), nil)
	if results[1].Verdict != VerdictIncomplete || results[1].Attribution.Status != StatusImageAbsent {
		t.Errorf("absent case = %s / %s", results[1].Verdict, results[1].Attribution.Status)
	}
	if s := SummarizeSeeded(results); s.N != 1 || s.Incomplete != 1 {
		t.Errorf("summary = %+v, an absent image must stay out of the denominator and be counted as incomplete", s)
	}
}

func TestRunSeededStopsOnCancel(t *testing.T) {
	truth, _ := ParseTruth([]byte(contractTruth), "t.json")
	ctx, cancel := context.WithCancel(context.Background())
	r := seededRunner()
	r.behave["localhost/conunit-rq1/needs-setuid-setgid-defect:rq1"] = func(rs RunSpec) Observation {
		cancel()
		return needsCaps("CAP_SETUID", "CAP_SETGID")(rs)
	}
	results := RunSeeded(ctx, r, minCfg(), truth, "", discard(), nil)
	if len(results) != 1 {
		t.Errorf("results = %d, the second case must not start after the cancel", len(results))
	}
}

// ---------------------------------------------------------------------------
// execute: the whole tool against a fake runner

func writeTruthFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "tier3_truth.json")
	if err := os.WriteFile(path, []byte(contractTruth), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeStudyFile(t *testing.T, dir string, images ...*spec.SuiteResult) string {
	t.Helper()
	st := spec.Study{SchemaVersion: spec.SchemaVersion, Run: spec.RunMetadata{ProbeWindowMs: 3000, EngineName: "podman", EngineVersion: "5.0"}, Images: images}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "empirical_study.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readDoc(t *testing.T, dir string) *Document {
	t.Helper()
	doc, err := LoadDocument(filepath.Join(dir, attributionJSON))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

var testMeta = spec.RunMetadata{EngineName: "podman", EngineVersion: "5.0", ConUnitVersion: "test"}

func TestExecuteTruthOnlyWritesTheSeededBlock(t *testing.T) {
	dir := t.TempDir()
	opts := options{truthPath: writeTruthFile(t, dir), outDir: dir, minimize: true}
	code := execute(context.Background(), opts, seededRunner(), testMeta, discard())
	if code != spec.ExitOK {
		t.Fatalf("exit %d", code)
	}
	doc := readDoc(t, dir)
	if doc.HasStudy() || doc.Seeded == nil || len(doc.Seeded.Cases) != 3 || !doc.Seeded.Complete {
		t.Fatalf("document = %+v", doc)
	}
	if s := doc.Seeded.Summary; s.N != 2 || s.Exact != 2 || s.NotManifested != 1 {
		t.Errorf("summary = %+v", s)
	}
	if doc.Seeded.TruthSHA256 == "" || doc.Seeded.ImagePrefix != "localhost/conunit-rq1" || doc.Seeded.WindowMs != 3000 || !doc.Seeded.Minimize {
		t.Errorf("seeded block does not describe its run: %+v", doc.Seeded)
	}
	data, err := os.ReadFile(filepath.Join(dir, attributionCSV))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rows[0], ",") != strings.Join(csvHeader, ",") {
		t.Errorf("header = %v", rows[0])
	}
	verdicts := map[string]string{}
	for _, row := range rows[1:] {
		if row[12] != scopeSeeded {
			t.Errorf("row scope = %q, want seeded: %v", row[12], row[:3])
		}
		verdicts[row[0]] = row[13]
	}
	if verdicts["localhost/conunit-rq1/needs-setuid-setgid-defect:rq1"] != VerdictExact ||
		verdicts["localhost/conunit-rq1/nonroot-privileged-port-defect:rq1"] != VerdictNotManifested {
		t.Errorf("verdicts in the CSV = %v", verdicts)
	}
}

func TestExecuteIncompleteSeededRunExitsThree(t *testing.T) {
	dir := t.TempDir()
	opts := options{truthPath: writeTruthFile(t, dir), outDir: dir, minimize: true}
	r := seededRunner()
	r.absent = map[string]bool{"localhost/conunit-rq1/needs-setuid-setgid-defect:rq1": true}
	if code := execute(context.Background(), opts, r, testMeta, discard()); code != spec.ExitIncomplete {
		t.Errorf("exit %d, want %d", code, spec.ExitIncomplete)
	}
	if doc := readDoc(t, dir); doc.Seeded == nil || doc.Seeded.Summary.Incomplete != 1 {
		t.Errorf("the incomplete case must be in the file: %+v", doc.Seeded)
	}
}

func TestExecuteImagePrefixOverridesTheFile(t *testing.T) {
	dir := t.TempDir()
	opts := options{truthPath: writeTruthFile(t, dir), outDir: dir, minimize: true, imagePrefix: "cu-tier3-x"}
	r := &scriptRunner{behave: map[string]func(RunSpec) Observation{}}
	execute(context.Background(), opts, r, testMeta, discard())
	if len(r.calls) == 0 || !strings.HasPrefix(r.calls[0].Image, "cu-tier3-x/") {
		t.Fatalf("calls = %v", r.calls)
	}
	if doc := readDoc(t, dir); doc.Seeded.ImagePrefix != "cu-tier3-x" {
		t.Errorf("image prefix = %q", doc.Seeded.ImagePrefix)
	}
}

func TestExecuteKeepsTheOtherBlockOfAnEarlierRun(t *testing.T) {
	dir := t.TempDir()
	study := writeStudyFile(t, dir, suite("web", spec.StatusCompleted, res("EXEC-02", spec.OutcomeFail)))
	truthPath := writeTruthFile(t, dir)
	runner := seededRunner()
	runner.behave["web"] = needsCaps("CAP_CHOWN", "CAP_FOWNER")

	// 1. The study run writes the study block.
	if code := execute(context.Background(), options{studyPath: study, outDir: dir, minimize: true, rules: []string{RuleDropCaps}}, runner, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("study run exit %d", code)
	}
	first := readDoc(t, dir)
	if !first.HasStudy() || first.Seeded != nil || len(first.Attributions) != 1 || first.Attributions[0].Status != StatusResolvedMinimal {
		t.Fatalf("study run = %+v", first)
	}

	// 2. A truth-only run adds the seeded block and keeps the study block.
	if code := execute(context.Background(), options{truthPath: truthPath, outDir: dir, minimize: true}, runner, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("truth run exit %d", code)
	}
	second := readDoc(t, dir)
	if !second.HasStudy() || second.Seeded == nil || strings.Join(second.CarriedOver, ",") != blockStudy {
		t.Fatalf("truth run: study %t, seeded %v, carried over %v", second.HasStudy(), second.Seeded != nil, second.CarriedOver)
	}
	if second.Source.StudySHA256 != first.Source.StudySHA256 || len(second.Attributions) != 1 || second.Summary.Total.ResolvedByMinimal != 1 {
		t.Errorf("the study block changed: %+v", second.Summary.Total)
	}
	if got := strings.Join(second.Attributions[0].MinimalSet, "+"); got != "CAP_CHOWN+CAP_FOWNER" {
		t.Errorf("carried minimal set = %s", got)
	}

	// 3. A new study run keeps the seeded block.
	if code := execute(context.Background(), options{studyPath: study, outDir: dir, minimize: true, rules: []string{RuleDropCaps}}, runner, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("second study run exit %d", code)
	}
	third := readDoc(t, dir)
	if third.Seeded == nil || strings.Join(third.CarriedOver, ",") != blockSeeded || third.Seeded.Summary.Exact != 2 {
		t.Errorf("study run: seeded %v, carried over %v", third.Seeded != nil, third.CarriedOver)
	}

	// 4. A run with both blocks carries nothing over.
	if code := execute(context.Background(), options{studyPath: study, truthPath: truthPath, outDir: dir, minimize: true, rules: []string{RuleDropCaps}}, runner, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("combined run exit %d", code)
	}
	if fourth := readDoc(t, dir); len(fourth.CarriedOver) != 0 || !fourth.HasStudy() || fourth.Seeded == nil {
		t.Errorf("combined run carried %v", fourth.CarriedOver)
	}
}

func TestExecuteIgnoresAnUnreadablePreviousDocument(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, attributionJSON), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := options{truthPath: writeTruthFile(t, dir), outDir: dir, minimize: true}
	if code := execute(context.Background(), opts, seededRunner(), testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("exit %d", code)
	}
	if doc := readDoc(t, dir); doc.Seeded == nil || len(doc.CarriedOver) != 0 {
		t.Errorf("document = %+v", doc)
	}
}

func TestExecuteRejectsAnInvalidTruthFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte(`{"schema_version":1,"cases":[]}`), 0o644)
	if code := execute(context.Background(), options{truthPath: path, outDir: dir}, seededRunner(), testMeta, discard()); code != spec.ExitUsage {
		t.Errorf("exit %d, want %d", code, spec.ExitUsage)
	}
	if _, err := os.Stat(filepath.Join(dir, attributionJSON)); err == nil {
		t.Error("nothing may be written for an invalid truth file")
	}
}

func TestParseOptions(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(t *testing.T, o options)
	}{
		{"study as the only argument", []string{"results/empirical_study.json"}, false, func(t *testing.T, o options) {
			if o.studyPath != "results/empirical_study.json" || !o.minimize || strings.Join(o.rules, ",") != "EXEC-01,EXEC-02" {
				t.Errorf("options = %+v", o)
			}
		}},
		{"study flag", []string{"-study", "s.json", "-out-dir", "o"}, false, func(t *testing.T, o options) {
			if o.studyPath != "s.json" || o.outDir != "o" {
				t.Errorf("options = %+v", o)
			}
		}},
		{"minimize off", []string{"-study", "s.json", "-minimize=false"}, false, func(t *testing.T, o options) {
			if o.minimize {
				t.Error("minimize must be off")
			}
		}},
		{"truth with a study", []string{"-study", "s.json", "-truth", "t.json", "-image-prefix", "p"}, false, func(t *testing.T, o options) {
			if o.truthPath != "t.json" || o.imagePrefix != "p" {
				t.Errorf("options = %+v", o)
			}
		}},
		{"truth alone needs an out-dir", []string{"-truth", "t.json"}, true, nil},
		{"truth alone with an out-dir", []string{"-truth", "t.json", "-out-dir", "o"}, false, nil},
		{"nothing to do", []string{}, true, nil},
		{"image prefix without truth", []string{"-study", "s.json", "-image-prefix", "p"}, true, nil},
		{"study given twice", []string{"-study", "s.json", "t.json"}, true, nil},
		{"two positional arguments", []string{"a.json", "b.json"}, true, nil},
		{"unknown rule", []string{"-study", "s.json", "-rules", "EXEC-04"}, true, nil},
		{"empty rules", []string{"-study", "s.json", "-rules", " , "}, true, nil},
		{"negative limit", []string{"-study", "s.json", "-limit", "-1"}, true, nil},
		{"negative window", []string{"-study", "s.json", "-probe-window", "-1s"}, true, nil},
		{"unknown flag", []string{"-study", "s.json", "-nope"}, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errBuf bytes.Buffer
			o, err := parseOptions(tc.args, &errBuf, NewLogger(&errBuf))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %t (output: %s)", err, tc.wantErr, errBuf.String())
			}
			if tc.check != nil && err == nil {
				tc.check(t, o)
			}
		})
	}
}

func TestDocumentIsSchemaTwoAndStudyBlockIsOptional(t *testing.T) {
	doc := &Document{SchemaVersion: documentSchemaVersion, GeneratedAt: time.Unix(0, 0).UTC(), Attributions: []Attribution{}}
	if doc.HasStudy() {
		t.Error("a document without a study path has no study block")
	}
	data, _ := json.Marshal(doc)
	if strings.Contains(string(data), "study_path") || strings.Contains(string(data), `"seeded"`) {
		t.Errorf("empty blocks must not be written: %s", data)
	}
	var nilDoc *Document
	if nilDoc.HasStudy() {
		t.Error("nil document")
	}
}
