package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "tools", name))
	if err != nil {
		t.Fatalf("reading testdata %s: %v", name, err)
	}
	return data
}

func TestParseHadolint(t *testing.T) {
	cases := []struct {
		file string
		want []string
	}{
		{"hadolint_shell_form.json", []string{"DL3025"}},
		{"hadolint_add_local.json", []string{"DL3020"}},
		{"hadolint_clean.json", nil},
	}
	for _, tc := range cases {
		obs, err := ParseHadolint(readTestdata(t, tc.file))
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if len(obs.Flagged) != len(tc.want) || (len(tc.want) > 0 && !reflect.DeepEqual(obs.Flagged, tc.want)) {
			t.Errorf("%s: flagged = %v, want %v", tc.file, obs.Flagged, tc.want)
		}
		if obs.Emitted != nil {
			t.Errorf("%s: hadolint reports findings only, Emitted must be nil", tc.file)
		}
	}
	if _, err := ParseHadolint([]byte("")); err == nil {
		t.Error("empty hadolint output must be an error, not a clean result")
	}
	if _, err := ParseHadolint([]byte("Invalid option")); err == nil {
		t.Error("non-JSON hadolint output must be an error")
	}
}

func TestParseTrivy(t *testing.T) {
	obs, err := ParseTrivy(readTestdata(t, "trivy_misconfig.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// DS002 appears in both sections and as AVD-DS-0002. DS026 is a PASS entry
	// and must not count as a finding.
	want := []string{"AVD-DS-0002", "DS002"}
	if !reflect.DeepEqual(obs.Flagged, want) {
		t.Errorf("flagged = %v, want %v", obs.Flagged, want)
	}

	obs, err = ParseTrivy(readTestdata(t, "trivy_secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"SECRET:aws-access-key-id", "SECRET:private-key"}
	if !reflect.DeepEqual(obs.Flagged, want) {
		t.Errorf("flagged = %v, want %v", obs.Flagged, want)
	}

	obs, err = ParseTrivy(readTestdata(t, "trivy_clean.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Flagged) != 0 {
		t.Errorf("clean output flagged %v", obs.Flagged)
	}

	if _, err := ParseTrivy(readTestdata(t, "trivy_failed_section.txt")); err == nil {
		t.Error("a failed section must make the whole Trivy observation an error")
	}
	if _, err := ParseTrivy([]byte("{}")); err == nil {
		t.Error("output without sections must be an error")
	}
}

func TestParseCST(t *testing.T) {
	// cst_fail, cst_pass and cst_exec_error are real outputs of
	// container-structure-test 1.22.1. The first two name their test
	// "Command Test: rq1-root-user", the third is a test that could not run.
	result := func(name string, pass bool, errors ...string) string {
		quoted := make([]string, len(errors))
		for i, e := range errors {
			quoted[i] = strconv.Quote(e)
		}
		return `{"Pass":0,"Fail":1,"Total":1,"Results":[{"Name":` + strconv.Quote(name) + `,"Pass":` + strconv.FormatBool(pass) + `,"Errors":[` + strings.Join(quoted, ",") + `]}]}`
	}
	cases := []struct {
		name    string
		input   string
		flagged []string
		emitted []string
		wantErr string
	}{
		{name: "assertion failure of a real run", input: string(readTestdata(t, "cst_fail.json")), flagged: []string{"rq1-root-user"}, emitted: []string{"rq1-root-user"}},
		{name: "passing test of a real run", input: string(readTestdata(t, "cst_pass.json")), emitted: []string{"rq1-root-user"}},
		{name: "test that could not run, from a real run", input: string(readTestdata(t, "cst_exec_error.json")), wantErr: "did not complete"},
		{name: "log lines before the JSON object are tolerated", input: "INFO running tests\n" + string(readTestdata(t, "cst_pass.json")), emitted: []string{"rq1-root-user"}},
		{name: "name without a type prefix", input: string(readTestdata(t, "cst_other_test.json")), emitted: []string{"some-other-test"}},
		{name: "expected string missing", input: result("Command Test: t", false, "Expected string 'x' not found in output 'y'"), flagged: []string{"t"}, emitted: []string{"t"}},
		{name: "excluded string in the error stream", input: result("Command Test: t", false, "Excluded string 'x' found in error 'y'"), flagged: []string{"t"}, emitted: []string{"t"}},
		{name: "wrong exit code", input: result("Command Test: t", false, "Test 't' exited with incorrect error code. Expected: 0, Actual: 1"), flagged: []string{"t"}, emitted: []string{"t"}},
		{name: "assertion with a multi-line output", input: result("Command Test: t", false, "Excluded string '.' found in output 'a\nb\n'"), flagged: []string{"t"}, emitted: []string{"t"}},
		{name: "file existence test prefix", input: result("File Existence Test: f", false, "Expected string 'x' not found in output 'y'"), flagged: []string{"f"}, emitted: []string{"f"}},
		{name: "file content test prefix", input: result("File Content Test: f", true), emitted: []string{"f"}},
		{name: "metadata test has no name", input: result("Metadata Test", true), emitted: []string{"Metadata Test"}},
		{name: "a prefix only counts at the start", input: result("x Command Test: t", true), emitted: []string{"x Command Test: t"}},
		{name: "engine error text is not an assertion", input: result("Command Test: t", false, "Error creating container: boom"), wantErr: "did not complete"},
		{name: "an assertion followed by an engine error is not a clean detection", input: result("Command Test: t", false, "Excluded string 'x' found in output 'y'", "Error removing container"), wantErr: "did not complete"},
		{name: "words that only look like an assertion", input: result("Command Test: t", false, "Expected string was not found"), wantErr: "did not complete"},
		{name: "failure without any message", input: result("Command Test: t", false), wantErr: "without an error message"},
		{name: "no json", input: "no json here", wantErr: "no JSON object"},
		{name: "broken json", input: `{"Results":[`, wantErr: "not JSON"},
		{name: "run without results", input: `{"Pass":0,"Fail":0,"Total":0,"Results":[]}`, wantErr: "no test results"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := ParseCST([]byte(tc.input))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !sameSet(obs.Flagged, tc.flagged) || !sameSet(obs.Emitted, tc.emitted) {
				t.Errorf("flagged %v emitted %v, want flagged %v emitted %v", obs.Flagged, obs.Emitted, tc.flagged, tc.emitted)
			}
		})
	}
}

func TestParseConUnit(t *testing.T) {
	obs, err := ParseConUnit(readTestdata(t, "conunit_sigterm_fail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obs.Flagged, []string{"EXEC-03"}) {
		t.Errorf("flagged = %v", obs.Flagged)
	}
	if !reflect.DeepEqual(obs.Unverified, []string{"EXEC-01"}) {
		t.Errorf("unverified = %v", obs.Unverified)
	}
	if !reflect.DeepEqual(obs.Emitted, []string{"EXEC-01", "EXEC-03", "SPEC-01"}) {
		t.Errorf("emitted = %v", obs.Emitted)
	}
	// Results that only carry the legacy passed field still classify.
	obs, err = ParseConUnit(readTestdata(t, "conunit_legacy_passed_only.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obs.Flagged, []string{"FS-04"}) {
		t.Errorf("legacy flagged = %v", obs.Flagged)
	}
	if _, err := ParseConUnit([]byte(`{"results":[]}`)); err == nil {
		t.Error("a suite without results must be an error")
	}
}

func TestClassify(t *testing.T) {
	inScope := func(ids ...string) ToolScope { return ToolScope{InScope: true, DetectIDs: ids} }
	outOfScope := ToolScope{InScope: false, DetectIDs: []string{"DL3025"}}

	cases := []struct {
		name   string
		scope  ToolScope
		defect bool
		obs    Observation
		want   string
	}{
		{"true positive", inScope("DL3025"), true, Observation{Flagged: []string{"DL3025"}}, ClassTP},
		{"false negative", inScope("DL3025"), true, Observation{Flagged: []string{"DL3002"}}, ClassFN},
		{"false positive", inScope("DL3025"), false, Observation{Flagged: []string{"DL3025"}}, ClassFP},
		{"true negative", inScope("DL3025"), false, Observation{}, ClassTN},
		{"unrelated finding on a clean control is not a false positive", inScope("DL3025"), false, Observation{Flagged: []string{"DL3018"}}, ClassTN},
		{"wildcard detect", inScope("SECRET:*"), true, Observation{Flagged: []string{"SECRET:aws-access-key-id"}}, ClassTP},
		{"out of scope never misses a defect", outOfScope, true, Observation{}, ClassOutOfScope},
		{"out of scope on clean control", outOfScope, false, Observation{}, ClassOutOfScope},
		{"out of scope even when a watched id fires", outOfScope, true, Observation{Flagged: []string{"DL3025"}}, ClassOutOfScope},
		{"not run beats scope", outOfScope, true, Observation{NotRunReason: "binary not found on PATH"}, ClassNotRun},
		{"not run in scope", inScope("DL3025"), true, Observation{NotRunReason: "image build failed"}, ClassNotRun},
		{"error in scope is not a true negative", inScope("DL3025"), false, Observation{Error: "unexpected exit code 2"}, ClassToolError},
		{"error out of scope stays out of scope", outOfScope, false, Observation{Error: "boom"}, ClassOutOfScope},
		{
			"expected check not emitted is an error, not a silent miss",
			inScope("EXEC-03"), true,
			Observation{Emitted: []string{"SPEC-01", "FS-04"}, Flagged: []string{"SPEC-01"}},
			ClassToolError,
		},
		{
			"expected check emitted and passing on the clean control",
			inScope("EXEC-03"), false,
			Observation{Emitted: []string{"EXEC-03", "SPEC-01"}},
			ClassTN,
		},
		{
			"expected check ended unverified",
			inScope("EXEC-02"), true,
			Observation{Emitted: []string{"EXEC-02"}, Unverified: []string{"EXEC-02"}},
			ClassUnverified,
		},
	}
	for _, tc := range cases {
		got := Classify(tc.scope, tc.defect, tc.obs)
		if got.Class != tc.want {
			t.Errorf("%s: class = %s (%s), want %s", tc.name, got.Class, got.Reason, tc.want)
		}
	}
}

func TestClassifyOutOfScopeKeepsAuditTrail(t *testing.T) {
	v := Classify(ToolScope{InScope: false, DetectIDs: []string{"DS005"}}, true, Observation{Flagged: []string{"DS005", "DS002"}})
	if v.Class != ClassOutOfScope {
		t.Fatalf("class = %s", v.Class)
	}
	if !reflect.DeepEqual(v.Detected, []string{"DS005"}) {
		t.Errorf("detected = %v, want the watched id so the scope can be audited", v.Detected)
	}
	if !strings.Contains(v.Reason, "watched identifier") {
		t.Errorf("reason = %q", v.Reason)
	}
}

func TestMatchID(t *testing.T) {
	cases := []struct {
		pattern, id string
		want        bool
	}{
		{"DL3025", "DL3025", true},
		{"DL3025", "DL30251", false},
		{"SECRET:*", "SECRET:private-key", true},
		{"SECRET:*", "SECRET:", true},
		{"SECRET:*", "DS002", false},
		{"*", "anything", true},
	}
	for _, tc := range cases {
		if got := MatchID(tc.pattern, tc.id); got != tc.want {
			t.Errorf("MatchID(%q, %q) = %t, want %t", tc.pattern, tc.id, got, tc.want)
		}
	}
}

func TestSectionRoundTrip(t *testing.T) {
	text := FormatSection("trivy config a b", 0, `{"x":1}`) + FormatSection("trivy image c", 3, "line1\nline2\n")
	sections := splitSections(text)
	if len(sections) != 2 {
		t.Fatalf("sections = %d", len(sections))
	}
	if sections[0].Command != "trivy config a b" || sections[0].ExitCode != 0 || strings.TrimSpace(sections[0].Body) != `{"x":1}` {
		t.Errorf("section 0 = %+v", sections[0])
	}
	if sections[1].Command != "trivy image c" || sections[1].ExitCode != 3 || sections[1].Body != "line1\nline2\n" {
		t.Errorf("section 1 = %+v", sections[1])
	}
}
