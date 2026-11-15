package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const cleanReport = "{\n  \"summary\": {\n    \"fatal\": 0,\n    \"warn\": 0,\n    \"info\": 0,\n    \"skip\": 0,\n    \"pass\": 16\n  },\n  \"details\": []\n}"

func TestParseReportRealOutput(t *testing.T) {
	cases := []struct {
		file      string
		wantCodes []string
		wantFatal int
	}{
		{"dockle_0.4.15_alpine.json", []string{"CIS-DI-0001", "CIS-DI-0005", "CIS-DI-0006"}, 0},
		{"dockle_0.4.15_seeded.json", []string{
			"CIS-DI-0007", "CIS-DI-0009", "CIS-DI-0010", "DKL-DI-0001", "DKL-DI-0002", "DKL-DI-0005", "DKL-LI-0002",
			"CIS-DI-0001", "DKL-DI-0003", "CIS-DI-0005", "CIS-DI-0006", "DKL-LI-0003",
		}, 7},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			r, err := ParseReport(readTestdata(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := r.Codes(); !reflect.DeepEqual(got, tc.wantCodes) {
				t.Errorf("codes = %v, want %v", got, tc.wantCodes)
			}
			if r.Summary.Fatal != tc.wantFatal {
				t.Errorf("summary fatal = %d, want %d", r.Summary.Fatal, tc.wantFatal)
			}
			if r.Image != "" {
				t.Errorf("image = %q, an --input run has no image name", r.Image)
			}
		})
	}
}

func TestParseReport(t *testing.T) {
	logLines := "2026-11-15T10:00:00.000Z\tINFO\tsomething from the logger\n"
	cases := []struct {
		name        string
		in          string
		wantErr     string
		wantDetails int
	}{
		{"clean image has an empty details array", cleanReport, "", 0},
		{"log lines before the report are skipped", logLines + cleanReport, "", 0},
		{"trailing text after the report is ignored", cleanReport + "\ntrailing log line\n", "", 0},
		{"windows line endings", strings.ReplaceAll(logLines+cleanReport, "\n", "\r\n"), "", 0},
		{"compact report without indentation", `{"summary":{"fatal":0,"warn":0,"info":0,"skip":0,"pass":1},"details":[]}`, "", 0},
		{"one entry", `{"summary":{"fatal":1,"warn":0,"info":0,"skip":0,"pass":0},"details":[{"code":"CIS-DI-0001","title":"t","level":"WARN","alerts":["a"]}]}`, "", 1},
		{"an image name is kept apart", `{"image":"x:1","summary":{},"details":[]}`, "", 0},
		{"empty output", "", "no JSON report", 0},
		{"only log lines", logLines, "no JSON report", 0},
		{"not json", "{\nnot json at all\n}", "not valid JSON", 0},
		{"truncated json", "{\n  \"summary\": {\n", "not valid JSON", 0},
		{"missing details must never read as a clean image", `{"summary":{"fatal":0,"warn":0,"info":0,"skip":0,"pass":16}}`, "no details array", 0},
		{"null details", `{"summary":{},"details":null}`, "no details array", 0},
		{"details is not an array", `{"summary":{},"details":{"code":"x"}}`, "not an array", 0},
		{"missing summary", `{"details":[]}`, "no summary", 0},
		{"entry without a code", `{"summary":{},"details":[{"level":"WARN","alerts":[]}]}`, "has no code", 0},
		{"an array instead of an object", `[1,2]`, "no JSON report", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseReport([]byte(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Details) != tc.wantDetails {
				t.Errorf("details = %d, want %d", len(r.Details), tc.wantDetails)
			}
		})
	}
}

func TestClassifyDetail(t *testing.T) {
	cases := []struct {
		name string
		d    DockleDetail
		want EntryState
	}{
		{"INFO is a finding", DockleDetail{Code: "CIS-DI-0006", Level: "INFO", Alerts: []string{"not found HEALTHCHECK statement"}}, EntryFinding},
		{"WARN is a finding", DockleDetail{Code: "CIS-DI-0001", Level: "WARN", Alerts: []string{"Last user should not be root"}}, EntryFinding},
		{"FATAL is a finding", DockleDetail{Code: "DKL-DI-0001", Level: "FATAL", Alerts: []string{"Avoid sudo in container : x"}}, EntryFinding},
		{"lower case level names are accepted", DockleDetail{Code: "X", Level: "fatal", Alerts: []string{"a"}}, EntryFinding},
		{"SKIP with the failed-to-detect notice is not a finding", DockleDetail{Code: "DKL-LI-0001", Level: "SKIP", Alerts: []string{"failed to detect etc/shadow,etc/master.passwd"}}, EntrySkipped},
		{"SKIP with two notices is not a finding", DockleDetail{Code: "DKL-LI-0002", Level: "SKIP", Alerts: []string{"failed to detect etc/passwd", "failed to detect etc/group"}}, EntrySkipped},
		{"SKIP that still holds a real alert is a finding", DockleDetail{Code: "DKL-LI-0002", Level: "SKIP", Alerts: []string{"duplicate UID 1000 : username dup2", "failed to detect etc/group"}}, EntryFinding},
		{"SKIP without alerts is not a finding", DockleDetail{Code: "DKL-LI-0002", Level: "SKIP"}, EntrySkipped},
		{"FATAL that carries a skip notice is still a finding", DockleDetail{Code: "DKL-LI-0002", Level: "FATAL", Alerts: []string{"failed to detect etc/passwd", "duplicate GroupID 5 : username g2"}}, EntryFinding},
		{"IGNORE is not a finding", DockleDetail{Code: "CIS-DI-0001", Level: "IGNORE", Alerts: []string{"Last user should not be root"}}, EntrySkipped},
		{"PASS in details is not a finding", DockleDetail{Code: "X", Level: "PASS"}, EntrySkipped},
		{"an unknown level counts as a finding", DockleDetail{Code: "X", Level: "CRITICAL", Alerts: []string{"a"}}, EntryFinding},
		{"an empty level counts as a finding", DockleDetail{Code: "X", Level: "", Alerts: []string{"a"}}, EntryFinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, note := ClassifyDetail(tc.d)
			if got != tc.want {
				t.Errorf("state = %s, want %s (note %q)", got, tc.want, note)
			}
		})
	}
	if _, note := ClassifyDetail(DockleDetail{Code: "X", Level: "CRITICAL"}); !strings.Contains(note, "unknown level") {
		t.Errorf("an unknown level must be reported in the note, got %q", note)
	}
}

func TestLookup(t *testing.T) {
	report := &DockleReport{Details: []DockleDetail{
		{Code: "CIS-DI-0001", Level: "WARN", Alerts: []string{"Last user should not be root"}},
		{Code: "DKL-DI-0004", Level: "FATAL", Alerts: []string{"Use --no-cache option if use 'apk add': x"}},
		{Code: "DKL-LI-0001", Level: "SKIP", Alerts: []string{"failed to detect etc/shadow,etc/master.passwd"}},
		{Code: "DKL-LI-0002", Level: "SKIP", Alerts: []string{"duplicate UID 1000 : username b", "failed to detect etc/group"}},
	}}
	cases := []struct {
		name         string
		codes        []string
		want         CodeState
		wantFindings []string
	}{
		{"finding", []string{"CIS-DI-0001"}, CodeFinding, []string{"CIS-DI-0001"}},
		{"no entry means clear", []string{"CIS-DI-0006"}, CodeClear, nil},
		{"skipped entry is not evaluated", []string{"DKL-LI-0001"}, CodeNotEvaluated, nil},
		{"skip level with a real alert is a finding", []string{"DKL-LI-0002"}, CodeFinding, []string{"DKL-LI-0002"}},
		{"one of two codes with a finding", []string{"DKL-DI-0004", "DKL-DI-0005"}, CodeFinding, []string{"DKL-DI-0004"}},
		{"a finding wins over a skipped entry", []string{"DKL-LI-0001", "CIS-DI-0001"}, CodeFinding, []string{"CIS-DI-0001"}},
		{"a skipped entry wins over a clear code", []string{"DKL-LI-0001", "CIS-DI-0006"}, CodeNotEvaluated, nil},
		{"no codes at all", nil, CodeClear, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := report.Lookup(tc.codes...)
			if got.State != tc.want {
				t.Errorf("state = %s, want %s", got.State, tc.want)
			}
			if !reflect.DeepEqual(got.Findings, tc.wantFindings) {
				t.Errorf("findings = %v, want %v", got.Findings, tc.wantFindings)
			}
		})
	}
}

func TestLookupOnRealSeededReport(t *testing.T) {
	r, err := ParseReport(readTestdata(t, "dockle_0.4.15_seeded.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range Mappings() {
		got := r.Lookup(m.Codes...)
		want := CodeClear
		for _, c := range m.Codes {
			for _, seen := range r.Codes() {
				if c == seen {
					want = CodeFinding
				}
			}
		}
		if got.State != want {
			t.Errorf("%s (%v) = %s, want %s", m.Check, m.Codes, got.State, want)
		}
	}
	// The seeded image has no DKL-DI-0004 or DKL-LI-0001 entry.
	if r.Lookup("DKL-DI-0004").State != CodeClear || r.Lookup("DKL-LI-0001").State != CodeClear {
		t.Error("codes without an entry must be clear")
	}
	// CIS-DI-0010 holds an ENV alert and a file-name alert in one entry.
	facets := findingFacets(r.Lookup("CIS-DI-0010").Entries)
	if !reflect.DeepEqual(facets, []string{FacetEnv, FacetFile}) {
		t.Errorf("facets = %v, want env and file", facets)
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"dockle version 0.4.15\n", "0.4.15", false},
		{"dockle version v0.4.15\n", "0.4.15", false},
		{"dockle version dev\n", "dev", false},
		{"noise\ndockle version 0.4.14\n", "0.4.14", false},
		{"", "", true},
		{"usage: dockle [options] image_name\n", "", true},
		{"hadolint version 2.14.0\n", "", true},
	}
	for _, tc := range cases {
		got, err := ParseVersion(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseVersion(%q) = %q, %v; want %q, error %v", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestScrubbedEnv(t *testing.T) {
	in := []string{"PATH=/bin", "DOCKLE_IGNORES=CIS-DI-0001", "HOME=/h", "DOCKLE_DEBUG=1", "DOCKLE_ACCEPT_KEYS=X", "MY_DOCKLE_X=1", "DOCKLE=1"}
	got := ScrubbedEnv(in)
	want := []string{"PATH=/bin", "HOME=/h", "MY_DOCKLE_X=1", "DOCKLE=1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScrubbedEnv = %v, want %v", got, want)
	}
}

// fakeDocklePath writes a shell script that behaves like Dockle for the parts
// the runner depends on: the version line, the arguments, the working
// directory, the DOCKLE_ variables, the exit code and the report.
func fakeDocklePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake Dockle is a shell script")
	}
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "dockle version 0.4.15"; exit 0; fi
echo "args: $*" >&2
echo "cwd: $(pwd)" >&2
env | grep '^DOCKLE_' >&2
if [ -e .dockleignore ]; then echo "dockleignore present" >&2; fi
if [ -n "$FAKE_SLEEP" ]; then sleep "$FAKE_SLEEP"; fi
echo '2026 log line before the report'
echo '{'
echo '  "summary": {"fatal":0,"warn":0,"info":0,"skip":0,"pass":16},'
echo '  "details": []'
echo '}'
exit "${FAKE_EXIT:-0}"
`
	path := filepath.Join(t.TempDir(), "dockle")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseEnv(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH")}, extra...)
}

func TestExecRunnerCommandAndEnvironment(t *testing.T) {
	// A .dockleignore in the directory of the caller must have no effect.
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".dockleignore", []byte("CIS-DI-0001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	callerDir, _ := os.Getwd()

	r := &ExecRunner{Binary: fakeDocklePath(t), Environ: baseEnv(
		"DOCKLE_IGNORES=CIS-DI-0001", "DOCKLE_ACCEPT_KEYS=SECRET", "DOCKLE_DEBUG=1", "DOCKLE_EXIT_CODE=1", "KEEP_ME=1",
	)}
	defer r.Close()

	out, err := r.Run(context.Background(), "relative/archive.tar")
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 {
		t.Errorf("exit code = %d", out.ExitCode)
	}
	stderr := string(out.Stderr)
	abs, _ := filepath.Abs("relative/archive.tar")
	if !strings.Contains(stderr, "args: --input "+abs+" --format json --exit-code 0") {
		t.Errorf("command line differs from the contract (absolute archive path expected):\n%s", stderr)
	}
	if strings.Contains(stderr, "DOCKLE_") {
		t.Errorf("a DOCKLE_ variable reached Dockle:\n%s", stderr)
	}
	if strings.Contains(stderr, "dockleignore present") {
		t.Errorf("Dockle must run in an empty directory:\n%s", stderr)
	}
	if strings.Contains(stderr, "cwd: "+callerDir) {
		t.Errorf("Dockle ran in the directory of the caller:\n%s", stderr)
	}
	if _, err := ParseReport(out.Stdout); err != nil {
		t.Errorf("the report must parse although a log line precedes it: %v", err)
	}
}

func TestExecRunnerVersion(t *testing.T) {
	r := &ExecRunner{Binary: fakeDocklePath(t), Environ: baseEnv()}
	defer r.Close()
	v, err := r.Version(context.Background())
	if err != nil || v != "0.4.15" {
		t.Errorf("Version = %q, %v", v, err)
	}
	missing := &ExecRunner{Binary: filepath.Join(t.TempDir(), "absent"), Environ: baseEnv()}
	defer missing.Close()
	if _, err := missing.Version(context.Background()); err == nil {
		t.Error("a missing binary must be an error")
	}
}

func TestExecRunnerFailures(t *testing.T) {
	bin := fakeDocklePath(t)
	t.Run("a failing exit code is returned, not an error", func(t *testing.T) {
		r := &ExecRunner{Binary: bin, Environ: baseEnv("FAKE_EXIT=3")}
		defer r.Close()
		out, err := r.Run(context.Background(), "a.tar")
		if err != nil || out.ExitCode != 3 {
			t.Errorf("exit = %d, err = %v; want exit 3 and no error", out.ExitCode, err)
		}
	})
	t.Run("a missing binary is an error", func(t *testing.T) {
		r := &ExecRunner{Binary: filepath.Join(t.TempDir(), "absent"), Environ: baseEnv()}
		defer r.Close()
		if _, err := r.Run(context.Background(), "a.tar"); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("the context cuts a slow run off", func(t *testing.T) {
		r := &ExecRunner{Binary: bin, Environ: baseEnv("FAKE_SLEEP=5")}
		defer r.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := r.Run(ctx, "a.tar")
		if err == nil || !strings.Contains(err.Error(), "cut off") {
			t.Errorf("err = %v, want a cut-off error", err)
		}
		if time.Since(start) > 3*time.Second {
			t.Error("the run was not cut off in time")
		}
	})
}

func TestExecRunnerCloseRemovesWorkingDirectory(t *testing.T) {
	r := &ExecRunner{Binary: fakeDocklePath(t), Environ: baseEnv()}
	if _, err := r.Run(context.Background(), "a.tar"); err != nil {
		t.Fatal(err)
	}
	dir := r.workDir
	if dir == "" {
		t.Fatal("no working directory was created")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the working directory %s still exists", dir)
	}
	if err := r.Close(); err != nil {
		t.Errorf("a second Close must be harmless: %v", err)
	}
}
