package main

import (
	"reflect"
	"strings"
	"testing"
)

// dockleEntry renders one element of the details array.
func dockleEntry(code, level string, alerts ...string) string {
	quoted := make([]string, len(alerts))
	for i, a := range alerts {
		quoted[i] = `"` + a + `"`
	}
	return `{"code":"` + code + `","title":"t","level":"` + level + `","alerts":[` + strings.Join(quoted, ",") + `]}`
}

// dockleJSON renders a report the way Dockle prints it: the opening brace
// alone on its first line.
func dockleJSON(details ...string) string {
	return "{\n  \"summary\": {\"fatal\": 0, \"warn\": 0, \"info\": 0, \"skip\": 0, \"pass\": 16},\n  \"details\": [" + strings.Join(details, ",") + "]\n}"
}

func sameSet(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func TestParseDockle(t *testing.T) {
	// A log line as the zap console encoder of Dockle prints it, with and
	// without the color codes of the level.
	const infoLine = "2026-11-15T19:00:00.000+0100\tINFO\tscan started\n"
	const errorLine = "2026-11-15T19:00:00.000+0100\tERROR\tconfig json file doesn't exist\n"
	const coloredError = "2026-11-15T19:00:00.000+0100\t\x1b[31mERROR\x1b[0m\tFail to parse docker config file.\n"

	cases := []struct {
		name         string
		input        string
		flagged      []string
		notEvaluated []string
		levels       map[string]string
		wantErr      string
	}{
		// Findings at every level count.
		{
			name:    "warn and info from a real run",
			input:   string(readTestdata(t, "dockle_root_user_implicit.json")),
			flagged: []string{"CIS-DI-0001", "CIS-DI-0005"},
			levels:  map[string]string{"CIS-DI-0001": "WARN", "CIS-DI-0005": "INFO"},
		},
		{
			name:    "fatal and info from a real run",
			input:   string(readTestdata(t, "dockle_update_alone_defect.json")),
			flagged: []string{"CIS-DI-0005", "CIS-DI-0007", "CIS-DI-0008", "DKL-DI-0005"},
			levels:  map[string]string{"CIS-DI-0007": "FATAL", "DKL-DI-0005": "FATAL", "CIS-DI-0005": "INFO", "CIS-DI-0008": "INFO"},
		},
		{
			name:    "duplicate uid at level fatal from a real run",
			input:   string(readTestdata(t, "dockle_uid_defect.json")),
			flagged: []string{"CIS-DI-0005", "CIS-DI-0008", "DKL-LI-0002"},
			levels:  map[string]string{"DKL-LI-0002": "FATAL"},
		},
		{
			name:    "each of the three finding levels on its own",
			input:   dockleJSON(dockleEntry("A-1", "FATAL", "x"), dockleEntry("A-2", "WARN", "x"), dockleEntry("A-3", "INFO", "x")),
			flagged: []string{"A-1", "A-2", "A-3"},
			levels:  map[string]string{"A-1": "FATAL", "A-2": "WARN", "A-3": "INFO"},
		},
		{
			name:    "level names are read case-insensitively",
			input:   dockleJSON(dockleEntry("A-1", "warn", "x")),
			flagged: []string{"A-1"},
			levels:  map[string]string{"A-1": "WARN"},
		},
		// Empty details.
		{name: "empty details from a real run", input: string(readTestdata(t, "dockle_empty_details.json"))},
		{name: "empty details array", input: dockleJSON()},
		// SKIP is not a finding.
		{
			name:         "skip entries whose alerts all say that a file was not found",
			input:        string(readTestdata(t, "dockle_skip_only.json")),
			flagged:      []string{"CIS-DI-0001", "CIS-DI-0005", "CIS-DI-0006"},
			notEvaluated: []string{"DKL-LI-0001", "DKL-LI-0002"},
			levels:       map[string]string{"DKL-LI-0001": "SKIP", "DKL-LI-0002": "SKIP"},
		},
		{
			name:         "skip entry that also holds a real finding is detected",
			input:        string(readTestdata(t, "dockle_skip_mixed.json")),
			flagged:      []string{"CIS-DI-0001", "CIS-DI-0005", "CIS-DI-0006", "DKL-LI-0002"},
			notEvaluated: []string{"DKL-LI-0001"},
			levels:       map[string]string{"DKL-LI-0002": "SKIP", "DKL-LI-0001": "SKIP"},
		},
		{
			name:         "skip entry without any alert is not evaluated",
			input:        dockleJSON(dockleEntry("DKL-LI-0001", "SKIP")),
			notEvaluated: []string{"DKL-LI-0001"},
		},
		{
			name:    "skip entry with a single non skip alert is detected",
			input:   dockleJSON(dockleEntry("DKL-LI-0002", "SKIP", "failed to detect etc/group", "duplicate GroupID 5 : username x")),
			flagged: []string{"DKL-LI-0002"},
		},
		{
			name:         "the failed to detect prefix must start the alert",
			input:        dockleJSON(dockleEntry("DKL-LI-0002", "SKIP", "note: failed to detect etc/group")),
			flagged:      []string{"DKL-LI-0002"},
			notEvaluated: nil,
		},
		{
			name:         "ignore level is a suppressed checkpoint, not a finding",
			input:        dockleJSON(dockleEntry("CIS-DI-0001", "IGNORE")),
			notEvaluated: []string{"CIS-DI-0001"},
		},
		{
			name:  "pass level never counts",
			input: dockleJSON(dockleEntry("CIS-DI-0001", "PASS", "fine")),
		},
		{
			name:         "a code at a finding level is not also not evaluated",
			input:        dockleJSON(dockleEntry("DKL-LI-0002", "SKIP", "failed to detect etc/group"), dockleEntry("DKL-LI-0002", "FATAL", "duplicate UID 1 : username x")),
			flagged:      []string{"DKL-LI-0002"},
			notEvaluated: nil,
		},
		// Log lines before the report.
		{
			name:    "info log line before the report is tolerated",
			input:   infoLine + dockleJSON(dockleEntry("A-1", "WARN", "x")),
			flagged: []string{"A-1"},
		},
		{
			name:    "windows line endings",
			input:   strings.ReplaceAll(dockleJSON(dockleEntry("A-1", "WARN", "x")), "\n", "\r\n"),
			flagged: []string{"A-1"},
		},
		{
			name:    "text after the report is ignored",
			input:   dockleJSON(dockleEntry("A-1", "WARN", "x")) + "\n2026-11-15T19:00:01.000+0100\tINFO\tdone\n",
			flagged: []string{"A-1"},
		},
		// An error in the log means a missing entry is not a clean result.
		{name: "error log line before the report", input: errorLine + dockleJSON(), wantErr: "logged an error"},
		{name: "error log line with a color code", input: coloredError + dockleJSON(dockleEntry("A-1", "WARN", "x")), wantErr: "logged an error"},
		{name: "fatal log line before the report", input: "2026-11-15T19:00:00.000+0100\tFATAL\tboom\n" + dockleJSON(), wantErr: "logged an error"},
		{
			name:    "the word error in a message is not an error line",
			input:   "2026-11-15T19:00:00.000+0100\tINFO\tno error found\n" + dockleJSON(),
			flagged: nil,
		},
		// Malformed input and tool errors.
		{name: "empty output", input: "", wantErr: "empty dockle output"},
		{name: "blank output", input: " \n\n", wantErr: "empty dockle output"},
		{name: "run error of a real run, a fatal log line and no report", input: string(readTestdata(t, "dockle_run_error.txt")), wantErr: "no report"},
		{name: "plain text", input: "something went wrong\n", wantErr: "no report"},
		{name: "report on one line has no opening brace line", input: `{"summary":{},"details":[]}`, wantErr: "no report"},
		{name: "truncated report", input: "{\n  \"summary\": {\"fatal\": 0},\n  \"details\": [", wantErr: "not valid JSON"},
		{name: "details of the wrong type", input: "{\n  \"summary\": {},\n  \"details\": \"none\"\n}", wantErr: "not valid JSON"},
		{name: "details key missing", input: "{\n  \"summary\": {}\n}", wantErr: "lacks the summary or details key"},
		{name: "details null", input: "{\n  \"summary\": {},\n  \"details\": null\n}", wantErr: "lacks the summary or details key"},
		{name: "summary key missing", input: "{\n  \"details\": []\n}", wantErr: "lacks the summary or details key"},
		{name: "empty object", input: "{\n}", wantErr: "lacks the summary or details key"},
		{name: "unknown level", input: dockleJSON(dockleEntry("A-1", "CRITICAL", "x")), wantErr: "unknown level"},
		{name: "entry without a level", input: dockleJSON(`{"code":"A-1","alerts":["x"]}`), wantErr: "unknown level"},
		{name: "entry without a code", input: dockleJSON(`{"level":"WARN","alerts":["x"]}`), wantErr: "has no code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := ParseDockle([]byte(tc.input))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !sameSet(obs.Flagged, tc.flagged) {
				t.Errorf("flagged = %v, want %v", obs.Flagged, tc.flagged)
			}
			if !sameSet(obs.NotEvaluated, tc.notEvaluated) {
				t.Errorf("not evaluated = %v, want %v", obs.NotEvaluated, tc.notEvaluated)
			}
			for code, level := range tc.levels {
				if obs.Levels[code] != level {
					t.Errorf("level of %s = %q, want %q", code, obs.Levels[code], level)
				}
			}
			if obs.Emitted != nil || obs.Unverified != nil {
				t.Errorf("Dockle reports findings only: emitted %v unverified %v", obs.Emitted, obs.Unverified)
			}
		})
	}
}

func TestDockleLogError(t *testing.T) {
	cases := []struct {
		name, text string
		want       bool
	}{
		{"empty", "", false},
		{"info line", "2026-11-15T19:00:00.000+0100\tINFO\tstarted\n", false},
		{"warn line", "2026-11-15T19:00:00.000+0100\tWARN\ta new version is available\n", false},
		{"debug line", "2026-11-15T19:00:00.000+0100\tDEBUG\tScan start : config file\n", false},
		{"error line", "2026-11-15T19:00:00.000+0100\tERROR\tcache assessor failed\n", true},
		{"fatal line", "2026-11-15T19:00:00.000+0100\tFATAL\tunable to initialize\n", true},
		{"panic line", "2026-11-15T19:00:00.000+0100\tPANIC\tx\n", true},
		{"colored error line", "2026-11-15T19:00:00.000+0100\t\x1b[31mERROR\x1b[0m\tx\n", true},
		{"error after an info line", "2026-11-15T19:00:00.000+0100\tINFO\ta\n2026-11-15T19:00:01.000+0100\tERROR\tb\n", true},
		{"level word in the message only", "2026-11-15T19:00:00.000+0100\tINFO\tERROR is not a level here\n", false},
		{"line without tabs", "ERROR happened\n", false},
	}
	for _, tc := range cases {
		if got := dockleLogError(tc.text) != ""; got != tc.want {
			t.Errorf("%s: error detected = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestClassifyDockle runs real Dockle reports through the classifier with the
// scopes of the oracle.
func TestClassifyDockle(t *testing.T) {
	scope := func(ids ...string) ToolScope { return ToolScope{InScope: true, DetectIDs: ids} }
	outOfScope := ToolScope{InScope: false}

	cases := []struct {
		name   string
		file   string
		scope  ToolScope
		defect bool
		want   string
	}{
		{"root user detected on the defect", "dockle_root_user_implicit.json", scope("CIS-DI-0001"), true, ClassTP},
		{"root user reported on a clean control is a false positive", "dockle_root_user_implicit.json", scope("CIS-DI-0001"), false, ClassFP},
		{"info level counts as a detection", "dockle_root_user_implicit.json", scope("CIS-DI-0005"), true, ClassTP},
		{"checkpoint not reported on the defect is a miss", "dockle_root_user_implicit.json", scope("CIS-DI-0010"), true, ClassFN},
		{"checkpoint not reported on the control is a true negative", "dockle_root_user_implicit.json", scope("CIS-DI-0010"), false, ClassTN},
		{"duplicate uid", "dockle_uid_defect.json", scope("DKL-LI-0002"), true, ClassTP},
		{"two detect ids, one fires", "dockle_update_alone_defect.json", scope("DKL-DI-0004", "DKL-DI-0005"), true, ClassTP},
		{"empty details on the defect is a miss", "dockle_empty_details.json", scope("DKL-LI-0002"), true, ClassFN},
		{"empty details on the control is a true negative", "dockle_empty_details.json", scope("DKL-LI-0002"), false, ClassTN},
		{"not evaluated on the defect is neither detection nor miss", "dockle_skip_only.json", scope("DKL-LI-0002"), true, ClassNotEvaluated},
		{"not evaluated on the control is neither silence nor alarm", "dockle_skip_only.json", scope("DKL-LI-0001"), false, ClassNotEvaluated},
		{"skip entry with a finding is a detection", "dockle_skip_mixed.json", scope("DKL-LI-0002"), true, ClassTP},
		{"skip entry of the other code stays not evaluated", "dockle_skip_mixed.json", scope("DKL-LI-0001"), true, ClassNotEvaluated},
		{"a finding of another checkpoint does not hide a not evaluated one", "dockle_skip_only.json", scope("DKL-LI-0001", "CIS-DI-0006"), true, ClassTP},
		{"out of scope is never a miss", "dockle_empty_details.json", outOfScope, true, ClassOutOfScope},
		{"out of scope stays out of scope when the checkpoint was not evaluated", "dockle_skip_only.json", ToolScope{DetectIDs: []string{"DKL-LI-0002"}}, true, ClassOutOfScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs, err := ParseDockle(readTestdata(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := Classify(tc.scope, tc.defect, obs); got.Class != tc.want {
				t.Errorf("class = %s (%s), want %s", got.Class, got.Reason, tc.want)
			}
		})
	}

	// A tool error and an absent tool keep their classes whatever the scope.
	if got := Classify(scope("CIS-DI-0001"), true, Observation{Error: "unexpected exit code 1"}); got.Class != ClassToolError {
		t.Errorf("tool error class = %s", got.Class)
	}
	if got := Classify(scope("CIS-DI-0001"), true, Observation{NotRunReason: "binary not found on PATH"}); got.Class != ClassNotRun {
		t.Errorf("not run class = %s", got.Class)
	}
}
