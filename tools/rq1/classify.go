package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Classification of one tool on one case.
const (
	ClassTP           = "TP"            // defect present, tool detected it
	ClassFP           = "FP"            // defect absent, tool reported it anyway
	ClassFN           = "FN"            // defect present, in-scope tool did not detect it
	ClassTN           = "TN"            // defect absent, tool stayed silent
	ClassOutOfScope   = "OUT_OF_SCOPE"  // the property is not addressed by the tool, never counted as a miss
	ClassNotRun       = "NOT_RUN"       // tool binary absent or its prerequisite (image build) failed
	ClassToolError    = "TOOL_ERROR"    // tool ran but produced no usable verdict
	ClassUnverified   = "UNVERIFIED"    // tool emitted the expected check with an UNVERIFIED outcome (ConUnit only)
	ClassNotEvaluated = "NOT_EVALUATED" // the tool's own check could not run on this image (Dockle SKIP), neither a detection nor a miss
)

// Observation is what one tool reported for one case, reduced to identifiers.
type Observation struct {
	// NotRunReason is set when the tool was not executed for this case.
	NotRunReason string
	// Error is set when the tool ran but its output could not be used.
	Error string
	// Emitted lists every check or test the tool produced a verdict for. It is
	// only populated by tools that report passing verdicts too (ConUnit, CST).
	Emitted []string
	// Flagged lists the identifiers the tool reported as findings or failed
	// tests.
	Flagged []string
	// Unverified lists checks that ended UNVERIFIED (ConUnit only).
	Unverified []string
	// NotEvaluated lists checkpoints the tool itself reports as not
	// evaluated on this image (Dockle entries at level SKIP whose alerts all
	// say that a required file was not found).
	NotEvaluated []string
	// Levels records the level the tool printed for each reported identifier
	// (Dockle only). Levels are kept for audit and never decide a detection.
	Levels map[string]string
}

// Verdict is the classification of one tool on one case.
type Verdict struct {
	Class    string   `json:"class"`
	Detected []string `json:"detected_ids,omitempty"` // observed IDs that matched the scope's detect_ids
	Reason   string   `json:"reason,omitempty"`
}

// Classify applies the benchmark rules. The order matters: a missing tool is
// NOT_RUN in every row, an out-of-scope property is never a miss, and a tool
// whose expected check never appears in its output is an error and not a
// silent true negative.
func Classify(scope ToolScope, defectPresent bool, obs Observation) Verdict {
	if obs.NotRunReason != "" {
		return Verdict{Class: ClassNotRun, Reason: obs.NotRunReason}
	}
	// Detected IDs are computed for every executed tool, also out of scope, so
	// the oracle's scope declaration can be audited from the results file.
	detected := matchAny(scope.DetectIDs, obs.Flagged)
	if !scope.InScope {
		reason := "property not addressed by the tool"
		if len(detected) > 0 {
			reason = "property not addressed by the tool, but a watched identifier was reported"
		}
		return Verdict{Class: ClassOutOfScope, Detected: detected, Reason: reason}
	}
	if obs.Error != "" {
		return Verdict{Class: ClassToolError, Reason: obs.Error}
	}
	// Tools that report passing verdicts too must have emitted at least one
	// of the expected checks. Otherwise the pack or test file did not cover the
	// property and a quiet output would be a false true negative.
	if obs.Emitted != nil {
		if len(matchAny(scope.DetectIDs, obs.Emitted)) == 0 {
			return Verdict{
				Class:  ClassToolError,
				Reason: fmt.Sprintf("none of the expected checks %v appear in the tool output", scope.DetectIDs),
			}
		}
	}
	if len(detected) == 0 {
		if notEvaluated := matchAny(scope.DetectIDs, obs.NotEvaluated); len(notEvaluated) > 0 {
			return Verdict{Class: ClassNotEvaluated, Reason: fmt.Sprintf("the tool did not evaluate %v on this image", notEvaluated)}
		}
		if unverified := matchAny(scope.DetectIDs, obs.Unverified); len(unverified) > 0 {
			return Verdict{Class: ClassUnverified, Reason: fmt.Sprintf("expected checks %v ended UNVERIFIED", unverified)}
		}
	}
	switch {
	case defectPresent && len(detected) > 0:
		return Verdict{Class: ClassTP, Detected: detected}
	case defectPresent:
		return Verdict{Class: ClassFN}
	case len(detected) > 0:
		return Verdict{Class: ClassFP, Detected: detected}
	default:
		return Verdict{Class: ClassTN}
	}
}

// ParseHadolint reads `hadolint --format json` output: an array of findings
// with a code such as DL3025 or SC2086.
func ParseHadolint(raw []byte) (Observation, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Observation{}, fmt.Errorf("empty hadolint output, expected a JSON array")
	}
	var findings []struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(trimmed, &findings); err != nil {
		return Observation{}, fmt.Errorf("hadolint output is not a JSON array: %w", err)
	}
	set := map[string]bool{}
	for _, f := range findings {
		if f.Code != "" {
			set[f.Code] = true
		}
	}
	return Observation{Flagged: sortedKeys(set)}, nil
}

// Dockle level names, as printed in the JSON `level` field of Dockle v0.4.15
// (pkg/report/writer.go, AlertLabels). PASS is never emitted. IGNORE appears
// only with --debug.
const (
	dockleLevelFatal  = "FATAL"
	dockleLevelWarn   = "WARN"
	dockleLevelInfo   = "INFO"
	dockleLevelSkip   = "SKIP"
	dockleLevelIgnore = "IGNORE"
	dockleLevelPass   = "PASS"
)

// dockleSkipAlertPrefix starts the only alert Dockle prints at level SKIP: the
// assessor found none of the files it reads (DKL-LI-0001, DKL-LI-0002).
const dockleSkipAlertPrefix = "failed to detect "

// ansiEscape matches the color codes of the console log encoder.
var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// dockleReport mirrors `dockle --format json`. Details is a pointer so that a
// missing key and an explicit null are told apart from the empty array Dockle
// prints for a clean image.
type dockleReport struct {
	Summary *json.RawMessage `json:"summary"`
	Details *[]struct {
		Code   string   `json:"code"`
		Title  string   `json:"title"`
		Level  string   `json:"level"`
		Alerts []string `json:"alerts"`
	} `json:"details"`
}

// dockleLogError returns the first error-level line of the log text that
// Dockle writes to stdout before the report, or "". Dockle logs an assessor
// error and then still exits 0 with a report that simply lacks the entries of
// the failed assessor, so such a report cannot be read as a clean result.
func dockleLogError(preamble string) string {
	for _, line := range strings.Split(preamble, "\n") {
		line = strings.TrimSpace(ansiEscape.ReplaceAllString(line, ""))
		if line == "" {
			continue
		}
		// The console encoder prints time, level and message separated by tabs.
		fields := strings.Split(line, "\t")
		for i := 0; i < len(fields) && i < 2; i++ {
			switch strings.TrimSpace(fields[i]) {
			case "ERROR", "FATAL", "PANIC", "DPANIC":
				return line
			}
		}
	}
	return ""
}

// ParseDockle reads `dockle --format json`. Dockle writes its log lines to the
// same stdout as the report, so the report starts at the first line that is
// exactly "{". The rules, which replace the contract sentence that every
// level is a finding, are:
//
//   - an entry at level INFO, WARN or FATAL for a code is a finding for it;
//   - an entry at level SKIP is a finding only when some alert does not start
//     with "failed to detect ". When every alert does, the checkpoint was not
//     evaluated, which is neither a finding nor a clean result;
//   - an entry at level IGNORE (only with --debug) was suppressed by the
//     configuration and counts as not evaluated;
//   - an unknown level, an entry without a code, a missing summary or details
//     key and an error line in the log are errors, never a clean result.
func ParseDockle(raw []byte) (Observation, error) {
	text := string(raw)
	if strings.TrimSpace(text) == "" {
		return Observation{}, fmt.Errorf("empty dockle output, expected a JSON report")
	}
	start, offset := -1, 0
	for _, line := range strings.SplitAfter(text, "\n") {
		if strings.TrimRight(line, "\r\n") == "{" {
			start = offset
			break
		}
		offset += len(line)
	}
	if start < 0 {
		return Observation{}, fmt.Errorf("dockle output has no report: no line is exactly %q", "{")
	}
	if msg := dockleLogError(text[:start]); msg != "" {
		return Observation{}, fmt.Errorf("dockle logged an error before the report, so an assessor may have failed and a missing entry is not a clean result: %s", msg)
	}
	var rep dockleReport
	if err := json.NewDecoder(strings.NewReader(text[start:])).Decode(&rep); err != nil {
		return Observation{}, fmt.Errorf("dockle report is not valid JSON: %w", err)
	}
	if rep.Summary == nil || rep.Details == nil {
		return Observation{}, fmt.Errorf("dockle report lacks the summary or details key, it is not a Dockle report")
	}

	flagged := map[string]bool{}
	notEvaluated := map[string]bool{}
	levels := map[string]string{}
	for i, d := range *rep.Details {
		code := strings.TrimSpace(d.Code)
		if code == "" {
			return Observation{}, fmt.Errorf("dockle report entry %d has no code", i)
		}
		level := strings.ToUpper(strings.TrimSpace(d.Level))
		levels[code] = level
		switch level {
		case dockleLevelFatal, dockleLevelWarn, dockleLevelInfo:
			flagged[code] = true
		case dockleLevelSkip:
			finding := false
			for _, a := range d.Alerts {
				if !strings.HasPrefix(a, dockleSkipAlertPrefix) {
					finding = true
					break
				}
			}
			if finding {
				flagged[code] = true
			} else {
				notEvaluated[code] = true
			}
		case dockleLevelIgnore:
			notEvaluated[code] = true
		case dockleLevelPass:
			// Dockle does not emit PASS entries. One would be no finding.
		default:
			return Observation{}, fmt.Errorf("dockle report entry %s has unknown level %q", code, d.Level)
		}
	}
	// A code that is flagged by one entry is not also not evaluated.
	for code := range flagged {
		delete(notEvaluated, code)
	}
	return Observation{Flagged: sortedKeys(flagged), NotEvaluated: sortedKeys(notEvaluated), Levels: levels}, nil
}

// trivyReport mirrors the parts of `trivy --format json` that the benchmark
// reads: misconfiguration IDs and secret rule IDs.
type trivyReport struct {
	Results []struct {
		Misconfigurations []struct {
			ID     string `json:"ID"`
			AVDID  string `json:"AVDID"`
			Status string `json:"Status"`
		} `json:"Misconfigurations"`
		Secrets []struct {
			RuleID string `json:"RuleID"`
		} `json:"Secrets"`
	} `json:"Results"`
}

// ParseTrivy reads the raw Trivy file. It holds one section per command, each
// introduced by a line that starts with "### ". Every section must parse; a
// single failed section makes the whole observation an error so a missing scan
// is never mistaken for a clean result. Misconfiguration IDs are reported as
// given (DS002 and AVD-DS-0002), secret findings as SECRET:<rule id>.
func ParseTrivy(raw []byte) (Observation, error) {
	sections := splitSections(string(raw))
	if len(sections) == 0 {
		return Observation{}, fmt.Errorf("no trivy sections found, expected lines starting with %q", sectionPrefix)
	}
	set := map[string]bool{}
	for _, s := range sections {
		if s.ExitCode != 0 {
			return Observation{}, fmt.Errorf("trivy command %q exited with code %d", s.Command, s.ExitCode)
		}
		body := bytes.TrimSpace([]byte(s.Body))
		if len(body) == 0 {
			return Observation{}, fmt.Errorf("trivy command %q produced no output", s.Command)
		}
		var rep trivyReport
		if err := json.Unmarshal(body, &rep); err != nil {
			return Observation{}, fmt.Errorf("trivy command %q: output is not JSON: %w", s.Command, err)
		}
		for _, res := range rep.Results {
			for _, m := range res.Misconfigurations {
				if strings.EqualFold(m.Status, "PASS") {
					continue
				}
				if m.ID != "" {
					set[m.ID] = true
				}
				if m.AVDID != "" {
					set[m.AVDID] = true
				}
			}
			for _, sec := range res.Secrets {
				if sec.RuleID != "" {
					set["SECRET:"+sec.RuleID] = true
				}
			}
		}
	}
	return Observation{Flagged: sortedKeys(set)}, nil
}

// cstReport mirrors `container-structure-test --output json`. The tool writes
// capitalized keys; encoding/json matches them case-insensitively.
type cstReport struct {
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Total   int `json:"total"`
	Results []struct {
		Name   string   `json:"name"`
		Pass   bool     `json:"pass"`
		Errors []string `json:"errors"`
	} `json:"results"`
}

// cstAssertionError matches the messages container-structure-test 1.22.1 writes
// when a command test ran and its expectation did not hold (pkg/types/v2/
// command.go). Any other error text, for example a container that could not
// be created, means the test did not complete.
var cstAssertionError = regexp.MustCompile(`(?s)^((Expected|Excluded) string '.*' (not found|found) in (output|error) '.*'|Test '.*' exited with incorrect error code\. Expected: -?\d+, Actual: -?\d+)$`)

// cstTypePrefixes are put in front of the test name in the results of
// container-structure-test 1.22.1, for example "Command Test: rq1-root-user".
// The oracle names the tests of its own policy files, so the prefix is removed.
var cstTypePrefixes = []string{"Command Test: ", "File Existence Test: ", "File Content Test: ", "License Test: "}

// cstTestName returns the name a policy file gave to a test.
func cstTestName(result string) string {
	for _, p := range cstTypePrefixes {
		if strings.HasPrefix(result, p) {
			return strings.TrimPrefix(result, p)
		}
	}
	return result
}

// ParseCST reads the JSON summary of Container Structure Test. A failed test
// is a detection, because the test files encode the desired state.
func ParseCST(raw []byte) (Observation, error) {
	body := bytes.TrimSpace(raw)
	start := bytes.IndexByte(body, '{')
	if start < 0 {
		return Observation{}, fmt.Errorf("no JSON object in container-structure-test output")
	}
	var rep cstReport
	if err := json.Unmarshal(body[start:], &rep); err != nil {
		return Observation{}, fmt.Errorf("container-structure-test output is not JSON: %w", err)
	}
	if len(rep.Results) == 0 {
		return Observation{}, fmt.Errorf("container-structure-test reported no test results")
	}
	emitted := map[string]bool{}
	flagged := map[string]bool{}
	for _, r := range rep.Results {
		name := cstTestName(r.Name)
		emitted[name] = true
		if r.Pass {
			continue
		}
		// A failed test is a detection only when its failure is an
		// assertion. A test that could not run says nothing about the image.
		if len(r.Errors) == 0 {
			return Observation{}, fmt.Errorf("container-structure-test test %q failed without an error message, so it cannot be told from a test that did not run", name)
		}
		for _, e := range r.Errors {
			if !cstAssertionError.MatchString(e) {
				return Observation{}, fmt.Errorf("container-structure-test test %q did not complete: %s", name, firstLine([]byte(e)))
			}
		}
		flagged[name] = true
	}
	return Observation{Emitted: sortedKeys(emitted), Flagged: sortedKeys(flagged)}, nil
}

// ParseConUnit reads the JSON written by `con-unit test --format json`, which
// is one spec.SuiteResult. FAIL wins when a rule ID appears more than once.
func ParseConUnit(raw []byte) (Observation, error) {
	body := bytes.TrimSpace(raw)
	if len(body) == 0 {
		return Observation{}, fmt.Errorf("empty con-unit output")
	}
	var suite spec.SuiteResult
	if err := json.Unmarshal(body, &suite); err != nil {
		return Observation{}, fmt.Errorf("con-unit output is not a suite result: %w", err)
	}
	if len(suite.Results) == 0 {
		return Observation{}, fmt.Errorf("con-unit output has no results")
	}
	emitted := map[string]bool{}
	flagged := map[string]bool{}
	unverified := map[string]bool{}
	for _, r := range suite.Results {
		emitted[r.TestID] = true
		switch r.EffectiveOutcome() {
		case spec.OutcomeFail:
			flagged[r.TestID] = true
		case spec.OutcomeUnverified:
			unverified[r.TestID] = true
		}
	}
	// A rule that failed in one result is not also reported as unverified.
	for id := range flagged {
		delete(unverified, id)
	}
	return Observation{
		Emitted:    sortedKeys(emitted),
		Flagged:    sortedKeys(flagged),
		Unverified: sortedKeys(unverified),
	}, nil
}

// sectionPrefix starts the header line of each command section in a raw file
// that holds several command outputs.
const sectionPrefix = "### "

// Section is one command output inside a multi-command raw file.
type Section struct {
	Command  string
	ExitCode int
	Body     string
}

// FormatSection renders one section. The header is "### <command> | exit=<n>".
func FormatSection(command string, exitCode int, body string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s%s | exit=%d\n", sectionPrefix, command, exitCode)
	sb.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		sb.WriteString("\n")
	}
	return sb.String()
}

// splitSections is the inverse of FormatSection.
func splitSections(text string) []Section {
	var sections []Section
	var cur *Section
	var body strings.Builder
	flush := func() {
		if cur != nil {
			cur.Body = body.String()
			sections = append(sections, *cur)
		}
		body.Reset()
	}
	for _, line := range strings.SplitAfter(text, "\n") {
		if strings.HasPrefix(line, sectionPrefix) {
			flush()
			header := strings.TrimSpace(strings.TrimPrefix(line, sectionPrefix))
			cmd, code := header, 0
			if i := strings.LastIndex(header, " | exit="); i >= 0 {
				cmd = header[:i]
				fmt.Sscanf(header[i+len(" | exit="):], "%d", &code)
			}
			cur = &Section{Command: cmd, ExitCode: code}
			continue
		}
		if cur != nil {
			body.WriteString(line)
		}
	}
	flush()
	return sections
}
