package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// VerifiedDockleVersion is the Dockle release whose source was read to fix the
// JSON schema, the level names and the behaviours below (tag v0.4.15, commit
// 54368575d2a0c34a82fb05c904b8207284a64891, pkg/report/json.go,
// pkg/report/writer.go, pkg/types, pkg/run.go and the assessors). The parser
// is tolerant, but a run with another version records that the schema was not
// verified for it.
const VerifiedDockleVersion = "0.4.15"

// Level names written by Dockle in the "level" field of a detail entry
// (pkg/report/writer.go, AlertLabels). PASS is never written to details.
const (
	LevelInfo   = "INFO"
	LevelWarn   = "WARN"
	LevelFatal  = "FATAL"
	LevelSkip   = "SKIP"
	LevelIgnore = "IGNORE"
	LevelPass   = "PASS"
)

// skipAlertPrefix starts the alert text of a SKIP assessment. The user,
// passwd and group assessors write "failed to detect <files>" when the file
// they need is absent from the image.
const skipAlertPrefix = "failed to detect "

// DockleSummary is the "summary" object of the JSON report.
type DockleSummary struct {
	Fatal int `json:"fatal"`
	Warn  int `json:"warn"`
	Info  int `json:"info"`
	Skip  int `json:"skip"`
	Pass  int `json:"pass"`
}

// DockleDetail is one entry of the "details" array: one checkpoint code with
// all of its alerts.
type DockleDetail struct {
	Code   string   `json:"code"`
	Title  string   `json:"title,omitempty"`
	Level  string   `json:"level"`
	Alerts []string `json:"alerts"`
}

// DockleReport is the decoded JSON report of `dockle --format json`.
type DockleReport struct {
	// Image is empty for --input runs: Dockle writes the image name only when
	// it is given an image name.
	Image   string         `json:"image,omitempty"`
	Summary DockleSummary  `json:"summary"`
	Details []DockleDetail `json:"details"`
}

// ParseReport decodes the stdout of a Dockle run. Dockle's logger writes to
// stdout too, so log lines can precede the report; the report starts at the
// first line that is exactly "{" (the writer uses MarshalIndent) and trailing
// text is ignored.
//
// A document without a "summary" object or without a "details" array is not a
// Dockle report: an empty details array is written as [] for a clean image,
// so a missing one must never read as a clean image.
func ParseReport(stdout []byte) (*DockleReport, error) {
	start := reportStart(stdout)
	if start < 0 {
		return nil, fmt.Errorf("no JSON report in the Dockle output (%s)", excerpt(stdout))
	}
	var raw struct {
		Image   string          `json:"image"`
		Summary *DockleSummary  `json:"summary"`
		Details json.RawMessage `json:"details"`
	}
	dec := json.NewDecoder(bytes.NewReader(stdout[start:]))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("the Dockle output is not valid JSON: %v (%s)", err, excerpt(stdout[start:]))
	}
	if raw.Summary == nil {
		return nil, errors.New("the Dockle report has no summary object")
	}
	trimmed := bytes.TrimSpace(raw.Details)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("the Dockle report has no details array")
	}
	var details []DockleDetail
	if err := json.Unmarshal(trimmed, &details); err != nil {
		return nil, fmt.Errorf("the Dockle details are not an array of entries: %v", err)
	}
	for i, d := range details {
		if strings.TrimSpace(d.Code) == "" {
			return nil, fmt.Errorf("details[%d] has no code", i)
		}
	}
	return &DockleReport{Image: raw.Image, Summary: *raw.Summary, Details: details}, nil
}

// reportStart returns the offset of the first line that is exactly "{", or -1.
func reportStart(b []byte) int {
	offset := 0
	for offset <= len(b) {
		end := bytes.IndexByte(b[offset:], '\n')
		var line []byte
		if end < 0 {
			line = b[offset:]
		} else {
			line = b[offset : offset+end]
		}
		if string(bytes.TrimRight(line, "\r")) == "{" {
			return offset
		}
		if end < 0 {
			break
		}
		offset += end + 1
	}
	// A report written without indentation starts the output.
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '{' {
		return len(b) - len(bytes.TrimLeft(b, " \t\r\n"))
	}
	return -1
}

func excerpt(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	if s == "" {
		return "output is empty"
	}
	return "output starts: " + s
}

// EntryState is the meaning of one Dockle detail entry for a comparison.
type EntryState string

const (
	// EntryFinding: Dockle reported the checkpoint. Any entry at the level
	// INFO, WARN or FATAL is a finding, as fixed in docs/INTERFACE_V2.md.
	EntryFinding EntryState = "FINDING"
	// EntrySkipped: Dockle could not evaluate the checkpoint because a file
	// it needs is absent (level SKIP) or because the checkpoint was ignored
	// (level IGNORE). That is not a finding and not a clean result.
	EntrySkipped EntryState = "NOT_EVALUATED"
)

// ClassifyDetail decides what an entry means.
//
// Dockle builds one entry per code and sets its level to the level of the
// LAST assessment of that code (types.CreateAssessmentMap). A SKIP assessment
// is appended by the assessor that misses its file, so an entry of level SKIP
// can still hold real alerts from an assessor that ran earlier, for example a
// duplicate UID in /etc/passwd when /etc/group is missing. The alert text
// therefore decides for level SKIP: any alert that is not a "failed to
// detect" notice is a finding. An entry of level INFO, WARN or FATAL always
// means that the last assessment was a real one, so it is a finding.
//
// A level that this parser does not know is treated as a finding, which is the
// rule of the contract (any level), and is reported through the note.
func ClassifyDetail(d DockleDetail) (state EntryState, note string) {
	switch level := strings.ToUpper(strings.TrimSpace(d.Level)); level {
	case LevelInfo, LevelWarn, LevelFatal:
		return EntryFinding, ""
	case LevelSkip:
		for _, a := range d.Alerts {
			if !strings.HasPrefix(strings.TrimSpace(a), strings.TrimSpace(skipAlertPrefix)) {
				return EntryFinding, "level SKIP with an alert that is not a failed-to-detect notice"
			}
		}
		return EntrySkipped, "the assessor could not find the file it needs"
	case LevelIgnore:
		return EntrySkipped, "the checkpoint was ignored by a Dockle setting"
	case LevelPass:
		// Never written to details by v0.4.15; if it appears, it is not a finding.
		return EntrySkipped, "level PASS in details is unexpected"
	default:
		return EntryFinding, fmt.Sprintf("unknown level %q is counted as a finding", d.Level)
	}
}

// CodeState is Dockle's answer for one ConUnit check on one image.
type CodeState string

const (
	CodeFinding      CodeState = "FINDING"
	CodeClear        CodeState = "CLEAR"
	CodeNotEvaluated CodeState = "NOT_EVALUATED"
)

// CodeResult is the outcome of looking up a set of codes in a report.
type CodeResult struct {
	State CodeState
	// Entries are the detail entries of the looked-up codes, findings and
	// skipped ones, in report order.
	Entries []DockleDetail
	// Findings are the codes with a finding.
	Findings []string
	Notes    []string
}

// Lookup combines the entries of the given codes. A finding in any code wins,
// then a skipped entry (the checkpoint was not evaluated), otherwise the
// checkpoint is clear.
func (r *DockleReport) Lookup(codes ...string) CodeResult {
	res := CodeResult{State: CodeClear}
	want := map[string]bool{}
	for _, c := range codes {
		want[c] = true
	}
	findings := map[string]bool{}
	skipped := false
	for _, d := range r.Details {
		if !want[d.Code] {
			continue
		}
		res.Entries = append(res.Entries, d)
		state, note := ClassifyDetail(d)
		if note != "" {
			res.Notes = append(res.Notes, d.Code+": "+note)
		}
		switch state {
		case EntryFinding:
			if !findings[d.Code] {
				findings[d.Code] = true
				res.Findings = append(res.Findings, d.Code)
			}
		case EntrySkipped:
			skipped = true
		}
	}
	switch {
	case len(res.Findings) > 0:
		res.State = CodeFinding
	case skipped:
		res.State = CodeNotEvaluated
	}
	return res
}

// Codes returns the distinct codes of the report in report order.
func (r *DockleReport) Codes() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range r.Details {
		if !seen[d.Code] {
			seen[d.Code] = true
			out = append(out, d.Code)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Running Dockle

// RunOutput is what a Dockle invocation produced.
type RunOutput struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// DockleRunner runs Dockle. Tests use a fake.
type DockleRunner interface {
	// Version returns the version number Dockle prints for --version.
	Version(ctx context.Context) (string, error)
	// Run analyses a docker-archive and returns what Dockle wrote. It returns
	// an error when the process cannot be started or is cut off by the
	// context, and a RunOutput with the exit code otherwise.
	Run(ctx context.Context, archivePath string) (RunOutput, error)
}

// maxCapture bounds what is kept of a Dockle stream.
const maxCapture = 32 << 20

// killWait is how long a run is waited for after its context ended and the
// process was killed.
const killWait = time.Second

// ExecRunner runs a Dockle binary.
//
// The command is exactly `dockle --input <archive> --format json --exit-code 0`.
// Two things in the environment change what Dockle reports and are removed:
// every DOCKLE_* variable (ignored checkpoints, accepted and rejected keys and
// files, exit level, debug mode) and a .dockleignore file in the working
// directory, which is why Dockle runs in an empty temporary directory.
type ExecRunner struct {
	Binary string
	// Environ is the environment to start from. The default is os.Environ.
	Environ []string

	workDir string
}

// Close removes the empty working directory.
func (r *ExecRunner) Close() error {
	if r.workDir == "" {
		return nil
	}
	err := os.RemoveAll(r.workDir)
	r.workDir = ""
	return err
}

func (r *ExecRunner) cwd() (string, error) {
	if r.workDir == "" {
		dir, err := os.MkdirTemp("", "crosscheck-dockle-cwd-*")
		if err != nil {
			return "", err
		}
		r.workDir = dir
	}
	return r.workDir, nil
}

// ScrubbedEnv returns env without any DOCKLE_ variable.
func ScrubbedEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "DOCKLE_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func (r *ExecRunner) environ() []string {
	env := r.Environ
	if env == nil {
		env = os.Environ()
	}
	return ScrubbedEnv(env)
}

var versionLine = regexp.MustCompile(`(?m)^dockle version (\S+)\s*$`)

// Version runs `dockle --version`. Dockle has no version subcommand: `dockle
// version` would be read as an image name and start a scan.
func (r *ExecRunner) Version(ctx context.Context) (string, error) {
	dir, err := r.cwd()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, r.Binary, "--version")
	cmd.Dir = dir
	cmd.Env = r.environ()
	cmd.WaitDelay = killWait
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w (%s)", r.Binary, err, excerpt(out))
	}
	return ParseVersion(string(out))
}

// ParseVersion extracts the version number from the output of
// `dockle --version`, which urfave/cli prints as "dockle version <number>".
func ParseVersion(out string) (string, error) {
	m := versionLine.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("cannot read a version from %q", strings.TrimSpace(out))
	}
	return strings.TrimPrefix(m[1], "v"), nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxCapture - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
			l.truncated = true
		} else {
			l.buf.Write(p)
		}
	} else {
		l.truncated = true
	}
	return len(p), nil
}

// Run implements DockleRunner.
func (r *ExecRunner) Run(ctx context.Context, archivePath string) (RunOutput, error) {
	dir, err := r.cwd()
	if err != nil {
		return RunOutput{}, err
	}
	// Dockle runs in another working directory, so the path must be absolute.
	abs, err := filepath.Abs(archivePath)
	if err != nil {
		return RunOutput{}, err
	}
	cmd := exec.CommandContext(ctx, r.Binary, "--input", abs, "--format", "json", "--exit-code", "0")
	cmd.Dir = dir
	cmd.Env = r.environ()
	// A child process of Dockle that outlives a kill must not hold the run.
	cmd.WaitDelay = killWait
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	out := RunOutput{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes()}
	if stdout.truncated {
		return out, errors.New("the Dockle output exceeds the capture limit")
	}
	if runErr == nil {
		return out, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && ctx.Err() == nil {
		out.ExitCode = exitErr.ExitCode()
		return out, nil
	}
	if ctx.Err() != nil {
		return out, fmt.Errorf("dockle was cut off: %w", ctx.Err())
	}
	return out, fmt.Errorf("cannot run %s: %w", r.Binary, runErr)
}
