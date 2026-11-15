package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestAnalyzeHadolintOnlyRawDir classifies real Hadolint 2.14.0 output over the
// real corpus. Other tools are absent, so their columns must be NOT_RUN.
func TestAnalyzeHadolintOnlyRawDir(t *testing.T) {
	o := loadRealOracle(t)
	res, err := Analyze(o, "testdata/hadolint_only")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"root-user-implicit":              ClassFN, // DL3002 only fires for an explicit USER root
		"root-user-explicit":              ClassTP,
		"root-user-clean":                 ClassTN,
		"no-healthcheck-defect":           ClassTP, // DL3057 enabled explicitly
		"no-healthcheck-clean":            ClassTN,
		"setuid-binary-defect":            ClassOutOfScope,
		"setuid-binary-clean":             ClassOutOfScope,
		"world-writable-file-defect":      ClassOutOfScope,
		"world-writable-file-clean":       ClassOutOfScope,
		"private-key-file-defect":         ClassOutOfScope,
		"private-key-file-clean":          ClassOutOfScope,
		"package-cache-defect":            ClassTP, // DL3019
		"package-cache-clean":             ClassTN,
		"apt-lists-defect":                ClassTP, // DL3009
		"apt-lists-clean":                 ClassTN,
		"shell-form-entrypoint-defect":    ClassTP, // DL3025
		"shell-form-entrypoint-clean":     ClassTN,
		"add-remote-url-defect":           ClassOutOfScope, // DL3020 exempts URLs by design
		"add-remote-url-clean":            ClassOutOfScope,
		"add-local-file-defect":           ClassTP, // DL3020
		"add-local-file-clean":            ClassTN,
		"secret-in-env-defect":            ClassOutOfScope,
		"secret-in-env-clean":             ClassOutOfScope,
		"privileged-port-defect":          ClassOutOfScope,
		"privileged-port-clean":           ClassOutOfScope,
		"runtime-needs-capability-defect": ClassOutOfScope,
		"runtime-needs-capability-clean":  ClassOutOfScope,
		// The properties added with Dockle. Hadolint has no rule for an index
		// update without an install, for duplicate UIDs or for run time defects,
		// and DL3004 reports sudo.
		"update-alone-defect":            ClassOutOfScope, // DL3009 fires but is only watched
		"update-alone-clean":             ClassOutOfScope,
		"sudo-usage-defect":              ClassTP, // DL3004
		"sudo-usage-clean":               ClassTN,
		"non-unique-uid-defect":          ClassOutOfScope,
		"non-unique-uid-clean":           ClassOutOfScope,
		"needs-setuid-setgid-defect":     ClassOutOfScope,
		"needs-setuid-setgid-clean":      ClassOutOfScope,
		"writes-outside-tmp-defect":      ClassOutOfScope,
		"writes-outside-tmp-clean":       ClassOutOfScope,
		"nonroot-privileged-port-defect": ClassOutOfScope,
		"nonroot-privileged-port-clean":  ClassOutOfScope,
	}
	if len(res.Cases) != len(want) {
		t.Fatalf("cases = %d, want %d", len(res.Cases), len(want))
	}
	for _, c := range res.Cases {
		if got := c.Tools[ToolHadolint].Class; got != want[c.ID] {
			t.Errorf("hadolint on %s = %s, want %s (%s)", c.ID, got, want[c.ID], c.Tools[ToolHadolint].Reason)
		}
		for _, tool := range []string{ToolConUnit, ToolTrivy, ToolCST, ToolDockle} {
			if got := c.Tools[tool].Class; got != ClassNotRun {
				t.Errorf("%s on %s = %s, want NOT_RUN for an absent tool", tool, c.ID, got)
			}
		}
	}

	// The two facts the corpus must reproduce: Hadolint is credited for the
	// shell-form ENTRYPOINT and for ADD of a local file.
	byID := map[string]CaseResult{}
	for _, c := range res.Cases {
		byID[c.ID] = c
	}
	if got := byID["shell-form-entrypoint-defect"].Tools[ToolHadolint].Detected; len(got) != 1 || got[0] != "DL3025" {
		t.Errorf("shell-form detected = %v, want [DL3025]", got)
	}
	if got := byID["add-local-file-defect"].Tools[ToolHadolint].Detected; len(got) != 1 || got[0] != "DL3020" {
		t.Errorf("add-local-file detected = %v, want [DL3020]", got)
	}

	s := res.Summary[ToolHadolint]
	if s.Status != "RAN" {
		t.Errorf("hadolint status = %s", s.Status)
	}
	if s.Counts[ClassTP] != 7 || s.Counts[ClassFN] != 1 || s.Counts[ClassFP] != 0 || s.Counts[ClassTN] != 7 {
		t.Errorf("hadolint counts = %+v", s.Counts)
	}
	if s.Recall.Numerator != 7 || s.Recall.Denominator != 8 || s.Recall.Value == nil {
		t.Errorf("hadolint recall = %+v", s.Recall)
	}
	if s.FalsePositiveRate.Numerator != 0 || s.FalsePositiveRate.Denominator != 7 {
		t.Errorf("hadolint false positive rate = %+v", s.FalsePositiveRate)
	}
	// DL3009 fires on the update-alone defect, which is outside the scope of
	// Hadolint. It is not credited, and the audit counts it.
	if s.OutOfScopeFlagged != 1 {
		t.Errorf("out of scope flagged = %d, want 1 (DL3009 on update-alone-defect)", s.OutOfScopeFlagged)
	}
	if got := byID["update-alone-defect"].Tools[ToolHadolint]; !reflect.DeepEqual(got.Detected, []string{"DL3009"}) || !strings.Contains(got.Reason, "watched identifier") {
		t.Errorf("update-alone-defect hadolint = %+v, want the watched DL3009 in the audit", got)
	}
	if got := byID["sudo-usage-defect"].Tools[ToolHadolint].Detected; !reflect.DeepEqual(got, []string{"DL3004"}) {
		t.Errorf("sudo-usage detected = %v, want [DL3004]", got)
	}
	// The tool versions are compared with the pins of the catalogs.
	if got := res.Catalogs[ToolHadolint]; got.State != catalogMatch || got.Version != "2.14.0" {
		t.Errorf("hadolint catalog = %+v, want a match with 2.14.0", got)
	}
	if got := res.Catalogs[ToolDockle].State; got != catalogNotRun {
		t.Errorf("dockle catalog state = %s, want not_run", got)
	}
	for _, tool := range []string{ToolConUnit, ToolTrivy, ToolCST, ToolDockle} {
		if got := res.Summary[tool].Status; got != "NOT_RUN" {
			t.Errorf("%s summary status = %s, want NOT_RUN", tool, got)
		}
		if res.Summary[tool].Recall.Value != nil {
			t.Errorf("%s: a tool that did not run must not have a recall value", tool)
		}
	}
	if got := res.Tools[ToolHadolint].Version; got != "Haskell Dockerfile Linter 2.14.0" {
		t.Errorf("hadolint version = %q", got)
	}
}

func TestRenderTableHadolintOnly(t *testing.T) {
	o := loadRealOracle(t)
	res, err := Analyze(o, "testdata/hadolint_only")
	if err != nil {
		t.Fatal(err)
	}
	table := RenderTable(o, res)
	// A tool that was not run, or that is out of scope for a property, gets one
	// shaded cell over its defect and control columns. Run tools get one symbol
	// per case: defect cases in corpus order, then the clean control.
	const (
		notRun = `\multicolumn{2}{c}{\cellcolor{cuUnver!20}n/r}`
		good   = `\cellcolor{cuPass!22}`
	)
	for _, want := range []string{
		`\texttt{shell-form-entrypoint} & ` + notRun + ` & ` + good + `$\bullet$ & ` + good + `$\circ$ & ` + notRun + ` & ` + notRun + ` & ` + notRun + ` \\`,
		`\texttt{root-user} & ` + notRun + ` & \cellcolor{cuFail!24}$\times$\,$\bullet$ & ` + good + `$\circ$ & ` + notRun + ` & ` + notRun + ` & ` + notRun + ` \\`,
		`\texttt{no-healthcheck} & ` + notRun + ` & ` + good + `$\bullet$\textsuperscript{a} & ` + good + `$\circ$ & ` + notRun + ` & ` + notRun + ` & ` + notRun + ` \\`,
		`\texttt{add-remote-url} & ` + notRun + ` & \multicolumn{2}{c}{\cellcolor{cuUnver!20}\textendash{}} & ` + notRun + ` & ` + notRun + ` & ` + notRun + ` \\`,
		`\texttt{sudo-usage} & ` + notRun + ` & ` + good + `$\bullet$ & ` + good + `$\circ$ & ` + notRun + ` & ` + notRun + ` & ` + notRun + ` \\`,
		`\texttt{update-alone} & ` + notRun + ` & \multicolumn{2}{c}{\cellcolor{cuUnver!20}\textendash{}} & ` + notRun + ` & ` + notRun + ` & ` + notRun + ` \\`,
		`Recall (in scope) & \multicolumn{2}{c}{n/r} & \multicolumn{2}{c}{7/8} & \multicolumn{2}{c}{n/r} & \multicolumn{2}{c}{n/r} & \multicolumn{2}{c}{n/r}`,
		`Haskell Dockerfile Linter 2.14.0`,
		`ConUnit not run`,
		`Dockle not run`,
		`\label{tab:rq1_detection}`,
	} {
		if !strings.Contains(table, want) {
			t.Errorf("table does not contain %q\n%s", want, table)
		}
	}
	if strings.Contains(table, "textsuperscript{b}") {
		t.Error("no ConUnit pack footnote expected when ConUnit did not run")
	}
}

func TestRenderTableHasNoAnalysisProse(t *testing.T) {
	o := loadRealOracle(t)
	res, err := Analyze(o, "testdata/hadolint_only")
	if err != nil {
		t.Fatal(err)
	}
	table := strings.ToLower(RenderTable(o, res))
	for _, banned := range []string{"outperform", "superior", "better than", "we conclude", "demonstrates", "complementary"} {
		if strings.Contains(table, banned) {
			t.Errorf("generated table contains analysis wording %q", banned)
		}
	}
}

func TestLatexEscape(t *testing.T) {
	got := latexEscape(`a_b & 50% #1 {x} $y ~ ^ \`)
	want := `a\_b \& 50\% \#1 \{x\} \$y \textasciitilde{} \textasciicircum{} \textbackslash{}`
	if got != want {
		t.Errorf("latexEscape = %q, want %q", got, want)
	}
}

// fakeExec replays canned tool behavior without any binary installed.
type fakeExec struct {
	present map[string]bool
	handle  func(cmd Command) (CommandResult, error)
	calls   []Command
}

func (f *fakeExec) LookPath(name string) (string, error) {
	base := filepath.Base(name)
	if f.present[base] {
		return "/fake/bin/" + base, nil
	}
	return "", errors.New("not found")
}

func (f *fakeExec) Run(ctx context.Context, cmd Command) (CommandResult, error) {
	f.calls = append(f.calls, cmd)
	return f.handle(cmd)
}

func ok(stdout string) (CommandResult, error) { return CommandResult{Stdout: []byte(stdout)}, nil }
func exit(code int, stdout, stderr string) (CommandResult, error) {
	return CommandResult{Stdout: []byte(stdout), Stderr: []byte(stderr), ExitCode: code}, nil
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// caseOf extracts the corpus case ID from a path or image reference.
func caseOf(s string) string {
	for _, id := range []string{"user-defect", "user-clean", "sigterm-defect", "sigterm-clean", "secret-defect", "secret-clean"} {
		if strings.Contains(s, "/"+id+"/") || strings.Contains(s, "/"+id+":") || strings.HasSuffix(s, "/"+id) {
			return id
		}
	}
	return ""
}

func miniHandler(t *testing.T) func(Command) (CommandResult, error) {
	return func(cmd Command) (CommandResult, error) {
		base := filepath.Base(cmd.Name)
		switch base {
		case "podman":
			switch cmd.Args[0] {
			case "--version":
				return ok("podman version 5.8.1\n")
			case "build":
				if caseOf(argAfter(cmd.Args, "-t")) == "sigterm-defect" {
					return exit(125, "", "Error: building at STEP \"RUN\": exit status 1\n")
				}
				if !contains(cmd.Args, "--format") || argAfter(cmd.Args, "--format") != "docker" {
					t.Errorf("podman build must use --format docker, args = %v", cmd.Args)
				}
				return ok("")
			case "image":
				return ok("sha256:0123456789abcdef0123456789abcdef\n")
			case "save":
				return ok("")
			case "rmi":
				return ok("")
			}
		case "hadolint":
			if contains(cmd.Args, "--version") {
				return ok("Haskell Dockerfile Linter 2.14.0\n")
			}
			df := cmd.Args[len(cmd.Args)-1]
			if strings.Contains(df, "/sigterm-defect/") {
				return exit(1, `[{"code":"DL3025","level":"warning","line":3}]`, "")
			}
			return ok("[]")
		case "trivy":
			if cmd.Args[0] == "--version" {
				return ok("Version: 0.58.0\n")
			}
			if cmd.Args[0] == "config" {
				dir := cmd.Args[len(cmd.Args)-1]
				if strings.Contains(dir, "/user-defect") {
					return ok(`{"Results":[{"Class":"config","Misconfigurations":[{"ID":"DS002","AVDID":"AVD-DS-0002","Status":"FAIL"}]}]}`)
				}
				return ok(`{"SchemaVersion":2}`)
			}
			if cmd.Args[0] == "image" {
				if strings.Contains(argAfter(cmd.Args, "--input"), "secret-defect") {
					return ok(`{"Results":[{"Class":"secret","Secrets":[{"RuleID":"aws-access-key-id"}]}]}`)
				}
				return ok(`{"Results":[]}`)
			}
		case "con-unit":
			if cmd.Args[0] == "version" {
				return ok("ConUnit version 0.2.0 (OCI Container Unit Testing Framework)\n")
			}
			img := cmd.Args[1]
			out := argAfter(cmd.Args, "--output")
			pack := argAfter(cmd.Args, "--pack")
			id := caseOf(img)
			var body string
			failed := false
			switch id {
			case "user-defect":
				body, failed = `{"results":[{"test_id":"SPEC-01","outcome":"FAIL"}]}`, true
			case "user-clean":
				body = `{"results":[{"test_id":"SPEC-01","outcome":"PASS"}]}`
			case "sigterm-clean":
				if pack != "hygiene" {
					t.Errorf("the SIGTERM case must run with the hygiene pack, got %q", pack)
				}
				body = `{"results":[{"test_id":"EXEC-03","outcome":"PASS"}]}`
			case "secret-defect":
				body, failed = `{"results":[{"test_id":"SPEC-03","outcome":"FAIL"}]}`, true
			case "secret-clean":
				body = `{"results":[{"test_id":"SPEC-03","outcome":"PASS"}]}`
			default:
				t.Errorf("con-unit called for unexpected image %q", img)
			}
			if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if failed {
				return exit(1, "", "")
			}
			return ok("")
		}
		t.Errorf("unexpected command %s", cmd)
		return exit(127, "", "unexpected")
	}
}

func TestExecuteAndAnalyzeWithFakeTools(t *testing.T) {
	o, err := LoadOracle("testdata/mini_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	fake := &fakeExec{
		// container-structure-test is absent on purpose.
		present: map[string]bool{"podman": true, "hadolint": true, "trivy": true, "con-unit": true},
		handle:  miniHandler(t),
	}
	cfg := &RunConfig{
		Oracle:          o,
		OutDir:          out,
		Engine:          "podman",
		ConUnitFlags:    []string{"--image-source", "local"},
		TrivyConfigArgs: []string{"--format", "json"},
		TrivyImageArgs:  []string{"--format", "json"},
		ImagePrefix:     "localhost/conunit-rq1",
		Timeout:         time.Minute,
		Log:             NewLogger(io.Discard),
	}
	if _, err := Execute(context.Background(), fake, cfg); err != nil {
		t.Fatal(err)
	}

	// Raw outputs are stored per case and tool.
	for _, rel := range []string{
		"raw/tools.json",
		"raw/user-defect/run.json",
		"raw/user-defect/hadolint.txt",
		"raw/user-defect/trivy.txt",
		"raw/user-defect/conunit.txt",
		"raw/user-defect/conunit.log.txt",
		"raw/user-defect/build.log.txt",
	} {
		if _, err := os.Stat(filepath.Join(out, rel)); err != nil {
			t.Errorf("missing raw file %s: %v", rel, err)
		}
	}

	res, err := Analyze(o, out)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]string{
		ToolConUnit: {
			"user-defect": ClassTP, "user-clean": ClassTN,
			"sigterm-defect": ClassNotRun, // image build failed
			"sigterm-clean":  ClassTN,
			"secret-defect":  ClassTP, "secret-clean": ClassTN,
		},
		ToolHadolint: {
			"user-defect": ClassFN, "user-clean": ClassTN,
			"sigterm-defect": ClassTP, // Hadolint needs no image
			"sigterm-clean":  ClassTN,
			"secret-defect":  ClassOutOfScope, "secret-clean": ClassOutOfScope,
		},
		ToolTrivy: {
			"user-defect": ClassTP, "user-clean": ClassTN,
			"sigterm-defect": ClassNotRun, "sigterm-clean": ClassOutOfScope,
			"secret-defect": ClassTP, "secret-clean": ClassTN,
		},
		ToolCST: {
			"user-defect": ClassNotRun, "user-clean": ClassNotRun,
			"sigterm-defect": ClassNotRun, "sigterm-clean": ClassNotRun,
			"secret-defect": ClassNotRun, "secret-clean": ClassNotRun,
		},
	}
	for _, c := range res.Cases {
		for tool, byCase := range want {
			if got := c.Tools[tool].Class; got != byCase[c.ID] {
				t.Errorf("%s on %s = %s (%s), want %s", tool, c.ID, got, c.Tools[tool].Reason, byCase[c.ID])
			}
		}
	}

	byID := map[string]CaseResult{}
	for _, c := range res.Cases {
		byID[c.ID] = c
	}
	if b := byID["sigterm-defect"].Build; b.Status != "failed" || !strings.Contains(b.Error, "125") {
		t.Errorf("build record = %+v", b)
	}
	if b := byID["user-defect"].Build; b.Status != "built" || b.ImageID == "" {
		t.Errorf("build record = %+v", b)
	}
	if got := byID["sigterm-defect"].Tools[ToolTrivy].Reason; !strings.Contains(got, "image build failed") {
		t.Errorf("trivy reason = %q", got)
	}
	if got := byID["user-defect"].Tools[ToolCST].Reason; got != "binary not found on PATH" {
		t.Errorf("cst reason = %q", got)
	}
	if res.Summary[ToolCST].Status != "NOT_RUN" {
		t.Errorf("cst summary = %+v", res.Summary[ToolCST])
	}
	if res.Summary[ToolConUnit].Status != "PARTIAL" {
		t.Errorf("conunit summary status = %s, want PARTIAL", res.Summary[ToolConUnit].Status)
	}
	if got := res.Tools[ToolConUnit].Version; !strings.HasPrefix(got, "ConUnit version 0.2.0") {
		t.Errorf("conunit version = %q", got)
	}
	if res.Tools[ToolCST].Available {
		t.Error("cst must be recorded as unavailable")
	}

	// The images are removed again unless -keep-images is set.
	removed := 0
	for _, c := range fake.calls {
		if filepath.Base(c.Name) == "podman" && c.Args[0] == "rmi" {
			removed++
		}
	}
	if removed != 5 {
		t.Errorf("rmi calls = %d, want 5 (one per built image)", removed)
	}

	// Re-classifying the stored raw directory is deterministic and runs no tool.
	callsBefore := len(fake.calls)
	again, err := Analyze(o, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != callsBefore {
		t.Error("analysis must not execute any command")
	}
	for i, c := range again.Cases {
		for tool := range c.Tools {
			if c.Tools[tool].Class != res.Cases[i].Tools[tool].Class {
				t.Errorf("re-analysis changed %s on %s", tool, c.ID)
			}
		}
	}
}

func TestToolErrorsAreNeverSilent(t *testing.T) {
	o, err := LoadOracle("testdata/mini_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	fake := &fakeExec{
		present: map[string]bool{"podman": true, "hadolint": true},
		handle: func(cmd Command) (CommandResult, error) {
			switch filepath.Base(cmd.Name) {
			case "podman":
				if cmd.Args[0] == "--version" {
					return ok("podman version 5.8.1\n")
				}
				return ok("")
			case "hadolint":
				if contains(cmd.Args, "--version") {
					return ok("hadolint 2\n")
				}
				// Exit code 2 and unusable output.
				return exit(2, "", "Invalid option")
			}
			return exit(127, "", "")
		},
	}
	cfg := &RunConfig{
		Oracle:      o,
		OutDir:      out,
		Engine:      "podman",
		Selected:    map[string]bool{ToolHadolint: true},
		ImagePrefix: "localhost/x",
		Timeout:     time.Minute,
		Log:         NewLogger(io.Discard),
	}
	if _, err := Execute(context.Background(), fake, cfg); err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(o, out)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cases {
		got := c.Tools[ToolHadolint]
		wantClass := ClassToolError
		if !got.InScope {
			wantClass = ClassOutOfScope
		}
		if got.Class != wantClass {
			t.Errorf("hadolint on %s = %s, want %s", c.ID, got.Class, wantClass)
		}
		if got.InScope && !strings.Contains(got.Error, "exit code 2") {
			t.Errorf("hadolint on %s: error = %q", c.ID, got.Error)
		}
		// Tools that were deselected are NOT_RUN with a reason.
		if c.Tools[ToolTrivy].Class != ClassNotRun || c.Tools[ToolTrivy].Reason == "" {
			t.Errorf("trivy on %s = %+v", c.ID, c.Tools[ToolTrivy])
		}
	}
}
