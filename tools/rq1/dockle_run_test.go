package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// dockleFake is a fake engine, Dockle and Trivy for the mini oracle. Every case
// has an image config, so each archive gets its own digest.
type dockleFake struct {
	t             *testing.T
	configs       map[string]string // case ID to image config JSON
	report        func(caseID string) (CommandResult, error)
	saveExit      map[string]int  // case ID to the exit code of the engine save
	garbage       map[string]bool // case ID to an archive that is not a tar file
	dockleVersion string
	dockleCmds    []Command
	saves         []Command
}

func newDockleFake(t *testing.T) *dockleFake {
	d := &dockleFake{
		t:             t,
		configs:       map[string]string{},
		saveExit:      map[string]int{},
		garbage:       map[string]bool{},
		dockleVersion: "dockle version 0.4.15",
	}
	for _, id := range []string{"user-defect", "user-clean", "sigterm-defect", "sigterm-clean", "secret-defect", "secret-clean"} {
		d.configs[id] = `{"architecture":"arm64","config":{"User":"` + id + `"}}`
	}
	d.report = func(id string) (CommandResult, error) {
		switch id {
		case "user-defect":
			return ok(dockleJSON(dockleEntry("CIS-DI-0001", "WARN", "Last user should not be root"), dockleEntry("CIS-DI-0005", "INFO", "x")))
		case "secret-defect":
			return ok(dockleJSON(dockleEntry("CIS-DI-0010", "FATAL", "Suspicious ENV key found"), dockleEntry("CIS-DI-0005", "INFO", "x")))
		}
		return ok(dockleJSON(dockleEntry("CIS-DI-0005", "INFO", "x")))
	}
	return d
}

func (d *dockleFake) caseOfArchive(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".tar")
	for id := range d.configs {
		if strings.HasSuffix(base, "-"+id) {
			return id
		}
	}
	d.t.Errorf("archive %s belongs to no case", path)
	return ""
}

func (d *dockleFake) caseOfImage(image string) string {
	for id := range d.configs {
		if image == ImageRef("localhost/conunit-rq1", id) {
			return id
		}
	}
	d.t.Errorf("image %s belongs to no case", image)
	return ""
}

func (d *dockleFake) handle(cmd Command) (CommandResult, error) {
	switch filepath.Base(cmd.Name) {
	case "podman":
		switch cmd.Args[0] {
		case "--version":
			return ok("podman version 5.8.1\n")
		case "build", "rmi":
			return ok("")
		case "image":
			return ok("sha256:" + digestOf(d.configs[d.caseOfImage(cmd.Args[len(cmd.Args)-1])]) + "\n")
		case "save":
			d.saves = append(d.saves, cmd)
			out := argAfter(cmd.Args, "-o")
			id := d.caseOfArchive(out)
			if code := d.saveExit[id]; code != 0 {
				return exit(code, "", "Error: save failed")
			}
			if d.garbage[id] {
				if err := os.WriteFile(out, []byte(strings.Repeat("garbage", 100)), 0o644); err != nil {
					d.t.Fatal(err)
				}
				return ok("")
			}
			members, _ := dockerArchive(d.configs[id])
			writeTarFile(d.t, out, members)
			return ok("")
		}
	case "dockle":
		if cmd.Args[0] == "--version" {
			return ok(d.dockleVersion + "\n")
		}
		d.dockleCmds = append(d.dockleCmds, cmd)
		// The isolation the runner promises: an empty working directory.
		entries, err := os.ReadDir(cmd.Dir)
		if cmd.Dir == "" || err != nil || len(entries) != 0 {
			d.t.Errorf("dockle must run in an empty working directory, dir %q entries %d err %v", cmd.Dir, len(entries), err)
		}
		return d.report(d.caseOfArchive(argAfter(cmd.Args, "--input")))
	case "trivy":
		switch cmd.Args[0] {
		case "--version":
			return ok("Version: 0.58.0\n")
		case "config":
			return ok(`{"SchemaVersion":2}`)
		case "image":
			return ok(`{"Results":[]}`)
		}
	}
	d.t.Errorf("unexpected command %s", cmd)
	return exit(127, "", "unexpected")
}

// run executes the selected tools on the mini oracle and analyzes the result.
func (d *dockleFake) run(selected map[string]bool, cases ...string) (*Results, string, *fakeExec) {
	d.t.Helper()
	o, err := LoadOracle("testdata/mini_oracle.json")
	if err != nil {
		d.t.Fatal(err)
	}
	out := d.t.TempDir()
	fake := &fakeExec{present: map[string]bool{"podman": true, "dockle": true, "trivy": true}, handle: d.handle}
	cfg := &RunConfig{
		Oracle:      o,
		OutDir:      out,
		Engine:      "podman",
		Selected:    selected,
		ImagePrefix: "localhost/conunit-rq1",
		Timeout:     time.Minute,
		Log:         NewLogger(&bytes.Buffer{}),
	}
	if len(cases) > 0 {
		cfg.Cases = map[string]bool{}
		for _, c := range cases {
			cfg.Cases[c] = true
		}
	}
	if _, err := Execute(context.Background(), fake, cfg); err != nil {
		d.t.Fatal(err)
	}
	res, err := Analyze(o, out)
	if err != nil {
		d.t.Fatal(err)
	}
	return res, out, fake
}

var dockleAndTrivy = map[string]bool{ToolDockle: true, ToolTrivy: true}

func resultOf(res *Results, id string) CaseResult {
	for _, c := range res.Cases {
		if c.ID == id {
			return c
		}
	}
	return CaseResult{}
}

func readRun(t *testing.T, out, id string) CaseRun {
	t.Helper()
	var run CaseRun
	if err := readJSON(filepath.Join(out, "raw", id, runFileName), &run); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestDockleRunsFromTheSharedArchive(t *testing.T) {
	d := newDockleFake(t)
	res, out, _ := d.run(dockleAndTrivy)

	want := map[string]string{
		"user-defect": ClassTP, "user-clean": ClassTN,
		"sigterm-defect": ClassOutOfScope, "sigterm-clean": ClassOutOfScope,
		"secret-defect": ClassTP, "secret-clean": ClassTN,
	}
	for id, class := range want {
		if got := resultOf(res, id).Tools[ToolDockle].Class; got != class {
			t.Errorf("dockle on %s = %s, want %s", id, got, class)
		}
	}

	// One export per case, read by both tools, with the contract command.
	if len(d.saves) != 6 {
		t.Fatalf("engine saves = %d, want one per case (6)", len(d.saves))
	}
	if len(d.dockleCmds) != 6 {
		t.Fatalf("dockle runs = %d, want one per case (6)", len(d.dockleCmds))
	}
	for _, cmd := range d.dockleCmds {
		archive := argAfter(cmd.Args, "--input")
		wantArgs := []string{"--input", archive, "--format", "json", "--exit-code", "0"}
		if !reflect.DeepEqual(cmd.Args, wantArgs) {
			t.Errorf("dockle args = %v, want %v", cmd.Args, wantArgs)
		}
		if !reflect.DeepEqual(cmd.UnsetPrefixes, []string{"DOCKLE_"}) {
			t.Errorf("dockle must run without DOCKLE_ variables, unset prefixes = %v", cmd.UnsetPrefixes)
		}
		if _, err := os.Stat(cmd.Dir); !os.IsNotExist(err) {
			t.Errorf("the empty working directory %s must be removed after the run (err %v)", cmd.Dir, err)
		}
		if _, err := os.Stat(archive); !os.IsNotExist(err) {
			t.Errorf("the archive %s must be removed after the case (err %v)", archive, err)
		}
		saved := false
		for _, s := range d.saves {
			if argAfter(s.Args, "-o") == archive && contains(s.Args, "docker-archive") {
				saved = true
			}
		}
		if !saved {
			t.Errorf("dockle read %s, which no `save --format docker-archive` wrote", archive)
		}
	}

	// The archive digest is recorded in the raw run file and in the results.
	for id, config := range d.configs {
		run := readRun(t, out, id)
		wantDigest := "sha256:" + digestOf(config)
		if run.Archive == nil || run.Archive.ConfigDigest != wantDigest {
			t.Errorf("%s: archive record = %+v, want config digest %s", id, run.Archive, wantDigest)
			continue
		}
		if run.Archive.MatchesImageID == nil || !*run.Archive.MatchesImageID || run.Archive.ImageID != wantDigest {
			t.Errorf("%s: the archive digest must match the engine image ID, record %+v", id, run.Archive)
		}
		if dr := run.Tools[ToolDockle]; dr.Status != runStatusRan || !strings.Contains(strings.Join(dr.Notes, "\n"), wantDigest) {
			t.Errorf("%s: dockle run = %+v, want status ran and the digest in its notes", id, dr)
		}
		if got := resultOf(res, id).Archive; got == nil || got.ConfigDigest != wantDigest {
			t.Errorf("%s: results carry archive %+v", id, got)
		}
		if raw := filepath.Join(out, "raw", id); !fileExists(filepath.Join(raw, "dockle.txt")) || !fileExists(filepath.Join(raw, "archive.log.txt")) {
			t.Errorf("%s: dockle.txt or archive.log.txt missing", id)
		}
	}

	// The observed identifiers and levels stay in the results for audit.
	got := resultOf(res, "user-defect").Tools[ToolDockle]
	if !reflect.DeepEqual(got.ObservedIDs, []string{"CIS-DI-0001", "CIS-DI-0005"}) || got.ObservedLevels["CIS-DI-0001"] != "WARN" {
		t.Errorf("observed = %v levels %v", got.ObservedIDs, got.ObservedLevels)
	}
	if len(got.Notes) == 0 {
		t.Error("the isolation notes of the run must reach the results")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestDockleRunFailureIsAToolError(t *testing.T) {
	d := newDockleFake(t)
	d.report = func(string) (CommandResult, error) {
		return exit(1, "2026-11-15T19:00:00.000+0100\tFATAL\tunable to initialize a image struct\n", "")
	}
	res, _, _ := d.run(dockleAndTrivy)
	for _, id := range []string{"user-defect", "user-clean", "secret-defect", "secret-clean"} {
		got := resultOf(res, id).Tools[ToolDockle]
		if got.Class != ClassToolError || !strings.Contains(got.Error, "unexpected exit code 1") {
			t.Errorf("dockle on %s = %s (%s), want TOOL_ERROR with the exit code", id, got.Class, got.Error)
		}
	}
	// Out of scope stays out of scope, and Trivy is not affected.
	if got := resultOf(res, "sigterm-defect").Tools[ToolDockle].Class; got != ClassOutOfScope {
		t.Errorf("out of scope case = %s", got)
	}
	if got := resultOf(res, "user-defect").Tools[ToolTrivy]; got.Error != "" {
		t.Errorf("trivy must not be affected by a dockle failure: %+v", got)
	}
	if res.Summary[ToolDockle].Status != "PARTIAL" {
		t.Errorf("summary status = %s, want PARTIAL", res.Summary[ToolDockle].Status)
	}
}

func TestLoggedAssessorErrorIsAToolError(t *testing.T) {
	d := newDockleFake(t)
	d.report = func(id string) (CommandResult, error) {
		// Exit code 0 and a complete report, but the log says an assessor failed.
		return ok("2026-11-15T19:00:00.000+0100\t\x1b[31mERROR\x1b[0m\tconfig json file doesn't exist\n" + dockleJSON())
	}
	res, _, _ := d.run(dockleAndTrivy, "user-defect", "user-clean")
	for _, id := range []string{"user-defect", "user-clean"} {
		got := resultOf(res, id).Tools[ToolDockle]
		if got.Class != ClassToolError || !strings.Contains(got.Error, "logged an error") {
			t.Errorf("dockle on %s = %s (%s), want TOOL_ERROR: a missing entry is not a clean result", id, got.Class, got.Error)
		}
	}
}

func TestSkippedCheckpointIsNotEvaluated(t *testing.T) {
	d := newDockleFake(t)
	d.report = func(id string) (CommandResult, error) {
		return ok(dockleJSON(dockleEntry("CIS-DI-0001", "SKIP", "failed to detect etc/passwd"), dockleEntry("CIS-DI-0010", "INFO", "x")))
	}
	res, _, _ := d.run(dockleAndTrivy, "user-defect", "user-clean", "secret-defect")
	for id, class := range map[string]string{"user-defect": ClassNotEvaluated, "user-clean": ClassNotEvaluated, "secret-defect": ClassTP} {
		if got := resultOf(res, id).Tools[ToolDockle]; got.Class != class {
			t.Errorf("dockle on %s = %s (%s), want %s", id, got.Class, got.Reason, class)
		}
	}
	s := res.Summary[ToolDockle]
	if s.Counts[ClassNotEvaluated] != 2 {
		t.Errorf("not evaluated count = %d, want 2", s.Counts[ClassNotEvaluated])
	}
	// A case that was not evaluated is neither a miss nor a true negative.
	if s.Recall.Numerator != 1 || s.Recall.Denominator != 1 || s.FalsePositiveRate.Denominator != 0 {
		t.Errorf("recall %+v false positive rate %+v: the not evaluated cases must enter neither", s.Recall, s.FalsePositiveRate)
	}
	got := resultOf(res, "user-defect").Tools[ToolDockle]
	if !reflect.DeepEqual(got.NotEvaluated, []string{"CIS-DI-0001"}) || got.ObservedLevels["CIS-DI-0001"] != "SKIP" {
		t.Errorf("audit data: not evaluated %v levels %v", got.NotEvaluated, got.ObservedLevels)
	}
}

func TestArchiveFailuresStopTheArchiveToolsOnly(t *testing.T) {
	t.Run("export fails", func(t *testing.T) {
		d := newDockleFake(t)
		d.saveExit["user-defect"] = 125
		res, out, _ := d.run(dockleAndTrivy, "user-defect", "user-clean")
		for _, tool := range []string{ToolDockle, ToolTrivy} {
			got := resultOf(res, "user-defect").Tools[tool]
			if !strings.Contains(got.Error, "saving the image archive failed") {
				t.Errorf("%s: error = %q, want the export failure", tool, got.Error)
			}
		}
		if got := resultOf(res, "user-defect").Tools[ToolDockle].Class; got != ClassToolError {
			t.Errorf("dockle class = %s, want TOOL_ERROR", got)
		}
		// The other case is not affected.
		if got := resultOf(res, "user-clean").Tools[ToolDockle].Class; got != ClassTN {
			t.Errorf("dockle on the other case = %s", got)
		}
		if run := readRun(t, out, "user-defect"); run.Archive == nil || run.Archive.ExportError == "" || run.Archive.ConfigDigest != "" {
			t.Errorf("archive record = %+v, want the export error and no digest", run.Archive)
		}
		if len(d.dockleCmds) != 1 {
			t.Errorf("dockle ran %d times, want only for the case whose export worked", len(d.dockleCmds))
		}
	})
	t.Run("archive without a readable digest", func(t *testing.T) {
		d := newDockleFake(t)
		d.garbage["user-defect"] = true
		res, out, _ := d.run(dockleAndTrivy, "user-defect")
		got := resultOf(res, "user-defect").Tools[ToolDockle]
		if got.Class != ClassToolError || !strings.Contains(got.Error, "config digest of the archive could not be read") {
			t.Errorf("dockle = %s (%s), want TOOL_ERROR about the digest", got.Class, got.Error)
		}
		// Dockle must not run on an archive that is not tied to the image.
		if len(d.dockleCmds) != 0 {
			t.Errorf("dockle ran %d times on an archive without a digest", len(d.dockleCmds))
		}
		// Trivy keeps its behavior and still runs.
		if tr := readRun(t, out, "user-defect").Tools[ToolTrivy]; tr.Status != runStatusRan {
			t.Errorf("trivy run = %+v, want it to run as before", tr)
		}
		if run := readRun(t, out, "user-defect"); run.Archive == nil || run.Archive.DigestError == "" {
			t.Errorf("archive record = %+v, want the digest error", run.Archive)
		}
	})
}

func TestDockleEnvironmentIsolationIsRecorded(t *testing.T) {
	t.Run("variables present", func(t *testing.T) {
		t.Setenv("DOCKLE_IGNORES", "CIS-DI-0001")
		t.Setenv("DOCKLE_ACCEPT_KEYS", "very-secret-value")
		d := newDockleFake(t)
		_, out, fake := d.run(map[string]bool{ToolDockle: true}, "user-defect")
		notes := strings.Join(readRun(t, out, "user-defect").Tools[ToolDockle].Notes, "\n")
		if !strings.Contains(notes, "removed from the environment: DOCKLE_ACCEPT_KEYS, DOCKLE_IGNORES") {
			t.Errorf("notes = %q, want the removed variable names", notes)
		}
		if strings.Contains(notes, "very-secret-value") || strings.Contains(notes, "CIS-DI-0001") {
			t.Errorf("notes must carry names only, never values: %q", notes)
		}
		for _, c := range fake.calls {
			if filepath.Base(c.Name) == "dockle" && len(c.Args) > 0 && c.Args[0] != "--version" {
				if len(c.Env) != 0 {
					t.Errorf("dockle must get no extra environment, got %v", c.Env)
				}
			}
		}
	})
	t.Run("no variable present", func(t *testing.T) {
		for _, kv := range os.Environ() {
			if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "DOCKLE_") {
				t.Setenv(name, "")
				os.Unsetenv(name)
			}
		}
		d := newDockleFake(t)
		_, out, _ := d.run(map[string]bool{ToolDockle: true}, "user-defect")
		notes := strings.Join(readRun(t, out, "user-defect").Tools[ToolDockle].Notes, "\n")
		if !strings.Contains(notes, "no DOCKLE_ variable was set") {
			t.Errorf("notes = %q", notes)
		}
		for _, want := range []string{"empty temporary directory", "DKL-DI-0006"} {
			if !strings.Contains(notes, want) {
				t.Errorf("notes lack %q: %q", want, notes)
			}
		}
	})
}

func TestToolVersionsAreComparedWithTheCatalogPins(t *testing.T) {
	cases := []struct {
		name          string
		dockleVersion string
		want          string
		observed      string
	}{
		{"same version", "dockle version 0.4.15", catalogMatch, "dockle version 0.4.15"},
		{"other patch version", "dockle version 0.4.14", catalogMismatch, "dockle version 0.4.14"},
		{"version that only starts like the pin", "dockle version 0.4.151", catalogMismatch, "dockle version 0.4.151"},
		{"version with a v prefix", "v0.4.15", catalogMatch, "v0.4.15"},
		{"development build without a version", "dockle version dev", catalogMismatch, "dockle version dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDockleFake(t)
			d.dockleVersion = tc.dockleVersion
			res, _, _ := d.run(dockleAndTrivy, "user-defect")
			got := res.Catalogs[ToolDockle]
			if got.State != tc.want || got.ObservedVersion != tc.observed || got.Version != "0.4.15" {
				t.Errorf("dockle catalog = %+v, want state %s observed %q", got, tc.want, tc.observed)
			}
			var log bytes.Buffer
			printSummary(NewLogger(&log), res)
			warned := strings.Contains(log.String(), "scope entries were read at version 0.4.15")
			if warned != (tc.want == catalogMismatch) {
				t.Errorf("warning printed = %t for state %s:\n%s", warned, tc.want, log.String())
			}
		})
	}

	d := newDockleFake(t)
	res, _, _ := d.run(dockleAndTrivy, "user-defect")
	for tool, want := range map[string]string{
		ToolTrivy:    catalogMatch,     // the fake reports 0.58.0, the mini oracle pins 0.58.0
		ToolConUnit:  catalogNotPinned, // the tool under test has no pinned version
		ToolHadolint: catalogNotRun,    // absent from PATH
		ToolCST:      catalogNotRun,
	} {
		if got := res.Catalogs[tool].State; got != want {
			t.Errorf("%s catalog state = %s, want %s", tool, got, want)
		}
	}
}

func TestResultsAreWrittenWithTheDockleAuditFields(t *testing.T) {
	d := newDockleFake(t)
	_, out, _ := d.run(dockleAndTrivy, "user-defect")
	o, err := LoadOracle("testdata/mini_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(o, out)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteResults(o, res, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, resultsFileName))
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Catalogs map[string]struct {
			State string `json:"state"`
		} `json:"catalogs"`
		Cases []struct {
			ID      string `json:"id"`
			Archive *struct {
				ConfigDigest string `json:"config_digest"`
			} `json:"archive"`
			Tools map[string]struct {
				Class string `json:"class"`
			} `json:"tools"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Catalogs[ToolDockle].State != catalogMatch {
		t.Errorf("catalogs = %+v", back.Catalogs)
	}
	for _, c := range back.Cases {
		if c.ID == "user-defect" && (c.Archive == nil || !strings.HasPrefix(c.Archive.ConfigDigest, "sha256:")) {
			t.Errorf("results lack the archive digest of %s: %+v", c.ID, c.Archive)
		}
		if _, ok := c.Tools[ToolDockle]; !ok {
			t.Errorf("results lack the dockle column for %s", c.ID)
		}
	}
	table, err := os.ReadFile(filepath.Join(out, tableFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), `\textbf{Dockle}`) || !strings.Contains(string(table), `\label{tab:rq1_detection}`) {
		t.Error("the table must have a Dockle column group and keep the label tab:rq1_detection")
	}
}
