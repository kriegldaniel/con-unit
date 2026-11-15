package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

func unverified(id string, tier spec.Tier, reason spec.Reason) spec.TestResult {
	return spec.TestResult{TestID: id, Tier: tier, Outcome: spec.OutcomeUnverified, Reason: reason}
}

func exitCode(n int) *int { return &n }

// tier3Image is a COMPLETED image whose four Tier 3 results are UNVERIFIED.
func tier3Image(ref string, reason spec.Reason) *spec.SuiteResult {
	ev := &spec.Evidence{BaselineState: "exited_nonzero", BaselineExitCode: exitCode(1)}
	var results []spec.TestResult
	for _, id := range []string{"EXEC-01", "EXEC-02", "EXEC-04", "EXEC-07"} {
		r := unverified(id, spec.TierContract, reason)
		r.Evidence = ev
		results = append(results, r)
	}
	results = append(results, spec.TestResult{TestID: "SPEC-01", Tier: spec.TierSpec, Outcome: spec.OutcomePass})
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, Status: spec.StatusCompleted, Results: results}
}

func TestSelectAblationTargets(t *testing.T) {
	failed := tier3Image("failed", spec.ReasonBaselineFailed)
	early := tier3Image("early", spec.ReasonNotObservable)
	early.Results[0].Evidence = &spec.Evidence{BaselineState: "exited0", BaselineExitCode: exitCode(0)}
	cases := []struct {
		name   string
		images []*spec.SuiteResult
		only   map[string]bool
		want   string // image:reasons, comma separated
	}{
		{"baseline failed and not observable are selected", []*spec.SuiteResult{failed, early}, nil, "failed:BASELINE_FAILED,early:NOT_OBSERVABLE"},
		{"a verified image is not selected", []*spec.SuiteResult{
			suite("ok", spec.StatusCompleted, res("EXEC-01", spec.OutcomePass), res("EXEC-02", spec.OutcomeFail)),
		}, nil, ""},
		{"other UNVERIFIED reasons are not selected", []*spec.SuiteResult{
			{ImageName: "x", Status: spec.StatusCompleted, Results: []spec.TestResult{unverified("EXEC-01", spec.TierContract, spec.ReasonProbeTimeout), unverified("EXEC-02", spec.TierContract, spec.ReasonProbeError), unverified("EXEC-04", spec.TierContract, spec.ReasonEvidenceIncomplete)}},
		}, nil, ""},
		{"a static check with the reason does not select the image", []*spec.SuiteResult{
			{ImageName: "x", Status: spec.StatusCompleted, Results: []spec.TestResult{unverified("SPEC-01", spec.TierSpec, spec.ReasonBaselineFailed)}},
		}, nil, ""},
		{"an image that did not complete is not selected", []*spec.SuiteResult{
			{ImageName: "t", RequestedRef: "t", Status: spec.StatusTimeout, Results: failed.Results},
		}, nil, ""},
		{"one baseline-gated result is enough", []*spec.SuiteResult{
			{ImageName: "mixed", Status: spec.StatusCompleted, Results: []spec.TestResult{res("EXEC-01", spec.OutcomePass), unverified("EXEC-02", spec.TierContract, spec.ReasonBaselineFailed)}},
		}, nil, "mixed:BASELINE_FAILED"},
		{"both reasons are listed in order", []*spec.SuiteResult{
			{ImageName: "both", Status: spec.StatusCompleted, Results: []spec.TestResult{unverified("EXEC-01", spec.TierContract, spec.ReasonNotObservable), unverified("EXEC-02", spec.TierContract, spec.ReasonBaselineFailed)}},
		}, nil, "both:BASELINE_FAILED+NOT_OBSERVABLE"},
		{"legacy result without a tier is recognized by its ID", []*spec.SuiteResult{
			{ImageName: "legacy", Status: "", Results: []spec.TestResult{{TestID: "EXEC-01", Outcome: spec.OutcomeUnverified, Reason: spec.ReasonBaselineFailed}}},
		}, nil, "legacy:BASELINE_FAILED"},
		{"the requested reference wins over the name", []*spec.SuiteResult{
			{ImageName: "n", RequestedRef: "docker.io/library/n@sha256:1", Status: spec.StatusCompleted, Results: failed.Results},
		}, nil, "docker.io/library/n@sha256:1:BASELINE_FAILED"},
		{"restricted to listed images", []*spec.SuiteResult{failed, early}, map[string]bool{"early": true}, "early:NOT_OBSERVABLE"},
		{"nil entries and empty names are skipped", []*spec.SuiteResult{nil, {Status: spec.StatusCompleted, Results: failed.Results}}, nil, ""},
		{"empty study", nil, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, tg := range SelectAblationTargets(tc.images, tc.only) {
				got = append(got, tg.Image+":"+strings.Join(tg.Reasons, "+"))
			}
			if strings.Join(got, ",") != tc.want {
				t.Errorf("targets = %v, want %q", got, tc.want)
			}
		})
	}

	// The study's baseline evidence travels with the target.
	targets := SelectAblationTargets([]*spec.SuiteResult{failed, early}, nil)
	if targets[0].BaselineState != "exited_nonzero" || targets[0].BaselineExitCode == nil || *targets[0].BaselineExitCode != 1 {
		t.Errorf("failed target = %+v", targets[0])
	}
	if targets[1].BaselineState != "exited0" || targets[1].BaselineExitCode == nil || *targets[1].BaselineExitCode != 0 {
		t.Errorf("early target = %+v", targets[1])
	}
	if strings.Join(targets[0].Rules, ",") != "EXEC-01,EXEC-02,EXEC-04,EXEC-07" {
		t.Errorf("rules = %v", targets[0].Rules)
	}
}

func TestAblationTreatmentsAreTheFourOfTheContract(t *testing.T) {
	join := func(f []string) string { return strings.Join(f, " ") }
	var got []string
	for _, tr := range ablationTreatments() {
		got = append(got, tr.Rule+"="+join(tr.Flags))
	}
	want := []string{
		"EXEC-01=" + join(engine.ReadOnlyRootfsFlags()),
		"EXEC-02=" + join(engine.DropAllCapabilitiesFlags()),
		"EXEC-04=" + join(engine.NoNewPrivilegesFlags()),
		"EXEC-07=" + join(engine.MemoryLimitFlags("256m", 0)),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("treatments\n got %v\nwant %v", got, want)
	}
	// The treatment of the hardening profile that the engine runs states the
	// same memory limit.
	if !strings.Contains(join(engine.MemoryLimitFlags("256m", 0)), "--memory=256m") || memoryLimitFlag != "--memory=256m" {
		t.Errorf("memory flag = %s", memoryLimitFlag)
	}
}

// ablationFake survives a treatment according to a per-image table.
func ablationFake(failing map[string]map[string]bool) *scriptRunner {
	s := &scriptRunner{behave: map[string]func(RunSpec) Observation{}}
	for image, rules := range failing {
		rules := rules
		s.behave[image] = func(rs RunSpec) Observation {
			rule := ""
			switch {
			case has(rs.Flags, "--read-only"):
				rule = "EXEC-01"
			case has(rs.Flags, "--cap-drop=ALL"):
				rule = "EXEC-02"
			case has(rs.Flags, "--security-opt=no-new-privileges:true"):
				rule = "EXEC-04"
			case has(rs.Flags, "--memory=256m"):
				rule = "EXEC-07"
			}
			if rules[rule] {
				return exited(1)
			}
			return running()
		}
	}
	return s
}

func targetsOf(refs ...string) []AblationTarget {
	var out []AblationTarget
	for _, r := range refs {
		out = append(out, AblationTarget{Image: r, Reasons: []string{string(spec.ReasonBaselineFailed)}, Rules: []string{"EXEC-01"}})
	}
	return out
}

func TestAblationCountsWhatASingleRunToolWouldCallFail(t *testing.T) {
	all := map[string]bool{"EXEC-01": true, "EXEC-02": true, "EXEC-04": true, "EXEC-07": true}
	r := ablationFake(map[string]map[string]bool{
		"crashes":     all,                                // fails under every treatment, as it does without one
		"flaky":       {"EXEC-02": true},                  // one treatment fails
		"recovered":   {},                                 // the baseline failure did not repeat
		"readonly":    {"EXEC-01": true, "EXEC-07": true}, // two fail
		"exits-clean": all,
	})
	r.behave["exits-clean"] = func(RunSpec) Observation { return exited(0) } // no long-running process
	images := RunAblation(context.Background(), r, cfg(), targetsOf("crashes", "flaky", "recovered", "readonly", "exits-clean"), discard(), nil)
	wantFails := map[string]int{"crashes": 4, "flaky": 1, "recovered": 0, "readonly": 2, "exits-clean": 4}
	for _, img := range images {
		if img.Status != AblationOK || img.SingleRunFails != wantFails[img.Image] || img.Misblamed != (wantFails[img.Image] > 0) {
			t.Errorf("%s: status %s, fails %d, misblamed %t, want %d fails", img.Image, img.Status, img.SingleRunFails, img.Misblamed, wantFails[img.Image])
		}
		if len(img.Runs) != 4 {
			t.Errorf("%s: %d runs, want one per treatment", img.Image, len(img.Runs))
		}
	}
	s := SummarizeAblation(images, 5)
	if s.ImagesSelected != 5 || s.ImagesExamined != 5 || s.ImagesMisblamed != 4 || s.PairsExamined != 20 || s.PairsFail != 11 {
		t.Errorf("summary = %+v", s)
	}
	if got := s.ByStudyReason["BASELINE_FAILED"]; got.Examined != 5 || got.Misblamed != 4 {
		t.Errorf("by reason = %+v", s.ByStudyReason)
	}
	if got := s.ByTreatment["EXEC-02"]; got.Runs != 5 || got.Fail != 3 || got.Pass != 2 {
		t.Errorf("EXEC-02 = %+v", got)
	}
}

func TestAblationRunsEachTreatmentWithoutABaseline(t *testing.T) {
	r := ablationFake(map[string]map[string]bool{"img": {}})
	RunAblation(context.Background(), r, Config{Window: 4 * 1e9}, targetsOf("img"), discard(), nil)
	if len(r.calls) != 4 {
		t.Fatalf("calls = %d, want exactly the four treatments and no baseline run", len(r.calls))
	}
	seen := map[string]bool{}
	for _, c := range r.calls {
		if !has(c.Flags, "--network=none") || !has(c.Flags, "--pids-limit=256") {
			t.Errorf("run without the defensive flags: %v", c.Flags)
		}
		for _, env := range mockEnv {
			found := false
			for i := 0; i+1 < len(c.Flags); i++ {
				found = found || (c.Flags[i] == "-e" && c.Flags[i+1] == env)
			}
			if !found {
				t.Errorf("run lacks the mock env %s: %v", env, c.Flags)
			}
		}
		treatments := 0
		for _, f := range []string{"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=256m"} {
			if has(c.Flags, f) {
				treatments++
				seen[f] = true
			}
		}
		if treatments != 1 {
			t.Errorf("a run must carry exactly one treatment, got %d: %v", treatments, c.Flags)
		}
		if c.Window != 4e9 || c.Image != "img" {
			t.Errorf("run = %+v", c)
		}
	}
	if len(seen) != 4 {
		t.Errorf("treatments seen = %v", seen)
	}
	// The read-only treatment mounts the base tmpfs of the study.
	if m := tmpfsMounts(r.calls[0].Flags); len(m) != 1 || m["/tmp"] != "rw,nosuid,size=65536k" {
		t.Errorf("read-only treatment mounts = %v", m)
	}
}

func TestAblationOutcomeStatuses(t *testing.T) {
	cases := []struct {
		name       string
		runner     func() *scriptRunner
		cfg        Config
		wantStatus string
		wantExam   int
	}{
		{"absent image", func() *scriptRunner {
			r := ablationFake(map[string]map[string]bool{})
			r.absent = map[string]bool{"img": true}
			return r
		}, cfg(), AblationAbsent, 0},
		{"unreadable state in the second treatment", func() *scriptRunner {
			n := 0
			r := &scriptRunner{behave: map[string]func(RunSpec) Observation{"img": func(RunSpec) Observation {
				n++
				if n == 2 {
					return Observation{State: StateUnknown, Err: "inspect failed"}
				}
				return running()
			}}}
			return r
		}, cfg(), AblationError, 0},
		{"a start failure is a FAIL for a single-run tool, not an error", func() *scriptRunner {
			return &scriptRunner{behave: map[string]func(RunSpec) Observation{"img": func(RunSpec) Observation {
				return Observation{State: StateStartFailed, LogTail: "no such file"}
			}}}
		}, cfg(), AblationOK, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.runner()
			images := RunAblation(context.Background(), r, tc.cfg, targetsOf("img"), discard(), nil)
			if len(images) != 1 || images[0].Status != tc.wantStatus {
				t.Fatalf("images = %+v", images)
			}
			s := SummarizeAblation(images, 1)
			if s.ImagesExamined != tc.wantExam {
				t.Errorf("examined = %d, want %d", s.ImagesExamined, tc.wantExam)
			}
			switch tc.wantStatus {
			case AblationAbsent:
				if s.ImagesAbsent != 1 || len(r.calls) != 0 {
					t.Errorf("absent image: summary %+v, calls %d", s, len(r.calls))
				}
			case AblationError:
				if s.ImagesError != 1 || !strings.Contains(images[0].Detail, "inspect failed") || images[0].Misblamed {
					t.Errorf("error image: summary %+v, detail %q", s, images[0].Detail)
				}
			case AblationOK:
				if !images[0].Misblamed || images[0].SingleRunFails != 4 {
					t.Errorf("start failures: %+v", images[0])
				}
			}
		})
	}
}

func TestAblationPullsAbsentImagesOnRequest(t *testing.T) {
	r := ablationFake(map[string]map[string]bool{})
	r.absent = map[string]bool{"img": true}
	c := cfg()
	c.Pull = true
	pulls := &pullRecorder{scriptRunner: r}
	images := RunAblation(context.Background(), pulls, c, targetsOf("img"), discard(), nil)
	if len(pulls.pulled) != 1 || images[0].Status != AblationOK {
		t.Errorf("pulled %v, status %s", pulls.pulled, images[0].Status)
	}
}

// pullRecorder makes an absent image present once it was pulled.
type pullRecorder struct {
	*scriptRunner
	pulled []string
}

func (p *pullRecorder) Pull(_ context.Context, image string) error {
	p.pulled = append(p.pulled, image)
	delete(p.absent, image)
	return nil
}

func TestAblationStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &scriptRunner{behave: map[string]func(RunSpec) Observation{"a": func(RunSpec) Observation { cancel(); return running() }}}
	images := RunAblation(ctx, r, cfg(), targetsOf("a", "b"), discard(), nil)
	if len(images) != 1 {
		t.Errorf("images = %d, the second image must not start after the cancel", len(images))
	}
}

func TestSummarizeAblationOfNothing(t *testing.T) {
	s := SummarizeAblation(nil, 0)
	if s.ImagesExamined != 0 || s.ImagesMisblamed != 0 || s.PairsExamined != 0 || s.ByStudyReason == nil || s.ByTreatment == nil {
		t.Errorf("summary = %+v", s)
	}
	// Two reasons are kept apart.
	imgs := []AblationImage{
		{Image: "a", StudyReasons: []string{"BASELINE_FAILED"}, Status: AblationOK, Misblamed: true, Runs: []AblationRun{{Rule: "EXEC-01", SingleRun: SingleRunFail}}},
		{Image: "b", StudyReasons: []string{"NOT_OBSERVABLE"}, Status: AblationOK, Runs: []AblationRun{{Rule: "EXEC-01", SingleRun: SingleRunPass}}},
		{Image: "c", StudyReasons: []string{"NOT_OBSERVABLE"}, Status: AblationOK, Misblamed: true, Runs: []AblationRun{{Rule: "EXEC-01", SingleRun: SingleRunFail}}},
	}
	got := SummarizeAblation(imgs, 3)
	if got.ByStudyReason["BASELINE_FAILED"].Misblamed != 1 || got.ByStudyReason["NOT_OBSERVABLE"].Examined != 2 || got.ByStudyReason["NOT_OBSERVABLE"].Misblamed != 1 {
		t.Errorf("by reason = %+v", got.ByStudyReason)
	}
}

func TestExecuteAblationWritesAblationJSONOnly(t *testing.T) {
	dir := t.TempDir()
	study := writeStudyFile(t, dir,
		tier3Image("crashes", spec.ReasonBaselineFailed),
		tier3Image("early", spec.ReasonNotObservable),
		suite("fine", spec.StatusCompleted, res("EXEC-01", spec.OutcomePass)),
	)
	r := &scriptRunner{behave: map[string]func(RunSpec) Observation{
		"crashes": func(RunSpec) Observation { return exited(1) },
		"early":   func(RunSpec) Observation { return running() },
	}}
	code := execute(context.Background(), options{studyPath: study, outDir: dir, ablation: true, minimize: true, rules: []string{RuleReadOnly, RuleDropCaps}}, r, testMeta, discard())
	if code != spec.ExitOK {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(filepath.Join(dir, ablationJSON))
	if err != nil {
		t.Fatal(err)
	}
	var doc AblationDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Complete || doc.Summary.ImagesSelected != 2 || doc.Summary.ImagesExamined != 2 || doc.Summary.ImagesMisblamed != 1 {
		t.Errorf("summary = %+v complete %t", doc.Summary, doc.Complete)
	}
	if doc.Source.StudySHA256 == "" || len(doc.Protocol.Treatments) != 4 || doc.Protocol.WindowMs != 3000 {
		t.Errorf("document does not describe itself: %+v", doc.Protocol)
	}
	if len(r.calls) != 8 {
		t.Errorf("calls = %d, want four treatments for each of the two selected images", len(r.calls))
	}
	if _, err := os.Stat(filepath.Join(dir, attributionJSON)); err == nil {
		t.Error("an ablation run computes no attribution and must not write attribution.json")
	}
}

func TestExecuteAblationWithAbsentImageExitsThree(t *testing.T) {
	dir := t.TempDir()
	study := writeStudyFile(t, dir, tier3Image("gone", spec.ReasonBaselineFailed))
	r := &scriptRunner{absent: map[string]bool{"gone": true}}
	if code := execute(context.Background(), options{studyPath: study, outDir: dir, ablation: true}, r, testMeta, discard()); code != spec.ExitIncomplete {
		t.Errorf("exit %d, want %d", code, spec.ExitIncomplete)
	}
}

func TestExecuteAblationOfAStudyWithoutSuchImagesWritesAnEmptyDocument(t *testing.T) {
	dir := t.TempDir()
	study := writeStudyFile(t, dir, suite("fine", spec.StatusCompleted, res("EXEC-01", spec.OutcomePass)))
	if code := execute(context.Background(), options{studyPath: study, outDir: dir, ablation: true}, &scriptRunner{}, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("exit %d", code)
	}
	var doc AblationDocument
	data, _ := os.ReadFile(filepath.Join(dir, ablationJSON))
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Images) != 0 || doc.Summary.ImagesExamined != 0 || !doc.Complete {
		t.Errorf("document = %+v (%v)", doc.Summary, err)
	}
}

func TestParseOptionsAblation(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"ablation with a study", []string{"-ablation", "-study", "s.json"}, false},
		{"ablation with a positional study", []string{"-ablation", "s.json"}, false},
		{"ablation without a study", []string{"-ablation", "-out-dir", "o"}, true},
		{"ablation with truth", []string{"-ablation", "-study", "s.json", "-truth", "t.json"}, true},
	}
	for _, tc := range cases {
		var b strings.Builder
		_, err := parseOptions(tc.args, &b, NewLogger(&b))
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: error = %v, want error %t (%s)", tc.name, err, tc.wantErr, b.String())
		}
	}
}
