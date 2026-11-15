package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

// fakeRunner answers Observe with a function of the flags. It records every
// call so tests can assert what was started.
type fakeRunner struct {
	behave  func(RunSpec) Observation
	absent  bool
	pullErr error
	calls   []RunSpec
	pulled  []string
}

func (f *fakeRunner) Observe(ctx context.Context, rs RunSpec) Observation {
	f.calls = append(f.calls, rs)
	return f.behave(rs)
}

func (f *fakeRunner) ImagePresent(ctx context.Context, image string) (bool, error) {
	return !f.absent, nil
}

func (f *fakeRunner) Pull(ctx context.Context, image string) error {
	f.pulled = append(f.pulled, image)
	if f.pullErr == nil {
		f.absent = false
	}
	return f.pullErr
}

func running() Observation { return Observation{State: StateRunning} }

func exited(code int) Observation {
	return Observation{State: StateExited, ExitCode: &code, LogTail: "chown: Operation not permitted\nexit"}
}

func discard() *Logger { return NewLogger(io.Discard) }

func has(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// tmpfsDests returns the destinations of the --tmpfs flags with their options.
func tmpfsMounts(flags []string) map[string]string {
	out := map[string]string{}
	for i, f := range flags {
		if f == "--tmpfs" && i+1 < len(flags) {
			dest, opts, _ := strings.Cut(flags[i+1], ":")
			out[dest] = opts
		}
	}
	return out
}

func cfg() Config { return Config{Window: 3 * time.Second} }

// capBehave builds a runner behavior: without --cap-drop the container runs,
// with it the container exits 1 unless the survive predicate accepts the flags.
func capBehave(survive func(flags []string) bool) func(RunSpec) Observation {
	return func(rs RunSpec) Observation {
		if !has(rs.Flags, "--cap-drop=ALL") {
			return running()
		}
		if survive(rs.Flags) {
			return running()
		}
		return exited(1)
	}
}

func TestProfileMatchesContract(t *testing.T) {
	// docs/CONTRACT.md section 6: baseline with only the defensive flags and
	// the mock environment variables.
	if strings.Join(defensiveFlags, " ") != "--network=none --pids-limit=256" {
		t.Errorf("defensive flags = %v", defensiveFlags)
	}
	want := []string{
		"POSTGRES_PASSWORD=conunit_test_password", "POSTGRES_HOST_AUTH_METHOD=trust",
		"MYSQL_ROOT_PASSWORD=conunit_test_password", "MARIADB_ROOT_PASSWORD=conunit_test_password", "ARANGO_NO_AUTH=1",
	}
	if strings.Join(mockEnv, "|") != strings.Join(want, "|") {
		t.Errorf("mock env = %v", mockEnv)
	}
	if strings.Join(capCandidates, ",") != "CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_SYS_CHROOT" {
		t.Errorf("capability candidates = %v", capCandidates)
	}
	if strings.Join(tmpfsCandidates, ",") != "/run,/var/run,/var/cache,/var/log,/var/lib" {
		t.Errorf("tmpfs candidates = %v", tmpfsCandidates)
	}
}

// TestTreatmentsMatchTheEngine pins the treatment flags of this tool against
// the engine package that the study run uses. The attribution is only
// meaningful when it re-runs the treatment that failed in the study.
func TestTreatmentsMatchTheEngine(t *testing.T) {
	join := func(f []string) string { return strings.Join(f, " ") }
	ro, _ := treatmentFlags(RuleReadOnly)
	caps, _ := treatmentFlags(RuleDropCaps)
	cases := []struct {
		name      string
		got, want []string
	}{
		{"read-only rootfs with the base tmpfs", ro, engine.ReadOnlyRootfsFlags()},
		{"drop all capabilities", caps, engine.DropAllCapabilitiesFlags()},
		{"no new privileges", []string{noNewPrivilegesFlag}, engine.NoNewPrivilegesFlags()},
		{"memory limit", []string{memoryLimitFlag}, engine.MemoryLimitFlags("256m", 0)},
		{"defensive flags", defensiveFlags, (&engine.Engine{}).DefensiveRunFlags()},
	}
	for _, tc := range cases {
		if join(tc.got) != join(tc.want) {
			t.Errorf("%s: tool flags %q differ from the engine flags %q", tc.name, join(tc.got), join(tc.want))
		}
	}
	if strings.Contains(join(ro), "noexec") {
		t.Error("the study treatment has no noexec restriction on /tmp, so the attribution must not add one")
	}
}

func TestEveryAttemptUsesTheDefensiveProfile(t *testing.T) {
	r := &fakeRunner{behave: capBehave(func([]string) bool { return false })}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if len(r.calls) != 13 {
		t.Fatalf("calls = %d, want baseline, treatment, 10 singles and the union", len(r.calls))
	}
	for i, c := range r.calls {
		if !has(c.Flags, "--network=none") || !has(c.Flags, "--pids-limit=256") {
			t.Errorf("call %d lacks the defensive flags: %v", i, c.Flags)
		}
		for _, env := range mockEnv {
			found := false
			for j := 0; j+1 < len(c.Flags); j++ {
				if c.Flags[j] == "-e" && c.Flags[j+1] == env {
					found = true
				}
			}
			if !found {
				t.Errorf("call %d lacks mock env %s", i, env)
			}
		}
		if c.Window != 3*time.Second || c.Image != "img" {
			t.Errorf("call %d = %+v", i, c)
		}
	}
	if has(r.calls[0].Flags, "--cap-drop=ALL") {
		t.Error("the baseline must carry no treatment flag")
	}
	if !has(r.calls[1].Flags, "--cap-drop=ALL") {
		t.Error("the treatment must drop all capabilities")
	}
	if a.Status != StatusUnresolved {
		t.Errorf("status = %s", a.Status)
	}
}

func TestSingleCapabilityResolvesTheFailure(t *testing.T) {
	r := &fakeRunner{behave: capBehave(func(f []string) bool { return has(f, "--cap-add=CAP_CHOWN") })}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusResolvedSingle || strings.Join(a.ResolvedBy, ",") != "CAP_CHOWN" {
		t.Errorf("status %s resolved by %v", a.Status, a.ResolvedBy)
	}
	if !a.UnionResolves {
		t.Error("the union contains CAP_CHOWN and must resolve as well")
	}
	// Only the attempt of CAP_CHOWN and the union are marked as resolving.
	var marked []string
	for _, at := range a.Attempts {
		if at.Resolved {
			marked = append(marked, at.Kind+":"+at.Candidate)
		}
	}
	if strings.Join(marked, ",") != "single:CAP_CHOWN,union:union" {
		t.Errorf("resolved attempts = %v", marked)
	}
	// Every single candidate adds exactly one capability on top of the treatment.
	for _, at := range a.Attempts {
		if at.Kind != KindSingle {
			continue
		}
		adds := 0
		for _, f := range at.Flags {
			if strings.HasPrefix(f, "--cap-add=") {
				adds++
			}
		}
		if adds != 1 || !has(at.Flags, "--cap-add="+at.Candidate) || !has(at.Flags, "--cap-drop=ALL") {
			t.Errorf("single candidate %s has flags %v", at.Candidate, at.Flags)
		}
	}
}

func TestSeveralSingleCandidatesAreAllReported(t *testing.T) {
	r := &fakeRunner{behave: capBehave(func(f []string) bool {
		return has(f, "--cap-add=CAP_SETUID") || has(f, "--cap-add=CAP_SETGID")
	})}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if strings.Join(a.ResolvedBy, ",") != "CAP_SETGID,CAP_SETUID" {
		t.Errorf("resolved by %v", a.ResolvedBy)
	}
}

func TestUnionOnlyResolvesWhenTwoCapabilitiesAreNeeded(t *testing.T) {
	r := &fakeRunner{behave: capBehave(func(f []string) bool {
		return has(f, "--cap-add=CAP_SETUID") && has(f, "--cap-add=CAP_SETGID")
	})}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusResolvedUnion || len(a.ResolvedBy) != 0 || !a.UnionResolves {
		t.Errorf("status %s, resolved by %v, union %t", a.Status, a.ResolvedBy, a.UnionResolves)
	}
	last := a.Attempts[len(a.Attempts)-1]
	if last.Kind != KindUnion || !last.Resolved {
		t.Errorf("last attempt = %+v", last)
	}
	adds := 0
	for _, f := range last.Flags {
		if strings.HasPrefix(f, "--cap-add=") {
			adds++
		}
	}
	if adds != 10 {
		t.Errorf("the union adds %d capabilities, want 10", adds)
	}
}

func TestUnresolvedWhenNothingHelps(t *testing.T) {
	r := &fakeRunner{behave: capBehave(func([]string) bool { return false })}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusUnresolved || a.UnionResolves || len(a.ResolvedBy) != 0 {
		t.Errorf("attribution = %+v", a)
	}
}

func TestFailureThatDoesNotReproduceIsNotAttributed(t *testing.T) {
	r := &fakeRunner{behave: func(RunSpec) Observation { return running() }}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusNotReproduced {
		t.Errorf("status = %s", a.Status)
	}
	if len(r.calls) != 2 {
		t.Errorf("calls = %d, candidates must not run when the failure does not reproduce", len(r.calls))
	}
}

func TestBaselineMustRunBeforeAnythingIsInterpreted(t *testing.T) {
	cases := []struct {
		name string
		obs  Observation
		want string
	}{
		{"exits 0 early", exited(0), StatusNotObservable},
		{"exits non-zero", exited(1), StatusBaselineFailed},
		{"does not start", Observation{State: StateStartFailed, LogTail: "no such image"}, StatusBaselineFailed},
	}
	for _, tc := range cases {
		r := &fakeRunner{behave: func(RunSpec) Observation { return tc.obs }}
		a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
		if a.Status != tc.want {
			t.Errorf("%s: status = %s, want %s", tc.name, a.Status, tc.want)
		}
		if len(r.calls) != 1 {
			t.Errorf("%s: calls = %d, only the baseline may run", tc.name, len(r.calls))
		}
	}
}

func TestUnreadableStateIsAnErrorNotAResult(t *testing.T) {
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		if has(rs.Flags, "--cap-add=CAP_FOWNER") {
			return Observation{State: StateUnknown, Err: "inspect failed"}
		}
		return capBehave(func([]string) bool { return false })(rs)
	}}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusError || !strings.Contains(a.Detail, "inspect failed") {
		t.Errorf("attribution = %s %s", a.Status, a.Detail)
	}
}

func TestReadOnlyCandidatesAreMountsNextToTheBaseTmp(t *testing.T) {
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		if !has(rs.Flags, "--read-only") {
			return running()
		}
		if _, ok := tmpfsMounts(rs.Flags)["/var/log"]; ok {
			return running()
		}
		return exited(1)
	}}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleReadOnly}, discard())
	if a.Status != StatusResolvedSingle || strings.Join(a.ResolvedBy, ",") != "/var/log" {
		t.Fatalf("status %s resolved by %v", a.Status, a.ResolvedBy)
	}
	if len(r.calls) != 2+len(tmpfsCandidates)+1 {
		t.Errorf("calls = %d", len(r.calls))
	}
	treatment := tmpfsMounts(r.calls[1].Flags)
	if len(treatment) != 1 || treatment["/tmp"] != "rw,nosuid,size=65536k" || !has(r.calls[1].Flags, "--read-only") {
		t.Errorf("treatment flags = %v", r.calls[1].Flags)
	}
	for _, at := range a.Attempts {
		if at.Kind != KindSingle {
			continue
		}
		mounts := tmpfsMounts(at.Flags)
		count := 0
		for _, f := range at.Flags {
			if f == "--tmpfs" {
				count++
			}
		}
		if count != len(mounts) {
			t.Errorf("candidate %s mounts a destination twice: %v", at.Candidate, at.Flags)
		}
		if at.Candidate == "/tmp" {
			t.Error("/tmp is mounted by the treatment itself and must not be a candidate")
			continue
		}
		if len(mounts) != 2 || mounts["/tmp"] != "rw,nosuid,size=65536k" || mounts[at.Candidate] != "rw,nosuid,size=65536k" {
			t.Errorf("candidate %s mounts = %v", at.Candidate, mounts)
		}
	}
	union := a.Attempts[len(a.Attempts)-1]
	if got := len(tmpfsMounts(union.Flags)); got != 6 {
		t.Errorf("the union mounts %d paths, want 6", got)
	}
}

func TestUnionFallsBackWhenOverlappingMountsDoNotStart(t *testing.T) {
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		if !has(rs.Flags, "--read-only") {
			return running()
		}
		m := tmpfsMounts(rs.Flags)
		_, run := m["/run"]
		_, varRun := m["/var/run"]
		if run && varRun {
			return Observation{State: StateStartFailed, LogTail: "duplicate mount destination"}
		}
		if len(m) >= 5 {
			return running()
		}
		return exited(1)
	}}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleReadOnly}, discard())
	if a.Status != StatusResolvedUnion {
		t.Fatalf("status = %s", a.Status)
	}
	if !strings.Contains(a.Detail, "without /var/run") {
		t.Errorf("detail = %q", a.Detail)
	}
	last := a.Attempts[len(a.Attempts)-1]
	if last.Candidate != "union-without-/var/run" || !last.Resolved {
		t.Errorf("last attempt = %+v", last)
	}
	if _, ok := tmpfsMounts(last.Flags)["/var/run"]; ok {
		t.Error("the fallback must not mount /var/run")
	}
}

func TestAbsentImageIsReportedAndPullIsOptIn(t *testing.T) {
	r := &fakeRunner{absent: true, behave: capBehave(func([]string) bool { return false })}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusImageAbsent || len(r.calls) != 0 || len(r.pulled) != 0 {
		t.Errorf("status %s, calls %d, pulled %v", a.Status, len(r.calls), r.pulled)
	}

	r2 := &fakeRunner{absent: true, behave: capBehave(func([]string) bool { return false })}
	c := cfg()
	c.Pull = true
	a2 := attributeOne(context.Background(), r2, c, Target{Image: "img", Rule: RuleDropCaps}, discard())
	if len(r2.pulled) != 1 || a2.Status != StatusUnresolved {
		t.Errorf("pulled %v, status %s", r2.pulled, a2.Status)
	}

	r3 := &fakeRunner{absent: true, pullErr: errors.New("manifest unknown"), behave: capBehave(func([]string) bool { return false })}
	a3 := attributeOne(context.Background(), r3, c, Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a3.Status != StatusImageAbsent || !strings.Contains(a3.Detail, "manifest unknown") {
		t.Errorf("failed pull = %s %s", a3.Status, a3.Detail)
	}
}

func TestUnknownRuleIsRejected(t *testing.T) {
	if _, err := treatmentFlags("EXEC-04"); err == nil {
		t.Error("only EXEC-01 and EXEC-02 can be attributed")
	}
	r := &fakeRunner{behave: func(RunSpec) Observation { return running() }}
	a := attributeOne(context.Background(), r, cfg(), Target{Image: "img", Rule: "EXEC-04"}, discard())
	if a.Status != StatusError || len(r.calls) != 0 {
		t.Errorf("attribution = %+v", a)
	}
}

func suite(ref string, status string, results ...spec.TestResult) *spec.SuiteResult {
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, Status: status, Results: results}
}

func res(id string, o spec.Outcome) spec.TestResult { return spec.TestResult{TestID: id, Outcome: o} }

func TestSelectTargets(t *testing.T) {
	images := []*spec.SuiteResult{
		suite("a", spec.StatusCompleted, res("EXEC-01", spec.OutcomeFail), res("EXEC-02", spec.OutcomeFail)),
		suite("b", spec.StatusCompleted, res("EXEC-01", spec.OutcomePass), res("EXEC-02", spec.OutcomeFail)),
		suite("c", spec.StatusCompleted, res("EXEC-01", spec.OutcomeUnverified), res("EXEC-02", spec.OutcomeUnverified)),
		suite("d", spec.StatusTimeout, res("EXEC-02", spec.OutcomeFail)),
		suite("e", "", res("EXEC-02", spec.OutcomeFail)),
		{ImageName: "f", Status: spec.StatusCompleted, Results: []spec.TestResult{{TestID: "EXEC-02", Passed: false}}}, // legacy field only
		nil,
	}
	got := SelectTargets(images, []string{RuleReadOnly, RuleDropCaps}, nil)
	var names []string
	for _, tg := range got {
		names = append(names, tg.Image+":"+tg.Rule)
	}
	want := "a:EXEC-01,a:EXEC-02,b:EXEC-02,e:EXEC-02,f:EXEC-02"
	if strings.Join(names, ",") != want {
		t.Errorf("targets = %v, want %s", names, want)
	}
	only := SelectTargets(images, []string{RuleDropCaps}, map[string]bool{"b": true})
	if len(only) != 1 || only[0].Image != "b" {
		t.Errorf("filtered targets = %v", only)
	}
	// The requested reference wins over the image name.
	pinned := []*spec.SuiteResult{{ImageName: "x", RequestedRef: "docker.io/library/x@sha256:1", Status: spec.StatusCompleted, Results: []spec.TestResult{res("EXEC-02", spec.OutcomeFail)}}}
	if got := SelectTargets(pinned, []string{RuleDropCaps}, nil); len(got) != 1 || got[0].Image != "docker.io/library/x@sha256:1" {
		t.Errorf("pinned = %v", got)
	}
}

func TestLoadStudyEnvelopeAndLegacy(t *testing.T) {
	dir := t.TempDir()
	envelope := spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run:           spec.RunMetadata{ProbeWindowMs: 2500, EngineName: "podman"},
		Images:        []*spec.SuiteResult{suite("a", spec.StatusCompleted, res("EXEC-02", spec.OutcomeFail))},
	}
	data, _ := json.Marshal(envelope)
	p1 := filepath.Join(dir, "envelope.json")
	if err := os.WriteFile(p1, data, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := LoadStudy(p1)
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != spec.SchemaVersion || st.Run == nil || st.Run.ProbeWindowMs != 2500 || len(st.Images) != 1 || len(st.SHA256) != 64 {
		t.Errorf("envelope = %+v", st)
	}

	legacy, _ := json.Marshal([]*spec.SuiteResult{suite("a", spec.StatusCompleted, res("EXEC-02", spec.OutcomeFail))})
	p2 := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(p2, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	st, err = LoadStudy(p2)
	if err != nil || st.Run != nil || len(st.Images) != 1 || st.SchemaVersion != "" {
		t.Errorf("legacy = %+v, err %v", st, err)
	}
	if _, err := LoadStudy(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing study must be an error")
	}
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte("  \n"), 0o644)
	if _, err := LoadStudy(empty); err == nil {
		t.Error("an empty study must be an error")
	}
}

func TestSummaryCountsSingleUnionAndUnresolved(t *testing.T) {
	attrs := []Attribution{
		{Image: "a", Rule: RuleDropCaps, Status: StatusResolvedSingle, ResolvedBy: []string{"CAP_CHOWN", "CAP_FOWNER"}},
		{Image: "b", Rule: RuleDropCaps, Status: StatusResolvedSingle, ResolvedBy: []string{"CAP_CHOWN"}},
		{Image: "c", Rule: RuleDropCaps, Status: StatusResolvedUnion},
		{Image: "d", Rule: RuleDropCaps, Status: StatusUnresolved},
		{Image: "e", Rule: RuleDropCaps, Status: StatusNotReproduced},
		{Image: "f", Rule: RuleDropCaps, Status: StatusBaselineFailed},
		{Image: "g", Rule: RuleReadOnly, Status: StatusResolvedSingle, ResolvedBy: []string{"/var/log"}},
		{Image: "h", Rule: RuleReadOnly, Status: StatusImageAbsent},
		{Image: "i", Rule: RuleReadOnly, Status: StatusNotObservable},
		{Image: "j", Rule: RuleReadOnly, Status: StatusError},
	}
	s := Summarize(attrs)
	caps := s.ByRule[RuleDropCaps]
	if caps.Examined != 6 || caps.Attributable != 4 || caps.ResolvedBySingle != 2 || caps.ResolvedByUnionOnly != 1 || caps.Unresolved != 1 {
		t.Errorf("EXEC-02 = %+v", caps)
	}
	if caps.NotReproduced != 1 || caps.BaselineFailed != 1 {
		t.Errorf("EXEC-02 reasons = %+v", caps)
	}
	if caps.BySingleCandidate["CAP_CHOWN"] != 2 || caps.BySingleCandidate["CAP_FOWNER"] != 1 {
		t.Errorf("per candidate = %v", caps.BySingleCandidate)
	}
	ro := s.ByRule[RuleReadOnly]
	if ro.Examined != 4 || ro.Attributable != 1 || ro.ImageAbsent != 1 || ro.NotObservable != 1 || ro.Error != 1 {
		t.Errorf("EXEC-01 = %+v", ro)
	}
	if s.Total.Examined != 10 || s.Total.Attributable != 5 || s.Total.ResolvedBySingle != 3 || s.Total.ResolvedByUnionOnly != 1 || s.Total.Unresolved != 1 {
		t.Errorf("total = %+v", s.Total)
	}
	for rule, rs := range s.ByRule {
		if rs.ResolvedBySingle+rs.ResolvedByUnionOnly+rs.Unresolved != rs.Attributable {
			t.Errorf("%s: the three outcomes must add up to the attributable pairs: %+v", rule, rs)
		}
	}
}

func TestCSVHasOneRowPerImageRuleAndCandidate(t *testing.T) {
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		if !has(rs.Flags, "--cap-drop=ALL") {
			return running()
		}
		if has(rs.Flags, "--cap-add=CAP_CHOWN") {
			return running()
		}
		o := exited(1)
		o.LogTail = "line one\nline two with, a comma and \"quotes\""
		return o
	}}
	attrs := Attribute(context.Background(), r, cfg(), []Target{
		{Image: "alpine", Rule: RuleDropCaps}, {Image: "nginx", Rule: RuleDropCaps},
	}, discard(), nil)
	var buf bytes.Buffer
	if err := WriteCSV(&buf, attrs); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1+2*13 {
		t.Fatalf("rows = %d, want header plus 13 attempts for each of 2 pairs", len(rows))
	}
	if strings.Join(rows[0], ",") != strings.Join(csvHeader, ",") {
		t.Errorf("header = %v", rows[0])
	}
	seen := map[string]bool{}
	for _, row := range rows[1:] {
		if len(row) != len(csvHeader) {
			t.Fatalf("row has %d columns: %v", len(row), row)
		}
		key := row[0] + "|" + row[1] + "|" + row[3] + "|" + row[4]
		if seen[key] {
			t.Errorf("duplicate row %s", key)
		}
		seen[key] = true
		if strings.Contains(row[10], "\n") {
			t.Errorf("log tail must be on one line: %q", row[10])
		}
	}
	// A resolving row.
	found := false
	for _, row := range rows[1:] {
		if row[0] == "alpine" && row[3] == KindSingle && row[4] == "CAP_CHOWN" {
			found = row[2] == StatusResolvedSingle && row[7] == "true" && row[8] == "true" && row[5] == StateRunning
		}
	}
	if !found {
		t.Error("the CAP_CHOWN row must show survived and resolved")
	}
	// Rows of failing attempts carry the exit code.
	for _, row := range rows[1:] {
		if row[3] == KindTreatment && (row[6] != "1" || row[7] != "false") {
			t.Errorf("treatment row = %v", row)
		}
	}
}

func TestCSVRowForATargetWithoutAnyRun(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCSV(&buf, []Attribution{{Image: "x", Rule: RuleDropCaps, Status: StatusImageAbsent, Detail: "not in the local store"}})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := csv.NewReader(&buf).ReadAll()
	if len(rows) != 2 || rows[1][2] != StatusImageAbsent || rows[1][3] != "" || !strings.Contains(rows[1][10], "local store") {
		t.Errorf("rows = %v", rows)
	}
}

func TestOutputsAreWrittenAndSnapshottedPerPair(t *testing.T) {
	dir := t.TempDir()
	r := &fakeRunner{behave: capBehave(func(f []string) bool { return has(f, "--cap-add=CAP_CHOWN") })}
	doc := &Document{SchemaVersion: "1", Protocol: NewProtocol(3 * time.Second), Source: Source{StudyPath: "s.json", StudySHA256: "x"}}
	snapshots := 0
	targets := []Target{{Image: "a", Rule: RuleDropCaps}, {Image: "b", Rule: RuleDropCaps}}
	attrs := Attribute(context.Background(), r, cfg(), targets, discard(), func(done []Attribution) {
		doc.Attributions = done
		doc.Summary = Summarize(done)
		if err := WriteOutputs(dir, doc); err != nil {
			t.Fatal(err)
		}
		snapshots++
		data, err := os.ReadFile(filepath.Join(dir, "attribution.json"))
		if err != nil {
			t.Fatal(err)
		}
		var snap Document
		if err := json.Unmarshal(data, &snap); err != nil || len(snap.Attributions) != snapshots {
			t.Errorf("snapshot %d holds %d attributions (err %v)", snapshots, len(snap.Attributions), err)
		}
	})
	if snapshots != 2 || len(attrs) != 2 {
		t.Errorf("snapshots %d attributions %d", snapshots, len(attrs))
	}
	doc.Complete = true
	if err := WriteOutputs(dir, doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"attribution.json", "attribution.csv"} {
		if st, err := os.Stat(filepath.Join(dir, name)); err != nil || st.Size() == 0 {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "attribution.json"))
	var back Document
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Summary.Total.ResolvedBySingle != 2 || back.Protocol.WindowMs != 3000 || len(back.Protocol.Treatments[RuleReadOnly]) == 0 {
		t.Errorf("document = %+v", back.Summary)
	}
	if back.Protocol.Treatments[RuleDropCaps][0] != "--cap-drop=ALL" {
		t.Errorf("treatments = %v", back.Protocol.Treatments)
	}
}

func TestInterruptedRunStopsBetweenPairs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		cancel()
		return running()
	}}
	attrs := Attribute(ctx, r, cfg(), []Target{{Image: "a", Rule: RuleDropCaps}, {Image: "b", Rule: RuleDropCaps}}, discard(), nil)
	if len(attrs) != 1 {
		t.Errorf("attributions = %d, the second pair must not start after the cancel", len(attrs))
	}
}
