package conunit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

// tier3Script emulates a container CLI whose container states come from files
// in $FAKE_DIR. A `run` whose arguments contain one of the words in
// $FAKE_TREATMENT_MARKERS uses treatment.seq, every other run uses
// baseline.seq (the baseline carries no treatment flag). `run.fail` holds a
// marker: runs containing it fail with exit code 126.
const tier3Script = `#!/bin/sh
D="$FAKE_DIR"
log() { printf '%s\n' "$*" >> "$D/calls.log"; }
case "$1" in
  --version) echo "podman version 5.0.0"; exit 0 ;;
  run)
    log "run $*"
    name=""; prev=""
    for a in "$@"; do if [ "$prev" = "--name" ]; then name="$a"; fi; prev="$a"; done
    seq="$D/baseline.seq"
    for m in $FAKE_TREATMENT_MARKERS; do
      case "$*" in *"$m"*) seq="$D/treatment.seq" ;; esac
    done
    if [ -f "$D/run.fail" ]; then
      marker=$(cat "$D/run.fail")
      case "$*" in *"$marker"*) echo "Error: container create failed" >&2; exit 126 ;; esac
    fi
    cp "$seq" "$D/$name.seq"
    echo 0 > "$D/$name.n"
    echo "0123456789abcdef"
    exit 0 ;;
  container)
    name="$5"
    n=$(cat "$D/$name.n"); n=$((n+1)); echo $n > "$D/$name.n"
    line=$(sed -n "${n}p" "$D/$name.seq")
    if [ -z "$line" ]; then line=$(tail -n 1 "$D/$name.seq"); fi
    echo "$line"
    exit 0 ;;
  logs)
    name="${3}"
    case "$name" in *) cat "$D/logs.txt" 2>/dev/null ;; esac
    exit 0 ;;
  rm) log "rm $*"; exit 0 ;;
  kill)
    name="$3"
    log "kill $*"
    if [ -f "$D/after-kill.seq" ]; then cp "$D/after-kill.seq" "$D/$name.seq"; echo 0 > "$D/$name.n"; fi
    exit 0 ;;
esac
exit 99
`

type tier3Fixture struct {
	t   *testing.T
	dir string
	eng *engine.Engine
}

func newTier3Fixture(t *testing.T, baseline string, treatment string, markers ...string) *tier3Fixture {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FAKE_DIR", dir)
	t.Setenv("FAKE_TREATMENT_MARKERS", strings.Join(markers, " "))
	path := filepath.Join(dir, "podman")
	if err := os.WriteFile(path, []byte(tier3Script), 0o700); err != nil {
		t.Fatal(err)
	}
	f := &tier3Fixture{t: t, dir: dir, eng: &engine.Engine{BinaryPath: path}}
	f.write("baseline.seq", baseline)
	f.write("treatment.seq", treatment)
	return f
}

func (f *tier3Fixture) write(name string, lines ...string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *tier3Fixture) calls() []string {
	data, _ := os.ReadFile(filepath.Join(f.dir, "calls.log"))
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func (f *tier3Fixture) runs(containing string) []string {
	var matched []string
	for _, call := range f.calls() {
		if strings.HasPrefix(call, "run ") && strings.Contains(call, containing) {
			matched = append(matched, call)
		}
	}
	return matched
}

func (f *tier3Fixture) container() *conunit.Container {
	return &conunit.Container{
		Context:     nil,
		Image:       "sha256:abc",
		Engine:      f.eng,
		ProbeWindow: 300 * time.Millisecond,
	}
}

func onlyResult(t *testing.T, c *conunit.Container) spec.TestResult {
	t.Helper()
	if len(c.Results) != 1 {
		t.Fatalf("results = %+v, want exactly one", c.Results)
	}
	return c.Results[0]
}

func codeOf(t *testing.T, p *int) int {
	t.Helper()
	if p == nil {
		t.Fatal("expected an exit code in the evidence")
	}
	return *p
}

func TestTier3PassesOnlyWhenBaselineAndTreatmentAreRunningAtTheWindowEnd(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "running 0", "--cap-drop=ALL")
	c := f.container()
	c.AssertContract().DropAllCapabilitiesCompatible()
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomePass || r.Reason != spec.ReasonNone {
		t.Fatalf("result = %+v, want a plain PASS", r)
	}
	ev := r.Evidence
	if ev == nil || ev.BaselineState != "running" || ev.TreatmentState != "running" || ev.WindowMillis != 300 {
		t.Fatalf("evidence = %+v, want baseline and treatment running with a 300 ms window", ev)
	}
	if got := f.runs("--cap-drop=ALL"); len(got) != 1 {
		t.Errorf("treatment runs = %v, want one", got)
	}
}

func TestTier3TreatmentExitingNonZeroFailsWithEvidenceAndOnlyAHint(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "exited 1", "--cap-drop=ALL")
	f.write("logs.txt", "exec gosu postgres docker-entrypoint.sh", "gosu: failed switching to 'postgres': operation not permitted")
	c := f.container()
	c.AssertContract().DropAllCapabilitiesCompatible()
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomeFail || r.Reason != spec.ReasonNone {
		t.Fatalf("result = %+v, want a plain FAIL", r)
	}
	ev := r.Evidence
	if ev == nil || ev.BaselineState != "running" || ev.TreatmentState != "exited_nonzero" || codeOf(t, ev.TreatmentExitCode) != 1 || ev.BaselineExitCode != nil {
		t.Fatalf("evidence = %+v", ev)
	}
	if !strings.Contains(ev.LogTail, "failed switching to") {
		t.Errorf("the log tail must be part of the evidence: %q", ev.LogTail)
	}
	if strings.Contains(strings.ToLower(r.Explanation), "gosu") || strings.Contains(strings.ToLower(r.Explanation), "antipattern") {
		t.Errorf("the explanation must not carry keyword diagnoses: %q", r.Explanation)
	}
	if !strings.Contains(r.Explanation, "not a defect claim") {
		t.Errorf("the explanation must say what a FAIL does and does not claim: %q", r.Explanation)
	}
	if !strings.Contains(r.Hint, "gosu") || !strings.HasPrefix(r.Hint, "Keyword match, not a diagnosis") {
		t.Errorf("the keyword diagnosis belongs in the non-authoritative hint: %q", r.Hint)
	}
}

func TestTier3SurvivingTreatmentThatDiesLaterIsAFail(t *testing.T) {
	// Running at the first polls but dead before the window ends.
	f := newTier3Fixture(t, "running 0", "running 0\nrunning 0\nexited 2", "--read-only")
	c := f.container()
	c.ProbeWindow = 2 * time.Second
	c.AssertContract().ReadOnlyRootfsCompatible()
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomeFail || r.Evidence.TreatmentState != "exited_nonzero" {
		t.Fatalf("result = %+v, want FAIL: the state is decided at the end of the window, not at the first poll", r)
	}
}

func TestTier3TreatmentThatExitsZeroEarlyFailsAgainstARunningBaseline(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "exited 0", "--security-opt=no-new-privileges:true")
	c := f.container()
	c.AssertContract().ComplyWithNoNewPrivileges()
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomeFail || r.Evidence.TreatmentState != "exited0" {
		t.Fatalf("result = %+v, want FAIL with state exited0", r)
	}
}

func TestTier3BaselineFailureMakesEveryTreatmentUnverified(t *testing.T) {
	for _, tc := range []struct {
		name     string
		baseline string
		runFail  bool
		state    string
		code     int
	}{
		{name: "exits non-zero", baseline: "exited 3", state: "exited_nonzero", code: 3},
		{name: "cannot start", baseline: "running 0", runFail: true, state: "start_failed", code: 126},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTier3Fixture(t, tc.baseline, "running 0", "--read-only", "--cap-drop=ALL", "--security-opt", "--memory=256m")
			if tc.runFail {
				// Only the baseline run (no treatment marker) fails.
				f.write("run.fail", "--pids-limit=256")
			}
			c := f.container()
			c.AssertContract().
				ReadOnlyRootfsCompatible().
				DropAllCapabilitiesCompatible().
				ComplyWithNoNewPrivileges().
				ComplyWithResourceLimits("256m", 0)
			if len(c.Results) != 4 {
				t.Fatalf("results = %+v", c.Results)
			}
			for _, r := range c.Results {
				if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonBaselineFailed {
					t.Errorf("%s = %s/%s, want UNVERIFIED/BASELINE_FAILED", r.TestID, r.EffectiveOutcome(), r.Reason)
				}
				if r.Evidence == nil || r.Evidence.BaselineState != tc.state || codeOf(t, r.Evidence.BaselineExitCode) != tc.code || r.Evidence.TreatmentState != "" {
					t.Errorf("%s evidence = %+v, want baseline %s with code %d and no treatment state", r.TestID, r.Evidence, tc.state, tc.code)
				}
			}
			if got := f.runs("--read-only"); len(got) != 0 {
				t.Errorf("no treatment may run when the baseline failed: %v", got)
			}
		})
	}
}

func TestTier3BaselineExitingZeroEarlyIsNotObservable(t *testing.T) {
	f := newTier3Fixture(t, "exited 0", "running 0", "--cap-drop=ALL")
	c := f.container()
	c.AssertContract().DropAllCapabilitiesCompatible().HandlesSigtermGracefully(time.Second)
	if len(c.Results) != 2 {
		t.Fatalf("results = %+v", c.Results)
	}
	for _, r := range c.Results {
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonNotObservable {
			t.Errorf("%s = %s/%s, want UNVERIFIED/NOT_OBSERVABLE instead of a trivial PASS", r.TestID, r.EffectiveOutcome(), r.Reason)
		}
		if r.Evidence == nil || r.Evidence.BaselineState != "exited0" {
			t.Errorf("%s evidence = %+v", r.TestID, r.Evidence)
		}
	}
	for _, call := range f.calls() {
		if strings.HasPrefix(call, "kill ") {
			t.Error("SIGTERM must not be sent when the baseline is not observable")
		}
	}
}

func TestTier3TreatmentStartFailureIsAFail(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "running 0", "--read-only")
	f.write("run.fail", "--read-only")
	c := f.container()
	c.AssertContract().ReadOnlyRootfsCompatible()
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomeFail || r.Evidence.TreatmentState != "start_failed" || codeOf(t, r.Evidence.TreatmentExitCode) != 126 {
		t.Fatalf("result = %+v", r)
	}
	if !strings.Contains(r.Evidence.LogTail, "container create failed") {
		t.Errorf("engine output must be part of the evidence: %q", r.Evidence.LogTail)
	}
}

func TestTier3TimeoutsAndEngineErrorsAreUnverifiedWithReasons(t *testing.T) {
	t.Run("baseline never observable", func(t *testing.T) {
		f := newTier3Fixture(t, "created 0", "running 0", "--cap-drop=ALL")
		c := f.container()
		c.AssertContract().DropAllCapabilitiesCompatible()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonProbeTimeout {
			t.Fatalf("result = %+v, want UNVERIFIED/PROBE_TIMEOUT", r)
		}
	})
	t.Run("treatment never observable", func(t *testing.T) {
		f := newTier3Fixture(t, "running 0", "created 0", "--cap-drop=ALL")
		c := f.container()
		c.AssertContract().DropAllCapabilitiesCompatible()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonProbeTimeout || r.Evidence.BaselineState != "running" {
			t.Fatalf("result = %+v, want UNVERIFIED/PROBE_TIMEOUT with the baseline in the evidence", r)
		}
	})
	t.Run("engine command fails", func(t *testing.T) {
		f := newTier3Fixture(t, "running 0", "running 0", "--cap-drop=ALL")
		f.write("baseline.seq", "garbage")
		c := f.container()
		c.AssertContract().DropAllCapabilitiesCompatible()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonProbeError {
			t.Fatalf("result = %+v, want UNVERIFIED/PROBE_ERROR", r)
		}
	})
	t.Run("no engine", func(t *testing.T) {
		c := &conunit.Container{Image: "sha256:abc"}
		c.AssertContract().ReadOnlyRootfsCompatible()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonProbeError {
			t.Fatalf("result = %+v, want UNVERIFIED/PROBE_ERROR", r)
		}
	})
}

func TestTier3BaselineRunsOncePerImageAndIsSharedByAllTreatments(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "running 0", "--read-only", "--cap-drop=ALL", "--security-opt", "--memory=256m")
	c := f.container()
	c.AssertContract().
		ReadOnlyRootfsCompatible().
		DropAllCapabilitiesCompatible().
		ComplyWithNoNewPrivileges().
		ComplyWithResourceLimits("256m", 0).
		HandlesSigtermGracefully(time.Second)

	baselineRuns := 0
	for _, call := range f.calls() {
		if !strings.HasPrefix(call, "run ") {
			continue
		}
		isTreatment := false
		for _, marker := range []string{"--read-only", "--cap-drop=ALL", "--security-opt", "--memory=256m"} {
			if strings.Contains(call, marker) {
				isTreatment = true
			}
		}
		if !isTreatment && strings.Contains(call, "con-unit-probe-") {
			baselineRuns++
		}
	}
	if baselineRuns != 1 {
		t.Errorf("baseline runs = %d, want exactly one per image\n%s", baselineRuns, strings.Join(f.calls(), "\n"))
	}
	if c.Baseline == nil || c.Baseline.Runs() != 1 {
		t.Errorf("baseline cache must record one run")
	}

	// A second container for the same image shares the cache.
	shared := f.container()
	shared.Baseline = c.Baseline
	shared.AssertContract().DropAllCapabilitiesCompatible()
	if c.Baseline.Runs() != 1 {
		t.Errorf("a shared baseline cache must not start another baseline, runs = %d", c.Baseline.Runs())
	}
}

func TestTier3MemoryTreatmentChangesOnlyTheMemoryLimit(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "running 0", "--memory=256m")
	c := f.container()
	c.AssertContract().ComplyWithResourceLimits("256m", 0)
	treatment := f.runs("--memory=256m")
	if len(treatment) != 1 || strings.Count(treatment[0], "--pids-limit") != 1 || !strings.Contains(treatment[0], "--pids-limit=256") {
		t.Fatalf("treatment run = %v, want the baseline PID limit of 256 left untouched", treatment)
	}
}

func TestTier3ExitCodeHintForMemoryLimit(t *testing.T) {
	f := newTier3Fixture(t, "running 0", "exited 137", "--memory=256m")
	c := f.container()
	c.AssertContract().ComplyWithResourceLimits("256m", 0)
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomeFail || !strings.Contains(r.Hint, "137") || strings.Contains(r.Explanation, "137") {
		t.Fatalf("result = %+v, want a FAIL whose hint, not its explanation, mentions exit code 137", r)
	}
}

func TestSigtermCheck(t *testing.T) {
	for _, tc := range []struct {
		name      string
		afterKill string
		want      spec.Outcome
		wantCode  int
	}{
		{"handled with exit 0", "exited 0", spec.OutcomePass, 0},
		{"default action exit 143", "exited 143", spec.OutcomePass, 143},
		{"other exit code", "exited 1", spec.OutcomeFail, 1},
		{"SIGKILL after the grace period", "exited 137", spec.OutcomeFail, 137},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTier3Fixture(t, "running 0", "running 0")
			f.write("after-kill.seq", tc.afterKill)
			c := f.container()
			c.AssertContract().HandlesSigtermGracefully(2 * time.Second)
			r := onlyResult(t, c)
			if r.EffectiveOutcome() != tc.want {
				t.Fatalf("result = %+v, want %s", r, tc.want)
			}
			if r.Evidence == nil || codeOf(t, r.Evidence.TreatmentExitCode) != tc.wantCode || r.Evidence.BaselineState != "running" {
				t.Errorf("evidence = %+v, want baseline running and exit code %d", r.Evidence, tc.wantCode)
			}
		})
	}

	t.Run("signal ignored", func(t *testing.T) {
		f := newTier3Fixture(t, "running 0", "running 0")
		f.write("after-kill.seq", "running 0")
		c := f.container()
		c.AssertContract().HandlesSigtermGracefully(time.Second)
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeFail || !strings.Contains(r.Message, "remained running") {
			t.Fatalf("result = %+v, want a FAIL for a container that ignores SIGTERM", r)
		}
	})
}

func TestEveryTier3ResultStaysWithinTheContractVocabulary(t *testing.T) {
	f := newTier3Fixture(t, "exited 1", "running 0", "--read-only")
	c := f.container()
	c.AssertContract().ReadOnlyRootfsCompatible().ComplyWithKubernetesPSS().ComplyWithArbitraryNonRootUID(10001)
	allowed := map[spec.Reason]bool{
		spec.ReasonBaselineFailed: true, spec.ReasonNotObservable: true,
		spec.ReasonProbeTimeout: true, spec.ReasonProbeError: true,
	}
	for _, r := range c.Results {
		if r.EffectiveOutcome() == spec.OutcomeUnverified && !allowed[r.Reason] {
			t.Errorf("%s has reason %q outside the Tier 3 vocabulary", r.TestID, r.Reason)
		}
	}
}
