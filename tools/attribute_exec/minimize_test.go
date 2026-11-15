package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func minCfg() Config {
	c := cfg()
	c.Minimize = true
	return c
}

// capsAdded returns the capabilities that a run adds back, sorted.
func capsAdded(flags []string) []string {
	var out []string
	for _, f := range flags {
		if c, ok := strings.CutPrefix(f, "--cap-add="); ok {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// needsCaps is a container that survives --cap-drop=ALL if and only if every
// capability of needed is added back. Without --cap-drop it always survives.
func needsCaps(needed ...string) func(RunSpec) Observation {
	return capBehave(func(flags []string) bool {
		have := map[string]bool{}
		for _, c := range capsAdded(flags) {
			have[c] = true
		}
		for _, n := range needed {
			if !have[n] {
				return false
			}
		}
		return true
	})
}

func minimizeAttempts(a Attribution) []Attempt {
	var out []Attempt
	for _, at := range a.Attempts {
		if at.Kind == KindMinimize {
			out = append(out, at)
		}
	}
	return out
}

// survivingSetObserved reports whether some attempt that survived added
// exactly the given capabilities: the minimal set must have been seen alive.
func survivingSetObserved(a Attribution, set []string) bool {
	want := strings.Join(sortedCopy(set), ",")
	for _, at := range a.Attempts {
		if at.Survived && at.Kind != KindBaseline && strings.Join(capsAdded(at.Flags), ",") == want {
			return true
		}
	}
	return false
}

func TestMinimizationFindsTheMinimalCapabilitySet(t *testing.T) {
	cases := []struct {
		name       string
		needed     []string
		wantStatus string
		wantSet    []string
		wantMethod string
		// wantMinimizeRuns is the number of removal runs, -1 when none run.
		wantMinimizeRuns int
	}{
		{"gosu style image needs setuid and setgid together", []string{"CAP_SETUID", "CAP_SETGID"}, StatusResolvedMinimal, []string{"CAP_SETGID", "CAP_SETUID"}, MethodMinimization, 10},
		{"three capabilities", []string{"CAP_CHOWN", "CAP_FOWNER", "CAP_SETUID"}, StatusResolvedMinimal, []string{"CAP_CHOWN", "CAP_FOWNER", "CAP_SETUID"}, MethodMinimization, 10},
		{"first and last candidate", []string{"CAP_CHOWN", "CAP_SYS_CHROOT"}, StatusResolvedMinimal, []string{"CAP_CHOWN", "CAP_SYS_CHROOT"}, MethodMinimization, 10},
		{"every candidate is needed", capCandidates, StatusResolvedMinimal, capCandidates, MethodMinimization, 10},
		{"one capability is a single, not a minimization", []string{"CAP_NET_BIND_SERVICE"}, StatusResolvedSingle, []string{"CAP_NET_BIND_SERVICE"}, MethodSingle, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{behave: needsCaps(tc.needed...)}
			a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
			if a.Status != tc.wantStatus {
				t.Fatalf("status = %s (%s), want %s", a.Status, a.Detail, tc.wantStatus)
			}
			if strings.Join(a.MinimalSet, ",") != strings.Join(sortedCopy(tc.wantSet), ",") || a.MinimalMethod != tc.wantMethod {
				t.Errorf("minimal set %v by %q, want %v by %q", a.MinimalSet, a.MinimalMethod, tc.wantSet, tc.wantMethod)
			}
			got := len(minimizeAttempts(a))
			switch {
			case tc.wantMinimizeRuns < 0 && got != 0:
				t.Errorf("%d removal runs, a single candidate needs none", got)
			case tc.wantMinimizeRuns >= 0 && got != tc.wantMinimizeRuns:
				t.Errorf("%d removal runs, want %d", got, tc.wantMinimizeRuns)
			}
			if !survivingSetObserved(a, a.MinimalSet) {
				t.Errorf("no surviving run added exactly the minimal set %v", a.MinimalSet)
			}
		})
	}
}

// TestMinimizationIsExactForEverySubsetOfCandidates checks all 1023 non-empty
// sets of capabilities that an image could need. The minimal set must be the
// needed set, a set of one must be named without removal runs, and a set of two
// or more must test every candidate once.
func TestMinimizationIsExactForEverySubsetOfCandidates(t *testing.T) {
	n := len(capCandidates)
	for mask := 1; mask < 1<<n; mask++ {
		var needed []string
		for i, c := range capCandidates {
			if mask&(1<<i) != 0 {
				needed = append(needed, c)
			}
		}
		r := &fakeRunner{behave: needsCaps(needed...)}
		a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
		if strings.Join(a.MinimalSet, ",") != strings.Join(sortedCopy(needed), ",") {
			t.Fatalf("needed %v: minimal set %v (status %s)", needed, a.MinimalSet, a.Status)
		}
		wantStatus, wantRuns := StatusResolvedMinimal, n
		if len(needed) == 1 {
			wantStatus, wantRuns = StatusResolvedSingle, 0
		}
		if a.Status != wantStatus || len(minimizeAttempts(a)) != wantRuns {
			t.Fatalf("needed %v: status %s with %d removal runs, want %s with %d", needed, a.Status, len(minimizeAttempts(a)), wantStatus, wantRuns)
		}
	}
}

func TestMinimizationRunsEveryStepUnderTheDefensiveProfile(t *testing.T) {
	r := &fakeRunner{behave: needsCaps("CAP_SETUID", "CAP_SETGID")}
	a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	steps := minimizeAttempts(a)
	if len(steps) == 0 {
		t.Fatal("no removal runs")
	}
	for _, at := range steps {
		if !has(at.Flags, "--network=none") || !has(at.Flags, "--pids-limit=256") || !has(at.Flags, "--cap-drop=ALL") {
			t.Errorf("removal run without %s lacks the profile: %v", at.Candidate, at.Flags)
		}
		if at.Candidate == "" {
			t.Error("a removal run must name the element it leaves out")
		}
		for _, c := range capsAdded(at.Flags) {
			if c == at.Candidate {
				t.Errorf("removal run still adds %s: %v", at.Candidate, at.Flags)
			}
		}
		if at.Resolved != at.Survived {
			t.Errorf("removal of %s: resolved %t but survived %t", at.Candidate, at.Resolved, at.Survived)
		}
	}
	// The set only ever shrinks: each run adds fewer capabilities than the
	// union, and a needed element is never removed for good.
	for _, at := range steps {
		if len(capsAdded(at.Flags)) >= len(capCandidates) {
			t.Errorf("removal of %s did not remove anything: %v", at.Candidate, at.Flags)
		}
	}
}

func TestMinimizationCanBeSwitchedOff(t *testing.T) {
	r := &fakeRunner{behave: needsCaps("CAP_SETUID", "CAP_SETGID")}
	c := cfg() // Minimize false
	a := attributeOne(context.Background(), r, c, Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusResolvedUnion || len(a.MinimalSet) != 0 || len(minimizeAttempts(a)) != 0 {
		t.Errorf("status %s, minimal set %v, removal runs %d: the union result must stand", a.Status, a.MinimalSet, len(minimizeAttempts(a)))
	}
	if len(r.calls) != 13 {
		t.Errorf("calls = %d, want baseline, treatment, 10 singles and the union only", len(r.calls))
	}
}

func TestMinimizationDoesNotRunWhenTheUnionDoesNotResolve(t *testing.T) {
	r := &fakeRunner{behave: needsCaps("CAP_SYS_ADMIN")} // not a candidate
	a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusUnresolved || len(minimizeAttempts(a)) != 0 || len(a.MinimalSet) != 0 {
		t.Errorf("status %s, removal runs %d, minimal set %v", a.Status, len(minimizeAttempts(a)), a.MinimalSet)
	}
}

// TestSingleFoundOnlyByMinimization covers a container that does not survive
// when one capability is added alone the first time but survives later: the
// singles resolve nothing, the minimization ends at a set of one, and the
// status is RESOLVED_MINIMAL for it.
func TestSingleFoundOnlyByMinimization(t *testing.T) {
	killAloneSeen := false
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		if !has(rs.Flags, "--cap-drop=ALL") {
			return running()
		}
		added := capsAdded(rs.Flags)
		if !strings.Contains(strings.Join(added, ","), "CAP_KILL") {
			return exited(1)
		}
		if len(added) == 1 && !killAloneSeen {
			killAloneSeen = true
			return exited(1) // the single run of CAP_KILL fails once
		}
		return running()
	}}
	a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusResolvedMinimal || strings.Join(a.MinimalSet, ",") != "CAP_KILL" || len(a.ResolvedBy) != 0 {
		t.Errorf("status %s, minimal set %v, resolved by %v", a.Status, a.MinimalSet, a.ResolvedBy)
	}
}

func TestMinimizationStopsOnAnUnreadableEngineState(t *testing.T) {
	// Calls 1 to 13 are the baseline, the treatment, ten singles and the union.
	// Call 16 is the third removal run, and it cannot read the container state.
	const thirdRemovalCall = 16
	calls := 0
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		calls++
		if calls == thirdRemovalCall {
			return Observation{State: StateUnknown, Err: "inspect failed"}
		}
		return needsCaps("CAP_SETUID", "CAP_SETGID")(rs)
	}}
	a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusResolvedUnion || len(a.MinimalSet) != 0 {
		t.Fatalf("status %s, minimal set %v: an interrupted minimization must not claim a minimal set", a.Status, a.MinimalSet)
	}
	if !strings.Contains(a.Detail, "inspect failed") || !a.UnionResolves {
		t.Errorf("detail = %q, union resolves %t", a.Detail, a.UnionResolves)
	}
	if got := len(minimizeAttempts(a)); got != 3 {
		t.Errorf("%d removal runs, the minimization must stop at the third", got)
	}
}

func TestAStartFailureDuringMinimizationKeepsTheElement(t *testing.T) {
	r := &fakeRunner{behave: func(rs RunSpec) Observation {
		if has(rs.Flags, "--cap-drop=ALL") && len(capsAdded(rs.Flags)) == len(capCandidates)-1 && !has(rs.Flags, "--cap-add=CAP_CHOWN") {
			return Observation{State: StateStartFailed, LogTail: "runtime error"}
		}
		return needsCaps("CAP_SETUID", "CAP_SETGID")(rs)
	}}
	a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleDropCaps}, discard())
	if a.Status != StatusResolvedMinimal {
		t.Fatalf("status = %s", a.Status)
	}
	// CAP_CHOWN could not be tested away, so it stays in the set.
	if strings.Join(a.MinimalSet, ",") != "CAP_CHOWN,CAP_SETGID,CAP_SETUID" {
		t.Errorf("minimal set = %v, an element whose removal run did not start must stay", a.MinimalSet)
	}
}

func TestMinimizationOfReadOnlyMounts(t *testing.T) {
	needs := func(mounts ...string) func(RunSpec) Observation {
		return func(rs RunSpec) Observation {
			if !has(rs.Flags, "--read-only") {
				return running()
			}
			m := tmpfsMounts(rs.Flags)
			for _, p := range mounts {
				if _, ok := m[p]; !ok {
					return exited(1)
				}
			}
			return running()
		}
	}
	cases := []struct {
		name       string
		behave     func(RunSpec) Observation
		wantStatus string
		wantSet    string
	}{
		{"two mounts", needs("/var/lib", "/var/log"), StatusResolvedMinimal, "/var/lib + /var/log"},
		{"all mounts", needs(tmpfsCandidates...), StatusResolvedMinimal, strings.Join(sortedCopy(tmpfsCandidates), " + ")},
		{"one mount", needs("/var/lib"), StatusResolvedSingle, "/var/lib"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{behave: tc.behave}
			a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleReadOnly}, discard())
			if a.Status != tc.wantStatus || setLabel(a.MinimalSet) != tc.wantSet {
				t.Fatalf("status %s, minimal set %q, want %s and %q", a.Status, setLabel(a.MinimalSet), tc.wantStatus, tc.wantSet)
			}
			for _, at := range minimizeAttempts(a) {
				mounts := tmpfsMounts(at.Flags)
				if _, ok := mounts[at.Candidate]; ok {
					t.Errorf("removal of %s still mounts it: %v", at.Candidate, at.Flags)
				}
				if mounts["/tmp"] != "rw,nosuid,size=65536k" {
					t.Errorf("the base /tmp mount must stay in every run: %v", at.Flags)
				}
			}
		})
	}
}

func TestMinimizationStartsFromTheUnionWithoutVarRunWhenTheFullUnionDoesNotStart(t *testing.T) {
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
		if _, ok := m["/var/lib"]; ok {
			if _, ok := m["/var/log"]; ok {
				return running()
			}
		}
		return exited(1)
	}}
	a := attributeOne(context.Background(), r, minCfg(), Target{Image: "img", Rule: RuleReadOnly}, discard())
	if a.Status != StatusResolvedMinimal || setLabel(a.MinimalSet) != "/var/lib + /var/log" {
		t.Fatalf("status %s, minimal set %v", a.Status, a.MinimalSet)
	}
	if !strings.Contains(a.Detail, "without /var/run") {
		t.Errorf("detail = %q", a.Detail)
	}
	steps := minimizeAttempts(a)
	if len(steps) != len(tmpfsCandidates)-1 {
		t.Errorf("%d removal runs, want one per element of the union without /var/run (%d)", len(steps), len(tmpfsCandidates)-1)
	}
	for _, at := range steps {
		if at.Candidate == "/var/run" {
			t.Error("/var/run is not part of the starting set and must not be tested")
		}
		if _, ok := tmpfsMounts(at.Flags)["/var/run"]; ok {
			t.Errorf("a removal run mounts /var/run: %v", at.Flags)
		}
	}
}

func TestSummaryCountsMinimalSets(t *testing.T) {
	attrs := []Attribution{
		{Image: "a", Rule: RuleDropCaps, Status: StatusResolvedMinimal, MinimalSet: []string{"CAP_SETUID", "CAP_SETGID"}},
		{Image: "b", Rule: RuleDropCaps, Status: StatusResolvedMinimal, MinimalSet: []string{"CAP_SETGID", "CAP_SETUID"}},
		{Image: "c", Rule: RuleDropCaps, Status: StatusResolvedSingle, ResolvedBy: []string{"CAP_CHOWN"}, MinimalSet: []string{"CAP_CHOWN"}},
		{Image: "d", Rule: RuleDropCaps, Status: StatusResolvedUnion},
		{Image: "e", Rule: RuleReadOnly, Status: StatusResolvedMinimal, MinimalSet: []string{"/var/log", "/var/lib"}},
	}
	s := Summarize(attrs)
	caps := s.ByRule[RuleDropCaps]
	if caps.ResolvedByMinimal != 2 || caps.ResolvedBySingle != 1 || caps.ResolvedByUnionOnly != 1 || caps.Attributable != 4 {
		t.Errorf("EXEC-02 = %+v", caps)
	}
	if caps.ByMinimalSet["CAP_SETGID + CAP_SETUID"] != 2 || caps.ByMinimalSet["CAP_CHOWN"] != 1 {
		t.Errorf("minimal sets = %v", caps.ByMinimalSet)
	}
	if ro := s.ByRule[RuleReadOnly]; ro.ByMinimalSet["/var/lib + /var/log"] != 1 {
		t.Errorf("EXEC-01 minimal sets = %v", ro.ByMinimalSet)
	}
	for rule, rs := range s.ByRule {
		if got := rs.ResolvedBySingle + rs.ResolvedByMinimal + rs.ResolvedByUnionOnly + rs.Unresolved; got != rs.Attributable {
			t.Errorf("%s: outcomes add up to %d, attributable %d", rule, got, rs.Attributable)
		}
	}
	if s.Total.ResolvedByMinimal != 3 {
		t.Errorf("total = %+v", s.Total)
	}
}

func TestSetLabelIsSortedAndStable(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"CAP_SETUID"}, "CAP_SETUID"},
		{[]string{"CAP_SETUID", "CAP_SETGID"}, "CAP_SETGID + CAP_SETUID"},
		{[]string{"/var/log", "/var/lib", "/run"}, "/run + /var/lib + /var/log"},
	}
	for _, tc := range cases {
		in := append([]string(nil), tc.in...)
		if got := setLabel(tc.in); got != tc.want {
			t.Errorf("setLabel(%v) = %q, want %q", tc.in, got, tc.want)
		}
		if fmt.Sprint(in) != fmt.Sprint(tc.in) {
			t.Errorf("setLabel modified its input: %v", tc.in)
		}
	}
}
