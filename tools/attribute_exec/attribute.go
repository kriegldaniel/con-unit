package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Rules that can be attributed.
const (
	RuleReadOnly = "EXEC-01" // read-only root filesystem
	RuleDropCaps = "EXEC-02" // all capabilities dropped
)

// The defensive profile and the mock environment are duplicated from
// docs/CONTRACT.md section 6, which fixes them for every Tier 3 run: the
// baseline starts with only these flags, and every treatment adds its own flag
// on top. They are copied here, with the engine's values at the contract
// commit, so this tool does not depend on engine internals. If the contract
// changes them, change them here too. TestProfileMatchesContract in
// attribute_test.go pins them.
var defensiveFlags = []string{"--network=none", "--pids-limit=256"}

var mockEnv = []string{
	"POSTGRES_PASSWORD=conunit_test_password",
	"POSTGRES_HOST_AUTH_METHOD=trust",
	"MYSQL_ROOT_PASSWORD=conunit_test_password",
	"MARIADB_ROOT_PASSWORD=conunit_test_password",
	"ARANGO_NO_AUTH=1",
}

// Treatment flags of the rules, copied from pkg/engine (ReadOnlyRootfsFlags,
// DropAllCapabilitiesFlags, NoNewPrivilegesFlags, MemoryLimitFlags). The study
// treatment of EXEC-01 mounts /tmp writable, with the nosuid restriction and
// without noexec, so the attribution must use exactly these options: a
// different /tmp mount would test another treatment than the one that failed.
// TestTreatmentsMatchTheEngine pins every flag against the engine package.
const (
	dropAllCapsFlag     = "--cap-drop=ALL"
	readOnlyFlag        = "--read-only"
	noNewPrivilegesFlag = "--security-opt=no-new-privileges:true"
	memoryLimitFlag     = "--memory=256m"
	baseTmpfsMountPoint = "/tmp"
	baseTmpfsOptions    = "rw,nosuid,size=65536k"
	// candidateTmpfsOptions apply to the candidate mounts. They equal the
	// options of the treatment's own /tmp mount, so that a candidate differs
	// from the treatment by the extra mount only.
	candidateTmpfsOptions = baseTmpfsOptions
)

// capCandidates are the capabilities added back one at a time for EXEC-02,
// then all together.
var capCandidates = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
	"CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT",
}

// tmpfsCandidates are the writable mounts added for EXEC-01, then all
// together. /tmp is not a candidate: the treatment already mounts it writable
// with the same options, so a candidate on /tmp would repeat the treatment.
var tmpfsCandidates = []string{"/run", "/var/run", "/var/cache", "/var/log", "/var/lib"}

// Attempt kinds.
const (
	KindBaseline  = "baseline"  // defensive flags only
	KindTreatment = "treatment" // defensive flags plus the rule's treatment
	KindSingle    = "single"    // treatment plus one candidate
	KindUnion     = "union"     // treatment plus every candidate
	// KindMinimize is the current resolving set minus one element, tried while
	// the set is shrunk. Its Candidate is the element that was left out.
	KindMinimize = "minimize"
)

// Attribution statuses of one image and rule.
const (
	StatusResolvedSingle = "RESOLVED_SINGLE" // at least one single candidate makes the container survive
	// StatusResolvedMinimal means that no single candidate resolves the failure
	// but a set of two or more does, and that the set was shrunk until removing
	// any one element lets the container fail again. A set of one found this
	// way (the singles did not resolve it, the minimization did) also counts.
	StatusResolvedMinimal = "RESOLVED_MINIMAL"
	StatusResolvedUnion   = "RESOLVED_UNION"  // only the union makes it survive, and it was not shrunk
	StatusUnresolved      = "UNRESOLVED"      // not even the union helps
	StatusNotReproduced   = "NOT_REPRODUCED"  // the treatment survived this time, the study failure did not repeat
	StatusBaselineFailed  = "BASELINE_FAILED" // baseline did not start or exited non-zero
	StatusNotObservable   = "NOT_OBSERVABLE"  // baseline exited 0 before the window
	StatusImageAbsent     = "IMAGE_ABSENT"    // the image is not in the local store
	StatusError           = "ERROR"           // the engine misbehaved, no interpretation possible
)

// Target is one failure of the study to attribute.
type Target struct {
	Image string
	Rule  string
}

// Attempt is one container run of the attribution.
type Attempt struct {
	Kind      string      `json:"kind"`
	Candidate string      `json:"candidate,omitempty"` // for example CAP_CHOWN, /run or union
	Flags     []string    `json:"flags"`
	Obs       Observation `json:"observation"`
	Survived  bool        `json:"survived"`
	// Resolved is true for a single or union attempt that survived although the
	// treatment alone did not.
	Resolved bool `json:"resolved"`
}

// Methods that name the minimal set.
const (
	MethodSingle       = "single"       // one candidate alone resolved the failure
	MethodMinimization = "minimization" // the union was shrunk one element at a time
)

// Attribution is the outcome for one image and rule.
type Attribution struct {
	Image         string   `json:"image"`
	Rule          string   `json:"rule"`
	Status        string   `json:"status"`
	Detail        string   `json:"detail,omitempty"`
	ResolvedBy    []string `json:"resolved_by,omitempty"` // single candidates that resolved the failure
	UnionResolves bool     `json:"union_resolves"`
	// MinimalSet is a smallest set of candidates, sorted by name, that keeps
	// the container alive under the treatment: removing any one of its
	// elements made the container fail again in the run that tested it. It is
	// set for RESOLVED_SINGLE (the first resolving candidate, a set of one can
	// not shrink) and for RESOLVED_MINIMAL. Several sets of the same size can
	// exist: this is the one the fixed candidate order leads to.
	MinimalSet    []string  `json:"minimal_set,omitempty"`
	MinimalMethod string    `json:"minimal_method,omitempty"`
	Attempts      []Attempt `json:"attempts"`
}

// Config is the attribution protocol.
type Config struct {
	Window time.Duration
	Pull   bool
	// Minimize shrinks a union that resolves the failure, one element at a
	// time, to a minimal set. It is on by default in the command.
	Minimize bool
}

// treatmentFlags returns the flags of a rule's treatment.
func treatmentFlags(rule string) ([]string, error) {
	switch rule {
	case RuleDropCaps:
		return []string{dropAllCapsFlag}, nil
	case RuleReadOnly:
		return mountFlags(map[string]string{baseTmpfsMountPoint: baseTmpfsOptions}, true), nil
	}
	return nil, fmt.Errorf("rule %q cannot be attributed (supported: %s, %s)", rule, RuleReadOnly, RuleDropCaps)
}

// mountFlags renders tmpfs mounts in sorted order, after --read-only when
// readOnly is set. One mount per destination, so a candidate on /tmp replaces
// the base mount instead of duplicating it.
func mountFlags(mounts map[string]string, readOnly bool) []string {
	var flags []string
	if readOnly {
		flags = append(flags, readOnlyFlag)
	}
	dests := make([]string, 0, len(mounts))
	for d := range mounts {
		dests = append(dests, d)
	}
	sort.Strings(dests)
	for _, d := range dests {
		flags = append(flags, "--tmpfs", d+":"+mounts[d])
	}
	return flags
}

// fullFlags assembles baseline flags (defensive flags plus mock environment)
// followed by the extra flags.
func fullFlags(extra ...string) []string {
	flags := append([]string(nil), defensiveFlags...)
	for _, e := range mockEnv {
		flags = append(flags, "-e", e)
	}
	return append(flags, extra...)
}

// candidate is one hypothesis: a name and the complete flag set it adds to the
// defensive profile.
type candidate struct {
	name  string
	flags []string
}

// ruleSpec says how the candidates of one rule turn into engine flags. A set of
// candidates is always an ordered list of element names, so singles, the union
// and every step of the minimization are built the same way.
type ruleSpec struct {
	// treatment are the flags of the rule's treatment.
	treatment []string
	// elements are the candidates in the order they are tried.
	elements []string
	// flagsFor returns the treatment flags plus the given set of elements.
	flagsFor func(set []string) []string
}

// specFor returns the candidate specification of a rule.
func specFor(rule string) (ruleSpec, error) {
	base, err := treatmentFlags(rule)
	if err != nil {
		return ruleSpec{}, err
	}
	switch rule {
	case RuleDropCaps:
		return ruleSpec{treatment: base, elements: capCandidates, flagsFor: func(set []string) []string {
			flags := append([]string(nil), base...)
			for _, c := range set {
				flags = append(flags, "--cap-add="+c)
			}
			return flags
		}}, nil
	case RuleReadOnly:
		return ruleSpec{treatment: base, elements: tmpfsCandidates, flagsFor: tmpfsWith}, nil
	}
	return ruleSpec{}, fmt.Errorf("rule %q cannot be attributed (supported: %s, %s)", rule, RuleReadOnly, RuleDropCaps)
}

// candidatesFor returns the single candidates and the union for a rule.
func candidatesFor(rule string) (singles []candidate, union candidate, err error) {
	spec, err := specFor(rule)
	if err != nil {
		return nil, candidate{}, err
	}
	for _, e := range spec.elements {
		singles = append(singles, candidate{name: e, flags: spec.flagsFor([]string{e})})
	}
	return singles, candidate{name: "union", flags: spec.flagsFor(spec.elements)}, nil
}

// tmpfsWith builds --read-only plus the base /tmp mount, extended by the
// candidate mounts.
func tmpfsWith(paths []string) []string {
	mounts := map[string]string{baseTmpfsMountPoint: baseTmpfsOptions}
	for _, p := range paths {
		mounts[p] = candidateTmpfsOptions
	}
	return mountFlags(mounts, true)
}

// varRunPath is the mount that is left out when the full union does not start.
const varRunPath = "/var/run"

// withoutVarRun returns the elements without /var/run. In almost all images
// /var/run is a symlink to /run, and two mounts on the same target can make
// the engine refuse to start the container.
func withoutVarRun(elements []string) []string {
	return without(elements, varRunPath)
}

// unionWithoutVarRun is the union minus /var/run. It is tried only when the
// union fails to start.
func unionWithoutVarRun() candidate {
	return candidate{name: "union-without-/var/run", flags: tmpfsWith(withoutVarRun(tmpfsCandidates))}
}

// without returns the elements except the one named, in order.
func without(elements []string, drop string) []string {
	out := make([]string, 0, len(elements))
	for _, e := range elements {
		if e != drop {
			out = append(out, e)
		}
	}
	return out
}

// sortedCopy returns a sorted copy of the set.
func sortedCopy(set []string) []string {
	out := append([]string(nil), set...)
	sort.Strings(out)
	return out
}

// Progress receives the attribution after each image and rule. It is optional.
type Progress func(done []Attribution)

// Attribute runs the attribution for every target in order. A problem with one
// target is recorded in its status and the run continues.
func Attribute(ctx context.Context, r ContainerRunner, cfg Config, targets []Target, log *Logger, progress Progress) []Attribution {
	var out []Attribution
	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		log.Section("[%d/%d] %s  %s", i+1, len(targets), t.Image, t.Rule)
		a := attributeOne(ctx, r, cfg, t, log)
		out = append(out, a)
		switch a.Status {
		case StatusResolvedSingle, StatusResolvedMinimal, StatusResolvedUnion, StatusUnresolved:
			log.Ok("%s: %s%s", t.Rule, a.Status, resolvedSuffix(a))
		default:
			log.Warn("%s: %s %s", t.Rule, a.Status, a.Detail)
		}
		if progress != nil {
			progress(out)
		}
	}
	return out
}

func resolvedSuffix(a Attribution) string {
	switch {
	case a.Status == StatusResolvedMinimal && len(a.MinimalSet) > 0:
		return " by the minimal set " + strings.Join(a.MinimalSet, " + ")
	case len(a.ResolvedBy) > 0:
		return " by " + strings.Join(a.ResolvedBy, ", ")
	}
	return ""
}

// ensurePresent checks that the image is in the local store and pulls it when
// the configuration allows. It returns an empty status when the image can be
// used, else StatusImageAbsent or StatusError with a detail.
func ensurePresent(ctx context.Context, r ContainerRunner, cfg Config, image string, log *Logger) (status, detail string) {
	present, err := r.ImagePresent(ctx, image)
	if err == nil && !present && cfg.Pull {
		log.Info("pulling %s", image)
		if perr := r.Pull(ctx, image); perr != nil {
			return StatusImageAbsent, perr.Error()
		}
		present = true
	}
	switch {
	case err != nil:
		return StatusError, "checking the local store: " + err.Error()
	case !present:
		return StatusImageAbsent, "not in the local store of the engine (use -pull to fetch it)"
	}
	return "", ""
}

func attributeOne(ctx context.Context, r ContainerRunner, cfg Config, t Target, log *Logger) Attribution {
	a := Attribution{Image: t.Image, Rule: t.Rule}
	spec, err := specFor(t.Rule)
	if err != nil {
		a.Status, a.Detail = StatusError, err.Error()
		return a
	}
	treatment := spec.treatment

	if status, detail := ensurePresent(ctx, r, cfg, t.Image, log); status != "" {
		a.Status, a.Detail = status, detail
		return a
	}

	run := func(kind, name string, extra []string) (Attempt, bool) {
		flags := fullFlags(extra...)
		obs := r.Observe(ctx, RunSpec{Image: t.Image, Flags: flags, Window: cfg.Window})
		at := Attempt{Kind: kind, Candidate: name, Flags: flags, Obs: obs, Survived: obs.Survived()}
		if kind == KindMinimize {
			// The reduced set still keeps the container alive: the element
			// that was left out is not needed.
			at.Resolved = at.Survived
		}
		a.Attempts = append(a.Attempts, at)
		logAttempt(log, at)
		return at, obs.State != StateUnknown
	}

	// Baseline: defensive flags only. The treatment is interpretable only when
	// the baseline is running at the end of the window.
	base, usable := run(KindBaseline, "", nil)
	switch {
	case !usable:
		a.Status, a.Detail = StatusError, "baseline: "+base.Obs.Err
		return a
	case base.Obs.State == StateStartFailed:
		a.Status, a.Detail = StatusBaselineFailed, "baseline did not start"
		return a
	case !base.Survived && base.Obs.ExitCode != nil && *base.Obs.ExitCode == 0:
		a.Status, a.Detail = StatusNotObservable, "baseline exited 0 before the window ended"
		return a
	case !base.Survived:
		a.Status, a.Detail = StatusBaselineFailed, "baseline exited before the window ended"
		return a
	}

	// Treatment: the study failure must reproduce.
	treat, usable := run(KindTreatment, "", treatment)
	switch {
	case !usable:
		a.Status, a.Detail = StatusError, "treatment: "+treat.Obs.Err
		return a
	case treat.Survived:
		a.Status, a.Detail = StatusNotReproduced, "the treatment survived the window this time"
		return a
	}

	// Candidates one at a time, then the union.
	for _, e := range spec.elements {
		at, ok := run(KindSingle, e, spec.flagsFor([]string{e}))
		if !ok {
			a.Status, a.Detail = StatusError, e+": "+at.Obs.Err
			return a
		}
		if at.Survived {
			a.Attempts[len(a.Attempts)-1].Resolved = true
			a.ResolvedBy = append(a.ResolvedBy, e)
		}
	}
	unionSet := spec.elements
	uat, ok := run(KindUnion, "union", spec.flagsFor(unionSet))
	if !ok {
		a.Status, a.Detail = StatusError, "union: "+uat.Obs.Err
		return a
	}
	a.UnionResolves = uat.Survived
	if t.Rule == RuleReadOnly && uat.Obs.State == StateStartFailed {
		alt := unionWithoutVarRun()
		unionSet = withoutVarRun(spec.elements)
		uat, ok = run(KindUnion, alt.name, alt.flags)
		if !ok {
			a.Status, a.Detail = StatusError, "union: "+uat.Obs.Err
			return a
		}
		a.UnionResolves = uat.Survived
		a.Detail = "the full union did not start, the union without /var/run was tried"
	}
	if a.UnionResolves {
		a.Attempts[len(a.Attempts)-1].Resolved = true
	}

	switch {
	case len(a.ResolvedBy) > 0:
		// One candidate is enough. The empty set is the treatment alone, which
		// failed, so a set of one is minimal without further runs.
		a.Status = StatusResolvedSingle
		a.MinimalSet, a.MinimalMethod = []string{a.ResolvedBy[0]}, MethodSingle
	case a.UnionResolves && cfg.Minimize:
		set, note := minimize(run, spec, unionSet, log)
		if note != "" {
			// The minimization stopped early. The union result stands, the set
			// is not claimed to be minimal.
			a.Status = StatusResolvedUnion
			a.Detail = joinNotes(a.Detail, note)
			break
		}
		a.Status = StatusResolvedMinimal
		a.MinimalSet, a.MinimalMethod = sortedCopy(set), MethodMinimization
	case a.UnionResolves:
		a.Status = StatusResolvedUnion
	default:
		a.Status = StatusUnresolved
	}
	return a
}

// runFunc starts one container for an attempt and records it on the
// attribution. The boolean is false when the engine state was unreadable.
type runFunc func(kind, name string, extra []string) (Attempt, bool)

// minimize shrinks a set that keeps the container alive. It tries the set
// without one element at a time, in the order of the set, and drops the element
// when the container still survives the window. One pass is enough for a set
// that no element can leave: an element that was needed in a larger set is
// needed in every smaller set too, provided that adding a candidate never
// makes a surviving container die. The set that is left was observed
// surviving in the run that produced it, either in the last removal that
// worked or, when nothing could be removed, in the union run.
//
// The empty set is the treatment alone, which failed before, so the last
// element is never tested. The note is not empty when an engine problem
// stopped the minimization, in which case the returned set is not minimal.
func minimize(run runFunc, spec ruleSpec, start []string, log *Logger) (set []string, note string) {
	set = append([]string(nil), start...)
	for _, e := range start {
		if len(set) <= 1 {
			break
		}
		trial := without(set, e)
		at, ok := run(KindMinimize, e, spec.flagsFor(trial))
		if !ok {
			return set, "minimization stopped without " + e + ": " + at.Obs.Err
		}
		if at.Survived {
			set = trial
		}
	}
	log.Info("%-34s %s", "minimal set", strings.Join(sortedCopy(set), " + "))
	return set, ""
}

// joinNotes joins two detail texts with a semicolon.
func joinNotes(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func logAttempt(log *Logger, at Attempt) {
	label := at.Kind
	if at.Candidate != "" {
		label += " " + at.Candidate
	}
	if at.Kind == KindMinimize {
		label = "minimize without " + at.Candidate
	}
	detail := at.Obs.State
	if at.Obs.ExitCode != nil {
		detail += fmt.Sprintf(" (exit %d)", *at.Obs.ExitCode)
	}
	if at.Survived {
		detail += ", survives the window"
	}
	log.Info("%-34s %s", label, detail)
}
