package conunit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

// Tier 3 semantics (docs/CONTRACT.md section 6, docs/ANALYSIS_PLAN.md section 5).
//
// For every image one baseline container runs with only the defensive flags
// (--network=none, --pids-limit=256) and the fixed mock environment, and is
// observed for the window W. Every treatment runs with the same flags plus its
// own treatment flag and is judged against that baseline:
//
//   - baseline did not start or exited non-zero: UNVERIFIED, BASELINE_FAILED
//   - baseline exited 0 before W: UNVERIFIED, NOT_OBSERVABLE
//   - baseline running at W: the treatment PASSES when it is also running at
//     W and FAILS otherwise, with states, exit codes and a log tail as evidence
//
// A FAIL means "did not survive the window under the profile although the
// baseline did". It is not a defect claim and not a root-cause claim. The
// image's own entrypoint always runs; contract probes never override it.

// BaselineCache holds the Tier 3 baseline observation of one image so that
// every treatment of that image reuses a single baseline run. The result,
// including a failure to observe, is computed once.
type BaselineCache struct {
	mu   sync.Mutex
	done bool
	obs  *engine.Observation
	err  error
	runs int
}

// Runs returns how many baseline containers were started.
func (b *BaselineCache) Runs() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.runs
}

func (b *BaselineCache) observe(ctx context.Context, eng *engine.Engine, image string, window time.Duration) (*engine.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.done {
		b.runs++
		b.obs, b.err = eng.ObserveContainer(ctx, image, nil, window)
		b.done = true
	}
	return b.obs, b.err
}

func (c *Container) baselineCache() *BaselineCache {
	if c.Baseline == nil {
		c.Baseline = &BaselineCache{}
	}
	return c.Baseline
}

func (c *Container) probeWindow() time.Duration {
	if c.ProbeWindow > 0 {
		return c.ProbeWindow
	}
	return engine.DefaultProbeWindow
}

// ContractAssertions are the Tier 3 runtime compatibility checks.
type ContractAssertions struct {
	c *Container
}

// treatmentCheck describes one baseline-controlled treatment.
type treatmentCheck struct {
	id          string
	name        string
	flags       []string
	description string // phrase used in messages, for example "a read-only root filesystem"
	remediation string
	reference   string
	hint        func(obs *engine.Observation) string
}

const failExplanation = "FAIL records that the container was not running at the end of the observation window although the baseline run (same defensive flags and mock environment, without the treatment) was. It describes behavior under this profile only; it is not a defect claim and not a root cause."

func exitCodeText(code *int) string {
	if code == nil {
		return "no exit code"
	}
	return fmt.Sprintf("exit code %d", *code)
}

func stateText(obs *engine.Observation) string {
	if obs == nil {
		return "no state"
	}
	if obs.ExitCode != nil {
		return fmt.Sprintf("%s, %s", obs.State, exitCodeText(obs.ExitCode))
	}
	return obs.State
}

func copyInt(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// tier3Evidence assembles the evidence of one check. Either observation may
// be nil, for example before the treatment ran.
func tier3Evidence(baseline, treatment *engine.Observation, window time.Duration) *spec.Evidence {
	evidence := &spec.Evidence{WindowMillis: window.Milliseconds()}
	if baseline != nil {
		evidence.BaselineState = baseline.State
		evidence.BaselineExitCode = copyInt(baseline.ExitCode)
		evidence.LogTail = baseline.LogTail
	}
	if treatment != nil {
		evidence.TreatmentState = treatment.State
		evidence.TreatmentExitCode = copyInt(treatment.ExitCode)
		if treatment.LogTail != "" {
			evidence.LogTail = treatment.LogTail
		}
	}
	return evidence
}

// probeErrorReason maps an engine boundary error to the Tier 3 reason.
func probeErrorReason(err error) spec.Reason {
	var timeout *engine.ProbeTimeoutError
	if errors.As(err, &timeout) {
		return spec.ReasonProbeTimeout
	}
	return spec.ReasonProbeError
}

func (c *Container) recordProbeUnverified(id, name string, start time.Time, reason spec.Reason, msg string, evidence *spec.Evidence) {
	c.RecordUnverifiedDetail(id, name, spec.TierContract, time.Since(start), msg,
		"Resolve the engine or image issue behind the baseline and rerun the runtime check", "",
		ResultDetail{Reason: reason, Evidence: evidence})
}

// recordUnverifiedProbe records the UNVERIFIED result of a probe that did not
// produce complete evidence (used by the HTTP check and by a missing engine).
func recordUnverifiedProbe(c *Container, id, name string, tier spec.Tier, start time.Time, probe *engine.ExecResult, err error) bool {
	if err == nil && probe != nil && probe.EvidenceComplete {
		return false
	}
	message := "Runtime contract probe did not produce complete evidence"
	if err != nil {
		message += fmt.Sprintf(": %v", err)
	} else if probe == nil {
		message += ": no probe result was returned"
	} else {
		detail := strings.TrimSpace(probe.Stderr + " " + probe.Stdout)
		if detail != "" {
			message += ": " + detail
		}
	}
	c.RecordUnverifiedDetail(id, name, tier, time.Since(start), message,
		"Resolve the engine or probe issue and rerun the runtime contract check", "",
		ResultDetail{Reason: spec.ReasonProbeError})
	return true
}

func probeExitCode(probe *engine.ExecResult) int {
	if probe == nil {
		return -1
	}
	return probe.ExitCode
}

// baselineVerdict interprets a baseline observation. It returns the reason
// and message of the UNVERIFIED result when the baseline cannot support a
// verdict, or an empty reason when the baseline was running at the window end.
func baselineVerdict(check string, baseline *engine.Observation, window time.Duration) (spec.Reason, string) {
	switch baseline.State {
	case engine.StateRunning:
		return spec.ReasonNone, ""
	case engine.StateExitedZero:
		return spec.ReasonNotObservable, fmt.Sprintf(
			"The baseline run (defensive flags only) exited with code 0 before the %s window ended, so the image has no long-running process to observe and the %s result cannot be interpreted",
			window, check)
	default:
		return spec.ReasonBaselineFailed, fmt.Sprintf(
			"The baseline run (defensive flags only) did not stay running for the %s window (%s), so the %s result cannot be interpreted",
			window, stateText(baseline), check)
	}
}

func (ca *ContractAssertions) runTreatment(check treatmentCheck) *ContractAssertions {
	c := ca.c
	start := time.Now()
	if c.Engine == nil {
		recordUnverifiedProbe(c, check.id, check.name, spec.TierContract, start, nil, errors.New("no container engine configured"))
		return ca
	}
	window := c.probeWindow()

	baseline, err := c.baselineCache().observe(c.context(), c.Engine, c.Image, window)
	if err != nil {
		c.recordProbeUnverified(check.id, check.name, start, probeErrorReason(err),
			fmt.Sprintf("The baseline run could not be observed: %v", err), tier3Evidence(nil, nil, window))
		return ca
	}
	if reason, message := baselineVerdict(check.id, baseline, window); reason != spec.ReasonNone {
		c.recordProbeUnverified(check.id, check.name, start, reason, message, tier3Evidence(baseline, nil, window))
		return ca
	}

	treatment, err := c.Engine.ObserveContainer(c.context(), c.Image, check.flags, window)
	if err != nil {
		c.recordProbeUnverified(check.id, check.name, start, probeErrorReason(err),
			fmt.Sprintf("The run with %s could not be observed: %v", check.description, err), tier3Evidence(baseline, nil, window))
		return ca
	}
	evidence := tier3Evidence(baseline, treatment, window)

	if treatment.State == engine.StateRunning {
		c.RecordPassDetail(check.id, check.name, spec.TierContract, time.Since(start),
			fmt.Sprintf("The container was still running at the end of the %s window with %s, as in the baseline", window, check.description),
			ResultDetail{Evidence: evidence})
		return ca
	}

	hint := ""
	if check.hint != nil {
		hint = check.hint(treatment)
	}
	c.RecordFailureDetail(check.id, check.name, spec.TierContract, time.Since(start),
		fmt.Sprintf("The container was not running at the end of the %s window with %s (%s) although the baseline run was running",
			window, check.description, stateText(treatment)),
		failExplanation, check.remediation, check.reference,
		ResultDetail{Hint: hint, Evidence: evidence})
	return ca
}

// keywordHint builds a non-authoritative hint from the log tail and exit
// code. A hint is a keyword match, never a diagnosis, and no statistic may
// use it.
func keywordHint(parts ...string) string {
	var kept []string
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	return "Keyword match, not a diagnosis: " + strings.Join(kept, "; ")
}

func dropCapabilitiesHint(obs *engine.Observation) string {
	log := strings.ToLower(obs.LogTail)
	var parts []string
	if containsAny(log, "su-exec", "gosu", "setpriv", "setgroups", "failed switching to") {
		parts = append(parts, "the log mentions a runtime privilege-dropping tool (gosu, su-exec, setpriv), which needs CAP_SETUID and CAP_SETGID")
	}
	if containsAny(log, "chown", "chmod") {
		parts = append(parts, "the log mentions chown or chmod, which need CAP_CHOWN or CAP_FOWNER")
	}
	if containsAny(log, "bind: permission denied", "could not bind to address") {
		parts = append(parts, "the log mentions a bind failure, which on ports below 1024 needs CAP_NET_BIND_SERVICE")
	}
	return keywordHint(parts...)
}

func readOnlyHint(obs *engine.Observation) string {
	if containsAny(strings.ToLower(obs.LogTail), "read-only file system", "read only file system") {
		return keywordHint("the log mentions a read-only file system error, so the image may write below a path that is not a tmpfs")
	}
	return ""
}

func memoryHint(obs *engine.Observation) string {
	if obs.ExitCode != nil && *obs.ExitCode == 137 {
		return keywordHint("exit code 137 is the usual signature of the out-of-memory killer or of SIGKILL")
	}
	return ""
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func (ca *ContractAssertions) ReadOnlyRootfsCompatible() *ContractAssertions {
	return ca.runTreatment(treatmentCheck{
		id:          "EXEC-01",
		name:        "Read-Only Root Filesystem Conformance",
		flags:       engine.ReadOnlyRootfsFlags(),
		description: "a read-only root filesystem (64 MiB writable tmpfs at /tmp)",
		remediation: "Ensure the application writes solely to ephemeral mounted tmpfs volumes (for example /tmp)",
		reference:   "https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
		hint:        readOnlyHint,
	})
}

func (ca *ContractAssertions) DropAllCapabilitiesCompatible() *ContractAssertions {
	return ca.runTreatment(treatmentCheck{
		id:          "EXEC-02",
		name:        "Dropped Linux Capabilities Conformance",
		flags:       engine.DropAllCapabilitiesFlags(),
		description: "all Linux capabilities dropped (--cap-drop=ALL)",
		remediation: "Remove the need for root capabilities, for example binding ports below 1024 or switching users at runtime",
		reference:   "https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
		hint:        dropCapabilitiesHint,
	})
}

func (ca *ContractAssertions) ComplyWithNoNewPrivileges() *ContractAssertions {
	return ca.runTreatment(treatmentCheck{
		id:          "EXEC-04",
		name:        "No-New-Privileges Kernel Contract",
		flags:       engine.NoNewPrivilegesFlags(),
		description: "no-new-privileges enabled",
		remediation: "Ensure the container application does not rely on setuid or setgid privilege escalation",
		reference:   "https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
	})
}

func (ca *ContractAssertions) ComplyWithArbitraryNonRootUID(uid int) *ContractAssertions {
	if uid <= 0 {
		uid = 10001
	}
	return ca.runTreatment(treatmentCheck{
		id:          "EXEC-05",
		name:        "Arbitrary Non-Root UID Conformance",
		flags:       engine.UserFlags(uid),
		description: fmt.Sprintf("a forced arbitrary UID %d", uid),
		remediation: "Give application directories group 0 ownership with group read and write permissions (chmod -R g=u)",
		reference:   "https://docs.openshift.com/container-platform/latest/authentication/managing-security-context-constraints.html",
	})
}

// ComplyWithResourceLimits applies the memory limit as the treatment. A pids
// value above zero also overrides the defensive PID limit of the baseline;
// the hardening profile passes zero so the treatment differs by memory only.
func (ca *ContractAssertions) ComplyWithResourceLimits(memoryLimit string, pidsLimit int) *ContractAssertions {
	if memoryLimit == "" {
		memoryLimit = "256m"
	}
	description := fmt.Sprintf("a memory limit of %s", memoryLimit)
	if pidsLimit > 0 {
		description += fmt.Sprintf(" and a PID limit of %d", pidsLimit)
	}
	return ca.runTreatment(treatmentCheck{
		id:          "EXEC-07",
		name:        "Resource Constraint Conformance",
		flags:       engine.MemoryLimitFlags(memoryLimit, pidsLimit),
		description: description,
		remediation: "Tune heap settings (for example -Xmx) and set explicit container memory limits that the application respects",
		reference:   "https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated; the PID limit is part of the baseline profile)",
		hint:        memoryHint,
	})
}

func (ca *ContractAssertions) ComplyWithKubernetesPSS() *ContractAssertions {
	return ca.runTreatment(treatmentCheck{
		id:          "EXEC-08",
		name:        "Kubernetes PSS Restricted Profile Conformance",
		flags:       engine.PSSRestrictedFlags(),
		description: "the Pod Security Standard Restricted settings (read-only root, no capabilities, no-new-privileges, UID 10001)",
		remediation: "Configure the image to run as an unprivileged UID with a read-only root filesystem and no capabilities",
		reference:   "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
		hint:        dropCapabilitiesHint,
	})
}

// HandlesSigtermGracefully sends SIGTERM to a container that was observed
// running at the end of the window and requires it to exit with code 0 or 143
// within the timeout. The check is gated by the same baseline as the other
// Tier 3 checks.
func (ca *ContractAssertions) HandlesSigtermGracefully(timeout time.Duration) *ContractAssertions {
	const (
		id   = "EXEC-03"
		name = "Graceful Signal Handling (SIGTERM)"
	)
	c := ca.c
	start := time.Now()
	if c.Engine == nil {
		recordUnverifiedProbe(c, id, name, spec.TierContract, start, nil, errors.New("no container engine configured"))
		return ca
	}
	timeoutSec := int(timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	timeout = time.Duration(timeoutSec) * time.Second
	window := c.probeWindow()

	baseline, err := c.baselineCache().observe(c.context(), c.Engine, c.Image, window)
	if err != nil {
		c.recordProbeUnverified(id, name, start, probeErrorReason(err), fmt.Sprintf("The baseline run could not be observed: %v", err), tier3Evidence(nil, nil, window))
		return ca
	}
	if reason, message := baselineVerdict(id, baseline, window); reason != spec.ReasonNone {
		c.recordProbeUnverified(id, name, start, reason, message, tier3Evidence(baseline, nil, window))
		return ca
	}

	obs, err := c.Engine.ObserveSigterm(c.context(), c.Image, window, timeout)
	if err != nil {
		c.recordProbeUnverified(id, name, start, probeErrorReason(err), fmt.Sprintf("The SIGTERM probe could not be observed: %v", err), tier3Evidence(baseline, nil, window))
		return ca
	}
	evidence := tier3Evidence(baseline, obs.Before, window)
	if obs.Before.State != engine.StateRunning {
		c.recordProbeUnverified(id, name, start, spec.ReasonNotObservable,
			fmt.Sprintf("The container was not running at the end of the %s window in the SIGTERM run (%s) although the baseline was, so SIGTERM could not be sent", window, stateText(obs.Before)), evidence)
		return ca
	}
	evidence.TreatmentExitCode = copyInt(obs.ExitCode)
	if obs.LogTail != "" {
		evidence.LogTail = obs.LogTail
	}
	if obs.Exited {
		evidence.TreatmentState = engine.StateExitedNonZero
		if obs.ExitCode != nil && *obs.ExitCode == 0 {
			evidence.TreatmentState = engine.StateExitedZero
		}
	}

	if obs.TerminatedBySigterm() {
		c.RecordPassDetail(id, name, spec.TierContract, time.Since(start),
			fmt.Sprintf("Terminated upon SIGTERM within the %ds timeout (%s, after %s)", timeoutSec, exitCodeText(obs.ExitCode), obs.Elapsed.Round(10*time.Millisecond)),
			ResultDetail{Evidence: evidence})
		return ca
	}
	message := fmt.Sprintf("The container remained running after SIGTERM beyond the %ds timeout", timeoutSec)
	if obs.Exited {
		message = fmt.Sprintf("The container exited with %s after SIGTERM; exit code 0 or 143 is required", exitCodeText(obs.ExitCode))
	}
	c.RecordFailureDetail(id, name, spec.TierContract, time.Since(start), message,
		"If PID 1 ignores SIGTERM, orchestrators must wait for the grace period and then send SIGKILL. FAIL describes this observation only; it is not a root cause.",
		"Ensure the application runs as PID 1 (use the exec form in ENTRYPOINT) and traps SIGTERM for a clean shutdown",
		"https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination",
		ResultDetail{Evidence: evidence})
	return ca
}

func (ca *ContractAssertions) ProbeHTTP(containerPort int, path string, expectedStatus int, timeout time.Duration) *ContractAssertions {
	const (
		id   = "EXEC-06"
		name = "HTTP Operational Readiness Contract"
	)
	c := ca.c
	start := time.Now()
	if c.Engine == nil {
		recordUnverifiedProbe(c, id, name, spec.TierContract, start, nil, errors.New("no container engine configured"))
		return ca
	}
	timeoutSec := int(timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	probe, err := c.Engine.TestHTTPContract(c.context(), c.Image, containerPort, path, expectedStatus, timeoutSec)
	if recordUnverifiedProbe(c, id, name, spec.TierContract, start, probe, err) {
		return ca
	}
	if probe.ExitCode != 0 {
		c.RecordFailure(id, name, spec.TierContract, time.Since(start),
			fmt.Sprintf("HTTP operational readiness contract failed on port %d: %s", containerPort, probe.Stdout),
			"A containerized HTTP service must bind to 0.0.0.0 and respond to health probes within the deadline.",
			"Verify that the entrypoint process starts the HTTP server and binds to 0.0.0.0",
			"https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/")
		return ca
	}
	c.RecordPass(id, name, spec.TierContract, time.Since(start), probe.Stdout)
	return ca
}
