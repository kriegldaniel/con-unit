package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// The ablation answers one question: how many images would a tool without a
// baseline gate have blamed on a treatment? ConUnit gates every Tier 3
// treatment on a baseline run. When the baseline does not stay running for the
// window (BASELINE_FAILED) or exits 0 early (NOT_OBSERVABLE) the treatments are
// UNVERIFIED. A single-run tool has no baseline. It starts the container with
// the treatment, observes it for the window and calls FAIL when the container
// is not running at the end of it. For the images that ConUnit marked
// UNVERIFIED, this experiment runs the four treatments of the hardening profile
// exactly like that and counts how many a single-run tool would have called
// FAIL. Those verdicts blame the treatment for a container that did not stay
// running without it either, so the count is the number of misblamed images.

// ablationTreatment is one treatment of the hardening profile.
type ablationTreatment struct {
	Rule  string   `json:"rule"`
	Name  string   `json:"name"`
	Flags []string `json:"flags"`
}

// ablationTreatments returns the four treatments of the ablation in the order
// of docs/INTERFACE_V2.md section 6: read-only root filesystem with the base
// tmpfs, all capabilities dropped, no-new-privileges and a memory limit of 256
// MiB. Their flags are those of pkg/engine, pinned by a test.
func ablationTreatments() []ablationTreatment {
	readOnly, _ := treatmentFlags(RuleReadOnly)
	dropCaps, _ := treatmentFlags(RuleDropCaps)
	return []ablationTreatment{
		{Rule: RuleReadOnly, Name: "read-only root filesystem with a 64 MiB tmpfs at /tmp", Flags: readOnly},
		{Rule: RuleDropCaps, Name: "all capabilities dropped", Flags: dropCaps},
		{Rule: RuleNoNewPrivileges, Name: "no-new-privileges", Flags: []string{noNewPrivilegesFlag}},
		{Rule: RuleMemoryLimit, Name: "memory limit of 256 MiB", Flags: []string{memoryLimitFlag}},
	}
}

// Rules that only the ablation runs, because they have no candidate to add
// back and so no attribution.
const (
	RuleNoNewPrivileges = "EXEC-04"
	RuleMemoryLimit     = "EXEC-07"
)

// Single-run verdicts of one treatment run.
const (
	SingleRunPass       = "PASS"       // the container was running at the end of the window
	SingleRunFail       = "FAIL"       // it was not: a tool without a baseline would report a failure
	SingleRunUnreadable = "UNREADABLE" // the engine state could not be read, no verdict
)

// Statuses of an image in the ablation.
const (
	AblationOK     = "OK"           // all four treatments were observed
	AblationAbsent = "IMAGE_ABSENT" // the image is not in the local store
	AblationError  = "ERROR"        // the engine failed, the image counts as not examined
)

// AblationTarget is an image that the study marked UNVERIFIED in Tier 3
// because of its baseline.
type AblationTarget struct {
	Image string
	// Reasons are the study reasons found on its Tier 3 results, sorted:
	// BASELINE_FAILED or NOT_OBSERVABLE.
	Reasons []string
	// Rules are the Tier 3 checks of the study that carry such a reason.
	Rules []string
	// BaselineState and BaselineExitCode are what the study recorded for the
	// baseline of the first such result.
	BaselineState    string
	BaselineExitCode *int
}

// ablationReason reports whether the reason makes an image a target.
func ablationReason(r spec.Reason) bool {
	return r == spec.ReasonBaselineFailed || r == spec.ReasonNotObservable
}

// isTierThree reports whether a result belongs to Tier 3. The ID decides for
// results of older studies that carry no tier.
func isTierThree(r spec.TestResult) bool {
	return r.Tier == spec.TierContract || strings.HasPrefix(r.TestID, "EXEC-")
}

// SelectAblationTargets returns the COMPLETED images of the study with at least
// one Tier 3 result that is UNVERIFIED with the reason BASELINE_FAILED or
// NOT_OBSERVABLE, in study order. only restricts the selection to the listed
// references when it is not empty.
func SelectAblationTargets(images []*spec.SuiteResult, only map[string]bool) []AblationTarget {
	var out []AblationTarget
	for _, img := range images {
		if img == nil || (img.Status != "" && img.Status != spec.StatusCompleted) {
			continue
		}
		ref := img.RequestedRef
		if ref == "" {
			ref = img.ImageName
		}
		if ref == "" || (len(only) > 0 && !only[ref] && !only[img.ImageName]) {
			continue
		}
		t := AblationTarget{Image: ref}
		reasons := map[string]bool{}
		for _, r := range img.Results {
			if !isTierThree(r) || r.EffectiveOutcome() != spec.OutcomeUnverified || !ablationReason(r.Reason) {
				continue
			}
			reasons[string(r.Reason)] = true
			t.Rules = append(t.Rules, r.TestID)
			if t.BaselineState == "" && r.Evidence != nil {
				t.BaselineState = r.Evidence.BaselineState
				if r.Evidence.BaselineExitCode != nil {
					code := *r.Evidence.BaselineExitCode
					t.BaselineExitCode = &code
				}
			}
		}
		if len(t.Rules) == 0 {
			continue
		}
		for reason := range reasons {
			t.Reasons = append(t.Reasons, reason)
		}
		sort.Strings(t.Reasons)
		sort.Strings(t.Rules)
		out = append(out, t)
	}
	return out
}

// AblationRun is one treatment run of one image.
type AblationRun struct {
	Rule      string      `json:"rule"`
	Treatment string      `json:"treatment"`
	Flags     []string    `json:"flags"`
	Obs       Observation `json:"observation"`
	// SingleRun is the verdict of a tool without a baseline gate.
	SingleRun string `json:"single_run_verdict"`
}

// AblationImage is the outcome for one image.
type AblationImage struct {
	Image string `json:"image"`
	// StudyReasons, StudyRules, StudyBaselineState and StudyBaselineExitCode
	// repeat what the study recorded, so the file shows why the image is here.
	StudyReasons          []string `json:"study_reasons"`
	StudyRules            []string `json:"study_rules"`
	StudyBaselineState    string   `json:"study_baseline_state,omitempty"`
	StudyBaselineExitCode *int     `json:"study_baseline_exit_code,omitempty"`

	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Runs holds one entry per treatment that was observed.
	Runs []AblationRun `json:"runs"`
	// SingleRunFails counts the treatments that a single-run tool would have
	// called FAIL. Misblamed is true when it is at least one.
	SingleRunFails int  `json:"single_run_fails"`
	Misblamed      bool `json:"misblamed"`
}

// primaryReason names the reason under which the image is counted. A baseline
// is shared by all Tier 3 checks of an image, so one reason is the rule.
func (a AblationImage) primaryReason() string {
	if len(a.StudyReasons) == 0 {
		return ""
	}
	return a.StudyReasons[0]
}

// RunAblation runs the ablation for every target in order. A problem with one
// image is recorded in its status and the run continues.
func RunAblation(ctx context.Context, r ContainerRunner, cfg Config, targets []AblationTarget, log *Logger, progress func([]AblationImage)) []AblationImage {
	var out []AblationImage
	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		log.Section("[%d/%d] %s  (study: %s)", i+1, len(targets), t.Image, strings.Join(t.Reasons, ", "))
		img := ablateOne(ctx, r, cfg, t, log)
		out = append(out, img)
		switch img.Status {
		case AblationOK:
			log.Ok("%d of %d treatments would be called FAIL by a single-run tool", img.SingleRunFails, len(img.Runs))
		default:
			log.Warn("%s %s", img.Status, img.Detail)
		}
		if progress != nil {
			progress(out)
		}
	}
	return out
}

func ablateOne(ctx context.Context, r ContainerRunner, cfg Config, t AblationTarget, log *Logger) AblationImage {
	img := AblationImage{
		Image: t.Image, StudyReasons: t.Reasons, StudyRules: t.Rules,
		StudyBaselineState: t.BaselineState, StudyBaselineExitCode: t.BaselineExitCode, Runs: []AblationRun{},
	}
	if status, detail := ensurePresent(ctx, r, cfg, t.Image, log); status != "" {
		img.Status, img.Detail = status, detail
		if status == StatusError {
			img.Status = AblationError
		}
		if status == StatusImageAbsent {
			img.Status = AblationAbsent
		}
		return img
	}
	for _, tr := range ablationTreatments() {
		// No baseline run and no gate: the treatment runs on its own, with the
		// defensive flags and the mock environment of the study profile.
		flags := fullFlags(tr.Flags...)
		obs := r.Observe(ctx, RunSpec{Image: t.Image, Flags: flags, Window: cfg.Window})
		run := AblationRun{Rule: tr.Rule, Treatment: tr.Name, Flags: flags, Obs: obs, SingleRun: singleRunVerdict(obs)}
		logAblationRun(log, run)
		if run.SingleRun == SingleRunUnreadable {
			img.Status, img.Detail = AblationError, tr.Rule+": "+obs.Err
			img.Runs = append(img.Runs, run)
			return img
		}
		img.Runs = append(img.Runs, run)
		if run.SingleRun == SingleRunFail {
			img.SingleRunFails++
		}
	}
	img.Status = AblationOK
	img.Misblamed = img.SingleRunFails > 0
	return img
}

// singleRunVerdict is the verdict of a tool that runs the treatment once and
// observes the container for the window: running at the end is a PASS, anything
// else (exited, never started) is a FAIL.
func singleRunVerdict(o Observation) string {
	switch o.State {
	case StateRunning:
		return SingleRunPass
	case StateUnknown:
		return SingleRunUnreadable
	}
	return SingleRunFail
}

func logAblationRun(log *Logger, run AblationRun) {
	detail := run.Obs.State
	if run.Obs.ExitCode != nil {
		detail += fmt.Sprintf(" (exit %d)", *run.Obs.ExitCode)
	}
	log.Info("%-9s %-52s %-8s %s", run.Rule, run.Treatment, run.SingleRun, detail)
}

// AblationReasonSummary counts the images of one study reason.
type AblationReasonSummary struct {
	Examined  int `json:"examined"`
	Misblamed int `json:"misblamed"`
}

// AblationTreatmentSummary counts the runs of one treatment.
type AblationTreatmentSummary struct {
	Runs int `json:"runs"`
	Fail int `json:"single_run_fail"`
	Pass int `json:"single_run_pass"`
}

// AblationSummary aggregates the ablation. An image is examined when all four
// treatments were observed. It is misblamed when a single-run tool would have
// called FAIL for at least one of them.
type AblationSummary struct {
	ImagesSelected  int                                 `json:"images_selected"`
	ImagesExamined  int                                 `json:"images_examined"`
	ImagesMisblamed int                                 `json:"images_misblamed"`
	ImagesAbsent    int                                 `json:"images_absent"`
	ImagesError     int                                 `json:"images_error"`
	PairsExamined   int                                 `json:"pairs_examined"`
	PairsFail       int                                 `json:"pairs_single_run_fail"`
	ByStudyReason   map[string]AblationReasonSummary    `json:"by_study_reason"`
	ByTreatment     map[string]AblationTreatmentSummary `json:"by_treatment"`
}

// SummarizeAblation counts the ablation results. selected is the number of
// images that the study selected, which exceeds the length of images when the
// run stopped early.
func SummarizeAblation(images []AblationImage, selected int) AblationSummary {
	s := AblationSummary{ImagesSelected: selected, ByStudyReason: map[string]AblationReasonSummary{}, ByTreatment: map[string]AblationTreatmentSummary{}}
	for _, img := range images {
		switch img.Status {
		case AblationAbsent:
			s.ImagesAbsent++
			continue
		case AblationOK:
		default:
			s.ImagesError++
			continue
		}
		s.ImagesExamined++
		rs := s.ByStudyReason[img.primaryReason()]
		rs.Examined++
		if img.Misblamed {
			s.ImagesMisblamed++
			rs.Misblamed++
		}
		s.ByStudyReason[img.primaryReason()] = rs
		for _, run := range img.Runs {
			s.PairsExamined++
			ts := s.ByTreatment[run.Rule]
			ts.Runs++
			if run.SingleRun == SingleRunFail {
				s.PairsFail++
				ts.Fail++
			} else {
				ts.Pass++
			}
			s.ByTreatment[run.Rule] = ts
		}
	}
	return s
}

// AblationProtocol records the profile of the ablation so that it can be
// reproduced and so that the file explains itself.
type AblationProtocol struct {
	WindowMs       int64               `json:"window_ms"`
	DefensiveFlags []string            `json:"defensive_flags"`
	MockEnv        []string            `json:"mock_env"`
	Treatments     []ablationTreatment `json:"treatments"`
	Selection      string              `json:"selection"`
	SingleRunRule  string              `json:"single_run_rule"`
	Unit           string              `json:"unit"`
}

// NewAblationProtocol describes the ablation for the given window.
func NewAblationProtocol(window time.Duration) AblationProtocol {
	return AblationProtocol{
		WindowMs:       window.Milliseconds(),
		DefensiveFlags: defensiveFlags,
		MockEnv:        mockEnv,
		Treatments:     ablationTreatments(),
		Selection:      "COMPLETED images of the study with at least one Tier 3 result that is UNVERIFIED with the reason BASELINE_FAILED or NOT_OBSERVABLE.",
		SingleRunRule:  "Each treatment runs on its own with the defensive flags and the mock environment of the study profile, with no baseline run and no gate. It is observed for the window W. A tool without a baseline would report FAIL when the container is not running at the end of W and PASS when it is.",
		Unit:           "Images are counted per image: examined images are those for which all four treatments were observed, misblamed images are those with at least one treatment that a single-run tool would call FAIL. Treatment runs are counted in pairs_examined and pairs_single_run_fail.",
	}
}

// AblationDocument is ablation.json.
type AblationDocument struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Complete      bool             `json:"complete"`
	Source        Source           `json:"source"`
	Run           spec.RunMetadata `json:"run"`
	Protocol      AblationProtocol `json:"protocol"`
	Summary       AblationSummary  `json:"summary"`
	Images        []AblationImage  `json:"images"`
}

// ablationSchemaVersion is the schema_version of ablation.json.
const ablationSchemaVersion = "1"

// Output file name of the ablation (docs/INTERFACE_V2.md section 6).
const ablationJSON = "ablation.json"
