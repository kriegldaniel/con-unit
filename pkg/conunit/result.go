package conunit

import (
	"context"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// Container represents an OCI image under test with full assertion tracking.
// RequestedRef is the image reference exactly as it was requested (SPEC-13). It
// is empty when the image came from a local archive, which has no reference.
type Container struct {
	Context               context.Context
	Image                 string
	RequestedRef          string
	ImmutableImageRef     string
	ImageDigest           string
	ConfigDigest          string
	Platform              string
	SignatureVerification *SignatureVerificationConfig
	Inspect               *engine.ImageInspect
	Engine                *engine.Engine
	OCIIndex              *oci.FilesystemIndex
	// ProbeWindow is the Tier 3 observation window W. Zero selects the
	// default of 3 seconds. Tier 3 latency is bounded below by W by design
	// and must not be presented as a performance result.
	ProbeWindow time.Duration
	// Baseline is shared by all containers that stand for the same image so
	// the baseline run happens once per image. When nil, the container uses
	// a private baseline.
	Baseline *BaselineCache
	// SBOM caches the Syft package inventory of the image so that SUP-01 and
	// SUP-03 run Syft once. When nil, the container uses a private cache.
	SBOM *SBOMCache

	Results           []spec.TestResult
	Failures          []spec.TestResult
	UnverifiedResults []spec.TestResult
}

// ResultDetail carries the optional machine-readable parts of a result:
// the reason that qualifies it, a non-authoritative hint, and the evidence
// behind the outcome.
type ResultDetail struct {
	Reason   spec.Reason
	Hint     string
	Evidence *spec.Evidence
}

func (c *Container) newResult(id, name string, tier spec.Tier, outcome spec.Outcome, d time.Duration, msg string, detail ResultDetail) spec.TestResult {
	return spec.TestResult{
		TestID:       id,
		TestName:     canonicalRuleName(id, name),
		Tier:         tier,
		Outcome:      outcome,
		Passed:       outcome == spec.OutcomePass,
		ImageDigest:  c.ImageDigest,
		ConfigDigest: c.ConfigDigest,
		Platform:     c.Platform,
		Duration:     d,
		Message:      msg,
		RuleType:     id,
		Reason:       detail.Reason,
		Hint:         detail.Hint,
		Evidence:     detail.Evidence,
		Rule:         ruleMetaFor(id),
	}
}

// RecordPass registers a successful assertion
func (c *Container) RecordPass(id, name string, tier spec.Tier, d time.Duration, msg string) {
	c.RecordPassDetail(id, name, tier, d, msg, ResultDetail{})
}

// RecordPassDetail registers a successful assertion with evidence.
func (c *Container) RecordPassDetail(id, name string, tier spec.Tier, d time.Duration, msg string, detail ResultDetail) {
	c.Results = append(c.Results, c.newResult(id, name, tier, spec.OutcomePass, d, msg, detail))
}

// RecordFailure registers a failed assertion (Soft Assertion: does not abort execution)
func (c *Container) RecordFailure(id, name string, tier spec.Tier, d time.Duration, msg, explanation, remediation, reference string) {
	c.RecordFailureDetail(id, name, tier, d, msg, explanation, remediation, reference, ResultDetail{})
}

// RecordFailureDetail registers a failed assertion with reason, hint and evidence.
func (c *Container) RecordFailureDetail(id, name string, tier spec.Tier, d time.Duration, msg, explanation, remediation, reference string, detail ResultDetail) {
	r := c.newResult(id, name, tier, spec.OutcomeFail, d, msg, detail)
	r.Explanation = explanation
	r.Remediation = remediation
	r.Reference = reference
	c.Results = append(c.Results, r)
	c.Failures = append(c.Failures, r)
}

// RecordUnverified registers an assertion whose required evidence is absent,
// incomplete, ambiguous, or unsupported. It remains non-passing for legacy
// callers while retaining a distinct outcome for reports and CI summaries.
func (c *Container) RecordUnverified(id, name string, tier spec.Tier, d time.Duration, msg, remediation, reference string) {
	c.RecordUnverifiedDetail(id, name, tier, d, msg, remediation, reference, ResultDetail{})
}

// RecordUnverifiedDetail registers an unverified assertion with reason and evidence.
func (c *Container) RecordUnverifiedDetail(id, name string, tier spec.Tier, d time.Duration, msg, remediation, reference string, detail ResultDetail) {
	r := c.newResult(id, name, tier, spec.OutcomeUnverified, d, msg, detail)
	r.Remediation = remediation
	r.Reference = reference
	c.Results = append(c.Results, r)
	c.Failures = append(c.Failures, r)
	c.UnverifiedResults = append(c.UnverifiedResults, r)
}

func (c *Container) recordMissingInspect(id, name string, tier spec.Tier, start time.Time) {
	c.RecordUnverifiedDetail(id, name, tier, time.Since(start), "Image inspection data is unavailable; assertion is unverified", "Ensure the image can be inspected before running this assertion", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
}

func (c *Container) recordMissingOCIIndex(id, name string, tier spec.Tier, start time.Time) {
	c.RecordUnverifiedDetail(id, name, tier, time.Since(start), "OCI filesystem index is unavailable; assertion is unverified", "Resolve and index the image successfully before running this assertion", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
}

func (c *Container) context() context.Context {
	if c.Context == nil {
		return context.Background()
	}
	return c.Context
}
