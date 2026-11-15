package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Verdicts of a seeded case. The first three count in the accuracy
// denominator. NOT_MANIFESTED is reported and excluded from it. INCOMPLETE is
// not an attribution result at all: the image was absent or the engine failed,
// so the run is incomplete and the case is in no count.
const (
	VerdictExact         = "EXACT"          // the minimal set equals the expected one
	VerdictSuperset      = "SUPERSET"       // the minimal set holds every expected element and more
	VerdictWrong         = "WRONG"          // anything else, including no minimal set at all
	VerdictNotManifested = "NOT_MANIFESTED" // the truth file says the defect does not manifest on this engine
	VerdictIncomplete    = "INCOMPLETE"     // infrastructure failure, no verdict
)

// truthSchemaVersion is the schema_version of tier3_truth.json that this tool
// reads (docs/INTERFACE_V2.md section 4).
const truthSchemaVersion = 1

// seededTag is the tag of every seeded image: <image_prefix>/<case>:rq1.
const seededTag = "rq1"

// TruthCase is one seeded defect with the cause the seeding intends.
type TruthCase struct {
	Case string `json:"case"`
	Rule string `json:"rule"`
	// ExpectedMinimal is the minimal set of capabilities or mounts that makes
	// the seeded image survive the treatment.
	ExpectedMinimal []string `json:"expected_minimal"`
	// Manifests is false when running the case on the real engine showed that
	// the defect does not manifest there, for example because the engine lowers
	// ip_unprivileged_port_start. Such a case is reported and not scored.
	Manifests bool   `json:"manifests"`
	Note      string `json:"note,omitempty"`
}

// UnmarshalJSON reads a case. The manifests field is required: a missing or
// misspelled key would otherwise read as false and drop the case silently from
// the accuracy denominator. Other fields that the corpus authors add are
// ignored.
func (c *TruthCase) UnmarshalJSON(data []byte) error {
	var raw struct {
		Case            string   `json:"case"`
		Rule            string   `json:"rule"`
		ExpectedMinimal []string `json:"expected_minimal"`
		Manifests       *bool    `json:"manifests"`
		Note            string   `json:"note"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Manifests == nil {
		return fmt.Errorf("case %q has no manifests field", raw.Case)
	}
	*c = TruthCase{Case: raw.Case, Rule: raw.Rule, ExpectedMinimal: raw.ExpectedMinimal, Manifests: *raw.Manifests, Note: raw.Note}
	return nil
}

// TruthFile is fixtures/rq1/tier3_truth.json.
type TruthFile struct {
	SchemaVersion int         `json:"schema_version"`
	ImagePrefix   string      `json:"image_prefix"`
	Cases         []TruthCase `json:"cases"`

	// Path and SHA256 identify the file that was read. They are not part of it.
	Path   string `json:"-"`
	SHA256 string `json:"-"`
}

// LoadTruth reads and validates a truth file.
func LoadTruth(path string) (*TruthFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading truth file: %w", err)
	}
	return ParseTruth(data, path)
}

// ParseTruth validates the content of a truth file.
func ParseTruth(data []byte, path string) (*TruthFile, error) {
	var t TruthFile
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing truth file %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	t.Path, t.SHA256 = path, hex.EncodeToString(sum[:])
	if t.SchemaVersion != truthSchemaVersion {
		return nil, fmt.Errorf("truth file %s: schema_version %d, this tool reads %d", path, t.SchemaVersion, truthSchemaVersion)
	}
	if len(t.Cases) == 0 {
		return nil, fmt.Errorf("truth file %s has no cases", path)
	}
	seen := map[string]bool{}
	for i, c := range t.Cases {
		where := fmt.Sprintf("truth file %s, case %d", path, i+1)
		switch {
		case strings.TrimSpace(c.Case) == "" || strings.ContainsAny(c.Case, "/:@ \t"):
			return nil, fmt.Errorf("%s: %q is not a usable case name", where, c.Case)
		case seen[c.Case]:
			return nil, fmt.Errorf("%s: case %q appears twice", where, c.Case)
		}
		seen[c.Case] = true
		if _, err := treatmentFlags(c.Rule); err != nil {
			return nil, fmt.Errorf("%s (%s): %w", where, c.Case, err)
		}
		if c.Manifests && len(c.ExpectedMinimal) == 0 {
			return nil, fmt.Errorf("%s (%s): a case that manifests needs a non-empty expected_minimal", where, c.Case)
		}
		if dup := firstDuplicate(c.ExpectedMinimal); dup != "" {
			return nil, fmt.Errorf("%s (%s): expected_minimal lists %q twice", where, c.Case, dup)
		}
	}
	return &t, nil
}

func firstDuplicate(set []string) string {
	seen := map[string]bool{}
	for _, e := range set {
		if seen[e] {
			return e
		}
		seen[e] = true
	}
	return ""
}

// ImageFor returns the image of a case: <prefix>/<case>:rq1. A non-empty
// prefix overrides the one in the file.
func (t *TruthFile) ImageFor(prefix string, c TruthCase) string {
	if prefix == "" {
		prefix = t.ImagePrefix
	}
	return fmt.Sprintf("%s/%s:%s", strings.TrimSuffix(prefix, "/"), c.Case, seededTag)
}

// Judge compares the outcome of an attribution with the case. It returns the
// verdict and a sentence that says why.
func Judge(c TruthCase, a Attribution) (verdict, detail string) {
	observed := observedText(a)
	if !c.Manifests {
		return VerdictNotManifested, "the truth file records that this defect does not manifest on the engine; observed: " + observed
	}
	switch a.Status {
	case StatusImageAbsent, StatusError:
		return VerdictIncomplete, observed
	case StatusResolvedSingle, StatusResolvedMinimal:
		return compareSets(a.MinimalSet, c.ExpectedMinimal)
	case StatusResolvedUnion:
		return VerdictWrong, "only the union of all candidates resolved the failure and no minimal set was named; " + observed
	case StatusUnresolved:
		return VerdictWrong, "no candidate or union resolved the failure; expected " + setLabel(c.ExpectedMinimal)
	default:
		// NOT_REPRODUCED, BASELINE_FAILED and NOT_OBSERVABLE: the truth file
		// says the defect manifests, so this run contradicts it. It counts
		// against the accuracy instead of dropping out of it.
		return VerdictWrong, "the seeded defect did not behave as the truth file says: " + observed
	}
}

// compareSets classifies a found minimal set against the expected one.
func compareSets(found, expected []string) (verdict, detail string) {
	want := map[string]bool{}
	for _, e := range expected {
		want[e] = true
	}
	have := map[string]bool{}
	for _, f := range found {
		have[f] = true
	}
	missing, extra := []string{}, []string{}
	for _, e := range sortedCopy(expected) {
		if !have[e] {
			missing = append(missing, e)
		}
	}
	for _, f := range sortedCopy(found) {
		if !want[f] {
			extra = append(extra, f)
		}
	}
	switch {
	case len(found) == 0:
		return VerdictWrong, "no minimal set was named; expected " + setLabel(expected)
	case len(missing) == 0 && len(extra) == 0:
		return VerdictExact, "found " + setLabel(found)
	case len(missing) == 0:
		return VerdictSuperset, fmt.Sprintf("found %s, which holds the expected %s and also %s", setLabel(found), setLabel(expected), setLabel(extra))
	default:
		return VerdictWrong, fmt.Sprintf("found %s, expected %s, missing %s", setLabel(found), setLabel(expected), setLabel(missing))
	}
}

func observedText(a Attribution) string {
	text := a.Status
	if len(a.MinimalSet) > 0 {
		text += " with the minimal set " + setLabel(a.MinimalSet)
	}
	if a.Detail != "" {
		text += " (" + a.Detail + ")"
	}
	return text
}

// SeededResult is the outcome of one seeded case.
type SeededResult struct {
	Case            string      `json:"case"`
	Rule            string      `json:"rule"`
	Image           string      `json:"image"`
	ExpectedMinimal []string    `json:"expected_minimal"`
	Manifests       bool        `json:"manifests"`
	Note            string      `json:"note,omitempty"`
	Verdict         string      `json:"verdict"`
	Detail          string      `json:"detail"`
	MinimalSet      []string    `json:"minimal_set,omitempty"`
	Attribution     Attribution `json:"attribution"`
}

// SeededSummary counts the verdicts. N is the accuracy denominator: the cases
// with a verdict EXACT, SUPERSET or WRONG.
type SeededSummary struct {
	N             int `json:"n"`
	Exact         int `json:"exact"`
	Superset      int `json:"superset"`
	Wrong         int `json:"wrong"`
	NotManifested int `json:"not_manifested"`
	Incomplete    int `json:"incomplete"`
}

// SummarizeSeeded counts the verdicts of the seeded cases.
func SummarizeSeeded(results []SeededResult) SeededSummary {
	var s SeededSummary
	for _, r := range results {
		switch r.Verdict {
		case VerdictExact:
			s.Exact++
		case VerdictSuperset:
			s.Superset++
		case VerdictWrong:
			s.Wrong++
		case VerdictNotManifested:
			s.NotManifested++
		default:
			s.Incomplete++
		}
	}
	s.N = s.Exact + s.Superset + s.Wrong
	return s
}

// SeededReport is the seeded block of attribution.json. It describes its own
// run, because it can be produced by a different invocation than the block of
// the real failures.
type SeededReport struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Complete    bool             `json:"complete"`
	TruthPath   string           `json:"truth_path"`
	TruthSHA256 string           `json:"truth_sha256"`
	ImagePrefix string           `json:"image_prefix"`
	WindowMs    int64            `json:"window_ms"`
	Minimize    bool             `json:"minimize"`
	Run         spec.RunMetadata `json:"run"`
	Summary     SeededSummary    `json:"summary"`
	Cases       []SeededResult   `json:"cases"`
	Note        string           `json:"note"`
}

// seededNote states how the cases are scored, so the file describes itself.
const seededNote = "A case is EXACT when the minimal set equals expected_minimal, SUPERSET when it holds every expected element and at least one more, and WRONG otherwise, which includes a failure that did not reproduce, an unresolved failure and a result without a minimal set. A case with manifests=false is NOT_MANIFESTED, is reported and is not in the denominator n. A case whose image was absent or whose engine run failed is INCOMPLETE and in no count."

// RunSeeded attributes the seeded cases in the order of the truth file and
// judges each against its expected set. A problem with one case is recorded in
// its verdict and the run continues. The returned results can be shorter than
// the cases when ctx ends.
func RunSeeded(ctx context.Context, r ContainerRunner, cfg Config, truth *TruthFile, prefix string, log *Logger, progress func([]SeededResult)) []SeededResult {
	var targets []Target
	for _, c := range truth.Cases {
		targets = append(targets, Target{Image: truth.ImageFor(prefix, c), Rule: c.Rule})
	}
	var results []SeededResult
	judge := func(attrs []Attribution) []SeededResult {
		out := make([]SeededResult, 0, len(attrs))
		for i, a := range attrs {
			c := truth.Cases[i]
			verdict, detail := Judge(c, a)
			out = append(out, SeededResult{
				Case: c.Case, Rule: c.Rule, Image: targets[i].Image, ExpectedMinimal: sortedCopy(c.ExpectedMinimal),
				Manifests: c.Manifests, Note: c.Note, Verdict: verdict, Detail: detail,
				MinimalSet: a.MinimalSet, Attribution: a,
			})
		}
		return out
	}
	attrs := Attribute(ctx, r, cfg, targets, log, func(done []Attribution) {
		if progress != nil {
			progress(judge(done))
		}
	})
	results = judge(attrs)
	for _, res := range results {
		line := fmt.Sprintf("%-34s %-15s %s", res.Case, res.Verdict, res.Detail)
		switch res.Verdict {
		case VerdictExact, VerdictSuperset:
			log.Ok("%s", line)
		case VerdictNotManifested:
			log.Info("%s", line)
		case VerdictWrong:
			log.Warn("%s", line)
		default:
			log.Error("%s", line)
		}
	}
	return results
}
