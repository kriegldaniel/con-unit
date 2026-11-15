// Package analysis turns a decoded study into the statistics reported in the
// paper, following docs/ANALYSIS_PLAN.md.
//
// Rules implemented here:
//   - only COMPLETED images enter statistics; every other status is counted
//     in the attrition flow
//   - per check: PASS, FAIL and UNVERIFIED counts, UNVERIFIED by reason,
//     verified = PASS + FAIL, prevalence = FAIL / verified with a Wilson 95
//     percent interval; UNVERIFIED never enters numerator or denominator
//   - findings under fixture-like locations (docs/CONTRACT.md addendum 1) are
//     counted separately from confirmed failures
//   - no per-image pass rate: per image the number of confirmed failures is
//     reported next to the number of verified checks
//   - checks classified as excluded produce no prevalence at all
package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/dataaudit"
	"github.com/con-unit/con-unit/tools/internal/stats"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// Class is the analysis role of a check.
type Class string

const (
	ClassHeadline    Class = "headline"
	ClassExploratory Class = "exploratory"
	ClassExcluded    Class = "excluded"
)

// Unmapped is printed where rule metadata or an archetype entry is missing.
const Unmapped = "unmapped"

// UnspecifiedReason labels UNVERIFIED results that carry no reason code.
const UnspecifiedReason = "UNSPECIFIED"

// InfraStatuses are the image statuses counted against the 5 percent
// attrition stopping rule of docs/ANALYSIS_PLAN.md section 6.
var InfraStatuses = []string{
	spec.StatusRateLimited, spec.StatusExecutionError, spec.StatusUnavailable, spec.StatusTimeout,
}

// InfraShareLimit is the share of infrastructure failures above which the
// affected images must be rerun.
const InfraShareLimit = 0.05

// Classification is fixtures/headline_checks.json.
type Classification struct {
	Headline    []string `json:"headline"`
	Exploratory []string `json:"exploratory"`
	Excluded    []string `json:"excluded"`
}

// LoadClassification reads and validates the classification file. Unknown keys
// and IDs listed in more than one class are errors.
func LoadClassification(path string) (*Classification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Classification
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]string{}
	for class, ids := range map[string][]string{
		"headline": c.Headline, "exploratory": c.Exploratory, "excluded": c.Excluded,
	} {
		for _, id := range ids {
			if prev, dup := seen[id]; dup {
				return nil, fmt.Errorf("%s: rule %s is listed as both %s and %s", path, id, prev, class)
			}
			seen[id] = class
		}
	}
	return &c, nil
}

// Lookup returns the class of a rule ID and whether it is listed.
func (c *Classification) Lookup(id string) (Class, bool) {
	if c == nil {
		return ClassExploratory, false
	}
	for _, x := range c.Headline {
		if x == id {
			return ClassHeadline, true
		}
	}
	for _, x := range c.Excluded {
		if x == id {
			return ClassExcluded, true
		}
	}
	for _, x := range c.Exploratory {
		if x == id {
			return ClassExploratory, true
		}
	}
	return ClassExploratory, false
}

// Archetype is one entry of fixtures/archetypes.json.
type Archetype struct {
	Archetype  string `json:"archetype"`
	BaseFamily string `json:"base_family"`
}

// Archetypes maps repository names (no registry) to their stratum labels.
type Archetypes map[string]Archetype

// LoadArchetypes reads fixtures/archetypes.json.
func LoadArchetypes(path string) (Archetypes, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var a Archetypes
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return a, nil
}

// Options configures Analyze.
type Options struct {
	Classification *Classification
	Archetypes     Archetypes
	Audit          *dataaudit.Audit
	// Source is the base name of the study file, recorded in outputs.
	Source string
	// Pinned holds the entries of fixtures/evaluation_dataset_pinned.json. A
	// nil slice means no file was given and no tag statistic is computed.
	Pinned       []PinnedEntry
	PinnedSource string
}

// Interval is a proportion with its Wilson 95 percent interval, all in [0,1].
type Interval struct {
	Estimate float64 `json:"estimate"`
	Lo       float64 `json:"lo"`
	Hi       float64 `json:"hi"`
}

// Check holds the statistics of one rule over all COMPLETED images.
type Check struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Tier     int            `json:"tier"`
	Class    Class          `json:"class"`
	Listed   bool           `json:"listed_in_classification"`
	Rule     *spec.RuleMeta `json:"rule,omitempty"`
	Standard string         `json:"standard"`

	Pass       int `json:"pass"`
	Fail       int `json:"fail"`
	Unverified int `json:"unverified"`
	Verified   int `json:"verified"`
	// FixtureOnly counts PASS images that have findings only under
	// fixture-like paths.
	FixtureOnly        int            `json:"fixture_only_images"`
	UnverifiedByReason map[string]int `json:"unverified_by_reason"`
	// Prevalence is nil when no image was verified or the check is excluded.
	Prevalence *Interval `json:"prevalence,omitempty"`
}

// CountPair is a failure count over a verified count.
type CountPair struct {
	Fail     int `json:"fail"`
	Verified int `json:"verified"`
}

// ImageStat is the per-image view: confirmed failures among verified checks.
type ImageStat struct {
	Name       string    `json:"name"`
	Ref        string    `json:"ref"`
	Archetype  string    `json:"archetype"`
	BaseFamily string    `json:"base_family"`
	Headline   CountPair `json:"headline"`
	// All covers headline and exploratory checks (not excluded ones).
	All CountPair `json:"all"`
}

// Distribution summarises ImageStat over images for one check family.
type Distribution struct {
	ConfirmedFailures stats.Summary `json:"confirmed_failures"`
	VerifiedChecks    stats.Summary `json:"verified_checks"`
	// NoConfirmedFailure counts images with verified checks and no FAIL.
	NoConfirmedFailure int `json:"images_without_confirmed_failure"`
	// NoVerifiedCheck counts images with no verified check at all.
	NoVerifiedCheck int `json:"images_without_verified_check"`
}

// Stratum is one archetype or base family with per-check counts.
type Stratum struct {
	Kind     string               `json:"kind"` // archetype or base_family
	Name     string               `json:"name"`
	Images   int                  `json:"images"`
	PerCheck map[string]CountPair `json:"per_check"`
}

// IndexLimitImage records the size of an image excluded by INDEX_LIMIT.
type IndexLimitImage struct {
	Name              string `json:"name"`
	Ref               string `json:"ref"`
	CompressedBytes   int64  `json:"compressed_bytes,omitempty"`
	UncompressedBytes int64  `json:"uncompressed_bytes,omitempty"`
	Layers            int    `json:"layers,omitempty"`
}

// Flow is the attrition flow of the study.
type Flow struct {
	Attempted    int                       `json:"attempted"`
	Completed    int                       `json:"completed"`
	NotCompleted int                       `json:"not_completed"`
	ByStatus     map[string]int            `json:"by_status"`
	ReasonsBy    map[string]map[string]int `json:"reasons_by_status"`
	// Infrastructure counts RATE_LIMITED, EXECUTION_ERROR, UNAVAILABLE and
	// TIMEOUT records together.
	Infrastructure      int               `json:"infrastructure"`
	InfrastructureShare *Interval         `json:"infrastructure_share,omitempty"`
	IndexLimit          []IndexLimitImage `json:"index_limit_images,omitempty"`
}

// Analysis is the complete result.
type Analysis struct {
	Source        string           `json:"source"`
	SourceSHA256  string           `json:"source_sha256"`
	Legacy        bool             `json:"legacy_input"`
	SchemaVersion string           `json:"schema_version"`
	Run           spec.RunMetadata `json:"run"`
	Audit         *dataaudit.Audit `json:"audit,omitempty"`
	// Tags is set only when a pinned dataset was given.
	Tags *TagStats `json:"pinned_tags,omitempty"`

	Flow         Flow                    `json:"flow"`
	Checks       []*Check                `json:"checks"`
	Images       []ImageStat             `json:"images"`
	Distribution map[string]Distribution `json:"distribution"`
	Strata       []Stratum               `json:"strata"`
	Warnings     []string                `json:"warnings"`

	// Completed holds the COMPLETED records in study order, for renderers
	// that need raw telemetry.
	Completed []*spec.SuiteResult `json:"-"`
	// Records holds every attempted image (one record each).
	Records []*spec.SuiteResult `json:"-"`
}

// Check returns the check with the given ID, or nil.
func (a *Analysis) Check(id string) *Check {
	for _, c := range a.Checks {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// ChecksOfClass returns the checks of one class in report order.
func (a *Analysis) ChecksOfClass(class Class) []*Check {
	var out []*Check
	for _, c := range a.Checks {
		if c.Class == class {
			out = append(out, c)
		}
	}
	return out
}

type metaKey struct {
	Standard, Version, Control, Mapping, Scope string
}

func keyOfMeta(m *spec.RuleMeta) metaKey {
	return metaKey{m.Standard, m.StandardVersion, m.ControlID, string(m.Mapping), string(m.Scope)}
}

type checkAcc struct {
	check          *Check
	names          map[string]int
	meta           *spec.RuleMeta
	metaK          metaKey
	metaOK         bool
	conflictWarned bool
}

// Analyze computes all statistics. It never fails; problems that need
// attention are collected in Analysis.Warnings.
func Analyze(l *studyfile.Loaded, opt Options) *Analysis {
	a := &Analysis{
		Source:        opt.Source,
		SourceSHA256:  l.SHA256,
		Legacy:        l.Legacy,
		SchemaVersion: l.Study.SchemaVersion,
		Run:           l.Study.Run,
		Audit:         opt.Audit,
		Records:       l.Records,
		Warnings:      append([]string(nil), l.Warnings...),
		Distribution:  map[string]Distribution{},
	}
	warn := func(format string, args ...any) { a.Warnings = append(a.Warnings, fmt.Sprintf(format, args...)) }

	// Flow.
	a.Flow = Flow{
		Attempted: len(l.Records),
		ByStatus:  map[string]int{},
		ReasonsBy: map[string]map[string]int{},
	}
	for _, rec := range l.Records {
		status := l.Status(rec)
		if status == spec.StatusCompleted {
			a.Flow.Completed++
			a.Completed = append(a.Completed, rec)
			continue
		}
		a.Flow.NotCompleted++
		a.Flow.ByStatus[status]++
		reason := string(rec.Reason)
		if reason == "" {
			reason = UnspecifiedReason
		}
		if a.Flow.ReasonsBy[status] == nil {
			a.Flow.ReasonsBy[status] = map[string]int{}
		}
		a.Flow.ReasonsBy[status][reason]++
		if status == spec.StatusIndexLimit {
			a.Flow.IndexLimit = append(a.Flow.IndexLimit, IndexLimitImage{
				Name:              studyfile.RepoName(imageRef(rec)),
				Ref:               imageRef(rec),
				CompressedBytes:   rec.Resources.CompressedBytes,
				UncompressedBytes: rec.Resources.UncompressedBytes,
				Layers:            rec.Resources.LayerCount,
			})
		}
		if status == studyfile.StatusUnspecified {
			warn("image %q has no status; it is reported as %s and excluded from statistics", imageRef(rec), studyfile.StatusUnspecified)
		}
	}
	for _, s := range InfraStatuses {
		a.Flow.Infrastructure += a.Flow.ByStatus[s]
	}
	if a.Flow.Attempted > 0 {
		lo, hi, _ := stats.Wilson(a.Flow.Infrastructure, a.Flow.Attempted)
		a.Flow.InfrastructureShare = &Interval{
			Estimate: float64(a.Flow.Infrastructure) / float64(a.Flow.Attempted), Lo: lo, Hi: hi,
		}
		if a.Flow.InfrastructureShare.Estimate > InfraShareLimit {
			warn("%d of %d attempted images (%.1f%%) ended in an infrastructure status; docs/ANALYSIS_PLAN.md section 6 requires a rerun above %.0f%%",
				a.Flow.Infrastructure, a.Flow.Attempted, 100*a.Flow.InfrastructureShare.Estimate, 100*InfraShareLimit)
		}
	}
	sort.Slice(a.Flow.IndexLimit, func(i, j int) bool { return a.Flow.IndexLimit[i].Ref < a.Flow.IndexLimit[j].Ref })

	if opt.Pinned != nil {
		ts := CountTags(a.Completed, opt.Pinned)
		ts.Source = opt.PinnedSource
		a.Tags = &ts
		if ts.NoPinnedEntry > 0 {
			warn("%d completed images match no entry of the pinned dataset %s; their tag is unknown and they are not counted as tagged (for example %q)",
				ts.NoPinnedEntry, opt.PinnedSource, ts.Unmatched[0])
		}
		if ts.Completed > 0 && ts.Tagged == 0 {
			warn("no completed image has a known tag in the pinned dataset %s", opt.PinnedSource)
		}
	}

	if opt.Audit != nil && !opt.Audit.Frame.Recorded() {
		warn("dataset audit does not record the sampling frame (commit and date)")
	}
	if opt.Audit != nil && l.Study.Run.DatasetSHA256 != "" {
		sums := map[string]bool{
			opt.Audit.Outputs.PinnedTxt.SHA256: true,
		}
		if t := opt.Audit.Outputs.Top10; t != nil {
			sums[t.Pinned.SHA256] = true
		}
		if !sums[l.Study.Run.DatasetSHA256] {
			warn("run.dataset_sha256 %s matches neither the pinned list nor the top-10 pinned list recorded in the dataset audit",
				short(l.Study.Run.DatasetSHA256))
		}
	}

	// Per check accumulation over COMPLETED images.
	accs := map[string]*checkAcc{}
	unclassified := map[string]bool{}
	for _, rec := range a.Completed {
		results, repeated := studyfile.UniqueResults(rec)
		for _, id := range repeated {
			warn("image %q has more than one result for %s; only the first is counted", imageRef(rec), id)
		}
		for _, r := range results {
			acc := accs[r.TestID]
			if acc == nil {
				class, listed := opt.Classification.Lookup(r.TestID)
				acc = &checkAcc{
					check: &Check{
						ID: r.TestID, Tier: int(r.Tier), Class: class, Listed: listed,
						UnverifiedByReason: map[string]int{},
					},
					names: map[string]int{},
				}
				accs[r.TestID] = acc
				if !listed && opt.Classification != nil && !unclassified[r.TestID] {
					unclassified[r.TestID] = true
					warn("rule %s is not listed in headline_checks.json; treated as exploratory", r.TestID)
				}
			}
			c := acc.check
			acc.names[r.TestName]++
			if r.Rule != nil {
				k := keyOfMeta(r.Rule)
				switch {
				case !acc.metaOK:
					acc.meta, acc.metaK, acc.metaOK = r.Rule, k, true
				case acc.metaK != k && !acc.conflictWarned:
					warn("rule %s carries conflicting rule metadata across images; the first is used", r.TestID)
					acc.conflictWarned = true
				}
			}
			switch r.EffectiveOutcome() {
			case spec.OutcomePass:
				c.Pass++
				if r.Evidence != nil && len(r.Evidence.FixtureCandidates) > 0 && len(r.Evidence.Paths) == 0 {
					c.FixtureOnly++
				}
			case spec.OutcomeFail:
				c.Fail++
				if r.Evidence != nil && len(r.Evidence.Paths) == 0 && len(r.Evidence.FixtureCandidates) > 0 {
					warn("%s on %q is FAIL but has fixture candidates only; the contract requires PASS in that case", r.TestID, imageRef(rec))
				}
			case spec.OutcomeUnverified:
				c.Unverified++
				reason := string(r.Reason)
				if reason == "" {
					reason = UnspecifiedReason
				}
				c.UnverifiedByReason[reason]++
			}
		}
	}
	if opt.Classification != nil {
		for _, id := range opt.Classification.Headline {
			if accs[id] == nil && len(a.Completed) > 0 {
				warn("headline check %s declared in headline_checks.json has no results in this study", id)
			}
		}
	}
	for _, acc := range accs {
		c := acc.check
		c.Name = majorityName(acc.names)
		if len(acc.names) > 1 {
			warn("rule %s has %d different test names across images (docs/CONTRACT.md requires a stable name); using %q",
				c.ID, len(acc.names), c.Name)
		}
		c.Rule = acc.meta
		c.Standard = StandardLabel(acc.meta)
		c.Verified = c.Pass + c.Fail
		if c.Class != ClassExcluded && c.Verified > 0 {
			lo, hi, _ := stats.Wilson(c.Fail, c.Verified)
			c.Prevalence = &Interval{Estimate: float64(c.Fail) / float64(c.Verified), Lo: lo, Hi: hi}
		}
		a.Checks = append(a.Checks, c)
	}
	sort.Slice(a.Checks, func(i, j int) bool {
		if a.Checks[i].Tier != a.Checks[j].Tier {
			return a.Checks[i].Tier < a.Checks[j].Tier
		}
		return NaturalLess(a.Checks[i].ID, a.Checks[j].ID)
	})

	// Per image statistics and strata.
	unmappedImages := 0
	archAcc := map[string]*stratumAcc{}
	famAcc := map[string]*stratumAcc{}
	bump := func(m map[string]*stratumAcc, name string, byCheck map[string]CountPair) {
		s := m[name]
		if s == nil {
			s = &stratumAcc{perCheck: map[string]*CountPair{}}
			m[name] = s
		}
		s.images++
		for id, cp := range byCheck {
			p := s.perCheck[id]
			if p == nil {
				p = &CountPair{}
				s.perCheck[id] = p
			}
			p.Fail += cp.Fail
			p.Verified += cp.Verified
		}
	}
	for _, rec := range a.Completed {
		results, _ := studyfile.UniqueResults(rec)
		is := ImageStat{Name: studyfile.RepoName(imageRef(rec)), Ref: imageRef(rec)}
		byCheck := map[string]CountPair{}
		for _, r := range results {
			class := accs[r.TestID].check.Class
			if class == ClassExcluded {
				continue
			}
			out := r.EffectiveOutcome()
			if out == spec.OutcomeUnverified {
				continue
			}
			cp := CountPair{Verified: 1}
			if out == spec.OutcomeFail {
				cp.Fail = 1
			}
			byCheck[r.TestID] = cp
			is.All.Verified += cp.Verified
			is.All.Fail += cp.Fail
			if class == ClassHeadline {
				is.Headline.Verified += cp.Verified
				is.Headline.Fail += cp.Fail
			}
		}
		arch := opt.Archetypes[is.Name] // a nil map yields the zero value
		if arch.Archetype == "" || arch.BaseFamily == "" {
			unmappedImages++
		}
		if arch.Archetype == "" {
			arch.Archetype = Unmapped
		}
		if arch.BaseFamily == "" {
			arch.BaseFamily = Unmapped
		}
		is.Archetype, is.BaseFamily = arch.Archetype, arch.BaseFamily
		a.Images = append(a.Images, is)
		bump(archAcc, is.Archetype, byCheck)
		bump(famAcc, is.BaseFamily, byCheck)
	}
	if unmappedImages > 0 {
		warn("%d completed images have no entry in archetypes.json and are reported as %q", unmappedImages, Unmapped)
	}
	a.Strata = append(a.Strata, strata("archetype", archAcc, archetypeOrder)...)
	a.Strata = append(a.Strata, strata("base_family", famAcc, baseFamilyOrder)...)

	a.Distribution["headline"] = distribution(a.Images, func(i ImageStat) CountPair { return i.Headline })
	a.Distribution["all"] = distribution(a.Images, func(i ImageStat) CountPair { return i.All })
	return a
}

var archetypeOrder = []string{"base-os", "language-runtime", "database", "web-ingress", "messaging", "application", "build-tool", "other", Unmapped}
var baseFamilyOrder = []string{"alpine", "debian", "ubuntu", "fedora-rhel", "scratch-or-distroless", "other", "unknown", Unmapped}

// stratumAcc accumulates the images and per-check counts of one stratum.
type stratumAcc struct {
	images   int
	perCheck map[string]*CountPair
}

// strata orders the accumulated strata: known labels in their fixed order,
// then any other label alphabetically.
func strata(kind string, m map[string]*stratumAcc, order []string) []Stratum {
	var names []string
	seen := map[string]bool{}
	for _, n := range order {
		if _, ok := m[n]; ok {
			names = append(names, n)
			seen[n] = true
		}
	}
	var extra []string
	for n := range m {
		if !seen[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	names = append(names, extra...)
	out := make([]Stratum, 0, len(names))
	for _, n := range names {
		st := Stratum{Kind: kind, Name: n, Images: m[n].images, PerCheck: map[string]CountPair{}}
		for id, p := range m[n].perCheck {
			st.PerCheck[id] = *p
		}
		out = append(out, st)
	}
	return out
}

func distribution(images []ImageStat, pick func(ImageStat) CountPair) Distribution {
	var fails, verified []float64
	d := Distribution{}
	for _, im := range images {
		cp := pick(im)
		fails = append(fails, float64(cp.Fail))
		verified = append(verified, float64(cp.Verified))
		switch {
		case cp.Verified == 0:
			d.NoVerifiedCheck++
		case cp.Fail == 0:
			d.NoConfirmedFailure++
		}
	}
	d.ConfirmedFailures = stats.Summarize(fails)
	d.VerifiedChecks = stats.Summarize(verified)
	return d
}

func imageRef(r *spec.SuiteResult) string { return studyfile.RecordKey(r) }

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

func majorityName(names map[string]int) string {
	best, bestN := "", -1
	for n, c := range names {
		if c > bestN || (c == bestN && n < best) {
			best, bestN = n, c
		}
	}
	return best
}

// StandardLabel builds the standard column text from rule metadata only. It
// returns Unmapped when no metadata is available.
func StandardLabel(m *spec.RuleMeta) string {
	if m == nil {
		return Unmapped
	}
	var parts []string
	if m.Standard != "" {
		parts = append(parts, m.Standard)
	}
	if m.StandardVersion != "" {
		parts = append(parts, "v"+strings.TrimPrefix(m.StandardVersion, "v"))
	}
	if m.ControlID != "" {
		parts = append(parts, m.ControlID)
	}
	label := strings.Join(parts, " ")
	if label == "" {
		if m.Mapping == "" {
			return Unmapped
		}
		label = "ConUnit"
	}
	if m.Mapping != "" {
		label += " (" + string(m.Mapping) + ")"
	}
	return label
}

// NaturalLess orders rule IDs so that SPEC-02 precedes SPEC-10 and CIS-4.6
// precedes CIS-4.10.
func NaturalLess(a, b string) bool {
	ta, tb := tokenize(a), tokenize(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		x, y := ta[i], tb[i]
		if x == y {
			continue
		}
		xn, xIsNum := atoi(x)
		yn, yIsNum := atoi(y)
		if xIsNum && yIsNum && xn != yn {
			return xn < yn
		}
		return x < y
	}
	return len(ta) < len(tb)
}

func tokenize(s string) []string {
	var toks []string
	var cur []rune
	kind := 0 // 0 none, 1 digit, 2 other
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range s {
		k := 2
		if unicode.IsDigit(r) {
			k = 1
		}
		if k != kind {
			flush()
			kind = k
		}
		cur = append(cur, r)
	}
	flush()
	return toks
}

func atoi(s string) (int, bool) {
	n := 0
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, s != ""
}
