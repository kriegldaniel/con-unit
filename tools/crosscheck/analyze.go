package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/stats"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// Cell is the place of one image and check pair in the comparison. The cells
// of one check partition the COMPLETED images of the study.
type Cell string

const (
	// The four cells of the 2x2 table. Both tools are verified for the pair.
	CellBoth        Cell = "both"         // ConUnit FAIL, Dockle finding
	CellOnlyConUnit Cell = "only_conunit" // ConUnit FAIL, no Dockle finding
	CellOnlyDockle  Cell = "only_dockle"  // ConUnit PASS, Dockle finding
	CellNeither     Cell = "neither"      // ConUnit PASS, no Dockle finding

	// Pairs that are counted separately and never enter the 2x2 table.
	CellConUnitUnverified  Cell = "conunit_unverified"   // ConUnit UNVERIFIED
	CellDockleError        Cell = "dockle_error"         // no Dockle result for the image
	CellDockleNotEvaluated Cell = "dockle_not_evaluated" // Dockle skipped the checkpoint
	CellNotComparable      Cell = "not_comparable"       // the mapping cannot be compared
	CellNotInStudy         Cell = "not_in_study"         // the study has no result for the check
)

// CheckResult is the comparison of one check on one image.
type CheckResult struct {
	Check           string   `json:"check"`
	ConUnitOutcome  string   `json:"conunit_outcome"`
	ConUnitReason   string   `json:"conunit_reason,omitempty"`
	ConUnitEvidence string   `json:"conunit_evidence,omitempty"`
	DockleState     string   `json:"dockle_state"`
	DockleCodes     []string `json:"dockle_codes,omitempty"`
	DockleAlerts    string   `json:"dockle_alerts,omitempty"`
	// DockleFacets lists the kinds of alert behind a finding of a code that
	// several checks share.
	DockleFacets []string `json:"dockle_facets,omitempty"`
	Cell         Cell     `json:"cell"`
}

// ImageResult is the Dockle side and the comparison of one COMPLETED image.
type ImageResult struct {
	Image               string      `json:"image"`
	Status              ImageStatus `json:"status"`
	Error               string      `json:"error,omitempty"`
	ConfigDigestStudy   string      `json:"config_digest_study"`
	ConfigDigestArchive string      `json:"config_digest_archive,omitempty"`
	Pulled              bool        `json:"pulled,omitempty"`
	PullSeconds         float64     `json:"pull_seconds,omitempty"`
	ExportSeconds       float64     `json:"export_seconds"`
	DockleSeconds       float64     `json:"dockle_seconds"`

	DockleSummary *DockleSummary `json:"dockle_summary,omitempty"`
	DockleDetails []DockleDetail `json:"dockle_details,omitempty"`
	// ExcludedCodes are excluded Dockle codes that the report holds.
	ExcludedCodes []string `json:"excluded_codes_seen,omitempty"`
	// UnmappedCodes are codes of the report that no check maps to and that are
	// not excluded.
	UnmappedCodes []string      `json:"unmapped_codes_seen,omitempty"`
	Checks        []CheckResult `json:"checks"`
}

// CheckSummary is the 2x2 table of one mapped check with the counts that stay
// outside of it.
type CheckSummary struct {
	Check       string   `json:"check"`
	Key         string   `json:"key"`
	DockleCodes []string `json:"dockle_codes"`
	Comparable  bool     `json:"comparable"`
	// NotComparableReason is set when Comparable is false.
	NotComparableReason string `json:"not_comparable_reason,omitempty"`

	Both           int `json:"both"`
	OnlyConUnit    int `json:"only_conunit"`
	OnlyDockle     int `json:"only_dockle"`
	Neither        int `json:"neither"`
	ConUnitUnverif int `json:"conunit_unverified"`
	DockleError    int `json:"dockle_error"`
	// DockleNotEvaluated counts images for which Dockle skipped the
	// checkpoint (level SKIP or IGNORE without a finding).
	DockleNotEvaluated int `json:"dockle_not_evaluated"`
	NotComparable      int `json:"not_comparable,omitempty"`
	NotInStudy         int `json:"not_in_study,omitempty"`

	// Images is the number of COMPLETED images of the check: the sum of all
	// counts above.
	Images int `json:"images"`
	// Table is the number of images in the 2x2 table.
	Table int `json:"table"`
	Agree int `json:"agree"`
	// PercentAgreement is Agree over Table, a proportion in [0,1], null
	// without an image in the table or for a check that is not comparable.
	PercentAgreement *float64 `json:"percent_agreement"`
	// BothFacetMismatch counts the Both pairs of a check that covers one part
	// of a shared Dockle code (CIS-DI-0010) in which Dockle reports only the
	// other part. They agree by the rule of the contract and are listed so that
	// the agreement is not read as stronger than it is.
	BothFacetMismatch int `json:"both_facet_mismatch,omitempty"`
	Discordant        int `json:"discordant"`
}

// Discordance is an image and check pair on which the two tools disagree.
type Discordance struct {
	Image              string `json:"image"`
	Check              string `json:"check"`
	Kind               Cell   `json:"kind"`
	DockleCode         string `json:"dockle_code"`
	ConUnitOutcome     string `json:"conunit_outcome"`
	DockleFinding      bool   `json:"dockle_finding"`
	ConUnitEvidence    string `json:"conunit_evidence"`
	DockleAlert        string `json:"dockle_alert"`
	IntendedDifference string `json:"intended_difference"`
	IntendedShort      string `json:"intended_short,omitempty"`
	// Resolution is conunit_correct, dockle_correct, undecidable or empty
	// while the pair is unresolved. ResolvedBy is consensus or agreed.
	Resolution string `json:"resolution"`
	ResolvedBy string `json:"resolved_by"`
}

// Resolution values.
const (
	ResolutionConUnit     = "conunit_correct"
	ResolutionDockle      = "dockle_correct"
	ResolutionUndecidable = "undecidable"
)

// Totals are the counts over the whole run.
type Totals struct {
	// ImagesCompleted is the number of COMPLETED images of the study.
	ImagesCompleted int `json:"images_completed"`
	// ImagesAnalyzed is the number of images with a Dockle result.
	ImagesAnalyzed  int            `json:"images_analyzed"`
	ImagesWithError int            `json:"images_with_error"`
	ErrorsByStatus  map[string]int `json:"errors_by_status,omitempty"`
	Discordant      int            `json:"discordant"`
	// Resolved is the number of discordances with a final TP or FP label; it
	// is null when no adjudication sheet was given.
	Resolved      *int   `json:"resolved"`
	Undecidable   int    `json:"undecidable"`
	DockleVersion string `json:"dockle_version"`
}

// Timings summarizes the seconds per image.
type Timings struct {
	Export stats.Summary `json:"export_seconds"`
	Dockle stats.Summary `json:"dockle_seconds"`
	// Total is export plus Dockle per image, over images that ran Dockle.
	Total stats.Summary `json:"export_plus_dockle_seconds"`
	Pull  stats.Summary `json:"pull_seconds"`
}

// UnmappedSeen counts the images that carry a code no check maps to.
type UnmappedSeen struct {
	Code   string `json:"code"`
	Images int    `json:"images"`
	// Known is true when the code is in the Dockle catalog.
	Known bool `json:"in_catalog"`
}

// Result is the whole analysis.
type Result struct {
	Images       []ImageResult  `json:"images"`
	Checks       []CheckSummary `json:"checks"`
	Discordances []Discordance  `json:"discordances"`
	Totals       Totals         `json:"totals"`
	Timings      Timings        `json:"timings"`
	// UnmappedCodes are the codes seen in reports that no check maps to.
	UnmappedCodes []UnmappedSeen `json:"unmapped_codes_seen"`
	ExcludedSeen  []UnmappedSeen `json:"excluded_codes_seen"`
	Warnings      []string       `json:"warnings,omitempty"`
}

// Options of Analyze.
type Options struct {
	Run RunInfo
	// Sheet holds the filled adjudication rows. Nil means none was given.
	Sheet *Sheet
	// Only restricts the analysis to these study record keys. Nil means every
	// COMPLETED image.
	Only []string
}

// Analyze compares the study with the Dockle records. records is keyed by the
// study record key; an absent entry means that no record exists, which counts
// as a Dockle error of that image.
func Analyze(l *studyfile.Loaded, records map[string]*ImageRecord, opt Options) *Result {
	res := &Result{}
	warn := func(format string, args ...any) { res.Warnings = append(res.Warnings, fmt.Sprintf(format, args...)) }

	var only map[string]bool
	if opt.Only != nil {
		only = map[string]bool{}
		for _, k := range opt.Only {
			only[k] = true
		}
	}
	var completed []*spec.SuiteResult
	allCompleted := 0
	for _, rec := range l.Records {
		if !l.Completed(rec) {
			continue
		}
		allCompleted++
		if only == nil || only[studyfile.RecordKey(rec)] {
			completed = append(completed, rec)
		}
	}
	sort.SliceStable(completed, func(i, j int) bool {
		return studyfile.RecordKey(completed[i]) < studyfile.RecordKey(completed[j])
	})
	if len(completed) < allCompleted {
		warn("the analysis covers %d of %d completed images of the study (-images or -limit)", len(completed), allCompleted)
	}

	mappings := Mappings()
	sums := make([]*CheckSummary, len(mappings))
	for i, m := range mappings {
		sums[i] = &CheckSummary{
			Check: m.Check, Key: m.Key(), DockleCodes: append([]string(nil), m.Codes...),
			Comparable: m.Comparable(), NotComparableReason: m.NotComparable,
		}
	}
	mapped := MappedCodes()
	unmapped := map[string]int{}
	excludedSeen := map[string]int{}
	var exportS, dockleS, totalS, pullS []float64

	res.Totals.ErrorsByStatus = map[string]int{}
	res.Totals.ImagesCompleted = len(completed)
	res.Totals.DockleVersion = opt.Run.DockleVersion

	for _, rec := range completed {
		key := studyfile.RecordKey(rec)
		ir := imageResultFrom(key, rec, records[key])
		var report *DockleReport
		if ir.Status == ImageOK {
			raw := records[key]
			parsed, err := ParseReport([]byte(raw.DockleStdout))
			if err != nil {
				ir.Status, ir.Error = ImageParseError, err.Error()
			} else {
				report = parsed
				sum := parsed.Summary
				ir.DockleSummary = &sum
				ir.DockleDetails = parsed.Details
			}
		}
		if ir.Status == ImageOK {
			res.Totals.ImagesAnalyzed++
			for _, code := range report.Codes() {
				switch {
				case IsExcluded(code):
					ir.ExcludedCodes = append(ir.ExcludedCodes, code)
					excludedSeen[code]++
				case !mapped[code]:
					ir.UnmappedCodes = append(ir.UnmappedCodes, code)
					unmapped[code]++
				}
			}
		} else {
			res.Totals.ImagesWithError++
			res.Totals.ErrorsByStatus[string(ir.Status)]++
		}
		exportS = append(exportS, ir.ExportSeconds)
		if ir.Pulled {
			pullS = append(pullS, ir.PullSeconds)
		}
		if ir.DockleSeconds > 0 {
			dockleS = append(dockleS, ir.DockleSeconds)
			totalS = append(totalS, ir.ExportSeconds+ir.DockleSeconds)
		}

		conunit, repeated := studyfile.UniqueResults(rec)
		for _, id := range repeated {
			warn("image %q has more than one result for %s; only the first is used", key, id)
		}
		byID := map[string]spec.TestResult{}
		for _, r := range conunit {
			byID[r.TestID] = r
		}
		for i, m := range mappings {
			cr, disc := compare(m, key, byID, ir, report)
			ir.Checks = append(ir.Checks, cr)
			count(sums[i], cr, m)
			if disc != nil {
				res.Discordances = append(res.Discordances, *disc)
				sums[i].Discordant++
			}
		}
		res.Images = append(res.Images, *ir)
	}

	for _, s := range sums {
		s.Images = s.Both + s.OnlyConUnit + s.OnlyDockle + s.Neither + s.ConUnitUnverif + s.DockleError +
			s.DockleNotEvaluated + s.NotComparable + s.NotInStudy
		s.Table = s.Both + s.OnlyConUnit + s.OnlyDockle + s.Neither
		s.Agree = s.Both + s.Neither
		if s.Comparable && s.Table > 0 {
			p := float64(s.Agree) / float64(s.Table)
			s.PercentAgreement = &p
		}
		if s.NotInStudy > 0 {
			warn("the study has no result for %s on %d of %d completed images; is the study made with the lint pack?",
				s.Check, s.NotInStudy, s.Images)
		}
		res.Checks = append(res.Checks, *s)
	}

	res.UnmappedCodes = seenList(unmapped)
	res.ExcludedSeen = seenList(excludedSeen)
	if len(res.UnmappedCodes) > 0 {
		var names []string
		for _, u := range res.UnmappedCodes {
			names = append(names, u.Code)
		}
		warn("Dockle reported codes that no check maps to: %s", strings.Join(names, ", "))
	}
	res.Totals.Discordant = len(res.Discordances)
	res.Timings = Timings{
		Export: stats.Summarize(exportS), Dockle: stats.Summarize(dockleS),
		Total: stats.Summarize(totalS), Pull: stats.Summarize(pullS),
	}
	res.applySheet(opt.Sheet, warn)
	return res
}

func seenList(m map[string]int) []UnmappedSeen {
	out := []UnmappedSeen{}
	for code, n := range m {
		out = append(out, UnmappedSeen{Code: code, Images: n, Known: KnownCode(code)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func imageResultFrom(key string, rec *spec.SuiteResult, raw *ImageRecord) *ImageResult {
	ir := &ImageResult{Image: key, ConfigDigestStudy: rec.ConfigDigest, Checks: []CheckResult{}}
	if raw == nil {
		ir.Status = ImageNoRawRecord
		ir.Error = "no Dockle record exists for this image"
		return ir
	}
	ir.Status, ir.Error = raw.Status, raw.Error
	ir.ConfigDigestArchive = raw.ConfigDigestArchive
	ir.Pulled, ir.PullSeconds = raw.Pulled, raw.PullSeconds
	ir.ExportSeconds, ir.DockleSeconds = raw.ExportSeconds, raw.DockleSeconds
	return ir
}

// compare decides the cell of one check on one image and builds the
// discordance when the tools disagree.
func compare(m Mapping, image string, byID map[string]spec.TestResult, ir *ImageResult, report *DockleReport) (CheckResult, *Discordance) {
	cr := CheckResult{Check: m.Check}
	conunit, present := byID[m.Check]
	if present {
		cr.ConUnitOutcome = string(conunit.EffectiveOutcome())
		cr.ConUnitReason = string(conunit.Reason)
		cr.ConUnitEvidence = conunitEvidence(conunit)
	} else {
		cr.ConUnitOutcome = "ABSENT"
	}

	var lookup CodeResult
	switch {
	case !m.Comparable():
		cr.DockleState = "NOT_COMPARABLE"
	case ir.Status != ImageOK:
		cr.DockleState = "ERROR"
	default:
		lookup = report.Lookup(m.Codes...)
		cr.DockleState = string(lookup.State)
		cr.DockleCodes = lookup.Findings
		cr.DockleAlerts = dockleAlerts(lookup.Entries)
		if m.Facet != FacetNone && lookup.State == CodeFinding {
			cr.DockleFacets = findingFacets(lookup.Entries)
		}
	}

	// Priority of the cells. A pair that cannot be compared stays out whatever
	// else is true. The study side comes next: without a ConUnit result there
	// is nothing to compare. An image without a Dockle result is excluded
	// before ConUnit's own UNVERIFIED, so every check of such an image reads the
	// same. Then UNVERIFIED, then a checkpoint that Dockle skipped.
	switch {
	case !m.Comparable():
		cr.Cell = CellNotComparable
	case !present:
		cr.Cell = CellNotInStudy
	case ir.Status != ImageOK:
		cr.Cell = CellDockleError
	case conunit.EffectiveOutcome() == spec.OutcomeUnverified:
		cr.Cell = CellConUnitUnverified
	case lookup.State == CodeNotEvaluated:
		cr.Cell = CellDockleNotEvaluated
	default:
		fail := conunit.EffectiveOutcome() == spec.OutcomeFail
		finding := lookup.State == CodeFinding
		switch {
		case fail && finding:
			cr.Cell = CellBoth
		case fail:
			cr.Cell = CellOnlyConUnit
		case finding:
			cr.Cell = CellOnlyDockle
		default:
			cr.Cell = CellNeither
		}
	}

	if cr.Cell != CellOnlyConUnit && cr.Cell != CellOnlyDockle {
		return cr, nil
	}
	d := &Discordance{
		Image: image, Check: m.Check, Kind: cr.Cell,
		ConUnitOutcome: cr.ConUnitOutcome, DockleFinding: cr.Cell == CellOnlyDockle,
		ConUnitEvidence: cr.ConUnitEvidence, DockleAlert: cr.DockleAlerts,
	}
	if cr.Cell == CellOnlyDockle {
		d.DockleCode = strings.Join(cr.DockleCodes, "+")
		d.IntendedDifference, d.IntendedShort = explain(m, cr, m.OnlyDockle)
	} else {
		d.DockleCode = strings.Join(m.Codes, "+")
		d.IntendedDifference, d.IntendedShort = explain(m, cr, m.OnlyConUnit)
	}
	return cr, d
}

// explain returns the intended difference that applies to a discordance, in
// full and in short, or two empty strings when none is known.
//
// A Dockle finding of the other part of a shared code is the first
// explanation: the check does not cover that part. Otherwise the documented
// difference of the direction is a candidate cause. Where the evidence can
// decide (Applies), a difference that the evidence does not support is not
// stated: the discordance then has no known intended difference.
func explain(m Mapping, cr CheckResult, dir Difference) (text, short string) {
	if facetMismatch(m, cr) {
		return facetText(cr.DockleFacets), "other part of " + strings.Join(m.Codes, "+")
	}
	if dir.Text == "" {
		return "", ""
	}
	if dir.Applies != nil && !dir.Applies(cr.ConUnitEvidence, cr.DockleAlerts) {
		return "", ""
	}
	return dir.Text, dir.Short
}

// facetMismatch reports whether Dockle's findings for a shared code are all of
// a kind that the check does not cover.
func facetMismatch(m Mapping, cr CheckResult) bool {
	if m.Facet == FacetNone || len(cr.DockleFacets) == 0 {
		return false
	}
	for _, f := range cr.DockleFacets {
		if f == m.Facet || f == "unknown" {
			return false
		}
	}
	return true
}

func facetText(facets []string) string {
	var parts []string
	for _, f := range facets {
		switch f {
		case FacetEnv:
			parts = append(parts, "ENV keys of the build history")
		case FacetFile:
			parts = append(parts, "credential file names")
		}
	}
	return "The Dockle entry for CIS-DI-0010 holds only alerts about " + strings.Join(parts, " and ") +
		", a different part of the checkpoint than this check covers."
}

// findingFacets returns the sorted distinct facets of the alerts of finding
// entries. An alert without a known prefix adds the facet "unknown".
func findingFacets(entries []DockleDetail) []string {
	set := map[string]bool{}
	for _, d := range entries {
		if state, _ := ClassifyDetail(d); state != EntryFinding {
			continue
		}
		for _, a := range d.Alerts {
			if strings.HasPrefix(strings.TrimSpace(a), strings.TrimSpace(skipAlertPrefix)) {
				continue
			}
			if f := FacetOfAlert(a); f != FacetNone {
				set[f] = true
			} else {
				set["unknown"] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func count(s *CheckSummary, cr CheckResult, m Mapping) {
	switch cr.Cell {
	case CellBoth:
		s.Both++
		if facetMismatch(m, cr) {
			s.BothFacetMismatch++
		}
	case CellOnlyConUnit:
		s.OnlyConUnit++
	case CellOnlyDockle:
		s.OnlyDockle++
	case CellNeither:
		s.Neither++
	case CellConUnitUnverified:
		s.ConUnitUnverif++
	case CellDockleError:
		s.DockleError++
	case CellDockleNotEvaluated:
		s.DockleNotEvaluated++
	case CellNotComparable:
		s.NotComparable++
	case CellNotInStudy:
		s.NotInStudy++
	}
}

const (
	maxEvidenceChars = 600
	maxAlertChars    = 800
	maxPathsListed   = 5
)

// conunitEvidence summarizes what ConUnit recorded for a result, on one line.
func conunitEvidence(r spec.TestResult) string {
	var parts []string
	if msg := oneLine(r.Message); msg != "" {
		parts = append(parts, msg)
	}
	if r.Reason != "" {
		parts = append(parts, "reason: "+string(r.Reason))
	}
	if ev := r.Evidence; ev != nil {
		if n := len(ev.Paths); n > 0 {
			shown := ev.Paths
			more := ""
			if n > maxPathsListed {
				shown, more = ev.Paths[:maxPathsListed], fmt.Sprintf(" (+%d more)", n-maxPathsListed)
			}
			parts = append(parts, "paths: "+strings.Join(shown, ", ")+more)
		}
		if n := len(ev.FixtureCandidates); n > 0 {
			parts = append(parts, fmt.Sprintf("fixture candidates: %d", n))
		}
	}
	return truncate(strings.Join(parts, "; "), maxEvidenceChars)
}

// dockleAlerts formats the entries of a lookup: code and level, then the
// alerts.
func dockleAlerts(entries []DockleDetail) string {
	var parts []string
	for _, d := range entries {
		var alerts []string
		for _, a := range d.Alerts {
			if a = oneLine(a); a != "" {
				alerts = append(alerts, a)
			}
		}
		parts = append(parts, fmt.Sprintf("%s %s: %s", d.Code, strings.ToUpper(d.Level), strings.Join(alerts, " | ")))
	}
	return truncate(strings.Join(parts, "; "), maxAlertChars)
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + " ..."
}
