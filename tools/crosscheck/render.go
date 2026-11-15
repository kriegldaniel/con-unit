package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

// File names written by this tool. No other tool writes these names.
const (
	fileJSON         = "crosscheck.json"
	fileDiscordances = "discordances.csv"
	fileTable        = "table_crosscheck.tex"
	fileDiscTable    = "table_discordances.tex"
	fileMacros       = "macros_crosscheck.tex"
	fileCoverage     = "table_coverage.tex"

	// SchemaVersion of crosscheck.json.
	SchemaVersion = "1"
)

// discordanceHeader is the column list fixed in docs/INTERFACE_V2.md.
var discordanceHeader = []string{
	"image", "check", "dockle_code", "conunit_outcome", "dockle_finding",
	"conunit_evidence", "dockle_alert", "intended_difference", "resolution", "resolved_by",
}

// StudyRef identifies the study that was compared. Only base names are kept so
// that no host path reaches the output.
type StudyRef struct {
	File          string `json:"file"`
	SHA256        string `json:"sha256"`
	ConUnit       string `json:"conunit_version,omitempty"`
	Commit        string `json:"commit,omitempty"`
	Pack          string `json:"pack,omitempty"`
	PackID        string `json:"pack_id,omitempty"`
	Platform      string `json:"platform,omitempty"`
	ImageSource   string `json:"image_source_policy,omitempty"`
	EngineName    string `json:"engine_name,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
	DatasetSHA256 string `json:"dataset_sha256,omitempty"`
}

// DockleInfo records how Dockle ran.
type DockleInfo struct {
	Version string `json:"version"`
	// SchemaVerifiedAt is the Dockle version whose source fixed the JSON schema
	// and the behaviours that the analysis relies on.
	SchemaVerifiedAt string `json:"schema_verified_at"`
	VersionVerified  bool   `json:"version_verified"`
	Command          string `json:"command"`
	Environment      string `json:"environment"`
}

// MappingEntry is one line of the mapping in crosscheck.json.
type MappingEntry struct {
	Check               string   `json:"check"`
	Key                 string   `json:"key"`
	DockleCodes         []string `json:"dockle_codes"`
	Comparable          bool     `json:"comparable"`
	NotComparableReason string   `json:"not_comparable_reason,omitempty"`
	Facet               string   `json:"facet,omitempty"`
}

// Report is crosscheck.json.
type Report struct {
	SchemaVersion string   `json:"schema_version"`
	Study         StudyRef `json:"study"`
	Tools         struct {
		Dockle   DockleInfo `json:"dockle"`
		Engine   string     `json:"engine"`
		Platform string     `json:"platform,omitempty"`
	} `json:"tools"`
	Rule string `json:"counting_rule"`

	Mapping                  []MappingEntry  `json:"mapping"`
	ExcludedDockleCodes      []ExcludedCode  `json:"excluded_dockle_codes"`
	DockleWithoutCounterpart []UncoveredCode `json:"dockle_codes_without_conunit_counterpart"`

	Totals        Totals         `json:"totals"`
	Checks        []CheckSummary `json:"checks"`
	Discordances  []Discordance  `json:"discordances"`
	Timings       Timings        `json:"timings"`
	UnmappedCodes []UnmappedSeen `json:"unmapped_codes_seen"`
	ExcludedSeen  []UnmappedSeen `json:"excluded_codes_seen"`
	Images        []ImageResult  `json:"images"`
	Warnings      []string       `json:"warnings"`
}

// countingRule states the rule of the comparison in the report.
const countingRule = "An entry of a mapped Dockle code at the level INFO, WARN or FATAL is a finding. An entry at the level SKIP is a finding only if an alert is not a failed-to-detect notice; otherwise Dockle did not evaluate the checkpoint. The 2x2 table holds images where ConUnit is verified (PASS or FAIL) and Dockle evaluated the checkpoint. ConUnit UNVERIFIED, Dockle errors and checkpoints that Dockle did not evaluate are counted separately. Agreement is the raw share of images in the 2x2 table on which both tools agree. No chance-corrected statistic is computed."

// BuildReport assembles crosscheck.json.
func BuildReport(res *Result, study StudyRef, run RunInfo) *Report {
	r := &Report{SchemaVersion: SchemaVersion, Study: study, Rule: countingRule}
	r.Tools.Dockle = DockleInfo{
		Version: run.DockleVersion, SchemaVerifiedAt: VerifiedDockleVersion,
		VersionVerified: run.DockleVersion == VerifiedDockleVersion,
		Command:         "dockle --input <archive> --format json --exit-code 0",
		Environment:     "every DOCKLE_ variable removed, empty working directory",
	}
	r.Tools.Engine, r.Tools.Platform = run.Engine, run.Platform
	for _, m := range Mappings() {
		r.Mapping = append(r.Mapping, MappingEntry{
			Check: m.Check, Key: m.Key(), DockleCodes: m.Codes, Comparable: m.Comparable(),
			NotComparableReason: m.NotComparable, Facet: m.Facet,
		})
	}
	r.ExcludedDockleCodes = ExcludedCodes()
	r.DockleWithoutCounterpart = UncoveredCodes()
	r.Totals, r.Checks, r.Discordances, r.Timings = res.Totals, res.Checks, res.Discordances, res.Timings
	r.UnmappedCodes, r.ExcludedSeen, r.Images = res.UnmappedCodes, res.ExcludedSeen, res.Images
	r.Warnings = append([]string{}, res.Warnings...)
	if r.Discordances == nil {
		r.Discordances = []Discordance{}
	}
	if run.DockleVersion != "" && run.DockleVersion != VerifiedDockleVersion {
		r.Warnings = append(r.Warnings, fmt.Sprintf(
			"Dockle %s differs from %s, the version whose source fixed the JSON schema and the level rules; verify them for this version",
			run.DockleVersion, VerifiedDockleVersion))
	}
	return r
}

// RenderJSON renders crosscheck.json.
func RenderJSON(r *Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// orderedDiscordances sorts discordances by the order of the mapping, then by
// image.
func orderedDiscordances(ds []Discordance) []Discordance {
	index := map[string]int{}
	for i, m := range Mappings() {
		index[m.Check] = i
	}
	out := append([]Discordance(nil), ds...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if index[a.Check] != index[b.Check] {
			return index[a.Check] < index[b.Check]
		}
		return a.Image < b.Image
	})
	return out
}

// RenderDiscordancesCSV renders discordances.csv. A pair that cannot be
// compared is never a row.
func RenderDiscordancesCSV(ds []Discordance) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(discordanceHeader); err != nil {
		return "", err
	}
	for _, d := range orderedDiscordances(ds) {
		finding := "no"
		if d.DockleFinding {
			finding = "yes"
		}
		if err := w.Write([]string{
			d.Image, d.Check, d.DockleCode, d.ConUnitOutcome, finding,
			d.ConUnitEvidence, d.DockleAlert, d.IntendedDifference, d.Resolution, d.ResolvedBy,
		}); err != nil {
			return "", err
		}
	}
	w.Flush()
	return buf.String(), w.Error()
}

// ---------------------------------------------------------------------------
// table_crosscheck.tex

func excludedCodeList() string {
	var codes []string
	for _, e := range ExcludedCodes() {
		codes = append(codes, tex.Texttt(e.Code))
	}
	return strings.Join(codes, " and ")
}

// RenderTable renders table_crosscheck.tex, label tab:crosscheck.
func RenderTable(res *Result) string {
	var w strings.Builder
	w.WriteString("% Generated by tools/crosscheck. Do not edit.\n")
	w.WriteString("\\begin{table*}[t]\n\\centering\n\\small\n")
	fmt.Fprintf(&w, "\\caption{Cross-check of ConUnit against Dockle on the images that completed in the study. "+
		"Both: ConUnit FAIL and a Dockle finding. ConUnit only: ConUnit FAIL and no Dockle finding. "+
		"Dockle only: a Dockle finding and ConUnit PASS. Neither: ConUnit PASS and no Dockle finding. "+
		"Unverified: ConUnit UNVERIFIED. Dockle error: Dockle gave no result for the image because the export, the digest check or the run failed. "+
		"Not evaluated: Dockle skipped the checkpoint. "+
		"Agree is the raw percent agreement over the four cells of the 2x2 table, without a chance-corrected statistic. "+
		"The Dockle checkpoints %s concern content trust of the scanning host and are excluded. "+
		"SPEC-13 against DKL-DI-0006 is not comparable: Dockle does not report the checkpoint for an archive.}\n", excludedCodeList())
	w.WriteString("\\label{tab:crosscheck}\n\\resizebox{\\textwidth}{!}{%\n")
	w.WriteString("\\begin{tabular}{llrrrrrrrr}\n\\toprule\n")
	w.WriteString(`\textbf{Check} & \textbf{Dockle} & \textbf{Both} & \textbf{ConUnit only} & \textbf{Dockle only} & \textbf{Neither} & \textbf{Unverified} & \textbf{Dockle error} & \textbf{Not evaluated} & \textbf{Agree}`)
	w.WriteString(" \\\\\n\\midrule\n")
	if len(res.Checks) == 0 {
		w.WriteString("\\multicolumn{10}{c}{no checks} \\\\\n")
	}
	for _, c := range res.Checks {
		fmt.Fprintf(&w, "%s & %s", tex.Texttt(c.Check), tex.Texttt(strings.Join(c.DockleCodes, ", ")))
		if !c.Comparable {
			fmt.Fprintf(&w, " & \\multicolumn{7}{c}{not comparable} & %s \\\\\n", tex.NotAvailable)
			continue
		}
		agree := tex.NotAvailable
		if c.PercentAgreement != nil {
			agree = tex.Percent(*c.PercentAgreement)
		}
		fmt.Fprintf(&w, " & %d & %d & %d & %d & %d & %d & %d & %s \\\\\n",
			c.Both, c.OnlyConUnit, c.OnlyDockle, c.Neither, c.ConUnitUnverif, c.DockleError, c.DockleNotEvaluated, agree)
	}
	w.WriteString("\\bottomrule\n\\end{tabular}}\n\\end{table*}\n")
	return w.String()
}

// ---------------------------------------------------------------------------
// table_discordances.tex

// discordanceRowsPerTable is the number of rows of one table float. The
// supplement is typeset in two columns without the longtable package, so a long
// list is split into floats that each fit on a page.
const discordanceRowsPerTable = 28

func resolutionText(d Discordance) string {
	switch d.Resolution {
	case ResolutionConUnit:
		return "ConUnit correct (" + d.ResolvedBy + ")"
	case ResolutionDockle:
		return "Dockle correct (" + d.ResolvedBy + ")"
	case ResolutionUndecidable:
		return "undecidable (" + d.ResolvedBy + ")"
	}
	return "pending"
}

// displayImage shortens a reference for a table: the repository name, then the
// first eight hex digits of the digest when it has one.
func displayImage(ref string) string {
	name := studyfile.RepoName(ref)
	if i := strings.Index(ref, "@sha256:"); i >= 0 {
		hex := ref[i+len("@sha256:"):]
		if len(hex) > 8 {
			hex = hex[:8]
		}
		return name + "@" + hex
	}
	return name
}

func shortDifference(d Discordance) string {
	if d.IntendedShort == "" {
		return "none known"
	}
	return d.IntendedShort
}

// RenderDiscordanceTable renders table_discordances.tex, label tab:discordances
// on the first float. Every row has the Dockle code, both outcomes, the intended
// difference and the resolution; a pair without a resolution shows pending.
func RenderDiscordanceTable(ds []Discordance) string {
	rows := orderedDiscordances(ds)
	var w strings.Builder
	w.WriteString("% Generated by tools/crosscheck. Do not edit.\n")
	chunks := (len(rows) + discordanceRowsPerTable - 1) / discordanceRowsPerTable
	if chunks == 0 {
		chunks = 1
	}
	for c := 0; c < chunks; c++ {
		lo := c * discordanceRowsPerTable
		hi := lo + discordanceRowsPerTable
		if hi > len(rows) {
			hi = len(rows)
		}
		w.WriteString("\\begin{table*}[t]\n\\centering\n\\footnotesize\n")
		if c == 0 {
			w.WriteString("\\caption{Image and check pairs on which ConUnit and Dockle disagree. " +
				"ConUnit: its outcome. Dockle: a finding or none. " +
				"The intended difference names the documented design difference of the two checks that can explain a pair of this direction, or none known. It is a candidate that the adjudication confirms or rejects, except where the recorded evidence decides it. " +
				"The resolution comes from the two-rater adjudication sheet and reads pending until both raters or the consensus decided. " +
				"Pairs that cannot be compared (SPEC-13 against DKL-DI-0006) are not listed.}\n")
			w.WriteString("\\label{tab:discordances}\n")
		} else {
			fmt.Fprintf(&w, "\\caption{Image and check pairs on which ConUnit and Dockle disagree, part %d of %d.}\n", c+1, chunks)
		}
		w.WriteString("\\begin{tabular}{@{}p{3.0cm}llllp{5.0cm}p{2.9cm}@{}}\n\\toprule\n")
		w.WriteString(`\textbf{Image} & \textbf{Check} & \textbf{Dockle code} & \textbf{ConUnit} & \textbf{Dockle} & \textbf{Intended difference} & \textbf{Resolution}`)
		w.WriteString(" \\\\\n\\midrule\n")
		if len(rows) == 0 {
			w.WriteString("\\multicolumn{7}{c}{no discordant pair} \\\\\n")
		}
		for _, d := range rows[lo:hi] {
			dockle := "none"
			if d.DockleFinding {
				dockle = "finding"
			}
			fmt.Fprintf(&w, "%s & %s & %s & %s & %s & %s & %s \\\\\n",
				tex.Texttt(displayImage(d.Image)), tex.Texttt(d.Check), tex.Texttt(d.DockleCode),
				tex.Escape(d.ConUnitOutcome), dockle, tex.Escape(shortDifference(d)), tex.Escape(resolutionText(d)))
		}
		w.WriteString("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")
	}
	return w.String()
}

// ---------------------------------------------------------------------------
// macros_crosscheck.tex

type macro struct{ name, value string }

// RenderMacros renders macros_crosscheck.tex with the names of
// docs/INTERFACE_V2.md section 5, per mapped check with key K:
// ConUnitXchkBoth<K>, OnlyConUnit<K>, OnlyDockle<K>, Neither<K>, Unverified<K>,
// DockleError<K> and Agree<K>, plus DockleNotEvaluated<K>, which counts the
// images for which Dockle skipped the checkpoint. A check that is not
// comparable prints n/a for every one of them. The totals are
// ConUnitXchkImages (images with a Dockle result), ConUnitXchkDiscordant,
// ConUnitXchkResolved (n/a without an adjudication sheet) and
// ConUnitXchkDockleVersion.
func RenderMacros(res *Result) (string, error) {
	var list []macro
	add := func(name, value string) { list = append(list, macro{"ConUnitXchk" + name, value}) }
	for _, c := range res.Checks {
		k := analysis.RuleKey(c.Check)
		na := tex.NotAvailable
		if !c.Comparable {
			for _, n := range []string{"Both", "OnlyConUnit", "OnlyDockle", "Neither", "Unverified", "DockleError", "DockleNotEvaluated", "Agree"} {
				add(n+k, na)
			}
			continue
		}
		agree := na
		if c.PercentAgreement != nil {
			agree = tex.Percent(*c.PercentAgreement)
		}
		add("Both"+k, fmt.Sprint(c.Both))
		add("OnlyConUnit"+k, fmt.Sprint(c.OnlyConUnit))
		add("OnlyDockle"+k, fmt.Sprint(c.OnlyDockle))
		add("Neither"+k, fmt.Sprint(c.Neither))
		add("Unverified"+k, fmt.Sprint(c.ConUnitUnverif))
		add("DockleError"+k, fmt.Sprint(c.DockleError))
		add("DockleNotEvaluated"+k, fmt.Sprint(c.DockleNotEvaluated))
		add("Agree"+k, agree)
	}
	resolved := tex.NotAvailable
	if res.Totals.Resolved != nil {
		resolved = fmt.Sprint(*res.Totals.Resolved)
	}
	version := tex.NotAvailable
	if res.Totals.DockleVersion != "" {
		version = tex.Escape(res.Totals.DockleVersion)
	}
	add("Images", fmt.Sprint(res.Totals.ImagesAnalyzed))
	add("Discordant", fmt.Sprint(res.Totals.Discordant))
	add("Resolved", resolved)
	add("DockleVersion", version)

	var w strings.Builder
	w.WriteString("% Generated by tools/crosscheck. Do not edit.\n")
	w.WriteString("% Cross-check macros. Images counts the images with a Dockle result; Discordant counts image and check pairs.\n")
	seen := map[string]bool{}
	for _, m := range list {
		for _, r := range m.name {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return "", fmt.Errorf("macro name %q is not letters only", m.name)
			}
		}
		if seen[m.name] {
			return "", fmt.Errorf("macro %s is defined twice", m.name)
		}
		seen[m.name] = true
		fmt.Fprintf(&w, "\\newcommand{\\%s}{%s}\n", m.name, m.value)
	}
	return w.String(), nil
}
