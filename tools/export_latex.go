// Command export_latex generates the paper tables, figures and macros from
// one empirical_study.json.
//
//	go run ./tools/export_latex.go [-out DIR] [-paper-dir DIR] [-audit FILE] <path/to/empirical_study.json>
//
// Every number in the paper comes from this command's output. The statistics
// follow docs/ANALYSIS_PLAN.md: only COMPLETED images enter prevalence,
// prevalence is FAIL over PASS plus FAIL with a Wilson 95 percent interval,
// UNVERIFIED is reported separately by reason, and no per-image pass rate or
// "fully compliant" figure exists.
//
// The command lives in a single file so that `go run ./tools/export_latex.go`
// works; shared logic sits in tools/internal.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/dataaudit"
	"github.com/con-unit/con-unit/tools/internal/stats"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

// File names written by this tool. No other tool may write these names.
const (
	fileMacros      = "macros_study.tex"
	filePrevalence  = "table_rq2_prevalence.tex"
	fileExploratory = "table_rq2_exploratory.tex"
	fileUnverified  = "table_unverified.tex"
	fileAttrition   = "table_attrition.tex"
	fileStrata      = "table_strata.tex"
	filePhases      = "table_rq3_phases.tex"
	figPrevalence   = "fig_rq2_prevalence.tex"
	figPhases       = "fig_rq3_phase_breakdown.tex"
	figMemory       = "fig_rq3_memory_scaling.tex"
	filePreview     = "preview_paper.tex"
	fileStatsJSON   = "study_stats.json"

	defaultStudyPath  = "results/empirical_study.json"
	defaultHeadline   = "fixtures/headline_checks.json"
	defaultArchetypes = "fixtures/archetypes.json"
)

// texOutputs lists the generated LaTeX files in a stable order.
var texOutputs = []string{
	fileMacros, filePrevalence, fileExploratory, fileUnverified, fileAttrition, fileStrata,
	filePhases, figPrevalence, figPhases, figMemory, filePreview,
}

// notAvailable is printed where a statistic is undefined, for example the
// prevalence of a check with no verified image.
const notAvailable = "n/a"

// maxPhaseRows is the number of representative images in the phases table,
// kept small so the table fits a two-column body.
const maxPhaseRows = 4

type config struct {
	StudyPath      string
	OutDir         string
	PaperDir       string
	AuditPath      string
	PinnedPath     string
	HeadlinePath   string
	ArchetypesPath string
	Check          bool
	ListOutputs    bool

	// archetypesExplicit records whether -archetypes was given, so that a
	// missing default file is tolerated while a missing explicit one is not.
	archetypesExplicit bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// parseArgs returns the configuration, or nil together with the exit code to
// use. Flags may appear before or after the study path.
func parseArgs(args []string, stderr io.Writer) (*config, int) {
	cfg := &config{}
	fset := flag.NewFlagSet("export_latex", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.StringVar(&cfg.OutDir, "out", "", "directory for study_stats.json and, without -paper-dir, for the LaTeX files (default: directory of the study JSON)")
	fset.StringVar(&cfg.PaperDir, "paper-dir", "", "write all generated .tex files to <paper-dir>/results/")
	fset.StringVar(&cfg.AuditPath, "audit", "", "path to fixtures/evaluation_dataset_audit.json for candidate and pinned counts")
	fset.StringVar(&cfg.PinnedPath, "pinned", "", "path to fixtures/evaluation_dataset_pinned.json for the alpine and slim tag counts")
	fset.StringVar(&cfg.HeadlinePath, "headline", defaultHeadline, "path to the headline check classification")
	fset.StringVar(&cfg.ArchetypesPath, "archetypes", defaultArchetypes, "path to the archetype and base family fixture")
	fset.BoolVar(&cfg.Check, "check", false, "do not write; verify that the files on disk equal what would be generated")
	fset.BoolVar(&cfg.ListOutputs, "list-outputs", false, "print the names of all generated files and exit")
	fset.Usage = func() {
		fmt.Fprintln(stderr, "usage: export_latex [-out DIR] [-paper-dir DIR] [-audit FILE] [-pinned FILE] [-headline FILE] [-archetypes FILE] [-check] [-list-outputs] <path/to/empirical_study.json>")
		fset.PrintDefaults()
	}

	var positional []string
	rest := args
	for {
		if err := fset.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, spec.ExitOK
			}
			return nil, spec.ExitUsage
		}
		if fset.NArg() == 0 {
			break
		}
		positional = append(positional, fset.Arg(0))
		rest = fset.Args()[1:]
		if len(rest) == 0 {
			break
		}
	}
	fset.Visit(func(f *flag.Flag) {
		if f.Name == "archetypes" {
			cfg.archetypesExplicit = true
		}
	})
	switch len(positional) {
	case 0:
		cfg.StudyPath = defaultStudyPath
	case 1:
		cfg.StudyPath = positional[0]
	default:
		fmt.Fprintf(stderr, "export_latex: expected one study path, got %d\n", len(positional))
		return nil, spec.ExitUsage
	}
	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Dir(cfg.StudyPath)
	}
	return cfg, -1
}

// texDir returns the directory that receives the generated .tex files.
func (c *config) texDir() string {
	if c.PaperDir != "" {
		return filepath.Join(c.PaperDir, "results")
	}
	return c.OutDir
}

func (c *config) pathFor(f outputFile) string {
	if f.JSON {
		return filepath.Join(c.OutDir, f.Name)
	}
	return filepath.Join(c.texDir(), f.Name)
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, code := parseArgs(args, stderr)
	if cfg == nil {
		return code
	}
	if cfg.ListOutputs {
		for _, name := range texOutputs {
			fmt.Fprintln(stdout, name)
		}
		fmt.Fprintln(stdout, fileStatsJSON)
		return spec.ExitOK
	}
	info := clilog.New(stdout)
	problem := clilog.New(stderr)

	loaded, err := studyfile.Load(cfg.StudyPath)
	if err != nil {
		problem.Error("cannot load study: %v", err)
		return spec.ExitFindings
	}
	class, err := analysis.LoadClassification(cfg.HeadlinePath)
	if err != nil {
		problem.Error("cannot load check classification: %v (run from the repository root or pass -headline)", err)
		return spec.ExitFindings
	}
	opt := analysis.Options{Classification: class, Source: filepath.Base(cfg.StudyPath)}
	arch, err := analysis.LoadArchetypes(cfg.ArchetypesPath)
	switch {
	case err == nil:
		opt.Archetypes = arch
	case !cfg.archetypesExplicit && errors.Is(err, fs.ErrNotExist):
		loaded.Warnings = append(loaded.Warnings,
			fmt.Sprintf("%s not found; every image is reported as %q", cfg.ArchetypesPath, analysis.Unmapped))
	default:
		problem.Error("cannot load archetypes: %v", err)
		return spec.ExitFindings
	}
	if cfg.AuditPath != "" {
		audit, err := dataaudit.Load(cfg.AuditPath)
		if err != nil {
			problem.Error("cannot load dataset audit: %v", err)
			return spec.ExitFindings
		}
		opt.Audit = audit
	} else {
		loaded.Warnings = append(loaded.Warnings,
			"no -audit file given; candidate and pinned counts are reported as "+notAvailable)
	}
	if cfg.PinnedPath != "" {
		pinned, err := analysis.LoadPinned(cfg.PinnedPath)
		if err != nil {
			problem.Error("cannot load pinned dataset: %v", err)
			return spec.ExitFindings
		}
		opt.Pinned = pinned
		opt.PinnedSource = filepath.Base(cfg.PinnedPath)
	} else {
		loaded.Warnings = append(loaded.Warnings,
			"no -pinned file given; the alpine, slim and tagged image counts are reported as "+notAvailable)
	}

	a := analysis.Analyze(loaded, opt)
	files, err := buildOutputs(a)
	if err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}

	info.Section("ConUnit LaTeX export")
	info.Info("study     %s (sha256 %s)", cfg.StudyPath, short(a.SourceSHA256))
	info.Info("schema    %s%s", orUnknown(a.SchemaVersion), legacyNote(a.Legacy))
	info.Info("flow      attempted %d, completed %d, not completed %d", a.Flow.Attempted, a.Flow.Completed, a.Flow.NotCompleted)
	printSummary(info, a)
	for _, w := range a.Warnings {
		problem.Warn("%s", w)
	}

	if cfg.Check {
		return verifyOutputs(cfg, files, info, problem)
	}
	if err := writeOutputs(cfg, files, info); err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	if a.Flow.Completed == 0 {
		problem.Error("no COMPLETED images in %s (%d attempted); statistics are undefined and every prevalence is %s",
			cfg.StudyPath, a.Flow.Attempted, notAvailable)
		return spec.ExitIncomplete
	}
	return spec.ExitOK
}

func legacyNote(legacy bool) string {
	if legacy {
		return " (legacy array input, run metadata unknown)"
	}
	return ""
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func printSummary(info *clilog.Logger, a *analysis.Analysis) {
	for _, class := range []analysis.Class{analysis.ClassHeadline, analysis.ClassExploratory, analysis.ClassExcluded} {
		checks := a.ChecksOfClass(class)
		if len(checks) == 0 {
			continue
		}
		info.Section(capitalize(string(class)) + " checks")
		for _, c := range checks {
			prev := "no prevalence (excluded)"
			if class != analysis.ClassExcluded {
				prev = "prevalence " + notAvailable
				if c.Prevalence != nil {
					prev = fmt.Sprintf("prevalence %5.1f%% [%.1f, %.1f]", 100*c.Prevalence.Estimate, 100*c.Prevalence.Lo, 100*c.Prevalence.Hi)
				}
			}
			info.Info("%-9s fail %3d / verified %3d   unverified %3d   %s", c.ID, c.Fail, c.Verified, c.Unverified, prev)
		}
	}
}

// outputFile is one generated file.
type outputFile struct {
	Name    string
	Content string
	JSON    bool
}

func buildOutputs(a *analysis.Analysis) ([]outputFile, error) {
	macros, err := renderMacros(a)
	if err != nil {
		return nil, err
	}
	statsJSON, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", fileStatsJSON, err)
	}
	return []outputFile{
		{Name: fileMacros, Content: macros},
		{Name: filePrevalence, Content: renderPrevalenceTable(a)},
		{Name: fileExploratory, Content: renderExploratoryTable(a)},
		{Name: fileUnverified, Content: renderUnverifiedTable(a)},
		{Name: fileAttrition, Content: renderAttritionTable(a)},
		{Name: fileStrata, Content: renderStrataTable(a)},
		{Name: filePhases, Content: renderPhasesTable(a)},
		{Name: figPrevalence, Content: renderPrevalenceFigure(a)},
		{Name: figPhases, Content: renderPhaseFigure(a)},
		{Name: figMemory, Content: renderMemoryFigure(a)},
		{Name: filePreview, Content: renderPreviewDocument()},
		{Name: fileStatsJSON, Content: string(statsJSON) + "\n", JSON: true},
	}, nil
}

func writeOutputs(cfg *config, files []outputFile, info *clilog.Logger) error {
	for _, f := range files {
		path := cfg.pathFor(f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(f.Content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		info.Success("wrote %s", path)
	}
	return nil
}

// verifyOutputs compares generated content with the files on disk.
func verifyOutputs(cfg *config, files []outputFile, info, problem *clilog.Logger) int {
	bad := 0
	for _, f := range files {
		path := cfg.pathFor(f)
		onDisk, err := os.ReadFile(path)
		switch {
		case err != nil:
			problem.Error("missing %s", path)
			bad++
		case string(onDisk) != f.Content:
			problem.Error("stale %s differs from what the study JSON produces", path)
			bad++
		default:
			info.Success("up to date %s", path)
		}
	}
	if bad > 0 {
		problem.Error("%d generated file(s) do not match %s", bad, cfg.StudyPath)
		return spec.ExitFindings
	}
	return spec.ExitOK
}

// ---------------------------------------------------------------------------
// LaTeX helpers

// escapeLatex escapes text for use in LaTeX text mode.
func escapeLatex(s string) string { return tex.Escape(s) }

func texttt(s string) string { return tex.Texttt(s) }

var digitWords = [...]string{"Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"}

// idKey converts a rule ID to the letters-only key used in macro names:
// hyphens and dots are removed and every digit is spelled out, so SPEC-01
// becomes SPECZeroOne and CIS-4.6 becomes CISFourSix.
func idKey(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
			b.WriteString(digitWords[r-'0'])
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// camel converts an upper snake case token such as RATE_LIMITED to RateLimited.
func camel(s string) string {
	var b strings.Builder
	for _, part := range strings.Split(s, "_") {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]) + strings.ToLower(part[1:]))
	}
	return b.String()
}

func f1(x float64) string { return fmt.Sprintf("%.1f", x) }

// numStr prints whole numbers without a decimal and others with one.
func numStr(x float64) string {
	if x == math.Trunc(x) {
		return fmt.Sprintf("%d", int64(x))
	}
	return f1(x)
}

// pctNum formats a proportion as a percentage with one decimal, without sign.
func pctNum(x float64) string { return f1(100 * x) }

// pctTex formats a proportion as a percentage with one decimal and an
// escaped percent sign, for use in LaTeX.
func pctTex(x float64) string { return pctNum(x) + `\%` }

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

func header(a *analysis.Analysis, what string) string {
	return fmt.Sprintf("%% Generated by tools/export_latex.go. Do not edit.\n%% %s\n%% Source: %s sha256 %s\n", what, a.Source, a.SourceSHA256)
}

func prevCell(c *analysis.Check) string {
	if c.Prevalence == nil {
		return notAvailable
	}
	return fmt.Sprintf(`%s\%% [%s, %s]`, pctNum(c.Prevalence.Estimate), pctNum(c.Prevalence.Lo), pctNum(c.Prevalence.Hi))
}

// ---------------------------------------------------------------------------
// Prevalence tables

type checkTableSpec struct {
	Env         string // table or table*
	Width       string // \columnwidth or \textwidth
	Label       string
	Caption     string
	ShowFixture bool
	// Compact shortens the standard column and the prevalence cell so the
	// table stays legible at column width in a two-column layout.
	Compact   bool
	EmptyNote string
}

// compactStandard shortens the standard column for body tables: the first
// word of the standard's name from rule metadata, the control and the
// mapping type. Versions stay in the full tables and the artifact.
func compactStandard(c *analysis.Check) string {
	m := c.Rule
	if m == nil || (m.Standard == "" && m.ControlID == "" && m.Mapping == "") {
		return analysis.Unmapped
	}
	var parts []string
	if words := strings.Fields(m.Standard); len(words) > 0 {
		parts = append(parts, words[0])
	}
	if m.ControlID != "" {
		parts = append(parts, m.ControlID)
	}
	label := strings.Join(parts, " ")
	if label == "" {
		label = "ConUnit"
	}
	if m.Mapping != "" {
		label += " (" + string(m.Mapping) + ")"
	}
	return label
}

// compactPrevCell prints the estimate and interval without percent signs;
// the column header carries the unit.
func compactPrevCell(c *analysis.Check) string {
	if c.Prevalence == nil {
		return notAvailable
	}
	return fmt.Sprintf("%s [%s, %s]", pctNum(c.Prevalence.Estimate), pctNum(c.Prevalence.Lo), pctNum(c.Prevalence.Hi))
}

func renderCheckTable(checks []*analysis.Check, ts checkTableSpec) string {
	cols := "llllrr"
	head := `\textbf{Rule} & \textbf{Evaluated property} & \textbf{Standard mapping} & \textbf{Fail/Verified} & \textbf{Prevalence [95\% CI]} & \textbf{Unverified}`
	if ts.ShowFixture {
		cols = "lllllrr"
		head = `\textbf{Rule} & \textbf{Evaluated property} & \textbf{Standard mapping} & \textbf{Fail/Verified} & \textbf{Prevalence [95\% CI]} & \textbf{Fixture-only} & \textbf{Unverified}`
	}
	if ts.Compact {
		head = `\textbf{Rule} & \textbf{Property} & \textbf{Standard} & \textbf{Fail/N} & \textbf{Prev.\ \% [95\% CI]} & \textbf{Unv.}`
	}
	var w strings.Builder
	fmt.Fprintf(&w, "\\begin{%s}[t]\n", ts.Env)
	w.WriteString("\\centering\n\\small\n")
	fmt.Fprintf(&w, "\\caption{%s}\n\\label{%s}\n", ts.Caption, ts.Label)
	fmt.Fprintf(&w, "\\resizebox{%s}{!}{%%\n\\begin{tabular}{%s}\n\\toprule\n%s \\\\\n\\midrule\n", ts.Width, cols, head)
	if len(checks) == 0 {
		fmt.Fprintf(&w, "\\multicolumn{%d}{c}{%s} \\\\\n", len(cols), escapeLatex(ts.EmptyNote))
	}
	for _, c := range checks {
		standard, prev := c.Standard, prevCell(c)
		if ts.Compact {
			standard, prev = compactStandard(c), compactPrevCell(c)
		}
		fmt.Fprintf(&w, "%s & %s & %s & %d/%d & %s",
			texttt(c.ID), escapeLatex(c.Name), escapeLatex(standard), c.Fail, c.Verified, prev)
		if ts.ShowFixture {
			fmt.Fprintf(&w, " & %d", c.FixtureOnly)
		}
		fmt.Fprintf(&w, " & %d \\\\\n", c.Unverified)
	}
	w.WriteString("\\bottomrule\n\\end{tabular}}\n")
	fmt.Fprintf(&w, "\\end{%s}\n", ts.Env)
	return w.String()
}

func renderPrevalenceTable(a *analysis.Analysis) string {
	caption := fmt.Sprintf("Headline checks: confirmed failures over verified images with Wilson 95\\%% intervals. "+
		"Unverified (Unv.) images enter neither numerator nor denominator. $N = %d$ completed images.", a.Flow.Completed)
	return header(a, "Headline checks only (fixtures/headline_checks.json); compact layout for a two-column body") +
		renderCheckTable(a.ChecksOfClass(analysis.ClassHeadline), checkTableSpec{
			Env: "table", Width: `\columnwidth`, Label: "tab:rq2_prevalence", Caption: caption,
			Compact: true, EmptyNote: "no headline check has results",
		})
}

func renderExploratoryTable(a *analysis.Analysis) string {
	caption := fmt.Sprintf("Exploratory checks, reported for completeness and not used for headline claims. "+
		"Definitions as in the headline table. Fixture-only counts images whose candidate findings lie only under fixture-like paths "+
		"(testdata, tests, fixtures, examples); these are PASS. $N = %d$ completed images.", a.Flow.Completed)
	return header(a, "Exploratory checks (fixtures/headline_checks.json); excluded checks appear in no prevalence table") +
		renderCheckTable(a.ChecksOfClass(analysis.ClassExploratory), checkTableSpec{
			Env: "table*", Width: `\textwidth`, Label: "tab:rq2_exploratory", Caption: caption, ShowFixture: true,
			EmptyNote: "no exploratory check has results",
		})
}

func renderUnverifiedTable(a *analysis.Analysis) string {
	var w strings.Builder
	w.WriteString(header(a, "UNVERIFIED results by reason, all checks including excluded ones"))
	w.WriteString("\\begin{table}[t]\n\\centering\n\\footnotesize\n")
	fmt.Fprintf(&w, "\\caption{UNVERIFIED results by check and reason among %d completed images. "+
		"A result is UNVERIFIED when the evidence needed for PASS or FAIL is missing; it is excluded from prevalence.}\n", a.Flow.Completed)
	w.WriteString("\\label{tab:unverified}\n\\begin{tabular}{llrp{0.48\\columnwidth}}\n\\toprule\n")
	w.WriteString("\\textbf{Rule} & \\textbf{Role} & \\textbf{Count} & \\textbf{Reasons} \\\\\n\\midrule\n")
	rows := 0
	for _, c := range a.Checks {
		if c.Unverified == 0 {
			continue
		}
		rows++
		fmt.Fprintf(&w, "%s & %s & %d & %s \\\\\n", texttt(c.ID), escapeLatex(string(c.Class)), c.Unverified, countList(c.UnverifiedByReason, texttt))
	}
	if rows == 0 {
		w.WriteString("\\multicolumn{4}{c}{no UNVERIFIED result} \\\\\n")
	}
	w.WriteString("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
	return w.String()
}

// countList renders counts as `label (n), label (m)` in descending count
// order, ties by name.
func countList(m map[string]int, label func(string) string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s (%d)", label(k), m[k])
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Attrition

var knownStatuses = []string{
	spec.StatusTimeout, spec.StatusUnavailable, spec.StatusRateLimited,
	spec.StatusIndexLimit, spec.StatusExecutionError, spec.StatusExcluded,
}

// statusRows returns the non-completed statuses to print: all known ones,
// even with a zero count, followed by any other status found in the study.
func statusRows(a *analysis.Analysis) []string {
	rows := append([]string(nil), knownStatuses...)
	seen := map[string]bool{}
	for _, s := range rows {
		seen[s] = true
	}
	var extra []string
	for s := range a.Flow.ByStatus {
		if !seen[s] {
			extra = append(extra, s)
		}
	}
	sort.Strings(extra)
	return append(rows, extra...)
}

func mb(bytes int64) string { return fmt.Sprintf("%.1f", float64(bytes)/(1024*1024)) }

// statusSummary lists every non-completed status that occurred with its
// count. INDEX_LIMIT also names the largest image seen, because that status
// is a tool limit and its size matters.
func statusSummary(a *analysis.Analysis) string {
	parts := statusItems(a)
	switch len(parts) {
	case 0:
		return "none"
	case 1:
		return parts[0]
	}
	// One status per line keeps the column narrow, so the resized table
	// stays legible at column width.
	return `\begin{tabular}[t]{@{}l@{}}` + strings.Join(parts, ` \\ `) + `\end{tabular}`
}

// statusItems returns one entry per non-completed status that occurred.
func statusItems(a *analysis.Analysis) []string {
	var parts []string
	for _, s := range statusRows(a) {
		n := a.Flow.ByStatus[s]
		if n == 0 {
			continue
		}
		item := fmt.Sprintf("%s (%d", texttt(s), n)
		if s == spec.StatusIndexLimit {
			var largest int64
			for _, im := range a.Flow.IndexLimit {
				if im.UncompressedBytes > largest {
					largest = im.UncompressedBytes
				}
			}
			if largest > 0 {
				item += fmt.Sprintf("; largest %s MB", mb(largest))
			}
		}
		parts = append(parts, item+")")
	}
	return parts
}

// renderAttritionTable is the compact body table: about six rows. Per-status
// reasons, all status counts and the index-limit image sizes are in
// study_stats.json and in the ConUnitAttrition macros.
func renderAttritionTable(a *analysis.Analysis) string {
	var w strings.Builder
	w.WriteString(header(a, "Evaluation flow and attrition; compact layout for a two-column body"))
	w.WriteString("\\begin{table}[t]\n\\centering\n\\small\n")
	w.WriteString("\\caption{Evaluation flow from candidate images to analyzed images. Only COMPLETED images enter the statistics; " +
		"every other attempted image has a typed status, listed in the last row.}\n\\label{tab:attrition}\n")
	w.WriteString("\\resizebox{\\columnwidth}{!}{%\n\\begin{tabular}{lrl}\n\\toprule\n")
	w.WriteString("\\textbf{Stage} & \\textbf{Images} & \\textbf{Detail} \\\\\n\\midrule\n")

	cand, pinned := notAvailable, notAvailable
	candDetail, pinDetail := "dataset audit not available", ""
	if au := a.Audit; au != nil {
		cand = fmt.Sprint(au.Counts.Candidates)
		pinned = fmt.Sprint(au.Counts.Pinned)
		candDetail = "sampling frame not recorded"
		if au.Frame.Recorded() {
			candDetail = fmt.Sprintf("library commit %s, %s", short(au.Frame.Commit), au.Frame.Date)
		}
		pinDetail = au.Platform
	}
	fmt.Fprintf(&w, "Candidates & %s & %s \\\\\n", cand, escapeLatex(candDetail))
	if au := a.Audit; au != nil && au.Counts.Excluded+au.Counts.Failed > 0 {
		_, counts := au.ExclusionsByStatus()
		fmt.Fprintf(&w, "Excluded before pinning & %d & %s \\\\\n", au.Counts.Excluded+au.Counts.Failed, countList(counts, texttt))
	}
	fmt.Fprintf(&w, "Pinned by digest & %s & %s \\\\\n", pinned, escapeLatex(pinDetail))
	fmt.Fprintf(&w, "Attempted & %d & \\\\\n", a.Flow.Attempted)
	if runUsesAuditPinnedList(a) && a.Audit.Counts.Pinned > a.Flow.Attempted {
		fmt.Fprintf(&w, "Pinned, not attempted & %d & \\\\\n", a.Audit.Counts.Pinned-a.Flow.Attempted)
	}
	fmt.Fprintf(&w, "Completed (analyzed) & %d & \\\\\n", a.Flow.Completed)
	fmt.Fprintf(&w, "Not completed & %d & %s \\\\\n", a.Flow.NotCompleted, statusSummary(a))
	w.WriteString("\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
	return w.String()
}

// runUsesAuditPinnedList reports whether the run's dataset hash equals the
// pinned list recorded in the audit, so pinned versus attempted is
// comparable.
func runUsesAuditPinnedList(a *analysis.Analysis) bool {
	return a.Audit != nil && a.Run.DatasetSHA256 != "" && a.Run.DatasetSHA256 == a.Audit.Outputs.PinnedTxt.SHA256
}

// ---------------------------------------------------------------------------
// Strata

func renderStrataTable(a *analysis.Analysis) string {
	headline := a.ChecksOfClass(analysis.ClassHeadline)
	var w strings.Builder
	w.WriteString(header(a, "Headline checks by archetype and base family (fixtures/archetypes.json)"))
	w.WriteString("\\begin{table*}[t]\n\\centering\n\\small\n")
	fmt.Fprintf(&w, "\\caption{Confirmed failures per stratum for the headline checks, as fails/verified (percent). "+
		"The stratum size is the number of completed images. No weighting is applied and images are not independent, "+
		"because they share base layers and maintainers; intervals are therefore not given. $N = %d$.}\n", a.Flow.Completed)
	w.WriteString("\\label{tab:strata}\n\\resizebox{\\textwidth}{!}{%\n")
	fmt.Fprintf(&w, "\\begin{tabular}{ll%s}\n\\toprule\n", strings.Repeat("l", len(headline)))
	w.WriteString("\\textbf{Stratum} & \\textbf{Images}")
	for _, c := range headline {
		fmt.Fprintf(&w, " & %s", texttt(c.ID))
	}
	w.WriteString(" \\\\\n\\midrule\n")
	if len(headline) == 0 || len(a.Strata) == 0 {
		fmt.Fprintf(&w, "\\multicolumn{%d}{c}{no strata available} \\\\\n", 2+len(headline))
	}
	lastKind := ""
	for _, s := range a.Strata {
		if s.Kind != lastKind {
			if lastKind != "" {
				w.WriteString("\\midrule\n")
			}
			label := map[string]string{"archetype": "Archetype", "base_family": "Base family"}[s.Kind]
			fmt.Fprintf(&w, "\\multicolumn{%d}{l}{\\textit{%s}} \\\\\n", 2+len(headline), label)
			lastKind = s.Kind
		}
		fmt.Fprintf(&w, "\\quad %s & %d", escapeLatex(s.Name), s.Images)
		for _, c := range headline {
			cp := s.PerCheck[c.ID]
			if cp.Verified == 0 {
				fmt.Fprintf(&w, " & %d/%d", cp.Fail, cp.Verified)
				continue
			}
			fmt.Fprintf(&w, " & %d/%d (%.0f\\%%)", cp.Fail, cp.Verified, 100*float64(cp.Fail)/float64(cp.Verified))
		}
		w.WriteString(" \\\\\n")
	}
	w.WriteString("\\bottomrule\n\\end{tabular}}\n\\end{table*}\n")
	return w.String()
}

// ---------------------------------------------------------------------------
// RQ3 phase timings

type phaseColumn struct {
	Label string
	Get   func(*spec.SuiteResult) float64 // milliseconds
}

func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

var phaseColumns = []phaseColumn{
	{"Resolve", func(r *spec.SuiteResult) float64 {
		return millis(r.Phases.PullDuration + r.Phases.InspectDuration + r.Phases.ResolveDuration)
	}},
	{"Stream", func(r *spec.SuiteResult) float64 { return millis(r.Phases.StreamDuration) }},
	{"Tier 1", func(r *spec.SuiteResult) float64 { return millis(r.Phases.Tier1Duration) }},
	{"Tier 2", func(r *spec.SuiteResult) float64 { return millis(r.Phases.Tier2Duration) }},
	{"Tier 3", func(r *spec.SuiteResult) float64 { return millis(r.Phases.Tier3Duration) }},
	{"Tier 4", func(r *spec.SuiteResult) float64 { return millis(r.Phases.Tier4Duration) }},
	{"Total", func(r *spec.SuiteResult) float64 { return millis(r.Duration) }},
}

// probeWindow returns the Tier 3 observation window in seconds, or false when
// the study does not record it.
func probeWindow(a *analysis.Analysis) (float64, bool) {
	if a.Run.ProbeWindowMs > 0 {
		return float64(a.Run.ProbeWindowMs) / 1000, true
	}
	for _, r := range a.Completed {
		if r.Phases.ProbeWindow > 0 {
			return r.Phases.ProbeWindow.Seconds(), true
		}
	}
	return 0, false
}

func formatWindow(seconds float64) string {
	if seconds == math.Trunc(seconds) {
		return fmt.Sprintf("%d s", int(seconds))
	}
	return fmt.Sprintf("%.1f s", seconds)
}

func windowText(a *analysis.Analysis) string {
	if w, ok := probeWindow(a); ok {
		return formatWindow(w)
	}
	return "unknown"
}

// pickRepresentative selects up to n records at evenly spaced ranks of total
// duration, so tables and figures show the spread rather than an arbitrary
// prefix. The result is in ascending duration order.
func pickRepresentative(recs []*spec.SuiteResult, n int) []*spec.SuiteResult {
	sorted := append([]*spec.SuiteResult(nil), recs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Duration != sorted[j].Duration {
			return sorted[i].Duration < sorted[j].Duration
		}
		return studyfile.RecordKey(sorted[i]) < studyfile.RecordKey(sorted[j])
	})
	if len(sorted) <= n {
		return sorted
	}
	if n <= 1 {
		return sorted[:n]
	}
	out := make([]*spec.SuiteResult, 0, n)
	last := -1
	for i := 0; i < n; i++ {
		idx := int(math.Round(float64(i) * float64(len(sorted)-1) / float64(n-1)))
		if idx == last {
			continue
		}
		out = append(out, sorted[idx])
		last = idx
	}
	return out
}

func imageName(r *spec.SuiteResult) string { return studyfile.RepoName(studyfile.RecordKey(r)) }

// renderPhasesTable is the compact body table: four images at evenly spaced
// duration ranks plus median and interquartile range, six rows in all.
func renderPhasesTable(a *analysis.Analysis) string {
	var w strings.Builder
	w.WriteString(header(a, "Per-image phase timings of one evaluation pass; compact layout for a two-column body"))
	w.WriteString("\\begin{table}[t]\n\\centering\n\\small\n")
	shown := pickRepresentative(a.Completed, maxPhaseRows)
	fmt.Fprintf(&w, "\\caption{Single-pass phase timings in ms for %d images at evenly spaced duration ranks, with median and Q1--Q3 over all %d completed images. "+
		"Tier 3 observes each container for the window $W = $ %s, so it is bounded below by $W$ and is not a performance result. "+
		"Resolve covers pull, inspect and OCI resolution.}\n", len(shown), a.Flow.Completed, escapeLatex(windowText(a)))
	w.WriteString("\\label{tab:rq3_phases}\n\\resizebox{\\columnwidth}{!}{%\n")
	fmt.Fprintf(&w, "\\begin{tabular}{lr%s}\n\\toprule\n", strings.Repeat("r", len(phaseColumns)))
	w.WriteString("\\textbf{Image} & \\textbf{MB}")
	for _, c := range phaseColumns {
		label := strings.TrimPrefix(c.Label, "Tier ")
		switch c.Label {
		case "Tier 1", "Tier 2", "Tier 4":
			label = "T" + label
		case "Tier 3":
			label = `T3 ($\geq W$)`
		}
		fmt.Fprintf(&w, " & \\textbf{%s}", label)
	}
	w.WriteString(" \\\\\n\\midrule\n")

	sort.SliceStable(shown, func(i, j int) bool { return imageName(shown[i]) < imageName(shown[j]) })
	if len(shown) == 0 {
		fmt.Fprintf(&w, "\\multicolumn{%d}{c}{no completed image} \\\\\n", 2+len(phaseColumns))
	}
	for _, r := range shown {
		fmt.Fprintf(&w, "%s & %s", texttt(imageName(r)), mb(r.Resources.UncompressedBytes))
		for _, c := range phaseColumns {
			fmt.Fprintf(&w, " & %s", f1(c.Get(r)))
		}
		w.WriteString(" \\\\\n")
	}
	if len(a.Completed) > 0 {
		w.WriteString("\\midrule\n")
		sizes := make([]float64, 0, len(a.Completed))
		for _, r := range a.Completed {
			sizes = append(sizes, float64(r.Resources.UncompressedBytes)/(1024*1024))
		}
		ss := stats.Summarize(sizes)
		cols := make([]stats.Summary, len(phaseColumns))
		for i, c := range phaseColumns {
			vals := make([]float64, 0, len(a.Completed))
			for _, r := range a.Completed {
				vals = append(vals, c.Get(r))
			}
			cols[i] = stats.Summarize(vals)
		}
		fmt.Fprintf(&w, "\\textit{Median} & %s", f1(ss.Median))
		for _, s := range cols {
			fmt.Fprintf(&w, " & %s", f1(s.Median))
		}
		w.WriteString(" \\\\\n")
		fmt.Fprintf(&w, "\\textit{Q1--Q3} & %s--%s", f1(ss.Q1), f1(ss.Q3))
		for _, s := range cols {
			fmt.Fprintf(&w, " & %s--%s", f1(s.Q1), f1(s.Q3))
		}
		w.WriteString(" \\\\\n")
	}
	w.WriteString("\\bottomrule\n\\end{tabular}}\n\\end{table}\n")
	return w.String()
}

// ---------------------------------------------------------------------------
// Figures

func emptyFigure(a *analysis.Analysis, what, note string) string {
	return header(a, what) + "\\begin{tikzpicture}\n\\node[font=\\footnotesize] {" + escapeLatex(note) + "};\n\\end{tikzpicture}\n"
}

// ---------------------------------------------------------------------------
// RQ2 forest plot (fig:rq2_prevalence)

// Geometry of the RQ2 figure in millimetres. The figure is drawn at its final
// size, so it is never scaled. The nominal IEEEtran column is 88.9 mm, but
// \columnwidth of the conference class is 252 pt (88.57 mm), so the figure is
// drawn 0.5 mm narrower and TeX never reports an overfull box. Text is set at
// a fixed 7 pt so that its size does not depend on the document class.
const (
	forestWidth     = 88.0
	forestRowPitch  = 4.3 // one row per headline check
	forestHeader    = 6.6 // two header lines above the first row
	forestAxisBand  = 4.2 // ticks and tick labels below the last row
	forestLegendGap = 2.6 // between the tick labels and the first legend row
	forestLegendRow = 3.3
	forestBarHeight = 2.7
	forestSwatchW   = 4.0
	forestSwatchH   = 2.2
	forestCapHalf   = 0.8

	// Width estimates for 7 pt sans serif text, used only to size columns;
	// they are deliberately a little generous.
	forestCharMM    = 1.55
	forestDigitMM   = 1.3
	forestSlashMM   = 1.2
	forestMinLabel  = 9.0
	forestMaxChars  = 12 // longer check IDs end with two dots
	forestMinCount  = 9.4
	forestMinUnv    = 5.6
	forestGapLabel  = 2.2
	forestGapCount  = 2.0
	forestGapBar    = 1.6
	forestGapUnv    = 1.2
	forestPlotShare = 0.54 // share of the free width given to the forest panel

	// forestNamedReasons is the number of UNVERIFIED reasons that get their own
	// bar segment and legend entry; the rest are pooled as Other.
	forestNamedReasons = 3
	// forestPendingRows sizes the pending frame when no check exists yet.
	forestPendingRows = 7

	forestPendingText   = "pending: generated from the final run"
	forestPrevalenceLbl = "fig:rq2_prevalence"
)

// forestPalette is the shared figure palette (Okabe-Ito based). It uses
// \providecolor, so the file compiles on its own and never redefines a color
// the paper already set.
const forestPalette = `\providecolor{cuTone}{HTML}{0072B2}
\providecolor{cuTtwo}{HTML}{56B4E9}
\providecolor{cuTthree}{HTML}{E69F00}
\providecolor{cuTfour}{HTML}{CC79A7}
\providecolor{cuPass}{HTML}{009E73}
\providecolor{cuFail}{HTML}{D55E00}
\providecolor{cuUnver}{HTML}{7F7F7F}
\providecolor{cuInk}{HTML}{222222}
\providecolor{cuLine}{HTML}{555555}
\providecolor{cuPaper}{HTML}{F5F5F5}
`

// forestStyles are the TikZ options shared by the figure and its pending
// frame. Bar segments pair a gray shade with a hatch pattern, so the reasons
// stay apart in grayscale.
const forestStyles = `x=1mm,y=1mm,
  every node/.style={inner sep=0pt,outer sep=0pt,text=cuInk,font=\sffamily\fontsize{7}{8}\selectfont},
  cuBand/.style={fill=cuPaper},
  cuGrid/.style={draw=cuLine!30,line width=0.25pt},
  cuAxis/.style={draw=cuLine,line width=0.4pt},
  cuWhisker/.style={draw=cuInk,line width=0.6pt},
  cuDot/.style={circle,fill=cuInk,draw=white,line width=0.3pt,minimum size=1.8mm},
  cuSegV/.style={fill=cuInk!75,draw=cuInk,line width=0.25pt},
  cuSegA/.style={preaction={fill=cuUnver!28},pattern=north east lines,pattern color=cuInk!85,draw=cuInk,line width=0.25pt},
  cuSegB/.style={preaction={fill=cuUnver!14},pattern=crosshatch dots,pattern color=cuInk!85,draw=cuInk,line width=0.25pt},
  cuSegC/.style={preaction={fill=cuUnver!14},pattern=horizontal lines,pattern color=cuInk!85,draw=cuInk,line width=0.25pt},
  cuSegO/.style={fill=cuUnver!12,draw=cuInk,line width=0.25pt}`

// forestSegStyles names the bar styles in legend order: verified, the named
// reasons, then Other.
var forestSegStyles = [...]string{"cuSegV", "cuSegA", "cuSegB", "cuSegC", "cuSegO"}

// forestSegment is one stacked bar segment: a style index into
// forestSegStyles and a number of results.
type forestSegment struct {
	Style int
	Count int
}

// forestRow is one headline check of the figure.
type forestRow struct {
	Check    *analysis.Check
	Short    string // check ID shortened to forestMaxChars, not escaped
	Segments []forestSegment
	Total    int // verified plus unverified results of the check
}

// forestLegend is one legend entry.
type forestLegend struct {
	Style int
	Label string // already escaped
}

// forestLayout holds the column positions in millimetres, measured from the
// left edge of the picture.
type forestLayout struct {
	LabelRight                float64
	PlotX0, PlotW             float64
	FailRight, Slash, VerLeft float64
	CountX0, CountW           float64
	BarX0, BarW               float64
	UnvRight, UnvW            float64
	FirstRow, Axis, Legend0   float64 // y positions; rows run downward from 0
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

func digits(n int) int { return len(fmt.Sprint(n)) }

// forestShort shortens a check ID to forestMaxChars characters; the last two
// become dots. The full ID stays in the comment of the row.
func forestShort(id string) string {
	r := []rune(id)
	if len(r) > forestMaxChars {
		r = append(append([]rune(nil), r[:forestMaxChars-2]...), '.', '.')
	}
	return string(r)
}

// forestRows prepares one row per headline check in table order, including
// checks without a verified image. UNVERIFIED reasons are ranked by their
// total over the figure (ties by name); the first forestNamedReasons get a
// segment of their own and the rest are pooled as Other.
func forestRows(a *analysis.Analysis) ([]forestRow, []forestLegend) {
	checks := a.ChecksOfClass(analysis.ClassHeadline)
	totals := map[string]int{}
	for _, c := range checks {
		for reason, n := range c.UnverifiedByReason {
			totals[reason] += n
		}
	}
	reasons := make([]string, 0, len(totals))
	for r, n := range totals {
		if n > 0 {
			reasons = append(reasons, r)
		}
	}
	sort.Slice(reasons, func(i, j int) bool {
		if totals[reasons[i]] != totals[reasons[j]] {
			return totals[reasons[i]] > totals[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	named := reasons
	if len(named) > forestNamedReasons {
		named = reasons[:forestNamedReasons]
	}
	styleOf := map[string]int{}
	legend := []forestLegend{{Style: 0, Label: "Verified"}}
	for i, r := range named {
		styleOf[r] = i + 1
		legend = append(legend, forestLegend{Style: i + 1, Label: escapeLatex(shortenReason(r))})
	}
	other := len(forestSegStyles) - 1
	var rows []forestRow
	pooled := false
	for _, c := range checks {
		row := forestRow{Check: c, Short: forestShort(c.ID)}
		add := func(style, n int) {
			if n > 0 {
				row.Segments = append(row.Segments, forestSegment{Style: style, Count: n})
				row.Total += n
			}
		}
		add(0, c.Verified)
		for _, r := range named {
			add(styleOf[r], c.UnverifiedByReason[r])
		}
		pool := 0
		for _, r := range reasons[len(named):] {
			pool += c.UnverifiedByReason[r]
		}
		if pool > 0 {
			pooled = true
		}
		add(other, pool)
		rows = append(rows, row)
	}
	if pooled {
		legend = append(legend, forestLegend{Style: other, Label: "Other"})
	}
	return rows, legend
}

// shortenReason limits a reason token in the legend to 22 characters.
func shortenReason(r string) string {
	if rs := []rune(r); len(rs) > 22 {
		return string(rs[:20]) + ".."
	}
	return r
}

// newForestLayout sizes the columns from the data: the label column from the
// longest check ID, the count columns from the number of digits. The forest
// panel and the stacked bar share what remains.
func newForestLayout(rows []forestRow) forestLayout {
	maxChars, failDigits, verDigits, unvDigits := 1, 1, 1, 1
	for _, r := range rows {
		maxChars = max(maxChars, len([]rune(r.Short)))
		failDigits = max(failDigits, digits(r.Check.Fail))
		verDigits = max(verDigits, digits(r.Check.Verified))
		unvDigits = max(unvDigits, digits(r.Check.Unverified))
	}
	var l forestLayout
	l.setRows(len(rows))
	l.LabelRight = round1(math.Max(forestMinLabel, forestCharMM*float64(maxChars)+0.6))
	failW := float64(failDigits) * forestDigitMM
	verW := float64(verDigits) * forestDigitMM
	l.CountW = round1(math.Max(forestMinCount, failW+forestSlashMM+verW))
	l.UnvW = round1(math.Max(forestMinUnv, float64(unvDigits)*forestDigitMM))
	fixed := l.LabelRight + forestGapLabel + forestGapCount + forestGapBar + forestGapUnv + l.CountW + l.UnvW
	free := forestWidth - fixed
	l.PlotW = round1(forestPlotShare * free)
	l.BarW = round1(free - l.PlotW)
	l.PlotX0 = round1(l.LabelRight + forestGapLabel)
	l.CountX0 = round1(l.PlotX0 + l.PlotW + forestGapCount)
	// The numbers fail/verified form one group centered in the column; the
	// slash is the fixed point, so slashes line up across rows.
	group := failW + forestSlashMM + verW
	l.Slash = round1(l.CountX0 + (l.CountW-group)/2 + failW + forestSlashMM/2)
	l.FailRight = round1(l.Slash - forestSlashMM/2)
	l.VerLeft = round1(l.Slash + forestSlashMM/2)
	l.BarX0 = round1(l.CountX0 + l.CountW + forestGapBar)
	l.UnvRight = forestWidth
	return l
}

// setRows fixes the vertical positions for a number of rows. The y axis runs
// upward, so rows lie at negative y below the header.
func (l *forestLayout) setRows(rows int) {
	l.FirstRow = -forestHeader
	l.Axis = l.FirstRow - float64(rows)*forestRowPitch
	l.Legend0 = l.Axis - forestAxisBand - forestLegendGap
}

func (l forestLayout) rowCenter(i int) float64 {
	return l.FirstRow - (float64(i)+0.5)*forestRowPitch
}

// height is the distance from the top edge of the figure to the bottom of the
// last legend row.
func (l forestLayout) height(legendRows int) float64 {
	return -l.Legend0 + forestLegendRow*float64(legendRows-1) + forestSwatchH/2
}

// mm formats a length with two decimals.
func mm(x float64) string { return fmt.Sprintf("%.2f", x) }

// prevalenceCaption is shared by the figure and its pending frame. With no
// completed image the number of images is omitted and the caption carries the
// same marker as the placeholder files of the paper.
func prevalenceCaption(a *analysis.Analysis) string {
	caption := "Prevalence of confirmed failures per headline check. " +
		"Left: confirmed failures over verified images with Wilson 95\\% intervals, and the counts. " +
		"Right: share of verified and UNVERIFIED results by reason, and the number of UNVERIFIED results (Unv.). " +
		"Unverified images enter neither numerator nor denominator."
	if a.Flow.Completed == 0 {
		return caption + " \\textbf{[pending: generated from the final run]}"
	}
	return caption + fmt.Sprintf(" $N = %d$ completed images.", a.Flow.Completed)
}

// forestPreamble is the generated-file header followed by the requirement
// note and the palette.
func forestPreamble(a *analysis.Analysis, what string) string {
	return header(a, what) +
		"% Requires: \\usetikzlibrary{patterns} (tikz and xcolor are loaded by the paper; no pgfplots)\n" +
		forestPalette
}

// renderPrevalenceFigure writes the RQ2 forest plot as a complete figure
// float: one row per headline check with the prevalence point and its Wilson
// interval, the failing over verified counts, and the stacked composition of
// verified and UNVERIFIED results. Without a verified headline check it
// writes a pending frame of the same size, caption and label.
func renderPrevalenceFigure(a *analysis.Analysis) string {
	const what = "RQ2 forest plot: prevalence of confirmed failures per headline check with Wilson 95 percent intervals, and verified versus UNVERIFIED results"
	rows, legend := forestRows(a)
	hasVerified := false
	for _, r := range rows {
		if r.Check.Prevalence != nil {
			hasVerified = true
		}
	}
	if a.Flow.Completed == 0 || !hasVerified {
		n := len(rows)
		if n == 0 {
			n = forestPendingRows
		}
		return forestPreamble(a, what) + pendingFigure(a, n)
	}

	l := newForestLayout(rows)
	legendRows := 1
	if len(legend) > 3 {
		legendRows = 2
	}
	var w strings.Builder
	w.WriteString(forestPreamble(a, what))
	w.WriteString("% Rows follow the headline table. Left panel x values are percent of verified images;\n")
	w.WriteString("% bar x values are result counts. Check IDs are shortened in the label only.\n")
	w.WriteString("\\begin{figure}[t]\n\\centering\n")
	w.WriteString("\\begin{tikzpicture}[" + forestStyles + "]\n")

	// Row bands tie the two panels together.
	for i := range rows {
		if i%2 == 1 {
			fmt.Fprintf(&w, "\\path[cuBand] (0,%s) rectangle (%s,%s);\n", mm(l.FirstRow-float64(i)*forestRowPitch), mm(forestWidth), mm(l.FirstRow-float64(i+1)*forestRowPitch))
		}
	}

	// Headers.
	head := func(x float64, line1, line2 string) {
		if line1 != "" {
			fmt.Fprintf(&w, "\\node[anchor=base] at (%s,%s) {%s};\n", mm(x), mm(-2.5), line1)
		}
		fmt.Fprintf(&w, "\\node[anchor=base] at (%s,%s) {%s};\n", mm(x), mm(-5.3), line2)
	}
	head(l.PlotX0+l.PlotW/2, `\bfseries Confirmed failures`, `\% of verified, 95\% CI`)
	head(l.CountX0+l.CountW/2, `fail/`, `verified`)
	head(l.BarX0+l.BarW/2, `\bfseries Verification`, `\% of results`)
	head(l.UnvRight-l.UnvW/2, "", `Unv.`)

	// Forest panel: grid, axis and ticks, in percent units.
	fmt.Fprintf(&w, "\\begin{scope}[xshift=%smm,x=%smm]\n", mm(l.PlotX0), fmt.Sprintf("%.3f", l.PlotW/100))
	for _, t := range []int{0, 25, 50, 75, 100} {
		fmt.Fprintf(&w, "\\draw[cuGrid] (%d,%s) -- (%d,%s);\n", t, mm(l.FirstRow), t, mm(l.Axis))
	}
	fmt.Fprintf(&w, "\\draw[cuAxis] (0,%s) -- (100,%s);\n", mm(l.Axis), mm(l.Axis))
	for _, t := range []int{0, 25, 50, 75, 100} {
		fmt.Fprintf(&w, "\\draw[cuAxis] (%d,%s) -- (%d,%s);\n", t, mm(l.Axis), t, mm(l.Axis-0.8))
		fmt.Fprintf(&w, "\\node[anchor=base] at (%d,%s) {%d};\n", t, mm(l.Axis-3.0), t)
	}
	for i, r := range rows {
		c := r.Check
		y := l.rowCenter(i)
		p := c.Prevalence
		if p == nil {
			fmt.Fprintf(&w, "\\node[anchor=base,text=cuLine] at (50,%s) {\\itshape n/a};\n", mm(y-0.85))
			continue
		}
		fmt.Fprintf(&w, "\\draw[cuWhisker] (%s,%s) -- (%s,%s);\n", pctNum(p.Lo), mm(y), pctNum(p.Hi), mm(y))
		for _, x := range []float64{p.Lo, p.Hi} {
			fmt.Fprintf(&w, "\\draw[cuWhisker] (%s,%s) -- (%s,%s);\n", pctNum(x), mm(y-forestCapHalf), pctNum(x), mm(y+forestCapHalf))
		}
		fmt.Fprintf(&w, "\\node[cuDot] at (%s,%s) {};\n", pctNum(p.Estimate), mm(y))
	}
	w.WriteString("\\end{scope}\n")

	// Row labels, counts and the unverified column.
	for i, r := range rows {
		c := r.Check
		base := mm(l.rowCenter(i) - 0.85)
		fmt.Fprintf(&w, "%% %s: fail %d, verified %d, unverified %d", c.ID, c.Fail, c.Verified, c.Unverified)
		if c.Prevalence != nil {
			fmt.Fprintf(&w, ", prevalence %s [%s, %s]", pctNum(c.Prevalence.Estimate), pctNum(c.Prevalence.Lo), pctNum(c.Prevalence.Hi))
		}
		w.WriteString("\n")
		fmt.Fprintf(&w, "\\node[anchor=base east] at (%s,%s) {%s};\n", mm(l.LabelRight), base, escapeLatex(r.Short))
		fmt.Fprintf(&w, "\\node[anchor=base east] at (%s,%s) {%d};\n", mm(l.FailRight), base, c.Fail)
		fmt.Fprintf(&w, "\\node[anchor=base] at (%s,%s) {/};\n", mm(l.Slash), base)
		fmt.Fprintf(&w, "\\node[anchor=base west] at (%s,%s) {%d};\n", mm(l.VerLeft), base, c.Verified)
		fmt.Fprintf(&w, "\\node[anchor=base east] at (%s,%s) {%d};\n", mm(l.UnvRight), base, c.Unverified)
	}

	// Bar axis, drawn before the bars so that the bars cover the grid.
	fmt.Fprintf(&w, "\\begin{scope}[xshift=%smm,x=%.3fmm]\n", mm(l.BarX0), l.BarW/100)
	for _, t := range []int{0, 50, 100} {
		fmt.Fprintf(&w, "\\draw[cuGrid] (%d,%s) -- (%d,%s);\n", t, mm(l.FirstRow), t, mm(l.Axis))
	}
	fmt.Fprintf(&w, "\\draw[cuAxis] (0,%s) -- (100,%s);\n", mm(l.Axis), mm(l.Axis))
	for _, t := range []int{0, 50, 100} {
		fmt.Fprintf(&w, "\\draw[cuAxis] (%d,%s) -- (%d,%s);\n", t, mm(l.Axis), t, mm(l.Axis-0.8))
		fmt.Fprintf(&w, "\\node[anchor=base] at (%d,%s) {%d};\n", t, mm(l.Axis-3.0), t)
	}
	w.WriteString("\\end{scope}\n")

	// Stacked bars. Each row has its own x scale, so segment edges are
	// cumulative result counts and the last edge is verified plus unverified.
	for i, r := range rows {
		y := l.rowCenter(i)
		y0, y1 := y-forestBarHeight/2, y+forestBarHeight/2
		if r.Total == 0 {
			fmt.Fprintf(&w, "\\draw[cuAxis] (%s,%s) rectangle (%s,%s);\n", mm(l.BarX0), mm(y0), mm(l.BarX0+l.BarW), mm(y1))
			continue
		}
		fmt.Fprintf(&w, "\\begin{scope}[xshift=%smm,x=%.5fmm]\n", mm(l.BarX0), l.BarW/float64(r.Total))
		cum := 0
		for _, s := range r.Segments {
			fmt.Fprintf(&w, "\\path[%s] (%d,%s) rectangle (%d,%s);\n", forestSegStyles[s.Style], cum, mm(y0), cum+s.Count, mm(y1))
			cum += s.Count
		}
		w.WriteString("\\end{scope}\n")
	}

	w.WriteString(forestLegendTikz(l, legend, legendRows))
	w.WriteString("\\end{tikzpicture}\n")
	fmt.Fprintf(&w, "\\caption{%s}\n\\label{%s}\n\\end{figure}\n", prevalenceCaption(a), forestPrevalenceLbl)
	return w.String()
}

// forestLegendTikz places the legend entries in rows of up to three. Each
// swatch and label is chained to the previous label with a fixed gap, so TeX
// measures the text and no width is guessed here.
func forestLegendTikz(l forestLayout, legend []forestLegend, rows int) string {
	var w strings.Builder
	per := 3
	if rows == 1 {
		per = len(legend)
	}
	prev := ""
	for k, e := range legend {
		row, col := k/per, k%per
		y := l.Legend0 - float64(row)*forestLegendRow
		swatch := fmt.Sprintf("lg%ds", k)
		text := fmt.Sprintf("lg%dt", k)
		at := fmt.Sprintf("(0,%s)", mm(y))
		if col > 0 {
			at = fmt.Sprintf("([xshift=3.4mm,yshift=0.85mm]%s.base east)", prev)
		}
		fmt.Fprintf(&w, "\\node[anchor=west,minimum width=%.1fmm,minimum height=%.1fmm] (%s) at %s {};\n", forestSwatchW, forestSwatchH, swatch, at)
		fmt.Fprintf(&w, "\\path[%s] (%s.south west) rectangle (%s.north east);\n", forestSegStyles[e.Style], swatch, swatch)
		fmt.Fprintf(&w, "\\node[anchor=base west] (%s) at ([xshift=1.4mm,yshift=-0.85mm]%s.east) {%s};\n", text, swatch, e.Label)
		prev = text
	}
	return w.String()
}

// pendingFigure is the figure float shown until the final run is exported: a
// dashed rounded frame of the size of the real figure with the same caption
// and label, so references resolve. Everything after the palette is the
// content of the committed placeholder file.
func pendingFigure(a *analysis.Analysis, rows int) string {
	var l forestLayout
	l.setRows(rows)
	h := l.height(2)
	var w strings.Builder
	w.WriteString("\\begin{figure}[t]\n\\centering\n")
	w.WriteString("\\begin{tikzpicture}[" + forestStyles + "]\n")
	fmt.Fprintf(&w, "\\draw[dashed,rounded corners=2mm,draw=cuLine,fill=cuPaper,line width=0.6pt] (0,0) rectangle (%s,%s);\n", mm(forestWidth), mm(-h))
	fmt.Fprintf(&w, "\\node[text=cuLine] at (%s,%s) {%s};\n", mm(forestWidth/2), mm(-h/2), forestPendingText)
	w.WriteString("\\end{tikzpicture}\n")
	fmt.Fprintf(&w, "\\caption{%s}\n\\label{%s}\n\\end{figure}\n", prevalenceCaption(a), forestPrevalenceLbl)
	return w.String()
}

var unsafeCoord = regexp.MustCompile(`[^A-Za-z0-9.\-]`)

// coordLabel makes an image name safe for use as a pgfplots symbolic
// coordinate and unique within one figure.
func coordLabel(name string, used map[string]bool, max int) string {
	label := unsafeCoord.ReplaceAllString(name, "-")
	if len(label) > max {
		label = label[:max-2] + ".."
	}
	base, n := label, 1
	for used[label] {
		n++
		label = fmt.Sprintf("%s-%d", base, n)
	}
	used[label] = true
	return label
}

func renderPhaseFigure(a *analysis.Analysis) string {
	const what = "Per-image phase breakdown of one evaluation pass (pgfplots); Tier 3 is bounded below by the probe window"
	shown := pickRepresentative(a.Completed, 8)
	if len(shown) == 0 {
		return emptyFigure(a, what, "No completed image")
	}
	used := map[string]bool{}
	coords := make([]string, len(shown))
	for i, r := range shown {
		coords[i] = coordLabel(imageName(r), used, 18)
	}
	type series struct {
		label, fill string
		get         func(*spec.SuiteResult) time.Duration
	}
	all := []series{
		{"Pull and resolve", "blue!60!black", func(r *spec.SuiteResult) time.Duration {
			return r.Phases.PullDuration + r.Phases.InspectDuration + r.Phases.ResolveDuration
		}},
		{"Stream and index", "teal!70!black", func(r *spec.SuiteResult) time.Duration { return r.Phases.StreamDuration }},
		{"Tiers 1 and 2", "orange!80!black", func(r *spec.SuiteResult) time.Duration { return r.Phases.Tier1Duration + r.Phases.Tier2Duration }},
		{"Tier 3 (window-bounded)", "violet!70!black", func(r *spec.SuiteResult) time.Duration { return r.Phases.Tier3Duration }},
		{"Tier 4", "gray!70!black", func(r *spec.SuiteResult) time.Duration { return r.Phases.Tier4Duration }},
	}
	var w strings.Builder
	w.WriteString(header(a, what))
	w.WriteString("% Images are chosen at evenly spaced ranks of total duration.\n")
	w.WriteString("\\begin{tikzpicture}\n\\begin{axis}[\n    xbar stacked,\n    width=0.88\\columnwidth,\n")
	fmt.Fprintf(&w, "    height=%.1fcm,\n", math.Max(4.8, float64(len(shown))*0.65+1.2))
	w.WriteString("    xlabel={Duration of one pass (seconds)},\n")
	fmt.Fprintf(&w, "    symbolic y coords={%s},\n", strings.Join(coords, ","))
	w.WriteString("    ytick=data,\n    xmin=0,\n    enlarge y limits=0.12,\n    bar width=9pt,\n    y dir=reverse,\n")
	w.WriteString("    legend style={at={(0.5,-0.25)}, anchor=north, legend columns=2, font=\\footnotesize},\n")
	w.WriteString("    tick label style={font=\\footnotesize},\n    label style={font=\\small},\n]\n")
	for _, s := range all {
		fmt.Fprintf(&w, "\\addplot[fill=%s] coordinates {\n", s.fill)
		for i, r := range shown {
			fmt.Fprintf(&w, "    (%.3f,%s)\n", s.get(r).Seconds(), coords[i])
		}
		fmt.Fprintf(&w, "};\n\\addlegendentry{%s}\n", s.label)
	}
	w.WriteString("\\end{axis}\n\\end{tikzpicture}\n")
	return w.String()
}

func renderMemoryFigure(a *analysis.Analysis) string {
	const what = "ConUnit process memory versus image size (pgfplots); memory is the ConUnit process only, not engine or containers"
	type point struct{ x, y float64 }
	useLive := true
	haveData := 0
	for _, r := range a.Completed {
		if r.Resources.UncompressedBytes <= 0 {
			continue
		}
		haveData++
		if r.Resources.LiveHeapMB <= 0 {
			// Mixed or legacy telemetry: fall back to one consistent series.
			useLive = false
		}
	}
	if haveData == 0 {
		return emptyFigure(a, what, "No resource telemetry")
	}
	var pts []point
	for _, r := range a.Completed {
		if r.Resources.UncompressedBytes <= 0 {
			continue
		}
		y := r.Resources.AllocMB
		if useLive {
			y = r.Resources.LiveHeapMB
		}
		pts = append(pts, point{float64(r.Resources.UncompressedBytes) / (1024 * 1024), y})
	}
	sort.Slice(pts, func(i, j int) bool {
		if pts[i].x != pts[j].x {
			return pts[i].x < pts[j].x
		}
		return pts[i].y < pts[j].y
	})
	ylabel := "ConUnit in-use heap (MB)"
	if useLive {
		ylabel = "ConUnit live heap after GC (MB)"
	}
	var w strings.Builder
	w.WriteString(header(a, what))
	w.WriteString("\\begin{tikzpicture}\n\\begin{axis}[\n    width=0.88\\columnwidth,\n    height=5.5cm,\n")
	w.WriteString("    xlabel={Uncompressed filesystem size scanned (MB)},\n")
	fmt.Fprintf(&w, "    ylabel={%s},\n", ylabel)
	w.WriteString("    xmin=0, ymin=0,\n    tick label style={font=\\footnotesize},\n    label style={font=\\small},\n]\n")
	w.WriteString("\\addplot[only marks, mark=*, mark size=1.4pt, blue!70!black] coordinates {\n")
	for _, p := range pts {
		fmt.Fprintf(&w, "    (%.2f,%.2f)\n", p.x, p.y)
	}
	w.WriteString("};\n\\end{axis}\n\\end{tikzpicture}\n")
	return w.String()
}

// ---------------------------------------------------------------------------
// Macros

type macro struct{ name, value string }

var macroNamePattern = regexp.MustCompile(`^[A-Za-z]+$`)

func intStr(n int) string { return fmt.Sprint(n) }

func orNA(s string, ok bool) string {
	if !ok {
		return notAvailable
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func renderMacros(a *analysis.Analysis) (string, error) {
	var list []macro
	add := func(name, value string) { list = append(list, macro{"ConUnit" + name, value}) }

	// Flow.
	cand, pinned, preExcl := notAvailable, notAvailable, notAvailable
	frameCommit, frameDate := notAvailable, notAvailable
	if au := a.Audit; au != nil {
		cand = intStr(au.Counts.Candidates)
		pinned = intStr(au.Counts.Pinned)
		preExcl = intStr(au.Counts.Excluded + au.Counts.Failed)
		if au.Frame.Recorded() {
			frameCommit, frameDate = escapeLatex(short(au.Frame.Commit)), escapeLatex(au.Frame.Date)
		}
	}
	add("NCandidates", cand)
	add("NPinned", pinned)
	add("NPreExcluded", preExcl)
	add("FrameCommit", frameCommit)
	add("FrameDate", frameDate)
	add("NAttempted", intStr(a.Flow.Attempted))
	add("NCompleted", intStr(a.Flow.Completed))
	add("NAttrition", intStr(a.Flow.NotCompleted))
	for _, s := range knownStatuses {
		add("Attrition"+camel(s), intStr(a.Flow.ByStatus[s]))
	}
	add("InfraAttrition", intStr(a.Flow.Infrastructure))
	if a.Flow.InfrastructureShare != nil {
		add("InfraAttritionPct", pctTex(a.Flow.InfrastructureShare.Estimate))
	} else {
		add("InfraAttritionPct", notAvailable)
	}

	// Variant tags of the completed images, from the pinned dataset. Without
	// the dataset the tags are unknown and every count is not available.
	// The repository name is excluded so that alpine:3.24.3 is not an alpine variant (28, not 29).
	nAlpine, nSlim, nTagged := notAvailable, notAvailable, notAvailable
	if t := a.Tags; t != nil {
		nAlpine, nSlim, nTagged = intStr(t.Alpine), intStr(t.Slim), intStr(t.Tagged)
	}
	add("NAlpineTag", nAlpine)
	add("NSlimTag", nSlim)
	add("NTagged", nTagged)

	// Environment, taken from the run block only.
	run := a.Run
	engine := strings.TrimSpace(run.EngineName + " " + run.EngineVersion)
	commit := short(run.Commit)
	if run.Commit != "" && (run.CommitDirty || run.Tainted) {
		commit += "+dirty"
	}
	memGiB := ""
	if run.MemoryBytes > 0 {
		memGiB = f1(float64(run.MemoryBytes) / (1 << 30))
	}
	date := ""
	if !run.StartedAt.IsZero() {
		date = run.StartedAt.UTC().Format("2006-01-02")
	}
	rootless := ""
	if run.Rootless != nil {
		rootless = map[bool]string{true: "yes", false: "no"}[*run.Rootless]
	}
	vcpus := ""
	if run.VCPUs > 0 {
		vcpus = intStr(run.VCPUs)
	}
	tainted := "no"
	if run.Tainted || run.CommitDirty {
		tainted = "yes"
	}
	window := ""
	if w, ok := probeWindow(a); ok {
		window = formatWindow(w)
	}
	env := func(name, value string) { add("Env"+name, escapeLatex(orUnknown(value))) }
	env("InstanceType", run.InstanceType)
	env("Engine", engine)
	env("Kernel", run.LinuxKernel)
	env("Virt", run.Virtualization)
	env("AMI", run.AMIID)
	env("Commit", commit)
	env("CommitFull", run.Commit)
	env("OS", run.HostOS)
	env("CPU", run.CPUModel)
	env("Date", date)
	env("Region", run.Region)
	env("VCPUs", vcpus)
	env("MemoryGiB", memGiB)
	env("Rootless", rootless)
	env("StorageDriver", run.StorageDriver)
	env("OCIRuntime", run.OCIRuntime)
	env("CgroupVersion", run.CgroupVersion)
	env("ExecutionMode", run.ExecutionMode)
	env("Platform", run.Platform)
	env("ImageSource", run.ImageSource)
	env("RegistryRemap", run.RegistryRemap)
	env("Pack", firstNonEmpty(run.PackID, run.Pack))
	env("Version", run.ConUnitVersion)
	env("DatasetSHA", short(run.DatasetSHA256))
	env("Tainted", tainted)
	env("ProbeWindow", window)

	// Per-image distribution of confirmed failures among verified checks.
	add("NHeadlineChecks", intStr(len(a.ChecksOfClass(analysis.ClassHeadline))))
	add("NExploratoryChecks", intStr(len(a.ChecksOfClass(analysis.ClassExploratory))))
	for _, fam := range []struct{ key, suffix string }{{"headline", "Headline"}, {"all", "All"}} {
		d := a.Distribution[fam.key]
		cf, vc := d.ConfirmedFailures, d.VerifiedChecks
		has := cf.N > 0
		add("ImgFailMean"+fam.suffix, orNA(f1(cf.Mean), has))
		add("ImgFailSD"+fam.suffix, orNA(f1(cf.SD), cf.SDOK))
		add("ImgFailMedian"+fam.suffix, orNA(numStr(cf.Median), has))
		add("ImgFailQOne"+fam.suffix, orNA(numStr(cf.Q1), has))
		add("ImgFailQThree"+fam.suffix, orNA(numStr(cf.Q3), has))
		add("ImgFailMin"+fam.suffix, orNA(numStr(cf.Min), has))
		add("ImgFailMax"+fam.suffix, orNA(numStr(cf.Max), has))
		add("ImgVerifiedMedian"+fam.suffix, orNA(numStr(vc.Median), has))
		add("ImgVerifiedMin"+fam.suffix, orNA(numStr(vc.Min), has))
		add("ImgVerifiedMax"+fam.suffix, orNA(numStr(vc.Max), has))
		add("ImgNoFail"+fam.suffix, intStr(d.NoConfirmedFailure))
		add("ImgNoVerified"+fam.suffix, intStr(d.NoVerifiedCheck))
	}

	// Batch memory ceiling: the only per-process memory figure kept.
	var peak float64
	for _, r := range a.Records {
		if r.Resources.PeakRSSMB > peak {
			peak = r.Resources.PeakRSSMB
		}
	}
	add("BatchPeakRSS", f1(peak))

	// Per-check macros. Excluded checks get counts but no prevalence.
	seenKey := map[string]string{}
	for _, c := range a.Checks {
		key := idKey(c.ID)
		if key == "" {
			return "", fmt.Errorf("rule ID %q has no letters or digits to build a macro name from", c.ID)
		}
		if prev, dup := seenKey[key]; dup {
			return "", fmt.Errorf("rule IDs %q and %q map to the same macro key %q", prev, c.ID, key)
		}
		seenKey[key] = c.ID
		if c.Class != analysis.ClassExcluded {
			prev, lo, hi := notAvailable, notAvailable, notAvailable
			if c.Prevalence != nil {
				prev, lo, hi = pctTex(c.Prevalence.Estimate), pctTex(c.Prevalence.Lo), pctTex(c.Prevalence.Hi)
			}
			add("Prev"+key, prev)
			add("PrevLo"+key, lo)
			add("PrevHi"+key, hi)
			add("FixtureOnly"+key, intStr(c.FixtureOnly))
		}
		add("Pass"+key, intStr(c.Pass))
		add("Fail"+key, intStr(c.Fail))
		add("Verified"+key, intStr(c.Verified))
		add("Unverified"+key, intStr(c.Unverified))
	}

	var w strings.Builder
	w.WriteString(header(a, "Macros for the paper; every result number is one of these or a generated table"))
	fmt.Fprintf(&w, "%% Schema: %s, legacy input: %t\n", orUnknown(a.SchemaVersion), a.Legacy)
	names := map[string]bool{}
	for _, m := range list {
		if !macroNamePattern.MatchString(m.name) {
			return "", fmt.Errorf("macro name %q is not letters only", m.name)
		}
		if names[m.name] {
			return "", fmt.Errorf("macro %s is defined twice", m.name)
		}
		names[m.name] = true
		fmt.Fprintf(&w, "\\newcommand{\\%s}{%s}\n", m.name, m.value)
	}
	return w.String(), nil
}

// ---------------------------------------------------------------------------
// Preview document

// renderPreviewDocument returns a standalone document that includes every
// generated file. It is written next to them and must be compiled from that
// directory. Files owned by other tools are included only when present.
func renderPreviewDocument() string {
	return `% Generated by tools/export_latex.go. Do not edit.
\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[margin=0.85in]{geometry}
\usepackage{booktabs}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{tikz}
\usetikzlibrary{patterns}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usepackage{caption}
\IfFileExists{placeins.sty}{\usepackage{placeins}}{\newcommand{\FloatBarrier}{\clearpage}}

\newcommand{\optionalinput}[1]{\IfFileExists{#1}{\input{#1}}{\par\texttt{\detokenize{#1}} not generated\par}}
\newcommand{\previewsection}[1]{\FloatBarrier\section*{#1}}
\newcommand{\optionalmacros}[1]{\IfFileExists{#1}{\input{#1}}{}}

\input{macros_study.tex}
\optionalmacros{macros_rq3.tex}

\title{ConUnit Evaluation Artifact Preview}
\author{Generated from one empirical\_study.json}
\date{\ConUnitEnvDate}

\begin{document}
\maketitle

\previewsection{Flow and environment}
\begin{itemize}
  \item Candidates: \ConUnitNCandidates, pinned: \ConUnitNPinned, attempted: \ConUnitNAttempted, completed: \ConUnitNCompleted, not completed: \ConUnitNAttrition
  \item Instance \ConUnitEnvInstanceType{} (\ConUnitEnvVirt), kernel \ConUnitEnvKernel, OS \ConUnitEnvOS
  \item Engine \ConUnitEnvEngine, probe window \ConUnitEnvProbeWindow, commit \ConUnitEnvCommit, AMI \ConUnitEnvAMI
  \item Confirmed failures among verified headline checks per image: median \ConUnitImgFailMedianHeadline{} (Q1 \ConUnitImgFailQOneHeadline, Q3 \ConUnitImgFailQThreeHeadline), mean \ConUnitImgFailMeanHeadline{} (SD \ConUnitImgFailSDHeadline); verified headline checks per image: median \ConUnitImgVerifiedMedianHeadline, range \ConUnitImgVerifiedMinHeadline{} to \ConUnitImgVerifiedMaxHeadline
  \item Images with verified headline checks and no confirmed failure: \ConUnitImgNoFailHeadline
  \item Batch ceiling of the ConUnit process (not per image): \ConUnitBatchPeakRSS{} MB
\end{itemize}

\previewsection{Attrition}
\optionalinput{table_attrition.tex}

\previewsection{Headline prevalence}
\optionalinput{table_rq2_prevalence.tex}
\optionalinput{fig_rq2_prevalence.tex}

\previewsection{Strata}
\optionalinput{table_strata.tex}

\previewsection{Exploratory checks}
\optionalinput{table_rq2_exploratory.tex}

\previewsection{Unverified results}
\optionalinput{table_unverified.tex}

\newpage
\previewsection{Phase timings (single pass)}
\optionalinput{table_rq3_phases.tex}
\begin{figure}[h!]
\centering
\optionalinput{fig_rq3_phase_breakdown.tex}
\caption{Phase breakdown of one pass. Tier 3 is bounded below by the probe window.}
\end{figure}
\begin{figure}[h!]
\centering
\optionalinput{fig_rq3_memory_scaling.tex}
\caption{ConUnit process memory versus scanned size (process only).}
\end{figure}

\previewsection{Repeated trials (written by benchmark\_rq3)}
\optionalinput{table_rq3_trials.tex}

\previewsection{Detection benchmark (written by the RQ1 runner)}
\optionalinput{table_rq1_detection.tex}

\end{document}
`
}
