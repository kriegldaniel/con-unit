// Command adjudication supports the two-rater validity study of
// docs/ANALYSIS_PLAN.md section 11.
//
//	adjudication export [-study FILE] [-crosscheck FILE] [-out FILE] [-exec-sample N] [-seed S]
//	adjudication score  [-csv FILE] [-out FILE] [-threshold P]
//
// export reads a study and writes adjudication_template.csv with one row per
// flagged finding: every FS-06 and FS-07 finding, every SPEC-07 failure and
// every EXEC failure (or a deterministic sample of them). Two raters fill in
// the rater_a and rater_b columns with TP, FP or UNDECIDABLE; disagreements are
// resolved by discussion in the consensus column.
//
// With -crosscheck, export also reads the crosscheck.json of tools/crosscheck
// and adds one row of the category crosscheck for every image and check pair on
// which ConUnit and Dockle disagree. For such a row TP means that the problem
// is really present in the image and FP means that it is absent; the first
// line of its evidence names the kind of the pair, which fixes who is right.
// The EXEC sample applies to the study rows only.
//
// score reads the filled file, reports Cohen's kappa overall and per check,
// resolves each row (consensus first, otherwise the common rating) and reports
// the precision per check, TP over TP plus FP, with a Wilson 95 percent
// interval. UNDECIDABLE rows are counted separately and never enter precision.
// Cross-check rows are scored apart: they never enter the overall agreement,
// the per-check precision or the row counts, and have a section of their own
// with the rater agreement, the rows in which ConUnit and Dockle are right, and
// the share of ConUnit with its Wilson interval. The summary is written to
// adjudication_summary.json, schema version 2.
package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/stats"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// Labels a rater may assign.
const (
	LabelTP          = "TP"
	LabelFP          = "FP"
	LabelUndecidable = "UNDECIDABLE"
)

// Row categories.
const (
	CategoryFinding          = "finding"           // a reported FS-06 or FS-07 finding (non-fixture path)
	CategoryFixtureCandidate = "fixture_candidate" // a finding exempted as fixture-like; TP means wrongly exempted
	CategoryFailure          = "failure"           // a SPEC-07 or EXEC FAIL result
)

const (
	templateName = "adjudication_template.csv"
	summaryName  = "adjudication_summary.json"

	// DefaultThreshold is the precision a check needs to be a headline
	// candidate (docs/ANALYSIS_PLAN.md section 4).
	DefaultThreshold = 0.8
)

var csvHeader = []string{"finding_id", "image", "rule", "category", "evidence", "rater_a", "rater_b", "consensus"}

// Row is one flagged finding to be adjudicated.
type Row struct {
	ID        string
	Image     string
	Rule      string
	Category  string
	Evidence  string
	RaterA    string
	RaterB    string
	Consensus string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: adjudication export [-study FILE] [-crosscheck FILE] [-out FILE] [-exec-sample N] [-seed S]")
	fmt.Fprintln(w, "       adjudication score  [-csv FILE] [-out FILE] [-threshold P]")
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return spec.ExitUsage
	}
	switch args[0] {
	case "export":
		return runExport(args[1:], stdout, stderr)
	case "score":
		return runScore(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		usage(stdout)
		return spec.ExitOK
	default:
		fmt.Fprintf(stderr, "adjudication: unknown subcommand %q\n", args[0])
		usage(stderr)
		return spec.ExitUsage
	}
}

// ---------------------------------------------------------------------------
// export

type exportOptions struct {
	ExecSample int
	Seed       string
}

func runExport(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("export", flag.ContinueOnError)
	fset.SetOutput(stderr)
	study := fset.String("study", "results/empirical_study.json", "study file")
	crosscheck := fset.String("crosscheck", "", "crosscheck.json of tools/crosscheck: add a row for every pair on which ConUnit and Dockle disagree")
	out := fset.String("out", "", "output CSV (default: "+templateName+" next to the study)")
	sample := fset.Int("exec-sample", 0, "keep a deterministic sample of this many EXEC failures (0 keeps all)")
	seed := fset.String("seed", "conunit-adjudication", "seed of the EXEC sample")
	if err := fset.Parse(args); err != nil {
		return spec.ExitUsage
	}
	log, problem := clilog.New(stdout), clilog.New(stderr)
	if *sample < 0 {
		problem.Error("-exec-sample must not be negative")
		return spec.ExitUsage
	}
	l, err := studyfile.Load(*study)
	if err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	rows := buildRows(l, exportOptions{ExecSample: *sample, Seed: *seed})
	if *crosscheck != "" {
		ds, warnings, err := readCrosscheck(*crosscheck, l.SHA256)
		if err != nil {
			problem.Error("%v", err)
			return spec.ExitFindings
		}
		for _, w := range warnings {
			problem.Warn("%s", w)
		}
		if len(ds) == 0 {
			problem.Warn("%s holds no discordance; no crosscheck row was added", *crosscheck)
		}
		// The EXEC sample is drawn from the study rows before these are added.
		rows = mergeRows(rows, crosscheckRows(ds))
	}
	dest := *out
	if dest == "" {
		dest = filepath.Join(filepath.Dir(*study), templateName)
	}
	if err := writeTemplate(dest, rows); err != nil {
		problem.Error("cannot write %s: %v", dest, err)
		return spec.ExitFindings
	}
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Rule+" "+r.Category]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return analysis.NaturalLess(keys[i], keys[j]) })
	log.Section("Adjudication template")
	for _, k := range keys {
		log.Info("%-28s %d rows", k, counts[k])
	}
	log.Success("wrote %d rows to %s", len(rows), dest)
	if len(rows) == 0 {
		problem.Warn("no finding to adjudicate in %s", *study)
	}
	return spec.ExitOK
}

var findingRules = map[string]bool{"FS-06": true, "FS-07": true}

// buildRows lists every flagged finding of the COMPLETED images in a stable
// order: rule, image, category, path.
func buildRows(l *studyfile.Loaded, opt exportOptions) []Row {
	var rows []Row
	for _, rec := range l.Records {
		if !l.Completed(rec) {
			continue
		}
		image := studyfile.RecordKey(rec)
		results, _ := studyfile.UniqueResults(rec)
		for _, r := range results {
			switch {
			case findingRules[r.TestID]:
				rows = append(rows, findingRows(image, r)...)
			case r.TestID == "SPEC-07" && r.EffectiveOutcome() == spec.OutcomeFail:
				rows = append(rows, newRow(image, r.TestID, CategoryFailure, "", failureEvidence(r)))
			case strings.HasPrefix(r.TestID, "EXEC-") && r.EffectiveOutcome() == spec.OutcomeFail:
				rows = append(rows, newRow(image, r.TestID, CategoryFailure, "", failureEvidence(r)))
			}
		}
	}
	if opt.ExecSample > 0 {
		rows = sampleExec(rows, opt.ExecSample, opt.Seed)
	}
	sortRows(rows)
	return rows
}

// sortRows orders rows by rule, image, category and ID.
func sortRows(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Rule != b.Rule {
			return analysis.NaturalLess(a.Rule, b.Rule)
		}
		if a.Image != b.Image {
			return a.Image < b.Image
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.ID < b.ID
	})
}

// mergeRows joins the study rows and the cross-check rows in the common order.
func mergeRows(study, crosscheck []Row) []Row {
	rows := append(append([]Row(nil), study...), crosscheck...)
	sortRows(rows)
	return rows
}

func findingRows(image string, r spec.TestResult) []Row {
	var rows []Row
	if r.EffectiveOutcome() == spec.OutcomeFail {
		if r.Evidence == nil || len(r.Evidence.Paths) == 0 {
			// Never drop a reported failure silently.
			rows = append(rows, newRow(image, r.TestID, CategoryFinding, "(no path recorded)", failureEvidence(r)))
		} else {
			for _, p := range r.Evidence.Paths {
				rows = append(rows, newRow(image, r.TestID, CategoryFinding, p, "path: "+p))
			}
		}
	}
	if r.Evidence != nil {
		for _, p := range r.Evidence.FixtureCandidates {
			rows = append(rows, newRow(image, r.TestID, CategoryFixtureCandidate, p, "path (exempted as fixture-like): "+p))
		}
	}
	return rows
}

func newRow(image, rule, category, key, evidence string) Row {
	sum := sha256.Sum256([]byte(strings.Join([]string{image, rule, category, key, evidence}, "\x00")))
	return Row{ID: hex.EncodeToString(sum[:])[:12], Image: image, Rule: rule, Category: category, Evidence: evidence}
}

// failureEvidence summarizes what a rater needs to judge a FAIL result. The
// keyword-derived hint is deliberately left out so it cannot bias the rating.
func failureEvidence(r spec.TestResult) string {
	var parts []string
	if r.Message != "" {
		parts = append(parts, "message: "+r.Message)
	}
	if r.Details != "" {
		parts = append(parts, "details: "+r.Details)
	}
	if ev := r.Evidence; ev != nil {
		state := func(label, st string, code *int) {
			if st == "" && code == nil {
				return
			}
			s := label + ": " + orDash(st)
			if code != nil {
				s += fmt.Sprintf(" (exit %d)", *code)
			}
			parts = append(parts, s)
		}
		state("baseline", ev.BaselineState, ev.BaselineExitCode)
		state("treatment", ev.TreatmentState, ev.TreatmentExitCode)
		if ev.WindowMillis > 0 {
			parts = append(parts, fmt.Sprintf("window: %d ms", ev.WindowMillis))
		}
		if len(ev.Paths) > 0 {
			parts = append(parts, "paths: "+strings.Join(ev.Paths, ", "))
		}
		if ev.LogTail != "" {
			parts = append(parts, "log tail:\n"+strings.TrimRight(ev.LogTail, "\n"))
		}
	}
	if len(parts) == 0 {
		return "(no evidence recorded)"
	}
	return strings.Join(parts, "\n")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// sampleExec keeps all non-EXEC rows and a deterministic sample of n EXEC
// failures, chosen by the order of sha256(seed, row id).
func sampleExec(rows []Row, n int, seed string) []Row {
	var exec, rest []Row
	for _, r := range rows {
		if strings.HasPrefix(r.Rule, "EXEC-") {
			exec = append(exec, r)
		} else {
			rest = append(rest, r)
		}
	}
	if len(exec) <= n {
		return rows
	}
	key := func(r Row) string {
		sum := sha256.Sum256([]byte(seed + "\x00" + r.ID + "\x00" + r.Image + "\x00" + r.Rule))
		return hex.EncodeToString(sum[:])
	}
	sort.Slice(exec, func(i, j int) bool { return key(exec[i]) < key(exec[j]) })
	return append(rest, exec[:n]...)
}

func writeTemplate(path string, rows []Row) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.Write([]string{r.ID, r.Image, r.Rule, r.Category, r.Evidence, r.RaterA, r.RaterB, r.Consensus}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// ---------------------------------------------------------------------------
// score

// ReadRows parses a filled adjudication CSV. Labels are normalised to upper
// case; anything other than TP, FP, UNDECIDABLE or empty is an error that
// names the row. A row of the category crosscheck whose evidence does not
// start with a kind line is an error too, because its labels cannot be read
// without the kind.
func ReadRows(r io.Reader) ([]Row, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("empty file")
	}
	col := map[string]int{}
	for i, h := range records[0] {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	for _, need := range csvHeader {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("missing column %q", need)
		}
	}
	get := func(rec []string, name string) string {
		if i := col[name]; i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	var rows []Row
	for n, rec := range records[1:] {
		row := Row{
			ID: get(rec, "finding_id"), Image: get(rec, "image"), Rule: get(rec, "rule"), Category: get(rec, "category"),
			Evidence: get(rec, "evidence"),
		}
		for _, f := range []struct {
			name string
			dst  *string
		}{{"rater_a", &row.RaterA}, {"rater_b", &row.RaterB}, {"consensus", &row.Consensus}} {
			v := strings.ToUpper(get(rec, f.name))
			if v != "" && v != LabelTP && v != LabelFP && v != LabelUndecidable {
				return nil, fmt.Errorf("row %d (%s %s): %s is %q, want TP, FP or UNDECIDABLE", n+2, row.Rule, row.ID, f.name, get(rec, f.name))
			}
			*f.dst = v
		}
		if row.Rule == "" {
			return nil, fmt.Errorf("row %d has no rule", n+2)
		}
		if row.Category == CategoryCrosscheck {
			if err := validateCrosscheckRow(n+2, row); err != nil {
				return nil, err
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Resolution says how a row's final label was obtained.
const (
	ResolvedConsensus = "consensus"
	ResolvedAgreed    = "agreed"
	Unresolved        = "unresolved"
)

// Resolve returns the final label of a row: the consensus when given,
// otherwise the rating both raters share. Rows without either are
// unresolved.
func Resolve(r Row) (label, how string) {
	switch {
	case r.Consensus != "":
		return r.Consensus, ResolvedConsensus
	case r.RaterA != "" && r.RaterA == r.RaterB:
		return r.RaterA, ResolvedAgreed
	default:
		return "", Unresolved
	}
}

// Agreement is inter-rater agreement over a set of doubly rated rows.
type Agreement struct {
	Rated     int      `json:"rated"`
	Agree     int      `json:"agree"`
	Agreement *float64 `json:"percent_agreement"`
	Kappa     *float64 `json:"kappa"` // null when undefined
}

// Interval is a proportion with its Wilson 95 percent interval.
type Interval struct {
	Estimate float64 `json:"estimate"`
	Lo       float64 `json:"wilson_lo"`
	Hi       float64 `json:"wilson_hi"`
}

// CheckSummary is the adjudication result of one rule.
type CheckSummary struct {
	Rule       string    `json:"rule"`
	Rows       int       `json:"rows"`
	Unrated    int       `json:"unrated"`
	Agreement  Agreement `json:"agreement"`
	TP         int       `json:"tp"`
	FP         int       `json:"fp"`
	Undecid    int       `json:"undecidable"`
	Unresolved int       `json:"unresolved"`
	Resolved   int       `json:"resolved_tp_fp"`
	Precision  *Interval `json:"precision"` // null when no TP or FP was resolved
	// MeetsThreshold is true when the precision point estimate reaches the
	// threshold; it is false when precision is undefined.
	MeetsThreshold bool `json:"meets_threshold"`
	// FixtureCandidates summarizes rows that were exempted as fixture-like:
	// a TP there means a real finding was wrongly exempted.
	FixtureCandidates *FixtureSummary `json:"fixture_candidates,omitempty"`
}

// FixtureSummary covers the fixture-candidate rows of one rule.
type FixtureSummary struct {
	Rows            int       `json:"rows"`
	TP              int       `json:"wrongly_exempted_tp"`
	FP              int       `json:"correctly_exempted_fp"`
	Undecidable     int       `json:"undecidable"`
	Unresolved      int       `json:"unresolved"`
	WronglyExempted *Interval `json:"wrongly_exempted_share"`
}

// Summary is adjudication_summary.json.
type Summary struct {
	SchemaVersion string         `json:"schema_version"`
	Source        string         `json:"source"`
	SourceSHA256  string         `json:"source_sha256"`
	Threshold     float64        `json:"precision_threshold"`
	Rows          int            `json:"rows"`
	Unrated       int            `json:"unrated"`
	Overall       Agreement      `json:"overall_agreement"`
	Checks        []CheckSummary `json:"checks"`
	// Crosscheck covers the rows of the category crosscheck, which are not
	// part of Rows, Unrated, Overall or Checks. It is null without such a row.
	Crosscheck *CrosscheckSummary `json:"crosscheck"`
}

func ptr(x float64) *float64 { return &x }

func wilson(k, n int) *Interval {
	lo, hi, ok := stats.Wilson(k, n)
	if !ok {
		return nil
	}
	return &Interval{Estimate: float64(k) / float64(n), Lo: lo, Hi: hi}
}

func agreementOf(a, b []string) Agreement {
	k := stats.Kappa(a, b)
	ag := Agreement{Rated: k.N, Agree: k.Agree}
	if k.N > 0 {
		ag.Agreement = ptr(k.Agreement)
	}
	if k.Defined {
		ag.Kappa = ptr(k.Kappa)
	}
	return ag
}

// SummarySchemaVersion is the schema of adjudication_summary.json. Version 2
// adds the crosscheck section; every other field is as in version 1.
const SummarySchemaVersion = "2"

// Score summarizes the rows. Rows of the category crosscheck are scored apart
// in Summary.Crosscheck and do not enter anything else.
func Score(rows []Row, source, sourceSHA string, threshold float64) *Summary {
	rows, crosscheck := splitRows(rows)
	s := &Summary{SchemaVersion: SummarySchemaVersion, Source: source, SourceSHA256: sourceSHA, Threshold: threshold, Rows: len(rows)}
	s.Crosscheck = scoreCrosscheck(crosscheck)
	var allA, allB []string
	byRule := map[string][]Row{}
	for _, r := range rows {
		byRule[r.Rule] = append(byRule[r.Rule], r)
		if r.RaterA == "" || r.RaterB == "" {
			s.Unrated++
			continue
		}
		allA, allB = append(allA, r.RaterA), append(allB, r.RaterB)
	}
	s.Overall = agreementOf(allA, allB)

	rules := make([]string, 0, len(byRule))
	for rule := range byRule {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return analysis.NaturalLess(rules[i], rules[j]) })
	for _, rule := range rules {
		cs := CheckSummary{Rule: rule, Rows: len(byRule[rule])}
		var a, b []string
		fix := &FixtureSummary{}
		for _, r := range byRule[rule] {
			if r.RaterA == "" || r.RaterB == "" {
				cs.Unrated++
			} else {
				a, b = append(a, r.RaterA), append(b, r.RaterB)
			}
			label, _ := Resolve(r)
			if r.Category == CategoryFixtureCandidate {
				fix.Rows++
				switch label {
				case LabelTP:
					fix.TP++
				case LabelFP:
					fix.FP++
				case LabelUndecidable:
					fix.Undecidable++
				default:
					fix.Unresolved++
				}
				continue
			}
			switch label {
			case LabelTP:
				cs.TP++
			case LabelFP:
				cs.FP++
			case LabelUndecidable:
				cs.Undecid++
			default:
				cs.Unresolved++
			}
		}
		cs.Agreement = agreementOf(a, b)
		cs.Resolved = cs.TP + cs.FP
		cs.Precision = wilson(cs.TP, cs.Resolved)
		cs.MeetsThreshold = cs.Precision != nil && cs.Precision.Estimate >= threshold
		if fix.Rows > 0 {
			fix.WronglyExempted = wilson(fix.TP, fix.TP+fix.FP)
			cs.FixtureCandidates = fix
		}
		s.Checks = append(s.Checks, cs)
	}
	return s
}

func runScore(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("score", flag.ContinueOnError)
	fset.SetOutput(stderr)
	csvPath := fset.String("csv", "results/adjudication.csv", "filled adjudication CSV")
	out := fset.String("out", "", "output JSON (default: "+summaryName+" next to the CSV)")
	threshold := fset.Float64("threshold", DefaultThreshold, "precision point estimate required for a headline check")
	if err := fset.Parse(args); err != nil {
		return spec.ExitUsage
	}
	log, problem := clilog.New(stdout), clilog.New(stderr)
	data, err := os.ReadFile(*csvPath)
	if err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	rows, err := ReadRows(strings.NewReader(string(data)))
	if err != nil {
		problem.Error("%s: %v", *csvPath, err)
		return spec.ExitFindings
	}
	sum := sha256.Sum256(data)
	summary := Score(rows, filepath.Base(*csvPath), hex.EncodeToString(sum[:]), *threshold)

	dest := *out
	if dest == "" {
		dest = filepath.Join(filepath.Dir(*csvPath), summaryName)
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	if err := os.WriteFile(dest, append(b, '\n'), 0o644); err != nil {
		problem.Error("cannot write %s: %v", dest, err)
		return spec.ExitFindings
	}

	log.Section("Adjudication summary")
	log.Info("rows %d, doubly rated %d, unrated %d", summary.Rows, summary.Overall.Rated, summary.Unrated)
	log.Info("overall: agreement %s, kappa %s", pct(summary.Overall.Agreement), num(summary.Overall.Kappa))
	for _, c := range summary.Checks {
		prec := "n/a (nothing resolved as TP or FP)"
		if c.Precision != nil {
			prec = fmt.Sprintf("%.1f%% [%.1f, %.1f]", 100*c.Precision.Estimate, 100*c.Precision.Lo, 100*c.Precision.Hi)
		}
		verdict := "below threshold"
		if c.MeetsThreshold {
			verdict = "meets threshold"
		}
		log.Info("%-9s rows %3d  TP %3d FP %3d undecidable %3d unresolved %3d  precision %s  kappa %s  %s",
			c.Rule, c.Rows, c.TP, c.FP, c.Undecid, c.Unresolved, prec, num(c.Agreement.Kappa), verdict)
	}
	if summary.Unrated > 0 {
		problem.Warn("%d rows lack a rating from one or both raters; they are excluded from kappa", summary.Unrated)
	}
	unresolved := 0
	for _, c := range summary.Checks {
		unresolved += c.Unresolved
		if c.FixtureCandidates != nil {
			unresolved += c.FixtureCandidates.Unresolved
		}
	}
	if unresolved > 0 {
		problem.Warn("%d rows are unresolved: raters disagree or are missing and no consensus is given", unresolved)
	}
	if cc := summary.Crosscheck; cc != nil {
		printCrosscheck(log, problem, cc)
	}
	log.Success("wrote %s", dest)
	return spec.ExitOK
}

// printCrosscheck prints the section of the cross-check rows. These rows are
// not part of the lines above.
func printCrosscheck(log, problem *clilog.Logger, cc *CrosscheckSummary) {
	share := func(c CrosscheckCounts) string {
		if c.ConUnitCorrectShare == nil {
			return "n/a (no row resolved as TP or FP)"
		}
		i := c.ConUnitCorrectShare
		return fmt.Sprintf("%.1f%% [%.1f, %.1f]", 100*i.Estimate, 100*i.Lo, 100*i.Hi)
	}
	line := func(c CrosscheckCounts) string {
		return fmt.Sprintf("rows %3d  ConUnit right %3d  Dockle right %3d  undecidable %3d  unresolved %3d  ConUnit share %s",
			c.Rows, c.ConUnitCorrect, c.DockleCorrect, c.Undecidable, c.Unresolved, share(c))
	}
	log.Section("Cross-check rows (ConUnit against Dockle)")
	log.Info("%-16s %s", "all", line(cc.CrosscheckCounts))
	log.Info("rater agreement %s over %d doubly rated rows, kappa %s", pct(cc.Agreement.Agreement), cc.Agreement.Rated, num(cc.Agreement.Kappa))
	for _, k := range cc.ByKind {
		log.Info("%-16s %s", k.Kind, line(k.CrosscheckCounts))
	}
	for _, c := range cc.Checks {
		log.Info("%-16s %s", c.Rule, line(c.CrosscheckCounts))
	}
	if cc.Unrated > 0 {
		problem.Warn("%d cross-check rows lack a rating from one or both raters; they are excluded from the rater agreement", cc.Unrated)
	}
	if cc.Unresolved > 0 {
		problem.Warn("%d cross-check rows are unresolved: raters disagree or are missing and no consensus is given", cc.Unresolved)
	}
	if cc.Unattributed > 0 {
		problem.Warn("%d resolved cross-check rows have no readable kind line and are attributed to neither tool", cc.Unattributed)
	}
}

func pct(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100**p)
}

func num(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", *p)
}
