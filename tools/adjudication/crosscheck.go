package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/con-unit/con-unit/tools/internal/analysis"
)

// CategoryCrosscheck is the category of a cross-check row: an image and check
// pair on which ConUnit and Dockle disagree (tools/crosscheck). The value is
// the one that tools/crosscheck reads back with -adjudication.
//
// For a cross-check row the raters decide whether the property that the check
// names is really present in the image. TP means present, FP means absent. Who
// is right follows from that label and from the kind of the pair:
//
//	only_conunit (ConUnit FAIL, no Dockle finding): TP means ConUnit is right, FP means Dockle is right.
//	only_dockle  (Dockle finding, ConUnit PASS):    TP means Dockle is right, FP means ConUnit is right.
const CategoryCrosscheck = "crosscheck"

// Kinds of a discordance, as written by tools/crosscheck.
const (
	KindOnlyConUnit = "only_conunit"
	KindOnlyDockle  = "only_dockle"
)

// kindPrefix starts the first line of the evidence of a cross-check row. The
// score reads the kind back from that line, so the line is part of the format.
const kindPrefix = "kind: "

// crosscheckSchemaVersion is the schema of crosscheck.json that this reader
// was written for.
const crosscheckSchemaVersion = "1"

// crosscheckDiscordance is the part of a discordance of crosscheck.json that
// the sheet needs. tools/crosscheck is a main package and cannot be imported,
// so the fields are decoded here; the round trip test pins the names.
type crosscheckDiscordance struct {
	Image              string `json:"image"`
	Check              string `json:"check"`
	Kind               string `json:"kind"`
	DockleCode         string `json:"dockle_code"`
	ConUnitOutcome     string `json:"conunit_outcome"`
	DockleFinding      bool   `json:"dockle_finding"`
	ConUnitEvidence    string `json:"conunit_evidence"`
	DockleAlert        string `json:"dockle_alert"`
	IntendedDifference string `json:"intended_difference"`
}

// crosscheckFile is the part of crosscheck.json that the export reads.
type crosscheckFile struct {
	SchemaVersion string `json:"schema_version"`
	Study         struct {
		SHA256 string `json:"sha256"`
	} `json:"study"`
	// Discordances is a pointer so that a missing or null array can be told
	// from an empty one.
	Discordances *[]crosscheckDiscordance `json:"discordances"`
}

// readCrosscheck decodes crosscheck.json. A file without a schema version or
// without a discordances array is not a crosscheck.json and is an error. An
// unexpected schema version and a different study are returned as warnings.
func readCrosscheck(path, studySHA string) (ds []crosscheckDiscordance, warnings []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f crosscheckFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.SchemaVersion == "" {
		return nil, nil, fmt.Errorf("%s is not a crosscheck.json: schema_version is missing", path)
	}
	if f.Discordances == nil {
		return nil, nil, fmt.Errorf("%s has no discordances array (missing or null)", path)
	}
	if f.SchemaVersion != crosscheckSchemaVersion {
		warnings = append(warnings, fmt.Sprintf("schema_version %q of %s differs from %q, the version this tool was written for",
			f.SchemaVersion, path, crosscheckSchemaVersion))
	}
	if studySHA != "" && f.Study.SHA256 != "" && f.Study.SHA256 != studySHA {
		warnings = append(warnings, fmt.Sprintf("%s was made from a study with sha256 %s, not from the study of this export (%s); the rows may name images that are not in it",
			path, short(f.Study.SHA256), short(studySHA)))
	}
	seen := map[string]bool{}
	for i, d := range *f.Discordances {
		switch {
		case d.Image == "" || d.Check == "":
			return nil, nil, fmt.Errorf("%s: discordance %d has no image or no check", path, i)
		case d.Kind != KindOnlyConUnit && d.Kind != KindOnlyDockle:
			return nil, nil, fmt.Errorf("%s: discordance %d (%s on %s) has kind %q, want %s or %s",
				path, i, d.Check, d.Image, d.Kind, KindOnlyConUnit, KindOnlyDockle)
		}
		key := d.Image + "\x00" + d.Check
		if seen[key] {
			return nil, nil, fmt.Errorf("%s: the pair %s on %s is listed twice", path, d.Check, d.Image)
		}
		seen[key] = true
	}
	return *f.Discordances, warnings, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// crosscheckRows turns discordances into sheet rows. The row ID is derived
// from the image, the check, the category, the Dockle code and the evidence,
// like the ID of every other row.
func crosscheckRows(ds []crosscheckDiscordance) []Row {
	rows := make([]Row, 0, len(ds))
	for _, d := range ds {
		rows = append(rows, newRow(d.Image, d.Check, CategoryCrosscheck, d.DockleCode, crosscheckEvidence(d)))
	}
	return rows
}

func orNone(s, none string) string {
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return none
}

// crosscheckEvidence is what the raters read. The first line carries the kind
// in a fixed form. The text states the question and what each label means, so
// that a rater does not have to know which tool is on which side.
func crosscheckEvidence(d crosscheckDiscordance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n", kindPrefix, d.Kind)
	code := orNone(d.DockleCode, "no Dockle code")
	switch d.Kind {
	case KindOnlyConUnit:
		fmt.Fprintf(&b, "question: ConUnit reports %s for %s and Dockle reports no finding for %s. Is the problem that %s names really present in the image?\n",
			orNone(d.ConUnitOutcome, "FAIL"), d.Check, code, d.Check)
		b.WriteString("labels: TP = present in the image, so ConUnit is right. FP = absent from the image, so Dockle is right. UNDECIDABLE = the image does not settle it.\n")
	case KindOnlyDockle:
		fmt.Fprintf(&b, "question: Dockle reports a finding (%s) and ConUnit reports %s for %s. Is the problem that %s names really present in the image?\n",
			code, orNone(d.ConUnitOutcome, "PASS"), d.Check, d.Check)
		b.WriteString("labels: TP = present in the image, so Dockle is right. FP = absent from the image, so ConUnit is right. UNDECIDABLE = the image does not settle it.\n")
	}
	fmt.Fprintf(&b, "ConUnit outcome: %s\n", orNone(d.ConUnitOutcome, "none recorded"))
	fmt.Fprintf(&b, "ConUnit evidence: %s\n", orNone(d.ConUnitEvidence, "none recorded"))
	fmt.Fprintf(&b, "Dockle code: %s\n", code)
	fmt.Fprintf(&b, "Dockle alert: %s\n", orNone(d.DockleAlert, "none recorded"))
	fmt.Fprintf(&b, "documented design difference (a candidate cause, not a verdict): %s", orNone(d.IntendedDifference, "none known"))
	return b.String()
}

// crosscheckKind reads the kind from the first line of the evidence of a
// cross-check row.
func crosscheckKind(evidence string) (string, bool) {
	first := strings.TrimSpace(strings.SplitN(evidence, "\n", 2)[0])
	if !strings.HasPrefix(first, kindPrefix) {
		return "", false
	}
	switch kind := strings.TrimSpace(strings.TrimPrefix(first, kindPrefix)); kind {
	case KindOnlyConUnit, KindOnlyDockle:
		return kind, true
	}
	return "", false
}

// Who is right in a resolved cross-check row.
const (
	rightConUnit = "conunit"
	rightDockle  = "dockle"
)

// crosscheckRight says which tool a TP or FP label supports, given the kind of
// the pair. It returns an empty string for any other label or kind.
func crosscheckRight(kind, label string) string {
	switch {
	case kind == KindOnlyConUnit && label == LabelTP, kind == KindOnlyDockle && label == LabelFP:
		return rightConUnit
	case kind == KindOnlyConUnit && label == LabelFP, kind == KindOnlyDockle && label == LabelTP:
		return rightDockle
	}
	return ""
}

// CrosscheckCounts are the counts of a set of cross-check rows. ConUnitCorrect
// and DockleCorrect count the resolved rows by the tool that the label
// supports; Unattributed counts resolved rows whose kind line cannot be read
// (ReadRows rejects such a row, so the count is 0 for a file read by score).
type CrosscheckCounts struct {
	Rows                int       `json:"rows"`
	Unrated             int       `json:"unrated"`
	TP                  int       `json:"tp"`
	FP                  int       `json:"fp"`
	Undecidable         int       `json:"undecidable"`
	Unresolved          int       `json:"unresolved"`
	ConUnitCorrect      int       `json:"conunit_correct"`
	DockleCorrect       int       `json:"dockle_correct"`
	Unattributed        int       `json:"unattributed"`
	ConUnitCorrectShare *Interval `json:"conunit_correct_share"` // null when no row is attributed
}

func (c *CrosscheckCounts) add(r Row, kind, label string) {
	c.Rows++
	if r.RaterA == "" || r.RaterB == "" {
		c.Unrated++
	}
	switch label {
	case LabelTP:
		c.TP++
	case LabelFP:
		c.FP++
	case LabelUndecidable:
		c.Undecidable++
		return
	default:
		c.Unresolved++
		return
	}
	switch crosscheckRight(kind, label) {
	case rightConUnit:
		c.ConUnitCorrect++
	case rightDockle:
		c.DockleCorrect++
	default:
		c.Unattributed++
	}
}

func (c *CrosscheckCounts) finish() {
	c.ConUnitCorrectShare = wilson(c.ConUnitCorrect, c.ConUnitCorrect+c.DockleCorrect)
}

// CrosscheckKind is the counts of the rows of one kind.
type CrosscheckKind struct {
	Kind string `json:"kind"`
	CrosscheckCounts
}

// CrosscheckCheck is the counts of the rows of one check.
type CrosscheckCheck struct {
	Rule string `json:"rule"`
	CrosscheckCounts
}

// CrosscheckSummary is the cross-check section of adjudication_summary.json.
// It stands apart from the study rows: those rows never enter the overall
// agreement, the per-check precision or the row counts of the summary.
type CrosscheckSummary struct {
	CrosscheckCounts
	// Agreement is the agreement of the two raters over the doubly rated rows.
	Agreement Agreement         `json:"rater_agreement"`
	ByKind    []CrosscheckKind  `json:"by_kind"`
	Checks    []CrosscheckCheck `json:"checks"`
}

// splitRows separates the study rows from the cross-check rows.
func splitRows(rows []Row) (study, crosscheck []Row) {
	for _, r := range rows {
		if r.Category == CategoryCrosscheck {
			crosscheck = append(crosscheck, r)
		} else {
			study = append(study, r)
		}
	}
	return study, crosscheck
}

// scoreCrosscheck summarizes the cross-check rows. It returns nil without a
// row.
func scoreCrosscheck(rows []Row) *CrosscheckSummary {
	if len(rows) == 0 {
		return nil
	}
	s := &CrosscheckSummary{}
	kinds := map[string]*CrosscheckCounts{KindOnlyConUnit: {}, KindOnlyDockle: {}}
	byRule := map[string]*CrosscheckCounts{}
	var a, b []string
	for _, r := range rows {
		kind, _ := crosscheckKind(r.Evidence)
		label, _ := Resolve(r)
		if byRule[r.Rule] == nil {
			byRule[r.Rule] = &CrosscheckCounts{}
		}
		s.add(r, kind, label)
		byRule[r.Rule].add(r, kind, label)
		if k := kinds[kind]; k != nil {
			k.add(r, kind, label)
		}
		if r.RaterA != "" && r.RaterB != "" {
			a, b = append(a, r.RaterA), append(b, r.RaterB)
		}
	}
	s.Agreement = agreementOf(a, b)
	s.finish()
	for _, kind := range []string{KindOnlyConUnit, KindOnlyDockle} {
		kinds[kind].finish()
		s.ByKind = append(s.ByKind, CrosscheckKind{Kind: kind, CrosscheckCounts: *kinds[kind]})
	}
	rules := make([]string, 0, len(byRule))
	for rule := range byRule {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return analysis.NaturalLess(rules[i], rules[j]) })
	for _, rule := range rules {
		byRule[rule].finish()
		s.Checks = append(s.Checks, CrosscheckCheck{Rule: rule, CrosscheckCounts: *byRule[rule]})
	}
	return s
}

// validateCrosscheckRow rejects a cross-check row whose evidence does not start
// with a readable kind line.
func validateCrosscheckRow(n int, r Row) error {
	if _, ok := crosscheckKind(r.Evidence); !ok {
		return fmt.Errorf("row %d (%s %s): a crosscheck row must start its evidence with the line %q or %q",
			n, r.Rule, r.ID, kindPrefix+KindOnlyConUnit, kindPrefix+KindOnlyDockle)
	}
	return nil
}
