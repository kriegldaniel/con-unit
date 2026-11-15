package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

// CategoryCrosscheck is the item type of a cross-check row in the two-rater
// sheet of tools/adjudication. The same value is written by `adjudication
// export -crosscheck`.
const CategoryCrosscheck = "crosscheck"

// Labels of the sheet. For a cross-check row a rater decides whether the
// property that the check names is really present in the image: TP means
// present, FP means absent.
const (
	LabelTP          = "TP"
	LabelFP          = "FP"
	LabelUndecidable = "UNDECIDABLE"
)

// Resolved-by values.
const (
	resolvedConsensus = "consensus"
	resolvedAgreed    = "agreed"
)

// SheetRow holds the ratings of one cross-check row.
type SheetRow struct {
	RaterA, RaterB, Consensus string
}

// Resolve returns the final label of a row: the consensus when given,
// otherwise the rating that both raters share. A row with neither is
// unresolved and returns an empty label. This is the rule of tools/adjudication.
func (r SheetRow) Resolve() (label, how string) {
	switch {
	case r.Consensus != "":
		return r.Consensus, resolvedConsensus
	case r.RaterA != "" && r.RaterA == r.RaterB:
		return r.RaterA, resolvedAgreed
	}
	return "", ""
}

// Sheet holds the cross-check rows of a filled adjudication sheet, keyed by
// image and check.
type Sheet struct {
	rows map[string]SheetRow
}

func sheetKey(image, check string) string { return image + "\x00" + check }

// ReadSheet parses a filled adjudication CSV and keeps the rows whose
// category is crosscheck. A label other than TP, FP, UNDECIDABLE or empty is an
// error that names the row. Two rows for the same image and check are an error.
func ReadSheet(r io.Reader) (*Sheet, error) {
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
	for _, need := range []string{"image", "rule", "category", "rater_a", "rater_b", "consensus"} {
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
	s := &Sheet{rows: map[string]SheetRow{}}
	for n, rec := range records[1:] {
		if get(rec, "category") != CategoryCrosscheck {
			continue
		}
		row := SheetRow{}
		for _, f := range []struct {
			name string
			dst  *string
		}{{"rater_a", &row.RaterA}, {"rater_b", &row.RaterB}, {"consensus", &row.Consensus}} {
			v := strings.ToUpper(get(rec, f.name))
			if v != "" && v != LabelTP && v != LabelFP && v != LabelUndecidable {
				return nil, fmt.Errorf("row %d (%s %s): %s is %q, want TP, FP or UNDECIDABLE",
					n+2, get(rec, "rule"), get(rec, "image"), f.name, get(rec, f.name))
			}
			*f.dst = v
		}
		key := sheetKey(get(rec, "image"), get(rec, "rule"))
		if _, dup := s.rows[key]; dup {
			return nil, fmt.Errorf("row %d: the cross-check row for %s on %s appears twice", n+2, get(rec, "rule"), get(rec, "image"))
		}
		s.rows[key] = row
	}
	return s, nil
}

// Len returns the number of cross-check rows.
func (s *Sheet) Len() int { return len(s.rows) }

// resolutionFor maps a final label to who was right, given the kind of the
// discordance. The label says whether the property is present in the image.
//
//	ConUnit FAIL, no Dockle finding:  TP means ConUnit was right, FP means Dockle was right.
//	Dockle finding, ConUnit PASS:     TP means Dockle was right, FP means ConUnit was right.
func resolutionFor(kind Cell, label string) string {
	switch label {
	case LabelUndecidable:
		return ResolutionUndecidable
	case LabelTP:
		if kind == CellOnlyConUnit {
			return ResolutionConUnit
		}
		return ResolutionDockle
	case LabelFP:
		if kind == CellOnlyConUnit {
			return ResolutionDockle
		}
		return ResolutionConUnit
	}
	return ""
}

// applySheet fills the resolution of every discordance from the sheet and sets
// the resolved count. Without a sheet the resolved count stays null.
func (r *Result) applySheet(s *Sheet, warn func(string, ...any)) {
	if s == nil {
		return
	}
	resolved := 0
	missing := 0
	used := map[string]bool{}
	for i := range r.Discordances {
		d := &r.Discordances[i]
		key := sheetKey(d.Image, d.Check)
		row, ok := s.rows[key]
		if !ok {
			missing++
			continue
		}
		used[key] = true
		label, how := row.Resolve()
		d.Resolution, d.ResolvedBy = resolutionFor(d.Kind, label), how
		switch d.Resolution {
		case ResolutionConUnit, ResolutionDockle:
			resolved++
		case ResolutionUndecidable:
			r.Totals.Undecidable++
		}
	}
	r.Totals.Resolved = &resolved
	if missing > 0 {
		warn("%d of %d discordances have no row in the adjudication sheet; export the sheet again with -crosscheck", missing, len(r.Discordances))
	}
	if stale := len(s.rows) - len(used); stale > 0 {
		warn("%d cross-check rows of the adjudication sheet match no discordance of this run", stale)
	}
}
