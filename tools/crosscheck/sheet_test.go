package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

const sheetHeader = "finding_id,image,rule,category,evidence,rater_a,rater_b,consensus\n"

// adjudicationTestdata holds the files that tools/adjudication writes in its
// own tests: the crosscheck.json that its export reads, the sheet that the
// export writes from it and the same sheet after the two raters filled it. The
// two tools share these files, so a change of the sheet format or of the
// meaning of a label breaks the test of the tool that did not change.
const adjudicationTestdata = "../adjudication/testdata"

func TestSheetOfTheAdjudicationExportRoundTrips(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(adjudicationTestdata, "crosscheck_input.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The input of the export must be a crosscheck.json of this tool: an
	// unknown or renamed field fails here and not in production.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var report Report
	if err := dec.Decode(&report); err != nil {
		t.Fatalf("the input of tools/adjudication is not a crosscheck.json of this tool: %v", err)
	}
	if report.SchemaVersion != SchemaVersion || len(report.Discordances) != 8 {
		t.Fatalf("schema %q with %d discordances, want %q with 8", report.SchemaVersion, len(report.Discordances), SchemaVersion)
	}

	apply := func(t *testing.T, name string) (*Result, []string) {
		t.Helper()
		f, err := os.Open(filepath.Join(adjudicationTestdata, "golden", name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		sheet, err := ReadSheet(f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The sheet also holds nine study rows that are not cross-check rows.
		if sheet.Len() != 8 {
			t.Fatalf("%s: %d cross-check rows, want 8", name, sheet.Len())
		}
		res := &Result{Discordances: append([]Discordance(nil), report.Discordances...)}
		var warnings []string
		res.applySheet(sheet, func(format string, args ...any) { warnings = append(warnings, format) })
		return res, warnings
	}

	t.Run("template", func(t *testing.T) {
		res, warnings := apply(t, "template_with_crosscheck.csv")
		if len(warnings) != 0 {
			t.Errorf("every discordance must have its row and no row may be stale: %v", warnings)
		}
		if res.Totals.Resolved == nil || *res.Totals.Resolved != 0 || res.Totals.Undecidable != 0 {
			t.Errorf("an unrated sheet resolves nothing: %+v", res.Totals)
		}
		for _, d := range res.Discordances {
			if d.Resolution != "" {
				t.Errorf("%s on %s is resolved without a rating", d.Check, d.Image)
			}
		}
	})

	t.Run("filled", func(t *testing.T) {
		res, warnings := apply(t, "filled_with_crosscheck.csv")
		if len(warnings) != 0 {
			t.Errorf("warnings: %v", warnings)
		}
		// The same pairs and ratings as fixtureFills of tools/adjudication.
		want := []struct{ check, image, resolution, by string }{
			{"CIS-4.6", "distroless", ResolutionDockle, "agreed"},
			{"SPEC-12", "distroless", ResolutionConUnit, "agreed"},
			{"SPEC-09", "nginx", ResolutionConUnit, "consensus"},
			{"FS-01", "nginx", ResolutionUndecidable, "agreed"},
			{"FS-06", "seeded", ResolutionConUnit, "agreed"},
			{"SPEC-11", "seeded", "", ""},
			{"FS-01", "seeded", ResolutionDockle, "agreed"},
			{"FS-11", "seeded", "", ""},
		}
		var conunit, dockle int
		for _, w := range want {
			found := 0
			for _, d := range res.Discordances {
				if d.Check != w.check || !strings.Contains(d.Image, w.image) {
					continue
				}
				found++
				if d.Resolution != w.resolution || d.ResolvedBy != w.by {
					t.Errorf("%s on %s: resolution %q by %q, want %q by %q", w.check, w.image, d.Resolution, d.ResolvedBy, w.resolution, w.by)
				}
				switch d.Resolution {
				case ResolutionConUnit:
					conunit++
				case ResolutionDockle:
					dockle++
				}
			}
			if found != 1 {
				t.Errorf("%s on %s matches %d discordances, want 1", w.check, w.image, found)
			}
		}
		// tools/adjudication scores the same file as 3 rows in which ConUnit is
		// right and 2 in which Dockle is right.
		if conunit != 3 || dockle != 2 {
			t.Errorf("ConUnit right in %d, Dockle right in %d; want 3 and 2", conunit, dockle)
		}
		if res.Totals.Resolved == nil || *res.Totals.Resolved != 5 || res.Totals.Undecidable != 1 {
			t.Errorf("totals = %+v, want 5 resolved and 1 undecidable", res.Totals)
		}
	})
}

func TestSheetRowResolve(t *testing.T) {
	cases := []struct {
		name      string
		row       SheetRow
		wantLabel string
		wantHow   string
	}{
		{"consensus wins", SheetRow{RaterA: "TP", RaterB: "FP", Consensus: "FP"}, "FP", "consensus"},
		{"consensus without ratings", SheetRow{Consensus: "TP"}, "TP", "consensus"},
		{"consensus beats agreement", SheetRow{RaterA: "TP", RaterB: "TP", Consensus: "UNDECIDABLE"}, "UNDECIDABLE", "consensus"},
		{"both raters agree", SheetRow{RaterA: "TP", RaterB: "TP"}, "TP", "agreed"},
		{"raters disagree and no consensus", SheetRow{RaterA: "TP", RaterB: "FP"}, "", ""},
		{"one rater missing", SheetRow{RaterA: "TP"}, "", ""},
		{"nothing rated", SheetRow{}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label, how := tc.row.Resolve()
			if label != tc.wantLabel || how != tc.wantHow {
				t.Errorf("Resolve = %q, %q; want %q, %q", label, how, tc.wantLabel, tc.wantHow)
			}
		})
	}
}

func TestResolutionFor(t *testing.T) {
	cases := []struct {
		kind  Cell
		label string
		want  string
	}{
		{CellOnlyConUnit, LabelTP, ResolutionConUnit},
		{CellOnlyConUnit, LabelFP, ResolutionDockle},
		{CellOnlyDockle, LabelTP, ResolutionDockle},
		{CellOnlyDockle, LabelFP, ResolutionConUnit},
		{CellOnlyConUnit, LabelUndecidable, ResolutionUndecidable},
		{CellOnlyDockle, LabelUndecidable, ResolutionUndecidable},
		{CellOnlyDockle, "", ""},
	}
	for _, tc := range cases {
		if got := resolutionFor(tc.kind, tc.label); got != tc.want {
			t.Errorf("resolutionFor(%s, %q) = %q, want %q", tc.kind, tc.label, got, tc.want)
		}
	}
}

func TestReadSheet(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantLen int
		wantErr string
	}{
		{"only crosscheck rows are kept", sheetHeader +
			"a1,img1,FS-06,finding,path: /x,TP,TP,\n" +
			"a2,img1,FS-06,crosscheck,discordance,TP,FP,TP\n" +
			"a3,img2,SPEC-07,failure,msg,,,\n", 1, ""},
		{"labels are normalised to upper case", sheetHeader + "a,img1,FS-10,crosscheck,x,tp,fp,undecidable\n", 1, ""},
		{"a byte order mark in front of the header", "\ufeff" + sheetHeader + "a,img1,FS-10,crosscheck,x,TP,TP,\n", 1, ""},
		{"no crosscheck rows", sheetHeader + "a,img1,FS-06,finding,p,TP,TP,\n", 0, ""},
		{"empty file", "", 0, "empty file"},
		{"missing column", "image,rule,category\nimg,FS-10,crosscheck\n", 0, "missing column"},
		{"unknown label", sheetHeader + "a,img1,FS-10,crosscheck,x,YES,TP,\n", 0, "want TP, FP or UNDECIDABLE"},
		{"unknown label in a row that is not a crosscheck row is ignored", sheetHeader + "a,img1,FS-06,finding,p,MAYBE,TP,\n", 0, ""},
		{"the same pair twice", sheetHeader + "a,img1,FS-10,crosscheck,x,TP,TP,\nb,img1,FS-10,crosscheck,y,FP,FP,\n", 0, "appears twice"},
		{"short rows are padded", sheetHeader + "a,img1,FS-10,crosscheck\n", 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ReadSheet(strings.NewReader(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Len() != tc.wantLen {
				t.Errorf("rows = %d, want %d", s.Len(), tc.wantLen)
			}
		})
	}
}

func TestApplySheetResolvesDiscordances(t *testing.T) {
	dup := finding("DKL-LI-0002", "FATAL", "duplicate UID 5 : username b")
	imgs := []*spec.SuiteResult{
		cuImage("a@sha256:1", cuResult("FS-10", spec.OutcomeFail)), // only ConUnit
		cuImage("b@sha256:2", cuResult("FS-10", spec.OutcomePass)), // only Dockle
		cuImage("c@sha256:3", cuResult("FS-10", spec.OutcomeFail)), // only ConUnit, undecidable
		cuImage("d@sha256:4", cuResult("FS-10", spec.OutcomePass)), // only Dockle, raters disagree
		cuImage("e@sha256:5", cuResult("FS-10", spec.OutcomePass)), // only Dockle, no row
		cuImage("f@sha256:6", cuResult("FS-10", spec.OutcomeFail)), // both: no discordance
		cuImage("g@sha256:7", cuResult("FS-10", spec.OutcomePass)), // only Dockle, FP
	}
	records := map[string]*ImageRecord{
		"a@sha256:1": okRecord("a@sha256:1"),
		"b@sha256:2": okRecord("b@sha256:2", dup),
		"c@sha256:3": okRecord("c@sha256:3"),
		"d@sha256:4": okRecord("d@sha256:4", dup),
		"e@sha256:5": okRecord("e@sha256:5", dup),
		"f@sha256:6": okRecord("f@sha256:6", dup),
		"g@sha256:7": okRecord("g@sha256:7", dup),
	}
	sheet, err := ReadSheet(strings.NewReader(sheetHeader +
		"1,a@sha256:1,FS-10,crosscheck,x,TP,TP,\n" + // property present: ConUnit right
		"2,b@sha256:2,FS-10,crosscheck,x,,,TP\n" + // property present: Dockle right (consensus)
		"3,c@sha256:3,FS-10,crosscheck,x,UNDECIDABLE,UNDECIDABLE,\n" +
		"4,d@sha256:4,FS-10,crosscheck,x,TP,FP,\n" + // unresolved
		"7,g@sha256:7,FS-10,crosscheck,x,FP,FP,\n" + // property absent: ConUnit right
		"9,zzz@sha256:9,FS-10,crosscheck,x,TP,TP,\n")) // stale row
	if err != nil {
		t.Fatal(err)
	}
	res := Analyze(loadedStudy(imgs...), records, Options{Sheet: sheet})

	if len(res.Discordances) != 6 {
		t.Fatalf("discordances = %d, want 6", len(res.Discordances))
	}
	byImage := map[string]Discordance{}
	for _, d := range res.Discordances {
		byImage[d.Image] = d
	}
	cases := []struct {
		image, resolution, by string
	}{
		{"a@sha256:1", ResolutionConUnit, "agreed"},
		{"b@sha256:2", ResolutionDockle, "consensus"},
		{"c@sha256:3", ResolutionUndecidable, "agreed"},
		{"d@sha256:4", "", ""},
		{"e@sha256:5", "", ""},
		{"g@sha256:7", ResolutionConUnit, "agreed"},
	}
	for _, c := range cases {
		d := byImage[c.image]
		if d.Resolution != c.resolution || d.ResolvedBy != c.by {
			t.Errorf("%s: resolution %q by %q, want %q by %q", c.image, d.Resolution, d.ResolvedBy, c.resolution, c.by)
		}
	}
	if res.Totals.Resolved == nil || *res.Totals.Resolved != 3 || res.Totals.Undecidable != 1 {
		t.Errorf("resolved = %v, undecidable = %d; want 3 resolved with a winner and 1 undecidable", res.Totals.Resolved, res.Totals.Undecidable)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "1 of 6 discordances have no row") {
		t.Errorf("missing rows must be warned about once: %v", res.Warnings)
	}
	if !strings.Contains(joined, "1 cross-check rows of the adjudication sheet match no discordance") {
		t.Errorf("a stale row must be warned about: %v", res.Warnings)
	}
}

func TestWithoutASheetResolvedIsNull(t *testing.T) {
	const key = "a@sha256:1"
	res := analyze1(t, cuImage(key, cuResult("FS-10", spec.OutcomeFail)), okRecord(key))
	if res.Totals.Resolved != nil {
		t.Errorf("resolved = %d, want null without an adjudication sheet", *res.Totals.Resolved)
	}
	for _, d := range res.Discordances {
		if d.Resolution != "" || d.ResolvedBy != "" {
			t.Errorf("discordance %+v must be unresolved", d)
		}
	}
}

func TestEmptySheetResolvesNothingButCountsZero(t *testing.T) {
	const key = "a@sha256:1"
	sheet, err := ReadSheet(strings.NewReader(sheetHeader))
	if err != nil {
		t.Fatal(err)
	}
	res := Analyze(loadedStudy(cuImage(key, cuResult("FS-10", spec.OutcomeFail))), map[string]*ImageRecord{key: okRecord(key)}, Options{Sheet: sheet})
	if res.Totals.Resolved == nil || *res.Totals.Resolved != 0 {
		t.Errorf("resolved = %v, want 0 when a sheet was given", res.Totals.Resolved)
	}
}
