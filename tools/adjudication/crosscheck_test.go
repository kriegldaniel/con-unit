package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

var update = flag.Bool("update", false, "rewrite the golden files of testdata/golden")

const (
	fixtureInput = "testdata/crosscheck_input.json"
	// fixtureStudySHA is the study digest that the fixture names. No study of
	// these tests has it.
	fixtureStudySHA = "abababababababababababababababababababababababababababababababab"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Reading crosscheck.json

func TestReadCrosscheckValidation(t *testing.T) {
	disc := func(extra string) string {
		return `{"image":"nginx@sha256:1","check":"SPEC-07","kind":"only_conunit","dockle_code":"CIS-DI-0001"` + extra + `}`
	}
	cases := []struct {
		name     string
		json     string
		studySHA string
		wantErr  string
		wantRows int
		wantWarn string
	}{
		{name: "valid", json: `{"schema_version":"1","discordances":[` + disc("") + `]}`, wantRows: 1},
		{name: "empty array is allowed", json: `{"schema_version":"1","discordances":[]}`, wantRows: 0},
		{name: "missing array", json: `{"schema_version":"1"}`, wantErr: "no discordances array"},
		{name: "null array", json: `{"schema_version":"1","discordances":null}`, wantErr: "no discordances array"},
		{name: "no schema version", json: `{"discordances":[]}`, wantErr: "schema_version is missing"},
		{name: "other schema version", json: `{"schema_version":"7","discordances":[]}`, wantWarn: `schema_version "7"`},
		{name: "other study", json: `{"schema_version":"1","study":{"sha256":"` + fixtureStudySHA + `"},"discordances":[]}`,
			studySHA: strings.Repeat("f", 64), wantWarn: "abababababab"},
		{name: "same study", json: `{"schema_version":"1","study":{"sha256":"` + fixtureStudySHA + `"},"discordances":[]}`,
			studySHA: fixtureStudySHA},
		{name: "no study digest in the file", json: `{"schema_version":"1","discordances":[]}`, studySHA: fixtureStudySHA},
		{name: "unknown kind", json: `{"schema_version":"1","discordances":[{"image":"i","check":"SPEC-07","kind":"both"}]}`, wantErr: `kind "both"`},
		{name: "empty kind", json: `{"schema_version":"1","discordances":[{"image":"i","check":"SPEC-07"}]}`, wantErr: `kind ""`},
		{name: "no image", json: `{"schema_version":"1","discordances":[{"check":"SPEC-07","kind":"only_dockle"}]}`, wantErr: "no image or no check"},
		{name: "no check", json: `{"schema_version":"1","discordances":[{"image":"i","kind":"only_dockle"}]}`, wantErr: "no image or no check"},
		{name: "pair listed twice", json: `{"schema_version":"1","discordances":[` + disc("") + `,` + disc("") + `]}`, wantErr: "listed twice"},
		{name: "not json", json: `{"schema_version":`, wantErr: "parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeFile(t, t.TempDir(), "crosscheck.json", c.json)
			ds, warnings, err := readCrosscheck(p, c.studySHA)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(ds) != c.wantRows {
				t.Errorf("%d discordances, want %d", len(ds), c.wantRows)
			}
			joined := strings.Join(warnings, "\n")
			switch {
			case c.wantWarn == "" && len(warnings) > 0:
				t.Errorf("unexpected warnings: %s", joined)
			case c.wantWarn != "" && !strings.Contains(joined, c.wantWarn):
				t.Errorf("warnings %q lack %q", joined, c.wantWarn)
			}
		})
	}
	if _, _, err := readCrosscheck(filepath.Join(t.TempDir(), "none.json"), ""); err == nil {
		t.Error("a missing file must be an error")
	}
}

// ---------------------------------------------------------------------------
// Evidence, kind and attribution

func TestCrosscheckEvidenceStatesQuestionAndLabelMeaning(t *testing.T) {
	cases := []struct {
		name   string
		d      crosscheckDiscordance
		first  string
		wants  []string
		absent []string
	}{
		{
			name: "only ConUnit, all fields",
			d: crosscheckDiscordance{
				Image: "nginx@sha256:1", Check: "SPEC-12", Kind: KindOnlyConUnit, DockleCode: "DKL-DI-0002",
				ConUnitOutcome: "FAIL", ConUnitEvidence: "volume /proc/self declared",
				IntendedDifference: "ConUnit also fails a volume below /proc",
			},
			first: "kind: only_conunit",
			wants: []string{
				"question: ConUnit reports FAIL for SPEC-12 and Dockle reports no finding for DKL-DI-0002.",
				"TP = present in the image, so ConUnit is right. FP = absent from the image, so Dockle is right.",
				"UNDECIDABLE",
				"ConUnit outcome: FAIL",
				"ConUnit evidence: volume /proc/self declared",
				"Dockle code: DKL-DI-0002",
				"Dockle alert: none recorded",
				"(a candidate cause, not a verdict): ConUnit also fails a volume below /proc",
			},
		},
		{
			name: "only Dockle, all fields",
			d: crosscheckDiscordance{
				Image: "seeded@sha256:3", Check: "FS-06", Kind: KindOnlyDockle, DockleCode: "CIS-DI-0010", DockleFinding: true,
				ConUnitOutcome: "PASS", DockleAlert: "CIS-DI-0010 FATAL: Suspicious filename found : app/id_rsa",
				IntendedDifference: "Dockle fails on a credential file name alone",
			},
			first: "kind: only_dockle",
			wants: []string{
				"question: Dockle reports a finding (CIS-DI-0010) and ConUnit reports PASS for FS-06.",
				"TP = present in the image, so Dockle is right. FP = absent from the image, so ConUnit is right.",
				"ConUnit outcome: PASS",
				"ConUnit evidence: none recorded",
				"Dockle alert: CIS-DI-0010 FATAL: Suspicious filename found : app/id_rsa",
				"a verdict): Dockle fails on a credential file name alone",
			},
		},
		{
			name:  "no documented difference",
			d:     crosscheckDiscordance{Image: "i", Check: "FS-11", Kind: KindOnlyDockle, DockleCode: "DKL-LI-0003", ConUnitOutcome: "PASS"},
			first: "kind: only_dockle",
			wants: []string{"a verdict): none known"},
		},
		{
			name:   "ConUnit is not told the answer",
			d:      crosscheckDiscordance{Image: "i", Check: "SPEC-07", Kind: KindOnlyConUnit, DockleCode: "CIS-DI-0001"},
			first:  "kind: only_conunit",
			wants:  []string{"ConUnit reports FAIL for SPEC-07"},
			absent: []string{"conunit_correct", "dockle_correct"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := crosscheckEvidence(c.d)
			if got := firstLine(ev); got != c.first {
				t.Errorf("first line = %q, want exactly %q", got, c.first)
			}
			if kind, ok := crosscheckKind(ev); !ok || kind != c.d.Kind {
				t.Errorf("the kind cannot be read back: %q %v", kind, ok)
			}
			for _, w := range c.wants {
				if !strings.Contains(ev, w) {
					t.Errorf("evidence lacks %q:\n%s", w, ev)
				}
			}
			for _, a := range c.absent {
				if strings.Contains(ev, a) {
					t.Errorf("evidence must not hold %q:\n%s", a, ev)
				}
			}
			for _, r := range ev {
				if r > 126 {
					t.Errorf("evidence holds the non-ASCII character %q", r)
					break
				}
			}
		})
	}
}

func TestCrosscheckKindReadsOnlyTheFirstLine(t *testing.T) {
	cases := []struct {
		name     string
		evidence string
		kind     string
		ok       bool
	}{
		{"only ConUnit", "kind: only_conunit\nrest", KindOnlyConUnit, true},
		{"only Dockle", "kind: only_dockle\nrest", KindOnlyDockle, true},
		{"nothing else", "kind: only_dockle", KindOnlyDockle, true},
		{"carriage return", "kind: only_conunit\r\nrest", KindOnlyConUnit, true},
		{"padding around the line", "  kind: only_dockle  \nrest", KindOnlyDockle, true},
		{"padding after the prefix", "kind:  only_dockle \nrest", KindOnlyDockle, true},
		{"no space after the colon", "kind:only_dockle\nrest", "", false},
		{"unknown kind", "kind: both\nrest", "", false},
		{"no prefix", "only_conunit\nrest", "", false},
		{"kind on a later line", "question: x\nkind: only_conunit", "", false},
		{"empty", "", "", false},
		{"upper case", "kind: ONLY_DOCKLE", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, ok := crosscheckKind(c.evidence)
			if kind != c.kind || ok != c.ok {
				t.Errorf("crosscheckKind(%q) = %q, %v; want %q, %v", c.evidence, kind, ok, c.kind, c.ok)
			}
		})
	}
}

func TestCrosscheckRightIsTheSameTableAsTheCrosscheckTool(t *testing.T) {
	cases := []struct{ kind, label, want string }{
		{KindOnlyConUnit, LabelTP, rightConUnit},
		{KindOnlyConUnit, LabelFP, rightDockle},
		{KindOnlyDockle, LabelTP, rightDockle},
		{KindOnlyDockle, LabelFP, rightConUnit},
		{KindOnlyConUnit, LabelUndecidable, ""},
		{KindOnlyDockle, LabelUndecidable, ""},
		{KindOnlyConUnit, "", ""},
		{"", LabelTP, ""},
		{"both", LabelFP, ""},
	}
	for _, c := range cases {
		if got := crosscheckRight(c.kind, c.label); got != c.want {
			t.Errorf("crosscheckRight(%q, %q) = %q, want %q", c.kind, c.label, got, c.want)
		}
	}
}

func TestCrosscheckRowsHaveStableDistinctIDs(t *testing.T) {
	ds := []crosscheckDiscordance{
		{Image: "a", Check: "SPEC-07", Kind: KindOnlyConUnit, DockleCode: "CIS-DI-0001", ConUnitOutcome: "FAIL"},
		{Image: "a", Check: "FS-01", Kind: KindOnlyDockle, DockleCode: "DKL-DI-0005", ConUnitOutcome: "PASS"},
		{Image: "b", Check: "SPEC-07", Kind: KindOnlyConUnit, DockleCode: "CIS-DI-0001", ConUnitOutcome: "FAIL"},
	}
	first, second := crosscheckRows(ds), crosscheckRows(ds)
	if !reflect.DeepEqual(first, second) {
		t.Error("the rows must not depend on anything but the input")
	}
	seen := map[string]bool{}
	for _, r := range first {
		if len(r.ID) != 12 || strings.Trim(r.ID, "0123456789abcdef") != "" {
			t.Errorf("row id %q must be 12 hex characters", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("row id %q is not unique", r.ID)
		}
		seen[r.ID] = true
		if r.Category != CategoryCrosscheck || r.RaterA != "" || r.RaterB != "" || r.Consensus != "" {
			t.Errorf("a template row needs the category crosscheck and no rating: %+v", r)
		}
	}
	// The same pair as a study row has another category and so another ID.
	study := newRow("a", "SPEC-07", CategoryFailure, "", "x")
	if seen[study.ID] {
		t.Error("a study row and a cross-check row must not share an ID")
	}
}

// ---------------------------------------------------------------------------
// Export

func writeCrosscheckFixture(t *testing.T, dir string, ds ...crosscheckDiscordance) string {
	t.Helper()
	doc := map[string]any{"schema_version": "1", "study": map[string]string{"sha256": fixtureStudySHA}, "discordances": ds}
	if ds == nil {
		doc["discordances"] = []crosscheckDiscordance{}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, "crosscheck.json", string(b))
}

func TestExportWithCrosscheckMergesRowsInOrderAndSamplesOnlyStudyRows(t *testing.T) {
	dir := t.TempDir()
	study := writeStudy(t, dir)
	cc := writeCrosscheckFixture(t, dir,
		// The same image and check as a study row of the fixture study.
		crosscheckDiscordance{Image: "a@sha256:1", Check: "SPEC-07", Kind: KindOnlyDockle, DockleCode: "CIS-DI-0001", ConUnitOutcome: "PASS", DockleFinding: true},
		crosscheckDiscordance{Image: "b@sha256:2", Check: "FS-01", Kind: KindOnlyConUnit, DockleCode: "DKL-DI-0004+DKL-DI-0005", ConUnitOutcome: "FAIL"},
		// A check name that the EXEC sample would drop if it applied to these rows.
		crosscheckDiscordance{Image: "b@sha256:2", Check: "EXEC-05", Kind: KindOnlyConUnit, DockleCode: "X", ConUnitOutcome: "FAIL"},
	)
	out := filepath.Join(dir, "template.csv")
	var stdout, stderr bytes.Buffer
	code := run([]string{"export", "-study", study, "-crosscheck", cc, "-exec-sample", "1", "-out", out}, &stdout, &stderr)
	if code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ReadRows(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("the template must be readable: %v", err)
	}
	var crosscheck, exec int
	for _, r := range rows {
		switch {
		case r.Category == CategoryCrosscheck:
			crosscheck++
		case strings.HasPrefix(r.Rule, "EXEC-"):
			exec++
		}
	}
	if crosscheck != 3 {
		t.Errorf("%d cross-check rows, want all 3", crosscheck)
	}
	if exec != 1 {
		t.Errorf("%d EXEC study rows, want the sample of 1", exec)
	}
	// 9 study rows of the fixture study, 2 EXEC rows dropped by the sample.
	if len(rows) != 9-2+3 {
		t.Errorf("%d rows, want 10", len(rows))
	}

	// The order is the common one: rule (natural), image, category, id. The
	// SPEC-07 pair on image a sorts before the study failure of the same
	// image, because crosscheck sorts before failure.
	var seen []string
	for _, r := range rows {
		if r.Rule == "SPEC-07" && strings.HasPrefix(r.Image, "a@") {
			seen = append(seen, r.Category)
		}
	}
	if strings.Join(seen, ",") != "crosscheck,failure" {
		t.Errorf("SPEC-07 on image a: categories %v, want crosscheck then failure", seen)
	}
	for i := 1; i < len(rows); i++ {
		a, b := rows[i-1], rows[i]
		if a.Rule == b.Rule && a.Image == b.Image && a.Category > b.Category {
			t.Errorf("rows %d and %d are out of order", i, i+1)
		}
	}
	if !strings.Contains(stdout.String(), "SPEC-07 crosscheck") {
		t.Errorf("the console summary must count the cross-check rows:\n%s", stdout.String())
	}
}

func TestExportWithoutDiscordanceChangesNothingAndWarns(t *testing.T) {
	dir := t.TempDir()
	study := writeStudy(t, dir)
	plain := filepath.Join(dir, "plain.csv")
	withEmpty := filepath.Join(dir, "with_empty.csv")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"export", "-study", study, "-out", plain}, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("plain export: exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "crosscheck") {
		t.Errorf("an export without -crosscheck must not mention it: %s", stderr.String())
	}
	cc := writeCrosscheckFixture(t, dir)
	stderr.Reset()
	if code := run([]string{"export", "-study", study, "-crosscheck", cc, "-out", withEmpty}, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("export with an empty crosscheck.json: exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "holds no discordance") {
		t.Errorf("an empty discordances array must warn: %s", stderr.String())
	}
	a, _ := os.ReadFile(plain)
	b, _ := os.ReadFile(withEmpty)
	if !bytes.Equal(a, b) {
		t.Error("an empty discordances array must not change the sheet")
	}
}

func TestExportWithBadCrosscheckFailsAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	study := writeStudy(t, dir)
	cases := map[string]string{
		"missing file":      filepath.Join(dir, "none.json"),
		"missing array":     writeFile(t, dir, "no_array.json", `{"schema_version":"1"}`),
		"null array":        writeFile(t, dir, "null_array.json", `{"schema_version":"1","discordances":null}`),
		"not a crosscheck":  writeFile(t, dir, "other.json", `{"images":[]}`),
		"unknown kind":      writeFile(t, dir, "kind.json", `{"schema_version":"1","discordances":[{"image":"i","check":"FS-01","kind":"x"}]}`),
		"truncated content": writeFile(t, dir, "cut.json", `{"schema_version":"1","discordances":[`),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".csv")
			var stdout, stderr bytes.Buffer
			if code := run([]string{"export", "-study", study, "-crosscheck", path, "-out", out}, &stdout, &stderr); code != spec.ExitFindings {
				t.Errorf("exit %d, want %d: %s", code, spec.ExitFindings, stderr.String())
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("no template may be written when crosscheck.json is unusable")
			}
			if !strings.Contains(stderr.String(), filepath.Base(path)) {
				t.Errorf("the error must name the file: %s", stderr.String())
			}
		})
	}
}

func TestExportWarnsWhenTheCrosscheckBelongsToAnotherStudy(t *testing.T) {
	dir := t.TempDir()
	study := writeStudy(t, dir)
	cc := writeCrosscheckFixture(t, dir, crosscheckDiscordance{Image: "a@sha256:1", Check: "FS-01", Kind: KindOnlyDockle, DockleCode: "DKL-DI-0005"})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"export", "-study", study, "-crosscheck", cc, "-out", filepath.Join(dir, "t.csv")}, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "was made from a study with sha256 abababababab") {
		t.Errorf("the study mismatch must be a warning: %s", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Score

func ccRow(id, image, rule, kind, a, b, consensus string) Row {
	d := crosscheckDiscordance{Image: image, Check: rule, Kind: kind, DockleCode: "CIS-DI-0001", ConUnitOutcome: "FAIL"}
	if kind == KindOnlyDockle {
		d.ConUnitOutcome, d.DockleFinding = "PASS", true
	}
	return Row{ID: id, Image: image, Rule: rule, Category: CategoryCrosscheck, Evidence: crosscheckEvidence(d), RaterA: a, RaterB: b, Consensus: consensus}
}

func attributionRows() []Row {
	return []Row{
		ccRow("c1", "i1", "SPEC-07", KindOnlyConUnit, LabelTP, LabelTP, ""),
		ccRow("c2", "i2", "SPEC-07", KindOnlyConUnit, LabelFP, LabelFP, ""),
		ccRow("c3", "i3", "SPEC-07", KindOnlyDockle, LabelTP, LabelTP, ""),
		ccRow("c4", "i4", "SPEC-07", KindOnlyDockle, LabelFP, LabelFP, ""),
		ccRow("c5", "i5", "FS-06", KindOnlyDockle, LabelTP, LabelFP, LabelFP),
		ccRow("c6", "i6", "FS-06", KindOnlyConUnit, LabelUndecidable, LabelUndecidable, ""),
		ccRow("c7", "i7", "FS-06", KindOnlyConUnit, LabelTP, LabelFP, ""),
		ccRow("c8", "i8", "FS-11", KindOnlyDockle, LabelTP, "", ""),
		ccRow("c9", "i9", "FS-11", KindOnlyDockle, "", "", LabelTP),
	}
}

type wantCounts struct {
	rows, unrated, tp, fp, undecidable, unresolved, conunit, dockle int
}

func (w wantCounts) check(t *testing.T, name string, c CrosscheckCounts) {
	t.Helper()
	got := wantCounts{c.Rows, c.Unrated, c.TP, c.FP, c.Undecidable, c.Unresolved, c.ConUnitCorrect, c.DockleCorrect}
	if got != w {
		t.Errorf("%s: %+v, want %+v", name, got, w)
	}
	if c.Unattributed != 0 {
		t.Errorf("%s: unattributed = %d, want 0", name, c.Unattributed)
	}
	if c.TP+c.FP != c.ConUnitCorrect+c.DockleCorrect {
		t.Errorf("%s: TP+FP = %d differs from the attributed rows %d", name, c.TP+c.FP, c.ConUnitCorrect+c.DockleCorrect)
	}
	if c.Rows != c.TP+c.FP+c.Undecidable+c.Unresolved {
		t.Errorf("%s: the rows do not add up: %+v", name, c)
	}
}

func TestScoreAttributesCrosscheckRowsByKindAndLabel(t *testing.T) {
	s := Score(attributionRows(), "x.csv", "abc", DefaultThreshold)
	cc := s.Crosscheck
	if cc == nil {
		t.Fatal("no crosscheck section")
	}
	wantCounts{rows: 9, unrated: 2, tp: 3, fp: 3, undecidable: 1, unresolved: 2, conunit: 3, dockle: 3}.check(t, "all", cc.CrosscheckCounts)
	if cc.ConUnitCorrectShare == nil || !near(cc.ConUnitCorrectShare.Estimate, 0.5) {
		t.Errorf("ConUnit share = %+v, want 0.5", cc.ConUnitCorrectShare)
	}
	if lo, hi := cc.ConUnitCorrectShare.Lo, cc.ConUnitCorrectShare.Hi; !(lo > 0 && lo < 0.5 && hi > 0.5 && hi < 1) {
		t.Errorf("Wilson interval = [%v, %v] must enclose 0.5", lo, hi)
	}

	if len(cc.ByKind) != 2 || cc.ByKind[0].Kind != KindOnlyConUnit || cc.ByKind[1].Kind != KindOnlyDockle {
		t.Fatalf("by_kind = %+v, want only_conunit then only_dockle", cc.ByKind)
	}
	wantCounts{rows: 4, unrated: 0, tp: 1, fp: 1, undecidable: 1, unresolved: 1, conunit: 1, dockle: 1}.check(t, "only_conunit", cc.ByKind[0].CrosscheckCounts)
	wantCounts{rows: 5, unrated: 2, tp: 2, fp: 2, undecidable: 0, unresolved: 1, conunit: 2, dockle: 2}.check(t, "only_dockle", cc.ByKind[1].CrosscheckCounts)

	want := []struct {
		rule string
		w    wantCounts
	}{
		{"FS-06", wantCounts{rows: 3, unrated: 0, tp: 0, fp: 1, undecidable: 1, unresolved: 1, conunit: 1, dockle: 0}},
		{"FS-11", wantCounts{rows: 2, unrated: 2, tp: 1, fp: 0, undecidable: 0, unresolved: 1, conunit: 0, dockle: 1}},
		{"SPEC-07", wantCounts{rows: 4, unrated: 0, tp: 2, fp: 2, undecidable: 0, unresolved: 0, conunit: 2, dockle: 2}},
	}
	if len(cc.Checks) != len(want) {
		t.Fatalf("%d checks, want %d: %+v", len(cc.Checks), len(want), cc.Checks)
	}
	for i, w := range want {
		if cc.Checks[i].Rule != w.rule {
			t.Errorf("check %d is %s, want %s", i, cc.Checks[i].Rule, w.rule)
		}
		w.w.check(t, w.rule, cc.Checks[i].CrosscheckCounts)
	}
	// FS-11 has only a Dockle-right row: the ConUnit share is 0 of 1, not undefined.
	if sh := cc.Checks[1].ConUnitCorrectShare; sh == nil || sh.Estimate != 0 {
		t.Errorf("FS-11 share = %+v, want 0", sh)
	}

	// Rater agreement covers the doubly rated rows only: c1 to c7, five of
	// which agree. Rows c8 and c9 are not rated twice.
	ag := cc.Agreement
	if ag.Rated != 7 || ag.Agree != 5 || ag.Agreement == nil || !near(*ag.Agreement, 5.0/7.0) || ag.Kappa == nil {
		t.Errorf("rater agreement = %+v", ag)
	}
}

func TestScoreKeepsCrosscheckRowsOutOfTheStudyFigures(t *testing.T) {
	var study []Row
	study = append(study, mkRows("FS-06", CategoryFinding, LabelTP, LabelTP, "", 20)...)
	study = append(study, mkRows("FS-06", CategoryFinding, LabelFP, LabelFP, "", 5)...)
	study = append(study, mkRows("SPEC-07", CategoryFailure, LabelTP, "", "", 2)...) // unrated
	study = append(study, mkRows("EXEC-01", CategoryFailure, LabelUndecidable, LabelUndecidable, "", 3)...)

	alone := Score(study, "x.csv", "abc", DefaultThreshold)
	both := Score(append(append([]Row(nil), study...), attributionRows()...), "x.csv", "abc", DefaultThreshold)

	if alone.Crosscheck != nil {
		t.Error("without cross-check rows the section must be absent")
	}
	if both.Crosscheck == nil || both.Crosscheck.Rows != 9 {
		t.Fatalf("crosscheck section = %+v", both.Crosscheck)
	}
	if both.Rows != alone.Rows || both.Unrated != alone.Unrated || both.Rows != len(study) {
		t.Errorf("rows %d unrated %d, want %d and %d", both.Rows, both.Unrated, alone.Rows, alone.Unrated)
	}
	if !reflect.DeepEqual(both.Overall, alone.Overall) {
		t.Errorf("overall agreement changed: %+v vs %+v", both.Overall, alone.Overall)
	}
	if !reflect.DeepEqual(both.Checks, alone.Checks) {
		t.Errorf("per-check results changed:\n%+v\n%+v", both.Checks, alone.Checks)
	}
	// SPEC-07 and FS-06 appear in both parts; the study line holds study rows only.
	if got := find(t, both, "SPEC-07"); got.Rows != 2 {
		t.Errorf("SPEC-07 study rows = %d, want 2", got.Rows)
	}
	// The study figures are those of the unchanged rule: a check of the study
	// only, without any cross-check row, still gets its entry.
	if got := find(t, both, "EXEC-01"); got.Undecid != 3 {
		t.Errorf("EXEC-01 = %+v", got)
	}
	if both.SchemaVersion != "2" || alone.SchemaVersion != "2" {
		t.Errorf("schema versions %q and %q, want 2", alone.SchemaVersion, both.SchemaVersion)
	}
}

func TestScoreWithOnlyCrosscheckRows(t *testing.T) {
	s := Score(attributionRows(), "x.csv", "abc", DefaultThreshold)
	if s.Rows != 0 || s.Unrated != 0 || s.Overall.Rated != 0 || len(s.Checks) != 0 {
		t.Errorf("a sheet of cross-check rows has no study figures: %+v", s)
	}
	if s.Crosscheck == nil {
		t.Error("no crosscheck section")
	}
}

func TestScoreCountsAResolvedRowWithoutKindAsUnattributed(t *testing.T) {
	r := Row{ID: "x", Image: "i", Rule: "SPEC-07", Category: CategoryCrosscheck, Evidence: "no kind line", RaterA: LabelTP, RaterB: LabelTP}
	cc := Score([]Row{r}, "x.csv", "abc", DefaultThreshold).Crosscheck
	if cc.TP != 1 || cc.Unattributed != 1 || cc.ConUnitCorrect != 0 || cc.DockleCorrect != 0 || cc.ConUnitCorrectShare != nil {
		t.Errorf("counts = %+v", cc.CrosscheckCounts)
	}
	if len(cc.ByKind) != 2 || cc.ByKind[0].Rows != 0 || cc.ByKind[1].Rows != 0 {
		t.Errorf("a row of unknown kind is in no kind: %+v", cc.ByKind)
	}
}

func TestReadRowsRequiresTheKindLineOfCrosscheckRows(t *testing.T) {
	header := "finding_id,image,rule,category,evidence,rater_a,rater_b,consensus\n"
	good := ccRow("id1", "img", "SPEC-07", KindOnlyDockle, "", "", "")
	var buf bytes.Buffer
	if err := writeTemplateTo(&buf, []Row{good}); err != nil {
		t.Fatal(err)
	}
	rows, err := ReadRows(&buf)
	if err != nil {
		t.Fatalf("a valid cross-check row must be read: %v", err)
	}
	if rows[0].Evidence != good.Evidence || rows[0].Category != CategoryCrosscheck {
		t.Errorf("the multi-line evidence must survive the round trip:\n%q\n%q", rows[0].Evidence, good.Evidence)
	}

	bad := map[string]string{
		"no kind line":      header + "id1,img,SPEC-07,crosscheck,some evidence,TP,TP,\n",
		"unknown kind":      header + "id1,img,SPEC-07,crosscheck,\"kind: both\nmore\",TP,TP,\n",
		"empty evidence":    header + "id1,img,SPEC-07,crosscheck,,TP,TP,\n",
		"kind on line two":  header + "id1,img,SPEC-07,crosscheck,\"first\nkind: only_dockle\",TP,TP,\n",
		"upper case kind":   header + "id1,img,SPEC-07,crosscheck,KIND: ONLY_DOCKLE,TP,TP,\n",
		"second row broken": header + "id1,img,SPEC-07,crosscheck,kind: only_dockle,TP,TP,\nid2,img,FS-01,crosscheck,nothing,TP,TP,\n",
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := ReadRows(strings.NewReader(content))
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, want := range []string{"crosscheck row", "kind: only_conunit", "kind: only_dockle"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q lacks %q", err, want)
				}
			}
		})
	}
	_, err = ReadRows(strings.NewReader(bad["second row broken"]))
	if err == nil || !strings.Contains(err.Error(), "row 3") || !strings.Contains(err.Error(), "FS-01") {
		t.Errorf("the error must name the row: %v", err)
	}
	// A study row needs no kind line.
	if _, err := ReadRows(strings.NewReader(header + "id1,img,FS-06,finding,path: /x,TP,TP,\n")); err != nil {
		t.Errorf("a study row must stay valid: %v", err)
	}
}

// writeTemplateTo renders rows the way writeTemplate does, into a buffer.
func writeTemplateTo(buf *bytes.Buffer, rows []Row) error {
	dir, err := os.MkdirTemp("", "adjudication-test")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "t.csv")
	if err := writeTemplate(p, rows); err != nil {
		return err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	buf.Write(b)
	return nil
}

func TestSummarySerializesTheCrosscheckSection(t *testing.T) {
	without, err := json.Marshal(Score(mkRows("FS-06", CategoryFinding, LabelTP, LabelTP, "", 2), "x.csv", "abc", DefaultThreshold))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(without), `"schema_version":"2"`) || !strings.Contains(string(without), `"crosscheck":null`) {
		t.Errorf("a summary without cross-check rows has schema 2 and a null section: %s", without)
	}

	with, err := json.Marshal(Score(attributionRows(), "x.csv", "abc", DefaultThreshold))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Crosscheck map[string]json.RawMessage `json:"crosscheck"`
	}
	if err := json.Unmarshal(with, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rows", "unrated", "tp", "fp", "undecidable", "unresolved", "conunit_correct", "dockle_correct",
		"unattributed", "conunit_correct_share", "rater_agreement", "by_kind", "checks"} {
		if _, ok := doc.Crosscheck[key]; !ok {
			t.Errorf("the crosscheck section lacks %q: %v", key, keys(doc.Crosscheck))
		}
	}
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// Golden files of the whole flow: export, rating, score

// fill is the rating of one cross-check row of the fixture, found by check and
// by a part of the image name.
type fill struct{ rule, image, a, b, consensus string }

// fixtureFills rates seven of the eight pairs of the fixture. The pair FS-11 on
// the seeded image stays unrated.
var fixtureFills = []fill{
	{"CIS-4.6", "distroless", LabelTP, LabelTP, ""},            // only Dockle, present: Dockle right
	{"SPEC-12", "distroless", LabelTP, LabelTP, ""},            // only ConUnit, present: ConUnit right
	{"SPEC-09", "nginx", LabelTP, LabelFP, LabelFP},            // only Dockle, consensus absent: ConUnit right
	{"FS-01", "nginx", LabelUndecidable, LabelUndecidable, ""}, // only ConUnit, undecidable
	{"FS-06", "seeded", LabelFP, LabelFP, ""},                  // only Dockle, absent: ConUnit right
	{"SPEC-11", "seeded", LabelTP, "", ""},                     // only rater A: unresolved
	{"FS-01", "seeded", LabelTP, LabelTP, ""},                  // only Dockle, present: Dockle right
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run the tests with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file; run the tests with -update and review the diff\n--- got\n%s", name, got)
	}
}

func TestGoldenCrosscheckSheetAndSummary(t *testing.T) {
	dir := t.TempDir()
	study := writeStudy(t, dir)
	template := filepath.Join(dir, "adjudication.csv")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"export", "-study", study, "-crosscheck", fixtureInput, "-out", template}, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("export: exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "was made from a study with sha256") {
		t.Errorf("the fixture names another study; expected the warning: %s", stderr.String())
	}
	templateBytes, err := os.ReadFile(template)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "template_with_crosscheck.csv", templateBytes)

	rows, err := ReadRows(bytes.NewReader(templateBytes))
	if err != nil {
		t.Fatal(err)
	}
	var studyRows, ccRows int
	for _, r := range rows {
		if r.Category == CategoryCrosscheck {
			ccRows++
		} else {
			studyRows++
		}
	}
	if ccRows != 8 || studyRows != 9 {
		t.Fatalf("the sheet has %d cross-check and %d study rows, want 8 and 9", ccRows, studyRows)
	}

	used := make([]bool, len(fixtureFills))
	for i := range rows {
		if rows[i].Category != CategoryCrosscheck {
			continue
		}
		for j, f := range fixtureFills {
			if rows[i].Rule == f.rule && strings.Contains(rows[i].Image, f.image) {
				if used[j] {
					t.Fatalf("fill %+v matches more than one row", f)
				}
				used[j] = true
				rows[i].RaterA, rows[i].RaterB, rows[i].Consensus = f.a, f.b, f.consensus
			}
		}
	}
	for j, ok := range used {
		if !ok {
			t.Fatalf("fill %+v matches no row", fixtureFills[j])
		}
	}
	filled := filepath.Join(dir, "adjudication.csv")
	if err := writeTemplate(filled, rows); err != nil {
		t.Fatal(err)
	}
	filledBytes, err := os.ReadFile(filled)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "filled_with_crosscheck.csv", filledBytes)

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"score", "-csv", filled}, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("score: exit %d: %s", code, stderr.String())
	}
	summaryBytes, err := os.ReadFile(filepath.Join(dir, "adjudication_summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "summary_with_crosscheck.json", summaryBytes)

	var sum Summary
	if err := json.Unmarshal(summaryBytes, &sum); err != nil {
		t.Fatal(err)
	}
	cc := sum.Crosscheck
	if cc == nil {
		t.Fatal("no crosscheck section")
	}
	wantCounts{rows: 8, unrated: 2, tp: 3, fp: 2, undecidable: 1, unresolved: 2, conunit: 3, dockle: 2}.check(t, "fixture", cc.CrosscheckCounts)
	if sum.Rows != 9 || sum.Unrated != 9 {
		t.Errorf("the nine study rows are unrated and counted apart: rows %d unrated %d", sum.Rows, sum.Unrated)
	}

	out := stdout.String()
	iStudy := strings.Index(out, "Adjudication summary")
	iCross := strings.Index(out, "Cross-check rows (ConUnit against Dockle)")
	if iStudy < 0 || iCross < iStudy {
		t.Fatalf("the cross-check section must follow the study section:\n%s", out)
	}
	for _, want := range []string{"only_conunit", "only_dockle", "ConUnit right", "Dockle right", "rater agreement", "SPEC-12"} {
		if !strings.Contains(out[iCross:], want) {
			t.Errorf("the cross-check section lacks %q:\n%s", want, out[iCross:])
		}
	}
	if strings.Contains(out[iStudy:iCross], "ConUnit right") {
		t.Errorf("the study section must not show cross-check figures:\n%s", out[iStudy:iCross])
	}
	for _, want := range []string{"cross-check rows lack a rating", "cross-check rows are unresolved"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
		}
	}
}

func TestScoreWithoutCrosscheckRowsPrintsNoCrosscheckSection(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "adjudication.csv")
	if err := writeTemplate(csvPath, mkRows("FS-06", CategoryFinding, LabelTP, LabelTP, "", 3)); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"score", "-csv", csvPath}, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "Cross-check") || strings.Contains(stderr.String(), "cross-check") {
		t.Errorf("no cross-check output without cross-check rows:\n%s\n%s", stdout.String(), stderr.String())
	}
}
