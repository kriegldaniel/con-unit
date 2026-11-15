package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

// update rewrites the golden files: go test ./tools/attribute_exec -run Golden -update
var update = flag.Bool("update", false, "rewrite golden files in tools/attribute_exec/testdata/golden")

const goldenRoot = "testdata/golden"

func assertGolden(t *testing.T, scenario, name, got string) {
	t.Helper()
	path := filepath.Join(goldenRoot, scenario, name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden %s\n--- got ---\n%s\n--- want ---\n%s", name, path, got, string(want))
	}
}

// contractMacros are the macro names of docs/INTERFACE_V2.md section 6 for the
// attribution and the ablation, in order.
var contractMacros = []string{
	"ConUnitAttrSeededN", "ConUnitAttrSeededExact", "ConUnitAttrSeededSuperset", "ConUnitAttrSeededWrong",
	"ConUnitAttrRealPairs", "ConUnitAttrRealReproducible", "ConUnitAttrRealNamedSingle", "ConUnitAttrRealNamedMinimal",
	"ConUnitAttrRealUnionOnly", "ConUnitAttrRealUnresolved", "ConUnitAblExamined", "ConUnitAblMisblamed",
}

var macroLine = regexp.MustCompile(`(?m)^\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}$`)

func macroValues(t *testing.T, tex string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range macroLine.FindAllStringSubmatch(tex, -1) {
		if _, dup := out[m[1]]; dup {
			t.Errorf("macro %s defined twice", m[1])
		}
		out[m[1]] = m[2]
	}
	if got, want := strings.Count(tex, `\newcommand`), len(out); got != want {
		t.Errorf("%d \\newcommand lines, %d of them parsed: a macro line has an unexpected form", got, want)
	}
	return out
}

// fullFixture holds every kind of data the outputs show.
func fullFixture() (*Document, *AblationDocument) {
	attrs := []Attribution{
		{Image: "nginx", Rule: RuleReadOnly, Status: StatusResolvedSingle, ResolvedBy: []string{"/var/cache"}, MinimalSet: []string{"/var/cache"}},
		{Image: "redis", Rule: RuleReadOnly, Status: StatusResolvedMinimal, MinimalSet: []string{"/var/log", "/var/lib"}},
		{Image: "postgres", Rule: RuleReadOnly, Status: StatusResolvedSingle, ResolvedBy: []string{"/var/run"}, MinimalSet: []string{"/var/run"}},
		{Image: "gosu-app", Rule: RuleDropCaps, Status: StatusResolvedMinimal, MinimalSet: []string{"CAP_SETUID", "CAP_SETGID"}},
		{Image: "gosu-two", Rule: RuleDropCaps, Status: StatusResolvedMinimal, MinimalSet: []string{"CAP_SETGID", "CAP_SETUID"}},
		{Image: "chown-app", Rule: RuleDropCaps, Status: StatusResolvedSingle, ResolvedBy: []string{"CAP_CHOWN"}, MinimalSet: []string{"CAP_CHOWN"}},
		{Image: "odd", Rule: RuleDropCaps, Status: StatusResolvedUnion},
		{Image: "stuck", Rule: RuleDropCaps, Status: StatusUnresolved},
		{Image: "flaky", Rule: RuleDropCaps, Status: StatusNotReproduced},
		{Image: "broken", Rule: RuleReadOnly, Status: StatusBaselineFailed},
		{Image: "oneshot", Rule: RuleReadOnly, Status: StatusNotObservable},
		{Image: "gone", Rule: RuleDropCaps, Status: StatusImageAbsent},
	}
	doc := &Document{
		SchemaVersion: documentSchemaVersion, Complete: true,
		Source:       Source{StudyPath: "results/empirical_study.json", StudySHA256: strings.Repeat("ab", 32)},
		Attributions: attrs, Summary: Summarize(attrs),
	}
	truth, _ := ParseTruth([]byte(contractTruth), "tier3_truth.json")
	cases := []struct {
		attr Attribution
	}{
		{resolvedAs(StatusResolvedMinimal, "CAP_SETGID", "CAP_SETUID")},
		{resolvedAs(StatusResolvedSingle, "/var/lib")},
		{resolvedAs(StatusNotReproduced)},
	}
	var results []SeededResult
	for i, c := range truth.Cases {
		verdict, detail := Judge(c, cases[i].attr)
		results = append(results, SeededResult{
			Case: c.Case, Rule: c.Rule, ExpectedMinimal: sortedCopy(c.ExpectedMinimal), Manifests: c.Manifests,
			Verdict: verdict, Detail: detail, MinimalSet: cases[i].attr.MinimalSet, Attribution: cases[i].attr,
		})
	}
	doc.Seeded = &SeededReport{Complete: true, Cases: results, Summary: SummarizeSeeded(results)}

	images := []AblationImage{
		{Image: "a", StudyReasons: []string{"BASELINE_FAILED"}, Status: AblationOK, Misblamed: true, SingleRunFails: 4, Runs: fourRuns(4)},
		{Image: "b", StudyReasons: []string{"BASELINE_FAILED"}, Status: AblationOK, Misblamed: true, SingleRunFails: 1, Runs: fourRuns(1)},
		{Image: "c", StudyReasons: []string{"NOT_OBSERVABLE"}, Status: AblationOK, Misblamed: true, SingleRunFails: 4, Runs: fourRuns(4)},
		{Image: "d", StudyReasons: []string{"NOT_OBSERVABLE"}, Status: AblationOK, Runs: fourRuns(0)},
		{Image: "e", StudyReasons: []string{"BASELINE_FAILED"}, Status: AblationAbsent},
	}
	abl := &AblationDocument{SchemaVersion: ablationSchemaVersion, Complete: true,
		Source: Source{StudyPath: "results/empirical_study.json", StudySHA256: strings.Repeat("ab", 32)},
		Images: images, Summary: SummarizeAblation(images, 5)}
	return doc, abl
}

// fourRuns returns the four treatment runs of an image with the given number of
// single-run FAILs, assigned to the first treatments.
func fourRuns(fails int) []AblationRun {
	var runs []AblationRun
	for i, tr := range ablationTreatments() {
		verdict := SingleRunPass
		if i < fails {
			verdict = SingleRunFail
		}
		runs = append(runs, AblationRun{Rule: tr.Rule, Treatment: tr.Name, SingleRun: verdict})
	}
	return runs
}

func TestGoldenFullOutputs(t *testing.T) {
	att, abl := fullFixture()
	assertGolden(t, "full", macrosFile, RenderMacros(att, abl))
	assertGolden(t, "full", tableFile, RenderTable(att, abl))
}

func TestGoldenWithoutAnyData(t *testing.T) {
	assertGolden(t, "empty", macrosFile, RenderMacros(nil, nil))
	assertGolden(t, "empty", tableFile, RenderTable(nil, nil))
}

func TestGoldenSeededOnly(t *testing.T) {
	att, _ := fullFixture()
	att.Source, att.Attributions, att.Summary = Source{}, nil, Summary{}
	assertGolden(t, "seeded_only", macrosFile, RenderMacros(att, nil))
	assertGolden(t, "seeded_only", tableFile, RenderTable(att, nil))
}

func TestGoldenAblationOnlyAndIncompleteBlocks(t *testing.T) {
	_, abl := fullFixture()
	abl.Complete = false
	assertGolden(t, "ablation_only", macrosFile, RenderMacros(nil, abl))
	assertGolden(t, "ablation_only", tableFile, RenderTable(nil, abl))
}

func TestMacrosHoldExactlyTheContractNamesFollowedByTheDocumentedExtra(t *testing.T) {
	att, abl := fullFixture()
	for _, tc := range []struct {
		name string
		att  *Document
		abl  *AblationDocument
	}{{"full", att, abl}, {"empty", nil, nil}} {
		values := macroValues(t, RenderMacros(tc.att, tc.abl))
		for _, name := range contractMacros {
			if _, ok := values[name]; !ok {
				t.Errorf("%s: macro %s of the contract is missing", tc.name, name)
			}
		}
		if len(values) != len(contractMacros)+1 || values["ConUnitAttrSeededNotManifested"] == "" {
			t.Errorf("%s: %d macros, want the %d of the contract plus ConUnitAttrSeededNotManifested", tc.name, len(values), len(contractMacros))
		}
		for name := range values {
			if !regexp.MustCompile(`^[A-Za-z]+$`).MatchString(name) {
				t.Errorf("macro name %q must contain letters only", name)
			}
		}
	}
}

func TestMacroValuesOfTheFullFixture(t *testing.T) {
	att, abl := fullFixture()
	got := macroValues(t, RenderMacros(att, abl))
	want := map[string]string{
		// Seeded: gosu EXACT, lib EXACT, port NOT_MANIFESTED.
		"ConUnitAttrSeededN": "2", "ConUnitAttrSeededExact": "2", "ConUnitAttrSeededSuperset": "0", "ConUnitAttrSeededWrong": "0", "ConUnitAttrSeededNotManifested": "1",
		// Real: 12 pairs, of which 8 reproduce.
		"ConUnitAttrRealPairs": "12", "ConUnitAttrRealReproducible": "8", "ConUnitAttrRealNamedSingle": "3",
		"ConUnitAttrRealNamedMinimal": "3", "ConUnitAttrRealUnionOnly": "1", "ConUnitAttrRealUnresolved": "1",
		// Ablation: 4 examined, 3 misblamed (the absent image is not examined).
		"ConUnitAblExamined": "4", "ConUnitAblMisblamed": "3",
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %q, want %q", name, got[name], v)
		}
	}
	// The outcomes of the reproducible pairs add up.
	sum := 0
	for _, n := range []string{"ConUnitAttrRealNamedSingle", "ConUnitAttrRealNamedMinimal", "ConUnitAttrRealUnionOnly", "ConUnitAttrRealUnresolved"} {
		v, err := strconv.Atoi(got[n])
		if err != nil {
			t.Fatal(err)
		}
		sum += v
	}
	if sum != 8 {
		t.Errorf("single, minimal, union only and unresolved add up to %d, want the 8 reproducible pairs", sum)
	}
}

func TestMissingBlocksPrintNotAvailableNeverZero(t *testing.T) {
	att, abl := fullFixture()
	cases := []struct {
		name       string
		att        *Document
		abl        *AblationDocument
		naPrefixes []string
		valPrefix  []string
	}{
		{"nothing", nil, nil, []string{"ConUnitAttr", "ConUnitAbl"}, nil},
		{"ablation only", nil, abl, []string{"ConUnitAttr"}, []string{"ConUnitAbl"}},
		{"no study block", &Document{Seeded: att.Seeded}, abl, []string{"ConUnitAttrReal"}, []string{"ConUnitAttrSeeded", "ConUnitAbl"}},
		{"study block, no seeded block", &Document{Source: att.Source, Complete: true, Summary: att.Summary, Attributions: att.Attributions}, nil, []string{"ConUnitAttrSeeded", "ConUnitAbl"}, []string{"ConUnitAttrReal"}},
	}
	for _, tc := range cases {
		values := macroValues(t, RenderMacros(tc.att, tc.abl))
		for name, v := range values {
			for _, p := range tc.naPrefixes {
				if strings.HasPrefix(name, p) && v != "n/a" {
					t.Errorf("%s: %s = %q, want n/a", tc.name, name, v)
				}
			}
			for _, p := range tc.valPrefix {
				if strings.HasPrefix(name, p) && v == "n/a" {
					t.Errorf("%s: %s must have a value", tc.name, name)
				}
			}
		}
	}
}

func TestIncompleteBlocksAreMarkedInTheMacros(t *testing.T) {
	att, abl := fullFixture()
	att.Complete, att.Seeded.Complete, abl.Complete = false, false, false
	got := RenderMacros(att, abl)
	for _, want := range []string{"the study block of attribution.json is incomplete", "the seeded block of attribution.json is incomplete", "ablation.json is incomplete"} {
		if !strings.Contains(got, want) {
			t.Errorf("macros lack the warning %q", want)
		}
	}
	att.Complete, att.Seeded.Complete, abl.Complete = true, true, true
	if strings.Contains(RenderMacros(att, abl), "WARNING") {
		t.Error("complete blocks must not be marked")
	}
}

func TestTableCarriesTheLabelOnceAndNoTypedNumbers(t *testing.T) {
	att, abl := fullFixture()
	table := RenderTable(att, abl)
	if strings.Count(table, `\label{tab:attribution}`) != 1 || strings.Count(table, `\caption{`) != 1 {
		t.Errorf("label or caption count wrong:\n%s", table)
	}
	if strings.Count(table, `\begin{table*}`) != 1 || strings.Count(table, `\end{table*}`) != 1 || strings.Count(table, `\begin{tabular}`) != strings.Count(table, `\end{tabular}`) {
		t.Error("unbalanced environments")
	}
	caption := table[strings.Index(table, `\caption{`):strings.Index(table, `\label{`)]
	// The names Tier 3, EXEC-01 and EXEC-02 are not results.
	caption = strings.NewReplacer("Tier 3", "", "EXEC-01", "", "EXEC-02", "").Replace(caption)
	if regexp.MustCompile(`[0-9]`).MatchString(caption) {
		t.Errorf("the caption must not contain a number, the text takes numbers from the macros: %s", caption)
	}
	// Special characters of the data are escaped.
	if strings.Contains(table, "CAP_SETGID") || !strings.Contains(table, `CAP\_SETGID`) {
		t.Error("underscores of capability names must be escaped")
	}
	if strings.Contains(RenderTable(nil, nil), "0 \\\\") {
		t.Error("a table without data must not print zeros")
	}
}

func TestTableListsMinimalSetsMostFrequentFirst(t *testing.T) {
	att, abl := fullFixture()
	table := RenderTable(att, abl)
	first := strings.Index(table, `CAP\_SETGID + CAP\_SETUID}} & 2`)
	other := strings.Index(table, `\texttt{/var/cache}} & 1`)
	if first < 0 || other < 0 || first > other {
		t.Errorf("sets must be listed by count, most frequent first (%d, %d):\n%s", first, other, table)
	}
}

// ---------------------------------------------------------------------------
// The files of one directory

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEveryRunRendersTheMacrosFromAllBlocksInTheDirectory(t *testing.T) {
	dir := t.TempDir()
	study := writeStudyFile(t, dir,
		suite("web", spec.StatusCompleted, res("EXEC-02", spec.OutcomeFail)),
		tier3Image("crashes", spec.ReasonBaselineFailed),
	)
	truthPath := writeTruthFile(t, dir)
	r := seededRunner()
	r.behave["web"] = needsCaps("CAP_CHOWN", "CAP_FOWNER")
	r.behave["crashes"] = func(RunSpec) Observation { return exited(1) }
	ctx := context.Background()

	// 1. The attribution of the study.
	if code := execute(ctx, options{studyPath: study, outDir: dir, minimize: true, rules: []string{RuleDropCaps}}, r, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("attribute exit %d", code)
	}
	m1 := macroValues(t, readFile(t, dir, macrosFile))
	if m1["ConUnitAttrRealNamedMinimal"] != "1" || m1["ConUnitAttrSeededN"] != "n/a" || m1["ConUnitAblExamined"] != "n/a" {
		t.Errorf("after the study run: %v", m1)
	}

	// 2. The seeded cases. The study numbers stay.
	if code := execute(ctx, options{truthPath: truthPath, outDir: dir, minimize: true}, r, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("truth exit %d", code)
	}
	m2 := macroValues(t, readFile(t, dir, macrosFile))
	if m2["ConUnitAttrRealNamedMinimal"] != "1" || m2["ConUnitAttrSeededExact"] != "2" || m2["ConUnitAblExamined"] != "n/a" {
		t.Errorf("after the truth run: %v", m2)
	}

	// 3. The ablation. Both attribution blocks stay.
	if code := execute(ctx, options{studyPath: study, outDir: dir, ablation: true}, r, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("ablation exit %d", code)
	}
	m3 := macroValues(t, readFile(t, dir, macrosFile))
	if m3["ConUnitAblExamined"] != "1" || m3["ConUnitAblMisblamed"] != "1" || m3["ConUnitAttrSeededExact"] != "2" || m3["ConUnitAttrRealNamedMinimal"] != "1" {
		t.Errorf("after the ablation run: %v", m3)
	}
	if !strings.Contains(readFile(t, dir, tableFile), `\label{tab:attribution}`) {
		t.Error("table lacks its label")
	}
	for _, name := range []string{attributionJSON, attributionCSV, ablationJSON, macrosFile, tableFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}

	// 4. A new attribution of the study keeps the ablation numbers.
	if code := execute(ctx, options{studyPath: study, outDir: dir, minimize: true, rules: []string{RuleDropCaps}}, r, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("second attribute exit %d", code)
	}
	if m4 := macroValues(t, readFile(t, dir, macrosFile)); m4["ConUnitAblExamined"] != "1" || m4["ConUnitAttrSeededN"] != "2" {
		t.Errorf("after the second study run: %v", m4)
	}
}

func TestExplicitPathsFeedTheLatexOutputsOfAnOtherDirectory(t *testing.T) {
	src := t.TempDir()
	study := writeStudyFile(t, src, tier3Image("crashes", spec.ReasonBaselineFailed))
	r := &scriptRunner{behave: map[string]func(RunSpec) Observation{"crashes": func(RunSpec) Observation { return exited(1) }}}
	if code := execute(context.Background(), options{studyPath: study, outDir: src, ablation: true}, r, testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("ablation exit %d", code)
	}
	dir := t.TempDir()
	opts := options{truthPath: writeTruthFile(t, dir), outDir: dir, minimize: true, ablationJSON: filepath.Join(src, ablationJSON)}
	if code := execute(context.Background(), opts, seededRunner(), testMeta, discard()); code != spec.ExitOK {
		t.Fatalf("truth exit %d", code)
	}
	m := macroValues(t, readFile(t, dir, macrosFile))
	if m["ConUnitAblMisblamed"] != "1" || m["ConUnitAttrSeededN"] != "2" {
		t.Errorf("macros = %v", m)
	}
	// Without the flag the other directory is not looked at.
	dir2 := t.TempDir()
	opts.outDir, opts.truthPath, opts.ablationJSON = dir2, writeTruthFile(t, dir2), ""
	execute(context.Background(), opts, seededRunner(), testMeta, discard())
	if m2 := macroValues(t, readFile(t, dir2, macrosFile)); m2["ConUnitAblMisblamed"] != "n/a" {
		t.Errorf("ablation numbers appeared without a source: %v", m2)
	}
}

func TestUnreadableOrMixedSourcesAreReportedOnce(t *testing.T) {
	dir := t.TempDir()
	var logged strings.Builder
	o := &Outputs{Dir: dir, Log: NewLogger(&logged)}
	if err := os.WriteFile(filepath.Join(dir, ablationJSON), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		o.ablationForReport()
	}
	if got := strings.Count(logged.String(), "ignoring the unreadable"); got != 1 {
		t.Errorf("unreadable file reported %d times:\n%s", got, logged.String())
	}

	att, abl := fullFixture()
	abl.Source.StudySHA256 = strings.Repeat("cd", 32)
	for i := 0; i < 2; i++ {
		o.warnOnMixedStudies(att, abl)
	}
	if got := strings.Count(logged.String(), "come from different studies"); got != 1 {
		t.Errorf("mixed studies reported %d times:\n%s", got, logged.String())
	}
	logged.Reset()
	abl.Source.StudySHA256 = att.Source.StudySHA256
	o.warnOnMixedStudies(att, abl)
	o.warnOnMixedStudies(nil, abl)
	o.warnOnMixedStudies(att, nil)
	if logged.Len() != 0 {
		t.Errorf("no warning expected: %s", logged.String())
	}
}
