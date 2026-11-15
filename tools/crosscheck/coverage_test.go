package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/runner"
)

var coverageDocPath = filepath.Join("..", "..", "docs", "COVERAGE_MATRIX.md")

func TestCoverageMarkdownIsCurrent(t *testing.T) {
	want := RenderCoverageMarkdown()
	if *update {
		if err := os.WriteFile(coverageDocPath, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(coverageDocPath)
	if err != nil {
		t.Fatalf("docs/COVERAGE_MATRIX.md is missing: %v\nrun: go test ./tools/crosscheck -run TestCoverageMarkdownIsCurrent -update", err)
	}
	if string(got) != want {
		t.Error("docs/COVERAGE_MATRIX.md differs from the generator output.\nrun: go test ./tools/crosscheck -run TestCoverageMarkdownIsCurrent -update")
	}
}

func packIDs(p conunit.RulePack) []string {
	var ids []string
	for _, c := range p.Checks() {
		ids = append(ids, c.ID)
	}
	return ids
}

func TestHardeningMembersMatchThePack(t *testing.T) {
	if got := packIDs(conunit.CISBenchmark()); !reflect.DeepEqual(got, hardeningMembers) {
		t.Errorf("the hardening pack has %v\nthe matrix lists %v", got, hardeningMembers)
	}
}

// The member list of the matrix must be exactly the list of the lint pack, in order.
func TestLintMembersMatchThePackWhenItExists(t *testing.T) {
	pack, err := runner.ResolvePack("lint")
	if err != nil {
		t.Skipf("the lint pack is not part of this branch yet: %v", err)
	}
	if got := packIDs(pack); !reflect.DeepEqual(got, lintMembers) {
		t.Errorf("the lint pack has %v\nthe matrix lists %v", got, lintMembers)
	}
}

func TestEveryPackMemberHasExactlyOneRow(t *testing.T) {
	rows := CoverageRows()
	count := map[string]int{}
	for _, r := range rows {
		if r.Check != "" {
			count[r.Check]++
		}
	}
	for _, id := range append(append([]string{}, hardeningMembers...), lintMembers...) {
		if count[id] != 1 {
			t.Errorf("check %s has %d rows, want exactly one", id, count[id])
		}
	}
	for id := range count {
		if !contains(hardeningMembers, id) && !contains(lintMembers, id) {
			t.Errorf("row for %s, which is in neither pack", id)
		}
	}
	// Every member of either pack has a row and every row is a member.
	union := map[string]bool{}
	for _, id := range hardeningMembers {
		union[id] = true
	}
	for _, id := range lintMembers {
		union[id] = true
	}
	if len(union) != len(count) {
		t.Errorf("%d distinct pack members, %d rows with a check", len(union), len(count))
	}
}

func TestRowsAgreeWithTheRuleCatalog(t *testing.T) {
	for _, r := range CoverageRows() {
		if r.Check == "" {
			continue
		}
		rule, ok := conunit.RuleByID(r.Check)
		if !ok {
			// A check of the lint pack that this branch does not have yet.
			if !contains(lintMembers, r.Check) || contains(hardeningMembers, r.Check) {
				t.Errorf("%s is not in the rule catalog", r.Check)
			}
			continue
		}
		if int(rule.Tier) != r.Tier {
			t.Errorf("%s: tier %d in the matrix, %d in the catalog", r.Check, r.Tier, rule.Tier)
		}
		if rule.Name != r.Name {
			t.Errorf("%s: name %q in the matrix, %q in the catalog", r.Check, r.Name, rule.Name)
		}
	}
}

func TestEveryImageLevelDockleCheckpointHasALintPackCheck(t *testing.T) {
	sum := Summarize(CoverageRows())
	if len(sum.DockleImageUncovered) != 0 {
		t.Errorf("image-level Dockle checkpoints without a check in the lint pack: %v", sum.DockleImageUncovered)
	}
	if len(sum.DockleImageLevel) != 15 || len(sum.DockleImageCovered) != 15 {
		t.Errorf("image-level checkpoints = %d, covered = %d; Dockle %s evaluates 15 from the image", len(sum.DockleImageLevel), len(sum.DockleImageCovered), VerifiedDockleVersion)
	}
}

// TestSevenOfTheCISDICheckpointsAreImplemented and the next test check the
// statements of an external review against the catalogs: Dockle covers roughly 7 of
// the static checks, and 7 of its 11 CIS-DI checkpoints have a code path.
func TestSevenOfElevenCISDICheckpointsHaveACodePath(t *testing.T) {
	sum := Summarize(CoverageRows())
	if sum.DockleCISDI != 11 || sum.DockleCISDIEvaluated != 7 {
		t.Errorf("CIS-DI checkpoints = %d, with a code path = %d; want 11 and 7", sum.DockleCISDI, sum.DockleCISDIEvaluated)
	}
}

func TestDockleOverlapWithTheStaticChecksOfTheHardeningProfile(t *testing.T) {
	sum := Summarize(CoverageRows())
	if sum.HardeningChecks != 17 || sum.HardeningStatic != 12 || sum.HardeningStaticDockle != 7 {
		t.Errorf("hardening checks = %d, static = %d, with a Dockle counterpart = %d; want 17, 12 and 7",
			sum.HardeningChecks, sum.HardeningStatic, sum.HardeningStaticDockle)
	}
	if got := strings.Split(listOverlap(CoverageRows()), ", "); !reflect.DeepEqual(got, []string{"SPEC-01", "CIS-4.6", "FS-04", "SPEC-07", "SPEC-03", "FS-06", "FS-08"}) {
		t.Errorf("overlapping static checks = %v", got)
	}
	if !reflect.DeepEqual(sum.HardeningStaticOnly, []string{"SPEC-05", "SPEC-06", "FS-05", "FS-09", "FS-07"}) {
		t.Errorf("static checks without a Dockle counterpart = %v", sum.HardeningStaticOnly)
	}
	if !reflect.DeepEqual(sum.HardeningOther, []string{"SUP-02", "EXEC-01", "EXEC-02", "EXEC-04", "EXEC-07"}) {
		t.Errorf("tier 3 and 4 checks = %v", sum.HardeningOther)
	}
}

func TestAnchoreControlsOfThePack(t *testing.T) {
	sum := Summarize(CoverageRows())
	if sum.AnchoreControls != 10 {
		t.Errorf("controls = %d, the pack page lists 10", sum.AnchoreControls)
	}
	if !reflect.DeepEqual(sum.AnchoreCovered, []string{"4.1", "4.6", "4.7", "4.8", "4.9", "4.10", "5.8"}) {
		t.Errorf("covered = %v", sum.AnchoreCovered)
	}
	if !reflect.DeepEqual(sum.AnchoreUncovered, []string{"4.2", "4.3", "4.4"}) {
		t.Errorf("uncovered = %v", sum.AnchoreUncovered)
	}
	// The controls that need a site configuration, as the page marks them.
	var needs []string
	for _, c := range AnchoreControls() {
		if c.NeedsConfiguration {
			needs = append(needs, c.Control)
		}
	}
	if !reflect.DeepEqual(needs, []string{"4.2", "4.3", "5.8"}) {
		t.Errorf("controls that need configuration = %v", needs)
	}
}

func TestCoverageRowsAreConsistent(t *testing.T) {
	valid := map[Relation]bool{RelOverlap: true, RelConUnitOnly: true, RelDockleOnly: true, RelAnchoreOnly: true, RelNeither: true, RelOverlapNotComparable: true}
	rows := CoverageRows()
	properties := map[string]bool{}
	seenDockle := map[string]int{}
	controls := map[string]bool{}
	for _, r := range rows {
		if r.Property == "" || properties[r.Property] {
			t.Errorf("property %q is empty or repeated", r.Property)
		}
		properties[r.Property] = true
		if !valid[r.VsDockle] || !valid[r.VsAnchore] {
			t.Errorf("%s: relations %q and %q", r.Property, r.VsDockle, r.VsAnchore)
		}
		for _, c := range r.Dockle {
			seenDockle[c]++
		}
		if r.Anchore != "" {
			controls[r.Anchore] = true
		}
		// ConUnit rows: the Dockle side is the mapping and nothing else.
		if r.Check != "" {
			m, mapped := MappingFor(r.Check)
			switch {
			case mapped && !reflect.DeepEqual(r.Dockle, m.Codes):
				t.Errorf("%s: Dockle side %v differs from the mapping %v", r.Check, r.Dockle, m.Codes)
			case mapped && m.Comparable() && r.VsDockle != RelOverlap:
				t.Errorf("%s is mapped and comparable, so it overlaps with Dockle, not %s", r.Check, r.VsDockle)
			case mapped && !m.Comparable() && r.VsDockle != RelOverlapNotComparable:
				t.Errorf("%s is mapped but not comparable, so the matrix must say %s, not %s", r.Check, RelOverlapNotComparable, r.VsDockle)
			case !mapped && (r.VsDockle != RelConUnitOnly || len(r.Dockle) != 0):
				t.Errorf("%s has no mapping, so it must be ConUnit-only against Dockle: %+v", r.Check, r)
			}
			if (r.Anchore != "") != (r.VsAnchore == RelOverlap) {
				t.Errorf("%s: Anchore control %q with relation %s", r.Check, r.Anchore, r.VsAnchore)
			}
		} else {
			// No ConUnit check: ConUnit is not the one that has it alone.
			if r.VsDockle == RelConUnitOnly || r.VsAnchore == RelConUnitOnly || r.VsAnchore == RelOverlap || r.VsDockle == RelOverlap || r.VsDockle == RelOverlapNotComparable {
				t.Errorf("%s has no ConUnit check but claims a ConUnit relation: %+v", r.Property, r)
			}
			if r.Note == "" {
				t.Errorf("%s: a property without a ConUnit check needs a note that says why", r.Property)
			}
		}
	}
	// Every checkpoint of the catalog is in exactly one row, except CIS-DI-0010,
	// which three checks of ConUnit share. Every control of the Anchore pack is
	// in at least one row.
	for _, c := range DockleCatalog() {
		want := 1
		if c.Code == "CIS-DI-0010" {
			want = 3
		}
		if seenDockle[c.Code] != want {
			t.Errorf("checkpoint %s is in %d rows, want %d", c.Code, seenDockle[c.Code], want)
		}
	}
	for _, c := range AnchoreControls() {
		if !controls[c.Control] {
			t.Errorf("control %s of the Anchore pack is in no row", c.Control)
		}
	}
}

func TestTheLatestTagPairIsMarkedNotComparableInTheMatrix(t *testing.T) {
	sum := Summarize(CoverageRows())
	if !reflect.DeepEqual(sum.NotComparable, []string{"SPEC-13"}) {
		t.Errorf("not comparable checks = %v, want SPEC-13 only", sum.NotComparable)
	}
	// The pair still counts as covered: ConUnit has the check, Dockle has the
	// checkpoint, and only the comparison on an archive is impossible.
	if len(sum.DockleImageUncovered) != 0 {
		t.Errorf("uncovered image-level checkpoints: %v", sum.DockleImageUncovered)
	}
	tx := RenderCoverageTable()
	if !strings.Contains(tx, `overlap, not comparable`) || !strings.Contains(RenderCoverageMarkdown(), "| overlap, not comparable |") {
		t.Error("both outputs must show the relation for SPEC-13")
	}
}

func TestExcludedCheckpointsAreInTheMatrixAsNotComparable(t *testing.T) {
	byCode := map[string]CoverageRow{}
	for _, r := range CoverageRows() {
		if r.Check == "" {
			for _, c := range r.Dockle {
				byCode[c] = r
			}
		}
	}
	for _, e := range ExcludedCodes() {
		r, ok := byCode[e.Code]
		if !ok {
			t.Errorf("excluded checkpoint %s has no row", e.Code)
			continue
		}
		if r.VsDockle == RelOverlap {
			t.Errorf("%s is excluded and cannot overlap", e.Code)
		}
	}
	if byCode["CIS-DI-0005"].VsDockle != RelDockleOnly {
		t.Error("CIS-DI-0005 is the one checkpoint that only Dockle evaluates")
	}
}

func TestCoverageOutputsAreAsciiAndWellFormed(t *testing.T) {
	md, tx := RenderCoverageMarkdown(), RenderCoverageTable()
	for name, s := range map[string]string{"markdown": md, "tex": tx} {
		for _, r := range s {
			if r > 126 {
				t.Errorf("%s holds the non-ASCII character %q", name, r)
				break
			}
		}
		if strings.Contains(s, " -- ") {
			t.Errorf("%s holds a sentence built around double dashes", name)
		}
	}
	if !strings.Contains(tx, `\label{tab:coverage}`) || strings.Count(tx, `\begin{table*}`) != 1 || strings.Count(tx, `\end{table*}`) != 1 {
		t.Error("the table needs one table* environment with the label tab:coverage")
	}
	rows := CoverageRows()
	// One line per row between \midrule and \bottomrule.
	body := tx[strings.Index(tx, `\midrule`)+len(`\midrule`) : strings.Index(tx, `\bottomrule`)]
	if got := strings.Count(strings.TrimSpace(body), "\n") + 1; got != len(rows) {
		t.Errorf("%d table lines, %d rows", got, len(rows))
	}
	for _, want := range []string{"CIS-DI-0005", "excluded", DockleSourceCommit[:8], AnchorePackVersion, "not public"} {
		if !strings.Contains(tx, want) {
			t.Errorf("the table must state %q", want)
		}
	}
	for _, want := range []string{DockleSourceCommit, AnchorePackURL, AnchorePackVersion, AnchorePackRead, "CIS-DI-0002", "CIS-DI-0005", "never emitted", "not public"} {
		if !strings.Contains(md, want) {
			t.Errorf("the markdown must state %q", want)
		}
	}
}

func TestCoverageMarkdownStatesTheComputedFacts(t *testing.T) {
	md := RenderCoverageMarkdown()
	for _, want := range []string{
		"7 of the 12 static checks (tier 1 and 2)",
		"20 checkpoints: 11 CIS-DI, 6 DKL-DI and 3 DKL-LI",
		"7 have a code path in Dockle 0.4.15",
		"answers the statement of an external review that Dockle covers roughly 7 of ConUnit's 11 static checks",
		"counts 12 static checks in the profile where that review counts 11, and 7 of them overlap",
		"This second \"7 of 11\" is a fact about Dockle, not about ConUnit",
		"15 of 15 are covered (uncovered: none)",
		"Not comparable from an archive: SPEC-13.",
		"Anchore pack: 10 controls. ConUnit has a check for 7 of them",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the markdown lacks %q", want)
		}
	}
}
