package conunit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// packFixture is an image that lets every Tier 1, 2 and 4 check reach a
// verdict without an engine. Tier 3 checks are UNVERIFIED because no engine is
// configured, which is still exactly one result each.
func packFixture() *conunit.Container {
	return &conunit.Container{
		ImageDigest:  "sha256:" + strings.Repeat("a", 64),
		ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		Platform:     "linux/amd64",
		Inspect: &engine.ImageInspect{
			Size: 10 << 20,
			Config: engine.ImageConfig{
				User:         "10001",
				Entrypoint:   []string{"/app"},
				Env:          []string{"PATH=/usr/bin"},
				ExposedPorts: map[string]struct{}{"8080/tcp": {}},
				Labels:       map[string]string{},
			},
		},
		OCIIndex: &oci.FilesystemIndex{
			Paths:              map[string]bool{"/app": true},
			SuidMap:            map[string]int64{},
			WorldWritableFiles: map[string]int64{},
			PrivateKeyFiles:    map[string]string{},
			PasswdUIDs:         map[string][]uint32{},
		},
	}
}

func resultIDs(c *conunit.Container) []string {
	ids := make([]string, 0, len(c.Results))
	for _, result := range c.Results {
		ids = append(ids, result.TestID)
	}
	return ids
}

func checkIDs(pack conunit.RulePack) []string {
	var ids []string
	for _, check := range pack.Checks() {
		ids = append(ids, check.ID)
	}
	return ids
}

func TestEveryPackEmitsExactlyOneResultPerCheckAndNeverTwoForOneRule(t *testing.T) {
	for _, pack := range conunit.AllPacks() {
		t.Run(pack.ID(), func(t *testing.T) {
			c := packFixture()
			pack.Apply(c)

			seen := map[string]int{}
			for _, result := range c.Results {
				seen[result.TestID]++
			}
			for id, count := range seen {
				if count != 1 {
					t.Errorf("rule %s produced %d results for one image, want 1", id, count)
				}
			}
			got, want := resultIDs(c), checkIDs(pack)
			sort.Strings(got)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("results %v differ from the checks of the pack %v", got, want)
			}
			for _, result := range c.Results {
				rule, ok := conunit.RuleByID(result.TestID)
				if !ok {
					t.Errorf("result %s has no catalog entry", result.TestID)
					continue
				}
				if result.TestName != rule.Name {
					t.Errorf("%s is named %q in the result and %q in the catalog", result.TestID, result.TestName, rule.Name)
				}
				if result.Rule == nil || result.Rule.Standard == "" || result.Rule.Mapping == "" || result.Rule.Scope == "" {
					t.Errorf("%s carries no standard mapping: %+v", result.TestID, result.Rule)
				}
			}
		})
	}
}

func TestResultsCarryTheirOwnCopyOfTheRuleMapping(t *testing.T) {
	c := packFixture()
	conunit.CISBenchmark().Apply(c)
	var first *spec.TestResult
	for i := range c.Results {
		if c.Results[i].TestID == "FS-04" {
			first = &c.Results[i]
		}
	}
	if first == nil || first.Rule == nil {
		t.Fatal("FS-04 result or its mapping is missing")
	}
	first.Rule.Scope = "tampered"
	rule, _ := conunit.RuleByID("FS-04")
	if rule.Meta.Scope != spec.ScopeImageContent {
		t.Fatalf("editing a result changed the catalog: scope %q", rule.Meta.Scope)
	}
}

func TestExcludingAnEmittedIDWorksInEveryPack(t *testing.T) {
	for _, reference := range conunit.AllPacks() {
		for _, check := range reference.Checks() {
			t.Run(reference.ID()+"/"+check.ID, func(t *testing.T) {
				var pack conunit.RulePack
				for _, candidate := range conunit.AllPacks() {
					if candidate.ID() == reference.ID() {
						pack = candidate
					}
				}
				c := packFixture()
				pack.Except(check.ID).Apply(c)
				if slices.Contains(resultIDs(c), check.ID) {
					t.Errorf("%s still ran after Except(%q)", check.ID, check.ID)
				}
				if got, want := len(c.Results), len(reference.Checks())-1; got != want {
					t.Errorf("%d results after one exclusion, want %d", got, want)
				}
			})
		}
	}
}

func TestLegacyPackLevelHandlesStillDisableTheChecksTheyCovered(t *testing.T) {
	covered := map[string]map[string][]string{} // pack ID -> legacy handle -> check IDs
	for _, pack := range conunit.AllPacks() {
		covered[pack.ID()] = map[string][]string{}
		for _, check := range pack.Checks() {
			for _, legacy := range check.LegacyIDs {
				covered[pack.ID()][legacy] = append(covered[pack.ID()][legacy], check.ID)
			}
		}
	}
	// The group handles of the hardening profile before the rule IDs were unified.
	for handle, want := range map[string][]string{
		"CIS-4.10": {"SPEC-03", "FS-06", "FS-08"},
		"CIS-4.11": {"FS-05", "FS-09"},
		"CIS-5.7":  {"SPEC-05", "SPEC-06"},
		"CIS-4.3":  {"FS-07"},
		"CIS-4.5":  {"SUP-02"},
	} {
		got := covered["PACK-CONUNIT-HARDENING"][handle]
		if !slices.Equal(got, want) {
			t.Errorf("legacy handle %s covers %v, want %v", handle, got, want)
		}
	}
	for packID, handles := range covered {
		for handle, ids := range handles {
			for _, pack := range conunit.AllPacks() {
				if pack.ID() != packID {
					continue
				}
				c := packFixture()
				pack.Except(handle).Apply(c)
				for _, id := range ids {
					if slices.Contains(resultIDs(c), id) {
						t.Errorf("%s: %s still ran after Except(%q)", packID, id, handle)
					}
				}
			}
		}
	}
}

func TestHardeningProfileHasTheChecksOfTheAnalysisPlan(t *testing.T) {
	// docs/ANALYSIS_PLAN.md lists the candidate headline, conditional and Tier 3
	// checks, plus SUP-02, which is UNVERIFIED by design without a trust
	// policy. EXEC-03 and FS-01 are deliberately not part of the profile; the
	// hygiene pack carries them.
	want := []string{
		"SPEC-01", "CIS-4.6", "FS-04", "FS-05", "FS-08", "SPEC-05", "SPEC-06",
		"FS-06", "FS-07", "SPEC-07", "FS-09", "SPEC-03",
		"EXEC-01", "EXEC-02", "EXEC-04", "EXEC-07",
		"SUP-02",
	}
	got := checkIDs(conunit.CISBenchmark())
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("the hardening profile has %v, want exactly %v", got, want)
	}
	for _, id := range []string{"EXEC-03", "FS-01"} {
		if slices.Contains(got, id) {
			t.Errorf("%s must not be part of the hardening profile", id)
		}
		if !slices.Contains(checkIDs(conunit.ProductionHygiene()), id) {
			t.Errorf("%s must be part of the hygiene pack", id)
		}
	}
}

func TestPackNamesDoNotClaimComplianceAndAliasStillResolves(t *testing.T) {
	cis := conunit.CISBenchmark()
	if strings.Contains(strings.ToLower(cis.Name()), "benchmark") || !strings.Contains(strings.ToLower(cis.Name()), "informed") {
		t.Errorf("pack name %q must say that the profile is CIS-informed, not the benchmark", cis.Name())
	}
	if !strings.Contains(cis.Description(), "not a CIS compliance assessment") {
		t.Errorf("description lacks the compliance disclaimer: %s", cis.Description())
	}
	if cis.ID() != "PACK-CONUNIT-HARDENING" {
		t.Errorf("the hardening profile must keep its pack ID PACK-CONUNIT-HARDENING, got %q", cis.ID())
	}
}

func TestCatalogIsConsistent(t *testing.T) {
	names := map[string]string{}
	for _, rule := range conunit.Rules() {
		if rule.Name == "" || rule.Oracle == "" || rule.Evidence == "" || rule.Limits == "" {
			t.Errorf("%s has an empty name, oracle, evidence or limits", rule.ID)
		}
		if other, dup := names[rule.Name]; dup {
			t.Errorf("%s and %s share the name %q", rule.ID, other, rule.Name)
		}
		names[rule.Name] = rule.ID

		meta := rule.Meta
		switch meta.Scope {
		case spec.ScopeImageContent, spec.ScopeMetadataDeclaration, spec.ScopeRuntimeCompat:
		default:
			t.Errorf("%s has scope %q", rule.ID, meta.Scope)
		}
		switch meta.Mapping {
		case spec.MappingCustom:
			if meta.Standard != "ConUnit" || meta.ControlID != "" {
				t.Errorf("custom rule %s must name ConUnit and no control: %+v", rule.ID, meta)
			}
		case spec.MappingExact, spec.MappingApproximate:
			if meta.Standard == "" || meta.ControlTitle == "" {
				t.Errorf("mapped rule %s needs a standard and a control title: %+v", rule.ID, meta)
			}
			if meta.Standard == "CIS Docker Benchmark" && (meta.StandardVersion != "1.8.0" || meta.ControlID == "") {
				t.Errorf("CIS rule %s must name version 1.8.0 and a control: %+v", rule.ID, meta)
			}
			if meta.Standard == "CIS Docker Benchmark" && strings.HasPrefix(meta.ControlTitle, "Ensure ") {
				t.Errorf("CIS rule %s carries a verbatim benchmark title %q, use a short ConUnit descriptor", rule.ID, meta.ControlTitle)
			}
		default:
			t.Errorf("%s has mapping %q", rule.ID, meta.Mapping)
		}
		if rule.Tier == spec.TierContract && rule.ID != "EXEC-06" && meta.Scope != spec.ScopeRuntimeCompat {
			t.Errorf("Tier 3 rule %s must have the runtime_compatibility scope", rule.ID)
		}
	}
}

func TestNoRuleClaimsACISControlUntilItIsConfirmed(t *testing.T) {
	// docs/DEVIATIONS.md (DEV-15): the CIS control numbers were checked
	// against third party audit lists only, never against the official document. Until
	// they are confirmed no rule may state one.
	for _, rule := range conunit.Rules() {
		meta := rule.Meta
		if strings.Contains(meta.Standard, "CIS") || meta.ControlID != "" || meta.StandardVersion != "" && meta.Standard == "ConUnit" {
			t.Errorf("%s states the standard %q, version %q and control %q, which are not confirmed", rule.ID, meta.Standard, meta.StandardVersion, meta.ControlID)
		}
	}
	for _, id := range []string{"SPEC-01", "CIS-4.6", "FS-04", "EXEC-01", "EXEC-02", "EXEC-04", "EXEC-07", "SPEC-09", "FS-12"} {
		rule, ok := conunit.RuleByID(id)
		if !ok {
			t.Fatalf("%s is missing from the catalog", id)
		}
		if rule.Meta.Mapping != spec.MappingCustom || rule.Meta.Standard != "ConUnit" {
			t.Errorf("%s = %+v, want a custom ConUnit check", id, rule.Meta)
		}
	}
}

var callSitePair = regexp.MustCompile(`"((?:SPEC|FS|EXEC|SUP|DISTRO)-\d+|CIS-4\.6)",\s*(?:name:\s*)?"([^"]+)"`)
var anyRuleID = regexp.MustCompile(`"((?:SPEC|FS|EXEC|SUP|DISTRO)-\d+|CIS-4\.6)"`)

func TestCatalogMatchesTheAssertionsInTheSource(t *testing.T) {
	emitted := map[string]bool{}
	sources := []string{"container.go", "contract.go"}
	lintSources, err := filepath.Glob("lint_*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range lintSources {
		if !strings.HasSuffix(file, "_test.go") {
			sources = append(sources, file)
		}
	}
	for _, file := range sources {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		for _, match := range anyRuleID.FindAllStringSubmatch(source, -1) {
			emitted[match[1]] = true
		}
		for _, match := range callSitePair.FindAllStringSubmatch(source, -1) {
			rule, ok := conunit.RuleByID(match[1])
			if ok && rule.Name != match[2] {
				t.Errorf("%s: the source names %s %q and the catalog %q", file, match[1], match[2], rule.Name)
			}
		}
	}
	for id := range emitted {
		if _, ok := conunit.RuleByID(id); !ok {
			t.Errorf("rule %s is emitted by the source but missing from the catalog", id)
		}
	}
	for _, rule := range conunit.Rules() {
		if !emitted[rule.ID] {
			t.Errorf("catalog rule %s is never emitted by the source", rule.ID)
		}
	}
}

func TestRulesDocumentIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "RULES.md")
	want := conunit.RulesMarkdown()
	if os.Getenv("CONUNIT_UPDATE_RULES") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s", path)
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("docs/RULES.md is missing: %v. Generate it with: go run ./cmd/con-unit rules > docs/RULES.md", err)
	}
	if string(got) != want {
		t.Fatal("docs/RULES.md is out of date. Regenerate it with: CONUNIT_UPDATE_RULES=1 go test ./pkg/conunit -run TestRulesDocumentIsCurrent")
	}
}

func TestRulesDocumentIsDeterministicAndStatesEachRuleWithItsLimits(t *testing.T) {
	first := conunit.RulesMarkdown()
	for i := 0; i < 10; i++ {
		if conunit.RulesMarkdown() != first {
			t.Fatal("the rule reference changed between renders")
		}
	}
	for _, rule := range conunit.Rules() {
		heading := "#### " + rule.ID + ": " + rule.Name
		if !strings.Contains(first, heading) {
			t.Errorf("reference lacks %q", heading)
		}
	}
	for _, want := range []string{"mapping approximate", "no standard control (custom ConUnit check)", "- Limits:", "- Oracle:", "`--pack hardening` (alias `cis`)"} {
		if !strings.Contains(first, want) {
			t.Errorf("reference lacks %q", want)
		}
	}
	if strings.Contains(first, "\u2014") || strings.Contains(first, "--  ") {
		t.Error("the reference must not use dashes as punctuation")
	}
}
