package conunit_test

import (
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/spec"
)

// mapping is what the interface contract fixes for each new rule.
var lintMappings = map[string]struct {
	name    string
	tier    spec.Tier
	mapping spec.MappingType
	scope   spec.RuleScope
	control string // CIS control, empty for a custom rule
	dockle  string // Dockle checkpoint named in the oracle
}{
	"SPEC-09": {"Update Instruction Combined With Install", spec.TierSpec, spec.MappingCustom, spec.ScopeMetadataDeclaration, "", "CIS-DI-0007"},
	"SPEC-10": {"No Sudo in the Build History", spec.TierSpec, spec.MappingCustom, spec.ScopeMetadataDeclaration, "", "DKL-DI-0001"},
	"SPEC-11": {"No Distribution Upgrade in the Build History", spec.TierSpec, spec.MappingCustom, spec.ScopeMetadataDeclaration, "", "DKL-DI-0003"},
	"SPEC-12": {"No Sensitive Host Paths as Volumes", spec.TierSpec, spec.MappingCustom, spec.ScopeMetadataDeclaration, "", "DKL-DI-0002"},
	"SPEC-13": {"Explicit Non-Latest Image Reference", spec.TierSpec, spec.MappingCustom, spec.ScopeMetadataDeclaration, "", "DKL-DI-0006"},
	"FS-10":   {"Unique Account and Group IDs", spec.TierFilesystem, spec.MappingCustom, spec.ScopeImageContent, "", "DKL-LI-0002"},
	"FS-11":   {"No Development, Editor, Cache or Cloud Leftovers", spec.TierFilesystem, spec.MappingCustom, spec.ScopeImageContent, "", "DKL-LI-0003"},
	"FS-12":   {"No Credential-Named Files", spec.TierFilesystem, spec.MappingCustom, spec.ScopeImageContent, "", "CIS-DI-0010"},
}

func TestEveryNewRuleHasACompleteCatalogEntry(t *testing.T) {
	for _, id := range newLintChecks {
		t.Run(id, func(t *testing.T) {
			rule, ok := conunit.RuleByID(id)
			if !ok {
				t.Fatalf("%s is missing from the catalog", id)
			}
			want := lintMappings[id]
			if rule.Name != want.name || rule.Tier != want.tier {
				t.Errorf("name/tier = %q/%v, want %q/%v", rule.Name, rule.Tier, want.name, want.tier)
			}
			for field, text := range map[string]string{"oracle": rule.Oracle, "evidence": rule.Evidence, "limits": rule.Limits} {
				if len(strings.Fields(text)) < 8 {
					t.Errorf("%s is too thin to document the check: %q", field, text)
				}
			}
			meta := rule.Meta
			if meta.Mapping != want.mapping || meta.Scope != want.scope || meta.ControlID != want.control {
				t.Errorf("mapping = %s/%s/control %q, want %s/%s/control %q", meta.Mapping, meta.Scope, meta.ControlID, want.mapping, want.scope, want.control)
			}
			switch meta.Mapping {
			case spec.MappingCustom:
				if meta.Standard != "ConUnit" || meta.ControlTitle != "" {
					t.Errorf("a custom rule names ConUnit and no control: %+v", meta)
				}
			default:
				if meta.Standard != "CIS Docker Benchmark" || meta.StandardVersion == "" || meta.ControlTitle == "" {
					t.Errorf("a mapped rule names the standard, its version and a descriptor: %+v", meta)
				}
				if strings.HasPrefix(meta.ControlTitle, "Ensure ") {
					t.Errorf("the control title %q is a verbatim benchmark title, use our own words", meta.ControlTitle)
				}
			}
			if !strings.Contains(rule.Oracle, want.dockle) {
				t.Errorf("the oracle must name the Dockle checkpoint %s: %q", want.dockle, rule.Oracle)
			}
			if !strings.Contains(rule.Limits, "Dockle") {
				t.Errorf("the limits must state the intended differences from Dockle: %q", rule.Limits)
			}
			if !strings.Contains(rule.Limits, "UNVERIFIED (EVIDENCE_INCOMPLETE)") {
				t.Errorf("the limits must state when the check is unverified: %q", rule.Limits)
			}
			if !strings.Contains(rule.Limits, "xploratory") {
				t.Errorf("the limits must say that the check starts as exploratory: %q", rule.Limits)
			}
		})
	}
}

// A check that cannot be compared with Dockle through an exported archive says
// so in its own limits, because the cross-check would otherwise show it as a
// silent disagreement.
func TestSpec13StatesThatDockleDoesNotEvaluateItForArchives(t *testing.T) {
	rule, _ := conunit.RuleByID("SPEC-13")
	for _, want := range []string{"image name", "--input", "tarball"} {
		if !strings.Contains(rule.Limits, want) {
			t.Errorf("the limits of SPEC-13 must mention %q: %s", want, rule.Limits)
		}
	}
}

func TestNewRuleTextHasNoEmojiAndNoDashPunctuation(t *testing.T) {
	doubleDash := regexp.MustCompile(`\s--\s`)
	for _, id := range newLintChecks {
		rule, _ := conunit.RuleByID(id)
		for _, text := range []string{rule.Name, rule.Oracle, rule.Evidence, rule.Limits, rule.Meta.ControlTitle} {
			if doubleDash.MatchString(text) || strings.ContainsRune(text, '\u2014') || strings.ContainsRune(text, '\u2013') {
				t.Errorf("%s uses dashes as punctuation: %q", id, text)
			}
			for _, r := range text {
				if r > unicode.MaxASCII {
					t.Errorf("%s holds the non-ASCII character %q", id, r)
				}
			}
		}
	}
}

func TestRuleReferenceDocumentsThePackAndTheNewRules(t *testing.T) {
	doc := conunit.RulesMarkdown()
	for _, want := range []string{
		"### Image Static Lint Pack (`PACK-IMAGE-LINT`)",
		"Select it with `--pack lint` (alias `image-lint`).",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the rule reference lacks %q", want)
		}
	}
	for _, id := range newLintChecks {
		rule, _ := conunit.RuleByID(id)
		if !strings.Contains(doc, "#### "+id+": "+rule.Name) {
			t.Errorf("the rule reference lacks the heading of %s", id)
		}
	}
	// The pack table lists the members in execution order.
	start := strings.Index(doc, "### Image Static Lint Pack")
	end := strings.Index(doc[start:], "\n## ")
	table := doc[start : start+end]
	last := -1
	for _, id := range lintMembers {
		at := strings.Index(table, "| "+id+" |")
		if at < 0 {
			t.Errorf("the pack table lacks %s", id)
			continue
		}
		if at < last {
			t.Errorf("%s is listed before an earlier member of the pack", id)
		}
		last = at
	}
	// Every new rule says in which pack it runs.
	for _, id := range newLintChecks {
		rule, _ := conunit.RuleByID(id)
		section := doc[strings.Index(doc, "#### "+id+": "+rule.Name):]
		if next := strings.Index(section[5:], "\n#### "); next >= 0 {
			section = section[:next+5]
		}
		if !strings.Contains(section, "- Packs: lint") {
			t.Errorf("%s must be documented as part of the lint pack only: %s", id, section)
		}
	}
}

func TestEveryNewRuleResultCarriesItsCatalogNameAndMapping(t *testing.T) {
	c := cleanSpec().container(t)
	conunit.ImageLint().Apply(c)
	for _, r := range c.Results {
		if !strings.Contains(strings.Join(newLintChecks, " "), r.TestID) {
			continue
		}
		rule, _ := conunit.RuleByID(r.TestID)
		if r.TestName != rule.Name {
			t.Errorf("%s is named %q in the result and %q in the catalog", r.TestID, r.TestName, rule.Name)
		}
		if r.Rule == nil || *r.Rule != rule.Meta {
			t.Errorf("%s carries the mapping %+v, want %+v", r.TestID, r.Rule, rule.Meta)
		}
	}
}
