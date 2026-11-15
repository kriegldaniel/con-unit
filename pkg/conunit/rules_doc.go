package conunit

import (
	"fmt"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
)

// PackFlagNames are the names `--pack` accepts for each shipped pack, by pack
// ID. The first name is the primary one.
var PackFlagNames = map[string][]string{
	"PACK-CONUNIT-HARDENING": {"hardening", "cis"},
	"PACK-PROD-HYGIENE":      {"hygiene"},
	"PACK-KUBE-HARDENED":     {"kube"},
	"PACK-NIST-800-190":      {"nist"},
	"PACK-DISTROLESS":        {"distroless"},
}

func mappingText(meta spec.RuleMeta) string {
	switch meta.Mapping {
	case spec.MappingCustom:
		return "no standard control (custom ConUnit check)"
	default:
		text := meta.Standard
		if meta.StandardVersion != "" {
			text += " " + meta.StandardVersion
		}
		if meta.ControlID != "" {
			text += ", control " + meta.ControlID
		}
		if meta.ControlTitle != "" {
			text += fmt.Sprintf(" (%q)", meta.ControlTitle)
		}
		return fmt.Sprintf("%s, mapping %s", text, meta.Mapping)
	}
}

func tierText(tier spec.Tier) string { return tier.String() }

// RulesMarkdown renders the rule reference, docs/RULES.md. It is generated
// from the rule catalog and the pack definitions, so the standard mapping, the
// oracle and the pack membership of a check cannot differ from what runs. A
// test fails when the committed file differs from this output.
func RulesMarkdown() string {
	var sb strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&sb, format, args...) }

	w("# ConUnit rule reference\n\n")
	w("This file is generated from the code by `con-unit rules`. Do not edit it by hand: `go test ./pkg/conunit` fails when it is out of date, and `CONUNIT_UPDATE_RULES=1 go test ./pkg/conunit -run TestRulesDocumentIsCurrent` rewrites it.\n\n")

	w("## How to read a rule\n\n")
	w("Every check has a stable ID and a stable name. One image gets at most one result per rule ID in a pack run.\n\n")
	w("Outcomes:\n\n")
	w("- PASS: the oracle observed the property the check looks for.\n")
	w("- FAIL: the oracle observed the opposite. A FAIL states an observation, not a defect claim.\n")
	w("- UNVERIFIED: the evidence needed for a verdict is missing, incomplete or ambiguous. The reason says which: EVIDENCE_INCOMPLETE, FILE_MISSING, NO_TRUST_POLICY, TOOL_UNAVAILABLE, BASELINE_FAILED, NOT_OBSERVABLE, PROBE_TIMEOUT or PROBE_ERROR.\n\n")
	w("Mapping types state how closely a check corresponds to a control of a standard:\n\n")
	w("- exact: the check observes the property that the control names.\n")
	w("- approximate: the check observes a related property, or a stricter or narrower one. The limits of the check say how.\n")
	w("- custom: no control of a standard covers the check. It is a ConUnit check.\n\n")
	w("Scopes state what kind of property a check observes:\n\n")
	w("- image_content: files and packages in the image layers.\n")
	w("- metadata_declaration: what the image configuration, history or labels declare.\n")
	w("- runtime_compatibility: whether the image still starts under a restriction. It says nothing about how it is run in production.\n\n")
	w("No pack is a compliance assessment. No check states a control number of the CIS Docker Benchmark. The numbers could not be confirmed against the official document, so every check of the hardening profile is a custom ConUnit check that is informed by topics of that benchmark. docs/DEVIATIONS.md (DEV-15) says why.\n\n")

	packs := AllPacks()

	w("## Packs\n\n")
	for _, pack := range packs {
		w("### %s (`%s`)\n\n", pack.Name(), pack.ID())
		if names := PackFlagNames[pack.ID()]; len(names) > 0 {
			w("Select it with `--pack %s`", names[0])
			if len(names) > 1 {
				w(" (alias `%s`)", strings.Join(names[1:], "`, `"))
			}
			w(".\n\n")
		}
		w("%s\n\n", pack.Description())
		w("| Check | Name | Parameters | Legacy exclusion handles |\n")
		w("|:---|:---|:---|:---|\n")
		for _, check := range pack.Checks() {
			name := check.ID
			if rule, ok := RuleByID(check.ID); ok {
				name = rule.Name
			}
			params, legacy := check.Params, strings.Join(check.LegacyIDs, ", ")
			if params == "" {
				params = "none"
			}
			if legacy == "" {
				legacy = "none"
			}
			w("| %s | %s | %s | %s |\n", check.ID, name, params, legacy)
		}
		w("\nA pack excludes a check with its rule ID. The legacy handles are older pack-level IDs that still disable the checks listed next to them; they are exclusion handles, not mappings to a standard. A handle named after a CIS control keeps the control number it had in an older version of the benchmark, so existing exclusion lists keep working. It is a name and says nothing about the numbering of any version.\n\n")
	}

	inPacks := func(id string) string {
		var names []string
		for _, pack := range packs {
			for _, check := range pack.Checks() {
				if check.ID == id {
					if flags := PackFlagNames[pack.ID()]; len(flags) > 0 {
						names = append(names, flags[0])
					} else {
						names = append(names, pack.ID())
					}
					break
				}
			}
		}
		if len(names) == 0 {
			return "none"
		}
		return strings.Join(names, ", ")
	}

	w("## Rules\n\n")
	currentTier := spec.Tier(0)
	for _, rule := range Rules() {
		if rule.Tier != currentTier {
			currentTier = rule.Tier
			w("### %s\n\n", tierText(rule.Tier))
		}
		w("#### %s: %s\n\n", rule.ID, rule.Name)
		w("- Standard: %s\n", mappingText(rule.Meta))
		w("- Scope: %s\n", rule.Meta.Scope)
		w("- Packs: %s\n", inPacks(rule.ID))
		w("- Oracle: %s\n", rule.Oracle)
		w("- Evidence: %s\n", rule.Evidence)
		w("- Limits: %s\n\n", rule.Limits)
	}
	return strings.TrimRight(sb.String(), "\n") + "\n"
}
