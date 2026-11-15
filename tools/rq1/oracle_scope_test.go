package main

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
)

// contractDockle is the Dockle scope of docs/INTERFACE_V2.md section 4:
// property to checkpoint codes. Every other property is out of scope.
var contractDockle = map[string][]string{
	"root-user":        {"CIS-DI-0001"},
	"no-healthcheck":   {"CIS-DI-0006"},
	"setuid-binary":    {"CIS-DI-0008"},
	"add-local-file":   {"CIS-DI-0009"},
	"add-remote-url":   {"CIS-DI-0009"},
	"secret-in-env":    {"CIS-DI-0010"},
	"private-key-file": {"CIS-DI-0010"},
	"package-cache":    {"DKL-DI-0004"},
	"apt-lists":        {"DKL-DI-0005"},
	"update-alone":     {"CIS-DI-0007"},
	"sudo-usage":       {"DKL-DI-0001"},
	"non-unique-uid":   {"DKL-LI-0002"},
}

var contractDockleOutOfScope = []string{
	"world-writable-file", "privileged-port", "shell-form-entrypoint", "runtime-needs-capability",
	"needs-setuid-setgid", "writes-outside-tmp", "nonroot-privileged-port",
}

func TestDockleScopeFollowsTheContract(t *testing.T) {
	o := loadRealOracle(t)
	covered := map[string]bool{}
	for prop, want := range contractDockle {
		covered[prop] = true
		scope := o.Properties[prop].Tools[ToolDockle]
		if !scope.InScope || !reflect.DeepEqual(scope.DetectIDs, want) {
			t.Errorf("%s: dockle scope = in_scope %t detect_ids %v, want in scope with %v", prop, scope.InScope, scope.DetectIDs, want)
		}
	}
	for _, prop := range contractDockleOutOfScope {
		covered[prop] = true
		scope := o.Properties[prop].Tools[ToolDockle]
		if scope.InScope || len(scope.DetectIDs) != 0 {
			t.Errorf("%s: dockle must be out of scope without detect ids, got %+v", prop, scope)
		}
	}
	for prop := range o.Properties {
		if !covered[prop] {
			t.Errorf("property %s is in the oracle but not in the contract scope of Dockle: extend the contract list deliberately", prop)
		}
	}
}

func TestEveryDockleOutOfScopePropertyHasAReason(t *testing.T) {
	o := loadRealOracle(t)
	var outOfScope []string
	for prop, p := range o.Properties {
		scope := p.Tools[ToolDockle]
		if scope.InScope {
			continue
		}
		outOfScope = append(outOfScope, prop)
		if len(strings.TrimSpace(scope.Note)) < minNoteLength {
			t.Errorf("%s: dockle is out of scope without a reason, note = %q", prop, scope.Note)
		}
		if strings.TrimSpace(scope.Source) == "" {
			t.Errorf("%s: the out-of-scope entry of dockle names no source", prop)
		}
	}
	sort.Strings(outOfScope)
	want := append([]string{}, contractDockleOutOfScope...)
	sort.Strings(want)
	if !reflect.DeepEqual(outOfScope, want) {
		t.Errorf("dockle out-of-scope properties = %v, want %v", outOfScope, want)
	}
}

func TestEveryScopeEntryNamesItsSource(t *testing.T) {
	o := loadRealOracle(t)
	for prop, p := range o.Properties {
		for _, tool := range o.Tools {
			scope := p.Tools[tool]
			if strings.TrimSpace(scope.Source) == "" {
				t.Errorf("%s/%s: no source", prop, tool)
				continue
			}
			if cat := o.Catalogs[tool]; cat.Version != "" && !versionMentioned(scope.Source, cat.Version) {
				t.Errorf("%s/%s: source %q does not name the catalog version %s", prop, tool, scope.Source, cat.Version)
			}
			// The identifiers that are credited must be findable in the source
			// text, so that a source is more than a label. CST test names are
			// the names of the policy file of this benchmark, not catalog ids.
			if tool == ToolCST {
				continue
			}
			for _, id := range scope.DetectIDs {
				if strings.HasSuffix(id, "*") {
					continue
				}
				if !strings.Contains(scope.Source, strings.TrimPrefix(id, "SECRET:")) {
					t.Errorf("%s/%s: detect id %s is not named in the source %q", prop, tool, id, scope.Source)
				}
			}
		}
	}
}

func TestCatalogsPinTheirVersionsAndReferences(t *testing.T) {
	o := loadRealOracle(t)
	wantVersions := map[string]string{ToolHadolint: "2.14.0", ToolTrivy: "0.76.1", ToolCST: "1.22.1", ToolDockle: "0.4.15"}
	commitLike := regexp.MustCompile(`^[0-9a-f]{12,40}$`)
	for tool, version := range wantVersions {
		cat := o.Catalogs[tool]
		if cat.Version != version {
			t.Errorf("%s: catalog version = %q, want %q", tool, cat.Version, version)
		}
		if !commitLike.MatchString(cat.Ref) {
			t.Errorf("%s: catalog ref %q is not a commit", tool, cat.Ref)
		}
		if !strings.HasPrefix(cat.URL, "https://") {
			t.Errorf("%s: catalog url %q is not an https url", tool, cat.URL)
		}
	}
	if cat := o.Catalogs[ToolConUnit]; cat.Version != "" {
		t.Errorf("the tool under test has no pinned version, catalog says %q", cat.Version)
	}
	for _, tool := range o.Tools {
		if _, ok := o.Catalogs[tool]; !ok {
			t.Errorf("tool %s has no catalog", tool)
		}
	}
}

// TestTrivyIdsUseTheCatalogForm guards against the alias spelling DS002: the
// checks bundled with Trivy 0.76.1 report the id DS-0002.
func TestTrivyIdsUseTheCatalogForm(t *testing.T) {
	o := loadRealOracle(t)
	form := regexp.MustCompile(`^(DS-\d{4}|SECRET:.+)$`)
	for prop, p := range o.Properties {
		for _, id := range p.Tools[ToolTrivy].DetectIDs {
			if !form.MatchString(id) {
				t.Errorf("%s: trivy id %q is not in the form DS-0000 or SECRET:<rule>", prop, id)
			}
		}
	}
}

func TestConUnitScopeFollowsTheContract(t *testing.T) {
	o := loadRealOracle(t)
	want := map[string]struct{ pack, rule string }{
		"update-alone":            {"lint", "SPEC-09"},
		"sudo-usage":              {"lint", "SPEC-10"},
		"non-unique-uid":          {"lint", "FS-10"},
		"needs-setuid-setgid":     {"cis", "EXEC-02"},
		"writes-outside-tmp":      {"cis", "EXEC-01"},
		"nonroot-privileged-port": {"cis", "EXEC-02"},
		"package-cache":           {"lint", "FS-01"},
		"apt-lists":               {"lint", "FS-01"},
	}
	for prop, w := range want {
		scope := o.Properties[prop].Tools[ToolConUnit]
		if !scope.InScope || scope.Pack != w.pack || !reflect.DeepEqual(scope.DetectIDs, []string{w.rule}) {
			t.Errorf("%s: conunit scope = %+v, want pack %s and %s", prop, scope, w.pack, w.rule)
		}
	}
}

// pendingConUnitRules are rules of the lint pack that docs/INTERFACE_V2.md
// section 3 defines. A rule of this list may be absent from the rule catalog of a
// tree that has no lint pack yet, and its oracle source says so.
var pendingConUnitRules = map[string]bool{"SPEC-09": true, "SPEC-10": true, "FS-10": true}

// packIDs maps the pack names of the oracle to the pack IDs of ConUnit.
var packIDs = map[string]string{"cis": "PACK-CONUNIT-HARDENING", "hygiene": "PACK-PROD-HYGIENE", "lint": "PACK-IMAGE-LINT"}

func TestConUnitDetectIdsExistInTheRuleCatalogAndPack(t *testing.T) {
	o := loadRealOracle(t)
	packs := map[string]map[string]bool{}
	for _, p := range conunit.AllPacks() {
		members := map[string]bool{}
		for _, c := range p.Checks() {
			members[c.ID] = true
		}
		packs[p.ID()] = members
	}
	for prop, p := range o.Properties {
		scope := p.Tools[ToolConUnit]
		packID, known := packIDs[scope.Pack]
		if !known {
			t.Errorf("%s: pack %q is not one of cis, hygiene, lint", prop, scope.Pack)
			continue
		}
		for _, id := range scope.DetectIDs {
			if _, found := conunit.RuleByID(id); !found {
				if !pendingConUnitRules[id] {
					t.Errorf("%s: %s is not in the rule catalog of ConUnit", prop, id)
				} else if !strings.Contains(scope.Source, "unverified") {
					t.Errorf("%s: %s is not in the rule catalog here, so its source must say it is unverified: %q", prop, id, scope.Source)
				}
			}
			members, packExists := packs[packID]
			if !packExists {
				if scope.Pack != "lint" {
					t.Errorf("%s: pack %s does not exist", prop, scope.Pack)
				}
				continue // the lint pack does not exist in this tree
			}
			if !members[id] {
				t.Errorf("%s: rule %s is not part of the pack %s", prop, id, scope.Pack)
			}
		}
	}
}

func TestOracleScopeValidationRejectsBrokenSources(t *testing.T) {
	load := func() *Oracle {
		o, err := LoadOracle("testdata/mini_oracle.json")
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	setScope := func(o *Oracle, prop, tool string, edit func(*ToolScope)) {
		p := o.Properties[prop]
		s := p.Tools[tool]
		edit(&s)
		p.Tools[tool] = s
	}
	cases := []struct {
		name   string
		mutate func(o *Oracle)
		want   string
	}{
		{"missing source", func(o *Oracle) { setScope(o, "user", ToolDockle, func(s *ToolScope) { s.Source = "" }) }, "has no source"},
		{"blank source", func(o *Oracle) { setScope(o, "user", ToolTrivy, func(s *ToolScope) { s.Source = "  " }) }, "has no source"},
		{"source without the pinned version", func(o *Oracle) {
			setScope(o, "user", ToolDockle, func(s *ToolScope) { s.Source = "dockle CHECKPOINT.md, CIS-DI-0001" })
		}, "does not name the pinned catalog version 0.4.15"},
		{"source with another version", func(o *Oracle) {
			setScope(o, "user", ToolDockle, func(s *ToolScope) { s.Source = "dockle 0.4.14 CHECKPOINT.md" })
		}, "does not name the pinned catalog version"},
		{"source with a longer version number", func(o *Oracle) {
			setScope(o, "user", ToolDockle, func(s *ToolScope) { s.Source = "dockle 0.4.151 CHECKPOINT.md" })
		}, "does not name the pinned catalog version"},
		{"out of scope without a reason", func(o *Oracle) {
			setScope(o, "sigterm", ToolDockle, func(s *ToolScope) { s.Note = "n" })
		}, "out of scope without a stated reason"},
		{"out of scope with an empty note", func(o *Oracle) {
			setScope(o, "sigterm", ToolDockle, func(s *ToolScope) { s.Note = "" })
		}, "has no note"},
		{"catalog missing", func(o *Oracle) { delete(o.Catalogs, ToolDockle) }, "has no catalog entry"},
		{"catalog without a pinned version", func(o *Oracle) {
			c := o.Catalogs[ToolDockle]
			c.Version = ""
			o.Catalogs[ToolDockle] = c
		}, "needs the pinned version"},
		{"catalog without a url", func(o *Oracle) {
			c := o.Catalogs[ToolHadolint]
			c.URL = ""
			o.Catalogs[ToolHadolint] = c
		}, "needs a name and a url"},
		{"catalog with a bad date", func(o *Oracle) {
			c := o.Catalogs[ToolTrivy]
			c.Retrieved = "15.11.2026"
			o.Catalogs[ToolTrivy] = c
		}, "needs a retrieved date"},
		{"catalog for an unknown tool", func(o *Oracle) {
			o.Catalogs["grype"] = Catalog{Name: "x", URL: "https://example.invalid", Retrieved: "2026-11-15", Version: "1"}
		}, "unknown tool"},
		{"dockle missing from the tools list", func(o *Oracle) {
			var tools []string
			for _, t := range o.Tools {
				if t != ToolDockle {
					tools = append(tools, t)
				}
			}
			o.Tools = tools
		}, "tool \"dockle\" missing"},
		{"dockle entry missing from a property", func(o *Oracle) { delete(o.Properties["user"].Tools, ToolDockle) }, "no scope entry"},
		{"dockle in scope without detect ids", func(o *Oracle) {
			setScope(o, "user", ToolDockle, func(s *ToolScope) { s.DetectIDs = nil })
		}, "no detect_ids"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := load()
			tc.mutate(o)
			err := o.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	if err := load().Validate(); err != nil {
		t.Errorf("the unmodified mini oracle must be valid: %v", err)
	}
}

func TestVersionMentioned(t *testing.T) {
	cases := []struct {
		text, version string
		want          bool
	}{
		{"dockle version 0.4.15", "0.4.15", true},
		{"v0.4.15", "0.4.15", true},
		{"0.4.15", "0.4.15", true},
		{"dockle 0.4.15 CHECKPOINT.md", "0.4.15", true},
		{"Haskell Dockerfile Linter 2.14.0", "2.14.0", true},
		{"Version: 0.76.1", "0.76.1", true},
		{"dockle (0.4.15)", "0.4.15", true},
		{"dockle 0.4.151", "0.4.15", false},
		{"dockle 10.4.15", "0.4.15", false},
		{"dockle 0.4.150", "0.4.15", false},
		{"dockle 0.0.4.15", "0.4.15", false},
		{"dockle version dev", "0.4.15", false},
		{"", "0.4.15", false},
		{"dockle 0.4.15", "", false},
		{"dockle 0x4y15", "0.4.15", false},
	}
	for _, tc := range cases {
		if got := versionMentioned(tc.text, tc.version); got != tc.want {
			t.Errorf("versionMentioned(%q, %q) = %t, want %t", tc.text, tc.version, got, tc.want)
		}
	}
}
