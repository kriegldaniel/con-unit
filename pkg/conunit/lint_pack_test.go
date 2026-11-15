package conunit_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

var (
	// lintMembers are the members of PACK-IMAGE-LINT in execution order, as the
	// interface contract fixes them.
	lintMembers = []string{
		"SPEC-01", "CIS-4.6", "FS-04", "SPEC-07", "SPEC-03", "FS-06", "FS-08", "FS-01",
		"SPEC-09", "SPEC-10", "SPEC-11", "SPEC-12", "SPEC-13", "FS-10", "FS-11", "FS-12",
	}
	newLintChecks = []string{"SPEC-09", "SPEC-10", "SPEC-11", "SPEC-12", "SPEC-13", "FS-10", "FS-11", "FS-12"}
)

func TestImageLintPackMembershipAndOrder(t *testing.T) {
	pack := conunit.ImageLint()
	if pack.ID() != "PACK-IMAGE-LINT" || pack.Name() != "Image Static Lint Pack" {
		t.Fatalf("pack = %q / %q, want PACK-IMAGE-LINT / Image Static Lint Pack", pack.ID(), pack.Name())
	}
	if got := checkIDs(pack); !slices.Equal(got, lintMembers) {
		t.Fatalf("members = %v\nwant     %v", got, lintMembers)
	}
	for _, check := range pack.Checks() {
		if len(check.LegacyIDs) != 0 {
			t.Errorf("%s carries the legacy handles %v, but the pack is new", check.ID, check.LegacyIDs)
		}
	}
	if !strings.Contains(pack.Description(), "not a compliance assessment") {
		t.Errorf("the description must not claim compliance: %q", pack.Description())
	}
}

func TestImageLintPackIsStaticOnly(t *testing.T) {
	for _, check := range conunit.ImageLint().Checks() {
		rule, ok := conunit.RuleByID(check.ID)
		if !ok {
			t.Fatalf("%s has no catalog entry", check.ID)
		}
		if rule.Tier != spec.TierSpec && rule.Tier != spec.TierFilesystem {
			t.Errorf("%s is a %v check, but the lint pack has no Tier 3 and no Tier 4 check", check.ID, rule.Tier)
		}
		if check.ID == "SUP-01" || check.ID == "SUP-03" {
			t.Errorf("%s needs a package inventory", check.ID)
		}
	}
}

func TestImageLintPackIsListedAndSelectable(t *testing.T) {
	found := false
	for _, pack := range conunit.AllPacks() {
		if pack.ID() == "PACK-IMAGE-LINT" {
			found = true
		}
	}
	if !found {
		t.Fatal("AllPacks does not list the lint pack")
	}
	if names := conunit.PackFlagNames["PACK-IMAGE-LINT"]; !slices.Equal(names, []string{"lint", "image-lint"}) {
		t.Errorf("flag names = %v, want lint and image-lint", names)
	}
}

func TestImageLintPackEmitsOneResultPerMemberEvenWithoutEvidence(t *testing.T) {
	// No index and no inspection data: every member must still emit exactly
	// one result, and none of them may pass.
	c := &conunit.Container{}
	conunit.ImageLint().Apply(c)
	if got := resultIDs(c); !slices.Equal(got, lintMembers) {
		t.Fatalf("results = %v, want one per member in order %v", got, lintMembers)
	}
	for _, r := range c.Results {
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonEvidenceIncomplete {
			t.Errorf("%s = %s/%s without any evidence, want UNVERIFIED/EVIDENCE_INCOMPLETE", r.TestID, r.EffectiveOutcome(), r.Reason)
		}
	}
}

func TestImageLintPackExclusion(t *testing.T) {
	for _, id := range lintMembers {
		t.Run(id, func(t *testing.T) {
			c := cleanSpec().container(t)
			conunit.ImageLint().Except(id).Apply(c)
			want := slices.DeleteFunc(slices.Clone(lintMembers), func(member string) bool { return member == id })
			if got := resultIDs(c); !slices.Equal(got, want) {
				t.Fatalf("after Except(%q) the results are %v, want %v", id, got, want)
			}
		})
	}
	t.Run("an ID of another pack changes nothing", func(t *testing.T) {
		c := cleanSpec().container(t)
		conunit.ImageLint().Except("EXEC-01", "SUP-02", "CIS-5.3").Apply(c)
		if got := resultIDs(c); !slices.Equal(got, lintMembers) {
			t.Fatalf("results = %v, want every member", got)
		}
	})
	t.Run("several exclusions", func(t *testing.T) {
		c := cleanSpec().container(t)
		conunit.ImageLint().Except("SPEC-13", "FS-12", "SPEC-01").Apply(c)
		if got := len(c.Results); got != len(lintMembers)-3 {
			t.Fatalf("%d results, want %d", got, len(lintMembers)-3)
		}
	})
}

func TestImageLintPackParameters(t *testing.T) {
	params := map[string]string{}
	for _, check := range conunit.ImageLint().Checks() {
		params[check.ID] = check.Params
	}
	if want := "disallowed keys: PASS, PASSWD, PASSWORD, SECRET, KEY, ACCESS, TOKEN; accepted keys: GPG_KEY, GPG_KEYS"; params["SPEC-03"] != want {
		t.Errorf("SPEC-03 parameters = %q, want %q", params["SPEC-03"], want)
	}
	for _, path := range []string{"/var/cache/apt", "/var/cache/apk", "/root/.cache", "/.git", "/root/.ssh", "/.env", "/var/lib/apt/lists"} {
		if !strings.Contains(params["FS-01"], path) {
			t.Errorf("FS-01 parameters %q lack %s", params["FS-01"], path)
		}
	}
	for _, id := range []string{"FS-11", "FS-12", "SPEC-12"} {
		if params[id] == "" {
			t.Errorf("%s states no parameters, but its lists are the point of the check", id)
		}
	}
	if !strings.Contains(params["FS-11"], "node_modules, vendor") {
		t.Errorf("FS-11 parameters %q must name the skipped trees", params["FS-11"])
	}
}

// The hygiene pack and every older pack keep their checks and their lists.
func TestOlderPacksAreUnchanged(t *testing.T) {
	want := map[string][]string{
		"PACK-PROD-HYGIENE":      {"SPEC-01", "SPEC-02", "SPEC-03", "FS-01", "FS-03", "FS-04", "EXEC-01", "EXEC-02", "EXEC-03"},
		"PACK-CONUNIT-HARDENING": {"SPEC-01", "CIS-4.6", "FS-04", "SPEC-07", "SPEC-03", "FS-06", "FS-08", "FS-05", "FS-09", "FS-07", "SUP-02", "EXEC-02", "SPEC-05", "SPEC-06", "EXEC-07", "EXEC-01", "EXEC-04"},
		"PACK-KUBE-HARDENED":     {"SPEC-01", "EXEC-01", "EXEC-02", "EXEC-05", "EXEC-04", "EXEC-03", "SPEC-05", "EXEC-08"},
		"PACK-NIST-800-190":      {"SPEC-01", "SPEC-03", "FS-06", "FS-03", "FS-01", "FS-04", "FS-05", "EXEC-01", "EXEC-02", "EXEC-03"},
		"PACK-DISTROLESS":        {"SPEC-01", "DISTRO-02", "DISTRO-03", "FS-04", "FS-05", "EXEC-01", "EXEC-02"},
	}
	seen := map[string]bool{}
	for _, pack := range conunit.AllPacks() {
		expected, ok := want[pack.ID()]
		if !ok {
			continue
		}
		seen[pack.ID()] = true
		if got := checkIDs(pack); !slices.Equal(got, expected) {
			t.Errorf("%s checks = %v, want %v", pack.ID(), got, expected)
		}
		for _, check := range pack.Checks() {
			if slices.Contains(newLintChecks, check.ID) {
				t.Errorf("%s gained the lint check %s", pack.ID(), check.ID)
			}
			if check.ID == "FS-01" && strings.Contains(check.Params, "/var/lib/apt/lists") {
				t.Errorf("%s FS-01 gained /var/lib/apt/lists: %s", pack.ID(), check.Params)
			}
		}
	}
	if len(seen) != len(want) {
		t.Errorf("only %d of %d older packs were found", len(seen), len(want))
	}
}

// engineCallLog is a fake engine that records every call and fails it, so a
// test can prove that a pack never reaches for the engine.
func engineCallLog(t *testing.T) (*engine.Engine, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\nexit 97\n"
	path := filepath.Join(dir, "engine")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &engine.Engine{BinaryPath: path}, log
}

func TestImageLintPackNeverCallsTheEngine(t *testing.T) {
	for _, withIndex := range []bool{true, false} {
		name := "with the file index"
		if !withIndex {
			name = "without the file index"
		}
		t.Run(name, func(t *testing.T) {
			eng, log := engineCallLog(t)
			c := cleanSpec().container(t)
			if !withIndex {
				c.OCIIndex = nil
			}
			c.Engine = eng
			conunit.ImageLint().Apply(c)
			if data, err := os.ReadFile(log); err == nil {
				t.Fatalf("the lint pack called the engine:\n%s", data)
			}
			if c.Engine != eng {
				t.Error("the pack must hand the engine back to the container")
			}
			if len(c.Results) != len(lintMembers) {
				t.Errorf("%d results, want %d", len(c.Results), len(lintMembers))
			}
		})
	}
}

// seededDefects changes the control image in one way per new check. Each
// defect must fail its own check and leave the other seven passing, and the
// control must pass all eight.
var seededDefects = map[string]func(*imageSpec){
	"SPEC-09": func(s *imageSpec) {
		s.history = runHistory("ADD alpine-minirootfs.tar.gz /", "apt-get update", `CMD ["/app/main"]`)
	},
	"SPEC-10": func(s *imageSpec) {
		s.history = runHistory("ADD alpine-minirootfs.tar.gz /", "sudo make install", `CMD ["/app/main"]`)
	},
	"SPEC-11": func(s *imageSpec) {
		s.history = runHistory("ADD alpine-minirootfs.tar.gz /", "apt-get dist-upgrade -y", `CMD ["/app/main"]`)
	},
	"SPEC-12": func(s *imageSpec) { s.volumes = []string{"/sys"} },
	"SPEC-13": func(s *imageSpec) { s.ref = "example.test/app:latest" },
	"FS-10": func(s *imageSpec) {
		s.layers = append(s.layers, []layerFile{fileEntry("etc/passwd", "root:x:0:0:root:/root:/bin/sh\ntoor:x:0:0:toor:/root:/bin/sh\napp:x:10001:10001:app:/app:/sbin/nologin\n")})
	},
	"FS-11": func(s *imageSpec) { s.layers = append(s.layers, []layerFile{fileEntry("app/.git/config", "[core]")}) },
	"FS-12": func(s *imageSpec) {
		s.layers = append(s.layers, []layerFile{fileEntry("app/config/credentials.json", "{}")})
	},
}

func newCheckOutcomes(t *testing.T, c *conunit.Container) map[string]spec.Outcome {
	t.Helper()
	conunit.ImageLint().Apply(c)
	outcomes := map[string]spec.Outcome{}
	for _, r := range c.Results {
		if slices.Contains(newLintChecks, r.TestID) {
			outcomes[r.TestID] = r.EffectiveOutcome()
		}
	}
	if len(outcomes) != len(newLintChecks) {
		t.Fatalf("got outcomes for %v, want all of %v", outcomes, newLintChecks)
	}
	return outcomes
}

func TestSeededDefectsAndCleanControlPerCheck(t *testing.T) {
	t.Run("the control passes every new check", func(t *testing.T) {
		for id, outcome := range newCheckOutcomes(t, cleanSpec().container(t)) {
			if outcome != spec.OutcomePass {
				t.Errorf("%s = %s on the clean control, want PASS", id, outcome)
			}
		}
	})
	for _, target := range newLintChecks {
		t.Run("defect of "+target, func(t *testing.T) {
			s := cleanSpec()
			seededDefects[target](&s)
			for id, outcome := range newCheckOutcomes(t, s.container(t)) {
				want := spec.OutcomePass
				if id == target {
					want = spec.OutcomeFail
				}
				if outcome != want {
					t.Errorf("%s = %s on the %s defect, want %s", id, outcome, target, want)
				}
			}
		})
	}
}

func TestImageLintPackExistingChecksOnTheFixtures(t *testing.T) {
	t.Run("SPEC-03 accepts GPG_KEY and flags other keys", func(t *testing.T) {
		accepted := cleanSpec()
		accepted.env = []string{"PATH=/usr/bin", "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305"}
		flagged := cleanSpec()
		flagged.env = []string{"PATH=/usr/bin", "API_KEY=abc"}
		for _, tc := range []struct {
			name string
			spec imageSpec
			want spec.Outcome
		}{{"accepted", accepted, spec.OutcomePass}, {"flagged", flagged, spec.OutcomeFail}} {
			c := tc.spec.container(t)
			conunit.ImageLint().Apply(c)
			for _, r := range c.Results {
				if r.TestID == "SPEC-03" && r.EffectiveOutcome() != tc.want {
					t.Errorf("%s: SPEC-03 = %s (%s), want %s", tc.name, r.EffectiveOutcome(), r.Message, tc.want)
				}
			}
		}
	})
	t.Run("FS-01 reports the apt lists and the operator can allow them", func(t *testing.T) {
		s := cleanSpec()
		s.layers = append(s.layers, []layerFile{dirEntry("var/lib/apt/lists/"), fileEntry("var/lib/apt/lists/lock", ""), fileEntry("var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease", "Origin: Debian\n")})
		lockOnly := cleanSpec()
		lockOnly.layers = append(lockOnly.layers, []layerFile{dirEntry("var/lib/apt/lists/"), fileEntry("var/lib/apt/lists/lock", "")})
		outcome := func(pack conunit.RulePack) spec.Outcome {
			c := s.container(t)
			pack.Apply(c)
			for _, r := range c.Results {
				if r.TestID == "FS-01" {
					return r.EffectiveOutcome()
				}
			}
			t.Fatal("no FS-01 result")
			return ""
		}
		if got := outcome(conunit.ImageLint()); got != spec.OutcomeFail {
			t.Errorf("FS-01 = %s with /var/lib/apt/lists present, want FAIL", got)
		}
		if got := outcome(conunit.ImageLint().AllowPaths("/var/lib/apt/lists")); got != spec.OutcomePass {
			t.Errorf("FS-01 = %s with the path allowed, want PASS", got)
		}
		if got := outcome(conunit.ProductionHygiene().Except("EXEC-01", "EXEC-02", "EXEC-03")); got != spec.OutcomePass {
			t.Errorf("the hygiene pack does not check /var/lib/apt/lists, FS-01 = %s, want PASS", got)
		}
		c := lockOnly.container(t)
		conunit.ImageLint().Apply(c)
		for _, r := range c.Results {
			if r.TestID == "FS-01" && r.EffectiveOutcome() != spec.OutcomePass {
				t.Errorf("a lists directory with only apt's empty lock file is cleaned up, FS-01 = %s (%s), want PASS", r.EffectiveOutcome(), r.Message)
			}
		}
	})
}
