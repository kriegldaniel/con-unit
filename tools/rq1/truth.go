package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// TruthFileName is the file next to the oracle that records the expected
// Tier 3 attribution of the seeded runtime defects.
const TruthFileName = "tier3_truth.json"

// TruthSchemaVersion is the schema of tier3_truth.json fixed by the interface
// contract (docs/INTERFACE_V2.md section 4).
const TruthSchemaVersion = 1

// TruthCase is one seeded runtime defect with the cause that the attribution
// is expected to find.
type TruthCase struct {
	// Case is the ID of the defect case in the oracle. The image of the case
	// is <image_prefix>/<case>:rq1.
	Case string `json:"case"`
	// Rule is the Tier 3 rule that is expected to fail, EXEC-01 or EXEC-02.
	Rule string `json:"rule"`
	// ExpectedMinimal is the minimal set of capabilities or writable mounts
	// that makes the container survive the treatment.
	ExpectedMinimal []string `json:"expected_minimal"`
	// Manifests is true when the defect shows on the real engine as a
	// treatment that fails while the baseline runs. A case that does not
	// manifest stays in the corpus and is left out of the accuracy
	// denominator.
	Manifests bool `json:"manifests"`
	// Note records what was observed on the engine. It is required when the
	// defect does not manifest.
	Note string `json:"note,omitempty"`
}

// Truth is fixtures/rq1/tier3_truth.json.
type Truth struct {
	SchemaVersion int         `json:"schema_version"`
	ImagePrefix   string      `json:"image_prefix"`
	Cases         []TruthCase `json:"cases"`
}

// LoadTruth reads a truth file and checks it on its own. Validate checks it
// against the oracle.
func LoadTruth(path string) (*Truth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading tier 3 truth file: %w", err)
	}
	var t Truth
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing tier 3 truth file %s: %w", path, err)
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	return &t, nil
}

var (
	capabilityName = regexp.MustCompile(`^CAP_[A-Z_]+$`)
	absolutePath   = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
)

// attributable lists the rules the attribution can explain, with the kind of
// entry each one expects in expected_minimal.
var attributable = map[string]func(string) bool{
	"EXEC-01": func(s string) bool { return absolutePath.MatchString(s) },
	"EXEC-02": func(s string) bool { return capabilityName.MatchString(s) },
}

// check enforces the invariants that do not need the oracle.
func (t *Truth) check() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if t.SchemaVersion != TruthSchemaVersion {
		add("schema_version is %d, want %d", t.SchemaVersion, TruthSchemaVersion)
	}
	if strings.TrimSpace(t.ImagePrefix) == "" {
		add("image_prefix is empty")
	}
	if len(t.Cases) == 0 {
		add("no cases")
	}
	seen := map[string]bool{}
	for _, c := range t.Cases {
		if c.Case == "" {
			add("a case has no name")
			continue
		}
		if seen[c.Case] {
			add("case %q is listed twice", c.Case)
		}
		seen[c.Case] = true
		valid, known := attributable[c.Rule]
		if !known {
			add("case %q: rule %q cannot be attributed (supported: EXEC-01, EXEC-02)", c.Case, c.Rule)
		}
		if len(c.ExpectedMinimal) == 0 {
			add("case %q: expected_minimal is empty", c.Case)
		}
		dup := map[string]bool{}
		for _, e := range c.ExpectedMinimal {
			if known && !valid(e) {
				add("case %q: %q is not a valid expected_minimal entry for %s", c.Case, e, c.Rule)
			}
			if dup[e] {
				add("case %q: expected_minimal lists %q twice", c.Case, e)
			}
			dup[e] = true
		}
		if !sort.StringsAreSorted(c.ExpectedMinimal) {
			add("case %q: expected_minimal must be sorted so that it compares with a sorted minimal set", c.Case)
		}
		if !c.Manifests && len(strings.TrimSpace(c.Note)) < minNoteLength {
			add("case %q does not manifest and needs a note that says what was observed", c.Case)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid tier 3 truth file:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// Validate checks the truth file against the oracle: every case is a defect
// case of the oracle, and the rule is the one the oracle credits to ConUnit
// for the property, run with a pack that contains it.
func (t *Truth) Validate(o *Oracle) error {
	if err := t.check(); err != nil {
		return err
	}
	byID := map[string]Case{}
	for _, c := range o.Cases {
		byID[c.ID] = c
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	for _, tc := range t.Cases {
		c, ok := byID[tc.Case]
		if !ok {
			add("case %q is not in the oracle", tc.Case)
			continue
		}
		if !c.DefectPresent {
			add("case %q is a clean control, a seeded defect is expected", tc.Case)
		}
		scope := o.Scope(c, ToolConUnit)
		if !scope.InScope {
			add("case %q: ConUnit is not in scope for property %q", tc.Case, c.Property)
			continue
		}
		if len(scope.DetectIDs) != 1 || scope.DetectIDs[0] != tc.Rule {
			add("case %q: the oracle credits ConUnit with %v for %q, the truth file says %s", tc.Case, scope.DetectIDs, c.Property, tc.Rule)
		}
		if scope.Pack != "cis" {
			add("case %q: the oracle runs ConUnit with pack %q, Tier 3 rules are in the hardening profile (cis)", tc.Case, scope.Pack)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("tier 3 truth file does not match the oracle:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// Image is the local image reference of a truth case.
func (t *Truth) Image(c TruthCase) string { return ImageRef(t.ImagePrefix, c.Case) }

// Scored returns the cases that enter the attribution accuracy denominator.
func (t *Truth) Scored() []TruthCase {
	var out []TruthCase
	for _, c := range t.Cases {
		if c.Manifests {
			out = append(out, c)
		}
	}
	return out
}
