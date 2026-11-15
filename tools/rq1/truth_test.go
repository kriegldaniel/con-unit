package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const realTruthPath = "../../fixtures/rq1/tier3_truth.json"

func loadRealTruth(t *testing.T) *Truth {
	t.Helper()
	truth, err := LoadTruth(realTruthPath)
	if err != nil {
		t.Fatalf("loading the real truth file: %v", err)
	}
	return truth
}

// execRulesOutsideTheTruthFile lists properties whose ConUnit rule is an
// attributable Tier 3 rule but whose case is deliberately not part of the
// seeded truth set. runtime-needs-capability predates the seeded set, and the
// interface contract names exactly three seeded cases.
var execRulesOutsideTheTruthFile = map[string]bool{"runtime-needs-capability": true}

func TestSeededCasesAndTruthFileAgree(t *testing.T) {
	o := loadRealOracle(t)
	truth := loadRealTruth(t)
	if err := truth.Validate(o); err != nil {
		t.Fatal(err)
	}

	// The three seeded runtime defects of the contract, with their expected
	// minimal cause and whether they manifest on the engine of the local run.
	want := map[string]struct {
		rule      string
		minimal   []string
		manifests bool
	}{
		"needs-setuid-setgid-defect":     {"EXEC-02", []string{"CAP_SETGID", "CAP_SETUID"}, true},
		"writes-outside-tmp-defect":      {"EXEC-01", []string{"/var/lib"}, true},
		"nonroot-privileged-port-defect": {"EXEC-02", []string{"CAP_NET_BIND_SERVICE"}, false},
	}
	if len(truth.Cases) != len(want) {
		t.Errorf("truth file has %d cases, the contract names %d", len(truth.Cases), len(want))
	}
	for _, tc := range truth.Cases {
		w, ok := want[tc.Case]
		if !ok {
			t.Errorf("truth case %q is not a seeded case of the contract", tc.Case)
			continue
		}
		if tc.Rule != w.rule || !reflect.DeepEqual(tc.ExpectedMinimal, w.minimal) || tc.Manifests != w.manifests {
			t.Errorf("%s = %+v, want rule %s minimal %v manifests %t", tc.Case, tc, w.rule, w.minimal, w.manifests)
		}
		if !tc.Manifests && len(tc.Note) < 100 {
			t.Errorf("%s does not manifest, the note must say what was observed, note = %q", tc.Case, tc.Note)
		}
	}

	// The image of a case is <image_prefix>/<case>:rq1, the reference that
	// tools/rq1 gives the image it builds, and the prefix is the default
	// prefix of the tool so that -keep-images leaves the images in place.
	if truth.ImagePrefix != defaultImagePrefix {
		t.Errorf("image_prefix = %q, the default image prefix of rq1 is %q", truth.ImagePrefix, defaultImagePrefix)
	}
	for _, tc := range truth.Cases {
		if got, wantRef := truth.Image(tc), "localhost/conunit-rq1/"+tc.Case+":rq1"; got != wantRef {
			t.Errorf("image of %s = %q, want %q", tc.Case, got, wantRef)
		}
	}

	// Every property that ConUnit checks with an attributable Tier 3 rule is
	// seeded in the truth file, or is listed above with its reason.
	inTruth := map[string]bool{}
	byID := map[string]Case{}
	for _, c := range o.Cases {
		byID[c.ID] = c
	}
	for _, tc := range truth.Cases {
		inTruth[byID[tc.Case].Property] = true
	}
	for prop, p := range o.Properties {
		scope := p.Tools[ToolConUnit]
		for _, id := range scope.DetectIDs {
			if _, attributableRule := attributable[id]; attributableRule && !inTruth[prop] && !execRulesOutsideTheTruthFile[prop] {
				t.Errorf("property %s is checked with the Tier 3 rule %s but has no case in the truth file", prop, id)
			}
		}
	}
	for prop := range execRulesOutsideTheTruthFile {
		if _, ok := o.Properties[prop]; !ok {
			t.Errorf("the allowance for property %s is stale, the oracle has no such property", prop)
		}
	}

	// Scored cases are the manifesting ones.
	scored := truth.Scored()
	sort.Slice(scored, func(i, j int) bool { return scored[i].Case < scored[j].Case })
	var names []string
	for _, c := range scored {
		names = append(names, c.Case)
	}
	if !reflect.DeepEqual(names, []string{"needs-setuid-setgid-defect", "writes-outside-tmp-defect"}) {
		t.Errorf("scored cases = %v, the case that does not manifest must be left out", names)
	}
}

func TestImageRef(t *testing.T) {
	cases := []struct{ prefix, id, want string }{
		{"localhost/conunit-rq1", "root-user-clean", "localhost/conunit-rq1/root-user-clean:rq1"},
		{"localhost/conunit-rq1/", "root-user-clean", "localhost/conunit-rq1/root-user-clean:rq1"},
		{"x", "a", "x/a:rq1"},
	}
	for _, tc := range cases {
		if got := ImageRef(tc.prefix, tc.id); got != tc.want {
			t.Errorf("ImageRef(%q, %q) = %q, want %q", tc.prefix, tc.id, got, tc.want)
		}
	}
}

// networkCommand finds build instructions that need the network.
var networkCommand = regexp.MustCompile(`(?m)^\s*(RUN|ADD)\b.*(apk (add|update)|apt-get (update|install)|apt (update|install)|curl |wget |pip install|npm install|https?://)`)

func TestSeededDockerfilesAreSelfContained(t *testing.T) {
	o := loadRealOracle(t)
	truth := loadRealTruth(t)
	seededProps := map[string]bool{}
	byID := map[string]Case{}
	for _, c := range o.Cases {
		byID[c.ID] = c
	}
	for _, tc := range truth.Cases {
		seededProps[byID[tc.Case].Property] = true
	}
	for _, c := range o.Cases {
		data, err := os.ReadFile(o.Path(c.Dockerfile))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		needsNetwork := networkCommand.MatchString(text)
		saysNetwork := strings.Contains(text, "Needs network at build time")
		switch {
		case seededProps[c.Property] && needsNetwork:
			t.Errorf("%s: a seeded runtime case must build without the network", c.ID)
		case needsNetwork && !saysNetwork:
			t.Errorf("%s: the build needs the network, its header comment must say \"Needs network at build time\"", c.ID)
		case !needsNetwork && saysNetwork:
			t.Errorf("%s: the header comment claims a network need that the instructions do not have", c.ID)
		}
		if seededProps[c.Property] && !strings.Contains(text, "No network needed") {
			t.Errorf("%s: the header comment of a seeded case states that no network is needed", c.ID)
		}
	}
}

// TestSeededPortCaseDeclaresNoPort keeps the nonroot-privileged-port case a
// runtime defect: with an EXPOSE it would also be a static defect and the
// static tools would be credited with it.
func TestSeededPortCaseDeclaresNoPort(t *testing.T) {
	o := loadRealOracle(t)
	for _, id := range []string{"nonroot-privileged-port-defect", "nonroot-privileged-port-clean"} {
		var dockerfile string
		for _, c := range o.Cases {
			if c.ID == id {
				dockerfile = c.Dockerfile
			}
		}
		data, err := os.ReadFile(o.Path(dockerfile))
		if err != nil {
			t.Fatal(err)
		}
		if regexp.MustCompile(`(?mi)^\s*EXPOSE\b`).Match(data) {
			t.Errorf("%s must not declare a port", id)
		}
		if !regexp.MustCompile(`(?m)^USER 10001$`).Match(data) {
			t.Errorf("%s must run as the non-root user 10001", id)
		}
	}
}

func TestTruthValidationRejectsBrokenInput(t *testing.T) {
	valid := func() Truth {
		return Truth{
			SchemaVersion: 1,
			ImagePrefix:   "localhost/conunit-rq1",
			Cases: []TruthCase{
				{Case: "needs-setuid-setgid-defect", Rule: "EXEC-02", ExpectedMinimal: []string{"CAP_SETGID", "CAP_SETUID"}, Manifests: true},
				{Case: "writes-outside-tmp-defect", Rule: "EXEC-01", ExpectedMinimal: []string{"/var/lib"}, Manifests: true},
			},
		}
	}
	const longNote = "Observed on the engine: the baseline exits with status 1 and the baseline gate stops the case."
	cases := []struct {
		name   string
		mutate func(t *Truth)
		want   string
	}{
		{"wrong schema version", func(t *Truth) { t.SchemaVersion = 2 }, "schema_version is 2"},
		{"no image prefix", func(t *Truth) { t.ImagePrefix = " " }, "image_prefix is empty"},
		{"no cases", func(t *Truth) { t.Cases = nil }, "no cases"},
		{"case without a name", func(t *Truth) { t.Cases[0].Case = "" }, "has no name"},
		{"duplicate case", func(t *Truth) { t.Cases = append(t.Cases, t.Cases[0]) }, "listed twice"},
		{"rule that cannot be attributed", func(t *Truth) { t.Cases[0].Rule = "EXEC-04" }, "cannot be attributed"},
		{"empty rule", func(t *Truth) { t.Cases[0].Rule = "" }, "cannot be attributed"},
		{"empty expected set", func(t *Truth) { t.Cases[0].ExpectedMinimal = nil }, "expected_minimal is empty"},
		{"capability without the prefix", func(t *Truth) { t.Cases[0].ExpectedMinimal = []string{"SETGID", "SETUID"} }, "not a valid expected_minimal entry"},
		{"mount for a capability rule", func(t *Truth) { t.Cases[0].ExpectedMinimal = []string{"/var/lib"} }, "not a valid expected_minimal entry"},
		{"relative path for a mount rule", func(t *Truth) { t.Cases[1].ExpectedMinimal = []string{"var/lib"} }, "not a valid expected_minimal entry"},
		{"capability for a mount rule", func(t *Truth) { t.Cases[1].ExpectedMinimal = []string{"CAP_CHOWN"} }, "not a valid expected_minimal entry"},
		{"unsorted expected set", func(t *Truth) { t.Cases[0].ExpectedMinimal = []string{"CAP_SETUID", "CAP_SETGID"} }, "must be sorted"},
		{"duplicate entry", func(t *Truth) { t.Cases[0].ExpectedMinimal = []string{"CAP_SETGID", "CAP_SETGID"} }, "lists \"CAP_SETGID\" twice"},
		{"no manifest without a note", func(t *Truth) { t.Cases[0].Manifests = false }, "needs a note"},
		{"no manifest with a short note", func(t *Truth) { t.Cases[0].Manifests, t.Cases[0].Note = false, "n/a" }, "needs a note"},
		{"case that is not in the oracle", func(t *Truth) { t.Cases[0].Case = "no-such-case" }, "is not in the oracle"},
		{"case that is a clean control", func(t *Truth) { t.Cases[0].Case = "needs-setuid-setgid-clean" }, "clean control"},
		{"rule that differs from the oracle", func(t *Truth) { t.Cases[0].Rule = "EXEC-01"; t.Cases[0].ExpectedMinimal = []string{"/var/lib"} }, "the oracle credits ConUnit with [EXEC-02]"},
		{"property that ConUnit does not detect with a Tier 3 rule", func(t *Truth) { t.Cases[0].Case = "root-user-implicit" }, "the oracle credits ConUnit with [SPEC-01]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			truth := valid()
			tc.mutate(&truth)
			err := truth.Validate(loadRealOracle(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	t.Run("valid file", func(t *testing.T) {
		truth := valid()
		if err := truth.Validate(loadRealOracle(t)); err != nil {
			t.Errorf("a valid truth file was rejected: %v", err)
		}
	})
	t.Run("a case that does not manifest with a note is valid", func(t *testing.T) {
		truth := valid()
		truth.Cases[0].Manifests, truth.Cases[0].Note = false, longNote
		if err := truth.Validate(loadRealOracle(t)); err != nil {
			t.Errorf("err = %v", err)
		}
		if got := truth.Scored(); len(got) != 1 || got[0].Case != "writes-outside-tmp-defect" {
			t.Errorf("scored = %+v, want only the case that manifests", got)
		}
	})
	t.Run("a pack other than the hardening profile", func(t *testing.T) {
		o := loadRealOracle(t)
		p := o.Properties["needs-setuid-setgid"]
		s := p.Tools[ToolConUnit]
		s.Pack = "hygiene"
		p.Tools[ToolConUnit] = s
		truth := valid()
		if err := truth.Validate(o); err == nil || !strings.Contains(err.Error(), "hardening profile (cis)") {
			t.Errorf("err = %v, want the pack to be rejected", err)
		}
	})
	t.Run("ConUnit out of scope for the property", func(t *testing.T) {
		o := loadRealOracle(t)
		p := o.Properties["needs-setuid-setgid"]
		s := p.Tools[ToolConUnit]
		s.InScope = false
		p.Tools[ToolConUnit] = s
		truth := valid()
		if err := truth.Validate(o); err == nil || !strings.Contains(err.Error(), "not in scope") {
			t.Errorf("err = %v, want the scope to be rejected", err)
		}
	})
}

func TestLoadTruthRejectsUnusableFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name, path, want string
	}{
		{"missing file", filepath.Join(dir, "absent.json"), "reading tier 3 truth file"},
		{"not JSON", write("bad.json", "not json"), "parsing tier 3 truth file"},
		{"cases of the wrong type", write("type.json", `{"schema_version":1,"image_prefix":"x","cases":"none"}`), "parsing tier 3 truth file"},
		{"empty object", write("empty.json", `{}`), "invalid tier 3 truth file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadTruth(tc.path); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCheckTruthAtStartup(t *testing.T) {
	o := loadRealOracle(t)

	t.Run("matching prefix is silent apart from the summary", func(t *testing.T) {
		var buf bytes.Buffer
		if err := checkTruth(NewLogger(&buf), o, defaultImagePrefix); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "3 seeded Tier 3 cases, 2 scored") || strings.Contains(buf.String(), "differs") {
			t.Errorf("log = %q", buf.String())
		}
	})
	t.Run("a trailing slash is the same prefix", func(t *testing.T) {
		var buf bytes.Buffer
		if err := checkTruth(NewLogger(&buf), o, defaultImagePrefix+"/"); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "differs") {
			t.Errorf("log = %q", buf.String())
		}
	})
	t.Run("another prefix is a warning, not an error", func(t *testing.T) {
		var buf bytes.Buffer
		if err := checkTruth(NewLogger(&buf), o, "localhost/other"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "differs") || !strings.Contains(buf.String(), "WARN") {
			t.Errorf("log = %q, want a warning", buf.String())
		}
	})
	t.Run("an oracle without a truth file is not checked", func(t *testing.T) {
		mini, err := LoadOracle("testdata/mini_oracle.json")
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := checkTruth(NewLogger(&buf), mini, defaultImagePrefix); err != nil || buf.Len() != 0 {
			t.Errorf("err = %v, log = %q", err, buf.String())
		}
	})
	t.Run("a truth file that disagrees with the oracle stops the run", func(t *testing.T) {
		dir := t.TempDir()
		body := `{"schema_version":1,"image_prefix":"localhost/conunit-rq1","cases":[{"case":"root-user-implicit","rule":"EXEC-02","expected_minimal":["CAP_CHOWN"],"manifests":true}]}`
		if err := os.WriteFile(filepath.Join(dir, TruthFileName), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		other := *o
		other.Dir = dir
		if err := checkTruth(NewLogger(&bytes.Buffer{}), &other, defaultImagePrefix); err == nil || !strings.Contains(err.Error(), "does not match the oracle") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("an unreadable truth file stops the run", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, TruthFileName), []byte("{"), 0o644); err != nil {
			t.Fatal(err)
		}
		other := *o
		other.Dir = dir
		if err := checkTruth(NewLogger(&bytes.Buffer{}), &other, defaultImagePrefix); err == nil {
			t.Error("a truth file that is not JSON must stop the run")
		}
	})
}
