package main

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const realOraclePath = "../../fixtures/rq1/oracle.json"

func loadRealOracle(t *testing.T) *Oracle {
	t.Helper()
	o, err := LoadOracle(realOraclePath)
	if err != nil {
		t.Fatalf("loading the real oracle: %v", err)
	}
	return o
}

func TestRealOracleIsValid(t *testing.T) {
	o := loadRealOracle(t)
	if err := o.ValidateFiles(); err != nil {
		t.Fatal(err)
	}
	if got := len(o.Properties); got != 19 {
		t.Errorf("properties = %d, want the 13 of the first corpus and the 6 added with Dockle (19)", got)
	}
	if got := len(o.Cases); got != 39 {
		t.Errorf("cases = %d, want 39", got)
	}
	if !reflect.DeepEqual(o.Tools, allTools) {
		t.Errorf("tools = %v, want the column order %v", o.Tools, allTools)
	}
	for id, p := range o.Properties {
		conunit := p.Tools[ToolConUnit]
		if !conunit.InScope {
			t.Errorf("property %s: ConUnit is expected in scope for every corpus property", id)
		}
		if conunit.Pack != "cis" && conunit.Pack != "hygiene" && conunit.Pack != "lint" {
			t.Errorf("property %s: unexpected pack %q", id, conunit.Pack)
		}
	}
}

func TestSigtermPropertyDeclaresItsPack(t *testing.T) {
	o := loadRealOracle(t)
	scope := o.Properties["shell-form-entrypoint"].Tools[ToolConUnit]
	if !scope.InScope || scope.Pack == "cis" || len(scope.DetectIDs) != 1 || scope.DetectIDs[0] != "EXEC-03" {
		t.Errorf("the SIGTERM property must run ConUnit with a pack that includes EXEC-03, got %+v", scope)
	}
	if !strings.Contains(scope.Note, "no SIGTERM check") {
		t.Errorf("the oracle must say why a non-hardening pack is used, note = %q", scope.Note)
	}
	hadolint := o.Properties["shell-form-entrypoint"].Tools[ToolHadolint]
	if !hadolint.InScope || hadolint.DetectIDs[0] != "DL3025" {
		t.Errorf("Hadolint must be credited with DL3025 for the shell-form ENTRYPOINT, got %+v", hadolint)
	}
	add := o.Properties["add-local-file"].Tools[ToolHadolint]
	if !add.InScope || add.DetectIDs[0] != "DL3020" {
		t.Errorf("Hadolint must be credited with DL3020 for ADD of local files, got %+v", add)
	}
}

// TestCorpusMatchesOracle checks that every case directory is listed and that
// every listed case exists, so the corpus and the ground truth cannot drift.
func TestCorpusMatchesOracle(t *testing.T) {
	o := loadRealOracle(t)
	entries, err := os.ReadDir(filepath.Join(o.Dir, "cases"))
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			onDisk[e.Name()] = true
		}
	}
	listed := map[string]bool{}
	for _, c := range o.Cases {
		listed[c.ID] = true
		if !onDisk[c.ID] {
			t.Errorf("case %s is listed in the oracle but has no directory", c.ID)
		}
		want := "cases/" + c.ID + "/Dockerfile"
		if c.Dockerfile != want {
			t.Errorf("case %s: dockerfile = %q, want %q", c.ID, c.Dockerfile, want)
		}
	}
	for name := range onDisk {
		if !listed[name] {
			t.Errorf("directory cases/%s is not listed in the oracle", name)
		}
	}
}

var fromLine = regexp.MustCompile(`(?im)^\s*FROM\s+(\S+)`)

// TestBasesArePinnedToTheDataset checks that every FROM line uses a digest that
// appears in the pinned evaluation dataset, so the corpus and the paper's
// dataset use the same base images. If the dataset is regenerated, update the
// digests in fixtures/rq1/cases with sed.
func TestBasesArePinnedToTheDataset(t *testing.T) {
	o := loadRealOracle(t)
	pinned := map[string]bool{}
	f, err := os.Open("../../fixtures/evaluation_dataset_pinned.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pinned[normalizeRef(line)] = true
	}
	if len(pinned) == 0 {
		t.Fatal("pinned dataset is empty")
	}
	for _, c := range o.Cases {
		data, err := os.ReadFile(o.Path(c.Dockerfile))
		if err != nil {
			t.Fatal(err)
		}
		matches := fromLine.FindAllStringSubmatch(string(data), -1)
		if len(matches) != 1 {
			t.Errorf("case %s: want exactly one FROM line, got %d", c.ID, len(matches))
			continue
		}
		ref := matches[0][1]
		if !strings.Contains(ref, "@sha256:") {
			t.Errorf("case %s: base %q is not digest-pinned", c.ID, ref)
			continue
		}
		if !pinned[normalizeRef(ref)] {
			t.Errorf("case %s: base %q is not in fixtures/evaluation_dataset_pinned.txt", c.ID, ref)
		}
	}
}

func normalizeRef(ref string) string {
	for _, prefix := range []string{"index.docker.io/library/", "docker.io/library/", "registry-1.docker.io/library/"} {
		ref = strings.TrimPrefix(ref, prefix)
	}
	return ref
}

// TestControlsAreSingleChangeVariants checks the corpus design rule that a
// control differs from its defect case. Identical Dockerfiles would make the
// pair meaningless.
func TestControlsAreSingleChangeVariants(t *testing.T) {
	o := loadRealOracle(t)
	for _, prop := range o.PropertyOrder() {
		var control string
		var defects []string
		for _, c := range o.CasesOf(prop) {
			data, err := os.ReadFile(o.Path(c.Dockerfile))
			if err != nil {
				t.Fatal(err)
			}
			body := stripComments(string(data))
			if c.DefectPresent {
				defects = append(defects, body)
			} else {
				control = body
			}
		}
		for _, d := range defects {
			if d == control {
				t.Errorf("property %s: a defect case has the same instructions as the control", prop)
			}
		}
	}
}

func stripComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// TestCSTPoliciesDefineTheirDetectNames checks that the test names the oracle
// expects to fail are actually defined by the CST config.
func TestCSTPoliciesDefineTheirDetectNames(t *testing.T) {
	o := loadRealOracle(t)
	for id, p := range o.Properties {
		scope := p.Tools[ToolCST]
		if !scope.InScope {
			continue
		}
		data, err := os.ReadFile(o.Path(scope.Config))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range scope.DetectIDs {
			if !strings.Contains(string(data), `name: "`+name+`"`) {
				t.Errorf("property %s: %s does not define a test named %q", id, scope.Config, name)
			}
		}
	}
}

func TestOracleValidationRejectsBrokenInput(t *testing.T) {
	load := func() *Oracle {
		o, err := LoadOracle("testdata/mini_oracle.json")
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	cases := []struct {
		name   string
		mutate func(o *Oracle)
		want   string
	}{
		{"duplicate case id", func(o *Oracle) { o.Cases = append(o.Cases, o.Cases[0]) }, "not unique"},
		{"unknown property", func(o *Oracle) { o.Cases[0].Property = "nope" }, "unknown property"},
		{"missing control", func(o *Oracle) { o.Cases[1].DefectPresent = true }, "exactly one clean control"},
		{"missing defect", func(o *Oracle) { o.Cases[0].DefectPresent = false }, "no defect case"},
		{"in scope without ids", func(o *Oracle) {
			p := o.Properties["user"]
			s := p.Tools[ToolHadolint]
			s.DetectIDs = nil
			p.Tools[ToolHadolint] = s
		}, "no detect_ids"},
		{"missing tool entry", func(o *Oracle) { delete(o.Properties["user"].Tools, ToolTrivy) }, "no scope entry"},
		{"conunit without pack", func(o *Oracle) {
			p := o.Properties["user"]
			s := p.Tools[ToolConUnit]
			s.Pack = ""
			p.Tools[ToolConUnit] = s
		}, "no pack"},
	}
	for _, tc := range cases {
		o := load()
		tc.mutate(o)
		err := o.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", tc.name, err, tc.want)
		}
	}
	if err := load().Validate(); err != nil {
		t.Errorf("unmodified mini oracle must be valid: %v", err)
	}
}
