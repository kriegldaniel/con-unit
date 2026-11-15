package analysis

import (
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

func r(id, name string, tier spec.Tier, out spec.Outcome, reason spec.Reason) spec.TestResult {
	return spec.TestResult{TestID: id, TestName: name, Tier: tier, Outcome: out, Reason: reason}
}

func img(ref, status string, results ...spec.TestResult) *spec.SuiteResult {
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, Status: status, Results: results}
}

func load(t *testing.T, images ...*spec.SuiteResult) *studyfile.Loaded {
	t.Helper()
	l := &studyfile.Loaded{Study: spec.Study{SchemaVersion: spec.SchemaVersion, Images: images}}
	for _, im := range images {
		l.Records = append(l.Records, im)
	}
	return l
}

var testClass = &Classification{
	Headline:    []string{"SPEC-01", "FS-04"},
	Exploratory: []string{"FS-06", "EXEC-01"},
	Excluded:    []string{"SUP-02"},
}

func TestPerCheckCountsAndWilson(t *testing.T) {
	var images []*spec.SuiteResult
	// 10 completed images: SPEC-01 fails on 3, passes on 5, unverified on 2.
	for i := 0; i < 10; i++ {
		var res spec.TestResult
		switch {
		case i < 3:
			res = r("SPEC-01", "Non-Root", spec.TierSpec, spec.OutcomeFail, "")
		case i < 8:
			res = r("SPEC-01", "Non-Root", spec.TierSpec, spec.OutcomePass, "")
		default:
			res = r("SPEC-01", "Non-Root", spec.TierSpec, spec.OutcomeUnverified, spec.ReasonEvidenceIncomplete)
		}
		images = append(images, img("img"+string(rune('a'+i)), spec.StatusCompleted, res))
	}
	a := Analyze(load(t, images...), Options{Classification: testClass})
	c := a.Check("SPEC-01")
	if c == nil {
		t.Fatal("SPEC-01 missing")
	}
	if c.Pass != 5 || c.Fail != 3 || c.Unverified != 2 || c.Verified != 8 {
		t.Errorf("counts = pass %d fail %d unverified %d verified %d", c.Pass, c.Fail, c.Unverified, c.Verified)
	}
	if c.UnverifiedByReason["EVIDENCE_INCOMPLETE"] != 2 {
		t.Errorf("unverified by reason = %v", c.UnverifiedByReason)
	}
	if c.Prevalence == nil || math.Abs(c.Prevalence.Estimate-3.0/8.0) > 1e-12 {
		t.Fatalf("prevalence = %+v, want 3/8 (UNVERIFIED must not enter the denominator)", c.Prevalence)
	}
	// Wilson 95 percent interval for 3/8.
	if math.Abs(c.Prevalence.Lo-0.1368) > 5e-4 || math.Abs(c.Prevalence.Hi-0.6943) > 5e-4 {
		t.Errorf("Wilson interval = [%.4f, %.4f], want about [0.1368, 0.6943]", c.Prevalence.Lo, c.Prevalence.Hi)
	}
	if c.Class != ClassHeadline || !c.Listed {
		t.Errorf("class = %s listed = %v", c.Class, c.Listed)
	}
}

func TestOnlyCompletedImagesEnterStatistics(t *testing.T) {
	a := Analyze(load(t,
		img("a", spec.StatusCompleted, r("FS-04", "SUID", spec.TierFilesystem, spec.OutcomeFail, "")),
		img("b", spec.StatusRateLimited, r("FS-04", "SUID", spec.TierFilesystem, spec.OutcomeFail, "")),
		img("c", spec.StatusIndexLimit),
	), Options{Classification: testClass})
	c := a.Check("FS-04")
	if c.Fail != 1 || c.Verified != 1 {
		t.Errorf("FS-04 counts include non-completed images: %+v", c)
	}
	if a.Flow.Attempted != 3 || a.Flow.Completed != 1 || a.Flow.NotCompleted != 2 {
		t.Errorf("flow = %+v", a.Flow)
	}
	if a.Flow.ByStatus[spec.StatusRateLimited] != 1 || a.Flow.ByStatus[spec.StatusIndexLimit] != 1 {
		t.Errorf("by status = %v", a.Flow.ByStatus)
	}
}

func TestEmptyDenominatorHasNoPrevalence(t *testing.T) {
	a := Analyze(load(t,
		img("a", spec.StatusCompleted, r("EXEC-01", "RO", spec.TierContract, spec.OutcomeUnverified, spec.ReasonBaselineFailed)),
		img("b", spec.StatusCompleted, r("EXEC-01", "RO", spec.TierContract, spec.OutcomeUnverified, spec.ReasonNotObservable)),
	), Options{Classification: testClass})
	c := a.Check("EXEC-01")
	if c.Verified != 0 || c.Prevalence != nil {
		t.Errorf("verified = %d prevalence = %+v, want 0 and nil", c.Verified, c.Prevalence)
	}
	if c.UnverifiedByReason["BASELINE_FAILED"] != 1 || c.UnverifiedByReason["NOT_OBSERVABLE"] != 1 {
		t.Errorf("reasons = %v", c.UnverifiedByReason)
	}
}

func TestExcludedCheckHasNoPrevalenceAndNoImageContribution(t *testing.T) {
	a := Analyze(load(t,
		img("a", spec.StatusCompleted,
			r("SUP-02", "Signature", spec.TierSupplyChain, spec.OutcomeFail, ""),
			r("FS-04", "SUID", spec.TierFilesystem, spec.OutcomePass, "")),
	), Options{Classification: testClass})
	c := a.Check("SUP-02")
	if c.Class != ClassExcluded || c.Prevalence != nil {
		t.Errorf("excluded check must carry no prevalence: %+v", c)
	}
	if a.Images[0].All.Verified != 1 || a.Images[0].All.Fail != 0 {
		t.Errorf("excluded check leaked into per-image counts: %+v", a.Images[0])
	}
}

func TestFixtureOnlyFindings(t *testing.T) {
	fixtureOnly := r("FS-06", "Keys", spec.TierFilesystem, spec.OutcomePass, "")
	fixtureOnly.Evidence = &spec.Evidence{FixtureCandidates: []string{"/usr/share/x/testdata/key.pem"}}
	real := r("FS-06", "Keys", spec.TierFilesystem, spec.OutcomeFail, "")
	real.Evidence = &spec.Evidence{Paths: []string{"/etc/ssl/private/server.key"}, FixtureCandidates: []string{"/opt/tests/id_rsa"}}
	clean := r("FS-06", "Keys", spec.TierFilesystem, spec.OutcomePass, "")
	a := Analyze(load(t,
		img("a", spec.StatusCompleted, fixtureOnly),
		img("b", spec.StatusCompleted, real),
		img("c", spec.StatusCompleted, clean),
	), Options{Classification: testClass})
	c := a.Check("FS-06")
	if c.Fail != 1 || c.Pass != 2 || c.FixtureOnly != 1 || c.Verified != 3 {
		t.Errorf("FS-06 = %+v, want fail 1 pass 2 fixture-only 1 verified 3", c)
	}
}

func TestFailWithFixtureCandidatesOnlyWarns(t *testing.T) {
	bad := r("FS-07", "Harness", spec.TierFilesystem, spec.OutcomeFail, "")
	bad.Evidence = &spec.Evidence{FixtureCandidates: []string{"/x/testdata/y"}}
	a := Analyze(load(t, img("a", spec.StatusCompleted, bad)), Options{Classification: testClass})
	if !hasWarning(a, "fixture candidates only") {
		t.Errorf("expected contract violation warning, got %v", a.Warnings)
	}
}

func TestUnlistedRuleIsExploratoryWithWarning(t *testing.T) {
	a := Analyze(load(t, img("a", spec.StatusCompleted, r("NEW-99", "New", spec.TierSpec, spec.OutcomeFail, ""))),
		Options{Classification: testClass})
	c := a.Check("NEW-99")
	if c.Class != ClassExploratory || c.Listed {
		t.Errorf("unlisted rule must be exploratory and unlisted: %+v", c)
	}
	if !hasWarning(a, "NEW-99 is not listed") {
		t.Errorf("expected unlisted warning, got %v", a.Warnings)
	}
}

func TestMissingHeadlineCheckWarns(t *testing.T) {
	a := Analyze(load(t, img("a", spec.StatusCompleted, r("FS-04", "SUID", spec.TierFilesystem, spec.OutcomePass, ""))),
		Options{Classification: testClass})
	if !hasWarning(a, "headline check SPEC-01") {
		t.Errorf("expected missing headline warning, got %v", a.Warnings)
	}
}

func TestPerImageConfirmedFailuresAmongVerified(t *testing.T) {
	a := Analyze(load(t,
		img("a", spec.StatusCompleted,
			r("SPEC-01", "n", spec.TierSpec, spec.OutcomeFail, ""),
			r("FS-04", "n", spec.TierFilesystem, spec.OutcomeFail, ""),
			r("FS-06", "n", spec.TierFilesystem, spec.OutcomePass, ""),
			r("EXEC-01", "n", spec.TierContract, spec.OutcomeUnverified, spec.ReasonBaselineFailed)),
		img("b", spec.StatusCompleted,
			r("SPEC-01", "n", spec.TierSpec, spec.OutcomePass, ""),
			r("FS-04", "n", spec.TierFilesystem, spec.OutcomeUnverified, spec.ReasonEvidenceIncomplete)),
		img("c", spec.StatusCompleted,
			r("EXEC-01", "n", spec.TierContract, spec.OutcomeUnverified, spec.ReasonNotObservable)),
	), Options{Classification: testClass})
	byName := map[string]ImageStat{}
	for _, im := range a.Images {
		byName[im.Ref] = im
	}
	if got := byName["a"].Headline; got.Fail != 2 || got.Verified != 2 {
		t.Errorf("image a headline = %+v, want 2 of 2", got)
	}
	if got := byName["a"].All; got.Fail != 2 || got.Verified != 3 {
		t.Errorf("image a all = %+v, want 2 of 3 (EXEC-01 unverified)", got)
	}
	if got := byName["b"].Headline; got.Fail != 0 || got.Verified != 1 {
		t.Errorf("image b headline = %+v, want 0 of 1", got)
	}
	if got := byName["c"].All; got.Verified != 0 {
		t.Errorf("image c should have no verified checks: %+v", got)
	}
	d := a.Distribution["headline"]
	if d.NoConfirmedFailure != 1 || d.NoVerifiedCheck != 1 {
		t.Errorf("distribution = %+v", d)
	}
	if d.ConfirmedFailures.N != 3 || !d.ConfirmedFailures.SDOK {
		t.Errorf("confirmed failure summary = %+v", d.ConfirmedFailures)
	}
	// Values are 2, 0, 0: sample SD with n-1 is sqrt(((4/3)^2 + 2*(2/3)^2)/2).
	want := math.Sqrt((16.0/9.0 + 2*4.0/9.0) / 2)
	if math.Abs(d.ConfirmedFailures.SD-want) > 1e-12 {
		t.Errorf("SD = %v, want sample SD %v", d.ConfirmedFailures.SD, want)
	}
}

func TestStrataCountsAndOrder(t *testing.T) {
	arch := Archetypes{
		"nginx":    {Archetype: "web-ingress", BaseFamily: "debian"},
		"alpine":   {Archetype: "base-os", BaseFamily: "alpine"},
		"postgres": {Archetype: "database", BaseFamily: "debian"},
	}
	a := Analyze(load(t,
		img("index.docker.io/library/postgres@sha256:aa", spec.StatusCompleted, r("FS-04", "n", spec.TierFilesystem, spec.OutcomeFail, "")),
		img("index.docker.io/library/nginx@sha256:bb", spec.StatusCompleted, r("FS-04", "n", spec.TierFilesystem, spec.OutcomeFail, "")),
		img("index.docker.io/library/alpine@sha256:cc", spec.StatusCompleted, r("FS-04", "n", spec.TierFilesystem, spec.OutcomePass, "")),
		img("index.docker.io/library/mystery@sha256:dd", spec.StatusCompleted, r("FS-04", "n", spec.TierFilesystem, spec.OutcomePass, "")),
	), Options{Classification: testClass, Archetypes: arch})

	var names []string
	for _, s := range a.Strata {
		names = append(names, s.Kind+":"+s.Name)
	}
	want := []string{
		"archetype:base-os", "archetype:database", "archetype:web-ingress", "archetype:unmapped",
		"base_family:alpine", "base_family:debian", "base_family:unmapped",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("strata order = %v, want %v", names, want)
	}
	for _, s := range a.Strata {
		if s.Kind == "base_family" && s.Name == "debian" {
			if s.Images != 2 || s.PerCheck["FS-04"] != (CountPair{Fail: 2, Verified: 2}) {
				t.Errorf("debian stratum = %+v", s)
			}
		}
	}
	if !hasWarning(a, "no entry in archetypes.json") {
		t.Errorf("expected unmapped archetype warning, got %v", a.Warnings)
	}
}

func TestInfrastructureShareWarning(t *testing.T) {
	var images []*spec.SuiteResult
	for i := 0; i < 18; i++ {
		images = append(images, img(string(rune('a'+i)), spec.StatusCompleted))
	}
	images = append(images, img("t", spec.StatusTimeout), img("u", spec.StatusRateLimited))
	a := Analyze(load(t, images...), Options{})
	if a.Flow.Infrastructure != 2 {
		t.Errorf("infrastructure = %d", a.Flow.Infrastructure)
	}
	if !hasWarning(a, "infrastructure status") {
		t.Errorf("10%% infrastructure share must warn: %v", a.Warnings)
	}
	// INDEX_LIMIT is a tool limit, not infrastructure.
	b := Analyze(load(t, img("a", spec.StatusCompleted), img("i", spec.StatusIndexLimit)), Options{})
	if b.Flow.Infrastructure != 0 || hasWarning(b, "infrastructure status") {
		t.Errorf("INDEX_LIMIT must not count as infrastructure: %+v", b.Flow)
	}
}

func TestIndexLimitSizesRecorded(t *testing.T) {
	big := img("big@sha256:1", spec.StatusIndexLimit)
	big.Reason = spec.ReasonIndexTooLarge
	big.Resources.UncompressedBytes = 5 << 30
	big.Resources.LayerCount = 12
	a := Analyze(load(t, big, img("ok", spec.StatusCompleted)), Options{})
	if len(a.Flow.IndexLimit) != 1 || a.Flow.IndexLimit[0].UncompressedBytes != 5<<30 || a.Flow.IndexLimit[0].Name != "big" {
		t.Errorf("index limit images = %+v", a.Flow.IndexLimit)
	}
	if a.Flow.ReasonsBy[spec.StatusIndexLimit]["INDEX_TOO_LARGE"] != 1 {
		t.Errorf("reasons = %v", a.Flow.ReasonsBy)
	}
}

func TestRepeatedResultsCountedOnce(t *testing.T) {
	a := Analyze(load(t, img("a", spec.StatusCompleted,
		r("FS-04", "n", spec.TierFilesystem, spec.OutcomePass, ""),
		r("FS-04", "n", spec.TierFilesystem, spec.OutcomeFail, ""))), Options{Classification: testClass})
	c := a.Check("FS-04")
	if c.Pass != 1 || c.Fail != 0 {
		t.Errorf("repeated result must be counted once (first wins): %+v", c)
	}
	if !hasWarning(a, "more than one result for FS-04") {
		t.Errorf("expected repeated-result warning, got %v", a.Warnings)
	}
}

func TestStandardLabelFromMetadata(t *testing.T) {
	cases := []struct {
		meta *spec.RuleMeta
		want string
	}{
		{nil, "unmapped"},
		{&spec.RuleMeta{}, "unmapped"},
		{&spec.RuleMeta{Standard: "CIS Docker Benchmark", StandardVersion: "1.6.0", ControlID: "4.1", Mapping: spec.MappingExact},
			"CIS Docker Benchmark v1.6.0 4.1 (exact)"},
		{&spec.RuleMeta{Standard: "NIST SP 800-190", ControlID: "4.4.2", Mapping: spec.MappingApproximate},
			"NIST SP 800-190 4.4.2 (approximate)"},
		{&spec.RuleMeta{Mapping: spec.MappingCustom}, "ConUnit (custom)"},
	}
	for _, c := range cases {
		if got := StandardLabel(c.meta); got != c.want {
			t.Errorf("StandardLabel(%+v) = %q, want %q", c.meta, got, c.want)
		}
	}
}

func TestNaturalLess(t *testing.T) {
	ids := []string{"SPEC-10", "SPEC-02", "FS-04", "CIS-4.10", "CIS-4.6", "EXEC-01", "SPEC-01", "FS-1"}
	sort.Slice(ids, func(i, j int) bool { return NaturalLess(ids[i], ids[j]) })
	want := "CIS-4.6,CIS-4.10,EXEC-01,FS-1,FS-04,SPEC-01,SPEC-02,SPEC-10"
	if got := strings.Join(ids, ","); got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
}

func TestLoadClassification(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok, err := LoadClassification(write("ok.json", `{"headline":["A-1"],"exploratory":["B-1"],"excluded":["C-1"]}`))
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if c, listed := ok.Lookup("C-1"); c != ClassExcluded || !listed {
		t.Errorf("Lookup(C-1) = %s %v", c, listed)
	}
	if _, listed := ok.Lookup("Z-9"); listed {
		t.Error("unknown ID must not be listed")
	}
	if _, err := LoadClassification(write("dup.json", `{"headline":["A-1"],"exploratory":["A-1"],"excluded":[]}`)); err == nil {
		t.Error("ID in two classes must be rejected")
	}
	if _, err := LoadClassification(write("typo.json", `{"headlines":["A-1"]}`)); err == nil {
		t.Error("unknown key must be rejected")
	}
	if _, err := LoadClassification(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file must be an error")
	}
}

func hasWarning(a *Analysis, substr string) bool {
	for _, w := range a.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
