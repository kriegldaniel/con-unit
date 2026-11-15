package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/dataaudit"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// update rewrites the golden files: go test ./tools -run Golden -update
var update = flag.Bool("update", false, "rewrite golden files in tools/testdata/export_latex/golden")

const goldenRoot = "testdata/export_latex/golden"

// ---------------------------------------------------------------------------
// Synthetic study

var testImages = []string{"alpine", "nginx", "postgres", "python", "redis", "traefik", "mystery", "busybox"}

func ref(name string) string {
	return fmt.Sprintf("index.docker.io/library/%s@sha256:%064x", name, len(name)*7919)
}

type rule struct {
	id, name string
	tier     spec.Tier
	meta     *spec.RuleMeta
	// outcomes has one letter per completed image: P pass, F fail,
	// f pass with fixture-only candidates, x fail with non-fixture paths,
	// e/b/n/t UNVERIFIED with EVIDENCE_INCOMPLETE, BASELINE_FAILED,
	// NOT_OBSERVABLE, NO_TRUST_POLICY, and - for absent.
	outcomes string
}

func cis(control string, mapping spec.MappingType) *spec.RuleMeta {
	return &spec.RuleMeta{Standard: "CIS Docker Benchmark", StandardVersion: "1.6.0", ControlID: control, Mapping: mapping, Scope: spec.ScopeImageContent}
}

var testRules = []rule{
	{"SPEC-01", "Non-Root Execution Identity", spec.TierSpec, cis("4.1", spec.MappingExact), "FFPFPFeF"},
	{"CIS-4.6", "Image HEALTHCHECK", spec.TierSpec, cis("4.6", spec.MappingExact), "FFFFFFPF"},
	{"SPEC-05", "Non-Privileged Declared Image Ports", spec.TierSpec, &spec.RuleMeta{Standard: "CIS Docker Benchmark", StandardVersion: "1.6.0", ControlID: "5.7", Mapping: spec.MappingApproximate}, "PFPPPPPP"},
	{"SPEC-06", "Dangling Debug Port Exclusion", spec.TierSpec, nil, "PPPPPPPP"},
	{"SPEC-07", "Instruction Hygiene", spec.TierSpec, cis("4.9", spec.MappingApproximate), "ePPPPPPP"},
	{"FS-04", "SUID/SGID Privilege Escalation Vectors", spec.TierFilesystem, cis("4.8", spec.MappingExact), "PFFFFPPP"},
	{"FS-05", "World-Writable File Elimination", spec.TierFilesystem, &spec.RuleMeta{Mapping: spec.MappingCustom}, "PPPFPPPP"},
	{"FS-06", "Hardcoded Private Key Elimination", spec.TierFilesystem, cis("4.10", spec.MappingApproximate), "PfPxPPPf"},
	{"FS-07", "Development and Test Harness Leakage", spec.TierFilesystem, cis("4.3", spec.MappingApproximate), "PfPPPPPP"},
	{"FS-08", "Account Security", spec.TierFilesystem, cis("4.10", spec.MappingApproximate), "PPPPPPeP"},
	{"EXEC-01", "Read-Only Root Filesystem Conformance", spec.TierContract, cis("5.12", spec.MappingApproximate), "bFPnPbbn"},
	{"EXEC-02", "Dropped Linux Capabilities Conformance", spec.TierContract, cis("5.3", spec.MappingApproximate), "PPFPPFbP"},
	{"SUP-02", "Cryptographic Image Provenance and Signature", spec.TierSupplyChain, cis("4.5", spec.MappingExact), "tttttttt"},
	{"XTRA-01", "Unclassified Future Check", spec.TierSpec, nil, "-F------"},
}

func result(r rule, code byte) (spec.TestResult, bool) {
	res := spec.TestResult{TestID: r.id, TestName: r.name, Tier: r.tier, Rule: r.meta}
	switch code {
	case '-':
		return res, false
	case 'P':
		res.Outcome, res.Passed = spec.OutcomePass, true
	case 'F':
		res.Outcome = spec.OutcomeFail
	case 'f':
		res.Outcome, res.Passed = spec.OutcomePass, true
		res.Evidence = &spec.Evidence{FixtureCandidates: []string{"/usr/share/doc/x/testdata/key.pem"}}
	case 'x':
		res.Outcome = spec.OutcomeFail
		res.Evidence = &spec.Evidence{Paths: []string{"/etc/ssl/private/server.key"}, FixtureCandidates: []string{"/opt/app/tests/id_rsa"}}
	case 'e':
		res.Outcome, res.Reason = spec.OutcomeUnverified, spec.ReasonEvidenceIncomplete
	case 'b':
		res.Outcome, res.Reason = spec.OutcomeUnverified, spec.ReasonBaselineFailed
	case 'n':
		res.Outcome, res.Reason = spec.OutcomeUnverified, spec.ReasonNotObservable
	case 't':
		res.Outcome, res.Reason = spec.OutcomeUnverified, spec.ReasonNoTrustPolicy
	}
	return res, true
}

func synthStudy() spec.Study {
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	rootless := false
	st := spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run: spec.RunMetadata{
			ConUnitVersion: "0.9.0-test", Commit: "0123456789abcdef0123456789abcdef01234567",
			Platform: "linux/amd64", ImageSource: "local", PackID: "PACK-CONUNIT-HARDENING",
			ProbeWindowMs: 3000, EngineName: "podman", EngineVersion: "5.0.2", Rootless: &rootless,
			CgroupVersion: "v2", StorageDriver: "overlay", OCIRuntime: "crun 1.14",
			RegistryRemap: "docker.io/library -> public.ecr.aws/docker/library",
			HostOS:        "Ubuntu 24.04.1 LTS", LinuxKernel: "6.8.0-1017-aws",
			CPUModel: "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz & friends", VCPUs: 8, MemoryBytes: 16 << 30,
			Virtualization: "aws-nitro-kvm", ExecutionMode: "virtualized-cloud", CloudProvider: "aws",
			InstanceType: "c6i.2xlarge", AMIID: "ami-0123456789abcdef0", Region: "eu-central-1",
			DatasetSHA256: strings.Repeat("ab", 32),
			StartedAt:     t0, FinishedAt: t0.Add(40 * time.Minute),
		},
	}
	for i, name := range testImages {
		img := &spec.SuiteResult{
			ImageName: ref(name), RequestedRef: ref(name), ImageDigest: fmt.Sprintf("sha256:%064x", i+1),
			Platform: "linux/amd64", Status: spec.StatusCompleted, ImageSource: spec.SourceLocalStore,
			Timestamp: t0, Duration: time.Duration(i+2) * 1500 * time.Millisecond,
			Phases: spec.PhaseBreakdown{
				PullDuration: time.Duration(120*(i+1)) * time.Millisecond, InspectDuration: 30 * time.Millisecond,
				ResolveDuration: 45 * time.Millisecond, StreamDuration: time.Duration(400+100*i) * time.Millisecond,
				Tier1Duration: 500 * time.Microsecond, Tier2Duration: time.Duration(12*(i+1)) * time.Millisecond,
				Tier3Duration: 3*time.Second + time.Duration(50*i)*time.Millisecond, Tier4Duration: 200 * time.Millisecond,
				ProbeWindow: 3 * time.Second,
			},
			Resources: spec.ResourceTelemetry{
				LayerCount: i + 3, UncompressedBytes: int64(i+1) * 50 << 20, CompressedBytes: int64(i+1) * 20 << 20,
				LiveHeapMB: 20 + float64(i)*2.5, AllocMB: 60 + float64(i)*10, TotalAllocMB: 300 + float64(i)*40,
				PeakRSSMB: 150 + float64(i)*10,
			},
		}
		for _, r := range testRules {
			if res, ok := result(r, r.outcomes[i]); ok {
				img.Results = append(img.Results, res)
			}
		}
		img.Total = len(img.Results)
		st.Images = append(st.Images, img)
	}
	st.Images = append(st.Images,
		&spec.SuiteResult{ImageName: ref("big"), RequestedRef: ref("big"), Status: spec.StatusIndexLimit, Reason: spec.ReasonIndexTooLarge,
			Resources: spec.ResourceTelemetry{LayerCount: 14, UncompressedBytes: 6 << 30, CompressedBytes: 2 << 30}},
		&spec.SuiteResult{ImageName: ref("slow"), RequestedRef: ref("slow"), Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled},
		&spec.SuiteResult{ImageName: ref("gone"), RequestedRef: ref("gone"), Status: spec.StatusUnavailable, Reason: spec.ReasonManifestNotFound},
		&spec.SuiteResult{ImageName: ref("hung"), RequestedRef: ref("hung"), Status: spec.StatusTimeout, Reason: spec.ReasonDeadlineExceeded},
	)
	return st
}

func synthAudit() dataaudit.Audit {
	declared := 16
	return dataaudit.Audit{
		SchemaVersion: dataaudit.SchemaVersion, Tool: "pin_dataset", ToolVersion: "test", GeneratedAt: "2026-11-14T09:00:00Z", Mode: "registry",
		Frame:         dataaudit.Frame{Repository: "docker-library/official-images", Commit: "abc1234def56789", Date: "2026-11-13"},
		InclusionRule: "test rule", Platform: "linux/amd64",
		Input:   dataaudit.ListInfo{Path: "in.txt", SHA256: strings.Repeat("11", 32), Entries: 16, DeclaredN: &declared},
		Outputs: dataaudit.Outputs{PinnedTxt: dataaudit.ListInfo{Path: "pinned.txt", SHA256: strings.Repeat("ab", 32), Entries: 14}},
		Counts:  dataaudit.Counts{Candidates: 16, Pinned: 14, Excluded: 2},
		ExclusionLog: []dataaudit.Exclusion{
			{OriginalTag: "chronograf:1", Status: "EXCLUDED_SINGLE_ARCH", Reason: "amd64 only"},
			{OriginalTag: "kapacitor:1", Status: "EXCLUDED_SINGLE_ARCH", Reason: "amd64 only"},
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers

type testEnv struct {
	dir                         string
	study, headline, archetypes string
	audit                       string
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T, study any) *testEnv {
	t.Helper()
	dir := t.TempDir()
	e := &testEnv{
		dir:        dir,
		study:      filepath.Join(dir, "empirical_study.json"),
		headline:   filepath.Join("testdata", "export_latex", "headline_checks.json"),
		archetypes: filepath.Join("testdata", "export_latex", "archetypes.json"),
		audit:      filepath.Join(dir, "audit.json"),
	}
	writeJSON(t, e.study, study)
	writeJSON(t, e.audit, synthAudit())
	return e
}

func (e *testEnv) args(extra ...string) []string {
	args := []string{"-headline", e.headline, "-archetypes", e.archetypes}
	args = append(args, extra...)
	return append(args, e.study)
}

func export(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func assertGolden(t *testing.T, scenario, name, got string) {
	t.Helper()
	path := filepath.Join(goldenRoot, scenario, name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden %s\n--- got ---\n%s\n--- want ---\n%s", name, path, got, string(want))
	}
}

func goldenAll(t *testing.T, scenario, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		assertGolden(t, scenario, n, read(t, filepath.Join(dir, n)))
	}
}

// ---------------------------------------------------------------------------
// Golden tests

func TestGoldenFullStudy(t *testing.T) {
	e := newEnv(t, synthStudy())
	code, _, stderr := export(t, e.args("-audit", e.audit)...)
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	goldenAll(t, "full", e.dir, append(append([]string{}, texOutputs...), fileStatsJSON)...)
	// The two expected warnings and no others of concern.
	if !strings.Contains(stderr, "XTRA-01 is not listed") {
		t.Errorf("expected unclassified rule warning, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "mystery") && !strings.Contains(stderr, "archetypes.json") {
		t.Errorf("expected unmapped archetype warning, got:\n%s", stderr)
	}
}

func TestGoldenLegacyArray(t *testing.T) {
	st := synthStudy()
	legacy := make([]spec.SuiteResult, 0, len(st.Images))
	for _, im := range st.Images {
		c := *im
		c.Status = "" // the legacy format had no status for completed images
		if im.Status != spec.StatusCompleted {
			c.Status = im.Status
		}
		// Legacy records also lack the explicit outcome for some results.
		legacy = append(legacy, c)
	}
	e := newEnv(t, legacy)
	code, _, stderr := export(t, e.args()...)
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "legacy array format") {
		t.Errorf("expected legacy warning, got:\n%s", stderr)
	}
	goldenAll(t, "legacy", e.dir, fileMacros, filePrevalence, fileAttrition)
	macros := read(t, filepath.Join(e.dir, fileMacros))
	for _, want := range []string{
		`\newcommand{\ConUnitEnvInstanceType}{unknown}`,
		`\newcommand{\ConUnitEnvEngine}{unknown}`,
		`\newcommand{\ConUnitEnvDate}{unknown}`,
		`\newcommand{\ConUnitNCompleted}{8}`,
		`\newcommand{\ConUnitNCandidates}{n/a}`,
	} {
		if !strings.Contains(macros, want) {
			t.Errorf("legacy macros missing %s", want)
		}
	}
}

func TestGoldenNoCompletedImages(t *testing.T) {
	st := spec.Study{SchemaVersion: spec.SchemaVersion, Run: synthStudy().Run, Images: []*spec.SuiteResult{
		{ImageName: ref("a"), RequestedRef: ref("a"), Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled},
		{ImageName: ref("b"), RequestedRef: ref("b"), Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled},
		{ImageName: ref("c"), RequestedRef: ref("c"), Status: spec.StatusTimeout, Reason: spec.ReasonDeadlineExceeded},
	}}
	e := newEnv(t, st)
	code, _, stderr := export(t, e.args("-audit", e.audit)...)
	if code != spec.ExitIncomplete {
		t.Errorf("exit = %d, want %d (no completed images)", code, spec.ExitIncomplete)
	}
	if !strings.Contains(stderr, "no COMPLETED images") {
		t.Errorf("expected explicit error, got:\n%s", stderr)
	}
	goldenAll(t, "no_completed", e.dir, fileMacros, filePrevalence, fileAttrition, filePhases, figPrevalence)
	if strings.Contains(read(t, filepath.Join(e.dir, fileMacros)), "NaN") {
		t.Error("macros contain NaN")
	}
}

// ---------------------------------------------------------------------------
// Behavior tests

func TestExcludedChecksAppearInNoPrevalenceOutput(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, name := range []string{filePrevalence, fileExploratory, fileStrata, figPrevalence} {
		if strings.Contains(read(t, filepath.Join(e.dir, name)), "SUP-02") {
			t.Errorf("%s must not mention the excluded check SUP-02", name)
		}
	}
	macros := read(t, filepath.Join(e.dir, fileMacros))
	if strings.Contains(macros, `\ConUnitPrevSUPZeroTwo`) || strings.Contains(macros, `\ConUnitPrevLoSUPZeroTwo`) {
		t.Error("macros must not define a prevalence for the excluded check")
	}
	if !strings.Contains(macros, `\newcommand{\ConUnitUnverifiedSUPZeroTwo}{8}`) {
		t.Error("excluded check keeps its UNVERIFIED count macro")
	}
	unv := read(t, filepath.Join(e.dir, fileUnverified))
	if !strings.Contains(unv, `\texttt{SUP-02}`) || !strings.Contains(unv, `\texttt{NO\_TRUST\_POLICY} (8)`) {
		t.Errorf("unverified table must list SUP-02 with its reason:\n%s", unv)
	}
}

func TestHeadlineAndExploratorySplit(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	head := read(t, filepath.Join(e.dir, filePrevalence))
	expl := read(t, filepath.Join(e.dir, fileExploratory))
	for _, id := range []string{"SPEC-01", "CIS-4.6", "FS-04", "FS-05", "FS-08", "SPEC-05", "SPEC-06"} {
		if !strings.Contains(head, `\texttt{`+id+`}`) {
			t.Errorf("headline table lacks %s", id)
		}
		if strings.Contains(expl, `\texttt{`+id+`}`) {
			t.Errorf("exploratory table must not contain headline check %s", id)
		}
	}
	for _, id := range []string{"FS-06", "FS-07", "SPEC-07", "EXEC-01", "EXEC-02", "XTRA-01"} {
		if strings.Contains(head, `\texttt{`+id+`}`) {
			t.Errorf("headline table must not contain exploratory check %s", id)
		}
		if !strings.Contains(expl, `\texttt{`+id+`}`) {
			t.Errorf("exploratory table lacks %s", id)
		}
	}
}

func TestPrevalenceNumbers(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	macros := read(t, filepath.Join(e.dir, fileMacros))
	// SPEC-01: 5 FAIL, 2 PASS, 1 UNVERIFIED: prevalence 5/7, Wilson [35.9, 91.8].
	for _, want := range []string{
		`\newcommand{\ConUnitFailSPECZeroOne}{5}`,
		`\newcommand{\ConUnitVerifiedSPECZeroOne}{7}`,
		`\newcommand{\ConUnitUnverifiedSPECZeroOne}{1}`,
		`\newcommand{\ConUnitPrevSPECZeroOne}{71.4\%}`,
		`\newcommand{\ConUnitPrevLoSPECZeroOne}{35.9\%}`,
		`\newcommand{\ConUnitPrevHiSPECZeroOne}{91.8\%}`,
		// CIS-4.6 naming rule: dots removed, digits spelled out.
		`\newcommand{\ConUnitFailCISFourSix}{7}`,
		// EXEC-01: only 3 images verified, 5 UNVERIFIED stay out of the denominator.
		`\newcommand{\ConUnitVerifiedEXECZeroOne}{3}`,
		`\newcommand{\ConUnitUnverifiedEXECZeroOne}{5}`,
		`\newcommand{\ConUnitPrevEXECZeroOne}{33.3\%}`,
		// FS-06: one confirmed finding plus two fixture-only images.
		`\newcommand{\ConUnitFailFSZeroSix}{1}`,
		`\newcommand{\ConUnitFixtureOnlyFSZeroSix}{2}`,
		// Flow.
		`\newcommand{\ConUnitNCandidates}{16}`,
		`\newcommand{\ConUnitNPinned}{14}`,
		`\newcommand{\ConUnitNAttempted}{12}`,
		`\newcommand{\ConUnitNCompleted}{8}`,
		`\newcommand{\ConUnitNAttrition}{4}`,
		`\newcommand{\ConUnitAttritionRateLimited}{1}`,
		`\newcommand{\ConUnitAttritionIndexLimit}{1}`,
		`\newcommand{\ConUnitAttritionTimeout}{1}`,
		`\newcommand{\ConUnitAttritionUnavailable}{1}`,
		`\newcommand{\ConUnitAttritionExcluded}{0}`,
		`\newcommand{\ConUnitInfraAttrition}{3}`,
		// Batch ceiling over all records.
		`\newcommand{\ConUnitBatchPeakRSS}{220.0}`,
	} {
		if !strings.Contains(macros, want) {
			t.Errorf("macros missing %s", want)
		}
	}
	// A check that never verified has no prevalence and no zero division.
	st := synthStudy()
	for _, im := range st.Images {
		for i := range im.Results {
			if im.Results[i].TestID == "FS-05" {
				im.Results[i].Outcome, im.Results[i].Reason, im.Results[i].Passed = spec.OutcomeUnverified, spec.ReasonEvidenceIncomplete, false
			}
		}
	}
	e2 := newEnv(t, st)
	if code, _, stderr := export(t, e2.args()...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	m2 := read(t, filepath.Join(e2.dir, fileMacros))
	for _, want := range []string{
		`\newcommand{\ConUnitPrevFSZeroFive}{n/a}`,
		`\newcommand{\ConUnitVerifiedFSZeroFive}{0}`,
		`\newcommand{\ConUnitUnverifiedFSZeroFive}{8}`,
	} {
		if !strings.Contains(m2, want) {
			t.Errorf("empty-denominator macros missing %s", want)
		}
	}
	if !strings.Contains(read(t, filepath.Join(e2.dir, filePrevalence)), `0/0 & n/a`) {
		t.Error("empty-denominator row must show 0/0 and n/a")
	}
}

func TestNoPassRateStatistics(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	banned := regexp.MustCompile(`(?i)pass ?rate|fully ?compliant|compliance rate|MinPass|MaxPass|MeanPass|ZeroViolation|StrictlyCompliant`)
	for _, name := range append(append([]string{}, texOutputs...), fileStatsJSON) {
		if m := banned.FindString(read(t, filepath.Join(e.dir, name))); m != "" {
			t.Errorf("%s contains removed statistic %q", name, m)
		}
	}
	macros := read(t, filepath.Join(e.dir, fileMacros))
	// Per-image confirmed failures with the sample SD (n-1), and the number
	// of verified checks.
	for _, want := range []string{`\ConUnitImgFailSDHeadline}`, `\ConUnitImgVerifiedMedianHeadline}`, `\ConUnitImgNoFailHeadline}`} {
		if !strings.Contains(macros, want) {
			t.Errorf("macros missing per-image summary %s", want)
		}
	}
}

func TestStandardColumnComesFromRuleMetadata(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	head := read(t, filepath.Join(e.dir, filePrevalence))
	lines := map[string]string{}
	for _, l := range strings.Split(head, "\n") {
		if strings.HasPrefix(l, `\texttt{`) {
			id := strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(l, " & ", 2)[0], `\texttt{`), `}`)
			lines[id] = l
		}
	}
	// The compact body table shortens the standard to its first word, the
	// control and the mapping type, all taken from rule metadata.
	if !strings.Contains(lines["SPEC-01"], "& CIS 4.1 (exact) &") {
		t.Errorf("SPEC-01 compact standard column wrong: %s", lines["SPEC-01"])
	}
	if !strings.Contains(lines["SPEC-05"], "& CIS 5.7 (approximate) &") {
		t.Errorf("SPEC-05 compact standard column wrong: %s", lines["SPEC-05"])
	}
	// The full exploratory table keeps standard, version, control and mapping.
	expl := read(t, filepath.Join(e.dir, fileExploratory))
	if !strings.Contains(expl, "CIS Docker Benchmark v1.6.0 4.3 (approximate)") {
		t.Errorf("exploratory table lacks the full standard label:\n%s", expl)
	}
	if !strings.Contains(lines["SPEC-06"], "& unmapped &") {
		t.Errorf("rule without metadata must print unmapped: %s", lines["SPEC-06"])
	}
	if !strings.Contains(lines["FS-05"], "ConUnit (custom)") {
		t.Errorf("custom mapping without a standard must say ConUnit (custom): %s", lines["FS-05"])
	}
	// The exporter source must not hard-code standards.
	src := read(t, "export_latex.go")
	for _, banned := range []string{"CIS Docker v1.6.0", "NIST SP 800-190", "NSA/CISA"} {
		if strings.Contains(src, banned) {
			t.Errorf("export_latex.go hard-codes %q; the standard must come from rule metadata", banned)
		}
	}
}

func TestEnvironmentMacrosAreEscaped(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	macros := read(t, filepath.Join(e.dir, fileMacros))
	for _, want := range []string{
		`\newcommand{\ConUnitEnvCPU}{Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz \& friends}`,
		`\newcommand{\ConUnitEnvRegistryRemap}{docker.io/library -\textgreater{} public.ecr.aws/docker/library}`,
		`\newcommand{\ConUnitEnvInstanceType}{c6i.2xlarge}`,
		`\newcommand{\ConUnitEnvEngine}{podman 5.0.2}`,
		`\newcommand{\ConUnitEnvKernel}{6.8.0-1017-aws}`,
		`\newcommand{\ConUnitEnvVirt}{aws-nitro-kvm}`,
		`\newcommand{\ConUnitEnvAMI}{ami-0123456789abcdef0}`,
		`\newcommand{\ConUnitEnvCommit}{0123456789ab}`,
		`\newcommand{\ConUnitEnvOS}{Ubuntu 24.04.1 LTS}`,
		`\newcommand{\ConUnitEnvDate}{2026-11-14}`,
		`\newcommand{\ConUnitEnvProbeWindow}{3 s}`,
		`\newcommand{\ConUnitEnvMemoryGiB}{16.0}`,
	} {
		if !strings.Contains(macros, want) {
			t.Errorf("macros missing %s", want)
		}
	}
}

func TestMacroNamesAreLettersOnly(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	def := regexp.MustCompile(`(?m)^\\newcommand\{\\([^}]*)\}`)
	matches := def.FindAllStringSubmatch(read(t, filepath.Join(e.dir, fileMacros)), -1)
	if len(matches) < 100 {
		t.Fatalf("only %d macros found", len(matches))
	}
	seen := map[string]bool{}
	for _, m := range matches {
		if !regexp.MustCompile(`^[A-Za-z]+$`).MatchString(m[1]) {
			t.Errorf("macro name %q is not letters only", m[1])
		}
		if seen[m[1]] {
			t.Errorf("macro %s defined twice", m[1])
		}
		seen[m[1]] = true
	}
}

func TestIDKey(t *testing.T) {
	cases := map[string]string{
		"SPEC-01": "SPECZeroOne", "FS-04": "FSZeroFour", "CIS-4.6": "CISFourSix",
		"EXEC-02": "EXECZeroTwo", "CIS-5.10": "CISFiveOneZero", "SUP-02": "SUPZeroTwo",
	}
	for in, want := range cases {
		if got := idKey(in); got != want {
			t.Errorf("idKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeLatex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"test_name", `test\_name`},
		{"A & B", `A \& B`},
		{"100%", `100\%`},
		{"a#b$c{d}", `a\#b\$c\{d\}`},
		{`a\b`, `a\textbackslash{}b`},
		{"x~y^z", `x\textasciitilde{}y\textasciicircum{}z`},
		{"a->b", `a-\textgreater{}b`},
		{"a<b|c", `a\textless{}b\textbar{}c`},
	}
	for _, c := range cases {
		if got := escapeLatex(c.in); got != c.want {
			t.Errorf("escapeLatex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFixtureOnlyFindingsAreReportedSeparately(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	expl := read(t, filepath.Join(e.dir, fileExploratory))
	var fs06, fs07 string
	for _, l := range strings.Split(expl, "\n") {
		switch {
		case strings.HasPrefix(l, `\texttt{FS-06}`):
			fs06 = l
		case strings.HasPrefix(l, `\texttt{FS-07}`):
			fs07 = l
		}
	}
	// FS-06: 1 confirmed finding of 8 verified, 2 fixture-only images.
	if !strings.Contains(fs06, "& 1/8 &") || !strings.Contains(fs06, "& 2 & 0 \\\\") {
		t.Errorf("FS-06 row = %q", fs06)
	}
	// FS-07: only a fixture-only image: no failure, one fixture-only.
	if !strings.Contains(fs07, "& 0/8 &") || !strings.Contains(fs07, "& 1 & 0 \\\\") {
		t.Errorf("FS-07 row = %q", fs07)
	}
}

func TestAttritionTableShowsFlowAndEveryOccurringStatus(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	att := read(t, filepath.Join(e.dir, fileAttrition))
	for _, want := range []string{
		`Candidates & 16 & library commit abc1234def56, 2026-11-13`,
		`Excluded before pinning & 2 & \texttt{EXCLUDED\_SINGLE\_ARCH} (2)`,
		`Pinned by digest & 14 & linux/amd64`,
		`Attempted & 12 &`,
		`Pinned, not attempted & 2 &`,
		`Completed (analyzed) & 8 &`,
		`Not completed & 4 &`,
		`\texttt{TIMEOUT} (1)`,
		`\texttt{UNAVAILABLE} (1)`,
		`\texttt{RATE\_LIMITED} (1)`,
		// INDEX_LIMIT is a tool limit; its size is reported.
		`\texttt{INDEX\_LIMIT} (1; largest 6144.0 MB)`,
	} {
		if !strings.Contains(att, want) {
			t.Errorf("attrition table missing %q\n%s", want, att)
		}
	}
	// Statuses that did not occur are in the macros, not in the compact table.
	for _, absent := range []string{`EXECUTION\_ERROR`, `\texttt{EXCLUDED} (`} {
		if strings.Contains(att, absent) {
			t.Errorf("compact attrition table lists a status that did not occur: %s", absent)
		}
	}
	// The full detail stays in study_stats.json.
	statsJSON := read(t, filepath.Join(e.dir, fileStatsJSON))
	for _, want := range []string{`"index_limit_images"`, `"reasons_by_status"`, `"uncompressed_bytes": 6442450944`} {
		if !strings.Contains(statsJSON, want) {
			t.Errorf("study_stats.json lacks %s", want)
		}
	}
}

// bodyRows counts the data rows of a generated table: lines that end a row
// between the header rule and the bottom rule, not counting rules.
func bodyRows(tex string) int {
	lines := strings.Split(tex, "\n")
	start, end := -1, len(lines)
	for i, l := range lines {
		if start < 0 && strings.HasPrefix(l, `\midrule`) {
			start = i
		}
		if strings.HasPrefix(l, `\bottomrule`) {
			end = i
			break
		}
	}
	n := 0
	for _, l := range lines[start+1 : end] {
		if strings.HasSuffix(l, `\\`) {
			n++
		}
	}
	return n
}

// TestPaperContract pins the labels and the layout of the tables the paper
// includes by \ref and in its two-column, page-limited body.
func TestPaperContract(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	cases := []struct {
		file, label string
		body        bool // included in the two-column body: single column, resized
		maxRows     int
	}{
		{fileAttrition, "tab:attrition", true, 7},
		{filePrevalence, "tab:rq2_prevalence", true, 8},
		{filePhases, "tab:rq3_phases", true, 6},
		{fileExploratory, "tab:rq2_exploratory", false, 0},
		{fileStrata, "tab:strata", false, 0},
	}
	for _, c := range cases {
		tex := read(t, filepath.Join(e.dir, c.file))
		if !strings.Contains(tex, `\label{`+c.label+`}`) {
			t.Errorf("%s must carry label %s", c.file, c.label)
		}
		if !strings.Contains(tex, `\toprule`) || !strings.Contains(tex, `\bottomrule`) {
			t.Errorf("%s must use booktabs rules", c.file)
		}
		if !c.body {
			continue
		}
		if !strings.Contains(tex, "\\begin{table}[t]") || strings.Contains(tex, `table*`) {
			t.Errorf("%s is a body table and must be a single-column table environment", c.file)
		}
		if !strings.Contains(tex, `\resizebox{\columnwidth}{!}{`) {
			t.Errorf("%s must wrap its tabular in \\resizebox{\\columnwidth}{!}{...}", c.file)
		}
		if rows := bodyRows(tex); rows > c.maxRows {
			t.Errorf("%s has %d rows, the body budget is %d", c.file, rows, c.maxRows)
		}
	}
	// The obsolete labels must not appear anywhere.
	for _, name := range texOutputs {
		tex := read(t, filepath.Join(e.dir, name))
		for _, old := range []string{"tab:rq2_defect_prevalence", "tab:rq3_performance", "tab:defect_prevalence"} {
			if strings.Contains(tex, old) {
				t.Errorf("%s still contains obsolete label %s", name, old)
			}
		}
	}
}

func TestPhasesTableStatesWindowBound(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	ph := read(t, filepath.Join(e.dir, filePhases))
	for _, want := range []string{`bounded below by $W$`, `$W = $ 3 s`, `not a performance result`, `\geq W`} {
		if !strings.Contains(ph, want) {
			t.Errorf("phases table missing %q", want)
		}
	}
}

func TestPaperDirPlacesTexUnderResults(t *testing.T) {
	e := newEnv(t, synthStudy())
	paper := filepath.Join(e.dir, "paper")
	outDir := filepath.Join(e.dir, "out")
	code, _, stderr := export(t, e.args("-audit", e.audit, "-paper-dir", paper, "-out", outDir)...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, n := range texOutputs {
		if _, err := os.Stat(filepath.Join(paper, "results", n)); err != nil {
			t.Errorf("%s not written to <paper-dir>/results: %v", n, err)
		}
		if _, err := os.Stat(filepath.Join(outDir, n)); err == nil {
			t.Errorf("%s must not be written to -out when -paper-dir is given", n)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, fileStatsJSON)); err != nil {
		t.Errorf("study_stats.json must be written to -out: %v", err)
	}
}

func TestOutDefaultsToStudyDirectory(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, n := range texOutputs {
		if _, err := os.Stat(filepath.Join(e.dir, n)); err != nil {
			t.Errorf("%s missing next to the study JSON: %v", n, err)
		}
	}
}

func TestCheckModeDetectsStaleFiles(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if code, _, stderr := export(t, e.args("-audit", e.audit, "-check")...); code != 0 {
		t.Fatalf("fresh output must verify, exit %d: %s", code, stderr)
	}
	macros := filepath.Join(e.dir, fileMacros)
	b := read(t, macros)
	edited := strings.Replace(b, `\ConUnitNCompleted}{8}`, `\ConUnitNCompleted}{9}`, 1)
	if edited == b {
		t.Fatal("test setup: macro to edit not found")
	}
	if err := os.WriteFile(macros, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := export(t, e.args("-audit", e.audit, "-check")...)
	if code == 0 || !strings.Contains(stderr, "stale") {
		t.Errorf("hand-edited macros must fail the check, exit %d stderr:\n%s", code, stderr)
	}
	if err := os.Remove(filepath.Join(e.dir, fileStrata)); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = export(t, e.args("-audit", e.audit, "-check")...)
	if code == 0 || !strings.Contains(stderr, "missing") {
		t.Errorf("missing file must fail the check, exit %d stderr:\n%s", code, stderr)
	}
}

func TestListOutputs(t *testing.T) {
	code, out, _ := export(t, "-list-outputs")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := strings.Fields(out)
	want := append(append([]string{}, texOutputs...), fileStatsJSON)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("list-outputs = %v, want %v", got, want)
	}
	// No generated name may collide with the names owned by other tools.
	foreign := []string{"table_rq3_trials.tex", "macros_rq3.tex", "table_rq1_detection.tex", "rq3_telemetry.json", "rq1_results.json",
		"empirical_study.json", "EMPIRICAL_SUMMARY.md", "ATTRITION_REPORT.md", "journal.jsonl", "RQ3_PERFORMANCE.md"}
	for _, f := range foreign {
		for _, g := range got {
			if f == g {
				t.Errorf("exporter output %s collides with a name owned by another tool", g)
			}
		}
	}
}

func TestUsageAndInputErrors(t *testing.T) {
	if code, _, _ := export(t, "-nosuchflag"); code != spec.ExitUsage {
		t.Errorf("unknown flag exit = %d, want %d", code, spec.ExitUsage)
	}
	if code, _, _ := export(t, "a.json", "b.json"); code != spec.ExitUsage {
		t.Errorf("two study paths exit = %d, want %d", code, spec.ExitUsage)
	}
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, "-headline", e.headline, filepath.Join(e.dir, "missing.json")); code == 0 || !strings.Contains(stderr, "cannot load study") {
		t.Errorf("missing study must fail clearly, exit %d: %s", code, stderr)
	}
	if code, _, stderr := export(t, "-headline", filepath.Join(e.dir, "nope.json"), e.study); code == 0 || !strings.Contains(stderr, "classification") {
		t.Errorf("missing classification must fail, exit %d: %s", code, stderr)
	}
	if code, _, stderr := export(t, "-headline", e.headline, "-archetypes", filepath.Join(e.dir, "nope.json"), e.study); code == 0 || !strings.Contains(stderr, "archetypes") {
		t.Errorf("explicit missing archetypes must fail, exit %d: %s", code, stderr)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "bad.json"), []byte(`{"images":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := export(t, "-headline", e.headline, filepath.Join(e.dir, "bad.json")); code == 0 || !strings.Contains(stderr, "schema_version") {
		t.Errorf("envelope without schema_version must fail, exit %d: %s", code, stderr)
	}
}

func TestMissingDefaultArchetypesIsAWarning(t *testing.T) {
	e := newEnv(t, synthStudy())
	dir := t.TempDir() // cwd without fixtures/archetypes.json
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	headline, _ := filepath.Abs(filepath.Join(old, e.headline))
	code, _, stderr := export(t, "-headline", headline, e.study)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "fixtures/archetypes.json not found") {
		t.Errorf("expected missing archetypes warning, got:\n%s", stderr)
	}
}

// ---------------------------------------------------------------------------
// RQ2 forest figure

// studyOf builds a study with n completed images whose results follow the
// outcome strings of the given rules (cycled when shorter than n).
func studyOf(n int, rules []rule) spec.Study {
	t0 := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	st := spec.Study{SchemaVersion: spec.SchemaVersion, Run: synthStudy().Run}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("img%03d", i)
		img := &spec.SuiteResult{
			ImageName: ref(name), RequestedRef: ref(name), Status: spec.StatusCompleted,
			Timestamp: t0, Duration: time.Second,
		}
		for _, r := range rules {
			if res, ok := result(r, r.outcomes[i%len(r.outcomes)]); ok {
				img.Results = append(img.Results, res)
			}
		}
		img.Total = len(img.Results)
		st.Images = append(st.Images, img)
	}
	return st
}

// exportHeadline exports a study with its own headline classification, so a
// test can choose the checks of the figure. It returns the output directory.
func exportHeadline(t *testing.T, study spec.Study, headline ...string) *testEnv {
	t.Helper()
	e := newEnv(t, study)
	cls := map[string][]string{"headline": headline, "exploratory": {}, "excluded": {}}
	e.headline = filepath.Join(e.dir, "headline_checks.json")
	writeJSON(t, e.headline, cls)
	if code, _, stderr := export(t, e.args()...); code != 0 && code != spec.ExitIncomplete {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	return e
}

// noPrevalenceStudy is the synthetic study with FS-05 UNVERIFIED on every
// image, so that this headline check has no verified image.
func noPrevalenceStudy() spec.Study {
	st := synthStudy()
	for _, im := range st.Images {
		for i := range im.Results {
			if im.Results[i].TestID == "FS-05" {
				im.Results[i].Outcome, im.Results[i].Reason, im.Results[i].Passed = spec.OutcomeUnverified, spec.ReasonEvidenceIncomplete, false
			}
		}
	}
	return st
}

var (
	figRowComment = regexp.MustCompile(`(?m)^% (\S+): fail (\d+), verified (\d+), unverified (\d+)`)
	figWhisker    = regexp.MustCompile(`\\draw\[cuWhisker\] \(([0-9.]+),(-?[0-9.]+)\) -- \(([0-9.]+),(-?[0-9.]+)\);`)
	figDot        = regexp.MustCompile(`\\node\[cuDot\] at \(([0-9.]+),(-?[0-9.]+)\) \{\};`)
	figBarScope   = regexp.MustCompile(`\\begin\{scope\}\[xshift=[0-9.]+mm,x=([0-9.]+)mm\]\n((?:\\path\[cuSeg[A-Z]\][^\n]*\n)+)\\end\{scope\}`)
	figBarSeg     = regexp.MustCompile(`\\path\[(cuSeg[A-Z])\] \((\d+),(-?[0-9.]+)\) rectangle \((\d+),(-?[0-9.]+)\);`)
	figNumberNode = regexp.MustCompile(`\\node\[anchor=base (east|west)\] at \(([0-9.]+),(-?[0-9.]+)\) \{(\d+)\};`)
)

func atof(t *testing.T, s string) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return f
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return n
}

// macroInt returns the integer value of \ConUnit<name>.
func macroInt(t *testing.T, macros, name string) int {
	t.Helper()
	m := regexp.MustCompile(`\\newcommand\{\\ConUnit` + name + `\}\{(\d+)\}`).FindStringSubmatch(macros)
	if m == nil {
		t.Fatalf("macro ConUnit%s not found", name)
	}
	return atoi(t, m[1])
}

// tableRows returns the rows of the headline table in order: check ID and
// the cells after the rule column.
func tableRows(t *testing.T, table string) (ids []string, cells map[string][]string) {
	t.Helper()
	cells = map[string][]string{}
	for _, l := range strings.Split(table, "\n") {
		if !strings.HasPrefix(l, `\texttt{`) {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(l, ` \\`), " & ")
		id := strings.TrimSuffix(strings.TrimPrefix(parts[0], `\texttt{`), `}`)
		ids = append(ids, id)
		cells[id] = parts[1:]
	}
	return ids, cells
}

func TestPrevalenceFigureIsACompleteFloat(t *testing.T) {
	e := newEnv(t, synthStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fig := read(t, filepath.Join(e.dir, figPrevalence))
	lines := strings.Split(fig, "\n")
	if lines[0] != "% Generated by tools/export_latex.go. Do not edit." {
		t.Errorf("first line must be the generated-file header, got %q", lines[0])
	}
	for _, want := range []string{
		"% Requires: \\usetikzlibrary{patterns}",
		"\\begin{figure}[t]\n\\centering\n\\begin{tikzpicture}[",
		"\\end{tikzpicture}\n\\caption{",
		"\\label{fig:rq2_prevalence}\n\\end{figure}\n",
		"Wilson 95\\% intervals",
		"Unverified images enter neither numerator nor denominator.",
		"$N = 8$ completed images.",
	} {
		if !strings.Contains(fig, want) {
			t.Errorf("figure lacks %q", want)
		}
	}
	// The palette makes the file compile on its own; it never uses color
	// definitions that clash with the paper.
	for name, hex := range map[string]string{"cuTone": "0072B2", "cuTtwo": "56B4E9", "cuTthree": "E69F00", "cuTfour": "CC79A7",
		"cuPass": "009E73", "cuFail": "D55E00", "cuUnver": "7F7F7F", "cuInk": "222222", "cuLine": "555555", "cuPaper": "F5F5F5"} {
		if !strings.Contains(fig, `\providecolor{`+name+`}{HTML}{`+hex+`}`) {
			t.Errorf("palette color %s=%s missing", name, hex)
		}
	}
	// Preamble commands belong to the paper, not to the generated float.
	for _, l := range lines {
		if strings.HasPrefix(l, "%") {
			continue
		}
		for _, banned := range []string{`\usepackage`, `\usetikzlibrary`, `\pgfplotsset`, `\documentclass`, `\newcommand`} {
			if strings.Contains(l, banned) {
				t.Errorf("generated float contains the preamble command %s: %s", banned, l)
			}
		}
	}
	// The figure is drawn at its final size and never scaled.
	for _, banned := range []string{`\resizebox`, `\scalebox`, `scale=`, `\tiny`, `\scriptsize`, `\footnotesize`} {
		if strings.Contains(fig, banned) {
			t.Errorf("figure must not use %s", banned)
		}
	}
	if !strings.Contains(fig, `font=\sffamily\fontsize{7}{8}\selectfont`) {
		t.Error("figure text must be sans serif at 7 pt")
	}
	// Every x coordinate outside a scaled scope is in millimetres and stays
	// inside the picture width; the two panels end inside it as well.
	unscaled := regexp.MustCompile(`(?s)\\begin\{scope\}.*?\\end\{scope\}`).ReplaceAllString(fig, "")
	for _, m := range regexp.MustCompile(`\\(?:node\[[^\]]*\]|path\[[^\]]*\]|draw\[[^\]]*\]) (?:at )?\(([0-9.]+),`).FindAllStringSubmatch(unscaled, -1) {
		if x := atof(t, m[1]); x > forestWidth {
			t.Errorf("element at x = %.2f mm lies outside the %.1f mm picture", x, forestWidth)
		}
	}
	panels := regexp.MustCompile(`\\begin\{scope\}\[xshift=([0-9.]+)mm,x=([0-9]\.[0-9]{3})mm\]`).FindAllStringSubmatch(fig, -1)
	if len(panels) != 2 {
		t.Errorf("%d percent-scaled panels, want 2 (forest panel and bar axis)", len(panels))
	}
	for _, p := range panels {
		if right := atof(t, p[1]) + 100*atof(t, p[2]); right > forestWidth {
			t.Errorf("panel ends at %.2f mm, outside the %.1f mm picture", right, forestWidth)
		}
	}
	if forestWidth > 88.9 {
		t.Errorf("forestWidth %.1f mm exceeds one column (88.9 mm)", forestWidth)
	}
	// Excluded and exploratory checks are not part of the figure.
	for _, id := range []string{"SUP-02", "EXEC-01", "FS-06", "XTRA-01"} {
		if strings.Contains(fig, id) {
			t.Errorf("figure mentions the non-headline check %s", id)
		}
	}
}

func TestPrevalenceFigureHasOneRowPerHeadlineCheckInTableOrder(t *testing.T) {
	for name, study := range map[string]spec.Study{"all verified": synthStudy(), "one check without verified image": noPrevalenceStudy()} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, study)
			if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			fig := read(t, filepath.Join(e.dir, figPrevalence))
			tableIDs, cells := tableRows(t, read(t, filepath.Join(e.dir, filePrevalence)))
			if len(tableIDs) != 7 {
				t.Fatalf("headline table has %d rows, want 7", len(tableIDs))
			}
			var figIDs []string
			for _, m := range figRowComment.FindAllStringSubmatch(fig, -1) {
				figIDs = append(figIDs, m[1])
			}
			if strings.Join(figIDs, ",") != strings.Join(tableIDs, ",") {
				t.Errorf("figure rows %v differ from table rows %v", figIDs, tableIDs)
			}
			// Check ID labels, one per row and in the same order.
			labels := regexp.MustCompile(`\\node\[anchor=base east\] at \(([0-9.]+),(-?[0-9.]+)\) \{([A-Z][^}]*)\};`).FindAllStringSubmatch(fig, -1)
			if len(labels) != len(tableIDs) {
				t.Fatalf("%d label nodes for %d rows", len(labels), len(tableIDs))
			}
			for i, m := range labels {
				if m[3] != tableIDs[i] {
					t.Errorf("label %d is %q, want %q", i, m[3], tableIDs[i])
				}
			}
			// fail and verified counts equal the table, per row.
			counts := map[string][]int{} // y -> numbers in drawing order
			var ys []string
			for _, m := range figNumberNode.FindAllStringSubmatch(fig, -1) {
				if _, ok := counts[m[3]]; !ok {
					ys = append(ys, m[3])
				}
				counts[m[3]] = append(counts[m[3]], atoi(t, m[4]))
			}
			if len(ys) != len(tableIDs) {
				t.Fatalf("%d rows of count nodes for %d checks", len(ys), len(tableIDs))
			}
			for i, id := range tableIDs {
				got := counts[ys[i]] // fail, verified, unverified
				wantCell := fmt.Sprintf("%d/%d", got[0], got[1])
				if cells[id][2] != wantCell {
					t.Errorf("%s: figure counts %s, table %s", id, wantCell, cells[id][2])
				}
				if cells[id][4] != strconv.Itoa(got[2]) {
					t.Errorf("%s: figure unverified %d, table %s", id, got[2], cells[id][4])
				}
			}
			// A check without a verified image keeps its row and is marked n/a.
			noPrev := strings.Count(fig, `\itshape n/a`)
			wantNA := 0
			if name != "all verified" {
				wantNA = 1
				if !strings.Contains(fig, "% FS-05: fail 0, verified 0, unverified 8\n") {
					t.Error("FS-05 lost its row")
				}
			}
			if noPrev != wantNA {
				t.Errorf("%d rows are marked n/a, want %d", noPrev, wantNA)
			}
			if strings.Count(fig, `\node[cuDot]`) != len(tableIDs)-wantNA {
				t.Errorf("%d prevalence points for %d rows with a verified image", strings.Count(fig, `\node[cuDot]`), len(tableIDs)-wantNA)
			}
		})
	}
}

func TestPrevalenceFigureWhiskersEqualTableValues(t *testing.T) {
	e := newEnv(t, noPrevalenceStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fig := read(t, filepath.Join(e.dir, figPrevalence))
	ids, cells := tableRows(t, read(t, filepath.Join(e.dir, filePrevalence)))
	prevCell := regexp.MustCompile(`^([0-9.]+) \[([0-9.]+), ([0-9.]+)\]$`)

	// Each row with a verified image has one whisker line, two caps and a point.
	whiskers := figWhisker.FindAllStringSubmatch(fig, -1)
	dots := figDot.FindAllStringSubmatch(fig, -1)
	w := 0
	d := 0
	rowsWithPrevalence := 0
	for _, id := range ids {
		m := prevCell.FindStringSubmatch(cells[id][3])
		if m == nil {
			if cells[id][3] != "n/a" {
				t.Fatalf("%s: unexpected prevalence cell %q", id, cells[id][3])
			}
			continue
		}
		rowsWithPrevalence++
		est, lo, hi := m[1], m[2], m[3]
		if w+3 > len(whiskers) || d >= len(dots) {
			t.Fatalf("%s: figure has too few whiskers or points", id)
		}
		main, capLo, capHi := whiskers[w], whiskers[w+1], whiskers[w+2]
		w += 3
		if main[1] != lo || main[3] != hi || main[2] != main[4] {
			t.Errorf("%s: whisker runs from %s to %s at y %s/%s, table interval is [%s, %s]", id, main[1], main[3], main[2], main[4], lo, hi)
		}
		if capLo[1] != lo || capLo[3] != lo || capHi[1] != hi || capHi[3] != hi {
			t.Errorf("%s: caps at %s and %s, table interval is [%s, %s]", id, capLo[1], capHi[1], lo, hi)
		}
		if dots[d][1] != est {
			t.Errorf("%s: point at %s, table estimate %s", id, dots[d][1], est)
		}
		if dots[d][2] != main[2] {
			t.Errorf("%s: point at y %s, whisker at y %s", id, dots[d][2], main[2])
		}
		d++
	}
	if w != len(whiskers) || d != len(dots) {
		t.Errorf("figure has %d whisker lines and %d points beyond the %d rows with a prevalence", len(whiskers)-w, len(dots)-d, rowsWithPrevalence)
	}
	if rowsWithPrevalence != 6 {
		t.Errorf("%d rows with a prevalence, want 6", rowsWithPrevalence)
	}
	// SPEC-01 spot check against the documented values.
	for _, want := range []string{
		`\node[cuDot] at (71.4,`, `\draw[cuWhisker] (35.9,`, `-- (91.8,`,
		"% SPEC-01: fail 5, verified 7, unverified 1, prevalence 71.4 [35.9, 91.8]\n",
	} {
		if !strings.Contains(fig, want) {
			t.Errorf("figure lacks %q", want)
		}
	}
}

func TestPrevalenceFigureStackedBarsAddUp(t *testing.T) {
	e := newEnv(t, noPrevalenceStudy())
	if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fig := read(t, filepath.Join(e.dir, figPrevalence))
	macros := read(t, filepath.Join(e.dir, fileMacros))
	ids, _ := tableRows(t, read(t, filepath.Join(e.dir, filePrevalence)))

	scopes := figBarScope.FindAllStringSubmatch(fig, -1)
	if len(scopes) != len(ids) {
		t.Fatalf("%d bars for %d rows", len(scopes), len(ids))
	}
	barWidth := 0.0
	fs05 := -1
	for i, id := range ids {
		if id == "FS-05" {
			fs05 = i
		}
		key := idKey(id)
		verified, unverified := macroInt(t, macros, "Verified"+key), macroInt(t, macros, "Unverified"+key)
		segs := figBarSeg.FindAllStringSubmatch(scopes[i][2], -1)
		if len(segs) == 0 {
			t.Fatalf("%s: bar without segments", id)
		}
		prevEnd := 0
		for j, s := range segs {
			start, end := atoi(t, s[2]), atoi(t, s[4])
			if start != prevEnd || end <= start {
				t.Errorf("%s: segment %d runs from %d to %d after %d", id, j, start, end, prevEnd)
			}
			prevEnd = end
			if j == 0 && verified > 0 && (s[1] != "cuSegV" || end != verified) {
				t.Errorf("%s: first segment %s ends at %d, want cuSegV at %d verified", id, s[1], end, verified)
			}
			if j > 0 && s[1] == "cuSegV" {
				t.Errorf("%s: verified segment is not first", id)
			}
		}
		if verified == 0 && segs[0][1] == "cuSegV" {
			t.Errorf("%s: has a verified segment but no verified image", id)
		}
		if prevEnd != verified+unverified {
			t.Errorf("%s: bar totals %d, verified %d plus unverified %d", id, prevEnd, verified, unverified)
		}
		// Every bar is 100 percent of the same width.
		width := atof(t, scopes[i][1]) * float64(prevEnd)
		if i == 0 {
			barWidth = width
		} else if math.Abs(width-barWidth) > 0.01 {
			t.Errorf("%s: bar is %.3f mm wide, the first bar %.3f mm", id, width, barWidth)
		}
		// The bar is centered on the row of its whisker.
		y0, y1 := atof(t, segs[0][3]), atof(t, segs[0][5])
		center := (y0 + y1) / 2
		labelY := regexp.MustCompile(`\\node\[anchor=base east\] at \([0-9.]+,(-?[0-9.]+)\) \{` + regexp.QuoteMeta(id) + `\};`).FindStringSubmatch(fig)
		if labelY == nil {
			t.Fatalf("%s: no label", id)
		}
		if math.Abs(atof(t, labelY[1])+0.85-center) > 0.011 {
			t.Errorf("%s: label baseline %s is not aligned with the bar center %.2f", id, labelY[1], center)
		}
	}
	// FS-05 has no verified image, so its bar is UNVERIFIED only.
	if fs05 < 0 {
		t.Fatal("FS-05 is not a headline row")
	}
	if !strings.Contains(scopes[fs05][2], "cuSegA") || strings.Contains(scopes[fs05][2], "cuSegV") {
		t.Errorf("FS-05 bar must contain only UNVERIFIED segments:\n%s", scopes[fs05][2])
	}
}

func TestPrevalenceFigureGroupsUnverifiedReasons(t *testing.T) {
	rules := []rule{
		{"SPEC-01", "a", spec.TierSpec, nil, "FPPPPPPPPe"},
		{"EXEC-01", "b", spec.TierContract, nil, "PPPbbbnnPP"},
		{"EXEC-02", "c", spec.TierContract, nil, "PPPbbbttPe"},
		{"SUP-02", "d", spec.TierSupplyChain, nil, "ttttPPPPeb"},
	}
	e := exportHeadline(t, studyOf(10, rules), "SPEC-01", "EXEC-01", "EXEC-02", "SUP-02")
	fig := read(t, filepath.Join(e.dir, figPrevalence))
	// Reasons ranked by their total over the figure: BASELINE_FAILED 7,
	// NO_TRUST_POLICY 6, EVIDENCE_INCOMPLETE 3, NOT_OBSERVABLE 2 (pooled).
	legend := regexp.MustCompile(`\\node\[anchor=base west\] \(lg\dt\) at [^{]*\{([^}]*)\};`).FindAllStringSubmatch(fig, -1)
	var got []string
	for _, m := range legend {
		got = append(got, m[1])
	}
	want := []string{"Verified", `BASELINE\_FAILED`, `NO\_TRUST\_POLICY`, `EVIDENCE\_INCOMPLETE`, "Other"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("legend = %v, want %v", got, want)
	}
	for _, style := range forestSegStyles {
		if !strings.Contains(fig, `\path[`+style+`] (lg`) {
			t.Errorf("legend has no swatch for %s", style)
		}
	}
	// Only the pooled reason lands in Other: EXEC-01 has two NOT_OBSERVABLE results.
	scopes := figBarScope.FindAllStringSubmatch(fig, -1)
	if len(scopes) != 4 {
		t.Fatalf("%d bars, want 4", len(scopes))
	}
	for i, id := range []string{"SPEC-01", "EXEC-01", "EXEC-02", "SUP-02"} {
		other := 0
		for _, s := range figBarSeg.FindAllStringSubmatch(scopes[i][2], -1) {
			if s[1] == "cuSegO" {
				other += atoi(t, s[4]) - atoi(t, s[2])
			}
		}
		wantOther := 0
		if id == "EXEC-01" {
			wantOther = 2
		}
		if other != wantOther {
			t.Errorf("%s: Other has %d results, want %d", id, other, wantOther)
		}
	}
	// A figure with at most three reasons has no Other entry.
	if strings.Contains(read(t, filepath.Join(exportHeadline(t, studyOf(10, rules[:2]), "SPEC-01", "EXEC-01").dir, figPrevalence)), "Other") {
		t.Error("legend names Other although no reason is pooled")
	}
}

func TestPrevalenceFigurePendingState(t *testing.T) {
	noCompleted := spec.Study{SchemaVersion: spec.SchemaVersion, Run: synthStudy().Run, Images: []*spec.SuiteResult{
		{ImageName: ref("a"), RequestedRef: ref("a"), Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled},
	}}
	// Completed images, but every headline check is UNVERIFIED.
	noVerified := studyOf(5, []rule{
		{"SPEC-01", "a", spec.TierSpec, nil, "e"},
		{"FS-04", "b", spec.TierFilesystem, nil, "b"},
	})
	cases := []struct {
		name     string
		e        *testEnv
		wantN    string
		wantMark bool // caption carries the pending marker of the placeholder files
	}{
		{"no completed image", exportHeadline(t, noCompleted, "SPEC-01"), "", true},
		{"no verified headline check", exportHeadline(t, noVerified, "SPEC-01", "FS-04"), "$N = 5$ completed images.", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fig := read(t, filepath.Join(c.e.dir, figPrevalence))
			for _, want := range []string{
				"\\begin{figure}[t]", "\\end{figure}", "\\label{fig:rq2_prevalence}", "\\caption{",
				"\\draw[dashed,rounded corners=2mm,",
				"{pending: generated from the final run};",
				"Wilson 95\\% intervals",
			} {
				if !strings.Contains(fig, want) {
					t.Errorf("pending figure lacks %q", want)
				}
			}
			for _, banned := range []string{`\node[cuDot]`, `cuWhisker]`, `cuSegV]`, `\itshape n/a`} {
				if strings.Contains(fig, banned) {
					t.Errorf("pending figure must not draw data (%s)", banned)
				}
			}
			if c.wantN != "" && !strings.Contains(fig, c.wantN) {
				t.Errorf("caption lacks %q", c.wantN)
			}
			if c.wantN == "" && strings.Contains(fig, "$N =") {
				t.Error("caption of a study without completed images must not state N")
			}
			if got := strings.Contains(fig, `\textbf{[pending: generated from the final run]}`); got != c.wantMark {
				t.Errorf("caption carries the pending marker = %t, want %t", got, c.wantMark)
			}
		})
	}
	// The frame has the final width and the height of a seven row figure.
	fig := read(t, filepath.Join(cases[0].e.dir, figPrevalence))
	m := regexp.MustCompile(`rectangle \(([0-9.]+),(-[0-9.]+)\);`).FindStringSubmatch(fig)
	if m == nil || atof(t, m[1]) != forestWidth {
		t.Fatalf("pending frame has no rectangle of width %.1f mm: %v", forestWidth, m)
	}
	var l forestLayout
	l.setRows(forestPendingRows)
	if math.Abs(-atof(t, m[2])-l.height(2)) > 0.011 {
		t.Errorf("pending frame is %s mm high, a %d row figure is %.2f mm", m[2], forestPendingRows, l.height(2))
	}
}

func TestPrevalenceFigureIsDeterministic(t *testing.T) {
	// Two exports of the same study are byte identical, which the -check
	// mode relies on.
	a, b := newEnv(t, synthStudy()), newEnv(t, synthStudy())
	for _, e := range []*testEnv{a, b} {
		if code, _, stderr := export(t, e.args("-audit", e.audit)...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	}
	for _, name := range []string{figPrevalence, filePreview} {
		if read(t, filepath.Join(a.dir, name)) != read(t, filepath.Join(b.dir, name)) {
			t.Errorf("%s differs between two exports", name)
		}
	}
	// Rendering repeatedly from one analysis must not depend on map order,
	// also with several UNVERIFIED reasons of equal count.
	rules := []rule{
		{"SPEC-01", "a", spec.TierSpec, nil, "bnte"},
		{"FS-04", "b", spec.TierFilesystem, nil, "PbntF"},
	}
	e := exportHeadline(t, studyOf(20, rules), "SPEC-01", "FS-04")
	loaded, err := studyfile.Load(e.study)
	if err != nil {
		t.Fatal(err)
	}
	class, err := analysis.LoadClassification(e.headline)
	if err != nil {
		t.Fatal(err)
	}
	an := analysis.Analyze(loaded, analysis.Options{Classification: class, Source: "empirical_study.json"})
	first := renderPrevalenceFigure(an)
	for i := 0; i < 50; i++ {
		if got := renderPrevalenceFigure(an); got != first {
			t.Fatalf("render %d differs from the first render", i)
		}
	}
	if first != read(t, filepath.Join(e.dir, figPrevalence)) {
		t.Error("the written file differs from a fresh render")
	}
	if code, _, stderr := export(t, e.args("-check")...); code != 0 {
		t.Errorf("-check must accept a fresh export, exit %d: %s", code, stderr)
	}
}

func TestForestShortensLongCheckIDs(t *testing.T) {
	for in, want := range map[string]string{
		"FS-04": "FS-04", "EXEC-01-READ": "EXEC-01-READ",
		"EXEC-01-READ-ONLY-ROOT": "EXEC-01-RE..", "SPEC-01-A-VERY-LONG-IDENTIFIER": "SPEC-01-A-..",
	} {
		if got := forestShort(in); got != want {
			t.Errorf("forestShort(%q) = %q, want %q", in, got, want)
		}
	}
	// The figure shortens the label only; the comment of the row keeps the ID.
	e := exportHeadline(t, studyOf(10, []rule{{"EXEC-01-READ-ONLY-ROOT", "a", spec.TierContract, nil, "FPPPPPPPPP"}}), "EXEC-01-READ-ONLY-ROOT")
	fig := read(t, filepath.Join(e.dir, figPrevalence))
	if !strings.Contains(fig, "{EXEC-01-RE..};") || !strings.Contains(fig, "% EXEC-01-READ-ONLY-ROOT: fail 1, verified 10") {
		t.Errorf("long check ID handled wrongly:\n%s", fig)
	}
}

func TestPrevalenceFigureLabelIsPartOfThePaperContract(t *testing.T) {
	doc := read(t, filepath.Join("..", "docs", "CONTRACT.md"))
	for _, want := range []string{"fig:rq2_prevalence", "fig_rq2_prevalence.tex"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/CONTRACT.md does not list %s", want)
		}
	}
}

// ---------------------------------------------------------------------------
// LaTeX compilation

// findPDFLaTeX returns the TeX engine to use, honoring PDFLATEX, or "".
func findPDFLaTeX() string {
	if p := os.Getenv("PDFLATEX"); p != "" {
		return p
	}
	if p, err := exec.LookPath("pdflatex"); err == nil {
		return p
	}
	return ""
}

// TestGeneratedLatexCompiles builds preview_paper.tex, which includes every
// generated file, for a full study and for a study without completed images.
// It is skipped when no pdflatex is available; set PDFLATEX to point at one.
func TestGeneratedLatexCompiles(t *testing.T) {
	tex := findPDFLaTeX()
	if tex == "" {
		t.Skip("pdflatex not found; set PDFLATEX to compile the generated LaTeX")
	}
	empty := spec.Study{SchemaVersion: spec.SchemaVersion, Run: synthStudy().Run, Images: []*spec.SuiteResult{
		{ImageName: ref("a"), RequestedRef: ref("a"), Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled},
	}}
	for name, study := range map[string]any{"full": synthStudy(), "no_completed": empty} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, study)
			code, _, stderr := export(t, e.args("-audit", e.audit)...)
			if code != 0 && code != spec.ExitIncomplete {
				t.Fatalf("export exit %d: %s", code, stderr)
			}
			cmd := exec.Command(tex, "-interaction=nonstopmode", "-halt-on-error", filePreview)
			cmd.Dir = e.dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("pdflatex failed: %v\n%s", err, tailString(string(out), 3000))
			}
		})
	}
}

// figureTestDocument is a minimal IEEEtran one-column document that loads
// what the paper loads for the figure (tikz with the patterns library, xcolor,
// pgfplots) and includes only the figure. It reports the picture width.
const figureTestDocument = `\documentclass[10pt,conference]{IEEEtran}
\usepackage[utf8]{inputenc}
\usepackage{xcolor}
\usepackage{tikz}
\usetikzlibrary{patterns}
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
\usepackage{hyperref}
\begin{document}
\typeout{COLUMNWIDTH \the\columnwidth}
See Fig.~\ref{fig:rq2_prevalence}.
\input{fig_rq2_prevalence.tex}
\makeatletter
\typeout{PICWIDTH \the\dimexpr\pgf@picmaxx-\pgf@picminx\relax}
\makeatother
\end{document}
`

// TestPrevalenceFigureFitsOneColumn compiles the figure alone, for a normal
// study, one with an unverifiable check, a stress study with twelve rows and
// a long check ID, and the pending state. It requires the picture to be
// narrower than \columnwidth, no overfull box and a resolved reference. It is
// skipped without pdflatex, IEEEtran or pgfplots.
func TestPrevalenceFigureFitsOneColumn(t *testing.T) {
	tex := findPDFLaTeX()
	if tex == "" {
		t.Skip("pdflatex not found; set PDFLATEX to compile the figure")
	}
	var stressRules []rule
	var stressIDs []string
	for i, id := range []string{"SPEC-01", "CIS-4.6", "SPEC-05", "FS-04", "FS-05", "FS-08", "EXEC-01-READ-ONLY-ROOT", "EXEC-02", "EXEC-03", "EXEC-04", "SUP-01", "NEVER-VERIFIED"} {
		outcomes := []string{"FPPPFPPPPPeP", "FFFFFFPFFF", "PPPPPPPPPF", "PFFFFPPPFFPPPPPPPPPP", "PPPPPPPPPF", "PPPPPPePPP",
			"bFPnPbbnPPPPPPPPtPPe", "PPFPPFbPPP", "bbbbbbnbbb", "PPPPFPPPPP", "tttttttnnb", "eeeeeeee"}[i]
		stressRules = append(stressRules, rule{id, "check", spec.TierSpec, nil, outcomes})
		stressIDs = append(stressIDs, id)
	}
	empty := spec.Study{SchemaVersion: spec.SchemaVersion, Run: synthStudy().Run, Images: []*spec.SuiteResult{
		{ImageName: ref("a"), RequestedRef: ref("a"), Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled},
	}}
	cases := []struct {
		name string
		e    *testEnv
	}{
		{"full", exportHeadline(t, synthStudy(), "SPEC-01", "CIS-4.6", "FS-04", "FS-05", "FS-08", "SPEC-05", "SPEC-06")},
		{"unverifiable check", exportHeadline(t, noPrevalenceStudy(), "SPEC-01", "CIS-4.6", "FS-04", "FS-05", "FS-08", "SPEC-05", "SPEC-06")},
		{"stress", exportHeadline(t, studyOf(100, stressRules), stressIDs...)},
		{"pending", exportHeadline(t, empty, "SPEC-01")},
	}
	num := func(out, key string) float64 {
		m := regexp.MustCompile(key + ` ([0-9.]+)pt`).FindStringSubmatch(out)
		if m == nil {
			t.Fatalf("no %s in the TeX output:\n%s", key, tailString(out, 2000))
		}
		return atof(t, m[1])
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(c.e.dir, "figtest.tex"), []byte(figureTestDocument), 0o644); err != nil {
				t.Fatal(err)
			}
			var out []byte
			for pass := 0; pass < 2; pass++ { // the second pass resolves the reference
				cmd := exec.Command(tex, "-interaction=nonstopmode", "-halt-on-error", "figtest.tex")
				cmd.Dir = c.e.dir
				var err error
				if out, err = cmd.CombinedOutput(); err != nil {
					if regexp.MustCompile(`File .(IEEEtran\.cls|pgfplots\.sty). not found`).Match(out) {
						t.Skipf("TeX installation lacks a package of the test document: %s", tailString(string(out), 300))
					}
					t.Fatalf("pdflatex failed: %v\n%s", err, tailString(string(out), 3000))
				}
			}
			log := string(out)
			column, picture := num(log, "COLUMNWIDTH"), num(log, "PICWIDTH")
			if picture > column {
				t.Errorf("the picture is %.2f pt wide, the column %.2f pt", picture, column)
			}
			// 3.5 in is the nominal column; IEEEtran's \columnwidth is 252 pt.
			if picture < column-6 {
				t.Errorf("the picture is %.2f pt wide, far below the column of %.2f pt", picture, column)
			}
			for _, bad := range []string{"Overfull", "Underfull", "Undefined control", "undefined", "Package pgf Warning", "LaTeX Warning"} {
				if strings.Contains(log, bad) {
					t.Errorf("TeX log contains %q", bad)
				}
			}
		})
	}
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// ---------------------------------------------------------------------------
// Real fixtures

func TestRealFixturesAreConsistent(t *testing.T) {
	root := ".."
	arch := map[string]struct{ Archetype, BaseFamily string }{}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(read(t, filepath.Join(root, "fixtures", "archetypes.json"))), &raw); err != nil {
		t.Fatal(err)
	}
	validArch := map[string]bool{"base-os": true, "language-runtime": true, "database": true, "web-ingress": true, "messaging": true, "application": true, "build-tool": true, "other": true}
	validFam := map[string]bool{"alpine": true, "debian": true, "ubuntu": true, "fedora-rhel": true, "scratch-or-distroless": true, "other": true, "unknown": true}
	for repo, v := range raw {
		var e struct {
			Archetype  string `json:"archetype"`
			BaseFamily string `json:"base_family"`
		}
		if err := json.Unmarshal(v, &e); err != nil {
			t.Fatalf("%s: %v", repo, err)
		}
		if !validArch[e.Archetype] || !validFam[e.BaseFamily] {
			t.Errorf("%s has invalid archetype %q or base family %q", repo, e.Archetype, e.BaseFamily)
		}
		arch[repo] = struct{ Archetype, BaseFamily string }{e.Archetype, e.BaseFamily}
	}
	// Every pinned repository has an entry.
	pinned := read(t, filepath.Join(root, "fixtures", "evaluation_dataset_pinned.txt"))
	re := regexp.MustCompile(`(?m)^\S*/library/([^@\s]+)@sha256:[a-f0-9]{64}$`)
	repos := re.FindAllStringSubmatch(pinned, -1)
	if len(repos) == 0 {
		t.Fatal("no pinned entries found")
	}
	for _, m := range repos {
		if _, ok := arch[m[1]]; !ok {
			t.Errorf("pinned repository %s has no archetypes.json entry", m[1])
		}
	}
	// Every excluded entry of the pinned JSON has an entry.
	var records []struct {
		OriginalTag string `json:"original_tag"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal([]byte(read(t, filepath.Join(root, "fixtures", "evaluation_dataset_pinned.json"))), &records); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		repo := strings.SplitN(r.OriginalTag, ":", 2)[0]
		if _, ok := arch[repo]; !ok {
			t.Errorf("%s repository %s has no archetypes.json entry", r.Status, repo)
		}
	}
	// The classification is valid and covers the provisional plan.
	var cls struct{ Headline, Exploratory, Excluded []string }
	if err := json.Unmarshal([]byte(read(t, filepath.Join(root, "fixtures", "headline_checks.json"))), &cls); err != nil {
		t.Fatal(err)
	}
	wantHeadline := "SPEC-01,CIS-4.6,FS-04,FS-05,FS-08,SPEC-05,SPEC-06"
	if strings.Join(cls.Headline, ",") != wantHeadline {
		t.Errorf("headline = %v, want %s", cls.Headline, wantHeadline)
	}
	if len(cls.Excluded) != 1 || cls.Excluded[0] != "SUP-02" {
		t.Errorf("excluded = %v, want [SUP-02]", cls.Excluded)
	}
	for _, id := range []string{"FS-06", "FS-07", "SPEC-07", "FS-09", "SPEC-03", "EXEC-01", "EXEC-02", "EXEC-04", "EXEC-07"} {
		found := false
		for _, e := range cls.Exploratory {
			found = found || e == id
		}
		if !found {
			t.Errorf("exploratory list lacks %s", id)
		}
	}
}
