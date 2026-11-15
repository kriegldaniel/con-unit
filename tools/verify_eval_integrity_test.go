package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/dataaudit"
)

// exporter binary shared by the integrity tests, built once.
var (
	exporterOnce sync.Once
	exporterDir  string
	exporterBin  string
	exporterErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if exporterDir != "" {
		os.RemoveAll(exporterDir)
	}
	os.Exit(code)
}

func exporterBinary(t *testing.T) string {
	t.Helper()
	exporterOnce.Do(func() {
		exporterDir, exporterErr = os.MkdirTemp("", "export-latex-bin-")
		if exporterErr != nil {
			return
		}
		exporterBin = filepath.Join(exporterDir, "export_latex")
		cmd := exec.Command("go", "build", "-o", exporterBin, "export_latex.go")
		cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			exporterErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if exporterErr != nil {
		t.Skipf("cannot build the exporter: %v", exporterErr)
	}
	return exporterBin
}

type integrityEnv struct {
	dir, fixtures, results string
	study                  spec.Study
	audit                  dataaudit.Audit
	names                  []string
}

func sumOf(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func (e *integrityEnv) path(parts ...string) string {
	return filepath.Join(append([]string{e.dir}, parts...)...)
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listInfoOf(t *testing.T, path string, entries int) dataaudit.ListInfo {
	t.Helper()
	return dataaudit.ListInfo{Path: filepath.Base(path), SHA256: sumOf(mustRead(t, path)), Entries: entries}
}

// newIntegrityEnv builds a small, fully consistent dataset, audit, study and
// generated artifact set, so each test can break exactly one thing.
func newIntegrityEnv(t *testing.T) *integrityEnv {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	e := &integrityEnv{dir: t.TempDir(), study: synthStudy()}
	e.fixtures, e.results = e.path("fixtures"), e.path("results")

	// The 12 attempted images are the pinned list; 2 more candidates were excluded.
	var refs, tags []string
	for _, img := range e.study.Images {
		refs = append(refs, img.RequestedRef)
		name := strings.SplitN(strings.TrimPrefix(img.RequestedRef, "index.docker.io/library/"), "@", 2)[0]
		e.names = append(e.names, name)
		tags = append(tags, name+":1")
	}
	tags = append(tags, "ex1:1", "ex2:1")

	list := func(header string, lines []string) []byte {
		return []byte(header + "\n\n" + strings.Join(lines, "\n") + "\n")
	}
	full := e.path("fixtures", "evaluation_dataset_full.txt")
	pinned := e.path("fixtures", "evaluation_dataset_pinned.txt")
	top10 := e.path("fixtures", "evaluation_dataset_top10.txt")
	top10p := e.path("fixtures", "evaluation_dataset_top10_pinned.txt")
	mustWrite(t, full, list(fmt.Sprintf("# Candidates (N = %d)", len(tags)), tags))
	mustWrite(t, pinned, list(fmt.Sprintf("# Pinned (N = %d)", len(refs)), refs))
	mustWrite(t, top10, list("# Top 10 (N = 10)", tags[:10]))
	mustWrite(t, top10p, list("# Pinned top 10 (N = 10)", refs[:10]))

	var records []PinnedRecord
	for i, tag := range tags {
		if i < len(refs) {
			records = append(records, PinnedRecord{OriginalTag: tag, ImmutableRef: refs[i], Status: "PINNED"})
		} else {
			records = append(records, PinnedRecord{OriginalTag: tag, Status: "EXCLUDED_SINGLE_ARCH", Error: "single architecture"})
		}
	}
	pj, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, e.path("fixtures", "evaluation_dataset_pinned.json"), pj)
	mustWrite(t, e.path("fixtures", "headline_checks.json"), mustRead(t, filepath.Join("testdata", "export_latex", "headline_checks.json")))
	mustWrite(t, e.path("fixtures", "archetypes.json"), mustRead(t, filepath.Join("testdata", "export_latex", "archetypes.json")))

	e.audit = dataaudit.Audit{
		SchemaVersion: dataaudit.SchemaVersion, Tool: "pin_dataset", ToolVersion: "test", GeneratedAt: "2026-11-14T09:00:00Z", Mode: "registry",
		Frame:         dataaudit.Frame{Repository: "docker-library/official-images", Commit: "abc1234def56789", Date: "2026-11-13"},
		InclusionRule: "test inclusion rule", Platform: "linux/amd64",
		Input: listInfoOf(t, full, len(tags)),
		Outputs: dataaudit.Outputs{
			PinnedTxt:  listInfoOf(t, pinned, len(refs)),
			PinnedJSON: listInfoOf(t, e.path("fixtures", "evaluation_dataset_pinned.json"), len(records)),
			Top10: &dataaudit.Top10Info{
				Input: listInfoOf(t, top10, 10), Pinned: listInfoOf(t, top10p, 10), AllInMain: true,
			},
		},
		Counts: dataaudit.Counts{Candidates: len(tags), Pinned: len(refs), Excluded: 2},
		ExclusionLog: []dataaudit.Exclusion{
			{OriginalTag: "ex1:1", Status: "EXCLUDED_SINGLE_ARCH", Reason: "single architecture"},
			{OriginalTag: "ex2:1", Status: "EXCLUDED_SINGLE_ARCH", Reason: "single architecture"},
		},
	}
	e.study.Run.DatasetSHA256 = e.audit.Outputs.PinnedTxt.SHA256
	e.writeAudit(t)
	e.regenerate(t)

	mustWrite(t, e.path("results", "EMPIRICAL_SUMMARY.md"), []byte("# summary\n"))
	mustWrite(t, e.path("results", "ATTRITION_REPORT.md"), []byte("# attrition\n"))
	mustWrite(t, e.path("results", "journal.jsonl"), []byte("{}\n"))
	mustWrite(t, e.path("results", "logs", "run.log"), []byte("log\n"))
	return e
}

// PinnedRecord mirrors one entry of evaluation_dataset_pinned.json.
type PinnedRecord struct {
	OriginalTag  string `json:"original_tag"`
	ImmutableRef string `json:"immutable_ref,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

func (e *integrityEnv) writeAudit(t *testing.T) {
	t.Helper()
	b, err := json.MarshalIndent(e.audit, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, e.path("fixtures", "evaluation_dataset_audit.json"), b)
}

func (e *integrityEnv) writeStudy(t *testing.T) {
	t.Helper()
	b, err := json.MarshalIndent(e.study, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, e.path("results", "empirical_study.json"), b)
}

// regenerate writes the study and every generated file with the exporter.
func (e *integrityEnv) regenerate(t *testing.T) {
	t.Helper()
	e.writeStudy(t)
	// The pipeline exports with -audit and -pinned, and the integrity script
	// checks the bundle against an export with the same flags.
	code, _, stderr := export(t, "-headline", e.path("fixtures", "headline_checks.json"),
		"-archetypes", e.path("fixtures", "archetypes.json"),
		"-audit", e.path("fixtures", "evaluation_dataset_audit.json"),
		"-pinned", e.path("fixtures", "evaluation_dataset_pinned.json"),
		"-out", e.results, e.path("results", "empirical_study.json"))
	if code != 0 {
		t.Fatalf("exporter exit %d: %s", code, stderr)
	}
}

// editStudyJSON applies edit to the raw study document and writes it back.
func (e *integrityEnv) editStudyJSON(t *testing.T, edit func(doc map[string]any)) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, e.path("results", "empirical_study.json")), &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, e.path("results", "empirical_study.json"), b)
}

func (e *integrityEnv) verify(t *testing.T, env ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", "verify_eval_integrity.sh")
	cmd.Env = append(os.Environ(),
		"FIXTURES_DIR="+e.fixtures, "RESULTS_DIR="+e.results, "NO_COLOR=1", "SKIP_GO_TESTS=1",
		"EXPORT_CMD="+exporterBinary(t))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run verify_eval_integrity.sh: %v", err)
	}
	return code, string(out)
}

func (e *integrityEnv) mustFail(t *testing.T, want string, env ...string) {
	t.Helper()
	code, out := e.verify(t, env...)
	if code != 1 {
		t.Errorf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
}

func replaceInFile(t *testing.T, path, old, new string) {
	t.Helper()
	b := string(mustRead(t, path))
	if !strings.Contains(b, old) {
		t.Fatalf("test setup: %q not found in %s", old, path)
	}
	mustWrite(t, path, []byte(strings.Replace(b, old, new, 1)))
}

// ---------------------------------------------------------------------------

func TestIntegrityPassesOnAConsistentBundle(t *testing.T) {
	e := newIntegrityEnv(t)
	code, out := e.verify(t)
	if code != 0 {
		t.Fatalf("exit = %d on a consistent bundle\n%s", code, out)
	}
	for _, want := range []string{
		"declared N = 14 equals the 14 entries", "declared N = 12 equals the 12 entries",
		"every top-10 pinned entry is contained in the main pinned list",
		"dataset audit agrees with the lists", "schema_version is 2", "run metadata block present",
		"every attempted image has exactly one record", "no image has two results for one test ID",
		"every image of evaluation_dataset_pinned.txt has a record",
		"macros equal an independent recount of the JSON (14 checks, flow counts)",
		"the exporter reproduces every generated file byte for byte",
		"no file name is written by two tools",
		", 0 warnings, 0 failures",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestIntegrityRealFixturesPass(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not available")
	}
	cmd := exec.Command("bash", "verify_eval_integrity.sh")
	cmd.Env = append(os.Environ(), "RESULTS_DIR="+t.TempDir(), "NO_COLOR=1", "SKIP_GO_TESTS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the repository dataset must pass the dataset checks: %v\n%s", err, out)
	}
}

func TestIntegrityCatchesDatasetProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, e *integrityEnv)
		want   string
	}{
		{"declared N differs from entries", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("fixtures", "evaluation_dataset_pinned.txt"), "(N = 12)", "(N = 99)")
		}, "declared N = 99 but 12 entries"},
		{"duplicate pinned entry", func(t *testing.T, e *integrityEnv) {
			f := e.path("fixtures", "evaluation_dataset_pinned.txt")
			mustWrite(t, f, append(mustRead(t, f), []byte(e.study.Images[0].RequestedRef+"\n")...))
		}, "evaluation_dataset_pinned.txt has duplicate entries"},
		{"entry without digest", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("fixtures", "evaluation_dataset_pinned.txt"), e.study.Images[3].RequestedRef, "index.docker.io/library/python:latest")
		}, "is not an immutable sha256 reference: index.docker.io/library/python:latest"},
		{"top-10 entry outside the main list", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("fixtures", "evaluation_dataset_top10_pinned.txt"), e.study.Images[1].RequestedRef,
				"index.docker.io/library/nginx@sha256:"+strings.Repeat("0", 64))
		}, "top-10 entries missing from the main pinned list"},
		{"pinned JSON disagrees with the list", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("fixtures", "evaluation_dataset_pinned.json"), `"status": "PINNED"`, `"status": "FAILED"`)
		}, "pinned JSON has 11 PINNED records"},
		{"audit counts differ", func(t *testing.T, e *integrityEnv) {
			e.audit.Counts.Pinned = 13
			e.writeAudit(t)
		}, "audit: pinned is 13, expected 12"},
		{"audit hash of the pinned list differs", func(t *testing.T, e *integrityEnv) {
			e.audit.Outputs.PinnedTxt.SHA256 = strings.Repeat("e", 64)
			e.writeAudit(t)
		}, "audit: pinned list sha256 is"},
		{"audit says top-10 is not contained", func(t *testing.T, e *integrityEnv) {
			e.audit.Outputs.Top10.AllInMain = false
			e.audit.Outputs.Top10.MissingInMain = []string{"x"}
			e.writeAudit(t)
		}, "audit: top-10 contained in the main list is false, expected true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newIntegrityEnv(t)
			c.mutate(t, e)
			e.mustFail(t, c.want)
		})
	}
}

func TestIntegrityCatchesResultProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, e *integrityEnv)
		want   string
	}{
		{"legacy array format", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) {})
			var doc map[string]any
			if err := json.Unmarshal(mustRead(t, e.path("results", "empirical_study.json")), &doc); err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(doc["images"])
			mustWrite(t, e.path("results", "empirical_study.json"), b)
		}, "legacy array format"},
		{"schema_version wrong", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) { doc["schema_version"] = "1" })
		}, "schema_version is '1', expected 2"},
		{"run block missing", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) { delete(doc, "run") })
		}, "run metadata block is missing"},
		{"image recorded twice", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) {
				imgs := doc["images"].([]any)
				doc["images"] = append(imgs, imgs[0])
			})
		}, "images with more than one record"},
		{"duplicate test ID inside an image", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) {
				img := doc["images"].([]any)[0].(map[string]any)
				res := img["results"].([]any)
				img["results"] = append(res, res[0])
			})
		}, "images with duplicate test IDs"},
		{"attempted image has no record", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) {
				doc["images"] = doc["images"].([]any)[1:]
			})
		}, "attempted images without a record"},
		{"unknown status", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) {
				doc["images"].([]any)[0].(map[string]any)["status"] = "DONE"
			})
		}, "records without a valid status"},
		{"FS-06 failure without non-fixture paths", func(t *testing.T, e *integrityEnv) {
			e.editStudyJSON(t, func(doc map[string]any) {
				for _, im := range doc["images"].([]any) {
					results, _ := im.(map[string]any)["results"].([]any)
					for _, r := range results {
						rm := r.(map[string]any)
						if rm["test_id"] == "FS-06" && rm["outcome"] == "FAIL" {
							rm["evidence"] = map[string]any{"fixture_candidate_paths": []string{"/x/testdata/k"}}
						}
					}
				}
			})
		}, "FS-06 or FS-07 FAIL without non-fixture evidence paths"},
		{"bundle file missing", func(t *testing.T, e *integrityEnv) {
			if err := os.Remove(e.path("results", "journal.jsonl")); err != nil {
				t.Fatal(err)
			}
		}, "missing or empty bundle file"},
		{"mirror check reports a miss", func(t *testing.T, e *integrityEnv) {
			mustWrite(t, e.path("results", "mirror_check.json"), []byte(`{"summary":{"total":3,"ok":2}}`))
		}, "mirror_check.json reports entries that do not resolve"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newIntegrityEnv(t)
			c.mutate(t, e)
			e.mustFail(t, c.want)
		})
	}
}

func TestIntegrityCatchesArtifactProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, e *integrityEnv)
		want   string
	}{
		{"macro edited by hand", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("results", "macros_study.tex"), `\ConUnitNCompleted}{8}`, `\ConUnitNCompleted}{9}`)
		}, `macro \ConUnitNCompleted is 9 but the JSON gives 8`},
		{"check count macro edited", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("results", "macros_study.tex"), `\ConUnitFailSPECZeroOne}{5}`, `\ConUnitFailSPECZeroOne}{4}`)
		}, `macro \ConUnitFailSPECZeroOne is 4 but the JSON gives 5`},
		{"macros from another study file", func(t *testing.T, e *integrityEnv) {
			b := string(mustRead(t, e.path("results", "macros_study.tex")))
			re := regexp.MustCompile(`sha256 [0-9a-f]{64}`)
			mustWrite(t, e.path("results", "macros_study.tex"), []byte(re.ReplaceAllString(b, "sha256 "+strings.Repeat("0", 64))))
		}, "does not belong to this study file"},
		{"macro missing", func(t *testing.T, e *integrityEnv) {
			replaceInFile(t, e.path("results", "macros_study.tex"), `\newcommand{\ConUnitPassFSZeroFour}`, `\newcommand{\ConUnitPassFSZeroFourX}`)
		}, `macro \ConUnitPassFSZeroFour is missing`},
		{"empty generated file", func(t *testing.T, e *integrityEnv) {
			mustWrite(t, e.path("results", "table_strata.tex"), nil)
		}, "missing or empty generated file"},
		{"generated file deleted", func(t *testing.T, e *integrityEnv) {
			if err := os.Remove(e.path("results", "study_stats.json")); err != nil {
				t.Fatal(err)
			}
		}, "missing or empty generated file"},
		{"generated table edited by hand", func(t *testing.T, e *integrityEnv) {
			f := e.path("results", "table_rq2_prevalence.tex")
			mustWrite(t, f, append(mustRead(t, f), []byte("% hand edit\n")...))
		}, "generated files differ from a fresh export"},
		{"pass-rate statistic reappears", func(t *testing.T, e *integrityEnv) {
			f := e.path("results", "table_unverified.tex")
			mustWrite(t, f, append(mustRead(t, f), []byte("% mean pass rate 75%\n")...))
		}, "removed statistics or obsolete labels"},
		{"two tools write one file", func(t *testing.T, e *integrityEnv) {}, "file written by more than one tool: table_rq2_prevalence.tex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newIntegrityEnv(t)
			c.mutate(t, e)
			var env []string
			if c.name == "two tools write one file" {
				env = []string{"INTEGRITY_EXTRA_OUTPUTS=benchmark_rq3:table_rq2_prevalence.tex"}
			}
			e.mustFail(t, c.want, env...)
		})
	}
}

func TestIntegrityStrictModeTurnsWarningsIntoFailures(t *testing.T) {
	e := newIntegrityEnv(t)
	e.audit.Frame = dataaudit.Frame{Repository: "docker-library/official-images", Commit: dataaudit.Unrecorded, Date: dataaudit.Unrecorded}
	e.writeAudit(t)
	// The exporter output depends on the frame, so regenerate it.
	e.regenerate(t)
	code, out := e.verify(t)
	if code != 0 || !strings.Contains(out, "the sampling frame (library commit and date) is not recorded") || !strings.Contains(out, "1 warnings, 0 failures") {
		t.Fatalf("a missing frame is a warning outside strict mode: exit %d\n%s", code, out)
	}
	e.mustFail(t, "(strict) the sampling frame", "INTEGRITY_STRICT=1")
}

func TestIntegrityRequireResults(t *testing.T) {
	e := newIntegrityEnv(t)
	if err := os.Remove(e.path("results", "empirical_study.json")); err != nil {
		t.Fatal(err)
	}
	if code, out := e.verify(t); code != 0 || !strings.Contains(out, "result and artifact checks skipped") {
		t.Errorf("a missing study is skipped by default: exit %d\n%s", code, out)
	}
	e.mustFail(t, "study file not found", "REQUIRE_RESULTS=1")
}

func TestIntegrityOutputRegistryMatchesTheExporter(t *testing.T) {
	script := string(mustRead(t, "verify_eval_integrity.sh"))
	parse := func(name string) []string {
		m := regexp.MustCompile(`(?s)` + name + `=\((.*?)\)`).FindStringSubmatch(script)
		if m == nil {
			t.Fatalf("%s not found in the script", name)
		}
		return strings.Fields(m[1])
	}
	got := append(parse("EXPORT_TEX_FILES"), parse("EXPORT_JSON_FILES")...)
	want := append(append([]string{}, texOutputs...), fileStatsJSON)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the script's exporter output list differs from the exporter\nscript:   %v\nexporter: %v", got, want)
	}
}
