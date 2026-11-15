package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// update rewrites the golden files: go test ./tools/crosscheck -run Golden -update
var update = flag.Bool("update", false, "rewrite golden files in tools/crosscheck/testdata/golden")

func assertGolden(t *testing.T, scenario, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", scenario, name)
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

func digestRef(name string, fill byte) string {
	return fmt.Sprintf("index.docker.io/library/%s@sha256:%s", name, strings.Repeat(string(fill), 64))
}

// goldenChecks gives every mapped check the outcome PASS, with overrides.
func goldenChecks(over map[string]spec.TestResult) []spec.TestResult {
	var out []spec.TestResult
	for _, m := range Mappings() {
		if r, ok := over[m.Check]; ok {
			out = append(out, r)
			continue
		}
		out = append(out, cuResult(m.Check, spec.OutcomePass))
	}
	return out
}

func fail(id, msg string, paths ...string) spec.TestResult {
	r := cuResult(id, spec.OutcomeFail)
	r.Message = msg
	if len(paths) > 0 {
		r.Evidence = &spec.Evidence{Paths: paths}
	}
	return r
}

func unverified(id string) spec.TestResult {
	r := cuResult(id, spec.OutcomeUnverified)
	r.Reason = spec.ReasonFileMissing
	r.Message = "a required file is missing"
	return r
}

// goldenFixture is a study of six completed images and one that did not
// complete, with the Dockle side of each. It covers every cell, both kinds of
// image error, a skipped checkpoint, the shared code CIS-DI-0010 and the pair
// that cannot be compared. Two of the reports are real Dockle v0.4.15 output.
func goldenFixture(t *testing.T) (*studyfile.Loaded, map[string]*ImageRecord, RunInfo) {
	t.Helper()
	realAlpine := string(readTestdata(t, "dockle_0.4.15_alpine.json"))
	realSeeded := string(readTestdata(t, "dockle_0.4.15_seeded.json"))
	rec := func(key, report string, export, dockle float64) *ImageRecord {
		return &ImageRecord{
			Image: key, Status: ImageOK, ExportSeconds: export, DockleSeconds: dockle,
			ConfigDigestStudy: "sha256:cfg", ConfigDigestArchive: "sha256:cfg", DockleStdout: report,
		}
	}

	alpine, nginx, seeded := digestRef("alpine", '1'), digestRef("nginx", '2'), digestRef("seeded", '3')
	broken, drifted, distroless := digestRef("broken", '4'), digestRef("drifted", '5'), digestRef("distroless", '6')
	timeout := digestRef("slow", '7')

	images := []*spec.SuiteResult{
		cuImage(nginx, goldenChecks(map[string]spec.TestResult{
			"SPEC-01": fail("SPEC-01", "Image runs as root user (configured user: '')"),
			"CIS-4.6": fail("CIS-4.6", "Image has no enabled HEALTHCHECK"),
			"FS-01":   fail("FS-01", "package manager caches present", "/var/cache/apt", "/var/lib/apt/lists"),
			"FS-08":   unverified("FS-08"),
		})...),
		cuImage(alpine, goldenChecks(map[string]spec.TestResult{
			"SPEC-01": fail("SPEC-01", "Image runs as root user (configured user: '')"),
			"CIS-4.6": fail("CIS-4.6", "Image has no enabled HEALTHCHECK"),
		})...),
		cuImage(seeded, goldenChecks(map[string]spec.TestResult{
			"SPEC-01": fail("SPEC-01", "Image runs as root user (configured user: '')"),
			"CIS-4.6": fail("CIS-4.6", "Image has no enabled HEALTHCHECK"),
			"SPEC-07": fail("SPEC-07", "Detected 1 ADD instructions in the recorded image history"),
			"SPEC-03": fail("SPEC-03", "Key=DB_PASSWORD"),
			"FS-12":   fail("FS-12", "credential-named file", "/app/id_rsa"),
			"SPEC-09": fail("SPEC-09", "apt-get update without install"),
			"SPEC-10": fail("SPEC-10", "sudo in command position"),
			"SPEC-12": fail("SPEC-12", "volume /proc declared"),
			"FS-10":   fail("FS-10", "UID 1000 shared by dup1 and dup2"),
		})...),
		cuImage(broken, goldenChecks(nil)...),
		cuImage(drifted, goldenChecks(nil)...),
		cuImage(distroless, goldenChecks(map[string]spec.TestResult{
			"SPEC-12": fail("SPEC-12", "volume /proc/self declared"),
		})...),
		{ImageName: timeout, RequestedRef: timeout, Status: spec.StatusTimeout, Reason: spec.ReasonDeadlineExceeded},
	}
	l := loadedStudy(images...)
	l.SHA256 = strings.Repeat("ab", 32)
	l.Study.Run = spec.RunMetadata{
		ConUnitVersion: "0.9.0-test", Commit: "0123456789abcdef0123456789abcdef01234567", Pack: "lint", PackID: "PACK-IMAGE-LINT",
		Platform: "linux/amd64", ImageSource: "auto", EngineName: "podman", EngineVersion: "5.8.1",
		DatasetSHA256: strings.Repeat("cd", 32), StartedAt: time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC),
	}

	records := map[string]*ImageRecord{
		alpine: rec(alpine, realAlpine, 0.8, 1.9),
		nginx: rec(nginx, reportJSON(
			finding("CIS-DI-0001", "WARN", "Last user should not be root"),
			finding("CIS-DI-0007", "FATAL", "Always combine 'apt-get update' with 'apt-get install|upgrade' : /bin/sh -c apt-get update"),
			finding("DKL-LI-0001", "SKIP", "failed to detect etc/shadow,etc/master.passwd"),
			finding("CIS-DI-0005", "INFO", "export DOCKER_CONTENT_TRUST=1 before docker pull/build"),
			finding("CIS-DI-0006", "INFO", "not found HEALTHCHECK statement"),
		), 1.4, 3.1),
		seeded: rec(seeded, realSeeded, 0.9, 2.2),
		broken: {Image: broken, Status: ImageExportError, Error: "the image is not in the engine store and could not be pulled: manifest unknown", ConfigDigestStudy: "sha256:cfg", ExportSeconds: 0.2},
		drifted: {
			Image: drifted, Status: ImageDigestMismatch, ConfigDigestStudy: "sha256:cfg", ConfigDigestArchive: "sha256:other",
			Error: "the archive config digest sha256:other differs from the study config digest sha256:cfg", ExportSeconds: 1.1,
		},
		distroless: rec(distroless, reportJSON(
			finding("DKL-LI-0001", "SKIP", "failed to detect etc/shadow,etc/master.passwd"),
			finding("DKL-LI-0002", "SKIP", "failed to detect etc/passwd", "failed to detect etc/group"),
			finding("CIS-DI-0005", "INFO", "export DOCKER_CONTENT_TRUST=1 before docker pull/build"),
			finding("CIS-DI-0006", "INFO", "not found HEALTHCHECK statement"),
		), 0.6, 1.2),
	}
	return l, records, RunInfo{DockleVersion: "0.4.15", Engine: "podman version 5.8.1", Platform: "linux/amd64"}
}

func goldenOutputs(t *testing.T, sheet *Sheet) ([]struct{ name, content string }, *Result) {
	t.Helper()
	l, records, run := goldenFixture(t)
	res := Analyze(l, records, Options{Run: run, Sheet: sheet})
	report := BuildReport(res, studyRef("/some/host/path/lint/empirical_study.json", l), run)
	files, err := outputs(res, report)
	if err != nil {
		t.Fatal(err)
	}
	return files, res
}

func TestGoldenPending(t *testing.T) {
	files, _ := goldenOutputs(t, nil)
	if len(files) != 6 {
		t.Fatalf("%d output files, want crosscheck.json, discordances.csv, table_crosscheck.tex, table_discordances.tex, macros_crosscheck.tex and table_coverage.tex", len(files))
	}
	for _, f := range files {
		assertGolden(t, "pending", f.name, f.content)
	}
}

func TestGoldenResolved(t *testing.T) {
	_, res := goldenOutputs(t, nil)
	// Resolve three discordances and leave the rest.
	var rows strings.Builder
	rows.WriteString(sheetHeader)
	ds := orderedDiscordances(res.Discordances)
	if len(ds) < 4 {
		t.Fatalf("the fixture needs at least four discordances, has %d", len(ds))
	}
	ratings := []string{"TP,TP,", ",,FP", "UNDECIDABLE,UNDECIDABLE,"}
	for i, rating := range ratings {
		fmt.Fprintf(&rows, "id%d,%s,%s,crosscheck,evidence,%s\n", i, ds[i].Image, ds[i].Check, rating)
	}
	sheet, err := ReadSheet(strings.NewReader(rows.String()))
	if err != nil {
		t.Fatal(err)
	}
	files, resolved := goldenOutputs(t, sheet)
	if resolved.Totals.Resolved == nil || *resolved.Totals.Resolved != 2 || resolved.Totals.Undecidable != 1 {
		t.Fatalf("resolved = %v, undecidable = %d", resolved.Totals.Resolved, resolved.Totals.Undecidable)
	}
	for _, f := range files {
		switch f.name {
		case fileDiscordances, fileDiscTable, fileMacros:
			assertGolden(t, "resolved", f.name, f.content)
		}
	}
}

// TestGoldenFixtureTellsTheExpectedStory checks the fixture itself, so that a
// change of the golden files cannot hide a change of the rules.
func TestGoldenFixtureTellsTheExpectedStory(t *testing.T) {
	_, res := goldenOutputs(t, nil)
	cellOf := func(image, check string) Cell {
		for _, ir := range res.Images {
			if strings.Contains(ir.Image, image) {
				for _, c := range ir.Checks {
					if c.Check == check {
						return c.Cell
					}
				}
			}
		}
		t.Fatalf("no result of %s on %s", check, image)
		return ""
	}
	want := []struct {
		image, check string
		cell         Cell
	}{
		{"alpine", "SPEC-01", CellBoth},
		{"alpine", "CIS-4.6", CellBoth},
		{"alpine", "FS-04", CellNeither},
		{"nginx", "SPEC-09", CellOnlyDockle},
		{"nginx", "FS-08", CellConUnitUnverified},
		{"nginx", "FS-01", CellOnlyConUnit},
		{"seeded", "SPEC-07", CellBoth},
		{"seeded", "SPEC-03", CellBoth},
		{"seeded", "FS-06", CellOnlyDockle},
		{"seeded", "FS-12", CellBoth},
		{"seeded", "SPEC-11", CellOnlyDockle},
		{"seeded", "FS-11", CellOnlyDockle},
		{"seeded", "FS-01", CellOnlyDockle},
		{"seeded", "SPEC-13", CellNotComparable},
		{"broken", "SPEC-01", CellDockleError},
		{"drifted", "FS-10", CellDockleError},
		{"distroless", "SPEC-12", CellOnlyConUnit},
		{"distroless", "FS-10", CellDockleNotEvaluated},
		{"distroless", "FS-08", CellDockleNotEvaluated},
		{"distroless", "SPEC-01", CellNeither},
	}
	for _, w := range want {
		if got := cellOf(w.image, w.check); got != w.cell {
			t.Errorf("%s on %s: cell %s, want %s", w.check, w.image, got, w.cell)
		}
	}
	if res.Totals.ImagesCompleted != 6 || res.Totals.ImagesAnalyzed != 4 || res.Totals.ImagesWithError != 2 {
		t.Errorf("totals = %+v", res.Totals)
	}
}
