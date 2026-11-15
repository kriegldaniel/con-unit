package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/journal"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

func readStudy(t *testing.T, outDir string) spec.Study {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(outDir, "empirical_study.json"))
	if err != nil {
		t.Fatalf("read empirical_study.json: %v", err)
	}
	var study spec.Study
	if err := json.Unmarshal(data, &study); err != nil {
		t.Fatalf("empirical_study.json is not a spec.Study envelope: %v\n%s", err, data)
	}
	return study
}

func TestEvalWritesStudyEnvelopeAndJournal(t *testing.T) {
	images := writeImageListFile(t, "a:1\nb:1\n")
	outDir := filepath.Join(t.TempDir(), "results")
	fake := &fakePackRunner{}
	code := runEvalCommandWithDeps([]string{"--images", images, "--pack", "hygiene", "--out-dir", outDir, "--platform", "linux/amd64", "--probe-window", "2s", "--image-source", "local", "--max-index-entries", "1234"}, offlineCommandDeps(fake))
	if code != spec.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, spec.ExitOK)
	}
	study := readStudy(t, outDir)
	if study.SchemaVersion != spec.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", study.SchemaVersion, spec.SchemaVersion)
	}
	if study.Run.ConUnitVersion != version || study.Run.PackID == "" || study.Run.Platform != "linux/amd64" {
		t.Errorf("run metadata not filled from runenv.Detect: %+v", study.Run)
	}
	if study.Run.FinishedAt.IsZero() {
		t.Error("run.finished_at must be set by eval")
	}
	if len(study.Images) != 2 || study.Images[0].RequestedRef != "a:1" || study.Images[1].RequestedRef != "b:1" {
		t.Fatalf("images = %+v, want one record per image in list order", study.Images)
	}
	for _, image := range study.Images {
		if image.Status != spec.StatusCompleted || image.ImageName != image.RequestedRef {
			t.Errorf("record = %+v, want COMPLETED with image_name equal to requested_ref", image)
		}
	}
	opts := fake.options
	if opts.Platform != "linux/amd64" || opts.ImageSource != "local" || opts.ProbeWindow != 2*time.Second || opts.MaxIndexEntries != 1234 {
		t.Errorf("runner options = %+v, want the flags forwarded", opts)
	}
	if opts.Retry.MaxAttempts < 2 {
		t.Errorf("rate-limit retry must be enabled for eval, got %+v", opts.Retry)
	}

	records, _, err := journal.Read(filepath.Join(outDir, "journal.jsonl"))
	if err != nil || len(records) != 2 {
		t.Fatalf("journal records = %d err=%v, want one line per image", len(records), err)
	}
}

func TestEvalResumeSkipsCompletedAndRetriesOthers(t *testing.T) {
	images := writeImageListFile(t, "done:1\nthrottled:1\nnew:1\n")
	outDir := filepath.Join(t.TempDir(), "results")

	first := &fakePackRunner{errors: map[string]error{
		"throttled:1": &engine.RateLimitError{Op: "pull", Image: "throttled:1"},
		"new:1":       errors.New("boom"),
	}}
	if code := runEvalCommandWithDeps([]string{"--images", images, "--out-dir", outDir}, offlineCommandDeps(first)); code != spec.ExitIncomplete {
		t.Fatalf("first run exit code = %d, want %d", code, spec.ExitIncomplete)
	}
	if len(first.calls) != 3 {
		t.Fatalf("first run calls = %v", first.calls)
	}

	second := &fakePackRunner{}
	code := runEvalCommandWithDeps([]string{"--images", images, "--out-dir", outDir, "--resume"}, offlineCommandDeps(second))
	if code != spec.ExitOK {
		t.Fatalf("resumed run exit code = %d, want %d", code, spec.ExitOK)
	}
	if strings.Join(second.calls, ",") != "throttled:1,new:1" {
		t.Fatalf("resume must skip the COMPLETED image and retry the others, calls = %v", second.calls)
	}
	study := readStudy(t, outDir)
	if len(study.Images) != 3 {
		t.Fatalf("study has %d images, want 3", len(study.Images))
	}
	for _, image := range study.Images {
		if image.Status != spec.StatusCompleted {
			t.Errorf("%s status = %s after resume, want COMPLETED (last record wins)", image.RequestedRef, image.Status)
		}
	}
	records, _, _ := journal.Read(filepath.Join(outDir, "journal.jsonl"))
	if len(records) != 5 {
		t.Errorf("journal has %d lines, want 5 (3 first run, 2 retried); the journal is append-only", len(records))
	}
}

func TestEvalWithoutResumeMovesAsideAnExistingJournal(t *testing.T) {
	images := writeImageListFile(t, "a:1\n")
	outDir := filepath.Join(t.TempDir(), "results")
	for run := 0; run < 2; run++ {
		fake := &fakePackRunner{}
		if code := runEvalCommandWithDeps([]string{"--images", images, "--out-dir", outDir}, offlineCommandDeps(fake)); code != spec.ExitOK {
			t.Fatalf("run %d exit code = %d", run, code)
		}
		if len(fake.calls) != 1 {
			t.Fatalf("run %d without --resume must evaluate the image again, calls = %v", run, fake.calls)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(outDir, "journal.jsonl.*.bak"))
	if len(matches) != 1 {
		t.Fatalf("rotated journals = %v, want exactly one backup of the first run", matches)
	}
	records, _, _ := journal.Read(filepath.Join(outDir, "journal.jsonl"))
	if len(records) != 1 {
		t.Fatalf("fresh journal has %d records, want only the second run", len(records))
	}
}

func TestEvalClassifiesFailuresWithTypedErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus string
		wantReason spec.Reason
	}{
		{"engine rate limit", &engine.RateLimitError{Op: "pull", Image: "x"}, spec.StatusRateLimited, spec.ReasonRegistryThrottled},
		{"registry rate limit", &oci.RateLimitError{Ref: "x", Err: errors.New("429")}, spec.StatusRateLimited, spec.ReasonRegistryThrottled},
		{"engine not found", &engine.NotFoundError{Op: "pull", Image: "x"}, spec.StatusUnavailable, spec.ReasonManifestNotFound},
		{"registry not found", &oci.NotFoundError{Ref: "x", Err: errors.New("404")}, spec.StatusUnavailable, spec.ReasonManifestNotFound},
		{"absent from local store", &engine.ImageNotInStoreError{Image: "x"}, spec.StatusUnavailable, spec.ReasonManifestNotFound},
		{"deadline", fmt.Errorf("pull: %w", context.DeadlineExceeded), spec.StatusTimeout, spec.ReasonDeadlineExceeded},
		{"index too large", fmt.Errorf("index: %w", &oci.IndexTooLargeError{Limit: 5}), spec.StatusIndexLimit, spec.ReasonIndexTooLarge},
		{"identity mismatch", &oci.IdentityMismatchError{Ref: "x", Detail: "digest"}, spec.StatusExecutionError, spec.ReasonIdentityMismatch},
		{"platform mismatch", &oci.PlatformMismatchError{Detail: "arch"}, spec.StatusExecutionError, spec.ReasonPlatformMismatch},
		{"untyped text is never classified", errors.New("pull manifest repository timeout deadline exceeded not found"), spec.StatusExecutionError, spec.ReasonNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			images := writeImageListFile(t, "x:1\n")
			outDir := filepath.Join(t.TempDir(), "results")
			wrapped := &runner.ImageError{Stage: "pull", ImageSource: spec.SourceRegistry, Err: tc.err}
			fake := &fakePackRunner{errors: map[string]error{"x:1": wrapped}}
			if code := runEvalCommandWithDeps([]string{"--images", images, "--out-dir", outDir}, offlineCommandDeps(fake)); code != spec.ExitIncomplete {
				t.Fatalf("exit code = %d, want %d", code, spec.ExitIncomplete)
			}
			record := readStudy(t, outDir).Images[0]
			if record.Status != tc.wantStatus || record.Reason != tc.wantReason {
				t.Errorf("status/reason = %s/%s, want %s/%s", record.Status, record.Reason, tc.wantStatus, tc.wantReason)
			}
			if record.ImageSource != spec.SourceRegistry || record.ErrorMessage == "" {
				t.Errorf("failure record must keep the image source and error message: %+v", record)
			}
			if record.Results == nil {
				t.Error("failure records must serialize results as an empty array, not null")
			}
		})
	}
}

func TestEvalExitCodeContract(t *testing.T) {
	finding := map[string]*spec.SuiteResult{"x:1": {ImageName: "x:1", Total: 2, Passed: 1, Failed: 1, Unverified: 0}}
	t.Run("findings do not matter without the flag", func(t *testing.T) {
		code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "x:1\n"), "--out-dir", t.TempDir()}, offlineCommandDeps(&fakePackRunner{results: finding}))
		if code != spec.ExitOK {
			t.Fatalf("exit code = %d, want %d", code, spec.ExitOK)
		}
	})
	t.Run("findings with --fail-on-findings", func(t *testing.T) {
		code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "x:1\n"), "--out-dir", t.TempDir(), "--fail-on-findings"}, offlineCommandDeps(&fakePackRunner{results: finding}))
		if code != spec.ExitFindings {
			t.Fatalf("exit code = %d, want %d", code, spec.ExitFindings)
		}
	})
	t.Run("an incomplete run wins over findings", func(t *testing.T) {
		fake := &fakePackRunner{results: finding, errors: map[string]error{"y:1": errors.New("boom")}}
		code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "x:1\ny:1\n"), "--out-dir", t.TempDir(), "--fail-on-findings"}, offlineCommandDeps(fake))
		if code != spec.ExitIncomplete {
			t.Fatalf("exit code = %d, want %d", code, spec.ExitIncomplete)
		}
	})
	t.Run("clean run with --fail-on-findings", func(t *testing.T) {
		code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "x:1\n"), "--out-dir", t.TempDir(), "--fail-on-findings"}, offlineCommandDeps(&fakePackRunner{}))
		if code != spec.ExitOK {
			t.Fatalf("exit code = %d, want %d", code, spec.ExitOK)
		}
	})
}

func TestEvalRejectsInvalidConfiguration(t *testing.T) {
	images := writeImageListFile(t, "x:1\n")
	cases := map[string][]string{
		"missing images":         {"--out-dir", t.TempDir()},
		"bad platform":           {"--images", images, "--platform", "amd64"},
		"bad image source":       {"--images", images, "--image-source", "cloud"},
		"window too small":       {"--images", images, "--probe-window", "10ms"},
		"bad engine":             {"--images", images, "--engine", "rkt"},
		"non-positive timeout":   {"--images", images, "--image-timeout", "0s"},
		"non-positive index cap": {"--images", images, "--max-index-entries", "0"},
		"stray positional":       {"--images", images, "extra"},
		"missing image list":     {"--images", filepath.Join(t.TempDir(), "absent.txt")},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakePackRunner{}
			if code := runEvalCommandWithDeps(args, offlineCommandDeps(fake)); code != spec.ExitUsage {
				t.Fatalf("exit code = %d, want %d", code, spec.ExitUsage)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("no image may be evaluated after a configuration error: %v", fake.calls)
			}
		})
	}
}

func TestEvalEvaluatesDuplicateImagesOnce(t *testing.T) {
	fake := &fakePackRunner{}
	outDir := t.TempDir()
	code := runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "a:1\nb:1\na:1\n"), "--out-dir", outDir}, offlineCommandDeps(fake))
	if code != spec.ExitOK || strings.Join(fake.calls, ",") != "a:1,b:1" {
		t.Fatalf("code=%d calls=%v, want each distinct image once", code, fake.calls)
	}
	if got := len(readStudy(t, outDir).Images); got != 2 {
		t.Fatalf("study has %d images, want 2", got)
	}
}

func TestTestCommandAcceptsRuntimeFlags(t *testing.T) {
	fake := &fakePackRunner{}
	code := runTestCommandWithDeps([]string{"x:1", "--pack", "hygiene", "--platform", "linux/arm64", "--image-source", "registry", "--probe-window", "1s", "--format", "json", "--output", filepath.Join(t.TempDir(), "r.json")}, offlineCommandDeps(fake))
	if code != spec.ExitOK {
		t.Fatalf("exit code = %d, want %d", code, spec.ExitOK)
	}
	if fake.options.Platform != "linux/arm64" || fake.options.ImageSource != "registry" || fake.options.ProbeWindow != time.Second {
		t.Fatalf("runner options = %+v", fake.options)
	}
	for _, bad := range [][]string{{"x:1", "--platform", "bogus"}, {"x:1", "--image-source", "x"}, {"x:1", "--probe-window", "1ms"}} {
		if code := runTestCommandWithDeps(bad, offlineCommandDeps(&fakePackRunner{})); code != spec.ExitUsage {
			t.Errorf("args %v exit code = %d, want %d", bad, code, spec.ExitUsage)
		}
	}
}

func sampleStudy() *spec.Study {
	return &spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run: spec.RunMetadata{
			ConUnitVersion: "test", Platform: "linux/amd64", ImageSource: "local",
			ProbeWindowMs: 3000, StartedAt: fixedClock, FinishedAt: fixedClock.Add(time.Hour),
		},
		Images: []*spec.SuiteResult{
			{ImageName: "a:1", RequestedRef: "a:1", Status: spec.StatusCompleted, ImageSource: spec.SourceLocalStore, ImageDigest: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64", Passed: 3, Failed: 1, Unverified: 1, Total: 5,
				Resources: spec.ResourceTelemetry{LayerCount: 2, UncompressedBytes: 5 << 20, CompressedBytes: 2 << 20, PeakRSSMB: 777.7}},
			{ImageName: "b:1", RequestedRef: "b:1", Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled, ErrorMessage: "throttled | retry", Timestamp: fixedClock},
			{ImageName: "c:1", RequestedRef: "c:1", Status: spec.StatusTimeout, Reason: spec.ReasonDeadlineExceeded, ErrorMessage: "deadline", Timestamp: fixedClock},
			{ImageName: "d:1", RequestedRef: "d:1", Status: spec.StatusRateLimited, Reason: spec.ReasonRegistryThrottled, ErrorMessage: "again", Timestamp: fixedClock},
			{ImageName: "e:1", RequestedRef: "e:1", Status: "FUTURE_STATUS", ErrorMessage: "unknown", Timestamp: fixedClock},
		},
	}
}

func TestReportsAreDeterministicAndOmitPerImagePeakMemory(t *testing.T) {
	study := sampleStudy()
	firstSummary, firstAttrition := renderMarkdownSummary(study), renderAttritionReport(study)
	for i := 0; i < 25; i++ {
		if renderMarkdownSummary(study) != firstSummary || renderAttritionReport(study) != firstAttrition {
			t.Fatal("report output changed between renders of the same study (map iteration leaked into the output)")
		}
	}
	for _, forbidden := range []string{"Peak RAM", "Pass Rate", "PeakRSS"} {
		if strings.Contains(firstSummary, forbidden) || strings.Contains(firstAttrition, forbidden) {
			t.Errorf("reports must not contain %q", forbidden)
		}
	}
	// Memory appears once, as the ceiling of the whole process, never per image.
	if strings.Count(firstSummary, "777.7 MiB") != 1 || strings.Count(firstSummary, "Peak resident set size over the whole run") != 1 {
		t.Errorf("the batch peak must be stated exactly once:\n%s", firstSummary)
	}
	if !strings.Contains(firstSummary, "## Resources (ConUnit process only)") || !strings.Contains(firstSummary, "not a per-image value") {
		t.Errorf("the batch ceiling must be labeled as process-wide and process-only:\n%s", firstSummary)
	}
	for _, line := range strings.Split(firstSummary, "\n") {
		if strings.HasPrefix(line, "|") && strings.Contains(line, "RSS") {
			t.Errorf("the results matrix must not carry a memory column: %s", line)
		}
	}
	if strings.Contains(firstAttrition, "777.7") {
		t.Errorf("the attrition report must not report memory:\n%s", firstAttrition)
	}
	// Canonical status order, then unknown statuses alphabetically.
	order := []string{"TIMEOUT: 1", "RATE_LIMITED: 2", "FUTURE_STATUS: 1"}
	last := -1
	for _, line := range order {
		at := strings.Index(firstSummary, line)
		if at < 0 || at < last {
			t.Fatalf("summary status breakdown is not in canonical order, missing or misplaced %q:\n%s", line, firstSummary)
		}
		last = at
	}
	if !strings.Contains(firstAttrition, "RATE_LIMITED / REGISTRY_THROTTLED: 2") {
		t.Errorf("attrition report must break non-completed images down by reason:\n%s", firstAttrition)
	}
	if !strings.Contains(firstSummary, "throttled \\| retry") {
		t.Errorf("table cells must escape pipes:\n%s", firstSummary)
	}
}

func TestDiagnosticLogDoesNotReportPeakMemory(t *testing.T) {
	dir := t.TempDir()
	study := sampleStudy()
	writeImageDiagnosticLog(dir, study.Images[0])
	data, err := os.ReadFile(filepath.Join(dir, "a_1.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "PeakRSS") || strings.Contains(string(data), "777.7") {
		t.Fatalf("per-image diagnostic log must not report the process peak RSS:\n%s", data)
	}
}
