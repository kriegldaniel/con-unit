package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

type fakePackRunner struct {
	calls           []string
	results         map[string]*spec.SuiteResult
	errors          map[string]error
	signatureConfig *conunit.SignatureVerificationConfig
	options         runner.Options
}

func (f *fakePackRunner) RunPack(_ context.Context, _ conunit.RulePack, image string) (*spec.SuiteResult, error) {
	f.calls = append(f.calls, image)
	if err := f.errors[image]; err != nil {
		return nil, err
	}
	if result := f.results[image]; result != nil {
		return result, nil
	}
	return &spec.SuiteResult{
		ImageName: image,
		SuiteName: "offline test pack",
		Total:     1,
		Passed:    1,
	}, nil
}
func (f *fakePackRunner) SetSignatureVerification(config conunit.SignatureVerificationConfig) {
	f.signatureConfig = &config
}

var fixedClock = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func offlineCommandDeps(fake *fakePackRunner) commandDeps {
	return commandDeps{
		detectEngine: func(string) (*engine.Engine, error) {
			return &engine.Engine{BinaryPath: "offline-fake"}, nil
		},
		resolvePack: runner.ResolvePack,
		newRunner: func(_ *engine.Engine, options runner.Options) packRunner {
			fake.options = options
			return fake
		},
		detectRun: func(_ context.Context, options runenv.Options) spec.RunMetadata {
			return spec.RunMetadata{ConUnitVersion: options.Version, Pack: options.Pack, PackID: options.PackID, Platform: options.Platform, StartedAt: fixedClock}
		},
		now: func() time.Time { return fixedClock },
	}
}

func writeImageListFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "images.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write images file: %v", err)
	}
	return path
}

func TestCLIRunTestCommandOffline(t *testing.T) {
	t.Run("boolean fix flag does not consume the image argument", func(t *testing.T) {
		fake := &fakePackRunner{}
		output := filepath.Join(t.TempDir(), "result.json")
		code := runTestCommandWithDeps([]string{
			"--fix",
			"example:latest",
			"--pack", "hygiene",
			"--format", "json",
			"--output", output,
		}, offlineCommandDeps(fake))

		if code != 0 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 0", code)
		}
		if len(fake.calls) != 1 || fake.calls[0] != "example:latest" {
			t.Fatalf("RunPack calls = %v, want [example:latest]", fake.calls)
		}
		if _, err := os.Stat(output); err != nil {
			t.Fatalf("expected JSON report at %s: %v", output, err)
		}
	})

	t.Run("rejects invalid flags", func(t *testing.T) {
		fake := &fakePackRunner{}
		code := runTestCommandWithDeps([]string{"--unknown", "example:latest"}, offlineCommandDeps(fake))
		if code != 2 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 2", code)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("RunPack called after invalid flags: %v", fake.calls)
		}
	})

	t.Run("rejects unsupported formats", func(t *testing.T) {
		fake := &fakePackRunner{}
		code := runTestCommandWithDeps([]string{"example:latest", "--format", "yaml"}, offlineCommandDeps(fake))
		if code != 2 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 2", code)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("RunPack called after invalid format: %v", fake.calls)
		}
	})

	t.Run("returns failure when report cannot be written", func(t *testing.T) {
		fake := &fakePackRunner{}
		output := filepath.Join(t.TempDir(), "result.json")
		if err := os.Mkdir(output, 0755); err != nil {
			t.Fatalf("create unwritable report destination: %v", err)
		}
		code := runTestCommandWithDeps([]string{
			"example:latest",
			"--format", "json",
			"--output", output,
		}, offlineCommandDeps(fake))
		if code != 1 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 1", code)
		}
	})

	t.Run("returns failure and writes JSON for unverified results", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "unverified.json")
		fake := &fakePackRunner{
			results: map[string]*spec.SuiteResult{
				"example:latest": {
					ImageName:  "example:latest",
					Total:      1,
					Unverified: 1,
					Results: []spec.TestResult{{
						TestID:  "SUP-02",
						Outcome: spec.OutcomeUnverified,
						Message: "No verifier configured",
					}},
				},
			},
		}
		code := runTestCommandWithDeps([]string{
			"example:latest",
			"--format", "json",
			"--output", output,
		}, offlineCommandDeps(fake))
		if code != 1 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 1 for unverified results", code)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatalf("read unverified JSON report: %v", err)
		}
		if !strings.Contains(string(data), `"UNVERIFIED"`) {
			t.Fatalf("JSON report does not distinguish unverified results: %s", data)
		}
	})

	t.Run("forwards explicit signature trust configuration", func(t *testing.T) {
		fake := &fakePackRunner{}
		code := runTestCommandWithDeps([]string{
			"example:latest",
			"--pack", "hygiene",
			"--cosign-key", "/keys/cosign.pub",
		}, offlineCommandDeps(fake))
		if code != 0 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 0", code)
		}
		if fake.signatureConfig == nil || fake.signatureConfig.TrustPolicy.KeyPath != "/keys/cosign.pub" || fake.signatureConfig.Verifier == nil {
			t.Fatalf("signature configuration was not forwarded: %+v", fake.signatureConfig)
		}
	})

	t.Run("rejects incomplete keyless signature policy", func(t *testing.T) {
		fake := &fakePackRunner{}
		code := runTestCommandWithDeps([]string{
			"example:latest",
			"--certificate-identity", "builder@example.test",
		}, offlineCommandDeps(fake))
		if code != 2 {
			t.Fatalf("runTestCommandWithDeps() = %d, want 2 for invalid signature policy", code)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("RunPack called after invalid signature policy: %v", fake.calls)
		}
	})
}

func TestCLIConsoleOutputIsCompactUnlessVerbose(t *testing.T) {
	for _, test := range []struct {
		name    string
		verbose bool
	}{
		{name: "compact default"},
		{name: "verbose details", verbose: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakePackRunner{
				results: map[string]*spec.SuiteResult{
					"example:latest": {
						ImageName: "example:latest",
						SuiteName: "offline hygiene pack",
						Total:     2,
						Passed:    1,
						Failed:    1,
						Results: []spec.TestResult{
							{
								TestID:   "SPEC-02",
								TestName: "Entrypoint",
								Tier:     spec.TierSpec,
								Passed:   true,
								Message:  "Entrypoint is configured",
							},
							{
								TestID:      "SPEC-01",
								TestName:    "Non-Root",
								Tier:        spec.TierSpec,
								Outcome:     spec.OutcomeFail,
								Message:     "Image runs as root",
								Explanation: "Root breakout risk",
								Remediation: "Set a non-root USER",
							},
						},
					},
				},
			}
			args := []string{"example:latest", "--pack", "hygiene"}
			if test.verbose {
				args = append(args, "--verbose")
			}
			code, stdout, stderr := captureCLIStreams(t, func() int {
				return runTestCommandWithDeps(args, offlineCommandDeps(fake))
			})
			if code != 1 {
				t.Fatalf("runTestCommandWithDeps() = %d, want 1 for a failure", code)
			}
			if !strings.Contains(stdout, "│ STATUS     [ FAIL ]") ||
				!strings.Contains(stdout, "1/2 checks passed") ||
				!strings.Contains(stdout, "[ PASS ] [SPEC-02] Entrypoint") {
				t.Errorf("console report is missing its structured summary or passing check: %s", stdout)
			}
			if strings.Contains(stdout, "Root breakout risk") != test.verbose {
				t.Errorf("verbose explanation visibility = %t, output: %s", test.verbose, stdout)
			}
			if strings.Contains(stdout, "Entrypoint is configured") != test.verbose {
				t.Errorf("verbose passing-check detail visibility = %t, output: %s", test.verbose, stdout)
			}
			if !strings.Contains(stderr, "Running ") || !strings.Contains(stderr, "example:latest with offline-fake") {
				t.Errorf("expected concise run context on stderr, got: %s", stderr)
			}
			if strings.Contains(stderr, "CONUNIT · IMAGE REPORT") || strings.Contains(stdout, "[PROGRESS]") {
				t.Errorf("report and progress output are mixed across streams: stdout=%s stderr=%s", stdout, stderr)
			}
		})
	}
}

func TestCLIMachineReportKeepsStdoutClean(t *testing.T) {
	output := filepath.Join(t.TempDir(), "result.json")
	code, stdout, stderr := captureCLIStreams(t, func() int {
		return runTestCommandWithDeps([]string{
			"example:latest",
			"--format", "json",
			"--output", output,
		}, offlineCommandDeps(&fakePackRunner{}))
	})
	if code != 0 {
		t.Fatalf("runTestCommandWithDeps() = %d, want 0", code)
	}
	if stdout != "" {
		t.Errorf("machine-readable output mode should leave stdout empty, got: %q", stdout)
	}
	if !strings.Contains(stderr, "Running ") || !strings.Contains(stderr, "Wrote JSON report:") {
		t.Errorf("expected progress and report path on stderr, got: %s", stderr)
	}
}

func captureCLIStreams(t *testing.T, run func() int) (int, string, string) {
	t.Helper()
	originalStdout, originalStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		t.Fatalf("create stderr pipe: %v", err)
	}

	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	code := run()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = originalStdout, originalStderr

	stdout, stdoutErr := io.ReadAll(stdoutReader)
	stderr, stderrErr := io.ReadAll(stderrReader)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	if stdoutErr != nil {
		t.Errorf("read captured stdout: %v", stdoutErr)
	}
	if stderrErr != nil {
		t.Errorf("read captured stderr: %v", stderrErr)
	}
	return code, string(stdout), string(stderr)
}
func TestReadImageListReturnsScannerErrors(t *testing.T) {
	_, err := readImageList(strings.NewReader(strings.Repeat("x", bufio.MaxScanTokenSize+1)))
	if err == nil {
		t.Fatal("readImageList() succeeded for a line exceeding the scanner limit")
	}
}

func TestCLIRunEvalCommandOffline(t *testing.T) {
	t.Run("writes JSON and Markdown summaries", func(t *testing.T) {
		images := writeImageListFile(t, "# test image\n\nexample:latest\n")
		outDir := filepath.Join(t.TempDir(), "results")
		fake := &fakePackRunner{}

		code := runEvalCommandWithDeps([]string{
			"--images", images,
			"--pack", "hygiene",
			"--out-dir", outDir,
		}, offlineCommandDeps(fake))
		if code != 0 {
			t.Fatalf("runEvalCommandWithDeps() = %d, want 0", code)
		}
		if len(fake.calls) != 1 || fake.calls[0] != "example:latest" {
			t.Fatalf("RunPack calls = %v, want [example:latest]", fake.calls)
		}
		for _, name := range []string{"empirical_study.json", "EMPIRICAL_SUMMARY.md", "ATTRITION_REPORT.md"} {
			if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
				t.Errorf("expected report %s: %v", name, err)
			}
		}
		logEntries, err := os.ReadDir(filepath.Join(outDir, "logs"))
		if err != nil || len(logEntries) == 0 {
			t.Errorf("expected diagnostic logs in results/logs: %v", err)
		}
	})

	t.Run("rejects invalid flags", func(t *testing.T) {
		fake := &fakePackRunner{}
		code := runEvalCommandWithDeps([]string{"--unknown"}, offlineCommandDeps(fake))
		if code != 2 {
			t.Fatalf("runEvalCommandWithDeps() = %d, want 2", code)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("RunPack called after invalid flags: %v", fake.calls)
		}
	})

	t.Run("returns a usage error for scanner errors", func(t *testing.T) {
		images := writeImageListFile(t, strings.Repeat("x", bufio.MaxScanTokenSize+1))
		fake := &fakePackRunner{}
		code := runEvalCommandWithDeps([]string{
			"--images", images,
			"--out-dir", filepath.Join(t.TempDir(), "results"),
		}, offlineCommandDeps(fake))
		if code != spec.ExitUsage {
			t.Fatalf("runEvalCommandWithDeps() = %d, want %d", code, spec.ExitUsage)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("RunPack called after scanner error: %v", fake.calls)
		}
	})

	t.Run("returns incomplete and preserves attrition records after a partial run", func(t *testing.T) {
		images := writeImageListFile(t, "broken:latest\nworking:latest\n")
		outDir := filepath.Join(t.TempDir(), "results")
		fake := &fakePackRunner{
			errors: map[string]error{"broken:latest": errors.New("simulated evaluation failure")},
		}

		code := runEvalCommandWithDeps([]string{
			"--images", images,
			"--out-dir", outDir,
		}, offlineCommandDeps(fake))
		if code != spec.ExitIncomplete {
			t.Fatalf("runEvalCommandWithDeps() = %d, want %d for an incomplete run", code, spec.ExitIncomplete)
		}
		if len(fake.calls) != 2 {
			t.Fatalf("RunPack calls = %v, want both images to be attempted", fake.calls)
		}
		jsonSummary, err := os.ReadFile(filepath.Join(outDir, "empirical_study.json"))
		if err != nil {
			t.Fatalf("read partial JSON summary: %v", err)
		}
		if !strings.Contains(string(jsonSummary), "working:latest") || !strings.Contains(string(jsonSummary), "broken:latest") {
			t.Fatalf("partial JSON summary does not record both attempted images: %s", jsonSummary)
		}
		if !strings.Contains(string(jsonSummary), `"status": "EXECUTION_ERROR"`) {
			t.Fatalf("partial JSON summary does not record EXECUTION_ERROR status: %s", jsonSummary)
		}
	})
	t.Run("findings alone do not change the exit code and unverified counts are recorded", func(t *testing.T) {
		images := writeImageListFile(t, "example:latest\n")
		outDir := filepath.Join(t.TempDir(), "results")
		fake := &fakePackRunner{
			results: map[string]*spec.SuiteResult{
				"example:latest": {
					ImageName:  "example:latest",
					Total:      1,
					Unverified: 1,
					Results: []spec.TestResult{{
						TestID:  "SUP-02",
						Outcome: spec.OutcomeUnverified,
						Message: "No verifier configured",
					}},
				},
			},
		}
		code := runEvalCommandWithDeps([]string{
			"--images", images,
			"--out-dir", outDir,
		}, offlineCommandDeps(fake))
		if code != spec.ExitOK {
			t.Fatalf("runEvalCommandWithDeps() = %d, want %d: findings must not affect eval unless --fail-on-findings is set", code, spec.ExitOK)
		}
		summary, err := os.ReadFile(filepath.Join(outDir, "empirical_study.json"))
		if err != nil {
			t.Fatalf("read evaluation JSON: %v", err)
		}
		if !strings.Contains(string(summary), `"unverified": 1`) || !strings.Contains(string(summary), `"UNVERIFIED"`) {
			t.Fatalf("evaluation JSON does not record unverified status: %s", summary)
		}
	})

	t.Run("returns failure when either report cannot be written", func(t *testing.T) {
		for _, reportName := range []string{"empirical_study.json", "EMPIRICAL_SUMMARY.md"} {
			t.Run(reportName, func(t *testing.T) {
				images := writeImageListFile(t, "example:latest\n")
				outDir := filepath.Join(t.TempDir(), "results")
				if err := os.MkdirAll(filepath.Join(outDir, reportName), 0755); err != nil {
					t.Fatalf("create report destination directory: %v", err)
				}

				code := runEvalCommandWithDeps([]string{
					"--images", images,
					"--out-dir", outDir,
				}, offlineCommandDeps(&fakePackRunner{}))
				if code != spec.ExitIncomplete {
					t.Fatalf("runEvalCommandWithDeps() = %d, want %d", code, spec.ExitIncomplete)
				}
			})
		}
	})

	t.Run("fails before evaluating when the output directory cannot be created", func(t *testing.T) {
		images := writeImageListFile(t, "example:latest\n")
		outPath := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(outPath, []byte("file"), 0644); err != nil {
			t.Fatalf("create output-path blocker: %v", err)
		}
		fake := &fakePackRunner{}
		code := runEvalCommandWithDeps([]string{
			"--images", images,
			"--out-dir", filepath.Join(outPath, "results"),
		}, offlineCommandDeps(fake))
		if code != spec.ExitIncomplete {
			t.Fatalf("runEvalCommandWithDeps() = %d, want %d", code, spec.ExitIncomplete)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("RunPack calls = %v, want no evaluation when results cannot be stored", fake.calls)
		}
	})
}
