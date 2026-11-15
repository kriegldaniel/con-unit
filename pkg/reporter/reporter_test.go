package reporter_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/reporter"
	"github.com/con-unit/con-unit/pkg/spec"
)

func TestWriteJUnitXML(t *testing.T) {
	tempDir := t.TempDir()
	xmlFile := filepath.Join(tempDir, "junit.xml")

	res := &spec.SuiteResult{
		ImageName:    "test-image:latest",
		ImageDigest:  "sha256:manifest",
		ConfigDigest: "sha256:config",
		Platform:     "linux/amd64",
		SuiteName:    "Sample Suite",
		Duration:     2 * time.Second,
		Total:        3,
		Passed:       1,
		Failed:       1,
		Unverified:   1,
		Results: []spec.TestResult{
			{
				TestID:   "SPEC-01",
				TestName: "User Check",
				Tier:     spec.TierSpec,
				Passed:   true,
				Duration: 50 * time.Millisecond,
			},
			{
				TestID:      "FS-01",
				TestName:    "Cache Check",
				Tier:        spec.TierFilesystem,
				Passed:      false,
				Duration:    100 * time.Millisecond,
				Message:     "Cache found",
				Remediation: "Clean cache",
			},
			{
				TestID:       "SUP-02",
				TestName:     "Signature Check",
				Tier:         spec.TierSupplyChain,
				Outcome:      spec.OutcomeUnverified,
				Passed:       false,
				ImageDigest:  "sha256:manifest",
				ConfigDigest: "sha256:config",
				Platform:     "linux/amd64",
				Message:      "No verifier configured",
			},
		},
	}

	if err := reporter.WriteJUnitXML(xmlFile, res); err != nil {
		t.Fatalf("WriteJUnitXML returned error: %v", err)
	}

	data, err := os.ReadFile(xmlFile)
	if err != nil {
		t.Fatalf("Failed to read generated XML: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Generated XML file is empty")
	}
	xml := string(data)
	for _, expected := range []string{`tests="3"`, `failures="1"`, `skipped="1"`, `<skipped`, `UNVERIFIED`, `sha256:manifest`, `sha256:config`, `linux/amd64`} {
		if !strings.Contains(xml, expected) {
			t.Errorf("JUnit XML does not contain %q: %s", expected, xml)
		}
	}
}

func TestPrintConsoleUsesUnverifiedStatusWhenNoFindingsFail(t *testing.T) {
	var buf bytes.Buffer
	reporter.PrintConsole(&buf, &spec.SuiteResult{
		ImageName:  "test:latest",
		SuiteName:  "Evidence Suite",
		Total:      1,
		Unverified: 1,
		Results: []spec.TestResult{{
			TestID:   "SUP-02",
			TestName: "Signature Check",
			Tier:     spec.TierSupplyChain,
			Outcome:  spec.OutcomeUnverified,
			Message:  "No verifier configured",
		}},
	})
	if !strings.Contains(buf.String(), "│ STATUS     [ UNVERIFIED ]") {
		t.Fatalf("Expected console status to be unverified, got: %s", buf.String())
	}
}

func TestPrintConsole(t *testing.T) {
	var buf bytes.Buffer
	res := &spec.SuiteResult{
		ImageName:  "test-app:v1.0",
		SuiteName:  "CIS Benchmark",
		Duration:   500 * time.Millisecond,
		Total:      3,
		Passed:     1,
		Failed:     1,
		Unverified: 1,
		Results: []spec.TestResult{
			{
				TestID:   "SPEC-02",
				TestName: "Entrypoint",
				Tier:     spec.TierSpec,
				Passed:   true,
				Duration: 10 * time.Millisecond,
				Message:  "Entrypoint is configured",
			},
			{
				TestID:      "SPEC-01",
				TestName:    "Non-Root",
				Tier:        spec.TierSpec,
				Passed:      false,
				Duration:    20 * time.Millisecond,
				Message:     "Runs as root",
				Explanation: "Root breakout risk",
				Remediation: "Add USER 10001",
				Reference:   "https://example.com/cis",
			},
			{
				TestID:   "SUP-02",
				TestName: "Signature Check",
				Tier:     spec.TierSupplyChain,
				Outcome:  spec.OutcomeUnverified,
				Message:  "No verifier configured",
			},
		},
	}

	reporter.PrintConsole(&buf, res)
	output := buf.String()

	if !strings.Contains(output, "│ STATUS     [ FAIL ]") || !strings.Contains(output, "│ IMAGE      test-app:v1.0") {
		t.Error("Expected a structured status and target header")
	}
	if !strings.Contains(output, "1/3 checks passed · 33.3%") {
		t.Error("Expected a clear pass summary")
	}
	if !strings.Contains(output, "╭─ PASSED CHECKS · 1") || !strings.Contains(output, "[ PASS ] [SPEC-02] Entrypoint") {
		t.Error("Passing checks should be listed by name by default")
	}
	if strings.Contains(output, "Entrypoint is configured") {
		t.Error("Passing check details should be hidden unless verbose output is requested")
	}
	if strings.Contains(output, "Root breakout risk") {
		t.Error("Explanations should be hidden unless verbose output is requested")
	}
	if !strings.Contains(output, "Add USER 10001") {
		t.Error("Expected remediation in output")
	}
	if !strings.Contains(output, "╭─ UNVERIFIED · 1") {
		t.Error("Expected a focused unverified section")
	}
	if strings.Contains(output, "\033[") {
		t.Error("Non-terminal output should not contain ANSI color escapes")
	}
}

func TestPrintConsoleVerboseIncludesPassesAndFindingContext(t *testing.T) {
	var buf bytes.Buffer
	res := &spec.SuiteResult{
		ImageName:   "test-app:v1.0",
		ImageDigest: "sha256:manifest",
		Platform:    "linux/amd64",
		SuiteName:   "CIS Benchmark",
		Duration:    500 * time.Millisecond,
		Total:       2,
		Passed:      1,
		Failed:      1,
		Results: []spec.TestResult{
			{
				TestID:   "SPEC-02",
				TestName: "Entrypoint",
				Tier:     spec.TierSpec,
				Passed:   true,
				Duration: 10 * time.Millisecond,
				Message:  "Entrypoint is configured",
			},
			{
				TestID:      "SPEC-01",
				TestName:    "Non-Root",
				Tier:        spec.TierSpec,
				Passed:      false,
				Duration:    20 * time.Millisecond,
				Message:     "Runs as root",
				Explanation: "Root breakout risk",
				Remediation: "Add USER 10001",
				Reference:   "https://example.com/cis",
			},
		},
	}

	reporter.PrintConsoleWithOptions(&buf, res, reporter.ConsoleOptions{Verbose: true})
	output := buf.String()
	for _, expected := range []string{
		"PASSED CHECKS · 1",
		"[ PASS ] [SPEC-02] Entrypoint",
		"Entrypoint is configured",
		"Why: Root breakout risk",
		"Reference: https://example.com/cis",
		"Tier: Tier 1: Specification",
		"Duration: 10ms",
		"│ IDENTITY   sha256:manifest (linux/amd64)",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("verbose console output does not contain %q: %s", expected, output)
		}
	}
}
func TestGenerateRemediationPatch(t *testing.T) {
	res := &spec.SuiteResult{
		ImageName: "python:3.11-slim",
		Results: []spec.TestResult{
			{TestID: "SPEC-01", Passed: false},
			{TestID: "SPEC-05", Passed: false},
			{TestID: "FS-01", Passed: false},
			{TestID: "FS-04", Passed: false},
			{TestID: "FS-05", Passed: false},
		},
	}

	patch := reporter.GenerateRemediationPatch(res)

	if !strings.Contains(patch, "USER 10001:10001") {
		t.Error("Expected USER 10001:10001 in remediation patch")
	}
	if !strings.Contains(patch, "EXPOSE 8080") {
		t.Error("Expected EXPOSE 8080 in remediation patch")
	}
	if !strings.Contains(patch, "chmod a-s") {
		t.Error("Expected SUID chmod fix in remediation patch")
	}
}

func TestWriteJSON(t *testing.T) {
	tempDir := t.TempDir()
	jsonFile := filepath.Join(tempDir, "results.json")

	res := spec.SuiteResult{
		ImageName:    "test:latest",
		ImageDigest:  "sha256:manifest",
		ConfigDigest: "sha256:config",
		Platform:     "linux/amd64",
		Total:        1,
		Unverified:   1,
		Results: []spec.TestResult{{
			TestID:       "SUP-02",
			TestName:     "Signature Check",
			Tier:         spec.TierSupplyChain,
			Outcome:      spec.OutcomeUnverified,
			ImageDigest:  "sha256:manifest",
			ConfigDigest: "sha256:config",
			Platform:     "linux/amd64",
		}},
	}

	if err := reporter.WriteJSON(jsonFile, res); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil || len(data) == 0 {
		t.Fatal("Failed reading generated JSON")
	}
	for _, expected := range []string{`"outcome": "UNVERIFIED"`, `"image_digest": "sha256:manifest"`, `"config_digest": "sha256:config"`, `"platform": "linux/amd64"`} {
		if !strings.Contains(string(data), expected) {
			t.Errorf("JSON report does not contain %q: %s", expected, data)
		}
	}
}
