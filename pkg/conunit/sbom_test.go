package conunit_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

// fakeSyft installs an executable named syft in front of PATH. It records one
// line per invocation, prints a warning on standard error, and prints the given
// JSON (or fails with the given exit code) on standard output.
func fakeSyft(t *testing.T, output string, exitCode int) (calls func() int) {
	t.Helper()
	dir := t.TempDir()
	callFile := filepath.Join(dir, "calls")
	jsonFile := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(jsonFile, []byte(output), 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo run >> %q
echo "warning: some catalogers were skipped" >&2
if [ %d -ne 0 ]; then
  echo "boom: cannot read the image" >&2
  exit %d
fi
cat %q
`, callFile, exitCode, exitCode, jsonFile)
	if err := os.WriteFile(filepath.Join(dir, "syft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int {
		data, err := os.ReadFile(callFile)
		if err != nil {
			return 0
		}
		return strings.Count(string(data), "run")
	}
}

func singleResultFor(t *testing.T, c *conunit.Container, id string) spec.TestResult {
	t.Helper()
	var found []spec.TestResult
	for _, result := range c.Results {
		if result.TestID == id {
			found = append(found, result)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s has %d results, want exactly 1: %+v", id, len(found), c.Results)
	}
	return found[0]
}

const sbomWithViolations = `{"artifacts":[
  {"name":"busybox","licenses":["MIT"]},
  {"name":"nmap","licenses":["GPL-2.0"]}
]}`

func TestSyftRunsOncePerImageAndStderrDoesNotBreakTheInventory(t *testing.T) {
	calls := fakeSyft(t, sbomWithViolations, 0)
	cache := &conunit.SBOMCache{}
	c := &conunit.Container{Image: "sha256:" + strings.Repeat("c", 64), SBOM: cache}

	c.AssertSupplyChain().PackagesNotExist("nmap", "netcat")
	c.AssertSupplyChain().RequireApprovedLicenses()

	if got := calls(); got != 1 || cache.Runs() != 1 {
		t.Fatalf("Syft ran %d times (cache says %d), want once for SUP-01 and SUP-03 together", got, cache.Runs())
	}
	sup01 := singleResultFor(t, c, "SUP-01")
	if sup01.EffectiveOutcome() != spec.OutcomeFail || !strings.Contains(sup01.Message, "nmap") {
		t.Errorf("SUP-01 = %s %q, want a FAIL naming nmap (the warning on stderr must not corrupt the JSON)", sup01.EffectiveOutcome(), sup01.Message)
	}
	sup03 := singleResultFor(t, c, "SUP-03")
	if sup03.EffectiveOutcome() != spec.OutcomeFail || !strings.Contains(sup03.Message, "nmap: GPL-2.0") {
		t.Errorf("SUP-03 = %s %q, want a FAIL naming the GPL-2.0 package", sup03.EffectiveOutcome(), sup03.Message)
	}
}

func TestContainerWithoutACacheStillRunsSyftOnce(t *testing.T) {
	calls := fakeSyft(t, sbomWithViolations, 0)
	c := &conunit.Container{Image: "sha256:" + strings.Repeat("c", 64)}
	c.AssertSupplyChain().PackagesNotExist("nmap")
	c.AssertSupplyChain().RequireApprovedLicenses()
	if got := calls(); got != 1 {
		t.Fatalf("Syft ran %d times, want 1 with the private cache of the container", got)
	}
}

func TestSUP03IsOneResultWithAStableNameWhateverTheEvidence(t *testing.T) {
	cases := []struct {
		name        string
		sbom        string
		wantOutcome spec.Outcome
		wantReason  spec.Reason
		wantInMsg   []string
	}{
		{
			name:        "a violation with incomplete evidence is one FAIL",
			sbom:        `{"artifacts":[{"name":"zlib-bad","licenses":["GPL-3.0"]},{"name":"nolicense","licenses":[]},{"name":"ok","licenses":["MIT"]}]}`,
			wantOutcome: spec.OutcomeFail,
			wantInMsg:   []string{"zlib-bad: GPL-3.0", "nolicense: no license metadata"},
		},
		{
			name:        "incomplete evidence alone is UNVERIFIED",
			sbom:        `{"artifacts":[{"name":"nolicense","licenses":[]},{"name":"ok","licenses":["MIT"]}]}`,
			wantOutcome: spec.OutcomeUnverified,
			wantReason:  spec.ReasonEvidenceIncomplete,
			wantInMsg:   []string{"nolicense: no license metadata"},
		},
		{
			name:        "approved licenses pass",
			sbom:        `{"artifacts":[{"name":"ok","licenses":["MIT"]},{"name":"fine","licenses":["Apache-2.0"]}]}`,
			wantOutcome: spec.OutcomePass,
			wantInMsg:   []string{"All 2 SBOM packages"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeSyft(t, tc.sbom, 0)
			c := &conunit.Container{Image: "sha256:" + strings.Repeat("d", 64)}
			c.AssertSupplyChain().RequireApprovedLicenses()
			result := singleResultFor(t, c, "SUP-03")
			if result.TestName != "SPDX License Compliance" {
				t.Errorf("name = %q, want the one stable name", result.TestName)
			}
			if result.EffectiveOutcome() != tc.wantOutcome || result.Reason != tc.wantReason {
				t.Errorf("outcome/reason = %s/%s, want %s/%s", result.EffectiveOutcome(), result.Reason, tc.wantOutcome, tc.wantReason)
			}
			for _, want := range tc.wantInMsg {
				if !strings.Contains(result.Message, want) {
					t.Errorf("message %q lacks %q", result.Message, want)
				}
			}
		})
	}
}

func TestSUP03MessageDoesNotDependOnTheOrderOfSyftPackages(t *testing.T) {
	forward := `{"artifacts":[{"name":"b","licenses":["GPL-2.0"]},{"name":"a","licenses":["GPL-3.0"]},{"name":"d","licenses":[]},{"name":"c","licenses":[]}]}`
	reverse := `{"artifacts":[{"name":"c","licenses":[]},{"name":"d","licenses":[]},{"name":"a","licenses":["GPL-3.0"]},{"name":"b","licenses":["GPL-2.0"]}]}`
	messages := map[string]bool{}
	for _, sbom := range []string{forward, reverse} {
		fakeSyft(t, sbom, 0)
		c := &conunit.Container{Image: "sha256:" + strings.Repeat("e", 64)}
		c.AssertSupplyChain().RequireApprovedLicenses()
		messages[singleResultFor(t, c, "SUP-03").Message] = true
	}
	if len(messages) != 1 {
		t.Fatalf("the message depends on Syft's package order: %v", messages)
	}
}

func TestSyftFailureAndAbsenceGiveDifferentReasonsAndAreCachedOnce(t *testing.T) {
	t.Run("syft fails", func(t *testing.T) {
		calls := fakeSyft(t, "", 3)
		c := &conunit.Container{Image: "sha256:" + strings.Repeat("f", 64)}
		c.AssertSupplyChain().PackagesNotExist("nmap")
		c.AssertSupplyChain().RequireApprovedLicenses()
		if got := calls(); got != 1 {
			t.Errorf("a failed inventory was attempted %d times, want once", got)
		}
		for _, id := range []string{"SUP-01", "SUP-03"} {
			result := singleResultFor(t, c, id)
			if result.EffectiveOutcome() != spec.OutcomeUnverified || result.Reason != spec.ReasonEvidenceIncomplete {
				t.Errorf("%s = %s/%s, want UNVERIFIED/EVIDENCE_INCOMPLETE", id, result.EffectiveOutcome(), result.Reason)
			}
			if !strings.Contains(result.Message, "boom: cannot read the image") {
				t.Errorf("%s message %q must carry the stderr of Syft", id, result.Message)
			}
		}
	})

	t.Run("syft is not installed", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		c := &conunit.Container{Image: "sha256:" + strings.Repeat("f", 64)}
		c.AssertSupplyChain().PackagesNotExist("nmap")
		c.AssertSupplyChain().RequireApprovedLicenses()
		for _, id := range []string{"SUP-01", "SUP-03"} {
			result := singleResultFor(t, c, id)
			if result.EffectiveOutcome() != spec.OutcomeUnverified || result.Reason != spec.ReasonToolUnavailable {
				t.Errorf("%s = %s/%s, want UNVERIFIED/TOOL_UNAVAILABLE", id, result.EffectiveOutcome(), result.Reason)
			}
		}
	})
}

func TestSignatureUnverifiedResultsStateWhyTheyAreUnverified(t *testing.T) {
	immutable := "docker.io/library/app@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name       string
		container  *conunit.Container
		config     []conunit.SignatureVerificationConfig
		wantReason spec.Reason
	}{
		{"no trust policy configured", &conunit.Container{ImmutableImageRef: immutable}, nil, spec.ReasonNoTrustPolicy},
		{"no immutable reference", &conunit.Container{SignatureVerification: &conunit.SignatureVerificationConfig{
			Verifier: func(_ context.Context, _ string, _ conunit.SignatureTrustPolicy) error { return nil },
		}}, nil, spec.ReasonEvidenceIncomplete},
		{"invalid trust policy", &conunit.Container{ImmutableImageRef: immutable, SignatureVerification: &conunit.SignatureVerificationConfig{
			Verifier: func(_ context.Context, _ string, _ conunit.SignatureTrustPolicy) error { return nil },
		}}, nil, spec.ReasonNoTrustPolicy},
		{"verifier tool missing", &conunit.Container{ImmutableImageRef: immutable, SignatureVerification: &conunit.SignatureVerificationConfig{
			Verifier: func(_ context.Context, _ string, _ conunit.SignatureTrustPolicy) error {
				return &conunit.SignatureVerificationUnavailableError{Err: errors.New("cosign is not installed")}
			},
			TrustPolicy: conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"},
		}}, nil, spec.ReasonToolUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.AssertSupplyChain().HasCryptographicSignature(tc.config...)
			result := singleResultFor(t, tc.container, "SUP-02")
			if result.EffectiveOutcome() != spec.OutcomeUnverified || result.Reason != tc.wantReason {
				t.Errorf("SUP-02 = %s/%s, want UNVERIFIED/%s (%s)", result.EffectiveOutcome(), result.Reason, tc.wantReason, result.Message)
			}
		})
	}
}

func TestPortCheckMessagesDoNotDependOnMapOrder(t *testing.T) {
	ports := map[string]struct{}{}
	for _, declared := range []string{"22/tcp", "80/tcp", "443/tcp", "5005/tcp", "9229/tcp", "8080/tcp", "1024/udp", "53/udp"} {
		ports[declared] = struct{}{}
	}
	render := func() (string, string) {
		c := &conunit.Container{Inspect: &engine.ImageInspect{Config: engine.ImageConfig{ExposedPorts: ports}}}
		c.AssertSpec().RequireNonPrivilegedPorts()
		c.AssertSpec().DisallowDebugPorts()
		return singleResultFor(t, c, "SPEC-05").Message, singleResultFor(t, c, "SPEC-06").Message
	}
	firstFive, firstSix := render()
	for i := 0; i < 50; i++ {
		five, six := render()
		if five != firstFive || six != firstSix {
			t.Fatalf("messages changed between runs on the same image:\n%q\n%q\nvs\n%q\n%q", firstFive, firstSix, five, six)
		}
	}
}

func TestUnrecognizedPortDeclarationNamedFirstIsTheSortedOne(t *testing.T) {
	ports := map[string]struct{}{"zeta": {}, "alpha": {}, "mid": {}, "8080/tcp": {}}
	for i := 0; i < 30; i++ {
		c := &conunit.Container{Inspect: &engine.ImageInspect{Config: engine.ImageConfig{ExposedPorts: ports}}}
		c.AssertSpec().DisallowDebugPorts()
		message := singleResultFor(t, c, "SPEC-06").Message
		if !strings.Contains(message, `"alpha"`) {
			t.Fatalf("run %d did not name the first unrecognized declaration in sorted order: %s", i, message)
		}
		if strings.Contains(message, `"zeta"`) || strings.Contains(message, `"mid"`) {
			t.Fatalf("run %d did not name the first declaration in sorted order: %s", i, message)
		}
	}
}
