package spec_test

import (
	"encoding/json"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

func TestTierStringRepresentation(t *testing.T) {
	cases := []struct {
		tier     spec.Tier
		expected string
	}{
		{spec.TierSpec, "Tier 1: Specification"},
		{spec.TierFilesystem, "Tier 2: Filesystem Hygiene"},
		{spec.TierContract, "Tier 3: Execution Contract"},
		{spec.TierSupplyChain, "Tier 4: Supply Chain"},
		{spec.Tier(99), "Unknown Tier"},
	}

	for _, tc := range cases {
		if tc.tier.String() != tc.expected {
			t.Errorf("Tier %d: expected '%s', got '%s'", tc.tier, tc.expected, tc.tier.String())
		}
	}
}

func TestSuiteResultSerialization(t *testing.T) {
	res := spec.SuiteResult{
		ImageName:    "test:latest",
		ImageDigest:  "sha256:manifest",
		ConfigDigest: "sha256:config",
		Platform:     "linux/amd64",
		SuiteName:    "Security Suite",
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
			},
			{
				TestID:   "FS-01",
				TestName: "Cache Check",
				Tier:     spec.TierFilesystem,
				Passed:   false,
				Message:  "Cache exists",
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

	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Failed to serialize SuiteResult: %v", err)
	}

	var parsed spec.SuiteResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse serialized SuiteResult: %v", err)
	}

	if parsed.ImageName != "test:latest" || parsed.Passed != 1 || parsed.Failed != 1 || parsed.Unverified != 1 {
		t.Errorf("Deserialized mismatch: %+v", parsed)
	}
	if parsed.ImageDigest != "sha256:manifest" || parsed.ConfigDigest != "sha256:config" || parsed.Platform != "linux/amd64" {
		t.Errorf("Deserialized image identity mismatch: %+v", parsed)
	}
	if got := parsed.Results[2].EffectiveOutcome(); got != spec.OutcomeUnverified {
		t.Errorf("Unverified result outcome = %s, want %s", got, spec.OutcomeUnverified)
	}
	if parsed.Results[2].ImageDigest != parsed.ImageDigest || parsed.Results[2].ConfigDigest != parsed.ConfigDigest || parsed.Results[2].Platform != parsed.Platform {
		t.Errorf("Assertion result is not bound to suite image identity: %+v", parsed.Results[2])
	}
}
