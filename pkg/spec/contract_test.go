package spec

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStudyEnvelopeRoundTrip(t *testing.T) {
	rootless := false
	exit := 1
	study := Study{
		SchemaVersion: SchemaVersion,
		Run: RunMetadata{
			ConUnitVersion: "test",
			Rootless:       &rootless,
			Virtualization: "aws-nitro-kvm",
			Tools:          map[string]string{"syft": "absent"},
			StartedAt:      time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),
		},
		Images: []*SuiteResult{{
			ImageName:    "docker.io/library/alpine@sha256:abc",
			RequestedRef: "docker.io/library/alpine@sha256:abc",
			ImageSource:  SourceLocalStore,
			Status:       StatusCompleted,
			Results: []TestResult{{
				TestID:  "EXEC-02",
				Outcome: OutcomeUnverified,
				Reason:  ReasonBaselineFailed,
				Evidence: &Evidence{
					BaselineState:    "exited_nonzero",
					BaselineExitCode: &exit,
				},
				Rule: &RuleMeta{Standard: "CIS Docker Benchmark", ControlID: "5.3", Mapping: MappingApproximate, Scope: ScopeRuntimeCompat},
			}},
		}},
	}

	data, err := json.Marshal(study)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Study
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q, want %q", decoded.SchemaVersion, SchemaVersion)
	}
	got := decoded.Images[0].Results[0]
	if got.Reason != ReasonBaselineFailed || got.Evidence == nil || *got.Evidence.BaselineExitCode != 1 {
		t.Fatalf("result did not round trip: %+v", got)
	}
	if got.Rule == nil || got.Rule.Mapping != MappingApproximate {
		t.Fatalf("rule metadata did not round trip: %+v", got.Rule)
	}
	if decoded.Run.Rootless == nil || *decoded.Run.Rootless {
		t.Fatalf("explicit rootless=false must survive a round trip")
	}
}

func TestLegacyResultStillDecodes(t *testing.T) {
	legacy := `[{"image_name":"alpine:3","results":[{"test_id":"SPEC-01","passed":false}]}]`
	var results []SuiteResult
	if err := json.Unmarshal([]byte(legacy), &results); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if results[0].Results[0].EffectiveOutcome() != OutcomeFail {
		t.Fatalf("legacy result must still map to FAIL")
	}
}
