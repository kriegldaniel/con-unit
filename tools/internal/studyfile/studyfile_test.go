package studyfile

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestDecodeEnvelope(t *testing.T) {
	study := spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run:           spec.RunMetadata{ConUnitVersion: "test", StartedAt: time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC), EngineName: "podman"},
		Images: []*spec.SuiteResult{
			{ImageName: "a", RequestedRef: "a@sha256:1", Status: spec.StatusCompleted},
			{ImageName: "b", RequestedRef: "b@sha256:2", Status: spec.StatusRateLimited},
			{ImageName: "c", RequestedRef: "c@sha256:3"},
		},
	}
	l, err := Decode(mustJSON(t, study))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if l.Legacy {
		t.Error("envelope decoded as legacy")
	}
	if l.Study.Run.EngineName != "podman" || len(l.Records) != 3 {
		t.Errorf("unexpected decode: run=%+v records=%d", l.Study.Run, len(l.Records))
	}
	if len(l.SHA256) != 64 {
		t.Errorf("sha256 length = %d", len(l.SHA256))
	}
	if !l.Completed(l.Records[0]) || l.Completed(l.Records[1]) {
		t.Error("Completed misclassifies explicit statuses")
	}
	if got := l.Status(l.Records[2]); got != StatusUnspecified {
		t.Errorf("envelope record without status = %q, want %q", got, StatusUnspecified)
	}
	if l.Completed(l.Records[2]) {
		t.Error("envelope record without status must not be COMPLETED")
	}
}

func TestDecodeLegacyArray(t *testing.T) {
	legacy := []spec.SuiteResult{
		{ImageName: "old-1", Results: []spec.TestResult{{TestID: "SPEC-01", Passed: true}}},
		{ImageName: "old-2", Status: "COMPLETED"},
		{ImageName: "old-3", Status: "TIMEOUT"},
	}
	l, err := Decode(mustJSON(t, legacy))
	if err != nil {
		t.Fatalf("Decode legacy: %v", err)
	}
	if !l.Legacy || l.Study.SchemaVersion != "" {
		t.Errorf("legacy flags wrong: legacy=%v schema=%q", l.Legacy, l.Study.SchemaVersion)
	}
	if l.Study.Run.ConUnitVersion != "" || !l.Study.Run.StartedAt.IsZero() {
		t.Errorf("legacy run metadata must be unknown, got %+v", l.Study.Run)
	}
	if !l.Completed(l.Records[0]) || !l.Completed(l.Records[1]) || l.Completed(l.Records[2]) {
		t.Error("legacy status handling wrong: empty status counts as COMPLETED, TIMEOUT does not")
	}
	found := false
	for _, w := range l.Warnings {
		if strings.Contains(w, "legacy") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a legacy warning, got %v", l.Warnings)
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := map[string]string{
		"empty":           "  \n",
		"not json":        "hello",
		"missing schema":  `{"images": []}`,
		"null image":      `{"schema_version":"2","images":[null]}`,
		"truncated array": `[{"image_name":`,
	}
	for name, in := range cases {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSchemaVersionMismatchWarns(t *testing.T) {
	l, err := Decode([]byte(`{"schema_version":"99","images":[]}`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(l.Warnings) == 0 || !strings.Contains(l.Warnings[0], "schema_version") {
		t.Errorf("expected schema warning, got %v", l.Warnings)
	}
}

func TestDuplicateRecordsLastWins(t *testing.T) {
	study := spec.Study{SchemaVersion: spec.SchemaVersion, Images: []*spec.SuiteResult{
		{ImageName: "x", RequestedRef: "x@sha256:1", Status: spec.StatusRateLimited},
		{ImageName: "y", RequestedRef: "y@sha256:2", Status: spec.StatusCompleted},
		{ImageName: "x", RequestedRef: "x@sha256:1", Status: spec.StatusCompleted},
	}}
	l, err := Decode(mustJSON(t, study))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(l.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(l.Records))
	}
	if l.Records[0].Status != spec.StatusCompleted || RecordKey(l.Records[0]) != "x@sha256:1" {
		t.Errorf("last record must win and keep first position: %+v", l.Records[0])
	}
	if len(l.Warnings) != 1 || !strings.Contains(l.Warnings[0], "2 records") {
		t.Errorf("expected one duplicate warning, got %v", l.Warnings)
	}
}

func TestUniqueResults(t *testing.T) {
	img := &spec.SuiteResult{Results: []spec.TestResult{
		{TestID: "A", Outcome: spec.OutcomePass},
		{TestID: "B", Outcome: spec.OutcomeFail},
		{TestID: "A", Outcome: spec.OutcomeFail},
		{TestID: "A", Outcome: spec.OutcomeFail},
	}}
	res, repeated := UniqueResults(img)
	if len(res) != 2 || res[0].Outcome != spec.OutcomePass {
		t.Errorf("first result per ID must be kept: %+v", res)
	}
	if len(repeated) != 1 || repeated[0] != "A" {
		t.Errorf("repeated = %v, want [A]", repeated)
	}
}

func TestRepoName(t *testing.T) {
	cases := map[string]string{
		"index.docker.io/library/nginx@sha256:abc":      "nginx",
		"docker.io/library/nginx:1.30":                  "nginx",
		"nginx:1.30.6-alpine":                           "nginx",
		"alpine":                                        "alpine",
		"rocket.chat:8.9.0":                             "rocket.chat",
		"eclipse-mosquitto:2.1.2-alpine":                "eclipse-mosquitto",
		"bitnami/redis:7":                               "bitnami/redis",
		"localhost:5000/team/app:v1":                    "team/app",
		"public.ecr.aws/docker/library/nginx@sha256:ab": "docker/library/nginx",
		"library/ubuntu@sha256:ab":                      "ubuntu",
	}
	for in, want := range cases {
		if got := RepoName(in); got != want {
			t.Errorf("RepoName(%q) = %q, want %q", in, got, want)
		}
	}
}
