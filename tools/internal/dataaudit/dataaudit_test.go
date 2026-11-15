package dataaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func valid() *Audit {
	return &Audit{
		SchemaVersion: SchemaVersion,
		Tool:          "pin_dataset",
		Frame:         Frame{Repository: "docker-library/official-images", Commit: "abc123", Date: "2026-11-14"},
		Input:         ListInfo{Path: "in.txt", Entries: 5},
		Outputs:       Outputs{PinnedTxt: ListInfo{Path: "out.txt", Entries: 3}},
		Counts:        Counts{Candidates: 5, Pinned: 3, Excluded: 1, Failed: 1},
		ExclusionLog: []Exclusion{
			{OriginalTag: "a:1", Status: "EXCLUDED_SINGLE_ARCH", Reason: "single arch"},
			{OriginalTag: "b:1", Status: "FAILED", Reason: "fetch error"},
		},
	}
}

func TestValidateAcceptsConsistentAudit(t *testing.T) {
	if p := valid().Validate(); len(p) != 0 {
		t.Errorf("unexpected problems: %v", p)
	}
}

func TestValidateReportsInconsistencies(t *testing.T) {
	a := valid()
	a.Counts.Pinned = 4
	a.ExclusionLog = a.ExclusionLog[:1]
	a.Outputs.PinnedTxt.Entries = 2
	a.SchemaVersion = "0"
	problems := strings.Join(a.Validate(), "\n")
	for _, want := range []string{"schema_version", "do not reconcile", "exclusion_log", "pinned list has"} {
		if !strings.Contains(problems, want) {
			t.Errorf("missing problem %q in:\n%s", want, problems)
		}
	}
}

func TestFrameRecorded(t *testing.T) {
	if !(Frame{Commit: "abc", Date: "2026-01-01"}).Recorded() {
		t.Error("complete frame must be recorded")
	}
	for _, f := range []Frame{{}, {Commit: "abc"}, {Commit: Unrecorded, Date: Unrecorded}} {
		if f.Recorded() {
			t.Errorf("frame %+v must not count as recorded", f)
		}
	}
}

func TestLoadRoundTripAndGrouping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.json")
	data, err := json.Marshal(valid())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	statuses, counts := a.ExclusionsByStatus()
	if strings.Join(statuses, ",") != "EXCLUDED_SINGLE_ARCH,FAILED" || counts["FAILED"] != 1 {
		t.Errorf("grouping = %v %v", statuses, counts)
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file must fail")
	}
}
