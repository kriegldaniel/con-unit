package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

func record(ref, status string) *spec.SuiteResult {
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, Status: status, Total: 1}
}

func TestAppendFlushesEachRecordAndReadReturnsThemInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "journal.jsonl")
	writer, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer writer.Close()
	for _, r := range []*spec.SuiteResult{record("a", spec.StatusCompleted), record("b", spec.StatusTimeout)} {
		if err := writer.Append(r); err != nil {
			t.Fatalf("Append: %v", err)
		}
		// The record must be on disk before the next image starts.
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), `"requested_ref":"`+r.RequestedRef+`"`) {
			t.Fatalf("record %s not flushed: err=%v data=%q", r.RequestedRef, err, data)
		}
	}
	records, skipped, err := Read(path)
	if err != nil || skipped || len(records) != 2 || records[0].RequestedRef != "a" || records[1].RequestedRef != "b" {
		t.Fatalf("Read = %+v skipped=%t err=%v", records, skipped, err)
	}
	if strings.Count(readFile(t, path), "\n") != 2 {
		t.Fatal("journal must contain exactly one JSON line per record")
	}
}

func TestLatestKeepsLastRecordPerRequestedRef(t *testing.T) {
	latest := Latest([]*spec.SuiteResult{
		record("a", spec.StatusTimeout),
		record("b", spec.StatusCompleted),
		record("a", spec.StatusCompleted),
	})
	if len(latest) != 2 || !Completed(latest["a"]) || !Completed(latest["b"]) {
		t.Fatalf("Latest = %+v, want a and b both completed", latest)
	}
	retried := Latest([]*spec.SuiteResult{record("a", spec.StatusCompleted), record("a", spec.StatusRateLimited)})
	if Completed(retried["a"]) {
		t.Fatal("a later non-COMPLETED record must supersede an earlier COMPLETED one")
	}
}

func TestReadMissingJournalIsEmpty(t *testing.T) {
	records, skipped, err := Read(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil || skipped || len(records) != 0 {
		t.Fatalf("Read(absent) = %v %t %v", records, skipped, err)
	}
}

func TestTornFinalLineIsSkippedAndRepairedOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	good := `{"image_name":"a","requested_ref":"a","status":"COMPLETED"}` + "\n"
	torn := `{"image_name":"b","requested_ref":"b","sta`
	if err := os.WriteFile(path, []byte(good+torn), 0o644); err != nil {
		t.Fatal(err)
	}
	records, skipped, err := Read(path)
	if err != nil || !skipped || len(records) != 1 || records[0].RequestedRef != "a" {
		t.Fatalf("Read = %+v skipped=%t err=%v, want one record and a skipped tail", records, skipped, err)
	}
	writer, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := writer.Append(record("c", spec.StatusCompleted)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	_ = writer.Close()
	records, skipped, err = Read(path)
	if err != nil || skipped || len(records) != 2 || records[1].RequestedRef != "c" {
		t.Fatalf("after repair Read = %+v skipped=%t err=%v, want records a and c", records, skipped, err)
	}
}

func TestCompleteFinalLineWithoutNewlineIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	if err := os.WriteFile(path, []byte(`{"image_name":"a","requested_ref":"a","status":"COMPLETED"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writer, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = writer.Append(record("b", spec.StatusCompleted))
	_ = writer.Close()
	records, _, err := Read(path)
	if err != nil || len(records) != 2 {
		t.Fatalf("Read = %+v err=%v, want both records", records, err)
	}
}

func TestCorruptMiddleLineIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	content := `{"image_name":"a","requested_ref":"a"}` + "\nnot json\n" + `{"image_name":"c","requested_ref":"c"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path); err == nil {
		t.Fatal("a corrupt line in the middle of the journal must not be skipped silently")
	}
}

func TestRotateIfPresentMovesNonEmptyJournalAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if rotated, err := RotateIfPresent(path, now); err != nil || rotated != "" {
		t.Fatalf("absent journal: rotated=%q err=%v", rotated, err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if rotated, err := RotateIfPresent(path, now); err != nil || rotated != "" {
		t.Fatalf("empty journal must stay in place: rotated=%q err=%v", rotated, err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rotated, err := RotateIfPresent(path, now)
	if err != nil || !strings.HasSuffix(rotated, "journal.jsonl.20261114T120000Z.bak") {
		t.Fatalf("rotated=%q err=%v", rotated, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("original journal path must be free after rotation")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
