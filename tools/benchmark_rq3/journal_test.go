package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJournalWritesOneLinePerTrialImmediately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "rq3_journal.jsonl")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for i := 1; i <= 3; i++ {
		rec := TrialRecord{Image: "alpine", Kind: KindTimed, Iteration: i, Status: "COMPLETED", TotalNs: int64(i) * 1_000_001}
		if err := j.Record(rec); err != nil {
			t.Fatal(err)
		}
		// The line is on disk before the next trial starts, without closing the file.
		got, err := ReadJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != i || got[i-1].TotalNs != int64(i)*1_000_001 {
			t.Fatalf("after %d records the journal holds %+v", i, got)
		}
	}
	data, _ := os.ReadFile(path)
	if lines := strings.Count(string(data), "\n"); lines != 3 {
		t.Errorf("lines = %d, want 3", lines)
	}
}

func TestJournalRotatesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rq3_journal.jsonl")
	old := `{"image":"old","kind":"timed","iteration":1,"status":"COMPLETED"}` + "\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Record(TrialRecord{Image: "new", Kind: KindTimed, Iteration: 1, Status: "COMPLETED"}); err != nil {
		t.Fatal(err)
	}
	rotated, err := os.ReadFile(path + ".20260102T030405Z")
	if err != nil || string(rotated) != old {
		t.Fatalf("the earlier journal must be kept intact: %v %q", err, rotated)
	}
	got, _ := ReadJournal(path)
	if len(got) != 1 || got[0].Image != "new" {
		t.Errorf("new journal = %+v", got)
	}
}

func TestReadJournalIgnoresATruncatedLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	content := `{"image":"a","kind":"timed","iteration":1,"status":"COMPLETED"}` + "\n" + `{"image":"a","kind":"timed","it`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadJournal(path)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, err %v: a crash may truncate the last line only", got, err)
	}
	bad := `{"image":"a"` + "\n" + `{"image":"b","kind":"timed","iteration":1,"status":"COMPLETED"}` + "\n"
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJournal(path); err == nil {
		t.Error("a corrupt line in the middle must be reported")
	}
}

func TestRunAllJournalsEveryTrialIncludingWarmupAndFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	h := newFake(map[string][]step{
		"alpine": okSteps(time.Second),
		"nginx":  {{err: os.ErrNotExist}},
	})
	s := testSetup(t, []string{"alpine", "nginx"}, 0)
	if _, err := RunAll(context.Background(), h, j, s); err != nil {
		t.Fatal(err)
	}
	j.Close()
	trials, err := ReadJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	failed := 0
	for _, tr := range trials {
		counts[tr.Image+"/"+tr.Kind]++
		if !tr.OK() {
			failed++
		}
	}
	if counts["alpine/warmup"] != 1 || counts["alpine/timed"] != 5 {
		t.Errorf("alpine lines = %v", counts)
	}
	if counts["nginx/warmup"]+counts["nginx/timed"] != 3 || failed != 3 {
		t.Errorf("nginx lines = %v, failed %d (dropped after 3 consecutive failures)", counts, failed)
	}
}
