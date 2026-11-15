package oci

import (
	"archive/tar"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func asIndexTooLarge(t *testing.T, err error) *IndexTooLargeError {
	t.Helper()
	var tooLarge *IndexTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("error = %v, want *IndexTooLargeError", err)
	}
	return tooLarge
}

func TestIndexTooLargeErrorReportsWhatWasObservedInOneLayer(t *testing.T) {
	layer := makeTestLayer(t,
		testLayerEntry{name: "opt/one", mode: 0644, data: make([]byte, 10)},
		testLayerEntry{name: "opt/two", mode: 0644, data: make([]byte, 20)},
		testLayerEntry{name: "opt/three", mode: 0644, data: make([]byte, 30)},
	)
	idx, err := (&ImageReader{Image: makeTestImage(t, layer)}).streamAndIndexFilesystem(2)
	if idx != nil {
		t.Fatal("a limit error must not return a partial index")
	}
	tooLarge := asIndexTooLarge(t, err)
	if tooLarge.Dimension != IndexLimitEntries || tooLarge.Limit != 2 {
		t.Errorf("dimension/limit = %s/%d, want %s/2", tooLarge.Dimension, tooLarge.Limit, IndexLimitEntries)
	}
	if tooLarge.Entries != 3 || tooLarge.Layer != 1 || tooLarge.Layers != 1 {
		t.Errorf("entries/layer = %d in %d of %d, want 3 in 1 of 1", tooLarge.Entries, tooLarge.Layer, tooLarge.Layers)
	}
	if tooLarge.ScannedBytes != 30 {
		t.Errorf("scanned bytes = %d, want the 30 bytes read before the third entry", tooLarge.ScannedBytes)
	}
	for _, want := range []string{"configured limit of 2 entries", "3 entries counted", "in layer 1 of 1", "30 B of file content read"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
}

func TestIndexTooLargeErrorNamesTheLayerThatBrokeTheMergedLimit(t *testing.T) {
	// Each layer fits the limit alone; only the merged view exceeds it.
	base := makeTestLayer(t,
		testLayerEntry{name: "opt/a", mode: 0644, data: make([]byte, 5)},
		testLayerEntry{name: "opt/b", mode: 0644, data: make([]byte, 5)},
	)
	upper := makeTestLayer(t,
		testLayerEntry{name: "opt/c", mode: 0644, data: make([]byte, 7)},
		testLayerEntry{name: "opt/d", mode: 0644, data: make([]byte, 7)},
	)
	_, err := (&ImageReader{Image: makeTestImage(t, base, upper)}).streamAndIndexFilesystem(3)
	tooLarge := asIndexTooLarge(t, err)
	if tooLarge.Layer != 2 || tooLarge.Layers != 2 || tooLarge.Entries != 4 {
		t.Errorf("limit hit at layer %d of %d with %d entries, want layer 2 of 2 with 4 entries", tooLarge.Layer, tooLarge.Layers, tooLarge.Entries)
	}
	if tooLarge.ScannedBytes != 24 {
		t.Errorf("scanned bytes = %d, want 24 (both layers were read in full)", tooLarge.ScannedBytes)
	}
}

func TestIndexMemoryBudgetStopsLongPathsBeforeTheEntryCap(t *testing.T) {
	// The cap is 10 entries, so the budget is 10 * (512 + 256) = 7680 estimated
	// bytes. Three paths of 3 KiB break the budget although only 3 entries exist.
	var entries []testLayerEntry
	for i := 0; i < 3; i++ {
		entries = append(entries, testLayerEntry{name: "deep/" + strings.Repeat("d", 3000) + strconv.Itoa(i), mode: 0644})
	}
	_, err := (&ImageReader{Image: makeTestImage(t, makeTestLayer(t, entries...))}).streamAndIndexFilesystem(10)
	tooLarge := asIndexTooLarge(t, err)
	if tooLarge.Dimension != IndexLimitMemory {
		t.Fatalf("dimension = %s, want %s", tooLarge.Dimension, IndexLimitMemory)
	}
	if tooLarge.Entries != 3 || tooLarge.ByteBudget != 7680 || tooLarge.EstimatedBytes <= tooLarge.ByteBudget {
		t.Errorf("entries=%d budget=%d estimate=%d, want 3 entries and an estimate above the 7680 byte budget", tooLarge.Entries, tooLarge.ByteBudget, tooLarge.EstimatedBytes)
	}
	for _, want := range []string{"configured limit of 10 entries", "estimated index memory", "budget derived from the limit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}

	// Two such paths fit, which shows the budget is the cause and not the path length itself.
	if _, err := (&ImageReader{Image: makeTestImage(t, makeTestLayer(t, entries[:2]...))}).streamAndIndexFilesystem(10); err != nil {
		t.Fatalf("two long paths fit the budget, got %v", err)
	}
}

func TestIndexMemoryBudgetAppliesToTheMergedView(t *testing.T) {
	// Two layers of two long paths each stay within the budget per layer but
	// not together.
	long := func(prefix string, i int) testLayerEntry {
		return testLayerEntry{name: prefix + strings.Repeat("d", 3000) + strconv.Itoa(i), mode: 0644}
	}
	base := makeTestLayer(t, long("a/", 0), long("a/", 1))
	upper := makeTestLayer(t, long("b/", 0), long("b/", 1))
	_, err := (&ImageReader{Image: makeTestImage(t, base, upper)}).streamAndIndexFilesystem(10)
	tooLarge := asIndexTooLarge(t, err)
	if tooLarge.Dimension != IndexLimitMemory || tooLarge.Layer != 2 {
		t.Fatalf("dimension/layer = %s/%d, want memory/2", tooLarge.Dimension, tooLarge.Layer)
	}
}

func TestIndexStatsStayConsistentThroughWhiteoutsAndReplacements(t *testing.T) {
	base := makeTestLayer(t,
		testLayerEntry{name: "a/one", mode: 0644, data: make([]byte, 100)},
		testLayerEntry{name: "a/two", mode: 0644, data: make([]byte, 200)},
		testLayerEntry{name: "b/three", mode: 0644, data: make([]byte, 300)},
		testLayerEntry{name: "c/four", mode: 0644, data: make([]byte, 400)},
		testLayerEntry{name: "d", typeflag: tar.TypeDir, mode: 0755},
		testLayerEntry{name: "d/link", typeflag: tar.TypeSymlink, linkname: "/a/one", mode: 0777},
	)
	upper := makeTestLayer(t,
		testLayerEntry{name: "a/.wh..wh..opq", mode: 0644},
		testLayerEntry{name: "a/five", mode: 0644, data: make([]byte, 50)},
		testLayerEntry{name: "b/.wh.three", mode: 0644},
		testLayerEntry{name: "c/four", mode: 0644, data: make([]byte, 60)},
	)
	idx, err := (&ImageReader{Image: makeTestImage(t, base, upper)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatal(err)
	}
	var wantPathBytes int64
	for p := range idx.Paths {
		wantPathBytes += int64(len(p))
	}
	if idx.Stats.Entries != len(idx.Paths) || idx.Stats.PathBytes != wantPathBytes {
		t.Errorf("stats entries=%d pathBytes=%d, want %d and %d recomputed from the final paths", idx.Stats.Entries, idx.Stats.PathBytes, len(idx.Paths), wantPathBytes)
	}
	if want := indexBytes(len(idx.Paths), wantPathBytes); idx.Stats.EstimatedBytes != want {
		t.Errorf("estimated bytes = %d, want %d", idx.Stats.EstimatedBytes, want)
	}
	if idx.Stats.Layers != 2 {
		t.Errorf("layers = %d, want 2", idx.Stats.Layers)
	}
	// Content of regular files is counted across layers, including files that a
	// later layer removed or replaced. Directories and symlinks add nothing.
	if want := int64(100 + 200 + 300 + 400 + 50 + 60); idx.Stats.ScannedBytes != want {
		t.Errorf("scanned bytes = %d, want %d", idx.Stats.ScannedBytes, want)
	}
	for _, removed := range []string{"/a/one", "/a/two", "/b/three"} {
		if idx.HasPath(removed) {
			t.Errorf("%s should have been removed by a whiteout", removed)
		}
	}
}

func TestIndexByteBudgetDoesNotOverflow(t *testing.T) {
	if got := indexByteBudget(math.MaxInt); got != math.MaxInt64 {
		t.Fatalf("budget for the largest cap = %d, want it clamped to %d", got, int64(math.MaxInt64))
	}
	if got := indexByteBudget(1_000); got != 1_000*(indexEntryOverheadBytes+indexAveragePathBytes) {
		t.Fatalf("budget = %d", got)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		0:                 "0 B",
		1023:              "1023 B",
		1024:              "1.0 KiB",
		1536:              "1.5 KiB",
		5 << 20:           "5.0 MiB",
		3 << 30:           "3.0 GiB",
		2 << 40:           "2.0 TiB",
		(1 << 40) * 1024:  "1024.0 TiB",
		(1<<20)*1024 - 1:  "1024.0 MiB",
		(1 << 20) * 1023:  "1023.0 MiB",
		(1<<30)*3 + 1<<29: "3.5 GiB",
	}
	for n, want := range cases {
		if got := FormatBytes(n); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// The memory model rests on a measured retained heap per entry. The retained
// figure is taken after a forced GC, so it does not depend on collector timing;
// the transient peak is reported by BenchmarkFilesystemIndexMemory instead.
func TestIndexRetainedHeapStaysBelowTheModelOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("measures heap with 50,000 synthetic entries")
	}
	measured := measureIndexMemory(t, 50_000)
	if got := measured.retainedPerEntry(); got <= 0 || got >= indexEntryOverheadBytes {
		t.Fatalf("retained heap = %.0f B per entry, want between 0 and the %d B modeled overhead", got, indexEntryOverheadBytes)
	}
}
