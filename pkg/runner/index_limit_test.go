package runner_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

func indexLimitFixture(t *testing.T) (imagePath, configDigest string) {
	t.Helper()
	imagePath = filepath.Join(t.TempDir(), "synthetic.tar")
	configDigest = writeRunnerImageTarball(t, imagePath, makeRunnerLayer(t,
		runnerLayerEntry{name: "opt/one", mode: 0644, data: make([]byte, 10)},
		runnerLayerEntry{name: "opt/two", mode: 0644, data: make([]byte, 20)},
		runnerLayerEntry{name: "opt/three", mode: 0644, data: make([]byte, 30)},
	))
	return imagePath, configDigest
}

func hygienePack(t *testing.T) conunit.RulePack {
	t.Helper()
	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack: %v", err)
	}
	return pack.Except("EXEC-01", "EXEC-02", "EXEC-03")
}

func TestRunPackExcludesAnOversizedImageWithItsIdentityAndSize(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath, configDigest := indexLimitFixture(t)
	t.Setenv("FAKE_CONFIG_DIGEST", configDigest)

	observed := 0
	res, err := runner.NewRunnerWithOptions(eng, runner.Options{
		MaxIndexEntries: 2,
		OnIndexed:       func(runner.IndexReport) { observed++ },
	}).RunPack(context.Background(), hygienePack(t), imagePath)
	if err == nil || res != nil {
		t.Fatalf("RunPack = %v, %v; want an index limit error and no result", res, err)
	}
	if observed != 0 {
		t.Errorf("the index observer ran %d times for an image that could not be indexed", observed)
	}

	status, reason := runner.ClassifyError(err)
	if status != spec.StatusIndexLimit || reason != spec.ReasonIndexTooLarge {
		t.Fatalf("classified as %s/%s, want INDEX_LIMIT/INDEX_TOO_LARGE (err: %v)", status, reason, err)
	}
	var tooLarge *oci.IndexTooLargeError
	if !errors.As(err, &tooLarge) || tooLarge.Limit != 2 || tooLarge.Entries != 3 || tooLarge.Dimension != oci.IndexLimitEntries {
		t.Fatalf("typed limit error = %+v, want 3 entries against a limit of 2", tooLarge)
	}
	if !strings.Contains(err.Error(), "failed indexing OCI filesystem") || !strings.Contains(err.Error(), "configured limit of 2 entries") {
		t.Errorf("message = %q", err.Error())
	}

	var imageErr *runner.ImageError
	if !errors.As(err, &imageErr) || imageErr.Stage != "index" || imageErr.ImageSource != spec.SourceTarball {
		t.Fatalf("failure must carry the index stage and the source, got %+v", imageErr)
	}
	partial := imageErr.Partial
	if partial == nil {
		t.Fatal("the failure must carry the identity and size of the excluded image")
	}
	if partial.ConfigDigest != configDigest || partial.Platform != "linux/amd64" || partial.ImageSource != spec.SourceTarball {
		t.Errorf("identity = config %q platform %q source %q, want %q linux/amd64 tarball", partial.ConfigDigest, partial.Platform, partial.ImageSource, configDigest)
	}
	if partial.ImageDigest != "" {
		t.Errorf("a tarball has no registry digest, got %q", partial.ImageDigest)
	}
	if partial.Resources.LayerCount != 1 || partial.Resources.UncompressedBytes != 30 || partial.Resources.IndexedEntries != 3 {
		t.Errorf("size = %+v, want 1 layer, the 30 bytes read before the limit and the 3 entries counted", partial.Resources)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}

func TestRunPackReportsIndexSizeToTheObserverAndTheResult(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath, configDigest := indexLimitFixture(t)
	t.Setenv("FAKE_CONFIG_DIGEST", configDigest)

	var reports []runner.IndexReport
	res, err := runner.NewRunnerWithOptions(eng, runner.Options{
		OnIndexed: func(report runner.IndexReport) { reports = append(reports, report) },
	}).RunPack(context.Background(), hygienePack(t), imagePath)
	if err != nil {
		t.Fatalf("RunPack: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("observer ran %d times, want once", len(reports))
	}
	report := reports[0]
	if report.Image != imagePath || report.Source != spec.SourceTarball {
		t.Errorf("report names %q from %q", report.Image, report.Source)
	}
	if report.Stats.Entries != 3 || report.Stats.Layers != 1 || report.Stats.ScannedBytes != 60 {
		t.Errorf("stats = %+v, want 3 entries, 1 layer and 60 content bytes", report.Stats)
	}
	if report.Stats.EstimatedBytes <= 0 || report.Stats.PathBytes <= 0 {
		t.Errorf("stats lack the memory model figures: %+v", report.Stats)
	}
	if res.Resources.UncompressedBytes != 60 || res.Resources.LayerCount != 1 || res.Resources.IndexedEntries != 3 {
		t.Errorf("result resources = %+v, want the 60 content bytes read, 1 layer and 3 entries", res.Resources)
	}
	// The process figures are measured for every image. CPU time of a very
	// short evaluation can round to zero, so only the heap and the ceiling are
	// required to be present.
	if res.Resources.LiveHeapMB <= 0 || res.Resources.PeakRSSMB <= 0 {
		t.Errorf("result resources = %+v, want a live heap after GC and the process peak", res.Resources)
	}
	if res.Resources.SelfCPUSeconds < 0 || res.Resources.ChildCPUSeconds < 0 {
		t.Errorf("CPU time must not be negative: %+v", res.Resources)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}
