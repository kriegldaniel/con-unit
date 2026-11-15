package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// step is one scripted answer of the fake harness.
type step struct {
	res *spec.SuiteResult
	err error
}

// fakeHarness answers Run from a per-image script. When a script is used up its
// last step repeats. Every call is recorded in order.
type fakeHarness struct {
	mu       sync.Mutex
	script   map[string][]step
	calls    []string
	used     map[string]int
	purgeErr error
	onRun    func(image string, n int)
}

func newFake(script map[string][]step) *fakeHarness {
	return &fakeHarness{script: script, used: map[string]int{}}
}

func (f *fakeHarness) Run(ctx context.Context, image string) (*spec.SuiteResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, "run:"+image)
	n := f.used[image]
	f.used[image] = n + 1
	steps := f.script[image]
	f.mu.Unlock()
	if f.onRun != nil {
		f.onRun(image, n+1)
	}
	if len(steps) == 0 {
		return nil, errors.New("no script for " + image)
	}
	if n >= len(steps) {
		n = len(steps) - 1
	}
	return steps[n].res, steps[n].err
}

func (f *fakeHarness) Purge(ctx context.Context, image string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "purge:"+image)
	return f.purgeErr
}

// memSink records trials in memory.
type memSink struct {
	mu     sync.Mutex
	trials []TrialRecord
}

func (m *memSink) Record(t TrialRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trials = append(m.trials, t)
	return nil
}

// okResult builds a successful suite result with the given total duration and
// a fixed phase split.
func okResult(total time.Duration) *spec.SuiteResult {
	return &spec.SuiteResult{
		Status:       spec.StatusCompleted,
		ImageDigest:  "sha256:aaaa",
		ConfigDigest: "sha256:bbbb",
		Platform:     "linux/amd64",
		ImageSource:  spec.SourceLocalStore,
		Duration:     total,
		Phases: spec.PhaseBreakdown{
			PullDuration:    2 * time.Millisecond,
			InspectDuration: 3 * time.Millisecond,
			ResolveDuration: 10 * time.Millisecond,
			StreamDuration:  20 * time.Millisecond,
			Tier1Duration:   100 * time.Microsecond,
			Tier2Duration:   5 * time.Millisecond,
			Tier3Duration:   3 * time.Second,
			Tier4Duration:   50 * time.Millisecond,
		},
		Resources: spec.ResourceTelemetry{
			PeakRSSMB: 77.5, LiveHeapMB: 12.5, LayerCount: 3, CompressedBytes: 1000, UncompressedBytes: 4000,
		},
	}
}

func discard() *Logger { return NewLogger(io.Discard) }

func baseCfg() BenchConfig {
	return BenchConfig{Iterations: 5, Warmup: 1, TrialTimeout: time.Minute, MaxConsecutiveFailures: 3}
}

func TestWarmupIsDiscardedAndTimedTrialsAreCounted(t *testing.T) {
	steps := []step{{res: okResult(9 * time.Hour)}} // warm-up: an absurd value that must not enter any statistic
	for i := 1; i <= 5; i++ {
		steps = append(steps, step{res: okResult(time.Duration(i) * time.Second)})
	}
	h := newFake(map[string][]step{"img": steps})
	sink := &memSink{}
	res := BenchmarkImage(context.Background(), h, sink, baseCfg(), "img", discard())

	if len(h.calls) != 6 {
		t.Fatalf("calls = %v, want 1 warm-up and 5 timed", h.calls)
	}
	if len(res.Warmup) != 1 || res.Warmup[0].Kind != KindWarmup {
		t.Errorf("warmup records = %+v", res.Warmup)
	}
	if len(res.Trials) != 5 {
		t.Fatalf("timed trials = %d", len(res.Trials))
	}
	for i, tr := range res.Trials {
		if tr.Kind != KindTimed || tr.Iteration != i+1 {
			t.Errorf("trial %d = kind %s iteration %d", i, tr.Kind, tr.Iteration)
		}
	}
	if res.Status != ImageCompleted {
		t.Errorf("status = %s (%s)", res.Status, res.StatusDetail)
	}
	st := res.Stats.Total
	if st.N != 5 || st.Median != float64(3*time.Second) || st.Mean != float64(3*time.Second) {
		t.Errorf("total stats = %+v, the discarded warm-up must not be included", st)
	}
	if len(sink.trials) != 6 {
		t.Errorf("journal received %d trials, want all 6 including the warm-up", len(sink.trials))
	}
	if res.ImageDigest != "sha256:aaaa" || res.ConfigDigest != "sha256:bbbb" || res.ImageSource != spec.SourceLocalStore {
		t.Errorf("identity not copied: %+v", res)
	}
	if res.LayerCount != 3 || res.UncompressedBytes != 4000 || res.CompressedBytes != 1000 {
		t.Errorf("sizes not copied: %+v", res)
	}
}

func TestPhasesAreReportedSeparatelyWithFullResolution(t *testing.T) {
	r := okResult(3100 * time.Millisecond)
	r.Phases.Tier1Duration = 123456 * time.Nanosecond
	h := newFake(map[string][]step{"img": {{res: r}}})
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations = 0, 3
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())
	ps := res.Stats
	if ps == nil {
		t.Fatal("no stats")
	}
	if ps.Tier1.Median != 123456 {
		t.Errorf("tier 1 median = %v ns, want 123456 (no truncation to milliseconds)", ps.Tier1.Median)
	}
	checks := map[string]struct{ got, want float64 }{
		"resolve":      {ps.Resolve.Median, float64(10 * time.Millisecond)},
		"stream_index": {ps.StreamIndex.Median, float64(20 * time.Millisecond)},
		"tier2":        {ps.Tier2.Median, float64(5 * time.Millisecond)},
		"tier3":        {ps.Tier3.Median, float64(3 * time.Second)},
		"tier4":        {ps.Tier4.Median, float64(50 * time.Millisecond)},
		"non_tier3":    {ps.NonTier3.Median, float64(100 * time.Millisecond)},
		"total":        {ps.Total.Median, float64(3100 * time.Millisecond)},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
}

func TestPartialFailureIsRecordedAndTheRunContinues(t *testing.T) {
	steps := []step{
		{res: okResult(time.Second)},                            // warm-up
		{res: okResult(time.Second)},                            // timed 1
		{err: errors.New("engine inspect failed: boom")},        // timed 2
		{res: okResult(3 * time.Second)},                        // timed 3
		{err: fmt.Errorf("pull: %w", context.DeadlineExceeded)}, // timed 4
		{res: &spec.SuiteResult{Status: spec.StatusUnavailable, ErrorMessage: "manifest unknown", Reason: spec.ReasonManifestNotFound}}, // timed 5
	}
	h := newFake(map[string][]step{"img": steps})
	sink := &memSink{}
	res := BenchmarkImage(context.Background(), h, sink, baseCfg(), "img", discard())

	if len(h.calls) != 6 {
		t.Fatalf("calls = %d, want all 6 attempted", len(h.calls))
	}
	if res.Status != ImagePartial || res.OKTimed() != 2 {
		t.Errorf("status = %s with %d ok trials (%s)", res.Status, res.OKTimed(), res.StatusDetail)
	}
	if res.Stats == nil || res.Stats.Total.N != 2 {
		t.Fatalf("stats must cover only the 2 successful trials: %+v", res.Stats)
	}
	byIter := map[int]TrialRecord{}
	for _, tr := range res.Trials {
		byIter[tr.Iteration] = tr
	}
	if tr := byIter[2]; tr.Status != spec.StatusExecutionError || tr.Error == "" || tr.OK() {
		t.Errorf("trial 2 = %+v", tr)
	}
	if tr := byIter[4]; tr.Status != spec.StatusTimeout || tr.Reason != string(spec.ReasonDeadlineExceeded) {
		t.Errorf("trial 4 = %+v, a deadline must map to TIMEOUT", tr)
	}
	if tr := byIter[5]; tr.Status != spec.StatusUnavailable || tr.Reason != string(spec.ReasonManifestNotFound) || tr.Error != "manifest unknown" {
		t.Errorf("trial 5 = %+v, a non-completed suite status must be kept", tr)
	}
	if len(sink.trials) != 6 {
		t.Errorf("failed trials must be journaled too, got %d lines", len(sink.trials))
	}
	if res.AbortedEarly {
		t.Error("two separated failures must not abort the image")
	}
}

func TestImageIsDroppedAfterConsecutiveFailures(t *testing.T) {
	h := newFake(map[string][]step{"img": {{err: errors.New("registry unreachable")}}})
	sink := &memSink{}
	cfg := baseCfg()
	cfg.Iterations = 10
	res := BenchmarkImage(context.Background(), h, sink, cfg, "img", discard())

	if len(h.calls) != 3 {
		t.Errorf("calls = %d, want 3 (the limit of consecutive failures)", len(h.calls))
	}
	if res.Status != ImageFailed || !res.AbortedEarly || res.Stats != nil {
		t.Errorf("result = status %s aborted %t stats %v", res.Status, res.AbortedEarly, res.Stats)
	}
	if len(sink.trials) != 3 {
		t.Errorf("journal lines = %d", len(sink.trials))
	}
	for _, tr := range sink.trials {
		if tr.Error == "" || tr.Status == "" {
			t.Errorf("a failed trial needs status and error: %+v", tr)
		}
	}
}

func TestSuccessResetsTheConsecutiveFailureCount(t *testing.T) {
	steps := []step{
		{res: okResult(time.Second)}, // warm-up
		{err: errors.New("x")}, {err: errors.New("x")}, {res: okResult(time.Second)},
		{err: errors.New("x")}, {err: errors.New("x")}, {res: okResult(time.Second)},
	}
	h := newFake(map[string][]step{"img": steps})
	cfg := baseCfg()
	cfg.Iterations = 6
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())
	if res.AbortedEarly || len(res.Trials) != 6 {
		t.Errorf("aborted %t after %d trials", res.AbortedEarly, len(res.Trials))
	}
}

func TestColdTrialsPurgeBeforeEachRunAndAreLabeled(t *testing.T) {
	h := newFake(map[string][]step{"img": {{res: okResult(time.Second)}}})
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations, cfg.ColdTrials = 0, 2, 2
	sink := &memSink{}
	res := BenchmarkImage(context.Background(), h, sink, cfg, "img", discard())

	want := []string{"run:img", "run:img", "purge:img", "run:img", "purge:img", "run:img"}
	if fmt.Sprint(h.calls) != fmt.Sprint(want) {
		t.Errorf("calls = %v, want %v", h.calls, want)
	}
	if len(res.Cold) != 2 || res.ColdStats == nil || res.ColdStats.Total.N != 2 {
		t.Fatalf("cold results = %+v", res.Cold)
	}
	for _, c := range res.Cold {
		if !c.NetworkDependent || c.Kind != KindCold {
			t.Errorf("cold trial not labeled: %+v", c)
		}
	}
	for _, tr := range res.Trials {
		if tr.NetworkDependent {
			t.Error("warm trials must not be labeled network dependent")
		}
	}
	if res.Stats.Total.N != 2 {
		t.Errorf("warm stats must not include cold trials: %+v", res.Stats.Total)
	}
}

func TestFailedPurgeIsRecordedAndTheRunIsNotAttempted(t *testing.T) {
	h := newFake(map[string][]step{"img": {{res: okResult(time.Second)}}})
	h.purgeErr = errors.New("image in use")
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations, cfg.ColdTrials = 0, 1, 1
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())
	if len(res.Cold) != 1 || res.Cold[0].OK() || res.Cold[0].Error == "" {
		t.Fatalf("cold = %+v", res.Cold)
	}
	if h.calls[len(h.calls)-1] != "purge:img" {
		t.Errorf("a trial after a failed purge would not be cold, calls = %v", h.calls)
	}
	if res.ColdStats != nil {
		t.Error("no cold statistics without a successful cold trial")
	}
}

func TestCPUTimeIsSeparatedAndOptional(t *testing.T) {
	with := okResult(time.Second)
	with.Resources.SelfCPUSeconds = 0.25
	with.Resources.ChildCPUSeconds = 1.5
	h := newFake(map[string][]step{"with": {{res: with}}, "without": {{res: okResult(time.Second)}}})
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations = 0, 3
	a := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "with", discard())
	b := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "without", discard())
	if a.Stats.SelfCPU == nil || a.Stats.ChildCPU == nil {
		t.Fatal("CPU statistics missing")
	}
	if a.Stats.SelfCPU.Median != 0.25 || a.Stats.ChildCPU.Median != 1.5 {
		t.Errorf("self %v child %v: the two must be kept apart", a.Stats.SelfCPU.Median, a.Stats.ChildCPU.Median)
	}
	if b.Stats.SelfCPU != nil || b.Stats.ChildCPU != nil {
		t.Error("absent CPU data must stay absent, not become zero")
	}
}

func TestPeakRSSIsNotKeptPerImageButAsBatchCeiling(t *testing.T) {
	h := newFake(map[string][]step{"a": {{res: okResult(time.Second)}}})
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations = 0, 2
	img := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "a", discard())
	if got := Summarize([]ImageResult{img}, 1).BatchPeakRSSMB; got != 77.5 {
		t.Errorf("batch peak RSS = %v", got)
	}
	if img.Stats.LiveHeap == nil || img.Stats.LiveHeap.Median != 12.5 {
		t.Errorf("live heap stats = %+v", img.Stats.LiveHeap)
	}
}

func TestInterruptionStopsTheImageAndIsFlagged(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := newFake(map[string][]step{"img": {{res: okResult(time.Second)}}})
	h.onRun = func(_ string, n int) {
		if n == 3 {
			cancel()
		}
	}
	cfg := baseCfg()
	cfg.Iterations = 10
	res := BenchmarkImage(ctx, h, &memSink{}, cfg, "img", discard())
	if !res.Interrupted {
		t.Error("the image must be flagged as interrupted")
	}
	if len(h.calls) != 3 {
		t.Errorf("calls = %d, want the run to stop after the cancel", len(h.calls))
	}
	if res.Status == ImageCompleted {
		t.Errorf("status = %s, an interrupted image is not completed", res.Status)
	}
	last := res.Trials[len(res.Trials)-1]
	if last.Status == "" {
		t.Errorf("last trial = %+v", last)
	}
}

func TestNilResultWithoutErrorIsAFailure(t *testing.T) {
	h := newFake(map[string][]step{"img": {{res: nil, err: nil}}})
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations = 0, 1
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())
	if res.Status != ImageFailed || res.Trials[0].Error == "" {
		t.Errorf("result = %+v", res.Trials)
	}
}

func TestWallClockIsUsedWhenTheRunnerReportsNoDuration(t *testing.T) {
	r := okResult(0)
	h := newFake(map[string][]step{"img": {{res: r}}})
	h.onRun = func(string, int) { time.Sleep(5 * time.Millisecond) }
	cfg := baseCfg()
	cfg.Warmup, cfg.Iterations = 0, 1
	res := BenchmarkImage(context.Background(), h, &memSink{}, cfg, "img", discard())
	if tr := res.Trials[0]; tr.TotalNs < int64(5*time.Millisecond) || tr.TotalNs != tr.WallNs {
		t.Errorf("total %d wall %d", tr.TotalNs, tr.WallNs)
	}
}
