package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Harness runs one image through the evaluation. The production
// implementation wraps pkg/runner, tests use a fake.
type Harness interface {
	// Run evaluates one image and returns the suite result.
	Run(ctx context.Context, image string) (*spec.SuiteResult, error)
	// Purge removes the image from the local store of the engine.
	Purge(ctx context.Context, image string) error
}

// TrialSink receives every trial as soon as it finishes. The journal is the
// production implementation.
type TrialSink interface {
	Record(TrialRecord) error
}

// Trial kinds.
const (
	KindWarmup = "warmup" // discarded, never part of a statistic
	KindTimed  = "timed"  // warm local store, counted
	KindCold   = "cold"   // after an explicit image purge, depends on the network
)

// Image statuses. A trial uses the Status* constants of pkg/spec.
const (
	ImageCompleted = "COMPLETED" // all requested timed trials succeeded
	ImagePartial   = "PARTIAL"   // some timed trials succeeded
	ImageFailed    = "FAILED"    // no timed trial succeeded
)

// TrialResources is the per-trial resource record. It describes the ConUnit
// process only, never the container engine or the probe containers. Peak RSS
// is recorded only as a process-wide ceiling, never as a per-image value.
type TrialResources struct {
	LiveHeapMB   float64 `json:"live_heap_mb,omitempty"`
	AllocMB      float64 `json:"alloc_mb,omitempty"`
	TotalAllocMB float64 `json:"total_alloc_mb,omitempty"`
	SysMB        float64 `json:"sys_mb,omitempty"`
	// ProcessPeakRSSMB is the process-wide peak resident set size when the trial
	// ended. It never decreases within a process, so it cannot be attributed to
	// this image. Reports use only its maximum over the whole batch.
	ProcessPeakRSSMB  float64 `json:"process_peak_rss_mb,omitempty"`
	NumGC             uint32  `json:"num_gc,omitempty"`
	SelfCPUSeconds    float64 `json:"self_cpu_seconds,omitempty"`  // ConUnit process
	ChildCPUSeconds   float64 `json:"child_cpu_seconds,omitempty"` // engine CLI, Syft
	LayerCount        int     `json:"layer_count,omitempty"`
	CompressedBytes   int64   `json:"compressed_bytes,omitempty"`
	UncompressedBytes int64   `json:"uncompressed_bytes,omitempty"`
}

// TrialRecord is one execution of one image. All durations are nanoseconds.
type TrialRecord struct {
	Image     string    `json:"image"`
	Kind      string    `json:"kind"`
	Iteration int       `json:"iteration"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`

	// Identity as reported by the runner for this trial.
	ImageDigest  string `json:"image_digest,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
	Platform     string `json:"platform,omitempty"`
	ImageSource  string `json:"image_source,omitempty"`

	// NetworkDependent is true for cold trials: they include a registry
	// transfer and vary with network and registry load.
	NetworkDependent bool `json:"network_dependent,omitempty"`

	WallNs        int64 `json:"wall_ns"`         // measured around the call by this tool
	TotalNs       int64 `json:"total_ns"`        // duration reported by the runner, wall time if absent
	PullNs        int64 `json:"pull_ns"`         // engine ensure-image call
	InspectNs     int64 `json:"inspect_ns"`      // engine inspect call
	ResolveNs     int64 `json:"resolve_ns"`      // manifest resolution and identity check
	StreamIndexNs int64 `json:"stream_index_ns"` // layer streaming and tar indexing
	Tier1Ns       int64 `json:"tier1_ns"`
	Tier2Ns       int64 `json:"tier2_ns"`
	Tier3Ns       int64 `json:"tier3_ns"` // bounded below by the probe window, see Protocol.ProbeWindowNs
	Tier4Ns       int64 `json:"tier4_ns"`
	NonTier3Ns    int64 `json:"non_tier3_ns"` // total minus Tier 3

	Resources TrialResources `json:"resources"`

	// DockleExportMs and DockleRunMs are the milliseconds that exporting the
	// image to a docker-archive and running Dockle on it took right after this
	// trial, on the same host. They are set only when the benchmark runs with
	// -dockle and the trial succeeded. DockleError says why one is missing.
	DockleExportMs *float64 `json:"dockle_export_ms,omitempty"`
	DockleRunMs    *float64 `json:"dockle_run_ms,omitempty"`
	DockleError    string   `json:"dockle_error,omitempty"`
}

// DockleDone reports whether the trial has both Dockle durations.
func (t TrialRecord) DockleDone() bool { return t.DockleExportMs != nil && t.DockleRunMs != nil }

// OK reports whether the trial produced usable timings.
func (t TrialRecord) OK() bool { return t.Status == spec.StatusCompleted }

// PhaseStats holds the statistics of one image over its successful trials.
// Durations are in nanoseconds, CPU in seconds, heap in megabytes.
type PhaseStats struct {
	Total       Stats  `json:"total"`
	NonTier3    Stats  `json:"non_tier3"`
	Pull        Stats  `json:"pull"`
	Inspect     Stats  `json:"inspect"`
	Resolve     Stats  `json:"resolve"`
	StreamIndex Stats  `json:"stream_index"`
	Tier1       Stats  `json:"tier1"`
	Tier2       Stats  `json:"tier2"`
	Tier3       Stats  `json:"tier3"`
	Tier4       Stats  `json:"tier4"`
	SelfCPU     *Stats `json:"self_cpu,omitempty"`
	ChildCPU    *Stats `json:"child_cpu,omitempty"`
	LiveHeap    *Stats `json:"live_heap,omitempty"`
	// Dockle covers the successful trials with both Dockle durations. Nil
	// without -dockle or when no trial has them.
	Dockle *DockleStats `json:"dockle,omitempty"`
}

// DockleStats summarizes the Dockle durations of one image. Every value is in
// milliseconds. Total is export plus analysis of the same trial.
type DockleStats struct {
	Export Stats `json:"export"`
	Run    Stats `json:"run"`
	Total  Stats `json:"total"`
}

// ImageResult is the outcome of benchmarking one image.
type ImageResult struct {
	Ref        string `json:"ref"`
	Repository string `json:"repository"`
	MacroKey   string `json:"macro_key"`
	Archetype  string `json:"archetype"`
	BaseFamily string `json:"base_family"`

	Status       string `json:"status"`
	StatusDetail string `json:"status_detail,omitempty"`
	// AbortedEarly is set when the image was dropped after too many
	// consecutive failed trials. The failed trials are recorded.
	AbortedEarly bool `json:"aborted_early,omitempty"`
	Interrupted  bool `json:"interrupted,omitempty"`

	ImageDigest  string `json:"image_digest,omitempty"`
	ConfigDigest string `json:"config_digest,omitempty"`
	Platform     string `json:"platform,omitempty"`
	ImageSource  string `json:"image_source,omitempty"`

	LayerCount        int   `json:"layer_count,omitempty"`
	CompressedBytes   int64 `json:"compressed_bytes,omitempty"`
	UncompressedBytes int64 `json:"uncompressed_bytes,omitempty"`

	Warmup []TrialRecord `json:"warmup,omitempty"`
	Trials []TrialRecord `json:"trials"`
	Cold   []TrialRecord `json:"cold_trials,omitempty"`

	// Stats covers the successful timed trials. ColdStats covers the
	// successful cold trials and is network dependent.
	Stats     *PhaseStats `json:"stats,omitempty"`
	ColdStats *PhaseStats `json:"cold_stats,omitempty"`
}

// OKTimed returns the number of successful timed trials.
func (r ImageResult) OKTimed() int { return countOK(r.Trials) }

func countOK(trials []TrialRecord) int {
	n := 0
	for _, t := range trials {
		if t.OK() {
			n++
		}
	}
	return n
}

// BenchConfig is the trial protocol.
type BenchConfig struct {
	Iterations             int           // timed trials per image
	Warmup                 int           // discarded iterations before the timed trials
	ColdTrials             int           // optional cold registry trials after the timed ones
	TrialTimeout           time.Duration // per trial deadline, zero for none
	MaxConsecutiveFailures int           // drop the image after this many failed trials in a row, zero for never
	// Dockle, when set, times the archive export and the Dockle analysis of the
	// image after every warm-up and timed trial that succeeded. Cold trials are
	// not compared: they purge the image first and depend on the registry.
	Dockle Comparator
}

// BenchmarkImage runs the protocol for one image: warm-up iterations, timed
// trials, then optional cold trials. A failing trial is recorded with its
// status and error and the run continues. Every trial goes to the sink as soon
// as it finishes, so a crash loses nothing. The returned result has no
// archetype or macro key; the caller adds them.
func BenchmarkImage(ctx context.Context, h Harness, sink TrialSink, cfg BenchConfig, ref string, log *Logger) ImageResult {
	res := ImageResult{Ref: ref, Trials: []TrialRecord{}}
	consecutive := 0
	aborted := func() bool {
		return cfg.MaxConsecutiveFailures > 0 && consecutive >= cfg.MaxConsecutiveFailures
	}
	finish := func(rec TrialRecord, total int) TrialRecord {
		if err := sink.Record(rec); err != nil {
			log.Error("journal write failed: %v", err)
		}
		if rec.OK() {
			consecutive = 0
		} else {
			consecutive++
		}
		logTrial(log, rec, total)
		return rec
	}

	for i := 1; i <= cfg.Warmup && ctx.Err() == nil && !aborted(); i++ {
		res.Warmup = append(res.Warmup, finish(compareTrial(ctx, cfg, runTrial(ctx, h, ref, KindWarmup, i, cfg.TrialTimeout)), cfg.Warmup))
	}
	for i := 1; i <= cfg.Iterations && ctx.Err() == nil && !aborted(); i++ {
		res.Trials = append(res.Trials, finish(compareTrial(ctx, cfg, runTrial(ctx, h, ref, KindTimed, i, cfg.TrialTimeout)), cfg.Iterations))
	}
	for i := 1; i <= cfg.ColdTrials && ctx.Err() == nil && !aborted(); i++ {
		res.Cold = append(res.Cold, finish(runColdTrial(ctx, h, ref, i, cfg.TrialTimeout), cfg.ColdTrials))
	}

	res.AbortedEarly = aborted()
	res.Interrupted = ctx.Err() != nil
	res.Stats = computePhaseStats(res.Trials)
	res.ColdStats = computePhaseStats(res.Cold)
	identify(&res)

	ok := countOK(res.Trials)
	switch {
	case ok == cfg.Iterations && cfg.Iterations > 0:
		res.Status = ImageCompleted
	case ok > 0:
		res.Status = ImagePartial
		res.StatusDetail = fmt.Sprintf("%d of %d timed trials succeeded", ok, cfg.Iterations)
	default:
		res.Status = ImageFailed
		res.StatusDetail = "no timed trial succeeded"
	}
	if res.AbortedEarly {
		res.StatusDetail += fmt.Sprintf("; dropped after %d consecutive failed trials", cfg.MaxConsecutiveFailures)
	}
	if res.Interrupted {
		res.StatusDetail += "; run interrupted"
	}
	return res
}

// compareTrial adds the Dockle timing to a finished trial when the benchmark
// compares with Dockle.
func compareTrial(ctx context.Context, cfg BenchConfig, rec TrialRecord) TrialRecord {
	timeDockle(ctx, cfg.Dockle, &rec, cfg.TrialTimeout)
	return rec
}

// runColdTrial purges the image and runs one trial. A failed purge is
// recorded as a failed trial and the run is not attempted, because it would
// not be cold.
func runColdTrial(ctx context.Context, h Harness, ref string, iter int, timeout time.Duration) TrialRecord {
	pctx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		pctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := h.Purge(pctx, ref); err != nil {
		return TrialRecord{
			Image: ref, Kind: KindCold, Iteration: iter, StartedAt: time.Now().UTC(),
			Status: spec.StatusExecutionError, Error: "image purge failed: " + err.Error(),
			NetworkDependent: true,
		}
	}
	rec := runTrial(ctx, h, ref, KindCold, iter, timeout)
	rec.NetworkDependent = true
	return rec
}

// runTrial executes one trial and converts the outcome to a record. It never
// returns an error: failures become a status and an error string.
func runTrial(ctx context.Context, h Harness, ref, kind string, iter int, timeout time.Duration) TrialRecord {
	rec := TrialRecord{Image: ref, Kind: kind, Iteration: iter, StartedAt: time.Now().UTC()}
	tctx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		tctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	res, err := h.Run(tctx, ref)
	wall := time.Since(start)
	rec.WallNs = wall.Nanoseconds()

	switch {
	case err != nil:
		rec.Status, rec.Reason = trialStatus(ctx, err)
		rec.Error = err.Error()
	case res == nil:
		rec.Status = spec.StatusExecutionError
		rec.Error = "the runner returned neither a result nor an error"
	case res.Status != "" && res.Status != spec.StatusCompleted:
		rec.Status = res.Status
		rec.Reason = string(res.Reason)
		rec.Error = res.ErrorMessage
		fillTimings(&rec, res, wall)
	default:
		rec.Status = spec.StatusCompleted
		fillTimings(&rec, res, wall)
	}
	return rec
}

// trialStatus maps an error to a status string and reason. A cancelled parent
// context is an interruption of the whole run, not a property of the image.
func trialStatus(parent context.Context, err error) (string, string) {
	if parent.Err() != nil {
		return spec.StatusExecutionError, "run interrupted"
	}
	status, reason := classifyError(err)
	return status, string(reason)
}

func fillTimings(rec *TrialRecord, res *spec.SuiteResult, wall time.Duration) {
	total := res.Duration
	if total <= 0 {
		total = wall
	}
	p := res.Phases
	rec.TotalNs = total.Nanoseconds()
	rec.PullNs = p.PullDuration.Nanoseconds()
	rec.InspectNs = p.InspectDuration.Nanoseconds()
	rec.ResolveNs = p.ResolveDuration.Nanoseconds()
	rec.StreamIndexNs = p.StreamDuration.Nanoseconds()
	rec.Tier1Ns = p.Tier1Duration.Nanoseconds()
	rec.Tier2Ns = p.Tier2Duration.Nanoseconds()
	rec.Tier3Ns = p.Tier3Duration.Nanoseconds()
	rec.Tier4Ns = p.Tier4Duration.Nanoseconds()
	rec.NonTier3Ns = rec.TotalNs - rec.Tier3Ns
	if rec.NonTier3Ns < 0 {
		rec.NonTier3Ns = 0
	}
	r := res.Resources
	rec.Resources = TrialResources{
		LiveHeapMB:        r.LiveHeapMB,
		AllocMB:           r.AllocMB,
		TotalAllocMB:      r.TotalAllocMB,
		SysMB:             r.SysMB,
		ProcessPeakRSSMB:  r.PeakRSSMB,
		NumGC:             r.NumGC,
		SelfCPUSeconds:    r.SelfCPUSeconds,
		ChildCPUSeconds:   r.ChildCPUSeconds,
		LayerCount:        r.LayerCount,
		CompressedBytes:   r.CompressedBytes,
		UncompressedBytes: r.UncompressedBytes,
	}
	rec.ImageDigest, rec.ConfigDigest, rec.Platform, rec.ImageSource = res.ImageDigest, res.ConfigDigest, res.Platform, res.ImageSource
}

// identify copies the image identity and size facts from the last successful
// timed trial.
func identify(res *ImageResult) {
	for i := len(res.Trials) - 1; i >= 0; i-- {
		if t := res.Trials[i]; t.OK() {
			res.ImageDigest, res.ConfigDigest, res.Platform, res.ImageSource = t.ImageDigest, t.ConfigDigest, t.Platform, t.ImageSource
			res.LayerCount = t.Resources.LayerCount
			res.CompressedBytes = t.Resources.CompressedBytes
			res.UncompressedBytes = t.Resources.UncompressedBytes
			break
		}
	}
}

// computePhaseStats summarizes the successful trials. It returns nil when no
// trial succeeded.
func computePhaseStats(trials []TrialRecord) *PhaseStats {
	var ok []TrialRecord
	for _, t := range trials {
		if t.OK() {
			ok = append(ok, t)
		}
	}
	if len(ok) == 0 {
		return nil
	}
	dur := func(get func(TrialRecord) int64) Stats {
		ds := make([]time.Duration, len(ok))
		for i, t := range ok {
			ds[i] = time.Duration(get(t))
		}
		return DurationStats(ds)
	}
	ps := &PhaseStats{
		Total:       dur(func(t TrialRecord) int64 { return t.TotalNs }),
		NonTier3:    dur(func(t TrialRecord) int64 { return t.NonTier3Ns }),
		Pull:        dur(func(t TrialRecord) int64 { return t.PullNs }),
		Inspect:     dur(func(t TrialRecord) int64 { return t.InspectNs }),
		Resolve:     dur(func(t TrialRecord) int64 { return t.ResolveNs }),
		StreamIndex: dur(func(t TrialRecord) int64 { return t.StreamIndexNs }),
		Tier1:       dur(func(t TrialRecord) int64 { return t.Tier1Ns }),
		Tier2:       dur(func(t TrialRecord) int64 { return t.Tier2Ns }),
		Tier3:       dur(func(t TrialRecord) int64 { return t.Tier3Ns }),
		Tier4:       dur(func(t TrialRecord) int64 { return t.Tier4Ns }),
	}
	var self, child, heap []float64
	for _, t := range ok {
		if t.Resources.SelfCPUSeconds > 0 || t.Resources.ChildCPUSeconds > 0 {
			self = append(self, t.Resources.SelfCPUSeconds)
			child = append(child, t.Resources.ChildCPUSeconds)
		}
		if t.Resources.LiveHeapMB > 0 {
			heap = append(heap, t.Resources.LiveHeapMB)
		}
	}
	if len(self) > 0 {
		s, c := ComputeStats(self, "s"), ComputeStats(child, "s")
		ps.SelfCPU, ps.ChildCPU = &s, &c
	}
	var export, run, total []float64
	for _, t := range ok {
		if t.DockleDone() {
			export = append(export, *t.DockleExportMs)
			run = append(run, *t.DockleRunMs)
			total = append(total, *t.DockleExportMs+*t.DockleRunMs)
		}
	}
	if len(total) > 0 {
		ps.Dockle = &DockleStats{Export: ComputeStats(export, "ms"), Run: ComputeStats(run, "ms"), Total: ComputeStats(total, "ms")}
	}
	if len(heap) > 0 {
		h := ComputeStats(heap, "MB")
		ps.LiveHeap = &h
	}
	return ps
}

func logTrial(log *Logger, rec TrialRecord, total int) {
	label := fmt.Sprintf("%-6s %2d/%-2d", rec.Kind, rec.Iteration, total)
	if !rec.OK() {
		log.Error("    %s %s: %s", label, rec.Status, rec.Error)
		return
	}
	net := ""
	if rec.NetworkDependent {
		net = "  (network dependent)"
	}
	log.Info("    %s total %s ms | resolve %s stream %s t1 %s t2 %s t3 %s t4 %s%s", label,
		fmtMs(float64(rec.TotalNs)), fmtMs(float64(rec.ResolveNs)), fmtMs(float64(rec.StreamIndexNs)),
		fmtMs(float64(rec.Tier1Ns)), fmtMs(float64(rec.Tier2Ns)), fmtMs(float64(rec.Tier3Ns)), fmtMs(float64(rec.Tier4Ns)), net)
	switch {
	case rec.DockleDone():
		log.Info("    %s dockle %.3f ms (export %.3f, analysis %.3f)", strings.Repeat(" ", len(label)),
			*rec.DockleExportMs+*rec.DockleRunMs, *rec.DockleExportMs, *rec.DockleRunMs)
	case rec.DockleError != "":
		log.Warn("    %s %s", strings.Repeat(" ", len(label)), rec.DockleError)
	}
}
