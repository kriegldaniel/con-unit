package main

import (
	"context"
	"fmt"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Setup is everything RunAll needs besides the harness and the trial sink.
type Setup struct {
	Images     []string
	Bench      BenchConfig
	Protocol   Protocol
	Run        spec.RunMetadata
	Archetypes Archetypes
	OutDir     string
	Log        *Logger
}

// RunAll benchmarks every image in order and writes the outputs. A failing
// image is recorded and the run continues. The outputs are rewritten after
// every image, so a crash leaves a complete snapshot of everything finished so
// far, and they are written once more at the end even when the run was
// interrupted or only partly succeeded. The returned telemetry is never nil.
func RunAll(ctx context.Context, h Harness, sink TrialSink, s Setup) (*Telemetry, error) {
	keys := AssignMacroKeys(s.Images)
	tel := &Telemetry{
		SchemaVersion: TelemetrySchemaVersion,
		Run:           s.Run,
		Protocol:      s.Protocol,
		Images:        []ImageResult{},
	}
	snapshot := func(complete bool) error {
		tel.Complete = complete
		tel.Summary = Summarize(tel.Images, len(s.Images))
		return WriteAll(s.OutDir, tel)
	}

	// A panic must not lose the telemetry of the finished images.
	defer func() {
		if r := recover(); r != nil {
			tel.Protocol.Warnings = append(tel.Protocol.Warnings, fmt.Sprintf("run aborted by a panic: %v", r))
			tel.Run.FinishedAt = time.Now().UTC()
			_ = snapshot(false)
			panic(r)
		}
	}()

	for i, ref := range s.Images {
		if ctx.Err() != nil {
			break
		}
		entry := s.Archetypes.Lookup(ref)
		s.Log.Section("[%d/%d] %s", i+1, len(s.Images), ref)
		s.Log.Info("archetype %s, base family %s", entry.Archetype, entry.BaseFamily)

		img := BenchmarkImage(ctx, h, sink, s.Bench, ref, s.Log)
		img.Repository = RepositoryName(ref)
		img.MacroKey = keys[ref]
		img.Archetype = entry.Archetype
		img.BaseFamily = entry.BaseFamily
		tel.Images = append(tel.Images, img)
		logImageSummary(s.Log, img)

		if err := snapshot(false); err != nil {
			s.Log.Error("writing snapshot outputs failed: %v", err)
		}
	}

	if ctx.Err() != nil {
		tel.Protocol.Warnings = append(tel.Protocol.Warnings,
			fmt.Sprintf("run interrupted after %d of %d images", len(tel.Images), len(s.Images)))
	}
	tel.Run.FinishedAt = time.Now().UTC()
	complete := ctx.Err() == nil && len(tel.Images) == len(s.Images)
	err := snapshot(complete)
	return tel, err
}

func logImageSummary(log *Logger, img ImageResult) {
	if img.Stats == nil {
		log.Error("%s: %s (%s)", img.Repository, img.Status, img.StatusDetail)
		return
	}
	t := img.Stats.Total
	line := fmt.Sprintf("%s: %s, n=%d, median %s ms, IQR %s ms, mean %s ms", img.Repository, img.Status, t.N,
		fmtMs(t.Median), fmtMs(t.IQR), fmtMs(t.Mean))
	if t.CIDefined {
		line += fmt.Sprintf(" +/- %s ms (95%% CI)", fmtMs(t.CIHalfWidth))
	}
	if img.Status == ImageCompleted {
		log.Ok("%s", line)
	} else {
		log.Warn("%s (%s)", line, img.StatusDetail)
	}
}
