package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
)

// ExportInfo describes what an export did and how long its steps took.
type ExportInfo struct {
	// Pulled is true when the image was absent from the engine store and had
	// to be pulled first.
	Pulled      bool
	PullSeconds float64
	// ExportSeconds covers the inspect and the `save --format docker-archive`
	// of the engine. A pull is not part of it.
	ExportSeconds float64
}

// Exporter writes the docker-archive of an image. Tests use a fake.
type Exporter interface {
	// Export writes the image to dest, which must not exist yet. platform is
	// passed to a pull; it may be empty.
	Export(ctx context.Context, ref, platform, dest string) (ExportInfo, error)
	// Describe returns the engine name and version for the report.
	Describe(ctx context.Context) string
}

// EngineExporter exports through a container engine, in the way ConUnit does
// for an image of the local store: `save --format docker-archive` addressed by
// the image ID (docker saves without the format flag).
type EngineExporter struct {
	Engine *engine.Engine
	// KeepPulled keeps an image that this export pulled. By default such an
	// image is removed again after the export so that the store ends as it was
	// found.
	KeepPulled bool
}

// Export implements Exporter.
func (e *EngineExporter) Export(ctx context.Context, ref, platform, dest string) (ExportInfo, error) {
	var info ExportInfo
	pullStart := time.Now()
	pulled, err := e.Engine.EnsureImageForPlatform(ctx, ref, platform)
	if err != nil {
		return info, fmt.Errorf("the image is not in the engine store and could not be pulled: %w", err)
	}
	if pulled {
		info.Pulled = true
		info.PullSeconds = time.Since(pullStart).Seconds()
		if !e.KeepPulled {
			defer e.remove(ref)
		}
	}
	start := time.Now()
	inspect, err := e.Engine.InspectImageForPlatform(ctx, ref, platform)
	if err != nil {
		return info, err
	}
	if err := e.Engine.SaveImage(ctx, inspect.ID, dest); err != nil {
		return info, err
	}
	info.ExportSeconds = time.Since(start).Seconds()
	return info, nil
}

// remove deletes an image that this tool pulled. It is best effort and uses
// its own context because the export context may have ended.
func (e *EngineExporter) remove(ref string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_ = e.Engine.Command(ctx, "rmi", ref).Run()
}

// Describe implements Exporter.
func (e *EngineExporter) Describe(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := e.Engine.Command(ctx, "--version").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(line)
}
