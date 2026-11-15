package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// ImageStatus is the outcome of the Dockle side for one image.
type ImageStatus string

const (
	// ImageOK: the archive matched the study and Dockle produced a report.
	ImageOK ImageStatus = "OK"
	// ImageExportError: the image could not be exported.
	ImageExportError ImageStatus = "EXPORT_ERROR"
	// ImageDigestMismatch: the exported archive is not the image the study
	// evaluated. It is an error of the cross-check, never a result.
	ImageDigestMismatch ImageStatus = "DIGEST_MISMATCH"
	// ImageNoStudyDigest: the study record has no config digest, so the
	// archive cannot be verified.
	ImageNoStudyDigest ImageStatus = "STUDY_DIGEST_MISSING"
	// ImageArchiveError: the archive could not be read for its digest.
	ImageArchiveError ImageStatus = "ARCHIVE_ERROR"
	// ImageDockleError: Dockle could not be started, was cut off or exited
	// with a failure.
	ImageDockleError ImageStatus = "DOCKLE_ERROR"
	// ImageParseError: Dockle ran, but its output is not a report.
	ImageParseError ImageStatus = "PARSE_ERROR"
	// ImageNoRawRecord: -analyze-only found no raw record for the image.
	ImageNoRawRecord ImageStatus = "NO_RAW_RECORD"
)

// ImageRecord is the raw record of the Dockle side for one image. It is
// written to raw/ and is the input of -analyze-only.
type ImageRecord struct {
	Image               string      `json:"image"`
	ConfigDigestStudy   string      `json:"config_digest_study"`
	ConfigDigestArchive string      `json:"config_digest_archive,omitempty"`
	Status              ImageStatus `json:"status"`
	Error               string      `json:"error,omitempty"`

	Pulled        bool    `json:"pulled,omitempty"`
	PullSeconds   float64 `json:"pull_seconds,omitempty"`
	ExportSeconds float64 `json:"export_seconds"`
	DockleSeconds float64 `json:"dockle_seconds"`

	DockleExitCode int `json:"dockle_exit_code"`
	// DockleStdout is the report as Dockle wrote it. It is kept in full for an
	// image with a report and as an excerpt otherwise.
	DockleStdout string `json:"dockle_stdout,omitempty"`
	DockleStderr string `json:"dockle_stderr,omitempty"`
}

// RunInfo is raw/run.json: what ran, so that -analyze-only can report it.
type RunInfo struct {
	DockleVersion string `json:"dockle_version"`
	Engine        string `json:"engine"`
	Platform      string `json:"platform,omitempty"`
}

// Pipeline exports each image, checks the archive against the study, runs
// Dockle and removes the archive.
type Pipeline struct {
	Exporter Exporter
	Dockle   DockleRunner
	// Platform is passed to the exporter.
	Platform string
	// Timeout bounds the work for one image. Zero means no limit.
	Timeout time.Duration
	// TempDir holds the archives. Empty means the system temporary directory.
	TempDir string
	// Now is the clock. Tests replace it.
	Now func() time.Time
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// maxExcerpt bounds the output kept for a failure.
const maxExcerpt = 4096

// Process runs the Dockle side for one COMPLETED study record. It never
// returns a result for an image whose archive does not match the study: such
// an image gets a status that is not OK and an error message.
func (p *Pipeline) Process(ctx context.Context, rec *spec.SuiteResult) *ImageRecord {
	ref := studyfile.RecordKey(rec)
	out := &ImageRecord{Image: ref, ConfigDigestStudy: rec.ConfigDigest, Status: ImageOK}
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}
	if strings.TrimSpace(rec.ConfigDigest) == "" {
		out.Status, out.Error = ImageNoStudyDigest, "the study record has no config_digest, so the archive cannot be verified"
		return out
	}

	dir, err := os.MkdirTemp(p.TempDir, "crosscheck-archive-*")
	if err != nil {
		out.Status, out.Error = ImageExportError, "cannot create a temporary directory: "+err.Error()
		return out
	}
	// The archive is deleted on every path, including the failures.
	defer os.RemoveAll(dir)
	archive := filepath.Join(dir, "image.tar")
	scrub := func(s string) string { return strings.ReplaceAll(s, dir, "<tmp>") }

	// Export. The time of the export is the time the exporter reports for it.
	info, err := p.Exporter.Export(ctx, ref, p.Platform, archive)
	out.Pulled, out.PullSeconds, out.ExportSeconds = info.Pulled, info.PullSeconds, info.ExportSeconds
	if err != nil {
		out.Status, out.Error = ImageExportError, scrub(err.Error())
		return out
	}

	// Digest check: the archive must be the image that the study evaluated.
	got, err := ArchiveConfigDigest(archive)
	if err != nil {
		out.Status, out.Error = ImageArchiveError, scrub(err.Error())
		return out
	}
	out.ConfigDigestArchive = got
	if want := NormalizeDigest(rec.ConfigDigest); got != want {
		out.Status = ImageDigestMismatch
		out.Error = fmt.Sprintf("the archive config digest %s differs from the study config digest %s", got, want)
		return out
	}

	// Dockle.
	start := p.now()
	run, err := p.Dockle.Run(ctx, archive)
	out.DockleSeconds = p.now().Sub(start).Seconds()
	out.DockleExitCode = run.ExitCode
	out.DockleStderr = excerptText(scrub(string(run.Stderr)))
	if err != nil {
		out.Status, out.Error = ImageDockleError, scrub(err.Error())
		out.DockleStdout = excerptText(scrub(string(run.Stdout)))
		return out
	}
	if run.ExitCode != 0 {
		out.Status = ImageDockleError
		out.Error = fmt.Sprintf("dockle exited with code %d (%s)", run.ExitCode, scrub(excerpt(run.Stdout)))
		out.DockleStdout = excerptText(scrub(string(run.Stdout)))
		return out
	}
	if _, err := ParseReport(run.Stdout); err != nil {
		out.Status, out.Error = ImageParseError, scrub(err.Error())
		out.DockleStdout = excerptText(scrub(string(run.Stdout)))
		return out
	}
	out.DockleStdout = string(run.Stdout)
	return out
}

func excerptText(s string) string {
	if len(s) > maxExcerpt {
		return s[:maxExcerpt] + "\n[truncated]"
	}
	return s
}
