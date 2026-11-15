package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

// Output file names, fixed by docs/CONTRACT.md section 7.
const (
	telemetryFile = "rq3_telemetry.json"
	markdownFile  = "RQ3_PERFORMANCE.md"
	tableFile     = "table_rq3_trials.tex"
	macrosFile    = "macros_rq3.tex"
)

// TelemetrySchemaVersion identifies the layout of rq3_telemetry.json.
const TelemetrySchemaVersion = "1"

// Fixed method statements. They describe how numbers are computed and carry no
// conclusion. They are repeated in the JSON so the file is self-describing.
const (
	methodQuantiles = "Median and quartiles by linear interpolation between order statistics (type 7). IQR is Q3 minus Q1."
	methodCI        = "Mean with a two-sided 95% confidence interval from Student's t distribution with n-1 degrees of freedom. The normal value 1.960 is used beyond 30 degrees of freedom. Standard deviation uses n-1."
	methodTier3     = "Tier 3 duration is bounded below by the probe window W by design. It is not a performance result."
	methodCold      = "Cold trials follow an explicit image purge and include a registry transfer. They are network dependent and are reported apart from the warm local-store trials."
	methodMemory    = "Memory figures describe the ConUnit process only, never the container engine or probe containers. Peak RSS is reported once as a ceiling over the whole batch, not per image."
	methodCPU       = "ConUnit CPU time is the user plus system time of this process. Child CPU time covers the engine CLI and Syft. Both are reported only when the runner provides them."
)

// Protocol records the trial protocol and configuration of the run.
type Protocol struct {
	Pack                   string `json:"pack"`
	PackID                 string `json:"pack_id,omitempty"`
	TimedTrials            int    `json:"timed_trials"`
	WarmupTrials           int    `json:"warmup_trials"`
	ColdTrials             int    `json:"cold_trials"`
	TrialTimeoutNs         int64  `json:"trial_timeout_ns"`
	MaxConsecutiveFailures int    `json:"max_consecutive_failures"`
	RequestedPlatform      string `json:"requested_platform,omitempty"`
	RequestedImageSource   string `json:"requested_image_source"`
	RequestedProbeWindowNs int64  `json:"requested_probe_window_ns"`
	DatasetPath            string `json:"dataset_path,omitempty"`
	ArchetypesFile         string `json:"archetypes_file"`
	ArchetypesLoaded       bool   `json:"archetypes_loaded"`
	QuantileMethod         string `json:"quantile_method"`
	CIMethod               string `json:"ci_method"`
	Tier3Note              string `json:"tier3_note"`
	ColdNote               string `json:"cold_note"`
	MemoryNote             string `json:"memory_note"`
	CPUNote                string `json:"cpu_note"`
	// Tier3Treatments are the Tier 3 treatments of the pack in the order the
	// pack runs them, and Tier3FloorNote states what the Tier 3 floor assumes.
	// Tier3Treatments is null in telemetry that does not say.
	Tier3Treatments []string `json:"tier3_treatments"`
	Tier3FloorNote  string   `json:"tier3_floor_note"`
	// DockleBinary, DockleVersion and DockleNote are set with -dockle.
	DockleBinary  string   `json:"dockle_binary,omitempty"`
	DockleVersion string   `json:"dockle_version,omitempty"`
	DockleNote    string   `json:"dockle_note,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// methodDockle states what the Dockle comparison times.
const methodDockle = "Dockle comparison: after every warm-up and timed trial of ConUnit that succeeded, the same image is exported from the local store of the engine to a docker-archive (the export time) and Dockle is run on that archive with --format json (the analysis time), on the same host. " +
	"The Dockle time of a trial is export plus analysis. Cold trials are not compared. Per image the median over its timed trials is taken, and the figures of the paper are the medians over images, in seconds."

// AcrossImages summarizes the per-image medians over all images that have
// statistics. Each value is a Stats over one median per image.
type AcrossImages struct {
	Images      int   `json:"images"`
	Total       Stats `json:"total"`
	NonTier3    Stats `json:"non_tier3"`
	Resolve     Stats `json:"resolve"`
	StreamIndex Stats `json:"stream_index"`
	Tier1       Stats `json:"tier1"`
	Tier2       Stats `json:"tier2"`
	Tier3       Stats `json:"tier3"`
	Tier4       Stats `json:"tier4"`
}

// Summary aggregates the run.
type Summary struct {
	ImagesRequested int `json:"images_requested"`
	ImagesCompleted int `json:"images_completed"`
	ImagesPartial   int `json:"images_partial"`
	ImagesFailed    int `json:"images_failed"`
	// BatchPeakRSSMB is the maximum process peak RSS over all trials of the
	// batch. ConUnit process only.
	BatchPeakRSSMB float64       `json:"batch_peak_rss_mb"`
	Across         *AcrossImages `json:"across_images,omitempty"`
	// Dockle summarizes the Dockle durations across images. Nil without -dockle
	// or when no image has a trial with both durations.
	Dockle *DockleSummary `json:"dockle,omitempty"`
}

// DockleSummary is the distribution across images of the per-image median
// Dockle times. Every value is in seconds: Total is export plus analysis,
// Export and Run are the two parts. Each of the three is the median over images
// of its own per-image median, so Export and Run do not add up to Total.
type DockleSummary struct {
	Images int   `json:"images"`
	Total  Stats `json:"total"`
	Export Stats `json:"export"`
	Run    Stats `json:"run"`
}

// dockleAcross summarizes the Dockle times of the images that have them.
func dockleAcross(images []ImageResult) *DockleSummary {
	var total, export, run []float64
	for _, img := range images {
		if img.Stats == nil || img.Stats.Dockle == nil {
			continue
		}
		d := img.Stats.Dockle
		total = append(total, d.Total.Median/1000)
		export = append(export, d.Export.Median/1000)
		run = append(run, d.Run.Median/1000)
	}
	if len(total) == 0 {
		return nil
	}
	return &DockleSummary{Images: len(total), Total: ComputeStats(total, "s"), Export: ComputeStats(export, "s"), Run: ComputeStats(run, "s")}
}

// Telemetry is rq3_telemetry.json.
type Telemetry struct {
	SchemaVersion string           `json:"schema_version"`
	Complete      bool             `json:"complete"` // false while the run is in progress or when it was interrupted
	Run           spec.RunMetadata `json:"run"`
	Protocol      Protocol         `json:"protocol"`
	Summary       Summary          `json:"summary"`
	Images        []ImageResult    `json:"images"`
}

// Summarize computes the Summary of the images benchmarked so far.
func Summarize(images []ImageResult, requested int) Summary {
	s := Summary{ImagesRequested: requested}
	for _, img := range images {
		switch img.Status {
		case ImageCompleted:
			s.ImagesCompleted++
		case ImagePartial:
			s.ImagesPartial++
		default:
			s.ImagesFailed++
		}
		for _, group := range [][]TrialRecord{img.Warmup, img.Trials, img.Cold} {
			for _, t := range group {
				if t.Resources.ProcessPeakRSSMB > s.BatchPeakRSSMB {
					s.BatchPeakRSSMB = t.Resources.ProcessPeakRSSMB
				}
			}
		}
	}
	s.Across = acrossImages(images)
	s.Dockle = dockleAcross(images)
	return s
}

func acrossImages(images []ImageResult) *AcrossImages {
	var with []*PhaseStats
	for _, img := range images {
		if img.Stats != nil {
			with = append(with, img.Stats)
		}
	}
	if len(with) == 0 {
		return nil
	}
	medians := func(get func(*PhaseStats) Stats) Stats {
		vals := make([]float64, len(with))
		for i, p := range with {
			vals[i] = get(p).Median
		}
		return ComputeStats(vals, "ns")
	}
	return &AcrossImages{
		Images:      len(with),
		Total:       medians(func(p *PhaseStats) Stats { return p.Total }),
		NonTier3:    medians(func(p *PhaseStats) Stats { return p.NonTier3 }),
		Resolve:     medians(func(p *PhaseStats) Stats { return p.Resolve }),
		StreamIndex: medians(func(p *PhaseStats) Stats { return p.StreamIndex }),
		Tier1:       medians(func(p *PhaseStats) Stats { return p.Tier1 }),
		Tier2:       medians(func(p *PhaseStats) Stats { return p.Tier2 }),
		Tier3:       medians(func(p *PhaseStats) Stats { return p.Tier3 }),
		Tier4:       medians(func(p *PhaseStats) Stats { return p.Tier4 }),
	}
}

// WriteAll writes every output file into dir. Files are written atomically, so
// a crash during the write leaves the previous complete version in place.
func WriteAll(dir string, tel *Telemetry) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tel, "", "  ")
	if err != nil {
		return err
	}
	outputs := []struct {
		name string
		data []byte
	}{
		{telemetryFile, append(data, '\n')},
		{markdownFile, []byte(RenderMarkdown(tel))},
		{tableFile, []byte(RenderTable(tel))},
		{macrosFile, []byte(RenderMacros(tel))},
	}
	var errs []string
	for _, o := range outputs {
		if err := writeFileAtomic(filepath.Join(dir, o.name), o.data); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", o.name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("writing outputs failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// fmtMs formats nanoseconds as milliseconds with microsecond resolution.
func fmtMs(ns float64) string {
	return strconv.FormatFloat(ns/1e6, 'f', 3, 64)
}

// fmtMsTable formats nanoseconds as milliseconds with about three significant
// digits for the compact table.
func fmtMsTable(ns float64) string {
	ms := ns / 1e6
	switch {
	case ms < 1:
		return strconv.FormatFloat(ms, 'f', 3, 64)
	case ms < 100:
		return strconv.FormatFloat(ms, 'f', 2, 64)
	default:
		return strconv.FormatFloat(ms, 'f', 1, 64)
	}
}

func fmtSec(s float64) string { return strconv.FormatFloat(s, 'f', 3, 64) }

// orDash returns "-" for an empty value.
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// RenderMarkdown renders RQ3_PERFORMANCE.md. It lists measured values and the
// fixed method statements. It contains no interpretation.
func RenderMarkdown(tel *Telemetry) string {
	var sb strings.Builder
	run := tel.Run
	sb.WriteString("# RQ3 Performance Measurements\n\n")
	sb.WriteString("Generated by tools/benchmark_rq3. This file lists measured values only.\n")
	if !tel.Complete {
		sb.WriteString("\nThis run did not finish. The values below cover the images benchmarked so far.\n")
	}

	sb.WriteString("\n## Environment\n\n| Field | Value |\n|:---|:---|\n")
	env := [][2]string{
		{"Execution mode", run.ExecutionMode},
		{"Virtualization", run.Virtualization},
		{"Cloud provider", run.CloudProvider},
		{"Instance type", run.InstanceType},
		{"AMI", run.AMIID},
		{"Region", run.Region},
		{"Host OS and architecture", strings.Trim(run.HostOS+"/"+run.HostArch, "/")},
		{"Linux kernel", run.LinuxKernel},
		{"CPU model", run.CPUModel},
		{"vCPUs", intOrEmpty(run.VCPUs)},
		{"Memory", memoryString(run.MemoryBytes)},
		{"Container engine", strings.TrimSpace(run.EngineName + " " + run.EngineVersion)},
		{"Rootless", boolPtrString(run.Rootless)},
		{"Cgroup version", run.CgroupVersion},
		{"Storage driver", run.StorageDriver},
		{"OCI runtime", run.OCIRuntime},
		{"ConUnit version", run.ConUnitVersion},
		{"Commit", run.Commit},
		{"Tainted", strconv.FormatBool(run.Tainted)},
		{"Go version", run.GoVersion},
		{"Dataset", run.DatasetPath},
		{"Dataset SHA-256", run.DatasetSHA256},
		{"Pack", strings.TrimSpace(tel.Protocol.Pack + " " + run.PackID)},
		{"Platform", run.Platform},
		{"Image source policy", run.ImageSource},
		{"Probe window W", windowString(run.ProbeWindowMs)},
		{"Started", run.StartedAt.Format("2006-01-02T15:04:05Z07:00")},
		{"Finished", finishedString(run)},
	}
	for _, kv := range env {
		fmt.Fprintf(&sb, "| %s | %s |\n", kv[0], mdCell(orDash(kv[1])))
	}

	p := tel.Protocol
	sb.WriteString("\n## Protocol\n\n")
	fmt.Fprintf(&sb, "- Warm-up iterations (discarded): %d\n", p.WarmupTrials)
	fmt.Fprintf(&sb, "- Timed trials per image: %d\n", p.TimedTrials)
	fmt.Fprintf(&sb, "- Cold trials per image (network dependent): %d\n", p.ColdTrials)
	fmt.Fprintf(&sb, "- Archetype source: %s (%s)\n", p.ArchetypesFile, loadedString(p.ArchetypesLoaded))
	for _, w := range p.Warnings {
		fmt.Fprintf(&sb, "- Warning: %s\n", w)
	}

	s := tel.Summary
	sb.WriteString("\n## Image flow\n\n")
	fmt.Fprintf(&sb, "- Requested: %d\n- Completed: %d\n- Partial: %d\n- Failed: %d\n", s.ImagesRequested, s.ImagesCompleted, s.ImagesPartial, s.ImagesFailed)

	sb.WriteString("\n## Latency per image (warm local store, milliseconds)\n\n")
	sb.WriteString("| Image | Archetype | Status | n | Median | IQR | Mean | 95% CI of mean | Min | Max |\n")
	sb.WriteString("|:---|:---|:---|:---:|---:|---:|---:|:---:|---:|---:|\n")
	for _, img := range tel.Images {
		if img.Stats == nil {
			fmt.Fprintf(&sb, "| `%s` | %s | %s | 0/%d | - | - | - | - | - | - |\n", img.Repository, img.Archetype, img.Status, p.TimedTrials)
			continue
		}
		t := img.Stats.Total
		ci := "n/a"
		if t.CIDefined {
			ci = fmt.Sprintf("%s to %s", fmtMs(t.CILow), fmtMs(t.CIHigh))
		}
		fmt.Fprintf(&sb, "| `%s` | %s | %s | %d/%d | %s | %s | %s | %s | %s | %s |\n",
			img.Repository, img.Archetype, img.Status, t.N, p.TimedTrials,
			fmtMs(t.Median), fmtMs(t.IQR), fmtMs(t.Mean), ci, fmtMs(t.Min), fmtMs(t.Max))
	}

	sb.WriteString("\n## Phase medians (milliseconds)\n\n")
	fmt.Fprintf(&sb, "Tier 3 is bounded below by %s and is not a performance result.\n\n", windowPhrase(run.ProbeWindowMs))
	sb.WriteString("| Image | Resolve | Stream and index | Tier 1 | Tier 2 | Tier 3 (bounded by W) | Tier 4 | Total without Tier 3 |\n")
	sb.WriteString("|:---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, img := range tel.Images {
		if img.Stats == nil {
			continue
		}
		ps := img.Stats
		fmt.Fprintf(&sb, "| `%s` | %s | %s | %s | %s | %s | %s | %s |\n", img.Repository,
			fmtMs(ps.Resolve.Median), fmtMs(ps.StreamIndex.Median), fmtMs(ps.Tier1.Median), fmtMs(ps.Tier2.Median),
			fmtMs(ps.Tier3.Median), fmtMs(ps.Tier4.Median), fmtMs(ps.NonTier3.Median))
	}

	if hasCPU(tel.Images) {
		sb.WriteString("\n## CPU time per evaluation (median seconds)\n\n")
		sb.WriteString("| Image | ConUnit process | Child processes |\n|:---|---:|---:|\n")
		for _, img := range tel.Images {
			if img.Stats == nil || img.Stats.SelfCPU == nil {
				continue
			}
			fmt.Fprintf(&sb, "| `%s` | %s | %s |\n", img.Repository, fmtSec(img.Stats.SelfCPU.Median), fmtSec(img.Stats.ChildCPU.Median))
		}
	} else {
		sb.WriteString("\n## CPU time per evaluation\n\nNot reported: the runner did not provide CPU time for these trials.\n")
	}

	if p.ColdTrials > 0 {
		sb.WriteString("\n## Cold registry trials (network dependent, milliseconds)\n\n")
		sb.WriteString("| Image | OK trials | Median | IQR | Mean | 95% CI of mean |\n|:---|:---:|---:|---:|---:|:---:|\n")
		for _, img := range tel.Images {
			if img.ColdStats == nil {
				fmt.Fprintf(&sb, "| `%s` | 0/%d | - | - | - | - |\n", img.Repository, p.ColdTrials)
				continue
			}
			t := img.ColdStats.Total
			ci := "n/a"
			if t.CIDefined {
				ci = fmt.Sprintf("%s to %s", fmtMs(t.CILow), fmtMs(t.CIHigh))
			}
			fmt.Fprintf(&sb, "| `%s` | %d/%d | %s | %s | %s | %s |\n", img.Repository, t.N, p.ColdTrials,
				fmtMs(t.Median), fmtMs(t.IQR), fmtMs(t.Mean), ci)
		}
	}

	if p.DockleBinary != "" {
		sb.WriteString("\n## Dockle comparison (seconds per image, same host and trials)\n\n")
		fmt.Fprintf(&sb, "Dockle: %s (%s).\n\n", mdCell(p.DockleBinary), mdCell(orDash(p.DockleVersion)))
		if d := s.Dockle; d == nil {
			sb.WriteString("No image has a trial with both Dockle durations.\n")
		} else {
			sb.WriteString("| Measure | Images | Median | Min | Max |\n|:---|:---:|---:|---:|---:|\n")
			for _, row := range []struct {
				name string
				st   Stats
			}{{"Export plus analysis", d.Total}, {"Export", d.Export}, {"Analysis", d.Run}} {
				fmt.Fprintf(&sb, "| %s | %d | %.3f | %.3f | %.3f |\n", row.name, d.Images, row.st.Median, row.st.Min, row.st.Max)
			}
		}
	}

	sb.WriteString("\n## Resource ceiling (ConUnit process only)\n\n")
	fmt.Fprintf(&sb, "- Batch peak RSS: %.1f MB\n", s.BatchPeakRSSMB)
	if hasLiveHeap(tel.Images) {
		sb.WriteString("\n| Image | Live heap median (MB) | Layers | Uncompressed size (MB) |\n|:---|---:|---:|---:|\n")
		for _, img := range tel.Images {
			if img.Stats == nil || img.Stats.LiveHeap == nil {
				continue
			}
			fmt.Fprintf(&sb, "| `%s` | %.1f | %d | %.1f |\n", img.Repository, img.Stats.LiveHeap.Median, img.LayerCount, float64(img.UncompressedBytes)/(1024*1024))
		}
	}

	var failures []string
	for _, img := range tel.Images {
		for _, group := range [][]TrialRecord{img.Warmup, img.Trials, img.Cold} {
			for _, t := range group {
				if !t.OK() {
					failures = append(failures, fmt.Sprintf("| `%s` | %s %d | %s | %s |", img.Repository, t.Kind, t.Iteration, t.Status, mdCell(oneLine(t.Error))))
				}
			}
		}
	}
	sb.WriteString("\n## Failed trials\n\n")
	if len(failures) == 0 {
		sb.WriteString("None.\n")
	} else {
		sb.WriteString("| Image | Trial | Status | Error |\n|:---|:---|:---|:---|\n")
		sb.WriteString(strings.Join(failures, "\n") + "\n")
	}

	sb.WriteString("\n## Methods\n\n")
	for _, m := range []string{methodQuantiles, methodCI, methodTier3, methodCold, methodMemory, methodCPU} {
		fmt.Fprintf(&sb, "- %s\n", m)
	}
	if p.Tier3FloorNote != "" {
		fmt.Fprintf(&sb, "- %s Treatments of this pack: %s.\n", p.Tier3FloorNote, orDash(strings.Join(p.Tier3Treatments, ", ")))
	}
	if p.DockleNote != "" {
		fmt.Fprintf(&sb, "- %s\n", p.DockleNote)
	}
	return sb.String()
}

func hasCPU(images []ImageResult) bool {
	for _, img := range images {
		if img.Stats != nil && img.Stats.SelfCPU != nil {
			return true
		}
	}
	return false
}

func hasLiveHeap(images []ImageResult) bool {
	for _, img := range images {
		if img.Stats != nil && img.Stats.LiveHeap != nil {
			return true
		}
	}
	return false
}

func intOrEmpty(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func memoryString(b int64) string {
	if b <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
}

func boolPtrString(b *bool) string {
	if b == nil {
		return ""
	}
	return strconv.FormatBool(*b)
}

func windowString(ms int64) string {
	if ms <= 0 {
		return "not applied"
	}
	return strconv.FormatInt(ms, 10)
}

// windowPhrase names the probe window for prose. A window that was not applied
// is said so instead of printing a number.
func windowPhrase(ms int64) string {
	if ms <= 0 {
		return "the probe window (length not recorded in this run)"
	}
	return fmt.Sprintf("the probe window of %d ms", ms)
}

func finishedString(run spec.RunMetadata) string {
	if run.FinishedAt.IsZero() {
		return ""
	}
	return run.FinishedAt.Format("2006-01-02T15:04:05Z07:00")
}

func loadedString(loaded bool) string {
	if loaded {
		return "loaded"
	}
	return "not found, images are labeled " + Unclassified
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func mdCell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// latexEscape escapes the characters that are special in LaTeX text.
func latexEscape(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			sb.WriteString(`\textbackslash{}`)
		case '&', '%', '$', '#', '_', '{', '}':
			sb.WriteRune('\\')
			sb.WriteRune(r)
		case '~':
			sb.WriteString(`\textasciitilde{}`)
		case '^':
			sb.WriteString(`\textasciicircum{}`)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// RenderTable renders table_rq3_trials.tex: one row per image with statistics.
func RenderTable(tel *Telemetry) string {
	p := tel.Protocol
	showCPU := hasCPU(tel.Images)

	var sb strings.Builder
	sb.WriteString("% Generated by tools/benchmark_rq3 from rq3_telemetry.json. Do not edit by hand.\n")
	sb.WriteString("\\begin{table*}[t]\n\\centering\n\\small\n")
	fmt.Fprintf(&sb, "\\caption{Evaluation latency per image in milliseconds, warm local store: median, interquartile range, and mean with a 95\\%% Student-$t$ interval over %d timed trials. Warm-up iterations discarded per image: %d. ",
		p.TimedTrials, p.WarmupTrials)
	fmt.Fprintf(&sb, "Phase columns are medians. Tier 3 (\\dag) is bounded below by %s and is not a performance result.", windowPhrase(tel.Run.ProbeWindowMs))
	if showCPU {
		sb.WriteString(" CPU columns are medians in seconds for the ConUnit process and its child processes.")
	}
	sb.WriteString("}\n\\label{tab:rq3_trials}\n\\resizebox{\\textwidth}{!}{\n")
	cols := "llrrrrrrrrrr"
	header := "\\textbf{Image} & \\textbf{Archetype} & \\textbf{n} & \\textbf{Median} & \\textbf{IQR} & \\textbf{Mean $\\pm$ CI} & \\textbf{Resolve} & \\textbf{Stream+index} & \\textbf{Tier 1} & \\textbf{Tier 2} & \\textbf{Tier 3 (\\dag)} & \\textbf{Tier 4}"
	if showCPU {
		cols += "rr"
		header += " & \\textbf{CPU self} & \\textbf{CPU child}"
	}
	fmt.Fprintf(&sb, "\\begin{tabular}{%s}\n\\toprule\n%s \\\\\n\\midrule\n", cols, header)
	for _, img := range tel.Images {
		ps := img.Stats
		if ps == nil {
			continue
		}
		n := strconv.Itoa(ps.Total.N)
		if ps.Total.N != p.TimedTrials {
			n = fmt.Sprintf("%d/%d", ps.Total.N, p.TimedTrials)
		}
		meanCI := fmtMsTable(ps.Total.Mean)
		if ps.Total.CIDefined {
			meanCI += " $\\pm$ " + fmtMsTable(ps.Total.CIHalfWidth)
		}
		row := []string{
			"\\texttt{" + latexEscape(img.Repository) + "}",
			latexEscape(img.Archetype),
			n,
			fmtMsTable(ps.Total.Median),
			fmtMsTable(ps.Total.IQR),
			meanCI,
			fmtMsTable(ps.Resolve.Median),
			fmtMsTable(ps.StreamIndex.Median),
			fmtMsTable(ps.Tier1.Median),
			fmtMsTable(ps.Tier2.Median),
			fmtMsTable(ps.Tier3.Median),
			fmtMsTable(ps.Tier4.Median),
		}
		if showCPU {
			if ps.SelfCPU != nil {
				row = append(row, fmtSec(ps.SelfCPU.Median), fmtSec(ps.ChildCPU.Median))
			} else {
				row = append(row, "-", "-")
			}
		}
		sb.WriteString(strings.Join(row, " & ") + " \\\\\n")
	}
	sb.WriteString("\\bottomrule\n\\end{tabular}\n}\n\\end{table*}\n")
	return sb.String()
}

// macroMetric names a phase for macros: the name part contains letters only.
type macroMetric struct {
	name string
	get  func(*PhaseStats) Stats
}

var macroMetrics = []macroMetric{
	{"Total", func(p *PhaseStats) Stats { return p.Total }},
	{"NonTierThree", func(p *PhaseStats) Stats { return p.NonTier3 }},
	{"Resolve", func(p *PhaseStats) Stats { return p.Resolve }},
	{"StreamIndex", func(p *PhaseStats) Stats { return p.StreamIndex }},
	{"TierOne", func(p *PhaseStats) Stats { return p.Tier1 }},
	{"TierTwo", func(p *PhaseStats) Stats { return p.Tier2 }},
	{"TierThree", func(p *PhaseStats) Stats { return p.Tier3 }},
	{"TierFour", func(p *PhaseStats) Stats { return p.Tier4 }},
}

// RenderMacros renders macros_rq3.tex. Every macro name contains letters only.
// Per-image macros are keyed by the sanitized image name, never by position.
// Durations are milliseconds, CPU time is seconds.
func RenderMacros(tel *Telemetry) string {
	var sb strings.Builder
	def := func(name, value string) {
		fmt.Fprintf(&sb, "\\newcommand{\\%s}{%s}\n", name, value)
	}
	const pre = "ConUnitRQThree"

	sb.WriteString("% Generated by tools/benchmark_rq3 from rq3_telemetry.json. Do not edit by hand.\n")
	sb.WriteString("% Macro names contain letters only. Durations are in milliseconds, CPU time in seconds.\n")
	sb.WriteString("% Per-image macros end in the sanitized image key (repository name and tag, digits spelled out).\n\n")

	p, s, run := tel.Protocol, tel.Summary, tel.Run
	def(pre+"TimedTrials", strconv.Itoa(p.TimedTrials))
	def(pre+"WarmupTrials", strconv.Itoa(p.WarmupTrials))
	def(pre+"ColdTrials", strconv.Itoa(p.ColdTrials))
	def(pre+"ProbeWindowMs", latexEscape(windowString(run.ProbeWindowMs)))
	def(pre+"NImages", strconv.Itoa(s.ImagesRequested))
	def(pre+"NCompleted", strconv.Itoa(s.ImagesCompleted))
	def(pre+"NPartial", strconv.Itoa(s.ImagesPartial))
	def(pre+"NFailed", strconv.Itoa(s.ImagesFailed))
	def(pre+"BatchPeakRSSMB", fmt.Sprintf("%.1f", s.BatchPeakRSSMB))

	sb.WriteString("\n% Environment of the RQ3 run.\n")
	def(pre+"EnvInstanceType", latexEscape(orDash(run.InstanceType)))
	def(pre+"EnvEngine", latexEscape(orDash(strings.TrimSpace(run.EngineName+" "+run.EngineVersion))))
	def(pre+"EnvKernel", latexEscape(orDash(run.LinuxKernel)))
	def(pre+"EnvVirt", latexEscape(orDash(run.Virtualization)))
	def(pre+"EnvMode", latexEscape(orDash(run.ExecutionMode)))
	def(pre+"EnvCPU", latexEscape(orDash(run.CPUModel)))
	def(pre+"EnvVCPUs", latexEscape(orDash(intOrEmpty(run.VCPUs))))
	def(pre+"EnvDate", latexEscape(orDash(dateOnly(run.StartedAt))))

	writeDockleAndFloorMacros(&sb, tel)

	if s.Across != nil {
		sb.WriteString("\n% Distribution across images of the per-image medians.\n")
		def(pre+"AcrossImages", strconv.Itoa(s.Across.Images))
		across := map[string]Stats{
			"Total": s.Across.Total, "NonTierThree": s.Across.NonTier3, "Resolve": s.Across.Resolve,
			"StreamIndex": s.Across.StreamIndex, "TierOne": s.Across.Tier1, "TierTwo": s.Across.Tier2,
			"TierThree": s.Across.Tier3, "TierFour": s.Across.Tier4,
		}
		for _, m := range macroMetrics {
			st := across[m.name]
			def(pre+"Across"+m.name+"MedianMs", fmtMs(st.Median))
			def(pre+"Across"+m.name+"MinMs", fmtMs(st.Min))
			def(pre+"Across"+m.name+"MaxMs", fmtMs(st.Max))
		}
	}

	imgs := append([]ImageResult(nil), tel.Images...)
	sort.Slice(imgs, func(i, j int) bool { return imgs[i].MacroKey < imgs[j].MacroKey })
	for _, img := range imgs {
		key := img.MacroKey
		fmt.Fprintf(&sb, "\n%% %s\n", sanitizeComment(img.Ref))
		def(pre+"Status"+key, img.Status)
		def(pre+"NTrials"+key, strconv.Itoa(img.OKTimed()))
		if ps := img.Stats; ps != nil {
			for _, m := range macroMetrics {
				def(pre+m.name+"MedianMs"+key, fmtMs(m.get(ps).Median))
			}
			t := ps.Total
			def(pre+"TotalIQRMs"+key, fmtMs(t.IQR))
			def(pre+"TotalMeanMs"+key, fmtMs(t.Mean))
			if t.CIDefined {
				def(pre+"TotalCIHalfMs"+key, fmtMs(t.CIHalfWidth))
			}
			if ps.SelfCPU != nil {
				def(pre+"SelfCPUMedianSec"+key, fmtSec(ps.SelfCPU.Median))
				def(pre+"ChildCPUMedianSec"+key, fmtSec(ps.ChildCPU.Median))
			}
		}
		if img.ColdStats != nil {
			def(pre+"ColdNTrials"+key, strconv.Itoa(img.ColdStats.Total.N))
			def(pre+"ColdTotalMedianMs"+key, fmtMs(img.ColdStats.Total.Median))
		}
	}
	return sb.String()
}

// writeDockleAndFloorMacros writes the macros of the Dockle comparison and of the
// Tier 3 floor. Their names are fixed by docs/INTERFACE_V2.md section 6, which
// spells the RQ3 part of the Dockle names Rq. All four are plain numbers in
// seconds without a unit, and n/a when there is no data.
func writeDockleAndFloorMacros(sb *strings.Builder, tel *Telemetry) {
	na := tex.NotAvailable
	seconds := func(get func(*DockleSummary) Stats) string {
		if tel.Summary.Dockle == nil {
			return na
		}
		return fmt.Sprintf("%.3f", get(tel.Summary.Dockle).Median)
	}
	def := func(name, value, comment string) {
		fmt.Fprintf(sb, "%% %s\n\\newcommand{\\%s}{%s}\n", comment, name, value)
	}
	sb.WriteString("\n% Cost of the Dockle comparison on the same host and trials, in seconds per image, as plain numbers without a unit.\n")
	sb.WriteString("% Each is the median over images of the per-image median of the timed trials. n/a without -dockle.\n")
	def("ConUnitRqThreeDockleMedian", seconds(func(d *DockleSummary) Stats { return d.Total }),
		"Dockle seconds per image: archive export plus analysis of the same trial.")
	def("ConUnitRqThreeDockleExportMedian", seconds(func(d *DockleSummary) Stats { return d.Export }),
		"Seconds per image to export the image to a docker-archive.")
	def("ConUnitRqThreeDockleRunMedian", seconds(func(d *DockleSummary) Stats { return d.Run }),
		"Seconds per image of the Dockle analysis of the archive.")

	sb.WriteString("\n% Tier 3 floor, in seconds, as a plain number without a unit.\n")
	sb.WriteString("% (1 + N) x W with N the number of Tier 3 treatments of the pack and W the probe window of the run, both read from the run, not typed.\n")
	sb.WriteString("% Assumption: the baseline and the treatments run one after another, each container observed for the whole window, so an image whose containers stay running needs at least this long. An image that exits earlier needs less.\n")
	def("ConUnitTierThreeFloor", Tier3FloorText(tel.Protocol.Tier3Treatments, tel.Run.ProbeWindowMs),
		"Least Tier 3 seconds per image.")
}

func dateOnly(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

// sanitizeComment keeps a reference on one LaTeX comment line.
func sanitizeComment(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}
