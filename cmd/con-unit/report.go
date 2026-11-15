package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// statusOrder is the canonical order of image statuses in every report.
var statusOrder = []string{
	spec.StatusCompleted,
	spec.StatusTimeout,
	spec.StatusUnavailable,
	spec.StatusRateLimited,
	spec.StatusIndexLimit,
	spec.StatusExecutionError,
	spec.StatusExcluded,
}

func recordStatus(record *spec.SuiteResult) string {
	if record.Status == "" {
		return spec.StatusCompleted
	}
	return record.Status
}

func statusCounts(images []*spec.SuiteResult) map[string]int {
	counts := make(map[string]int)
	for _, image := range images {
		counts[recordStatus(image)]++
	}
	return counts
}

// orderedStatuses lists the statuses present in counts: canonical ones first
// in canonical order, then any unknown ones sorted by name. Report sections
// iterate this slice, never the map, so output is deterministic.
func orderedStatuses(counts map[string]int) []string {
	var ordered []string
	known := make(map[string]struct{}, len(statusOrder))
	for _, status := range statusOrder {
		known[status] = struct{}{}
		if counts[status] > 0 {
			ordered = append(ordered, status)
		}
	}
	var unknown []string
	for status, count := range counts {
		if _, ok := known[status]; !ok && count > 0 {
			unknown = append(unknown, status)
		}
	}
	sort.Strings(unknown)
	return append(ordered, unknown...)
}

// reasonCounts counts non-COMPLETED records by "STATUS / REASON".
func reasonCounts(images []*spec.SuiteResult) ([]string, map[string]int) {
	counts := make(map[string]int)
	for _, image := range images {
		status := recordStatus(image)
		if status == spec.StatusCompleted {
			continue
		}
		label := status
		if image.Reason != "" {
			label += " / " + string(image.Reason)
		}
		counts[label]++
	}
	labels := make([]string, 0, len(counts))
	for label := range counts {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels, counts
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

// sizeLabel renders a byte count with a binary unit, or n/a when it is unknown.
func sizeLabel(bytes int64) string {
	if bytes <= 0 {
		return "n/a"
	}
	return oci.FormatBytes(bytes)
}

func shortDigest(digest string) string {
	if digest == "" {
		return "n/a"
	}
	if len(digest) > 19 {
		return digest[:19] + "..."
	}
	return digest
}

// renderMarkdownSummary renders EMPIRICAL_SUMMARY.md. The output depends only
// on the study, so regenerating it from the same empirical_study.json yields
// identical bytes. It reports no pass rate and no per-image peak memory.
func renderMarkdownSummary(study *spec.Study) string {
	var sb strings.Builder
	sb.WriteString("# Empirical Evaluation Summary: Container Images\n\n")
	sb.WriteString(fmt.Sprintf("Run started: %s\n\n", formatTime(study.Run.StartedAt)))
	sb.WriteString(fmt.Sprintf("Run finished: %s\n\n", formatTime(study.Run.FinishedAt)))

	sb.WriteString("## Run Configuration\n\n")
	run := study.Run
	writeKV := func(key, value string) {
		if value != "" {
			sb.WriteString(fmt.Sprintf("- %s: %s\n", key, value))
		}
	}
	writeKV("ConUnit version", run.ConUnitVersion)
	if run.Commit != "" {
		commit := run.Commit
		if run.CommitDirty || run.Tainted {
			commit += " (tainted)"
		}
		writeKV("Commit", commit)
	}
	writeKV("Rule pack", strings.TrimSpace(run.Pack+" "+bracketed(run.PackID)))
	writeKV("Platform", run.Platform)
	writeKV("Image source policy", run.ImageSource)
	if run.ProbeWindowMs > 0 {
		writeKV("Tier 3 window W", fmt.Sprintf("%d ms (a lower bound on Tier 3 latency, not a performance result)", run.ProbeWindowMs))
	}
	writeKV("Engine", strings.TrimSpace(run.EngineName+" "+run.EngineVersion))
	if run.Rootless != nil {
		writeKV("Rootless", fmt.Sprintf("%t", *run.Rootless))
	}
	writeKV("Host", strings.TrimSpace(run.HostOS+"/"+run.HostArch+" "+run.LinuxKernel))
	writeKV("Virtualization", run.Virtualization)
	writeKV("Instance type", run.InstanceType)
	if run.VCPUs > 0 {
		writeKV("vCPUs", fmt.Sprintf("%d", run.VCPUs))
	}
	writeKV("Dataset SHA-256", run.DatasetSHA256)
	sb.WriteString("\n")

	counts := statusCounts(study.Images)
	completed := counts[spec.StatusCompleted]
	sb.WriteString("## Sample Flow and Attrition Accounting\n\n")
	sb.WriteString(fmt.Sprintf("- Attempted images: %d\n", len(study.Images)))
	sb.WriteString(fmt.Sprintf("- COMPLETED: %d\n", completed))
	sb.WriteString(fmt.Sprintf("- Not completed: %d\n", len(study.Images)-completed))
	for _, status := range orderedStatuses(counts) {
		if status != spec.StatusCompleted {
			sb.WriteString(fmt.Sprintf("  - %s: %d\n", status, counts[status]))
		}
	}

	sb.WriteString(renderBatchResources(study))

	sb.WriteString("\n## Results Matrix\n\n")
	sb.WriteString("Counts are checks per image. Prevalence statistics are computed by the exporter from verified (PASS or FAIL) results only.\n\n")
	sb.WriteString("| Target Image | Status | Source | Registry Digest | Platform | Layers | Compressed | Uncompressed | Passed | Failed | Unverified | Duration | Stream | Tier 3 | Notes |\n")
	sb.WriteString("|:---|:---:|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|\n")
	for _, r := range study.Images {
		status := recordStatus(r)
		source := r.ImageSource
		if source == "" {
			source = "n/a"
		}
		if status == spec.StatusCompleted {
			sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | `%s` | `%s` | %d | %s | %s | %d | %d | %d | %v | %v | %v | - |\n",
				r.ImageName, status, source, shortDigest(r.ImageDigest), r.Platform, r.Resources.LayerCount,
				sizeLabel(r.Resources.CompressedBytes), sizeLabel(r.Resources.UncompressedBytes),
				r.Passed, r.Failed, r.Unverified,
				r.Duration.Round(time.Millisecond), r.Phases.StreamDuration.Round(time.Millisecond), r.Phases.Tier3Duration.Round(time.Millisecond)))
			continue
		}
		note := string(r.Reason)
		if r.ErrorMessage != "" {
			if note != "" {
				note += ": "
			}
			note += r.ErrorMessage
		}
		sb.WriteString(fmt.Sprintf("| `%s` | **%s** | %s | n/a | n/a | 0 | n/a | n/a | 0 | 0 | 0 | n/a | n/a | n/a | %s |\n",
			r.ImageName, status, source, escapeMarkdown(note)))
	}
	return sb.String()
}

func bracketed(value string) string {
	if value == "" {
		return ""
	}
	return "(" + value + ")"
}

// renderAttritionReport renders ATTRITION_REPORT.md deterministically.
func renderAttritionReport(study *spec.Study) string {
	var sb strings.Builder
	sb.WriteString("# Empirical Evaluation Attrition and Exclusion Audit Report\n\n")
	sb.WriteString(fmt.Sprintf("Run finished: %s\n\n", formatTime(study.Run.FinishedAt)))

	counts := statusCounts(study.Images)
	completed := counts[spec.StatusCompleted]
	attrition := len(study.Images) - completed

	sb.WriteString("## 1. Denominator Flow Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Total attempted images: %d\n", len(study.Images)))
	sb.WriteString(fmt.Sprintf("- Successfully analyzed images: %d\n", completed))
	sb.WriteString(fmt.Sprintf("- Excluded attrition images: %d\n\n", attrition))

	sb.WriteString("## 2. Attrition Categorization\n\n")
	if attrition == 0 {
		sb.WriteString("Zero attrition observed. All attempted images completed evaluation.\n")
		return sb.String()
	}
	for _, status := range orderedStatuses(counts) {
		if status != spec.StatusCompleted {
			sb.WriteString(fmt.Sprintf("- **%s**: %d images\n", status, counts[status]))
		}
	}
	labels, byReason := reasonCounts(study.Images)
	sb.WriteString("\nBy status and reason:\n\n")
	for _, label := range labels {
		sb.WriteString(fmt.Sprintf("- %s: %d\n", label, byReason[label]))
	}
	sb.WriteString("\n## 3. Disaggregated Exclusion Log\n\n")
	sb.WriteString("Rows follow the order of the image list.\n\n")
	sb.WriteString("| Target Image | Classification | Reason | Timestamp | Diagnostic Error Message |\n")
	sb.WriteString("|:---|:---:|:---:|:---|:---|\n")
	for _, r := range study.Images {
		status := recordStatus(r)
		if status == spec.StatusCompleted {
			continue
		}
		reason := string(r.Reason)
		if reason == "" {
			reason = "-"
		}
		sb.WriteString(fmt.Sprintf("| `%s` | **%s** | %s | %s | %s |\n",
			r.ImageName, status, reason, formatTime(r.Timestamp), escapeMarkdown(r.ErrorMessage)))
	}
	sb.WriteString(renderIndexLimitSection(study))
	return sb.String()
}

// renderIndexLimitSection lists the images excluded by the filesystem index
// limit with their size. Such an image was not analyzed because of a limit of
// the tool, not because of a property of the image, so the study reports how
// large the excluded images are. It is empty when no image hit the limit.
func renderIndexLimitSection(study *spec.Study) string {
	var excluded []*spec.SuiteResult
	for _, r := range study.Images {
		if recordStatus(r) == spec.StatusIndexLimit {
			excluded = append(excluded, r)
		}
	}
	if len(excluded) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n## 4. Tool-Limit Exclusions (INDEX_LIMIT)\n\n")
	sb.WriteString("These images were not analyzed because ConUnit's filesystem index reached its configured limit. ")
	sb.WriteString("The limit belongs to the tool, not to the image. Entry counts and content sizes are lower bounds, measured before indexing stopped; ")
	sb.WriteString("the compressed size is known only when the layers were read from a registry.\n\n")
	sb.WriteString("| Target Image | Layers | Entries Counted | Compressed | Content Read (uncompressed) | Config Digest |\n")
	sb.WriteString("|:---|:---:|:---:|:---:|:---:|:---|\n")
	for _, r := range excluded {
		layers, entries := "n/a", "n/a"
		if r.Resources.LayerCount > 0 {
			layers = fmt.Sprintf("%d", r.Resources.LayerCount)
		}
		if r.Resources.IndexedEntries > 0 {
			entries = formatCount(r.Resources.IndexedEntries)
		}
		sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s | %s | `%s` |\n",
			r.ImageName, layers, entries, sizeLabel(r.Resources.CompressedBytes), sizeLabel(r.Resources.UncompressedBytes), shortDigest(r.ConfigDigest)))
	}
	return sb.String()
}

// batchResources summarizes the resource figures of a whole run. Memory is
// only ever reported as the process-wide ceiling over the batch: the peak
// resident set size never decreases within a process, so a per-image value
// would describe the images before it as much as the image itself.
type batchResources struct {
	peakRSSMB float64
	selfCPU   float64
	childCPU  float64
}

func (b batchResources) known() bool {
	return b.peakRSSMB > 0 || b.selfCPU > 0 || b.childCPU > 0
}

func summarizeBatchResources(images []*spec.SuiteResult) batchResources {
	var batch batchResources
	for _, r := range images {
		if r.Resources.PeakRSSMB > batch.peakRSSMB {
			batch.peakRSSMB = r.Resources.PeakRSSMB
		}
		batch.selfCPU += r.Resources.SelfCPUSeconds
		batch.childCPU += r.Resources.ChildCPUSeconds
	}
	return batch
}

// renderBatchResources states the batch figures and their scope. It is empty
// when no image carries resource figures.
func renderBatchResources(study *spec.Study) string {
	batch := summarizeBatchResources(study.Images)
	if !batch.known() {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n## Resources (ConUnit process only)\n\n")
	sb.WriteString("These figures describe the ConUnit process. They exclude the container engine and the probe containers.\n\n")
	if batch.peakRSSMB > 0 {
		sb.WriteString(fmt.Sprintf("- Peak resident set size over the whole run: %s (a ceiling of the process, not a per-image value)\n", oci.FormatBytes(int64(batch.peakRSSMB*1024*1024))))
	}
	sb.WriteString(fmt.Sprintf("- CPU time of the ConUnit process, summed over images: %.2f s\n", batch.selfCPU))
	sb.WriteString(fmt.Sprintf("- CPU time of child processes (engine CLI, Syft), summed over images: %.2f s\n", batch.childCPU))
	return sb.String()
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func sanitizeFilename(name string) string {
	s := strings.ReplaceAll(name, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "@", "_")
	return s
}

// writeImageDiagnosticLog writes the per-image diagnostic log. Failures to
// write it are not fatal; the journal is the record of the image.
func writeImageDiagnosticLog(logDir string, record *spec.SuiteResult) {
	_ = os.MkdirAll(logDir, 0o755)
	logFile := filepath.Join(logDir, sanitizeFilename(record.ImageName)+".log")
	const rule = "================================================================================\n"
	const thin = "--------------------------------------------------------------------------------\n"
	var sb strings.Builder
	sb.WriteString(rule)
	sb.WriteString(fmt.Sprintf("CONUNIT DIAGNOSTIC LOG FOR: %s\n", record.ImageName))
	sb.WriteString(fmt.Sprintf("TIMESTAMP: %s\n", formatTime(record.Timestamp)))
	sb.WriteString(rule + "\n")

	status := recordStatus(record)
	if status != spec.StatusCompleted {
		sb.WriteString(fmt.Sprintf("STATUS: %s\n", status))
		if record.Reason != "" {
			sb.WriteString(fmt.Sprintf("REASON: %s\n", record.Reason))
		}
		if record.ImageSource != "" {
			sb.WriteString(fmt.Sprintf("IMAGE SOURCE: %s\n", record.ImageSource))
		}
		// A failure after the image was identified keeps its identity and the
		// size read so far, which is what an INDEX_LIMIT exclusion reports.
		if record.ImageDigest != "" {
			sb.WriteString(fmt.Sprintf("REGISTRY DIGEST: %s\n", record.ImageDigest))
		}
		if record.ConfigDigest != "" {
			sb.WriteString(fmt.Sprintf("CONFIG DIGEST: %s\n", record.ConfigDigest))
		}
		if record.Platform != "" {
			sb.WriteString(fmt.Sprintf("PLATFORM: %s\n", record.Platform))
		}
		if res := record.Resources; res.LayerCount > 0 || res.IndexedEntries > 0 || res.CompressedBytes > 0 || res.UncompressedBytes > 0 {
			entries := "n/a"
			if res.IndexedEntries > 0 {
				entries = formatCount(res.IndexedEntries)
			}
			sb.WriteString(fmt.Sprintf("SIZE READ: layers=%d, entries=%s, compressed=%s, content=%s (lower bounds)\n",
				res.LayerCount, entries, sizeLabel(res.CompressedBytes), sizeLabel(res.UncompressedBytes)))
		}
		sb.WriteString(fmt.Sprintf("ERROR: %s\n\n", record.ErrorMessage))
		_ = os.WriteFile(logFile, []byte(sb.String()), 0o644)
		return
	}

	sb.WriteString("STATUS: COMPLETED\n")
	sb.WriteString(fmt.Sprintf("SUITE: %s\n", record.SuiteName))
	sb.WriteString(fmt.Sprintf("PLATFORM: %s\n", record.Platform))
	sb.WriteString(fmt.Sprintf("IMAGE SOURCE: %s\n", record.ImageSource))
	sb.WriteString(fmt.Sprintf("REGISTRY DIGEST: %s\n", record.ImageDigest))
	sb.WriteString(fmt.Sprintf("CONFIG DIGEST: %s\n", record.ConfigDigest))
	sb.WriteString(fmt.Sprintf("TOTAL DURATION: %v\n", record.Duration))
	p := record.Phases
	sb.WriteString(fmt.Sprintf("PHASE BREAKDOWN: Pull=%v, Inspect=%v, Resolve=%v, Stream=%v, Tier1=%v, Tier2=%v, Tier3=%v (window %v), Tier4=%v\n",
		p.PullDuration, p.InspectDuration, p.ResolveDuration, p.StreamDuration,
		p.Tier1Duration, p.Tier2Duration, p.Tier3Duration, p.ProbeWindow, p.Tier4Duration))
	res := record.Resources
	sb.WriteString(fmt.Sprintf("RESOURCES (ConUnit process only): Layers=%d, IndexedEntries=%d, CompressedBytes=%d, UncompressedBytes=%d, LiveHeapMB=%.1f, SelfCPU=%.2fs, ChildCPU=%.2fs\n",
		res.LayerCount, res.IndexedEntries, res.CompressedBytes, res.UncompressedBytes, res.LiveHeapMB, res.SelfCPUSeconds, res.ChildCPUSeconds))
	sb.WriteString(fmt.Sprintf("SUMMARY: %d passed, %d failed, %d unverified (total %d)\n\n", record.Passed, record.Failed, record.Unverified, record.Total))

	sb.WriteString(thin)
	sb.WriteString("DETAILED ASSERTION OUTCOMES\n")
	sb.WriteString(thin)
	for idx, tr := range record.Results {
		sb.WriteString(fmt.Sprintf("[%d] [%s] %s (%s)\n", idx+1, tr.EffectiveOutcome(), tr.TestID, tr.TestName))
		sb.WriteString(fmt.Sprintf("    Tier:        %s\n", tr.Tier))
		sb.WriteString(fmt.Sprintf("    Duration:    %v\n", tr.Duration))
		if tr.Reason != "" {
			sb.WriteString(fmt.Sprintf("    Reason:      %s\n", tr.Reason))
		}
		if tr.Message != "" {
			sb.WriteString(fmt.Sprintf("    Message:     %s\n", tr.Message))
		}
		if tr.Details != "" {
			sb.WriteString(fmt.Sprintf("    Details:     %s\n", tr.Details))
		}
		if tr.Explanation != "" {
			sb.WriteString(fmt.Sprintf("    Explanation: %s\n", tr.Explanation))
		}
		if tr.Hint != "" {
			sb.WriteString(fmt.Sprintf("    Hint:        %s (non-authoritative)\n", tr.Hint))
		}
		if tr.Remediation != "" {
			sb.WriteString(fmt.Sprintf("    Remediation: %s\n", tr.Remediation))
		}
		sb.WriteString("\n")
	}

	_ = os.WriteFile(logFile, []byte(sb.String()), 0o644)
}
