// Command preview renders a terminal overview and a static HTML dashboard from
// an existing empirical_study.json without rerunning the evaluation.
//
// It uses the same analysis as tools/export_latex.go: only COMPLETED images
// enter prevalence, prevalence is FAIL over PASS plus FAIL with a Wilson 95
// percent interval, UNVERIFIED is reported separately, and no per-image pass
// rate exists.
package main

import (
	"flag"
	"fmt"
	"html"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/stats"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("preview", flag.ContinueOnError)
	fset.SetOutput(stderr)
	resultsDir := fset.String("dir", "results", "path to the results directory")
	openBrowser := fset.Bool("open", false, "open the HTML preview in the default browser")
	headline := fset.String("headline", "fixtures/headline_checks.json", "headline check classification")
	archetypes := fset.String("archetypes", "fixtures/archetypes.json", "archetype fixture")
	if err := fset.Parse(args); err != nil {
		return spec.ExitUsage
	}
	problem := clilog.New(stderr)
	info := clilog.New(stdout)

	jsonPath := filepath.Join(*resultsDir, "empirical_study.json")
	loaded, err := studyfile.Load(jsonPath)
	if err != nil {
		problem.Error("%v", err)
		problem.Info("run 'just eval-top10' or 'just eval-full' first to generate evaluation results")
		return spec.ExitFindings
	}
	opt := analysis.Options{Source: filepath.Base(jsonPath)}
	if c, err := analysis.LoadClassification(*headline); err == nil {
		opt.Classification = c
	} else {
		problem.Warn("%v; every check is shown as exploratory", err)
	}
	if a, err := analysis.LoadArchetypes(*archetypes); err == nil {
		opt.Archetypes = a
	}
	a := analysis.Analyze(loaded, opt)
	if a.Flow.Completed == 0 {
		problem.Error("no completed image evaluations in %s (%d attempted)", jsonPath, a.Flow.Attempted)
		printFlow(info, a)
		return spec.ExitIncomplete
	}

	printDashboard(stdout, a)
	htmlPath := filepath.Join(*resultsDir, "preview.html")
	if err := os.WriteFile(htmlPath, []byte(renderHTML(a)), 0o644); err != nil {
		problem.Error("cannot write %s: %v", htmlPath, err)
		return spec.ExitFindings
	}
	info.Success("wrote %s", htmlPath)
	if *openBrowser && runtime.GOOS == "darwin" {
		_ = exec.Command("open", htmlPath).Start()
	}
	return spec.ExitOK
}

func printFlow(info *clilog.Logger, a *analysis.Analysis) {
	statuses := make([]string, 0, len(a.Flow.ByStatus))
	for s := range a.Flow.ByStatus {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	for _, s := range statuses {
		info.Info("%-16s %d", s, a.Flow.ByStatus[s])
	}
}

// ---------------------------------------------------------------------------
// Terminal dashboard

func bar(frac float64, width int) string {
	n := int(math.Round(frac * float64(width)))
	if n < 0 {
		n = 0
	}
	if n > width {
		n = width
	}
	return strings.Repeat("#", n) + strings.Repeat(".", width-n)
}

func medianMs(a *analysis.Analysis, get func(*spec.SuiteResult) time.Duration) float64 {
	var xs []float64
	for _, r := range a.Completed {
		xs = append(xs, float64(get(r))/float64(time.Millisecond))
	}
	return stats.Summarize(xs).Median
}

func windowLabel(a *analysis.Analysis) string {
	if a.Run.ProbeWindowMs > 0 {
		return fmt.Sprintf("%.1f s", float64(a.Run.ProbeWindowMs)/1000)
	}
	for _, r := range a.Completed {
		if r.Phases.ProbeWindow > 0 {
			return fmt.Sprintf("%.1f s", r.Phases.ProbeWindow.Seconds())
		}
	}
	return "unknown"
}

func printDashboard(w io.Writer, a *analysis.Analysis) {
	rule := strings.Repeat("=", 80)
	fmt.Fprintf(w, "\n%s\n CONUNIT EVALUATION PREVIEW  analyzed N = %d of %d attempted (not completed: %d)\n%s\n",
		rule, a.Flow.Completed, a.Flow.Attempted, a.Flow.NotCompleted, rule)
	run := a.Run
	fmt.Fprintf(w, " environment : %s | %s %s | virtualization %s | kernel %s\n",
		orUnknown(run.InstanceType), orUnknown(run.EngineName), run.EngineVersion, orUnknown(run.Virtualization), orUnknown(run.LinuxKernel))
	if a.Legacy {
		fmt.Fprintln(w, " note        : legacy array input, run metadata unknown")
	}
	for s, n := range a.Flow.ByStatus {
		fmt.Fprintf(w, " not completed: %-16s %d\n", s, n)
	}

	for _, class := range []analysis.Class{analysis.ClassHeadline, analysis.ClassExploratory} {
		checks := a.ChecksOfClass(class)
		if len(checks) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n--- %s CHECKS: confirmed failures among verified images (Wilson 95%% CI) ---\n", strings.ToUpper(string(class)))
		for _, c := range checks {
			if c.Prevalence == nil {
				fmt.Fprintf(w, "  %-9s  n/a   |%s| %3d/%-3d verified, %d unverified  %s\n",
					c.ID, bar(0, 24), c.Fail, c.Verified, c.Unverified, c.Name)
				continue
			}
			p := c.Prevalence
			fmt.Fprintf(w, "  %-9s %5.1f%% |%s| %3d/%-3d verified [%.1f, %.1f], %d unverified, %d fixture-only  %s\n",
				c.ID, 100*p.Estimate, bar(p.Estimate, 24), c.Fail, c.Verified, 100*p.Lo, 100*p.Hi, c.Unverified, c.FixtureOnly, c.Name)
		}
	}
	if ex := a.ChecksOfClass(analysis.ClassExcluded); len(ex) > 0 {
		fmt.Fprintln(w, "\n--- EXCLUDED CHECKS: no prevalence reported ---")
		for _, c := range ex {
			fmt.Fprintf(w, "  %-9s %d unverified of %d completed  %s\n", c.ID, c.Unverified, a.Flow.Completed, c.Name)
		}
	}

	d := a.Distribution["headline"]
	fmt.Fprintln(w, "\n--- PER-IMAGE CONFIRMED FAILURES AMONG VERIFIED HEADLINE CHECKS ---")
	fmt.Fprintf(w, "  median %.1f (Q1 %.1f, Q3 %.1f), mean %.1f, SD %s (sample, n-1), verified checks per image: median %.1f (min %.0f, max %.0f)\n",
		d.ConfirmedFailures.Median, d.ConfirmedFailures.Q1, d.ConfirmedFailures.Q3, d.ConfirmedFailures.Mean,
		sdText(d.ConfirmedFailures), d.VerifiedChecks.Median, d.VerifiedChecks.Min, d.VerifiedChecks.Max)
	for _, b := range failureHistogram(a) {
		fmt.Fprintf(w, "  %2d confirmed failures: %3d images %s\n", b.failures, b.images, strings.Repeat("#", b.images))
	}

	fmt.Fprintln(w, "\n--- SINGLE-PASS TIMINGS (median over completed images; not repeated measurements) ---")
	fmt.Fprintf(w, "  total %.0f ms | stream %.0f ms | Tier 3 %.0f ms (bounded below by the probe window %s, not a performance result)\n",
		medianMs(a, func(r *spec.SuiteResult) time.Duration { return r.Duration }),
		medianMs(a, func(r *spec.SuiteResult) time.Duration { return r.Phases.StreamDuration }),
		medianMs(a, func(r *spec.SuiteResult) time.Duration { return r.Phases.Tier3Duration }),
		windowLabel(a))
	var peak float64
	for _, r := range a.Records {
		peak = math.Max(peak, r.Resources.PeakRSSMB)
	}
	fmt.Fprintf(w, "  ConUnit process memory ceiling over the batch: %.1f MB (process only, not per image)\n", peak)
	fmt.Fprintln(w, rule)
}

func sdText(s stats.Summary) string {
	if !s.SDOK {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", s.SD)
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

type histBin struct{ failures, images int }

// failureHistogram counts images by confirmed failures among verified
// headline checks.
func failureHistogram(a *analysis.Analysis) []histBin {
	counts := map[int]int{}
	maxF := 0
	for _, im := range a.Images {
		counts[im.Headline.Fail]++
		if im.Headline.Fail > maxF {
			maxF = im.Headline.Fail
		}
	}
	bins := make([]histBin, 0, maxF+1)
	for f := 0; f <= maxF; f++ {
		bins = append(bins, histBin{f, counts[f]})
	}
	return bins
}

// ---------------------------------------------------------------------------
// HTML report

func renderHTML(a *analysis.Analysis) string {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ConUnit Evaluation Preview</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 30px; background: #0f141c; color: #e1e7f0; }
  h1, h2 { color: #ffffff; border-bottom: 1px solid #2d3748; padding-bottom: 8px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 24px 0; }
  .card { background: #1a2332; border: 1px solid #2d3e58; border-radius: 8px; padding: 18px; text-align: center; }
  .card-value { font-size: 28px; font-weight: bold; color: #4da3ff; margin-top: 6px; }
  .card-label { font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: #8fa0ba; }
  .chart-box { background: #1a2332; border: 1px solid #2d3e58; border-radius: 8px; padding: 20px; margin: 24px 0; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #2d3e58; }
  th { background: #131b26; color: #a4b7d1; text-transform: uppercase; font-size: 12px; letter-spacing: 0.05em; }
  tr:hover { background: #222f42; }
  .note { color: #8fa0ba; }
  svg text { font-family: inherit; }
</style>
</head>
<body>
<h1>ConUnit Evaluation Preview</h1>
`)
	fmt.Fprintf(&sb, `<p class="note">Source %s. Prevalence is confirmed failures over verified images (PASS plus FAIL) with Wilson 95%% intervals; UNVERIFIED results are counted separately.</p>`+"\n",
		html.EscapeString(a.Source))

	d := a.Distribution["headline"]
	var peak float64
	for _, r := range a.Records {
		peak = math.Max(peak, r.Resources.PeakRSSMB)
	}
	sb.WriteString(`<div class="grid">` + "\n")
	card := func(label, value string) {
		fmt.Fprintf(&sb, `  <div class="card"><div class="card-label">%s</div><div class="card-value">%s</div></div>`+"\n",
			html.EscapeString(label), html.EscapeString(value))
	}
	card("Analyzed images", fmt.Sprint(a.Flow.Completed))
	card("Not completed", fmt.Sprint(a.Flow.NotCompleted))
	card("Median failures per image (headline)", fmt.Sprintf("%.1f of %.1f verified", d.ConfirmedFailures.Median, d.VerifiedChecks.Median))
	card("Batch memory ceiling (process)", fmt.Sprintf("%.1f MB", peak))
	sb.WriteString("</div>\n")

	// Prevalence chart with Wilson whiskers.
	sb.WriteString("<h2>Prevalence of confirmed failures</h2><div class=\"chart-box\">\n")
	var shown []*analysis.Check
	for _, class := range []analysis.Class{analysis.ClassHeadline, analysis.ClassExploratory} {
		shown = append(shown, a.ChecksOfClass(class)...)
	}
	height := len(shown)*32 + 50
	fmt.Fprintf(&sb, `<svg width="900" height="%d" viewBox="0 0 900 %d" xmlns="http://www.w3.org/2000/svg">`, height, height)
	fmt.Fprintf(&sb, `<line x1="150" y1="20" x2="150" y2="%d" stroke="#4a5568"/>`, height-30)
	fmt.Fprintf(&sb, `<line x1="150" y1="%d" x2="810" y2="%d" stroke="#4a5568"/>`, height-30, height-30)
	for pct := 0; pct <= 100; pct += 20 {
		x := 150 + int(float64(pct)*6.6)
		fmt.Fprintf(&sb, `<line x1="%d" y1="20" x2="%d" y2="%d" stroke="#2d3748" stroke-dasharray="3,3"/>`, x, x, height-30)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" fill="#8fa0ba" font-size="11" text-anchor="middle">%d%%</text>`, x, height-14, pct)
	}
	for i, c := range shown {
		y := 35 + i*32
		label := c.ID
		if c.Class == analysis.ClassExploratory {
			label += " (exploratory)"
		}
		fmt.Fprintf(&sb, `<text x="140" y="%d" fill="#e1e7f0" font-size="12" font-weight="600" text-anchor="end">%s</text>`, y+12, html.EscapeString(label))
		if c.Prevalence == nil {
			fmt.Fprintf(&sb, `<text x="156" y="%d" fill="#d69e2e" font-size="11">n/a: %d verified, %d unverified</text>`, y+13, c.Verified, c.Unverified)
			continue
		}
		p := c.Prevalence
		color := "#3182ce"
		if c.Class == analysis.ClassExploratory {
			color = "#718096"
		}
		w := int(p.Estimate * 660)
		if w > 0 {
			fmt.Fprintf(&sb, `<rect x="150" y="%d" width="%d" height="16" fill="%s" rx="2"/>`, y, w, color)
		}
		lo, hi := 150+int(p.Lo*660), 150+int(p.Hi*660)
		fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#f6e05e" stroke-width="2"/>`, lo, y+8, hi, y+8)
		fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#f6e05e" stroke-width="2"/>`, lo, y+3, lo, y+13)
		fmt.Fprintf(&sb, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#f6e05e" stroke-width="2"/>`, hi, y+3, hi, y+13)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" fill="#ffffff" font-size="11">%.1f%% (%d/%d, %d unverified)</text>`,
			hi+8, y+13, 100*p.Estimate, c.Fail, c.Verified, c.Unverified)
	}
	sb.WriteString("</svg></div>\n")

	// Per-image failure histogram.
	sb.WriteString("<h2>Confirmed failures per image among verified headline checks</h2><div class=\"chart-box\">\n")
	bins := failureHistogram(a)
	maxCount := 1
	for _, b := range bins {
		if b.images > maxCount {
			maxCount = b.images
		}
	}
	fmt.Fprintf(&sb, `<svg width="%d" height="240" xmlns="http://www.w3.org/2000/svg">`, 120+len(bins)*70)
	sb.WriteString(`<line x1="60" y1="20" x2="60" y2="190" stroke="#4a5568"/>`)
	fmt.Fprintf(&sb, `<line x1="60" y1="190" x2="%d" y2="190" stroke="#4a5568"/>`, 80+len(bins)*70)
	for i, b := range bins {
		x := 80 + i*70
		h := int(float64(b.images) / float64(maxCount) * 140)
		if h > 0 {
			fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="46" height="%d" fill="#319795" rx="3"/>`, x, 190-h, h)
			fmt.Fprintf(&sb, `<text x="%d" y="%d" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">%d</text>`, x+23, 190-h-6, b.images)
		}
		fmt.Fprintf(&sb, `<text x="%d" y="208" fill="#8fa0ba" font-size="11" text-anchor="middle">%d</text>`, x+23, b.failures)
	}
	sb.WriteString(`<text x="60" y="230" fill="#8fa0ba" font-size="11">confirmed failures among verified headline checks (images on the vertical axis)</text>`)
	sb.WriteString("</svg></div>\n")

	// Phase breakdown for representative images.
	sb.WriteString("<h2>Single-pass phase timings</h2><div class=\"chart-box\">\n")
	fmt.Fprintf(&sb, `<p class="note">Tier 3 is bounded below by the probe window (%s) by design and is not a performance result. These are single runs, not repeated measurements.</p>`+"\n",
		html.EscapeString(windowLabel(a)))
	recs := append([]*spec.SuiteResult(nil), a.Completed...)
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Duration > recs[j].Duration })
	if len(recs) > 10 {
		recs = recs[:10]
	}
	maxDur := 1.0
	for _, r := range recs {
		maxDur = math.Max(maxDur, float64(r.Duration)/float64(time.Millisecond))
	}
	phaseHeight := len(recs)*34 + 40
	fmt.Fprintf(&sb, `<svg width="900" height="%d" viewBox="0 0 900 %d" xmlns="http://www.w3.org/2000/svg">`, phaseHeight, phaseHeight)
	for i, r := range recs {
		y := 20 + i*34
		stream := float64(r.Phases.StreamDuration) / float64(time.Millisecond)
		t3 := float64(r.Phases.Tier3Duration) / float64(time.Millisecond)
		total := float64(r.Duration) / float64(time.Millisecond)
		sw, tw := int(stream/maxDur*560), int(t3/maxDur*560)
		fmt.Fprintf(&sb, `<text x="200" y="%d" fill="#e1e7f0" font-size="12" text-anchor="end">%s</text>`, y+13, html.EscapeString(truncate(studyfile.RepoName(studyfile.RecordKey(r)), 26)))
		fmt.Fprintf(&sb, `<rect x="210" y="%d" width="%d" height="18" fill="#319795" rx="2"/>`, y, sw)
		fmt.Fprintf(&sb, `<rect x="%d" y="%d" width="%d" height="18" fill="#805ad5" rx="2"/>`, 210+sw, y, tw)
		fmt.Fprintf(&sb, `<text x="%d" y="%d" fill="#ffffff" font-size="11">total %.1f s, stream %.1f s, Tier 3 %.1f s</text>`,
			218+sw+tw, y+13, total/1000, stream/1000, t3/1000)
	}
	sb.WriteString("</svg></div>\n")

	// Image table without any pass rate.
	sb.WriteString(`<h2>Evaluated images</h2><table>
<thead><tr><th>Image</th><th>Status</th><th>Archetype</th><th>Base family</th><th>Verified headline</th><th>Confirmed failures</th><th>Layers</th><th>Size</th><th>Duration</th></tr></thead>
<tbody>
`)
	stat := map[string]analysis.ImageStat{}
	for _, im := range a.Images {
		stat[im.Ref] = im
	}
	for _, r := range a.Records {
		key := studyfile.RecordKey(r)
		im, completed := stat[key]
		status := r.Status
		if status == "" {
			status = "COMPLETED"
		}
		if !completed {
			fmt.Fprintf(&sb, `<tr><td><code>%s</code></td><td>%s</td><td colspan="7" class="note">%s</td></tr>`+"\n",
				html.EscapeString(key), html.EscapeString(status), html.EscapeString(string(r.Reason)))
			continue
		}
		fmt.Fprintf(&sb, `<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%.1f MB</td><td>%v</td></tr>`+"\n",
			html.EscapeString(key), html.EscapeString(status), html.EscapeString(im.Archetype), html.EscapeString(im.BaseFamily),
			im.Headline.Verified, im.Headline.Fail, r.Resources.LayerCount,
			float64(r.Resources.UncompressedBytes)/(1024*1024), r.Duration.Round(time.Millisecond))
	}
	sb.WriteString("</tbody></table></body></html>\n")
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-2] + ".."
}
