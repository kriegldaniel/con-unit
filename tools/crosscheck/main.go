// Command crosscheck compares ConUnit's static checks with Dockle on the
// images of one study.
//
//	crosscheck -study <RESULTS_DIR>/lint/empirical_study.json -dockle dockle -engine podman \
//	    -platform linux/amd64 -out-dir <RESULTS_DIR>/crosscheck \
//	    [-images a,b] [-limit N] [-timeout 10m] [-analyze-only]
//
// For each COMPLETED image the tool exports the docker-archive to a temporary
// file with `save --format docker-archive`, checks that the config digest of
// the archive equals the config_digest of the study record (a mismatch is a
// recorded error, never a result), runs
// `dockle --input <archive> --format json --exit-code 0`, deletes the archive
// and records the seconds of the export and of Dockle separately.
//
// ConUnit's checks are mapped to Dockle codes as fixed in
// docs/INTERFACE_V2.md section 5. For each mapped check the tool builds a 2x2
// table over the images where ConUnit is verified and Dockle evaluated the
// checkpoint: both, only ConUnit, only Dockle, neither. ConUnit UNVERIFIED,
// Dockle errors and checkpoints that Dockle skipped are counted separately.
// The agreement is the raw percent agreement; no kappa is computed. SPEC-13
// against DKL-DI-0006 cannot be compared, because Dockle never reports that
// checkpoint for an archive.
//
// Outputs in -out-dir: crosscheck.json, discordances.csv, table_crosscheck.tex
// (label tab:crosscheck), table_discordances.tex (label tab:discordances),
// macros_crosscheck.tex and table_coverage.tex (label tab:coverage), plus raw/
// with one record per image so that -analyze-only can rebuild everything
// without running Dockle.
//
//	crosscheck coverage [-md FILE] [-tex FILE]
//
// writes the coverage matrix of docs/COVERAGE_MATRIX.md and its LaTeX table
// from the catalogs, without a study.
//
// Exit status: 0 on success, 1 on a failure, 2 on a usage error, 3 when
// outputs were written and at least one image has no Dockle result.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

const rawDir = "raw"

// config holds the command line.
type config struct {
	Study       string
	Dockle      string
	Engine      string
	Platform    string
	OutDir      string
	Images      string
	Limit       int
	Timeout     time.Duration
	AnalyzeOnly bool
	KeepPulled  bool
	Adjudicated string
}

// deps are the external parts of a run. Tests replace newDeps.
type deps struct {
	Exporter Exporter
	Dockle   DockleRunner
	// Close releases what the parts hold, for example a working directory.
	Close func()
}

// newDeps builds the real exporter and the Dockle runner.
var newDeps = func(cfg config) (deps, error) {
	eng, err := engine.DetectEngine(cfg.Engine)
	if err != nil {
		return deps{}, err
	}
	runner := &ExecRunner{Binary: cfg.Dockle}
	return deps{
		Exporter: &EngineExporter{Engine: eng, KeepPulled: cfg.KeepPulled},
		Dockle:   runner,
		Close:    func() { _ = runner.Close() },
	}, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "coverage" {
		return runCoverage(args[1:], stdout, stderr)
	}
	var cfg config
	fset := flag.NewFlagSet("crosscheck", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.StringVar(&cfg.Study, "study", "", "empirical_study.json of the lint pack run")
	fset.StringVar(&cfg.Dockle, "dockle", "dockle", "Dockle binary")
	fset.StringVar(&cfg.Engine, "engine", "auto", "container engine: podman, docker or auto")
	fset.StringVar(&cfg.Platform, "platform", "", "platform for a pull, default: the platform of the study run")
	fset.StringVar(&cfg.OutDir, "out-dir", "", "output directory (default: crosscheck next to the study)")
	fset.StringVar(&cfg.Images, "images", "", "comma-separated image references or repository names to restrict the run to")
	fset.IntVar(&cfg.Limit, "limit", 0, "process at most this many images (0 means all)")
	fset.DurationVar(&cfg.Timeout, "timeout", 10*time.Minute, "time limit for the export and Dockle of one image")
	fset.BoolVar(&cfg.AnalyzeOnly, "analyze-only", false, "do not export or run Dockle; rebuild the outputs from raw/")
	fset.BoolVar(&cfg.KeepPulled, "keep-pulled", false, "keep images that the export had to pull")
	fset.StringVar(&cfg.Adjudicated, "adjudication", "", "filled adjudication CSV, to fill the resolution of the discordances")
	fset.Usage = func() {
		fmt.Fprintln(stderr, "usage: crosscheck -study FILE [-dockle PATH] [-engine NAME] [-platform P] [-out-dir DIR] [-images a,b] [-limit N] [-timeout D] [-analyze-only] [-keep-pulled] [-adjudication FILE]")
		fmt.Fprintln(stderr, "       crosscheck coverage [-md FILE] [-tex FILE]")
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return spec.ExitOK
		}
		return spec.ExitUsage
	}
	if cfg.Study == "" || fset.NArg() > 0 || cfg.Limit < 0 || cfg.Timeout < 0 {
		fset.Usage()
		return spec.ExitUsage
	}
	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Join(filepath.Dir(cfg.Study), "crosscheck")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return execute(ctx, cfg, stdout, stderr)
}

// matches reports whether a record is selected by an -images entry.
func matches(entry, key string) bool {
	return entry == key || entry == studyfile.RepoName(key)
}

// selectImages applies -images and -limit to the COMPLETED records, in sorted
// order. It returns the keys that were selected and the entries that matched
// nothing.
func selectImages(l *studyfile.Loaded, images string, limit int) (keys []string, unmatched []string) {
	var all []string
	for _, rec := range l.Records {
		if l.Completed(rec) {
			all = append(all, studyfile.RecordKey(rec))
		}
	}
	sort.Strings(all)
	if strings.TrimSpace(images) == "" {
		keys = all
	} else {
		for _, entry := range strings.Split(images, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			found := false
			for _, k := range all {
				if matches(entry, k) {
					found = true
					if !contains(keys, k) {
						keys = append(keys, k)
					}
				}
			}
			if !found {
				unmatched = append(unmatched, entry)
			}
		}
		sort.Strings(keys)
	}
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	return keys, unmatched
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// rawName is the file name of the raw record of an image: a readable part and
// a short hash of the reference, which keeps different references apart.
func rawName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return unsafeName.ReplaceAllString(displayImage(key), "_") + "-" + hex.EncodeToString(sum[:4]) + ".json"
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readRecord(path string) (*ImageRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec ImageRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return &rec, nil
}

func execute(ctx context.Context, cfg config, stdout, stderr io.Writer) int {
	log, problem := clilog.New(stdout), clilog.New(stderr)

	loaded, err := studyfile.Load(cfg.Study)
	if err != nil {
		problem.Error("cannot load the study: %v", err)
		return spec.ExitFindings
	}
	keys, unmatched := selectImages(loaded, cfg.Images, cfg.Limit)
	if len(unmatched) > 0 {
		problem.Error("-images matches no completed image of the study for: %s", strings.Join(unmatched, ", "))
		return spec.ExitUsage
	}
	platform := cfg.Platform
	if platform == "" {
		platform = loaded.Study.Run.Platform
	}
	var sheet *Sheet
	if cfg.Adjudicated != "" {
		data, err := os.ReadFile(cfg.Adjudicated)
		if err != nil {
			problem.Error("cannot read the adjudication sheet: %v", err)
			return spec.ExitFindings
		}
		if sheet, err = ReadSheet(strings.NewReader(string(data))); err != nil {
			problem.Error("%s: %v", filepath.Base(cfg.Adjudicated), err)
			return spec.ExitFindings
		}
	}
	if err := os.MkdirAll(filepath.Join(cfg.OutDir, rawDir), 0o755); err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}

	log.Section("Cross-check against Dockle")
	log.Info("study     %s (sha256 %s)", filepath.Base(cfg.Study), shortSum(loaded.SHA256))
	log.Info("images    %d selected of %d completed", len(keys), completedCount(loaded))

	var run RunInfo
	records := map[string]*ImageRecord{}
	if cfg.AnalyzeOnly {
		data, err := os.ReadFile(filepath.Join(cfg.OutDir, rawDir, "run.json"))
		if err != nil {
			problem.Error("-analyze-only needs %s: %v", filepath.Join(rawDir, "run.json"), err)
			return spec.ExitFindings
		}
		if err := json.Unmarshal(data, &run); err != nil {
			problem.Error("%s: %v", filepath.Join(rawDir, "run.json"), err)
			return spec.ExitFindings
		}
		for _, key := range keys {
			rec, err := readRecord(filepath.Join(cfg.OutDir, rawDir, rawName(key)))
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					problem.Warn("raw record of %s: %v", displayImage(key), err)
				}
				continue
			}
			records[key] = rec
		}
		log.Info("analyze   %d raw records read, no export and no Dockle run", len(records))
	} else {
		d, err := newDeps(cfg)
		if err != nil {
			problem.Error("%v", err)
			return spec.ExitFindings
		}
		if d.Close != nil {
			defer d.Close()
		}
		version, err := d.Dockle.Version(ctx)
		if err != nil {
			problem.Error("cannot determine the Dockle version: %v", err)
			return spec.ExitFindings
		}
		run = RunInfo{DockleVersion: version, Engine: d.Exporter.Describe(ctx), Platform: platform}
		log.Info("dockle    %s", version)
		log.Info("engine    %s", run.Engine)
		if version != VerifiedDockleVersion {
			problem.Warn("Dockle %s differs from %s, the version whose source fixed the JSON schema and the level rules", version, VerifiedDockleVersion)
		}
		if err := writeJSON(filepath.Join(cfg.OutDir, rawDir, "run.json"), run); err != nil {
			problem.Error("%v", err)
			return spec.ExitFindings
		}
		byKey := map[string]*spec.SuiteResult{}
		for _, rec := range loaded.Records {
			byKey[studyfile.RecordKey(rec)] = rec
		}
		p := &Pipeline{Exporter: d.Exporter, Dockle: d.Dockle, Platform: platform, Timeout: cfg.Timeout}
		for i, key := range keys {
			if ctx.Err() != nil {
				problem.Error("interrupted after %d of %d images; the outputs were not written", i, len(keys))
				return spec.ExitFindings
			}
			rec := p.Process(ctx, byKey[key])
			records[key] = rec
			if err := writeJSON(filepath.Join(cfg.OutDir, rawDir, rawName(key)), rec); err != nil {
				problem.Error("%v", err)
				return spec.ExitFindings
			}
			line := fmt.Sprintf("%3d/%-3d %-34s export %6.2fs  dockle %6.2fs  %s", i+1, len(keys), displayImage(key), rec.ExportSeconds, rec.DockleSeconds, rec.Status)
			if rec.Status == ImageOK {
				log.Info("%s", line)
			} else {
				problem.Warn("%s  %s", line, rec.Error)
			}
		}
	}

	res := Analyze(loaded, records, Options{Run: run, Sheet: sheet, Only: keys})
	study := studyRef(cfg.Study, loaded)
	report := BuildReport(res, study, run)
	if err := writeOutputs(cfg.OutDir, res, report); err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	printSummary(log, res)
	for _, w := range report.Warnings {
		problem.Warn("%s", w)
	}
	log.Success("wrote %s, %s, %s, %s, %s and %s in %s", fileJSON, fileDiscordances, fileTable, fileDiscTable, fileMacros, fileCoverage, cfg.OutDir)
	if res.Totals.ImagesCompleted == 0 {
		problem.Error("the study has no COMPLETED image; nothing was compared")
		return spec.ExitIncomplete
	}
	if res.Totals.ImagesWithError > 0 {
		problem.Error("%d of %d images have no Dockle result (%s); they are counted as Dockle errors",
			res.Totals.ImagesWithError, res.Totals.ImagesCompleted, errorSummary(res.Totals.ErrorsByStatus))
		return spec.ExitIncomplete
	}
	return spec.ExitOK
}

func completedCount(l *studyfile.Loaded) int {
	n := 0
	for _, rec := range l.Records {
		if l.Completed(rec) {
			n++
		}
	}
	return n
}

func shortSum(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func studyRef(path string, l *studyfile.Loaded) StudyRef {
	r := l.Study.Run
	return StudyRef{
		File: filepath.Base(path), SHA256: l.SHA256, ConUnit: r.ConUnitVersion, Commit: r.Commit,
		Pack: r.Pack, PackID: r.PackID, Platform: r.Platform, ImageSource: r.ImageSource,
		EngineName: r.EngineName, EngineVersion: r.EngineVersion, DatasetSHA256: r.DatasetSHA256,
	}
}

func errorSummary(m map[string]int) string {
	var parts []string
	for _, s := range []ImageStatus{ImageExportError, ImageDigestMismatch, ImageNoStudyDigest, ImageArchiveError, ImageDockleError, ImageParseError, ImageNoRawRecord} {
		if n := m[string(s)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", s, n))
		}
	}
	return strings.Join(parts, ", ")
}

// outputs lists the files of a run in the order they are written.
func outputs(res *Result, report *Report) ([]struct{ name, content string }, error) {
	js, err := RenderJSON(report)
	if err != nil {
		return nil, err
	}
	csv, err := RenderDiscordancesCSV(res.Discordances)
	if err != nil {
		return nil, err
	}
	macros, err := RenderMacros(res)
	if err != nil {
		return nil, err
	}
	return []struct{ name, content string }{
		{fileJSON, string(js)},
		{fileDiscordances, csv},
		{fileTable, RenderTable(res)},
		{fileDiscTable, RenderDiscordanceTable(res.Discordances)},
		{fileMacros, macros},
		{fileCoverage, RenderCoverageTable()},
	}, nil
}

func writeOutputs(dir string, res *Result, report *Report) error {
	files, err := outputs(res, report)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(f.content), 0o644); err != nil {
			return fmt.Errorf("cannot write %s: %w", f.name, err)
		}
	}
	return nil
}

func printSummary(log *clilog.Logger, res *Result) {
	log.Section("Result per check")
	log.Info("%-8s %-24s %5s %5s %5s %5s | %5s %5s %5s | %s", "check", "dockle", "both", "c-only", "d-only", "neither", "unver", "error", "n-eval", "agree")
	for _, c := range res.Checks {
		codes := strings.Join(c.DockleCodes, ",")
		if !c.Comparable {
			log.Info("%-8s %-24s not comparable: %s", c.Check, codes, "Dockle never reports it for an archive")
			continue
		}
		agree := tex.NotAvailable
		if c.PercentAgreement != nil {
			agree = fmt.Sprintf("%.1f%%", 100**c.PercentAgreement)
		}
		log.Info("%-8s %-24s %5d %5d %5d %5d | %5d %5d %5d | %s",
			c.Check, codes, c.Both, c.OnlyConUnit, c.OnlyDockle, c.Neither, c.ConUnitUnverif, c.DockleError, c.DockleNotEvaluated, agree)
	}
	t := res.Totals
	log.Info("images: %d completed, %d with a Dockle result, %d without", t.ImagesCompleted, t.ImagesAnalyzed, t.ImagesWithError)
	log.Info("discordant image and check pairs: %d", t.Discordant)
	if res.Timings.Dockle.N > 0 {
		log.Info("seconds per image: export median %.2f, dockle median %.2f", res.Timings.Export.Median, res.Timings.Dockle.Median)
	}
}
