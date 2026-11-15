// Command benchmark_rq3 measures the evaluation latency of ConUnit per image.
//
// Protocol (docs/ANALYSIS_PLAN.md section 10): -warmup iterations are
// discarded, then -iterations timed trials run per image against the warm
// local store. The result is median, IQR and the mean with a Student t
// interval, per phase: resolve, stream and index, Tier 1, Tier 2, Tier 3
// (bounded below by the probe window) and Tier 4. ConUnit CPU time is kept
// apart from child-process CPU time. The environment comes only from
// pkg/runenv. Optional cold registry trials (-cold-trials) follow an explicit
// image purge and are labeled network dependent everywhere.
//
// A failing trial or image is recorded with status and error and the run
// continues. Every trial is appended to a JSON Lines journal as it finishes.
// The outputs are written after every image and again at the end, also for
// partial or interrupted runs.
//
// With -dockle <binary> every warm-up and timed trial that succeeded is followed
// by an export of the same image to a docker-archive and a Dockle run on it, both
// timed on the same host (dockle_export_ms and dockle_run_ms per trial). The
// macros ConUnitRqThreeDockleMedian, ConUnitRqThreeDockleExportMedian and
// ConUnitRqThreeDockleRunMedian give the median seconds per image.
//
// Outputs in -out-dir: rq3_telemetry.json, RQ3_PERFORMANCE.md,
// table_rq3_trials.tex, macros_rq3.tex and rq3_journal.jsonl. macros_rq3.tex also
// holds ConUnitTierThreeFloor, the least Tier 3 time per image, (1 + N) x W in
// seconds, with N the number of Tier 3 treatments of the pack. It assumes that
// the baseline and the treatments run one after another.
//
// Exit codes: 0 every image completed, 2 usage error, 3 incomplete.
//
// Build with -ldflags "-X main.conunitVersion=<version>" to record the
// ConUnit version in the run metadata.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/spec"
)

// conunitVersion is set at build time. It names the tool version in the run
// metadata.
var conunitVersion = "dev"

const (
	defaultIterations = 10
	defaultWarmup     = 1
	// minRecommendedIterations is the number of timed trials the analysis plan
	// asks for. Fewer is allowed for development runs and is flagged.
	minRecommendedIterations = 10
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr *os.File) int {
	log := NewLogger(stderr)
	fs := flag.NewFlagSet("benchmark_rq3", flag.ContinueOnError)
	fs.SetOutput(stderr)
	iterations := fs.Int("iterations", defaultIterations, "Timed trials per image")
	warmup := fs.Int("warmup", defaultWarmup, "Discarded warm-up iterations before the timed trials")
	coldTrials := fs.Int("cold-trials", 0, "Optional cold registry trials per image, each after an explicit image purge. Network dependent")
	fileFlag := fs.String("file", "", "Text file with image references, one per line")
	imagesFlag := fs.String("images", "", "Comma-separated image references")
	imageFlag := fs.String("image", "", "Single image reference")
	packName := fs.String("pack", "cis", "Rule pack to evaluate")
	outDir := fs.String("out-dir", "results", "Output directory")
	platform := fs.String("platform", "", "Target platform such as linux/amd64, empty for the host platform")
	probeWindow := fs.Duration("probe-window", 3*time.Second, "Tier 3 observation window W")
	enginePref := fs.String("engine", "auto", "Container engine: auto, podman or docker")
	imageSource := fs.String("image-source", "auto", "Image source: auto, local or registry")
	archetypesPath := fs.String("archetypes", "fixtures/archetypes.json", "Archetype table keyed by repository name")
	journalPath := fs.String("journal", "", "Trial journal path (default <out-dir>/rq3_journal.jsonl)")
	trialTimeout := fs.Duration("trial-timeout", 5*time.Minute, "Deadline per trial")
	maxFailures := fs.Int("max-consecutive-failures", 3, "Drop an image after this many failed trials in a row, 0 for never")
	dockleBin := fs.String("dockle", "", "Dockle binary: also time the archive export and the Dockle analysis of every image on the same host and trials")
	if err := fs.Parse(args); err != nil {
		return spec.ExitUsage
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	// Validate the configuration.
	usage := func(format string, a ...any) int {
		log.Error(format, a...)
		return spec.ExitUsage
	}
	if *iterations < 1 {
		return usage("-iterations must be at least 1, got %d", *iterations)
	}
	if *warmup < 0 || *coldTrials < 0 || *maxFailures < 0 {
		return usage("-warmup, -cold-trials and -max-consecutive-failures must not be negative")
	}
	switch *imageSource {
	case "auto", "local", "registry":
	default:
		return usage("-image-source must be auto, local or registry, got %q", *imageSource)
	}
	if *coldTrials > 0 && *imageSource == "local" {
		return usage("-cold-trials purges the image and then needs the registry, which -image-source local forbids")
	}
	if *probeWindow <= 0 {
		return usage("-probe-window must be positive")
	}
	if err := ValidateDockleOptions(*dockleBin, *imageSource); err != nil {
		return usage("%v", err)
	}
	images, err := collectImages(*fileFlag, *imagesFlag, *imageFlag)
	if err != nil {
		return usage("%v", err)
	}
	if len(images) == 0 {
		return usage("no images given: use -file, -images or -image")
	}

	eng, err := engine.DetectEngine(*enginePref)
	if err != nil {
		return usage("container engine: %v", err)
	}
	pack, err := resolvePack(*packName)
	if err != nil {
		return usage("rule pack: %v", err)
	}

	var comparator Comparator
	dockleVersion, dockleBinary := "", ""
	if *dockleBin != "" {
		path, version, err := PrepareDockle(*dockleBin)
		if err != nil {
			return usage("%v", err)
		}
		comparator = &DockleRunner{Engine: eng, Binary: path}
		dockleBinary, dockleVersion = path, version
	}

	opts := EvalOptions{Platform: *platform, ImageSource: *imageSource, ProbeWindow: *probeWindow}
	harness, applied := newEvaluator(eng, pack, opts)
	if unsupported := opts.Unsupported(applied, explicit["probe-window"]); len(unsupported) > 0 {
		return usage("this build cannot apply -%s yet and refuses to ignore it silently (see tools/benchmark_rq3/adapter.go)",
			strings.Join(unsupported, ", -"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Environment facts come only from pkg/runenv.
	meta := runenv.Detect(ctx, detectOptions(eng.BinaryPath, *fileFlag, *packName, pack.ID(), applied, args))

	protocol := Protocol{
		Pack:                   *packName,
		PackID:                 pack.ID(),
		TimedTrials:            *iterations,
		WarmupTrials:           *warmup,
		ColdTrials:             *coldTrials,
		TrialTimeoutNs:         trialTimeout.Nanoseconds(),
		MaxConsecutiveFailures: *maxFailures,
		RequestedPlatform:      *platform,
		RequestedImageSource:   *imageSource,
		RequestedProbeWindowNs: probeWindow.Nanoseconds(),
		DatasetPath:            *fileFlag,
		ArchetypesFile:         *archetypesPath,
		QuantileMethod:         methodQuantiles,
		CIMethod:               methodCI,
		Tier3Note:              methodTier3,
		ColdNote:               methodCold,
		MemoryNote:             methodMemory,
		CPUNote:                methodCPU,
		Tier3Treatments:        Tier3Treatments(pack),
		Tier3FloorNote:         tier3FloorNote,
	}
	if comparator != nil {
		protocol.DockleBinary, protocol.DockleVersion, protocol.DockleNote = dockleBinary, dockleVersion, methodDockle
	}
	if *iterations < minRecommendedIterations {
		protocol.Warnings = append(protocol.Warnings,
			fmt.Sprintf("%d timed trials per image, fewer than the %d required by the analysis plan", *iterations, minRecommendedIterations))
	}
	if *iterations < 2 {
		protocol.Warnings = append(protocol.Warnings, "a confidence interval needs at least 2 timed trials and is not defined")
	}

	archetypes, archErr := LoadArchetypes(*archetypesPath)
	switch {
	case archErr == nil:
		protocol.ArchetypesLoaded = true
	case os.IsNotExist(archErr):
		protocol.Warnings = append(protocol.Warnings, fmt.Sprintf("%s not found, every image is labeled %s", *archetypesPath, Unclassified))
		log.Warn("%s not found, every image is labeled %s", *archetypesPath, Unclassified)
	default:
		return usage("%v", archErr)
	}

	// Announce the environment once.
	log.Section("RQ3 performance benchmark")
	log.Info("host    %s", runenv.DescribeHost(meta))
	if meta.EngineName == "" || meta.EngineVersion == "" {
		w := "engine facts are empty in the run metadata (probe failed or timed out), the result does not identify its engine"
		log.Warn("%s", w)
		protocol.Warnings = append(protocol.Warnings, w)
	}
	for _, w := range unappliedWarnings(opts, applied) {
		log.Warn("%s", w)
		protocol.Warnings = append(protocol.Warnings, w)
	}
	log.Info("images  %d, warm-up %d, timed %d, cold %d, pack %s", len(images), *warmup, *iterations, *coldTrials, pack.ID())
	log.Info("tier 3  %d treatments (%s), floor %s s per image at W = %s", len(protocol.Tier3Treatments), strings.Join(protocol.Tier3Treatments, ", "),
		Tier3FloorText(protocol.Tier3Treatments, applied.ProbeWindow.Milliseconds()), applied.ProbeWindow)
	if comparator != nil {
		log.Info("dockle  %s (%s), timed after every warm-up and timed trial", dockleBinary, dockleVersion)
	}
	if *coldTrials > 0 {
		log.Warn("cold trials purge each image first and depend on the network and the registry")
	}

	jpath := *journalPath
	if jpath == "" {
		jpath = filepath.Join(*outDir, "rq3_journal.jsonl")
	}
	journal, err := OpenJournal(jpath)
	if err != nil {
		return usage("opening the journal: %v", err)
	}
	defer journal.Close()
	log.Info("journal %s", jpath)

	tel, err := RunAll(ctx, harness, journal, Setup{
		Images:     images,
		Bench:      BenchConfig{Iterations: *iterations, Warmup: *warmup, ColdTrials: *coldTrials, TrialTimeout: *trialTimeout, MaxConsecutiveFailures: *maxFailures, Dockle: comparator},
		Protocol:   protocol,
		Run:        meta,
		Archetypes: archetypes,
		OutDir:     *outDir,
		Log:        log,
	})
	code := spec.ExitOK
	if err != nil {
		log.Error("%v", err)
		code = spec.ExitIncomplete
	}
	log.Section("Summary")
	s := tel.Summary
	log.Info("images: %d requested, %d completed, %d partial, %d failed", s.ImagesRequested, s.ImagesCompleted, s.ImagesPartial, s.ImagesFailed)
	log.Info("batch peak RSS (ConUnit process only): %.1f MB", s.BatchPeakRSSMB)
	for _, name := range []string{telemetryFile, markdownFile, tableFile, macrosFile} {
		log.Ok("wrote %s", filepath.Join(*outDir, name))
	}
	if !tel.Complete || s.ImagesCompleted != s.ImagesRequested {
		log.Error("incomplete: %d of %d images completed all timed trials", s.ImagesCompleted, s.ImagesRequested)
		code = spec.ExitIncomplete
	}
	return code
}

// registryRemapEnv names the variable through which the evaluation host states its registry
// remap. The AWS run installs one (docs/CONTRACT.md section 9), and the run metadata of every
// result file must say so, as it does for `con-unit eval`.
const registryRemapEnv = "CONUNIT_REGISTRY_REMAP"

// detectOptions is the run configuration that the host cannot reveal to runenv.Detect. It is a
// function of its own so that a test can see what the run metadata will state.
func detectOptions(engineBinary, datasetPath, packName, packID string, applied Applied, args []string) runenv.Options {
	return runenv.Options{
		Version:       conunitVersion,
		EngineBinary:  engineBinary,
		DatasetPath:   datasetPath,
		Pack:          packName,
		PackID:        packID,
		Platform:      applied.Platform,
		ImageSource:   applied.ImageSource,
		ProbeWindow:   applied.ProbeWindow,
		Flags:         args,
		RegistryRemap: os.Getenv(registryRemapEnv),
	}
}

// unappliedWarnings states the options that are requested but not applied,
// so the telemetry never suggests they took effect. Unsupported explicit
// options are refused earlier, this covers the defaults.
func unappliedWarnings(opts EvalOptions, applied Applied) []string {
	var out []string
	if applied.ProbeWindow == 0 {
		out = append(out, fmt.Sprintf("probe window %s is not configurable in this build, Tier 3 uses the engine's fixed windows and the run metadata records no window", opts.ProbeWindow))
	}
	if applied.ImageSource == "" {
		out = append(out, "image source policy is not configurable in this build, the runner uses its default")
	}
	return out
}

// collectImages reads image references from -file, -images and -image, in that
// order, keeping the order and dropping exact duplicates.
func collectImages(file, list, single string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "#") || seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	if strings.TrimSpace(file) != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading image file %s: %w", file, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			add(line)
		}
	}
	for _, ref := range strings.Split(list, ",") {
		add(ref)
	}
	add(single)
	return out, nil
}
