// Command rq1 runs the RQ1 detection benchmark.
//
// It builds a defect-seeded corpus of Dockerfiles with clean controls
// (fixtures/rq1), runs ConUnit, Hadolint, Trivy, Google Container Structure
// Test and Dockle at the versions found on PATH, stores the raw output of
// every tool, and classifies each tool on each case as TP, FP, FN, TN or
// OUT_OF_SCOPE against the ground truth in fixtures/rq1/oracle.json.
//
// A tool whose binary is absent is reported as NOT_RUN in every row. A tool
// that is out of scope for a property is never counted as having missed it.
// The scope of every tool and property comes from the tool's published
// catalog at a pinned version, recorded per entry in the oracle. The version
// each binary reports is compared with that pin in rq1_results.json.
//
// Trivy and Dockle read the same docker-archive export of each image. Dockle
// runs as `dockle --input <archive> --format json --exit-code 0` in an empty
// working directory with every DOCKLE_ variable removed, and the config
// digest of the archive is recorded in raw/<case>/run.json.
//
// Outputs in -out-dir:
//
//	rq1_results.json          classification per case and tool, tool versions, summary
//	table_rq1_detection.tex   LaTeX table generated from the results
//	raw/tools.json            tool versions and availability
//	raw/<case>/<tool>.txt     raw tool output
//	raw/<case>/<tool>.log.txt command line, exit code and stderr
//	raw/<case>/archive.log.txt the image export that Trivy and Dockle read
//	raw/<case>/run.json       how each tool was executed for the case, with the archive config digest
//
// The analysis reads only the raw directory, so -analyze-only repeats the
// classification offline from stored outputs.
//
// Exit codes: 0 completed, 2 usage error, 3 incomplete (a tool failed, a
// build failed, or with -require-all a tool was not run).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/spec"
)

// defaultImagePrefix is the repository prefix of the built corpus images. The
// image_prefix of tier3_truth.json is the same string, so that the attribution
// step finds the images this tool keeps with -keep-images.
const defaultImagePrefix = "localhost/conunit-rq1"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr *os.File) int {
	log := NewLogger(stderr)
	fs := flag.NewFlagSet("rq1", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oraclePath := fs.String("oracle", "fixtures/rq1/oracle.json", "Ground truth oracle")
	outDir := fs.String("out-dir", "results", "Output directory")
	enginePref := fs.String("engine", "auto", "Container engine used to build images: auto, podman or docker")
	conunitBin := fs.String("conunit", "", "con-unit binary (default: bin/con-unit if present, else con-unit on PATH)")
	hadolintBin := fs.String("hadolint", "", "hadolint binary (default: hadolint on PATH)")
	trivyBin := fs.String("trivy", "", "trivy binary (default: trivy on PATH)")
	cstBin := fs.String("cst", "", "container-structure-test binary (default: container-structure-test on PATH)")
	dockleBin := fs.String("dockle", "", "dockle binary (default: dockle on PATH)")
	toolsFlag := fs.String("tools", "", "Comma-separated tools to run (default: all of "+strings.Join(allTools, ",")+")")
	casesFlag := fs.String("cases", "", "Comma-separated case IDs to run (default: all)")
	conunitFlags := fs.String("conunit-flags", "--image-source local", "Extra flags for con-unit test")
	trivyConfigArgs := fs.String("trivy-config-args", "--format json --quiet --skip-check-update", "Arguments of trivy config (the Dockerfile directory is appended)")
	trivyImageArgs := fs.String("trivy-image-args", "--format json --quiet --skip-check-update --scanners secret --image-config-scanners misconfig,secret", "Arguments of trivy image (--input <archive> is appended)")
	cstHost := fs.String("cst-docker-host", "", "DOCKER_HOST for container-structure-test (default: start a rootful podman service socket when needed)")
	imagePrefix := fs.String("image-prefix", defaultImagePrefix, "Repository prefix of the built images")
	keepImages := fs.Bool("keep-images", false, "Keep the built images after the run")
	timeout := fs.Duration("timeout", 10*time.Minute, "Timeout per external command")
	analyzeOnly := fs.Bool("analyze-only", false, "Skip execution and classify the existing raw directory")
	requireAll := fs.Bool("require-all", false, "Exit 3 when any tool is NOT_RUN")
	if err := fs.Parse(args); err != nil {
		return spec.ExitUsage
	}

	oracle, err := LoadOracle(*oraclePath)
	if err != nil {
		log.Error("%v", err)
		return spec.ExitUsage
	}
	if err := oracle.ValidateFiles(); err != nil {
		log.Error("%v", err)
		return spec.ExitUsage
	}
	if err := checkTruth(log, oracle, *imagePrefix); err != nil {
		log.Error("%v", err)
		return spec.ExitUsage
	}
	selectedTools, err := parseSelection(*toolsFlag, allTools, "tool")
	if err != nil {
		log.Error("%v", err)
		return spec.ExitUsage
	}
	var caseIDs []string
	for _, c := range oracle.Cases {
		caseIDs = append(caseIDs, c.ID)
	}
	selectedCases, err := parseSelection(*casesFlag, caseIDs, "case")
	if err != nil {
		log.Error("%v", err)
		return spec.ExitUsage
	}

	ex := osExecutor{}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	engine, err := chooseEngine(ex, *enginePref)
	if err != nil {
		log.Error("%v", err)
		return spec.ExitUsage
	}

	if !*analyzeOnly {
		cfg := &RunConfig{
			Oracle: oracle,
			OutDir: *outDir,
			Engine: engine,
			Binaries: map[string]string{
				ToolConUnit:  resolveConUnit(*conunitBin),
				ToolHadolint: *hadolintBin,
				ToolTrivy:    *trivyBin,
				ToolCST:      *cstBin,
				ToolDockle:   *dockleBin,
			},
			Selected:        selectedTools,
			Cases:           selectedCases,
			ConUnitFlags:    strings.Fields(*conunitFlags),
			TrivyConfigArgs: strings.Fields(*trivyConfigArgs),
			TrivyImageArgs:  strings.Fields(*trivyImageArgs),
			CSTDockerHost:   *cstHost,
			ImagePrefix:     *imagePrefix,
			KeepImages:      *keepImages,
			Timeout:         *timeout,
			Log:             log,
		}
		if cfg.CSTDockerHost == "" && selectedTools[ToolCST] {
			cfg.CSTDockerHost = os.Getenv("DOCKER_HOST")
		}
		if cfg.CSTDockerHost == "" && selectedTools[ToolCST] && engine != "" && filepath.Base(engine) == "podman" && runtime.GOOS == "linux" {
			if _, lookErr := ex.LookPath(defaultBinary(*cstBin, ToolCST)); lookErr == nil {
				host, stopSvc, svcErr := startPodmanService(ctx, engine)
				if svcErr != nil {
					log.Warn("could not start a podman service socket for container-structure-test: %v", svcErr)
				} else {
					defer stopSvc()
					cfg.CSTDockerHost = host
					log.Info("podman service socket for container-structure-test: %s", host)
				}
			}
		}
		log.Section("RQ1 detection benchmark")
		log.Info("oracle   %s (sha256 %s)", *oraclePath, shortID(oracle.SHA256))
		log.Info("cases    %d, properties %d", len(oracle.Cases), len(oracle.Properties))
		log.Info("out-dir  %s", *outDir)
		if _, err := Execute(ctx, ex, cfg); err != nil {
			log.Error("execution interrupted: %v", err)
		}
	}

	res, err := Analyze(oracle, *outDir)
	if err != nil {
		log.Error("%v", err)
		return spec.ExitIncomplete
	}
	res.OraclePath = *oraclePath
	meta := runenv.Detect(ctx, runenv.Options{Version: conunitVersion(res), EngineBinary: engine})
	meta.FinishedAt = time.Now().UTC()
	res.Run = &meta
	if err := WriteResults(oracle, res, *outDir); err != nil {
		log.Error("%v", err)
		return spec.ExitIncomplete
	}

	incomplete := printSummary(log, res)
	log.Ok("wrote %s", filepath.Join(*outDir, resultsFileName))
	log.Ok("wrote %s", filepath.Join(*outDir, tableFileName))
	if incomplete.errors > 0 || incomplete.builds > 0 || (*requireAll && incomplete.notRun > 0) {
		return spec.ExitIncomplete
	}
	return spec.ExitOK
}

// checkTruth validates tier3_truth.json when it sits next to the oracle, so a
// seeded case that was renamed or re-scoped in only one of the two files stops
// the run. A different -image-prefix is only a warning: the attribution step
// looks the seeded images up by the prefix of the truth file.
func checkTruth(log *Logger, o *Oracle, imagePrefix string) error {
	path := filepath.Join(o.Dir, TruthFileName)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	truth, err := LoadTruth(path)
	if err != nil {
		return err
	}
	if err := truth.Validate(o); err != nil {
		return err
	}
	log.Info("truth    %d seeded Tier 3 cases, %d scored", len(truth.Cases), len(truth.Scored()))
	if strings.TrimSuffix(imagePrefix, "/") != strings.TrimSuffix(truth.ImagePrefix, "/") {
		log.Warn("image prefix %s differs from %s of %s, the attribution step will not find these images", imagePrefix, truth.ImagePrefix, TruthFileName)
	}
	return nil
}

type incompleteness struct{ errors, builds, notRun int }

// printSummary prints the per-tool counts and returns what was incomplete.
func printSummary(log *Logger, res *Results) incompleteness {
	var inc incompleteness
	log.Section("Summary")
	fmt.Fprintf(log.w, "%-10s %-8s %4s %4s %4s %4s %5s %5s %5s %5s %5s  %s\n", "tool", "status", "TP", "FP", "FN", "TN", "OOS", "N/R", "ERR", "UNV", "N/E", "recall")
	for _, name := range allTools {
		s, ok := res.Summary[name]
		if !ok {
			continue
		}
		recall := "n/a"
		if s.Recall.Value != nil {
			recall = fmt.Sprintf("%d/%d", s.Recall.Numerator, s.Recall.Denominator)
		}
		fmt.Fprintf(log.w, "%-10s %-8s %4d %4d %4d %4d %5d %5d %5d %5d %5d  %s\n", name, s.Status,
			s.Counts[ClassTP], s.Counts[ClassFP], s.Counts[ClassFN], s.Counts[ClassTN],
			s.Counts[ClassOutOfScope], s.Counts[ClassNotRun], s.Counts[ClassToolError], s.Counts[ClassUnverified], s.Counts[ClassNotEvaluated], recall)
		inc.errors += s.Counts[ClassToolError]
		inc.notRun += s.Counts[ClassNotRun]
		if s.Status == "NOT_RUN" {
			log.Warn("%s was NOT_RUN for every case, its column is not a result", name)
		}
	}
	for _, name := range allTools {
		if cat, ok := res.Catalogs[name]; ok && cat.State == catalogMismatch {
			log.Warn("%s reports %q but its scope entries were read at version %s", name, cat.ObservedVersion, cat.Version)
		}
	}
	for _, c := range res.Cases {
		if c.Build.Status == "failed" {
			inc.builds++
			log.Error("build of %s failed: %s", c.ID, c.Build.Error)
		}
	}
	return inc
}

// parseSelection turns a comma-separated list into a set. An empty list
// selects everything and returns a set containing all known names.
func parseSelection(list string, known []string, what string) (map[string]bool, error) {
	set := map[string]bool{}
	if strings.TrimSpace(list) == "" {
		for _, k := range known {
			set[k] = true
		}
		return set, nil
	}
	valid := map[string]bool{}
	for _, k := range known {
		valid[k] = true
	}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !valid[item] {
			return nil, fmt.Errorf("unknown %s %q", what, item)
		}
		set[item] = true
	}
	return set, nil
}

func chooseEngine(ex Executor, pref string) (string, error) {
	candidates := []string{"podman", "docker"}
	switch pref {
	case "", "auto":
	case "podman", "docker":
		candidates = []string{pref}
	default:
		return "", fmt.Errorf("unknown engine %q (use auto, podman or docker)", pref)
	}
	for _, c := range candidates {
		if _, err := ex.LookPath(c); err == nil {
			return c, nil
		}
	}
	return "", nil
}

func resolveConUnit(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if _, err := os.Stat("bin/con-unit"); err == nil {
		abs, absErr := filepath.Abs("bin/con-unit")
		if absErr == nil {
			return abs
		}
	}
	return ""
}

func defaultBinary(explicit, tool string) string {
	if explicit != "" {
		return explicit
	}
	return defaultBinaries[tool]
}

// startPodmanService starts a rootful podman API socket for tools that speak
// the Docker API. It returns the DOCKER_HOST value and a stop function.
func startPodmanService(ctx context.Context, engine string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "rq1p")
	if err != nil {
		return "", nil, err
	}
	sock := filepath.Join(dir, "p.sock")
	cmd := exec.CommandContext(ctx, engine, "system", "service", "--time=0", "unix://"+sock)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		os.RemoveAll(dir)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(sock); statErr == nil {
			return "unix://" + sock, stop, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	stop()
	return "", nil, fmt.Errorf("socket %s did not appear within 15s", sock)
}

// conunitVersion returns the version string of the con-unit binary that was
// benchmarked, or "unknown" when it was not available.
func conunitVersion(res *Results) string {
	if info, ok := res.Tools[ToolConUnit]; ok && info.Version != "" {
		return info.Version
	}
	return "unknown"
}
