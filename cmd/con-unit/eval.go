package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/journal"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/reporter"
	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

func runEvalCommand(args []string) int {
	return runEvalCommandWithDeps(args, defaultCommandDeps())
}

// evalFlags holds the parsed and validated flags of `con-unit eval`.
type evalFlags struct {
	imagesFile     string
	packName       string
	outDir         string
	enginePref     string
	platform       string
	imageSource    string
	probeWindow    time.Duration
	imageTimeout   time.Duration
	journalPath    string
	resume         bool
	failOnFindings bool
	maxIndex       int
	signature      conunit.SignatureTrustPolicy
	signatureOn    bool
}

func parseEvalFlags(args []string) (evalFlags, error) {
	var parsed evalFlags
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	imagesFile := fs.String("images", "", "File containing newline-delimited images")
	packName := fs.String("pack", "cis", "Rule pack to evaluate: hardening (alias cis), hygiene, kube, nist, distroless, lint (alias image-lint)")
	outDir := fs.String("out-dir", "results", "Output directory for evaluation results")
	enginePref := fs.String("engine", "auto", "Container engine (auto, podman, docker)")
	imageTimeout := fs.Duration("image-timeout", defaultImageTimeout, "Per-image deadline")
	journalPath := fs.String("journal", "", "Append-only JSONL journal (default: <out-dir>/journal.jsonl)")
	resume := fs.Bool("resume", false, "Skip images that already have a COMPLETED journal record")
	failOnFindings := fs.Bool("fail-on-findings", false, "Exit 1 when any FAIL or UNVERIFIED result exists")
	maxIndex := fs.Int("max-index-entries", defaultMaxIndexEntries, "Filesystem index entry cap; it also bounds the estimated index memory")
	cosignKey := fs.String("cosign-key", "", "Public key used to verify image signatures")
	certificateIdentity := fs.String("certificate-identity", "", "Trusted keyless signer identity")
	certificateIssuer := fs.String("certificate-oidc-issuer", "", "Trusted keyless OIDC issuer")
	shared := registerRuntimeFlags(fs)

	if err := fs.Parse(args); err != nil {
		return parsed, fmt.Errorf("invalid evaluation flags: %w", err)
	}
	if fs.NArg() > 0 {
		return parsed, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	signaturePolicy, signatureConfigured, err := signaturePolicyFromFlags(*cosignKey, *certificateIdentity, *certificateIssuer)
	if err != nil {
		return parsed, fmt.Errorf("invalid signature configuration: %w", err)
	}
	platform, imageSource, window, err := shared.resolved()
	if err != nil {
		return parsed, err
	}
	if err := validateEngineFlag(*enginePref); err != nil {
		return parsed, err
	}
	if *imageTimeout <= 0 {
		return parsed, fmt.Errorf("invalid --image-timeout %s (must be positive)", *imageTimeout)
	}
	if *maxIndex < 1 {
		return parsed, fmt.Errorf("invalid --max-index-entries %d (must be at least 1)", *maxIndex)
	}
	if *imagesFile == "" {
		return parsed, errors.New("--images is required for evaluation mode")
	}

	parsed = evalFlags{
		imagesFile:     *imagesFile,
		packName:       strings.TrimPrefix(strings.TrimPrefix(*packName, "pack="), "pack:"),
		outDir:         strings.TrimPrefix(strings.TrimPrefix(*outDir, "out_dir="), "out_dir:"),
		enginePref:     *enginePref,
		platform:       platform,
		imageSource:    imageSource,
		probeWindow:    window,
		imageTimeout:   *imageTimeout,
		journalPath:    *journalPath,
		resume:         *resume,
		failOnFindings: *failOnFindings,
		maxIndex:       *maxIndex,
		signature:      signaturePolicy,
		signatureOn:    signatureConfigured,
	}
	if parsed.journalPath == "" {
		parsed.journalPath = filepath.Join(parsed.outDir, "journal.jsonl")
	}
	return parsed, nil
}

// namedFlag is one flag with the value in effect.
type namedFlag struct {
	name, value string
}

// effectiveDefaults lists the flags that decide which images end in an
// infrastructure or tool-limit status (the index limit and the per-image
// deadline) with the values in effect. A default must not be implicit, because
// the study reports its attrition.
func (f evalFlags) effectiveDefaults() []namedFlag {
	return []namedFlag{
		{"image-timeout", f.imageTimeout.String()},
		{"max-index-entries", strconv.Itoa(f.maxIndex)},
	}
}

// withEffectiveFlags appends --name=value for every flag in effective that the
// operator did not pass, so the flag list stored in the run metadata states the
// configuration that was really used, defaults included.
func withEffectiveFlags(args []string, effective []namedFlag) []string {
	passed := make(map[string]struct{}, len(args))
	for _, arg := range args {
		trimmed := strings.TrimLeft(arg, "-")
		if len(trimmed) == len(arg) {
			continue // not a flag
		}
		name, _, _ := strings.Cut(trimmed, "=")
		passed[name] = struct{}{}
	}
	out := append([]string(nil), args...)
	for _, flag := range effective {
		if _, ok := passed[flag.name]; !ok {
			out = append(out, "--"+flag.name+"="+flag.value)
		}
	}
	return out
}

// formatCount renders an integer with thousands separators.
func formatCount(n int) string {
	digits := strconv.Itoa(n)
	sign := ""
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	var sb strings.Builder
	for i, digit := range digits {
		if i > 0 && (len(digits)-i)%3 == 0 {
			sb.WriteByte(',')
		}
		sb.WriteRune(digit)
	}
	return sign + sb.String()
}

// logIndexReport prints how large an image is relative to the index limit.
// The line precedes the outcome line of the image and gives the distribution of
// image sizes, which the choice of --max-index-entries rests on.
func logIndexReport(report runner.IndexReport) {
	fmt.Fprintf(os.Stderr, "  %-14s %s entries | %d layers | %s read | est. %s index memory | %s\n",
		"INDEXED", formatCount(report.Stats.Entries), report.Stats.Layers,
		oci.FormatBytes(report.Stats.ScannedBytes), oci.FormatBytes(report.Stats.EstimatedBytes),
		report.Duration.Round(time.Millisecond))
}

// uniqueImages removes repeated references while keeping the first occurrence.
func uniqueImages(images []string) (unique, duplicates []string) {
	seen := make(map[string]struct{}, len(images))
	for _, image := range images {
		if _, ok := seen[image]; ok {
			duplicates = append(duplicates, image)
			continue
		}
		seen[image] = struct{}{}
		unique = append(unique, image)
	}
	return unique, duplicates
}

func runEvalCommandWithDeps(args []string, deps commandDeps) int {
	flags, err := parseEvalFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return spec.ExitUsage
	}

	file, err := os.Open(flags.imagesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not open image list %q: %v\n", flags.imagesFile, err)
		return spec.ExitUsage
	}
	listed, err := readImageList(file)
	_ = file.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return spec.ExitUsage
	}
	images, duplicates := uniqueImages(listed)
	if len(images) == 0 {
		fmt.Fprintf(os.Stderr, "error: no valid images found in %q\n", flags.imagesFile)
		return spec.ExitUsage
	}
	for _, duplicate := range duplicates {
		fmt.Fprintf(os.Stderr, "warning: image listed more than once, evaluating it once: %s\n", duplicate)
	}

	eng, err := deps.detectEngine(flags.enginePref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: container engine: %v\n", err)
		return spec.ExitUsage
	}
	pack, err := deps.resolvePack(flags.packName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compliance pack: %v\n", err)
		return spec.ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "Evaluating %d images with %s using %s (platform %s, source %s, window %s)\n",
		len(images), pack.Name(), filepath.Base(eng.BinaryPath), flags.platform, flags.imageSource, flags.probeWindow)

	r := deps.newRunner(eng, runner.Options{
		Platform:        flags.platform,
		ImageSource:     flags.imageSource,
		ProbeWindow:     flags.probeWindow,
		MaxIndexEntries: flags.maxIndex,
		Retry:           retryPolicy(),
		OnIndexed:       logIndexReport,
	})
	if !configureSignatureVerification(r, flags.signatureOn, flags.signature) {
		return spec.ExitUsage
	}

	runMeta := deps.detectRun(ctx, runenv.Options{
		Version:       version,
		EngineBinary:  eng.BinaryPath,
		DatasetPath:   flags.imagesFile,
		Pack:          flags.packName,
		PackID:        pack.ID(),
		Platform:      flags.platform,
		ImageSource:   flags.imageSource,
		ProbeWindow:   flags.probeWindow,
		Flags:         withEffectiveFlags(append([]string{"eval"}, args...), flags.effectiveDefaults()),
		RegistryRemap: os.Getenv("CONUNIT_REGISTRY_REMAP"),
	})
	reportRunEnvironment(runMeta)

	// Resume keeps the journal; a fresh run moves any earlier journal aside so
	// two runs never share one study.
	completed := map[string]*spec.SuiteResult{}
	if flags.resume {
		prior, skipped, readErr := journal.Read(flags.journalPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", readErr)
			return spec.ExitUsage
		}
		if skipped {
			fmt.Fprintln(os.Stderr, "warning: ignored a torn final journal line left by an interrupted run")
		}
		for ref, record := range journal.Latest(prior) {
			if journal.Completed(record) {
				completed[ref] = record
			}
		}
	} else if rotated, rotateErr := journal.RotateIfPresent(flags.journalPath, deps.clock()); rotateErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", rotateErr)
		return spec.ExitIncomplete
	} else if rotated != "" {
		fmt.Fprintf(os.Stderr, "note: moved the existing journal to %s (use --resume to continue it)\n", rotated)
	}

	if err := os.MkdirAll(flags.outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create output directory %q: %v\n", flags.outDir, err)
		return spec.ExitIncomplete
	}
	jw, err := journal.Open(flags.journalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return spec.ExitIncomplete
	}
	defer jw.Close()

	logDir := filepath.Join(flags.outDir, "logs")
	outputFailed := false
	interrupted := false
	inMemory := make(map[string]*spec.SuiteResult, len(images))

	for idx, img := range images {
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		fmt.Fprintf(os.Stderr, "[%*d/%d] %s\n", len(fmt.Sprint(len(images))), idx+1, len(images), img)
		if prior, ok := completed[img]; ok {
			inMemory[img] = prior
			fmt.Fprintf(os.Stderr, "  %-14s resumed from the journal\n", spec.StatusCompleted)
			continue
		}

		started := deps.clock()
		imgCtx, cancel := context.WithTimeout(ctx, flags.imageTimeout)
		res, runErr := r.RunPack(imgCtx, pack, img)
		cancel()
		if ctx.Err() != nil && runErr != nil && !errors.Is(runErr, context.DeadlineExceeded) {
			// The operator interrupted the run; the image was not attempted to
			// completion, so it gets no record and a resume will retry it.
			interrupted = true
			fmt.Fprintf(os.Stderr, "  %-14s interrupted, no record written\n", "ABORTED")
			break
		}
		record := buildImageRecord(img, pack, res, runErr, started, deps.clock().Sub(started))
		writeImageDiagnosticLog(logDir, record)
		inMemory[img] = record
		if err := jw.Append(record); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			outputFailed = true
		}
		logImageOutcome(record)
	}

	// The study is assembled from the journal, the source of truth. A record
	// whose append failed falls back to the in-memory copy.
	journalRecords, _, readErr := journal.Read(flags.journalPath)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", readErr)
		outputFailed = true
	}
	study := assembleStudy(runMeta, images, journal.Latest(journalRecords), inMemory, deps.clock())

	studyPath := filepath.Join(flags.outDir, "empirical_study.json")
	if err := writeJSONAtomic(studyPath, study); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write empirical JSON: %v\n", err)
		outputFailed = true
	} else {
		fmt.Fprintf(os.Stderr, "Wrote results: %s\n", studyPath)
	}
	summaryPath := filepath.Join(flags.outDir, "EMPIRICAL_SUMMARY.md")
	if err := writeFileAtomic(summaryPath, []byte(renderMarkdownSummary(study))); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write evaluation summary: %v\n", err)
		outputFailed = true
	} else {
		fmt.Fprintf(os.Stderr, "Wrote summary: %s\n", summaryPath)
	}
	attritionPath := filepath.Join(flags.outDir, "ATTRITION_REPORT.md")
	if err := writeFileAtomic(attritionPath, []byte(renderAttritionReport(study))); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write attrition report: %v\n", err)
		outputFailed = true
	} else {
		fmt.Fprintf(os.Stderr, "Wrote attrition report: %s\n", attritionPath)
	}

	if batch := summarizeBatchResources(study.Images); batch.peakRSSMB > 0 {
		fmt.Fprintf(os.Stderr, "ConUnit process peak RSS over the run: %s (ceiling of the process only; the engine and probe containers are excluded)\n",
			oci.FormatBytes(int64(batch.peakRSSMB*1024*1024)))
	}

	return evalExitCode(study, len(images), interrupted, outputFailed, flags.failOnFindings)
}

// evalExitCode implements the exit-code contract of docs/CONTRACT.md section 4.
// An incomplete run takes precedence over findings.
func evalExitCode(study *spec.Study, attempted int, interrupted, outputFailed, failOnFindings bool) int {
	counts := statusCounts(study.Images)
	notCompleted := 0
	findings := false
	for status, count := range counts {
		if status != spec.StatusCompleted {
			notCompleted += count
		}
	}
	for _, image := range study.Images {
		if image.Status == spec.StatusCompleted && (image.Failed > 0 || image.Unverified > 0) {
			findings = true
		}
	}
	if interrupted || outputFailed || notCompleted > 0 || len(study.Images) < attempted {
		fmt.Fprintf(os.Stderr, "Evaluation incomplete: %d of %d images COMPLETED (exit %d)\n",
			counts[spec.StatusCompleted], attempted, spec.ExitIncomplete)
		return spec.ExitIncomplete
	}
	fmt.Fprintf(os.Stderr, "Evaluation complete: all %d images COMPLETED\n", attempted)
	if failOnFindings && findings {
		fmt.Fprintf(os.Stderr, "Findings present and --fail-on-findings is set (exit %d)\n", spec.ExitFindings)
		return spec.ExitFindings
	}
	return spec.ExitOK
}

// buildImageRecord turns the outcome of RunPack into the one record written
// for the image. Failures get a typed status and reason, never a text guess.
func buildImageRecord(img string, pack conunit.RulePack, res *spec.SuiteResult, runErr error, started time.Time, elapsed time.Duration) *spec.SuiteResult {
	if runErr != nil {
		status, reason := runner.ClassifyError(runErr)
		record := &spec.SuiteResult{
			ImageName:    img,
			RequestedRef: img,
			SuiteName:    pack.Name(),
			Status:       status,
			Reason:       reason,
			ErrorMessage: runErr.Error(),
			Timestamp:    started.UTC(),
			Duration:     elapsed,
			Results:      []spec.TestResult{},
		}
		var imageErr *runner.ImageError
		if errors.As(runErr, &imageErr) {
			record.ImageSource = imageErr.ImageSource
			// A failure after the image was identified keeps its identity and
			// the size read so far, so an exclusion such as INDEX_LIMIT can
			// say which image it was and how large it is.
			if partial := imageErr.Partial; partial != nil {
				record.ImageDigest = partial.ImageDigest
				record.ConfigDigest = partial.ConfigDigest
				record.Platform = partial.Platform
				record.Resources = partial.Resources
			}
		}
		return record
	}
	record := *res
	record.ImageName = img
	record.RequestedRef = img
	if record.Status == "" {
		record.Status = spec.StatusCompleted
	}
	if record.Results == nil {
		record.Results = []spec.TestResult{}
	}
	return &record
}

func logImageOutcome(record *spec.SuiteResult) {
	if record.Status != spec.StatusCompleted {
		label := record.Status
		if record.Reason != "" {
			label += " (" + string(record.Reason) + ")"
		}
		fmt.Fprintf(os.Stderr, "  %s\n", label)
		fmt.Fprintf(os.Stderr, "    error: %s\n", record.ErrorMessage)
		return
	}
	source := record.ImageSource
	if source == "" {
		source = "unknown source"
	}
	fmt.Fprintf(os.Stderr, "  %-14s %d passed | %d failed | %d unverified | %s | %s\n",
		record.Status, record.Passed, record.Failed, record.Unverified,
		record.Duration.Round(time.Millisecond), source)
}

// assembleStudy builds the study document in image-list order. Journal
// records win; the in-memory copy is only used when an append failed.
func assembleStudy(meta spec.RunMetadata, images []string, fromJournal, inMemory map[string]*spec.SuiteResult, now time.Time) *spec.Study {
	meta.FinishedAt = now.UTC()
	study := &spec.Study{
		SchemaVersion: spec.SchemaVersion,
		Run:           meta,
		Images:        make([]*spec.SuiteResult, 0, len(images)),
	}
	for _, img := range images {
		if record, ok := fromJournal[img]; ok {
			study.Images = append(study.Images, record)
		} else if record, ok := inMemory[img]; ok {
			study.Images = append(study.Images, record)
		}
	}
	return study
}

func writeJSONAtomic(path string, data any) error {
	tmp := path + ".tmp"
	if err := reporter.WriteJSON(tmp, data); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
