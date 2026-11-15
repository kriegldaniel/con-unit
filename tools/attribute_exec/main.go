// Command attribute_exec attributes Tier 3 failures to a cause by experiment.
//
// Input is a study document (empirical_study.json). For every image with an
// EXEC-02 FAIL (all capabilities dropped) or an EXEC-01 FAIL (read-only root
// filesystem) the tool starts the image again under the same defensive
// profile as docs/CONTRACT.md section 6, observes it for the window W, and
// reports which candidate makes the container survive:
//
//	EXEC-02: add back one capability at a time (CAP_CHOWN, CAP_DAC_OVERRIDE,
//	         CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID,
//	         CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT), then all of them.
//	EXEC-01: add a writable tmpfs at /run, /var/run, /var/cache, /var/log or
//	         /var/lib, one at a time, then all of them. The treatment already
//	         mounts /tmp.
//
// Each pair first reruns a baseline (defensive flags only) and the treatment.
// Candidates are tried only when the baseline runs and the failure
// reproduces. When no single candidate resolves the failure but the union of
// all of them does, the union is shrunk to a minimal set (-minimize, on by
// default), because an image such as a gosu or su-exec entrypoint needs
// CAP_SETUID and CAP_SETGID together. The result states a cause by
// experiment, not by keywords in logs. It says nothing about whether the cause
// is a defect of the image.
//
// Work, which can be combined as noted:
//
//	-study <empirical_study.json>  attribute the real FAILs of a study
//	-truth <tier3_truth.json>      attribute the seeded images of the truth file
//	                               and compare each minimal set with the
//	                               expected one (EXACT, SUPERSET, WRONG,
//	                               NOT_MANIFESTED). Works with or without a study
//	-ablation -study <study>       rerun the four treatments (read-only rootfs
//	                               with the base tmpfs, --cap-drop=ALL,
//	                               --security-opt=no-new-privileges:true,
//	                               --memory=256m) without the baseline gate on
//	                               every image whose Tier 3 is UNVERIFIED with
//	                               BASELINE_FAILED or NOT_OBSERVABLE, and count
//	                               how many a single-run tool would have called
//	                               FAIL. Runs the ablation only
//
// Outputs in -out-dir: attribution.json and attribution.csv, with one CSV row
// per image, rule and attempt, ablation.json, table_attribution.tex (label
// tab:attribution) and macros_attribution.tex. The study block and the seeded
// block of attribution.json can come from different invocations: a run that
// does not compute a block keeps the one the file already holds and lists it in
// carried_over. The two LaTeX files are rendered from this run and from the
// attribution.json and ablation.json that already sit in the same directory (or
// at the paths given with -attribution-json and -ablation-json), so every
// invocation can refresh them and a value without data prints n/a. Use one
// directory for all kinds of work.
//
// The images must be in the local store of the engine, as left by the
// evaluation run on the same host. Use -pull to fetch absent study images.
//
// Exit codes: 0 completed, 2 usage error, 3 incomplete (an image was absent
// or the engine failed for at least one pair).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/spec"
)

// conunitVersion is set at build time with -ldflags "-X main.conunitVersion=...".
var conunitVersion = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// options is the validated command line.
type options struct {
	studyPath   string
	outDir      string
	enginePref  string
	window      time.Duration // 0 means the window of the study, else 3 s
	rules       []string
	only        map[string]bool
	limit       int
	pull        bool
	minimize    bool
	truthPath   string
	imagePrefix string
	ablation    bool
	// attributionJSON and ablationJSON name the files from which the LaTeX
	// outputs take the block that this run does not compute. Empty means
	// attribution.json and ablation.json in the output directory.
	attributionJSON string
	ablationJSON    string
	args            []string
}

// errUsage reports an invalid command line. The message was logged already.
var errUsage = errors.New("usage")

func parseOptions(args []string, stderr io.Writer, log *Logger) (options, error) {
	fs := flag.NewFlagSet("attribute_exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := options{only: map[string]bool{}, args: args}
	studyFlag := fs.String("study", "", "Study JSON (empirical_study.json). May also be given as the only argument")
	fs.StringVar(&o.outDir, "out-dir", "", "Output directory (default: the directory of the study)")
	fs.StringVar(&o.enginePref, "engine", "auto", "Container engine: auto, podman or docker")
	fs.DurationVar(&o.window, "probe-window", 0, "Observation window W (default: the window recorded in the study, else 3s)")
	rulesFlag := fs.String("rules", "EXEC-01,EXEC-02", "Comma-separated rules to attribute")
	onlyFlag := fs.String("images", "", "Comma-separated image references to restrict the run to")
	fs.IntVar(&o.limit, "limit", 0, "Attribute at most this many image and rule pairs (images with -ablation), 0 for all")
	fs.BoolVar(&o.pull, "pull", false, "Pull images that are absent from the local store")
	fs.BoolVar(&o.minimize, "minimize", true, "Shrink a resolving union one element at a time to a minimal set (status RESOLVED_MINIMAL)")
	fs.StringVar(&o.truthPath, "truth", "", "Attribute the seeded images of this tier3_truth.json and compare each minimal set with the expected one")
	fs.StringVar(&o.imagePrefix, "image-prefix", "", "Image prefix of the seeded images, <prefix>/<case>:rq1 (default: image_prefix of the truth file)")
	fs.BoolVar(&o.ablation, "ablation", false, "Rerun the four treatments of the images whose Tier 3 is UNVERIFIED without the baseline gate and count the single-run FAILs (ablation only)")
	fs.StringVar(&o.attributionJSON, "attribution-json", "", "attribution.json to take the attribution numbers of the LaTeX outputs from when this run computes none (default: <out-dir>/attribution.json)")
	fs.StringVar(&o.ablationJSON, "ablation-json", "", "ablation.json to take the ablation numbers of the LaTeX outputs from when this run computes none (default: <out-dir>/ablation.json)")
	if err := fs.Parse(args); err != nil {
		return o, errUsage
	}
	usage := func(format string, a ...any) (options, error) {
		log.Error(format, a...)
		return o, errUsage
	}

	o.studyPath = *studyFlag
	if o.studyPath == "" && fs.NArg() == 1 {
		o.studyPath = fs.Arg(0)
	} else if o.studyPath != "" && fs.NArg() > 0 || fs.NArg() > 1 {
		return usage("give the study once, either with -study or as the only argument")
	}
	switch {
	case o.ablation && o.truthPath != "":
		return usage("-ablation runs the ablation only and cannot be combined with -truth")
	case o.ablation && o.studyPath == "":
		return usage("-ablation needs the study: attribute_exec -ablation -study <path/to/empirical_study.json>")
	case o.studyPath == "" && o.truthPath == "":
		return usage("no study given: attribute_exec [flags] <path/to/empirical_study.json>, or give -truth <tier3_truth.json>")
	case o.imagePrefix != "" && o.truthPath == "":
		return usage("-image-prefix is only used together with -truth")
	case o.studyPath == "" && o.outDir == "":
		return usage("-out-dir is required when no study is given")
	}
	for _, r := range strings.Split(*rulesFlag, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, err := treatmentFlags(r); err != nil {
			return usage("%v", err)
		}
		o.rules = append(o.rules, r)
	}
	if len(o.rules) == 0 {
		return usage("-rules is empty")
	}
	for _, ref := range strings.Split(*onlyFlag, ",") {
		if ref = strings.TrimSpace(ref); ref != "" {
			o.only[ref] = true
		}
	}
	if o.limit < 0 {
		return usage("-limit must not be negative")
	}
	if o.window < 0 {
		return usage("-probe-window must not be negative")
	}
	return o, nil
}

func run(args []string, stderr *os.File) int {
	log := NewLogger(stderr)
	opts, err := parseOptions(args, stderr, log)
	if err != nil {
		return spec.ExitUsage
	}
	binary, err := findEngine(opts.enginePref)
	if err != nil {
		log.Error("container engine: %v", err)
		return spec.ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	meta := runenv.Detect(ctx, runenv.Options{Version: conunitVersion, EngineBinary: binary, Flags: args})
	return execute(ctx, opts, &EngineRunner{Binary: binary}, meta, log)
}

// execute runs the work that the options ask for against a container runner
// and writes the outputs. It is the whole tool except the engine lookup.
func execute(ctx context.Context, opts options, r ContainerRunner, meta spec.RunMetadata, log *Logger) int {
	var study *LoadedStudy
	if opts.studyPath != "" {
		var err error
		if study, err = LoadStudy(opts.studyPath); err != nil {
			log.Error("%v", err)
			return spec.ExitUsage
		}
	}
	var truth *TruthFile
	if opts.truthPath != "" {
		var err error
		if truth, err = LoadTruth(opts.truthPath); err != nil {
			log.Error("%v", err)
			return spec.ExitUsage
		}
	}
	win := opts.window
	if win == 0 && study != nil && study.Run != nil && study.Run.ProbeWindowMs > 0 {
		win = time.Duration(study.Run.ProbeWindowMs) * time.Millisecond
	}
	if win <= 0 {
		win = 3 * time.Second
	}
	outDir := opts.outDir
	if outDir == "" {
		outDir = filepath.Dir(opts.studyPath)
	}

	log.Section("Tier 3 failure attribution")
	log.Info("host    %s", runenv.DescribeHost(meta))
	if meta.EngineName == "" || meta.EngineVersion == "" {
		log.Warn("engine facts are empty in the run metadata, the result does not identify its engine")
	}
	log.Info("window  %s, minimize %t, out-dir %s", win, opts.minimize, outDir)
	if study != nil {
		log.Info("study   %s (sha256 %s, %d images)", opts.studyPath, short(study.SHA256), len(study.Images))
	}
	if truth != nil {
		log.Info("truth   %s (sha256 %s, %d cases)", opts.truthPath, short(truth.SHA256), len(truth.Cases))
	}

	out := &Outputs{Dir: outDir, Log: log, AttributionJSON: opts.attributionJSON, AblationJSON: opts.ablationJSON}
	cfg := Config{Window: win, Pull: opts.pull, Minimize: opts.minimize}
	code := spec.ExitOK
	incomplete := func(format string, a ...any) {
		log.Error("incomplete: "+format, a...)
		code = spec.ExitIncomplete
	}

	if opts.ablation {
		ablateStudy(ctx, r, cfg, opts, study, meta, out, log, incomplete)
		printAblationSummary(log, out.Ablation.Summary)
	} else {
		doc := out.StartDocument(study, opts.studyPath, meta, win, opts.minimize, truth != nil)
		out.Attribution = doc
		if study != nil {
			attributeStudy(ctx, r, cfg, opts, study, doc, out, log, incomplete)
		}
		if truth != nil {
			attributeSeeded(ctx, r, cfg, opts, truth, meta, doc, out, log, incomplete)
		}
		if study != nil {
			printSummary(log, doc.Summary)
		}
		if truth != nil {
			printSeededSummary(log, doc.Seeded.Summary)
		}
	}

	if err := out.Write(); err != nil {
		log.Error("%v", err)
		code = spec.ExitIncomplete
	} else {
		for _, name := range out.Written() {
			log.Ok("wrote %s", filepath.Join(outDir, name))
		}
	}
	return code
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// attributeStudy attributes the FAILs of the study into the study block of doc.
func attributeStudy(ctx context.Context, r ContainerRunner, cfg Config, opts options, study *LoadedStudy, doc *Document, out *Outputs, log *Logger, incomplete func(string, ...any)) {
	targets := SelectTargets(study.Images, opts.rules, opts.only)
	if opts.limit > 0 && len(targets) > opts.limit {
		targets = targets[:opts.limit]
	}
	log.Info("pairs   %d to attribute (%s)", len(targets), strings.Join(opts.rules, ", "))
	if len(targets) == 0 {
		log.Warn("the study has no %s failure, the study block is written empty", strings.Join(opts.rules, " or "))
	}
	snapshot := func(done []Attribution, complete bool) {
		doc.Complete = complete
		doc.Attributions = done
		if doc.Attributions == nil {
			doc.Attributions = []Attribution{}
		}
		doc.Summary = Summarize(done)
	}
	attrs := Attribute(ctx, r, cfg, targets, log, func(done []Attribution) {
		snapshot(done, false)
		if err := out.Write(); err != nil {
			log.Error("writing snapshot outputs failed: %v", err)
		}
	})
	doc.Run.FinishedAt = time.Now().UTC()
	complete := ctx.Err() == nil && len(attrs) == len(targets)
	snapshot(attrs, complete)
	if t := doc.Summary.Total; !complete || t.ImageAbsent > 0 || t.Error > 0 {
		incomplete("%d absent images, %d engine errors, %d of %d pairs processed", t.ImageAbsent, t.Error, len(attrs), len(targets))
	}
}

// attributeSeeded attributes the seeded cases into the seeded block of doc.
func attributeSeeded(ctx context.Context, r ContainerRunner, cfg Config, opts options, truth *TruthFile, meta spec.RunMetadata, doc *Document, out *Outputs, log *Logger, incomplete func(string, ...any)) {
	log.Section("Seeded cases")
	report := &SeededReport{
		TruthPath: truth.Path, TruthSHA256: truth.SHA256,
		ImagePrefix: strings.TrimSuffix(firstNonEmpty(opts.imagePrefix, truth.ImagePrefix), "/"),
		WindowMs:    cfg.Window.Milliseconds(), Minimize: cfg.Minimize, Run: meta, Cases: []SeededResult{}, Note: seededNote,
	}
	fill := func(results []SeededResult, complete bool) {
		report.GeneratedAt = time.Now().UTC()
		report.Complete = complete
		report.Cases = results
		if report.Cases == nil {
			report.Cases = []SeededResult{}
		}
		report.Summary = SummarizeSeeded(results)
		doc.Seeded = report
	}
	fill(nil, false)
	results := RunSeeded(ctx, r, cfg, truth, opts.imagePrefix, log, func(done []SeededResult) {
		fill(done, false)
		if err := out.Write(); err != nil {
			log.Error("writing snapshot outputs failed: %v", err)
		}
	})
	report.Run.FinishedAt = time.Now().UTC()
	complete := ctx.Err() == nil && len(results) == len(truth.Cases)
	fill(results, complete)
	if s := report.Summary; !complete || s.Incomplete > 0 {
		incomplete("%d seeded cases without a verdict, %d of %d cases processed", s.Incomplete, len(results), len(truth.Cases))
	}
}

// ablateStudy runs the ablation of the study into out.Ablation.
func ablateStudy(ctx context.Context, r ContainerRunner, cfg Config, opts options, study *LoadedStudy, meta spec.RunMetadata, out *Outputs, log *Logger, incomplete func(string, ...any)) {
	log.Section("Ablation without the baseline gate")
	targets := SelectAblationTargets(study.Images, opts.only)
	if opts.limit > 0 && len(targets) > opts.limit {
		targets = targets[:opts.limit]
	}
	log.Info("images  %d with a Tier 3 result that is UNVERIFIED because of the baseline", len(targets))
	if len(targets) == 0 {
		log.Warn("the study has no such image, ablation.json is written empty")
	}
	doc := &AblationDocument{
		SchemaVersion: ablationSchemaVersion,
		Source:        Source{StudyPath: opts.studyPath, StudySHA256: study.SHA256, StudySchemaVersion: study.SchemaVersion},
		Run:           meta,
		Protocol:      NewAblationProtocol(cfg.Window),
		Images:        []AblationImage{},
	}
	out.Ablation = doc
	snapshot := func(done []AblationImage, complete bool) {
		doc.GeneratedAt = time.Now().UTC()
		doc.Complete = complete
		doc.Images = done
		if doc.Images == nil {
			doc.Images = []AblationImage{}
		}
		doc.Summary = SummarizeAblation(done, len(targets))
	}
	snapshot(nil, false)
	images := RunAblation(ctx, r, cfg, targets, log, func(done []AblationImage) {
		snapshot(done, false)
		if err := out.Write(); err != nil {
			log.Error("writing snapshot outputs failed: %v", err)
		}
	})
	doc.Run.FinishedAt = time.Now().UTC()
	complete := ctx.Err() == nil && len(images) == len(targets)
	snapshot(images, complete)
	if s := doc.Summary; !complete || s.ImagesAbsent > 0 || s.ImagesError > 0 {
		incomplete("%d absent images, %d engine errors, %d of %d images processed", s.ImagesAbsent, s.ImagesError, len(images), len(targets))
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func findEngine(pref string) (string, error) {
	candidates := []string{"podman", "docker"}
	switch pref {
	case "", "auto":
	case "podman", "docker":
		candidates = []string{pref}
	default:
		return "", fmt.Errorf("unknown engine %q (use auto, podman or docker)", pref)
	}
	for _, c := range candidates {
		if path, err := lookPath(c); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no container engine found (checked %v)", candidates)
}

func printSummary(log *Logger, s Summary) {
	log.Section("Summary of the real failures")
	for _, rule := range []string{RuleReadOnly, RuleDropCaps} {
		rs, ok := s.ByRule[rule]
		if !ok {
			continue
		}
		log.Info("%s: %d pairs, %d reproducible: %d by a single candidate, %d by a minimal set, %d by the union only, %d unresolved",
			rule, rs.Examined, rs.Attributable, rs.ResolvedBySingle, rs.ResolvedByMinimal, rs.ResolvedByUnionOnly, rs.Unresolved)
		log.Info("%s: not reproduced %d, baseline failed %d, not observable %d, image absent %d, error %d",
			rule, rs.NotReproduced, rs.BaselineFailed, rs.NotObservable, rs.ImageAbsent, rs.Error)
		for _, c := range sortedCandidates(rs.BySingleCandidate) {
			log.Info("%s:   %-22s resolves %d", rule, c, rs.BySingleCandidate[c])
		}
		for _, set := range sortedCandidates(rs.ByMinimalSet) {
			log.Info("%s:   minimal set %-28s %d", rule, set, rs.ByMinimalSet[set])
		}
	}
}

func printAblationSummary(log *Logger, s AblationSummary) {
	log.Section("Summary of the ablation")
	log.Info("images: %d selected, %d examined, %d absent, %d with an engine error", s.ImagesSelected, s.ImagesExamined, s.ImagesAbsent, s.ImagesError)
	log.Info("a single-run tool would call FAIL for %d of %d examined images (%d of %d treatment runs)", s.ImagesMisblamed, s.ImagesExamined, s.PairsFail, s.PairsExamined)
	for _, reason := range sortedKeys(s.ByStudyReason) {
		rs := s.ByStudyReason[reason]
		log.Info("%-16s examined %d, FAIL for at least one treatment %d", reason, rs.Examined, rs.Misblamed)
	}
	for _, rule := range sortedKeys(s.ByTreatment) {
		ts := s.ByTreatment[rule]
		log.Info("%-16s runs %d, FAIL %d, PASS %d", rule, ts.Runs, ts.Fail, ts.Pass)
	}
}

func printSeededSummary(log *Logger, s SeededSummary) {
	log.Section("Summary of the seeded cases")
	log.Info("scored %d: exact %d, superset %d, wrong %d", s.N, s.Exact, s.Superset, s.Wrong)
	log.Info("not manifested %d (reported, not scored), incomplete %d", s.NotManifested, s.Incomplete)
}
