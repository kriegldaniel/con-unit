package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/reporter"
	"github.com/con-unit/con-unit/pkg/retry"
	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

const version = "0.3.0"

// Defaults shared by the test and eval commands.
const (
	defaultProbeWindow     = 3 * time.Second
	defaultImageTimeout    = 5 * time.Minute
	defaultMaxIndexEntries = oci.MaxIndexedFiles
)

type packRunner interface {
	RunPack(context.Context, conunit.RulePack, string) (*spec.SuiteResult, error)
}

type commandDeps struct {
	detectEngine func(string) (*engine.Engine, error)
	resolvePack  func(string) (conunit.RulePack, error)
	newRunner    func(*engine.Engine, runner.Options) packRunner
	detectRun    func(context.Context, runenv.Options) spec.RunMetadata
	now          func() time.Time
}

func defaultCommandDeps() commandDeps {
	return commandDeps{
		detectEngine: engine.DetectEngine,
		resolvePack:  runner.ResolvePack,
		newRunner: func(eng *engine.Engine, options runner.Options) packRunner {
			return runner.NewRunnerWithOptions(eng, options)
		},
		detectRun: runenv.Detect,
		now:       time.Now,
	}
}

func (d commandDeps) clock() time.Time {
	if d.now == nil {
		return time.Now()
	}
	return d.now()
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(spec.ExitUsage)
	}

	command := os.Args[1]

	switch command {
	case "test":
		os.Exit(runTestCommand(os.Args[2:]))
	case "eval":
		os.Exit(runEvalCommand(os.Args[2:]))
	case "rules":
		os.Exit(runRulesCommand(os.Args[2:], os.Stdout, os.Stderr))
	case "version":
		fmt.Printf("ConUnit version %s (OCI Container Unit Testing Framework)\n", version)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", command)
		printHelp()
		os.Exit(spec.ExitUsage)
	}
}

func printHelp() {
	fmt.Println("ConUnit: the Unit Testing Framework for OCI Containers")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  con-unit test <image> [flags]       Execute a rule pack against an OCI image")
	fmt.Println("  con-unit eval [flags]               Run an empirical evaluation over multiple images")
	fmt.Println("  con-unit rules                      Print the rule reference (the source of docs/RULES.md)")
	fmt.Println("  con-unit version                    Print version information")
	fmt.Println()
	fmt.Println("Flags for 'test':")
	fmt.Println("  --pack <name>                       Rule pack: hardening (alias cis), hygiene, kube, nist, distroless, lint (alias image-lint) (default: cis)")
	fmt.Println("  --fix                               Generate an automated Dockerfile hardening patch to resolve failures")
	fmt.Println("  --verbose                           Include passing-check details and expanded finding context")
	fmt.Println("  --format <console|junit|json>       Output format (default: console)")
	fmt.Println("  --output <path>                     File path to write JUnit XML or JSON report")
	fmt.Println("  --engine <auto|podman|docker>       OCI engine to use (default: auto)")
	fmt.Println("  --platform <os/arch>                Platform passed to pull (default: linux/<host arch>)")
	fmt.Println("  --image-source <auto|local|registry>  Where layers are read from (default: auto)")
	fmt.Println("  --probe-window <duration>           Tier 3 observation window W (default: 3s)")
	fmt.Println("  --cosign-key <path>                 Public key used to verify an image signature")
	fmt.Println("  --certificate-identity <identity>   Trusted keyless signer identity")
	fmt.Println("  --certificate-oidc-issuer <issuer>  Trusted keyless OIDC issuer")
	fmt.Println()
	fmt.Println("Flags for 'eval':")
	fmt.Println("  --images <file>                     File containing newline-delimited container images")
	fmt.Println("  --pack <name>                       Rule pack to run (default: cis)")
	fmt.Println("  --out-dir <dir>                     Directory to save evaluation results (default: results)")
	fmt.Println("  --engine <auto|podman|docker>       OCI engine to use (default: auto)")
	fmt.Println("  --platform <os/arch>                Platform passed to pull (default: linux/<host arch>)")
	fmt.Println("  --image-source <auto|local|registry>  Where layers are read from (default: auto)")
	fmt.Println("  --probe-window <duration>           Tier 3 observation window W (default: 3s)")
	fmt.Println("  --image-timeout <duration>          Per-image deadline (default: 5m)")
	fmt.Println("  --journal <path>                    Append-only JSONL journal (default: <out-dir>/journal.jsonl)")
	fmt.Println("  --resume                            Skip images that already have a COMPLETED journal record")
	fmt.Println("  --fail-on-findings                  Exit 1 when any FAIL or UNVERIFIED result exists")
	fmt.Printf("  --max-index-entries <n>             Filesystem index entry cap, also bounds index memory (default: %d)\n", defaultMaxIndexEntries)
	fmt.Println("                                      An image above the cap is recorded as INDEX_LIMIT with its size, not analyzed")
	fmt.Println("  --cosign-key <path>                 Public key used to verify an image signature")
	fmt.Println("  --certificate-identity <identity>   Trusted keyless signer identity")
	fmt.Println("  --certificate-oidc-issuer <issuer>  Trusted keyless OIDC issuer")
	fmt.Println()
	fmt.Println("Exit codes of 'eval': 0 all images COMPLETED, 1 findings (with --fail-on-findings), 2 usage, 3 incomplete")
}

func splitInterspersedFlags(fs *flag.FlagSet, args []string) ([]string, []string) {
	var flagArgs []string
	var positionalArgs []string
	positionalOnly := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if positionalOnly || arg == "-" || !strings.HasPrefix(arg, "-") {
			positionalArgs = append(positionalArgs, arg)
			continue
		}
		if arg == "--" {
			positionalOnly = true
			continue
		}

		flagArgs = append(flagArgs, arg)
		if strings.Contains(arg, "=") {
			continue
		}
		flagName := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if parsedFlag := fs.Lookup(flagName); parsedFlag != nil {
			if boolFlag, ok := parsedFlag.Value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
				continue
			}
		}
		if i+1 < len(args) && args[i+1] != "--" && !strings.HasPrefix(args[i+1], "-") {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return flagArgs, positionalArgs
}

// runtimeFlags are the flags shared by the test and eval commands.
type runtimeFlags struct {
	platform    *string
	imageSource *string
	probeWindow *time.Duration
}

func registerRuntimeFlags(fs *flag.FlagSet) runtimeFlags {
	return runtimeFlags{
		platform:    fs.String("platform", "", "Platform passed to pull and inspect (default: linux/<host arch>)"),
		imageSource: fs.String("image-source", "auto", "Where layers are read from (auto, local, registry)"),
		probeWindow: fs.Duration("probe-window", defaultProbeWindow, "Tier 3 observation window W"),
	}
}

// resolved validates the shared flags and returns the effective platform,
// image-source policy and probe window.
func (f runtimeFlags) resolved() (platform, imageSource string, window time.Duration, err error) {
	platform = strings.TrimSpace(*f.platform)
	if platform == "" {
		platform = defaultPlatform()
	}
	if err := validatePlatform(platform); err != nil {
		return "", "", 0, err
	}
	imageSource = strings.ToLower(strings.TrimSpace(*f.imageSource))
	switch imageSource {
	case "auto", "local", "registry":
	default:
		return "", "", 0, fmt.Errorf("invalid --image-source %q (choose auto, local or registry)", *f.imageSource)
	}
	window = *f.probeWindow
	if window < 500*time.Millisecond || window > 5*time.Minute {
		return "", "", 0, fmt.Errorf("invalid --probe-window %s (choose between 500ms and 5m)", window)
	}
	return platform, imageSource, window, nil
}

// defaultPlatform is the platform of containers on this host. Containers are
// always Linux containers, so only the architecture is taken from the host.
func defaultPlatform() string {
	return "linux/" + runtime.GOARCH
}

func validatePlatform(platform string) error {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Errorf("invalid --platform %q (expected os/arch or os/arch/variant)", platform)
	}
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("invalid --platform %q (empty component)", platform)
		}
	}
	return nil
}

func validateEngineFlag(preference string) error {
	switch preference {
	case "auto", "podman", "docker", "":
		return nil
	}
	return fmt.Errorf("invalid --engine %q (choose auto, podman or docker)", preference)
}

// reportRunEnvironment logs the detected run environment once, as one line,
// and warns loudly when the engine facts are missing: results without them
// cannot state which engine produced them. Detection never fails the run, so
// the warning is the only signal.
func reportRunEnvironment(meta spec.RunMetadata) {
	fmt.Fprintf(os.Stderr, "Environment: %s\n", runenv.DescribeHost(meta))
	var missing []string
	if meta.EngineName == "" {
		missing = append(missing, "engine name")
	}
	if meta.EngineVersion == "" {
		missing = append(missing, "engine version")
	}
	if len(missing) == 0 {
		return
	}
	const bar = "========================================================================"
	fmt.Fprintln(os.Stderr, bar)
	fmt.Fprintf(os.Stderr, "WARNING: the run metadata is missing: %s\n", strings.Join(missing, ", "))
	fmt.Fprintln(os.Stderr, "  The results will not state which container engine produced them.")
	fmt.Fprintln(os.Stderr, "  Engine probes are bounded to 2 s each; check that the engine answers")
	fmt.Fprintln(os.Stderr, "  `<engine> --version` and `<engine> info` promptly, then rerun.")
	fmt.Fprintln(os.Stderr, bar)
}

// retryPolicy returns the rate-limit retry policy and logs every retry to stderr.
func retryPolicy() retry.Policy {
	policy := retry.DefaultPolicy()
	maxRetries := policy.MaxAttempts - 1
	policy.OnRetry = func(attempt int, delay time.Duration, err error) {
		fmt.Fprintf(os.Stderr, "  [RETRY %d/%d] registry rate limit, waiting %s\n", attempt, maxRetries, delay.Round(time.Millisecond))
	}
	return policy
}

func configureSignatureVerification(r packRunner, enabled bool, policy conunit.SignatureTrustPolicy) bool {
	if !enabled {
		return true
	}
	configurer, ok := r.(interface {
		SetSignatureVerification(conunit.SignatureVerificationConfig)
	})
	if !ok {
		fmt.Fprintln(os.Stderr, "error: runner does not support signature verification configuration")
		return false
	}
	configurer.SetSignatureVerification(conunit.SignatureVerificationConfig{
		Verifier:    conunit.VerifyWithCosign,
		TrustPolicy: policy,
	})
	return true
}

func runTestCommand(args []string) int {
	return runTestCommandWithDeps(args, defaultCommandDeps())
}

func runTestCommandWithDeps(args []string, deps commandDeps) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	packName := fs.String("pack", "cis", "Rule pack: hardening (alias cis), hygiene, kube, nist, distroless, lint (alias image-lint)")
	generateFix := fs.Bool("fix", false, "Generate an automated Dockerfile hardening patch to resolve failures")
	verbose := fs.Bool("verbose", false, "Include passing-check details and expanded finding context")
	format := fs.String("format", "console", "Output format (console, junit, json)")
	outputPath := fs.String("output", "", "Optional output file path")
	enginePref := fs.String("engine", "auto", "Container engine (auto, podman, docker)")
	cosignKey := fs.String("cosign-key", "", "Public key used to verify image signatures")
	certificateIdentity := fs.String("certificate-identity", "", "Trusted keyless signer identity")
	certificateIssuer := fs.String("certificate-oidc-issuer", "", "Trusted keyless OIDC issuer")
	shared := registerRuntimeFlags(fs)
	flagArgs, posArgs := splitInterspersedFlags(fs, args)
	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid test flags: %v\n", err)
		return spec.ExitUsage
	}
	signaturePolicy, signatureConfigured, err := signaturePolicyFromFlags(*cosignKey, *certificateIdentity, *certificateIssuer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid signature configuration: %v\n", err)
		return spec.ExitUsage
	}
	platform, imageSource, window, err := shared.resolved()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return spec.ExitUsage
	}
	if err := validateEngineFlag(*enginePref); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return spec.ExitUsage
	}

	if len(posArgs) != 1 {
		fmt.Fprintln(os.Stderr, "error: missing target container image argument")
		fmt.Fprintln(os.Stderr, "Example: con-unit test alpine:latest")
		return spec.ExitUsage
	}
	targetImage := posArgs[0]
	formatName := strings.ToLower(*format)
	if formatName != "console" && formatName != "junit" && formatName != "json" {
		fmt.Fprintf(os.Stderr, "error: unsupported output format %q (choose console, junit, or json)\n", *format)
		return spec.ExitUsage
	}

	eng, err := deps.detectEngine(*enginePref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: container engine: %v\n", err)
		return spec.ExitFindings
	}

	pack, err := deps.resolvePack(*packName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: compliance pack: %v\n", err)
		return spec.ExitFindings
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultImageTimeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, "Running %s on %s with %s\n", pack.Name(), targetImage, filepath.Base(eng.BinaryPath))
	reportRunEnvironment(deps.detectRun(ctx, runenv.Options{
		Version:       version,
		EngineBinary:  eng.BinaryPath,
		Pack:          *packName,
		PackID:        pack.ID(),
		Platform:      platform,
		ImageSource:   imageSource,
		ProbeWindow:   window,
		Flags:         append([]string{"test"}, args...),
		RegistryRemap: os.Getenv("CONUNIT_REGISTRY_REMAP"),
	}))

	r := deps.newRunner(eng, runner.Options{
		Platform:        platform,
		ImageSource:     imageSource,
		ProbeWindow:     window,
		MaxIndexEntries: defaultMaxIndexEntries,
		Retry:           retryPolicy(),
	})
	if !configureSignatureVerification(r, signatureConfigured, signaturePolicy) {
		return spec.ExitUsage
	}
	res, err := r.RunPack(ctx, pack, targetImage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: test execution: %v\n", err)
		return spec.ExitFindings
	}

	// Output results
	switch formatName {
	case "console":
		reporter.PrintConsoleWithOptions(os.Stdout, res, reporter.ConsoleOptions{Verbose: *verbose})
	case "junit":
		if *outputPath == "" {
			*outputPath = "junit.xml"
		}
	case "json":
		if *outputPath == "" {
			*outputPath = "results.json"
		}
	}

	reportWriteFailed := false
	if *outputPath != "" {
		if strings.HasSuffix(*outputPath, ".xml") || formatName == "junit" {
			if err := reporter.WriteJUnitXML(*outputPath, res); err != nil {
				fmt.Fprintf(os.Stderr, "error: could not write JUnit XML: %v\n", err)
				reportWriteFailed = true
			} else {
				fmt.Fprintf(os.Stderr, "Wrote JUnit report: %s\n", *outputPath)
			}
		} else {
			if err := reporter.WriteJSON(*outputPath, res); err != nil {
				fmt.Fprintf(os.Stderr, "error: could not write JSON report: %v\n", err)
				reportWriteFailed = true
			} else {
				fmt.Fprintf(os.Stderr, "Wrote JSON report: %s\n", *outputPath)
			}
		}
	}

	if *generateFix && res.Failed > 0 {
		patch := reporter.GenerateRemediationPatch(res)
		if patch != "" {
			fmt.Print(patch)
		}
	}

	if reportWriteFailed {
		return spec.ExitFindings
	}
	if res.Failed > 0 || res.Unverified > 0 {
		return spec.ExitFindings
	}
	return spec.ExitOK
}

func readImageList(input io.Reader) ([]string, error) {
	var images []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading images list: %w", err)
	}
	return images, nil
}

func signaturePolicyFromFlags(key, identity, issuer string) (conunit.SignatureTrustPolicy, bool, error) {
	policy := conunit.SignatureTrustPolicy{
		KeyPath:             strings.TrimSpace(key),
		CertificateIdentity: strings.TrimSpace(identity),
		CertificateIssuer:   strings.TrimSpace(issuer),
	}
	configured := policy.KeyPath != "" || policy.CertificateIdentity != "" || policy.CertificateIssuer != ""
	if !configured {
		return policy, false, nil
	}
	if err := policy.Validate(); err != nil {
		return conunit.SignatureTrustPolicy{}, true, err
	}
	return policy, true, nil
}
