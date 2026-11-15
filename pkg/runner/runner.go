package runner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/acquire"
	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/retry"
	"github.com/con-unit/con-unit/pkg/spec"
)

// Options configures a Runner. The zero value selects the defaults noted on
// each field.
type Options struct {
	// Platform is the requested platform, for example linux/amd64. Empty
	// accepts whatever platform the engine resolves.
	Platform string
	// ImageSource is auto, local or registry. Empty means auto.
	ImageSource string
	// ProbeWindow is the Tier 3 observation window W. Zero selects the default.
	ProbeWindow time.Duration
	// MaxIndexEntries caps the filesystem index. Zero selects the default.
	MaxIndexEntries int
	// Retry bounds the retries for registry rate limiting. The zero value
	// disables retries.
	Retry retry.Policy
	// OnIndexed, when set, is called once for every image whose filesystem
	// was indexed. It exists so a run can log how large each image is
	// relative to the index limit.
	OnIndexed func(IndexReport)
}

// IndexReport describes one completed filesystem index.
type IndexReport struct {
	Image    string
	Source   string
	Stats    oci.IndexStats
	Duration time.Duration
}

// Runner coordinates execution of compliance packs against container images
type Runner struct {
	Engine                *engine.Engine
	SignatureVerification *conunit.SignatureVerificationConfig
	Options               Options
}

// NewRunner creates a new Runner instance
func NewRunner(eng *engine.Engine) *Runner {
	return &Runner{Engine: eng}
}

// NewRunnerWithOptions creates a Runner with explicit options.
func NewRunnerWithOptions(eng *engine.Engine, options Options) *Runner {
	return &Runner{Engine: eng, Options: options}
}

// ImageError annotates a failed image evaluation with the failing stage
// (pull, inspect, resolve or index) and, once known, the image source. Its
// message is the message of the wrapped error.
type ImageError = acquire.ImageError

func stageError(stage, source string, err error) error {
	return &acquire.ImageError{Stage: stage, ImageSource: source, Err: err}
}

// stageErrorWithImage is stageError for a failure after the image was
// acquired, so the failure record can state the identity and size of the image.
func stageErrorWithImage(stage string, acquired *acquire.Result, image string, resources spec.ResourceTelemetry, err error) error {
	return &acquire.ImageError{
		Stage:       stage,
		ImageSource: acquired.Source,
		Partial: &spec.SuiteResult{
			ImageName:    image,
			RequestedRef: image,
			ImageSource:  acquired.Source,
			ImageDigest:  acquired.RegistryDigest,
			ConfigDigest: acquired.ConfigDigest,
			Platform:     acquired.Platform,
			Resources:    resources,
		},
		Err: err,
	}
}

// ClassifyError maps an image failure to the status and reason recorded in
// the image record. It relies only on typed errors defined at the engine and
// OCI boundaries, never on error text.
func ClassifyError(err error) (string, spec.Reason) {
	var (
		engineRate    *engine.RateLimitError
		ociRate       *oci.RateLimitError
		engineMissing *engine.NotFoundError
		notInStore    *engine.ImageNotInStoreError
		ociMissing    *oci.NotFoundError
		tooLarge      *oci.IndexTooLargeError
		identity      *oci.IdentityMismatchError
		platform      *oci.PlatformMismatchError
	)
	switch {
	case err == nil:
		return spec.StatusCompleted, spec.ReasonNone
	case errors.Is(err, context.DeadlineExceeded):
		return spec.StatusTimeout, spec.ReasonDeadlineExceeded
	case errors.As(err, &tooLarge):
		return spec.StatusIndexLimit, spec.ReasonIndexTooLarge
	case errors.As(err, &engineRate), errors.As(err, &ociRate):
		return spec.StatusRateLimited, spec.ReasonRegistryThrottled
	case errors.As(err, &engineMissing), errors.As(err, &ociMissing), errors.As(err, &notInStore):
		return spec.StatusUnavailable, spec.ReasonManifestNotFound
	case errors.As(err, &identity):
		return spec.StatusExecutionError, spec.ReasonIdentityMismatch
	case errors.As(err, &platform):
		return spec.StatusExecutionError, spec.ReasonPlatformMismatch
	default:
		return spec.StatusExecutionError, spec.ReasonNone
	}
}

// SetSignatureVerification configures the trust policy used by signature assertions.
func (r *Runner) SetSignatureVerification(config conunit.SignatureVerificationConfig) {
	r.SignatureVerification = &config
}

// ResolvePack returns the standard RulePack associated with the given name
func ResolvePack(name string) (conunit.RulePack, error) {
	cleanName := strings.ToLower(strings.TrimSpace(name))
	cleanName = strings.TrimPrefix(cleanName, "pack=")
	cleanName = strings.TrimPrefix(cleanName, "pack:")
	cleanName = strings.Trim(cleanName, `"'`)
	switch cleanName {
	case "hardening", "cis-informed", "cis", "cis-docker", "cisbenchmark":
		return conunit.CISBenchmark(), nil
	case "hygiene", "prod", "production", "default", "":
		return conunit.ProductionHygiene(), nil
	case "kube", "k8s", "kubernetes", "kubehardened":
		return conunit.KubeHardened(), nil
	case "nist", "nist-800-190":
		return conunit.NIST_SP_800_190(), nil
	case "distro", "distroless":
		return conunit.DistrolessHardening(), nil
	case "lint", "image-lint":
		return conunit.ImageLint(), nil
	default:
		return nil, fmt.Errorf("unknown compliance pack '%s' (available: hardening (alias cis), hygiene, kube, nist, distroless, lint (alias image-lint))", name)
	}
}

// RunPack executes a compliance RulePack against a container image
func (r *Runner) RunPack(ctx context.Context, pack conunit.RulePack, image string) (*spec.SuiteResult, error) {
	start := time.Now()
	startUsage := readProcessUsage()
	var startMem runtime.MemStats
	runtime.ReadMemStats(&startMem)

	// 1 to 3. Make the image available, read it from the selected source and
	// verify its identity (see package acquire for the exact semantics).
	policy, err := acquire.ParsePolicy(r.Options.ImageSource)
	if err != nil {
		return nil, stageError("pull", "", err)
	}
	acquired, err := acquire.Acquire(ctx, r.Engine, image, acquire.Options{
		Platform: r.Options.Platform,
		Policy:   policy,
		Retry:    r.Options.Retry,
	})
	if err != nil {
		return nil, err
	}
	defer acquired.Close()
	reader := acquired.Reader
	inspect := acquired.Inspect
	source := acquired.Source
	pullDuration := acquired.PullDuration
	inspectDuration := acquired.InspectDuration
	resolveDuration := acquired.ResolveDuration

	var layerCount int
	var compressedBytes int64
	if layers, layersErr := reader.Image.Layers(); layersErr == nil {
		layerCount = len(layers)
		// Layer.Size() is the compressed blob size only when the source is a
		// registry. For archives it would compress every layer to find out, so
		// the figure is left unknown rather than computed at a cost.
		if source == spec.SourceRegistry {
			for _, l := range layers {
				if sz, sizeErr := l.Size(); sizeErr == nil {
					compressedBytes += sz
				}
			}
		}
	}

	streamStart := time.Now()
	maxEntries := r.Options.MaxIndexEntries
	if maxEntries <= 0 {
		maxEntries = oci.MaxIndexedFiles
	}
	ociIndex, err := reader.StreamAndIndexFilesystemLimit(maxEntries)
	if err != nil {
		// Whatever was learned about the image before indexing stopped goes
		// on the failure record, so an image excluded by the index limit is
		// reported with its identity and the size read so far.
		resources := spec.ResourceTelemetry{LayerCount: layerCount, CompressedBytes: compressedBytes}
		detail := ""
		var tooLarge *oci.IndexTooLargeError
		if errors.As(err, &tooLarge) {
			// For an excluded image the entry count is the count when the limit
			// tripped, a lower bound on the size of the image.
			resources.UncompressedBytes = tooLarge.ScannedBytes
			resources.IndexedEntries = tooLarge.Entries
			if inspect != nil && inspect.Size > 0 {
				detail = fmt.Sprintf("; engine-reported image size %s", oci.FormatBytes(inspect.Size))
			}
		}
		return nil, stageErrorWithImage("index", acquired, image, resources,
			fmt.Errorf("failed indexing OCI filesystem for image '%s': %w%s", image, err, detail))
	}
	streamDuration := time.Since(streamStart)
	if r.Options.OnIndexed != nil {
		r.Options.OnIndexed(IndexReport{Image: image, Source: source, Stats: ociIndex.Stats, Duration: streamDuration})
	}

	probeWindow := r.Options.ProbeWindow
	if probeWindow <= 0 {
		probeWindow = engine.DefaultProbeWindow
	}
	// The requested reference is evidence for SPEC-13. A local archive has no
	// image reference, so none is recorded for it.
	requestedRef := image
	if source == spec.SourceTarball {
		requestedRef = ""
	}
	container := &conunit.Container{
		Context:               ctx,
		Image:                 acquired.EngineImageID,
		RequestedRef:          requestedRef,
		ImmutableImageRef:     acquired.ImmutableRef,
		ImageDigest:           acquired.RegistryDigest,
		ConfigDigest:          acquired.ConfigDigest,
		Platform:              acquired.Platform,
		SignatureVerification: r.SignatureVerification,
		Inspect:               inspect,
		Engine:                r.Engine,
		OCIIndex:              ociIndex,
		ProbeWindow:           probeWindow,
	}

	// 4. Apply the compliance rule pack. The Tier 3 baseline of this image is
	// computed once inside the container and reused by every treatment.
	pack.Apply(container)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// The deadline lapsed while the pack ran, so the remaining results are
		// not evidence about the image. The image is recorded as timed out
		// instead of as completed with a trail of UNVERIFIED results.
		return nil, stageErrorWithImage("evaluate", acquired, image,
			spec.ResourceTelemetry{LayerCount: layerCount, CompressedBytes: compressedBytes, UncompressedBytes: ociIndex.Stats.ScannedBytes, IndexedEntries: ociIndex.Stats.Entries},
			fmt.Errorf("evaluation of image '%s' did not finish: %w", image, ctxErr))
	}
	if len(container.Results) == 0 {
		container.RecordUnverified(
			"PACK-EMPTY",
			"Rule Pack Produced No Assertions",
			spec.TierSpec,
			0,
			fmt.Sprintf("Rule pack %q produced no assertion results", pack.Name()),
			"Include at least one active assertion in the rule pack",
			"",
		)
	}

	passedCount := 0
	failedCount := 0
	unverifiedCount := 0
	var tier1Dur, tier2Dur, tier3Dur, tier4Dur time.Duration
	for _, res := range container.Results {
		switch res.Tier {
		case spec.TierSpec:
			tier1Dur += res.Duration
		case spec.TierFilesystem:
			tier2Dur += res.Duration
		case spec.TierContract:
			tier3Dur += res.Duration
		case spec.TierSupplyChain:
			tier4Dur += res.Duration
		}

		switch res.EffectiveOutcome() {
		case spec.OutcomePass:
			passedCount++
		case spec.OutcomeUnverified:
			unverifiedCount++
		default:
			failedCount++
		}
	}

	// Every phase timer has stopped. The elapsed time is fixed here so that the
	// forced collection below, which only serves the live heap figure, is not
	// part of the evaluation time.
	elapsed := time.Since(start)
	selfCPU, childCPU := readProcessUsage().since(startUsage)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	deltaAlloc := float64(0)
	if mem.TotalAlloc >= startMem.TotalAlloc {
		deltaAlloc = float64(mem.TotalAlloc-startMem.TotalAlloc) / bytesPerMiB
	}
	resources := spec.ResourceTelemetry{
		AllocMB:      float64(mem.Alloc) / bytesPerMiB,
		TotalAllocMB: deltaAlloc,
		SysMB:        float64(mem.Sys) / bytesPerMiB,
		// PeakRSSMB is a ceiling of the whole process, not a figure of this
		// image (see processPeakRSSMB). Consumers use only its batch maximum.
		PeakRSSMB:         processPeakRSSMB(),
		NumGC:             mem.NumGC - startMem.NumGC,
		LayerCount:        layerCount,
		CompressedBytes:   compressedBytes,
		UncompressedBytes: ociIndex.Stats.ScannedBytes,
		IndexedEntries:    ociIndex.Stats.Entries,
		SelfCPUSeconds:    selfCPU,
		ChildCPUSeconds:   childCPU,
	}
	// The index and the results are still reachable here, so the live heap
	// includes the filesystem index of this image, the dominant allocation.
	resources.LiveHeapMB = liveHeapMB()
	runtime.KeepAlive(container)

	phases := spec.PhaseBreakdown{
		PullDuration:    pullDuration,
		InspectDuration: inspectDuration,
		ResolveDuration: resolveDuration,
		StreamDuration:  streamDuration,
		Tier1Duration:   tier1Dur,
		Tier2Duration:   tier2Dur,
		Tier3Duration:   tier3Dur,
		Tier4Duration:   tier4Dur,
		ProbeWindow:     probeWindow,
	}

	return &spec.SuiteResult{
		ImageName:    image,
		RequestedRef: image,
		ImageSource:  source,
		ImageDigest:  acquired.RegistryDigest,
		ConfigDigest: acquired.ConfigDigest,
		Platform:     acquired.Platform,
		SuiteName:    pack.Name(),
		Timestamp:    start,
		Duration:     elapsed,
		Total:        len(container.Results),
		Passed:       passedCount,
		Failed:       failedCount,
		Unverified:   unverifiedCount,
		Phases:       phases,
		Resources:    resources,
		Results:      container.Results,
	}, nil
}
