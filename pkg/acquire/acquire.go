// Package acquire gets an image into a state ConUnit can analyze and states,
// without overclaiming, where its content came from and which identity was
// verified.
//
// Two things must be true after Acquire succeeds. First, the engine holds the
// image (Tier 3 probes run from the engine store). Second, the layer content
// used by Tiers 1, 2 and 4 is the content of that same image, read from the
// source the policy selects:
//
//   - local: the image is exported from the engine store with `save` and read
//     from the temporary archive. The engine never pulls in this mode, so the
//     image must already be in the store.
//   - auto: like local, but an image that is absent from the store is first
//     pulled by the engine (through its own registry configuration, for
//     example a mirror remap). The layers are then read from the store.
//   - registry: the layers are read directly from the registry with ConUnit's
//     own client. The engine still pulls the image when it is absent, because
//     Tier 3 needs it.
//
// A failure to export from the store is an error, never a silent fallback to
// a registry download, so the recorded source is always the real one.
package acquire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/retry"
	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Policy selects where layer content is read from.
type Policy string

const (
	PolicyAuto     Policy = "auto"
	PolicyLocal    Policy = "local"
	PolicyRegistry Policy = "registry"
)

// ParsePolicy converts the --image-source flag value. Empty means auto.
func ParsePolicy(value string) (Policy, error) {
	switch Policy(strings.ToLower(strings.TrimSpace(value))) {
	case "", PolicyAuto:
		return PolicyAuto, nil
	case PolicyLocal:
		return PolicyLocal, nil
	case PolicyRegistry:
		return PolicyRegistry, nil
	}
	return "", fmt.Errorf("unknown image source %q (choose auto, local or registry)", value)
}

// Options configures Acquire.
type Options struct {
	// Platform is the requested platform (os/arch[/variant]). Empty accepts
	// the platform the engine resolves.
	Platform string
	Policy   Policy
	// Retry bounds retries of rate-limited pulls and registry reads.
	Retry retry.Policy
}

// ImageError annotates a failure with the stage that failed and, when it was
// already known, the image source. Its message is the wrapped message.
type ImageError struct {
	Stage       string // pull, inspect, resolve, index, evaluate
	ImageSource string // spec.Source* value or empty
	// Partial holds what was already established about the image when the
	// stage failed: its identity (digests, platform, source) and the size
	// figures read so far. It lets the failure record state which image was
	// excluded and how large it was. Nil when the failure came before the
	// image was identified.
	Partial *spec.SuiteResult
	Err     error
}

func (e *ImageError) Error() string { return e.Err.Error() }
func (e *ImageError) Unwrap() error { return e.Err }

func stageError(stage, source string, err error) error {
	return &ImageError{Stage: stage, ImageSource: source, Err: err}
}

// Result is an acquired image. Close it to release temporary files.
type Result struct {
	Reader  *oci.ImageReader
	Inspect *engine.ImageInspect
	// EngineImageID is "sha256:<hex>" of the image as the engine names it. It
	// is what probe containers run, so the probe cannot drift to another image.
	EngineImageID string
	// ConfigDigest is the digest of the OCI config that was read.
	ConfigDigest string
	// RegistryDigest is the registry digest of the requested image: the pinned
	// digest of a digest-pinned request after verification against the
	// engine's RepoDigests, otherwise a digest the engine or registry
	// reported. Empty when none is known. It is never computed from a local
	// archive.
	RegistryDigest string
	// ImmutableRef is repository@RegistryDigest, empty when RegistryDigest is.
	ImmutableRef string
	// Platform is the os/arch[/variant] of the image config.
	Platform string
	// Source is spec.SourceLocalStore, spec.SourceRegistry or spec.SourceTarball.
	Source string
	// Pulled is true when this call had to pull the image into the engine
	// store, so the caller knows it owns the image and may remove it again.
	Pulled bool

	PullDuration    time.Duration
	InspectDuration time.Duration
	ResolveDuration time.Duration
}

// Close releases the temporary archive, if any.
func (r *Result) Close() {
	if r != nil && r.Reader != nil {
		r.Reader.Close()
	}
}

func isRateLimited(err error) bool {
	var engineRate *engine.RateLimitError
	var ociRate *oci.RateLimitError
	return errors.As(err, &engineRate) || errors.As(err, &ociRate)
}

// Acquire makes the image available and verifies its identity.
func Acquire(ctx context.Context, eng *engine.Engine, image string, opts Options) (*Result, error) {
	policy := opts.Policy
	if policy == "" {
		policy = PolicyAuto
	}
	tarball := oci.IsTarballReference(image)
	res := &Result{}

	// A malformed reference, including one that would be read as an engine
	// flag, is rejected before the engine is contacted at all.
	if !tarball {
		if _, err := name.ParseReference(image); err != nil {
			return nil, stageError("resolve", "", fmt.Errorf("failed resolving OCI image '%s': invalid image reference: %w", image, err))
		}
	}

	// 1. The engine must hold the image.
	pullStart := time.Now()
	if policy == PolicyLocal && !tarball {
		present, err := eng.HasImage(ctx, image)
		if err != nil {
			return nil, stageError("pull", "", fmt.Errorf("failed ensuring image '%s': %w", image, err))
		}
		if !present {
			return nil, stageError("pull", "", fmt.Errorf("failed ensuring image '%s' with --image-source local: %w", image, &engine.ImageNotInStoreError{Image: image}))
		}
	} else {
		err := retry.Do(ctx, opts.Retry, isRateLimited, func() error {
			pulled, ensureErr := eng.EnsureImageForPlatform(ctx, image, opts.Platform)
			if ensureErr == nil && pulled {
				res.Pulled = true
			}
			return ensureErr
		})
		if err != nil {
			return nil, stageError("pull", "", fmt.Errorf("failed ensuring image '%s': %w", image, err))
		}
	}
	res.PullDuration = time.Since(pullStart)

	// 2. Inspect and check the platform the engine resolved.
	inspectStart := time.Now()
	inspect, err := eng.InspectImageForPlatform(ctx, image, opts.Platform)
	if err != nil {
		return nil, stageError("inspect", "", fmt.Errorf("failed inspecting image '%s': %w", image, err))
	}
	if inspect == nil {
		return nil, stageError("inspect", "", fmt.Errorf("failed inspecting image '%s': engine returned no inspection data", image))
	}
	if strings.TrimSpace(inspect.Os) == "" || strings.TrimSpace(inspect.Architecture) == "" {
		return nil, stageError("inspect", "", fmt.Errorf("failed inspecting image '%s': engine did not identify the resolved OS and architecture", image))
	}
	if strings.TrimSpace(inspect.ID) == "" {
		return nil, stageError("inspect", "", fmt.Errorf("failed inspecting image '%s': engine did not provide an immutable image config ID", image))
	}
	if err := checkRequestedPlatform(image, opts.Platform, inspect); err != nil {
		return nil, stageError("inspect", "", err)
	}
	platform := v1.Platform{OS: inspect.Os, Architecture: inspect.Architecture, Variant: inspect.Variant}
	res.Inspect = inspect
	res.InspectDuration = time.Since(inspectStart)

	// 3. Read the layer content from the selected source.
	resolveStart := time.Now()
	var reader *oci.ImageReader
	switch {
	case tarball:
		reader, err = oci.ResolveImageForPlatform(ctx, image, platform)
	case policy == PolicyRegistry:
		err = retry.Do(ctx, opts.Retry, isRateLimited, func() error {
			var resolveErr error
			reader, resolveErr = oci.ResolveFromRegistry(ctx, image, platform)
			return resolveErr
		})
	default:
		reader, err = readFromEngineStore(ctx, eng, inspect, platform)
	}
	source := ""
	switch {
	case tarball:
		source = spec.SourceTarball
	case policy == PolicyRegistry:
		source = spec.SourceRegistry
	default:
		source = spec.SourceLocalStore
	}
	if err != nil {
		return nil, stageError("resolve", source, fmt.Errorf("failed resolving OCI image '%s': %w", image, err))
	}
	res.Reader = reader
	res.Source = reader.Source
	fail := func(err error) (*Result, error) {
		res.Close()
		return nil, stageError("resolve", source, err)
	}

	identity, err := reader.Identity()
	if err != nil {
		return fail(fmt.Errorf("failed identifying resolved OCI image '%s': %w", image, err))
	}
	res.ConfigDigest = identity.ConfigDigest
	res.Platform = identity.Platform

	// 4. Identity: engine image, config that was read, registry digest.
	registryDigest, err := verifyIdentity(image, inspect, identity, reader.Source)
	if err != nil {
		return fail(err)
	}
	res.RegistryDigest = registryDigest
	res.EngineImageID = inspect.NormalizedID()
	if registryDigest != "" {
		if ref, parseErr := name.ParseReference(image); parseErr == nil {
			res.ImmutableRef = ref.Context().Digest(registryDigest).String()
		}
	}
	res.ResolveDuration = time.Since(resolveStart)
	return res, nil
}

// checkRequestedPlatform verifies that the engine resolved the platform that
// was requested. OS and architecture must match; a variant is compared only
// when both sides state one.
func checkRequestedPlatform(image, requested string, inspect *engine.ImageInspect) error {
	if requested == "" {
		return nil
	}
	parts := strings.Split(requested, "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid requested platform %q", requested)
	}
	mismatch := func(detail string) error {
		return &oci.PlatformMismatchError{Ref: image, Detail: detail}
	}
	if !strings.EqualFold(parts[0], inspect.Os) || !strings.EqualFold(parts[1], inspect.Architecture) {
		return mismatch(fmt.Sprintf("requested %s but the engine resolved %s/%s", requested, inspect.Os, inspect.Architecture))
	}
	if len(parts) > 2 && parts[2] != "" && inspect.Variant != "" && !strings.EqualFold(parts[2], inspect.Variant) {
		return mismatch(fmt.Sprintf("requested variant %s but the engine resolved %s", parts[2], inspect.Variant))
	}
	return nil
}

// readFromEngineStore exports the image from the engine store into a private
// temporary directory and reads it from there. The export is addressed by the
// image ID, which is unambiguous, and the config digest is verified later.
func readFromEngineStore(ctx context.Context, eng *engine.Engine, inspect *engine.ImageInspect, platform v1.Platform) (*oci.ImageReader, error) {
	dir, err := os.MkdirTemp("", "conunit-save-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating a temporary directory for the image export: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	archive := filepath.Join(dir, "image.tar")
	if err := eng.SaveImage(ctx, inspect.ID, archive); err != nil {
		cleanup()
		return nil, err
	}
	reader, err := oci.ResolveFromArchive(archive, platform)
	if err != nil {
		cleanup()
		return nil, err
	}
	reader.OnClose(cleanup)
	return reader, nil
}

// verifyIdentity checks that the content that was read is the image the
// engine holds and, for a digest-pinned request, that the engine holds the
// pinned registry digest. It returns the registry digest to report.
func verifyIdentity(image string, inspect *engine.ImageInspect, identity oci.ImageIdentity, source string) (string, error) {
	mismatch := func(detail string) error {
		return &oci.IdentityMismatchError{Ref: image, Detail: detail}
	}

	engineID := inspect.NormalizedID()
	configDigest := engine.NormalizeDigest(identity.ConfigDigest)
	repoDigests := inspect.RepoDigestSet()
	_, engineIDIsRepoDigest := repoDigests[engineID]
	switch {
	case engineID == configDigest:
	case source != spec.SourceTarball && engineIDIsRepoDigest:
		// Docker with the containerd image store names an image by its target
		// manifest or index digest instead of the config digest. That digest is
		// content-addressed and listed in RepoDigests, so it identifies the
		// image just as well.
	case identity.ManifestDigest != "" && engineID == engine.NormalizeDigest(identity.ManifestDigest):
		// The same containerd-store form, matched against the manifest read
		// from the registry.
	default:
		return "", mismatch(fmt.Sprintf("engine config digest %s differs from OCI config digest %s", engineID, configDigest))
	}

	if source == spec.SourceTarball {
		// A tarball was never fetched from a registry. No registry digest is
		// claimed for it.
		return "", nil
	}

	ref, err := name.ParseReference(image)
	if err != nil {
		return "", nil
	}
	if pinned, ok := ref.(name.Digest); ok {
		want := engine.NormalizeDigest(pinned.DigestStr())
		if len(repoDigests) == 0 {
			return "", mismatch(fmt.Sprintf("the engine reports no RepoDigests for the image, so the pinned digest %s cannot be verified", want))
		}
		if _, ok := repoDigests[want]; !ok {
			return "", mismatch(fmt.Sprintf("the engine's RepoDigests %s do not contain the pinned digest %s", joinDigests(repoDigests), want))
		}
		return want, nil
	}

	// Not pinned: report a digest only when a source of truth names exactly
	// one, never one computed from an archive.
	if identity.ManifestDigest != "" {
		return identity.ManifestDigest, nil
	}
	candidates := repoDigestsForRepository(inspect, ref)
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	return "", nil
}

// repoDigestsForRepository returns the distinct digests the engine records
// for the repository of ref. Repository names are compared in canonical form,
// so docker.io/library/alpine and index.docker.io/library/alpine match.
func repoDigestsForRepository(inspect *engine.ImageInspect, ref name.Reference) []string {
	seen := map[string]struct{}{}
	for _, entry := range inspect.RepoDigests {
		entryRef, err := name.ParseReference(strings.TrimSpace(entry))
		if err != nil {
			continue
		}
		digest, ok := entryRef.(name.Digest)
		if !ok || entryRef.Context().Name() != ref.Context().Name() {
			continue
		}
		seen[engine.NormalizeDigest(digest.DigestStr())] = struct{}{}
	}
	return sortedDigests(seen)
}

func sortedDigests(set map[string]struct{}) []string {
	digests := make([]string, 0, len(set))
	for digest := range set {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return digests
}

func joinDigests(set map[string]struct{}) string {
	return "[" + strings.Join(sortedDigests(set), ", ") + "]"
}
