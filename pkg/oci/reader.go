package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// HistoryEntry is one entry of the OCI image history. EmptyLayer is true for
// instructions that changed only metadata and produced no filesystem layer.
type HistoryEntry struct {
	CreatedBy  string
	EmptyLayer bool
}

// FilesystemIndex represents the in-memory reconstructed filesystem state of an OCI image
type FilesystemIndex struct {
	Paths                 map[string]bool
	SuidMap               map[string]int64
	WorldWritableFiles    map[string]int64
	PrivateKeyFiles       map[string]string
	EmptyPasswordAccounts []string
	NonRootSystemBinaries []string
	// History is the image history with the EmptyLayer flag. When it is empty,
	// HistoryEntries (instruction text only) is used and every entry is taken
	// to have produced a layer.
	History                 []HistoryEntry
	HistoryEntries          []string
	HistoryEvidenceIssue    string
	PasswdEvidenceIssue     string
	AccountEvidenceIssue    string
	PrivateKeyEvidenceIssue string
	// PrivateKeyIssues holds the evidence issue per key-file candidate path, so
	// that issues under fixture-like locations can be told apart.
	PrivateKeyIssues map[string]string
	PasswdUIDs       map[string][]uint32
	// GroupGIDs maps a group name to the GIDs of its records in the final
	// /etc/group (FS-10). GroupEvidenceIssue is set when that file is missing,
	// not a regular file, oversized or malformed. It is separate from
	// AccountEvidenceIssue, which only covers /etc/passwd and /etc/shadow.
	GroupGIDs          map[string][]uint32
	GroupEvidenceIssue string
	// Dirs holds the directory entries of the final view. A path of Paths that
	// is not in Dirs is a file, a link or another non-directory entry. An index
	// built by hand may leave it nil, which means that the types are unknown.
	Dirs map[string]struct{}
	// EmptyFiles holds the regular files of the final view that have zero
	// bytes, such as the lock file apt creates under /var/cache/apt/archives.
	// A nil map means that no such file is known.
	EmptyFiles map[string]struct{}
	// UnresolvedHardLinks lists the hard-link entries of the final view whose
	// target is not a file of the same layer, sorted. Their mode and owner
	// cannot be read, so the mode and ownership checks cannot rule them out.
	// UnresolvedHardLinkReasons holds the reason per listed path.
	// HardLinkEvidence turns them into an evidence issue.
	UnresolvedHardLinks       []string
	UnresolvedHardLinkReasons map[string]string
	// Stats is the size of the index, filled by the indexer.
	Stats IndexStats
}

// GetEmptyPasswordAccounts returns accounts in /etc/shadow with blank password hashes (FS-08)
func (fi *FilesystemIndex) GetEmptyPasswordAccounts() []string {
	return fi.EmptyPasswordAccounts
}

// EmptyPasswordAccountsEvidence returns findings and an error when the final
// passwd/shadow account files could not be completely inspected.
func (fi *FilesystemIndex) EmptyPasswordAccountsEvidence() ([]string, error) {
	if fi.AccountEvidenceIssue != "" {
		return fi.EmptyPasswordAccounts, fmt.Errorf("%s", fi.AccountEvidenceIssue)
	}
	return fi.EmptyPasswordAccounts, nil
}

// ResolveUserUID resolves an image-config user to its numeric UID using the
// final image /etc/passwd contents.
func (fi *FilesystemIndex) ResolveUserUID(user string) (uint32, error) {
	username, _, _ := strings.Cut(strings.TrimSpace(user), ":")
	if username == "" {
		return 0, fmt.Errorf("configured user is empty")
	}
	if uid, err := strconv.ParseUint(username, 10, 32); err == nil {
		return uint32(uid), nil
	}
	if fi.PasswdEvidenceIssue != "" {
		return 0, fmt.Errorf("%s", fi.PasswdEvidenceIssue)
	}
	matches := fi.PasswdUIDs[username]
	if len(matches) == 0 {
		return 0, fmt.Errorf("user %q is not present in the final image /etc/passwd", username)
	}
	if len(matches) != 1 {
		return 0, fmt.Errorf("user %q has %d /etc/passwd entries", username, len(matches))
	}
	return matches[0], nil
}

// PrivateKeyEvidence returns detected paths and an error when a recognized
// key-file candidate was truncated or used an unsupported encoding.
func (fi *FilesystemIndex) PrivateKeyEvidence() ([]string, error) {
	if fi.PrivateKeyEvidenceIssue != "" {
		return fi.GetPrivateKeyFiles(), fmt.Errorf("%s", fi.PrivateKeyEvidenceIssue)
	}
	return fi.GetPrivateKeyFiles(), nil
}

// HardLinkEvidence returns an error when a hard-link entry of the final view
// could not be resolved to a file of its layer, so that its mode and owner are
// unknown and a finding behind it cannot be excluded. With path prefixes only
// the links below one of them count (FS-09 reads four system directories);
// without prefixes every unresolved link counts (FS-04, FS-05).
func (fi *FilesystemIndex) HardLinkEvidence(prefixes ...string) error {
	var scoped []string
	for _, linkPath := range fi.UnresolvedHardLinks {
		if len(prefixes) == 0 || hasAnyPrefix(linkPath, prefixes) {
			scoped = append(scoped, linkPath)
		}
	}
	if len(scoped) == 0 {
		return nil
	}
	return fmt.Errorf("%s", unresolvedLinkIssue(scoped, fi.UnresolvedHardLinkReasons))
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// GetNonRootSystemBinaries returns system binaries in /bin or /usr/bin owned by non-root UIDs (FS-09)
func (fi *FilesystemIndex) GetNonRootSystemBinaries() []string {
	return fi.NonRootSystemBinaries
}

func (fi *FilesystemIndex) historyEntries() []HistoryEntry {
	if len(fi.History) > 0 {
		return fi.History
	}
	entries := make([]HistoryEntry, 0, len(fi.HistoryEntries))
	for _, createdBy := range fi.HistoryEntries {
		entries = append(entries, HistoryEntry{CreatedBy: createdBy})
	}
	return entries
}

// historyInstruction strips the shell wrapper that legacy builders put around
// metadata instructions, leaving the Dockerfile instruction text.
func historyInstruction(createdBy string) string {
	instruction := strings.TrimSpace(createdBy)
	instruction = strings.TrimPrefix(instruction, "/bin/sh -c #(nop)")
	return strings.TrimSpace(instruction)
}

var rootfsArchiveName = regexp.MustCompile(`^[^/:\s]+\.(?:tar|tgz|tar\.[A-Za-z0-9]+)$`)

// isBaseRootfsImport recognizes the history entry that imports a base image
// root filesystem, in both builder generations:
//
//	legacy:   ADD file:<digest> in /
//	BuildKit: ADD <name>.tar* / # buildkit   (for example alpine-minirootfs-3.24.4-aarch64.tar.gz)
//
// The destination must be the filesystem root and the source a bare local
// file name or a builder generated file reference, never a URL.
func isBaseRootfsImport(instruction string) bool {
	rest, ok := strings.CutPrefix(instruction, "ADD ")
	if !ok {
		return false
	}
	rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), "# buildkit"))
	if strings.Contains(rest, "://") {
		return false
	}
	fields := strings.Fields(rest)
	if len(fields) == 3 && fields[1] == "in" && fields[2] == "/" {
		return strings.HasPrefix(fields[0], "file:") && len(fields[0]) > len("file:")
	}
	if len(fields) == 2 && fields[1] == "/" {
		return rootfsArchiveName.MatchString(fields[0])
	}
	return false
}

// GetAddInstructions inspects the image history for ADD instructions (SPEC-07).
// Only the first layer-producing history entry can be the base image rootfs
// import, and it is exempt only when it is a rootfs-style ADD. Every later ADD,
// and every ADD from a URL or to a path other than the root, is reported.
func (fi *FilesystemIndex) GetAddInstructions() []string {
	var addViolations []string
	firstLayerSeen := false
	for _, entry := range fi.historyEntries() {
		instruction := historyInstruction(entry.CreatedBy)
		isAdd := strings.HasPrefix(instruction, "ADD ")
		exempt := false
		if !entry.EmptyLayer && !firstLayerSeen {
			firstLayerSeen = true
			exempt = isAdd && isBaseRootfsImport(instruction)
		}
		if isAdd && !exempt {
			addViolations = append(addViolations, instruction)
		}
	}
	return addViolations
}

// AddInstructionEvidence reports observed ADD instructions only when OCI
// history contains usable evidence.
func (fi *FilesystemIndex) AddInstructionEvidence() ([]string, error) {
	if fi.HistoryEvidenceIssue != "" {
		return fi.GetAddInstructions(), fmt.Errorf("%s", fi.HistoryEvidenceIssue)
	}
	return fi.GetAddInstructions(), nil
}

// HasPath checks whether a normalized path exists in the image filesystem
func (fi *FilesystemIndex) HasPath(targetPath string) bool {
	norm := normalizePath(targetPath)
	return fi.Paths[norm]
}

// HasContentAt reports whether the path holds something in the final view. A
// file, a link or any other non-directory entry holds content, even a file of
// zero bytes, because the path itself is then the finding (an empty .env is
// still a .env). A directory holds content only when an entry that carries
// something lies below it at any depth. A directory entry does not, and a
// regular file of zero bytes does not either. An empty directory, or one that
// has only empty directories and empty files below it, is therefore empty:
// base images ship such directories (for example /var/cache/apk), and apt
// leaves an empty lock file under /var/cache/apt/archives after every run.
// Neither is a package cache. An index built by hand without Dirs does not
// know which paths are directories, so every existing path counts.
func (fi *FilesystemIndex) HasContentAt(targetPath string) bool {
	norm := normalizePath(targetPath)
	if !fi.Paths[norm] {
		return false
	}
	if fi.Dirs == nil {
		return true
	}
	if _, isDir := fi.Dirs[norm]; !isDir {
		return true
	}
	prefix := strings.TrimSuffix(norm, "/") + "/"
	for p := range fi.Paths {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		if _, isDir := fi.Dirs[p]; isDir {
			continue
		}
		if _, isEmpty := fi.EmptyFiles[p]; isEmpty {
			continue
		}
		return true
	}
	return false
}

// HasBinary checks whether an executable exists under standard binary locations (/bin, /usr/bin, /usr/local/bin)
func (fi *FilesystemIndex) HasBinary(binName string) bool {
	locations := []string{
		"/bin/" + binName,
		"/usr/bin/" + binName,
		"/usr/local/bin/" + binName,
		"/sbin/" + binName,
		"/usr/sbin/" + binName,
	}
	for _, loc := range locations {
		if fi.HasPath(loc) {
			return true
		}
	}
	return false
}

// GetSuidBinaries returns all paths possessing SUID or SGID permission bits, sorted
func (fi *FilesystemIndex) GetSuidBinaries() []string {
	var suids []string
	for p := range fi.SuidMap {
		suids = append(suids, p)
	}
	sort.Strings(suids)
	return suids
}

// GetWorldWritableFiles returns all regular files that are world-writable (mode & 0002 != 0), sorted
func (fi *FilesystemIndex) GetWorldWritableFiles() []string {
	var files []string
	for p := range fi.WorldWritableFiles {
		files = append(files, p)
	}
	sort.Strings(files)
	return files
}

// GetPrivateKeyFiles returns all identified secret/private key files, sorted
func (fi *FilesystemIndex) GetPrivateKeyFiles() []string {
	var keys []string
	for p := range fi.PrivateKeyFiles {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	return keys
}

// fixtureComponents are the path components that mark test fixtures, sample
// data and examples. Findings below such a component are fixture candidates.
var fixtureComponents = map[string]struct{}{
	"testdata": {}, "test": {}, "tests": {},
	"fixtures": {}, "fixture": {},
	"examples": {}, "example": {},
}

func pathComponents(p string) []string {
	trimmed := strings.Trim(normalizePath(p), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// IsFixtureLikePath reports whether a finding sits in a fixture-like location:
// any path component in {testdata, test, tests, fixtures, fixture, examples,
// example}, or a Debian snakeoil key or certificate (ssl-cert-snakeoil.*).
// Components are compared whole, never as substrings.
func IsFixtureLikePath(p string) bool {
	components := pathComponents(p)
	if len(components) == 0 {
		return false
	}
	if matched, _ := path.Match("ssl-cert-snakeoil.*", components[len(components)-1]); matched {
		return true
	}
	for _, component := range components {
		if _, ok := fixtureComponents[strings.ToLower(component)]; ok {
			return true
		}
	}
	return false
}

func splitFixturePaths(paths []string) (findings, fixtureCandidates []string) {
	for _, p := range paths {
		if IsFixtureLikePath(p) {
			fixtureCandidates = append(fixtureCandidates, p)
		} else {
			findings = append(findings, p)
		}
	}
	sort.Strings(findings)
	sort.Strings(fixtureCandidates)
	return findings, fixtureCandidates
}

// PrivateKeyScan is the outcome of the private-key scan (FS-06).
type PrivateKeyScan struct {
	// Findings are private-key files outside fixture-like locations, sorted.
	// Only they can make FS-06 fail.
	Findings []string
	// FixtureCandidates are private-key files under fixture-like locations,
	// sorted and counted separately.
	FixtureCandidates []string
	// Issues are evidence problems (unsupported encoding, truncated scan) for
	// key-file candidates outside fixture-like locations, sorted.
	Issues []string
}

// ScanPrivateKeys classifies the detected private-key files and the evidence
// issues by location.
func (fi *FilesystemIndex) ScanPrivateKeys() PrivateKeyScan {
	scan := PrivateKeyScan{}
	scan.Findings, scan.FixtureCandidates = splitFixturePaths(fi.GetPrivateKeyFiles())
	if len(fi.PrivateKeyIssues) > 0 {
		for issuePath, issue := range fi.PrivateKeyIssues {
			if !IsFixtureLikePath(issuePath) {
				scan.Issues = append(scan.Issues, issue)
			}
		}
		sort.Strings(scan.Issues)
	} else if fi.PrivateKeyEvidenceIssue != "" {
		scan.Issues = []string{fi.PrivateKeyEvidenceIssue}
	}
	return scan
}

// GetInstalledShells checks for interactive Unix shells present in image
func (fi *FilesystemIndex) GetInstalledShells() []string {
	candidates := []string{"sh", "bash", "zsh", "dash", "ash", "csh", "tcsh"}
	var found []string
	for _, sh := range candidates {
		if fi.HasBinary(sh) {
			found = append(found, sh)
		}
	}
	return found
}

// GetInstalledPackageManagers checks for package management tools present in image
func (fi *FilesystemIndex) GetInstalledPackageManagers() []string {
	candidates := []string{"apk", "apt", "apt-get", "dpkg", "yum", "rpm", "dnf", "microdnf", "pacman", "pip", "npm"}
	var found []string
	for _, pm := range candidates {
		if fi.HasBinary(pm) {
			found = append(found, pm)
		}
	}
	return found
}

// harnessBasenames are test runner configuration files matched by exact basename.
var harnessBasenames = map[string]struct{}{
	"phpunit.xml":      {},
	"phpunit.xml.dist": {},
	"jest.config.js":   {},
	"pytest.ini":       {},
}

// harnessComponentSequences are directory component sequences matched as whole
// consecutive components anywhere in the path.
var harnessComponentSequences = [][]string{
	{"testdata"},
	{"tests", "phpunit"},
	{"tests", "assets"},
}

// harnessMatch returns the path to report for a harness finding. A test
// directory is reported once, as the shallowest matching directory, instead
// of once per file below it. Matching is by whole path component or exact
// basename, never by substring.
func harnessMatch(p string) (string, bool) {
	components := pathComponents(p)
	if len(components) == 0 {
		return "", false
	}
	if _, ok := harnessBasenames[components[len(components)-1]]; ok {
		return "/" + strings.Join(components, "/"), true
	}
	best := -1
	for _, sequence := range harnessComponentSequences {
		for start := 0; start+len(sequence) <= len(components); start++ {
			matched := true
			for offset, want := range sequence {
				if components[start+offset] != want {
					matched = false
					break
				}
			}
			if matched {
				end := start + len(sequence)
				if best == -1 || end < best {
					best = end
				}
				break
			}
		}
	}
	if best == -1 {
		return "", false
	}
	return "/" + strings.Join(components[:best], "/"), true
}

// GetTestHarnessPaths detects unstripped unit testing directories and test
// harnesses left in production layers (FS-07), sorted, all locations included.
func (fi *FilesystemIndex) GetTestHarnessPaths() []string {
	seen := map[string]struct{}{}
	for p := range fi.Paths {
		if reported, ok := harnessMatch(p); ok {
			seen[reported] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

// TestHarnessScan is the outcome of the test-harness scan (FS-07).
type TestHarnessScan struct {
	// Findings are harness files outside fixture-like locations, sorted. Only
	// they can make FS-07 fail.
	Findings []string
	// FixtureCandidates are harness paths under fixture-like locations (all
	// test directories are, by definition), sorted and counted separately.
	FixtureCandidates []string
}

// ScanTestHarness classifies the harness paths by location.
func (fi *FilesystemIndex) ScanTestHarness() TestHarnessScan {
	findings, candidates := splitFixturePaths(fi.GetTestHarnessPaths())
	return TestHarnessScan{Findings: findings, FixtureCandidates: candidates}
}

func normalizePath(p string) string {
	cleaned := path.Clean("/" + strings.TrimPrefix(p, "/"))
	return cleaned
}

// ImageReader streams and inspects an OCI image. Its Source states where the
// layer content comes from, because that decides which identity claims are
// honest: only a registry source has a genuine registry manifest digest.
type ImageReader struct {
	Image v1.Image
	Ref   name.Reference
	// Source is spec.SourceLocalStore, spec.SourceRegistry or spec.SourceTarball.
	Source  string
	cleanup func()
}

// Close releases temporary files held by the reader. It is safe to call more
// than once and on readers without temporary files.
func (ir *ImageReader) Close() {
	if ir == nil || ir.cleanup == nil {
		return
	}
	cleanup := ir.cleanup
	ir.cleanup = nil
	cleanup()
}

// OnClose registers a function that Close runs after any earlier cleanup.
func (ir *ImageReader) OnClose(fn func()) {
	previous := ir.cleanup
	ir.cleanup = func() {
		if previous != nil {
			previous()
		}
		fn()
	}
}

// ImageIdentity binds all checks to one immutable OCI config and platform.
// ManifestDigest is the registry manifest digest and is empty unless the
// layers were read from a registry; a digest computed from a local archive is
// synthetic and must never be presented as a registry digest.
type ImageIdentity struct {
	ManifestDigest string
	ConfigDigest   string
	Platform       string
}

// IsTarballReference reports whether imageRef names an existing local image
// tarball (for example the output of `docker save` or a Nix image build).
func IsTarballReference(imageRef string) bool {
	if !strings.HasSuffix(imageRef, ".tar") && !strings.HasSuffix(imageRef, ".tar.gz") {
		return false
	}
	_, err := os.Stat(imageRef)
	return err == nil
}

// ResolveImage resolves an image tarball or a registry reference.
func ResolveImage(ctx context.Context, imageRef string) (*ImageReader, error) {
	return ResolveImageForPlatform(ctx, imageRef, v1.Platform{})
}

// ResolveImageForPlatform resolves an image tarball on disk or, otherwise, the
// registry reference, and validates the platform chosen by the container
// engine. It never consults a local container daemon: reading from the
// engine's local store is the explicit job of ResolveFromArchive.
func ResolveImageForPlatform(ctx context.Context, imageRef string, platform v1.Platform) (*ImageReader, error) {
	if IsTarballReference(imageRef) {
		img, err := tarball.ImageFromPath(imageRef, nil)
		if err != nil {
			return nil, fmt.Errorf("failed loading OCI image tarball '%s': %w", imageRef, err)
		}
		if err := validateImagePlatform(img, platform); err != nil {
			return nil, fmt.Errorf("OCI image tarball '%s': %w", imageRef, err)
		}
		return &ImageReader{Image: img, Source: spec.SourceTarball}, nil
	}
	return ResolveFromRegistry(ctx, imageRef, platform)
}

// ResolveFromRegistry reads the image directly from its registry. For a
// digest-pinned reference the content is verified against the pinned digest.
func ResolveFromRegistry(ctx context.Context, imageRef string, platform v1.Platform) (*ImageReader, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference '%s': %w", imageRef, err)
	}
	options := []remote.Option{remote.WithContext(ctx)}
	if platform.OS != "" || platform.Architecture != "" || platform.Variant != "" {
		options = append(options, remote.WithPlatform(platform))
	}
	img, err := remote.Image(ref, options...)
	if err != nil {
		return nil, fmt.Errorf("failed resolving image '%s' from the registry: %w", imageRef, classifyRemoteError(imageRef, err))
	}
	if err := validateImagePlatform(img, platform); err != nil {
		return nil, fmt.Errorf("resolved OCI image '%s': %w", imageRef, err)
	}
	if digestRef, ok := ref.(name.Digest); ok {
		if err := verifyDigestMatch(ctx, digestRef, img, platform); err != nil {
			return nil, err
		}
	}
	return &ImageReader{Image: img, Ref: ref, Source: spec.SourceRegistry}, nil
}

// ResolveFromArchive reads an image from a docker-archive written by the
// container engine (`podman save` or `docker save`), which is how the local
// store is read without a Docker-compatible socket. The archive must hold a
// single image. The caller owns the file and removes it (directly or through
// OnClose) once the reader is no longer needed.
func ResolveFromArchive(archivePath string, platform v1.Platform) (*ImageReader, error) {
	img, err := tarball.ImageFromPath(archivePath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed loading the image archive exported from the engine store: %w", err)
	}
	if err := validateImagePlatform(img, platform); err != nil {
		return nil, fmt.Errorf("exported image archive: %w", err)
	}
	return &ImageReader{Image: img, Source: spec.SourceLocalStore}, nil
}
func verifyDigestMatch(ctx context.Context, ref name.Digest, img v1.Image, platform v1.Platform) error {
	digest, err := img.Digest()
	if err == nil && ref.Identifier() == digest.String() {
		return nil
	}

	imgConfig, err := img.ConfigName()
	if err != nil {
		return fmt.Errorf("failed reading image config digest: %w", err)
	}

	desc, err := remote.Get(ref, remote.WithContext(ctx))
	if err != nil {
		if digest.String() != "" && ref.Identifier() == digest.String() {
			return nil
		}
		if typed := classifyRemoteError(ref.String(), err); typed != err {
			return typed
		}
		return &IdentityMismatchError{Ref: ref.String(), Detail: fmt.Sprintf("resolved image digest %s does not match requested digest %s (remote verification failed: %v)", digest, ref.Identifier(), err)}
	}

	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return fmt.Errorf("failed reading image index: %w", err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return fmt.Errorf("failed reading index manifest: %w", err)
		}
		for _, m := range im.Manifests {
			if m.Platform != nil && platform.OS != "" && platform.Architecture != "" {
				if !strings.EqualFold(m.Platform.OS, platform.OS) || !strings.EqualFold(m.Platform.Architecture, platform.Architecture) {
					continue
				}
			}
			if m.Digest.String() == ref.Identifier() || m.Digest.String() == digest.String() {
				return nil
			}
			childImg, err := idx.Image(m.Digest)
			if err == nil {
				cfgName, err := childImg.ConfigName()
				if err == nil && cfgName.String() == imgConfig.String() {
					return nil
				}
			}
		}
		return &IdentityMismatchError{Ref: ref.String(), Detail: fmt.Sprintf("image index %s does not contain matching platform image for config %s", ref.Identifier(), imgConfig)}
	}

	mismatch := &IdentityMismatchError{Ref: ref.String(), Detail: fmt.Sprintf("resolved image digest %s does not match requested digest %s", digest, ref.Identifier())}
	remoteImg, err := desc.Image()
	if err != nil {
		return mismatch
	}
	remoteConfig, err := remoteImg.ConfigName()
	if err != nil || remoteConfig.String() != imgConfig.String() {
		return mismatch
	}
	return nil
}

func validateImagePlatform(img v1.Image, expected v1.Platform) error {
	if expected.OS == "" && expected.Architecture == "" && expected.Variant == "" {
		return nil
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("failed retrieving OCI config file: %w", err)
	}
	if expected.OS != "" && !strings.EqualFold(cfg.OS, expected.OS) {
		return &PlatformMismatchError{Detail: fmt.Sprintf("expected OS %q, got %q", expected.OS, cfg.OS)}
	}
	if expected.Architecture != "" && !strings.EqualFold(cfg.Architecture, expected.Architecture) {
		return &PlatformMismatchError{Detail: fmt.Sprintf("expected architecture %q, got %q", expected.Architecture, cfg.Architecture)}
	}
	// Engines report a variant (for example v8) that many configs omit, so a
	// variant is only compared when both sides state one.
	if expected.Variant != "" && cfg.Variant != "" && !strings.EqualFold(cfg.Variant, expected.Variant) {
		return &PlatformMismatchError{Detail: fmt.Sprintf("expected variant %q, got %q", expected.Variant, cfg.Variant)}
	}
	return nil
}

// Identity returns the config digest and platform of the image and, for a
// registry source only, the registry manifest digest. For archives and
// tarballs Image.Digest() would compress every layer to synthesize a manifest,
// which is both expensive and not a registry digest, so it is never computed.
func (ir *ImageReader) Identity() (ImageIdentity, error) {
	manifestDigest := ""
	if ir.Source == spec.SourceRegistry {
		digest, err := ir.Image.Digest()
		if err != nil {
			return ImageIdentity{}, fmt.Errorf("failed retrieving OCI manifest digest: %w", err)
		}
		manifestDigest = digest.String()
	}
	configDigest, err := ir.Image.ConfigName()
	if err != nil {
		return ImageIdentity{}, fmt.Errorf("failed retrieving OCI config digest: %w", err)
	}
	cfg, err := ir.Image.ConfigFile()
	if err != nil {
		return ImageIdentity{}, fmt.Errorf("failed retrieving OCI config file: %w", err)
	}
	if cfg.OS == "" || cfg.Architecture == "" {
		return ImageIdentity{}, fmt.Errorf("OCI config does not identify a complete platform (OS=%q, architecture=%q)", cfg.OS, cfg.Architecture)
	}
	platform := cfg.OS + "/" + cfg.Architecture
	if cfg.Variant != "" {
		platform += "/" + cfg.Variant
	}
	return ImageIdentity{
		ManifestDigest: manifestDigest,
		ConfigDigest:   configDigest.String(),
		Platform:       platform,
	}, nil
}

// ImmutableReference returns the repository pinned to the registry manifest
// digest. It is empty unless the image was read from a registry; for other
// sources the caller derives a reference from a verified registry digest.
func (ir *ImageReader) ImmutableReference() (string, error) {
	if ir.Ref == nil || ir.Source != spec.SourceRegistry {
		return "", nil
	}
	digest, err := ir.Image.Digest()
	if err != nil {
		return "", fmt.Errorf("failed retrieving OCI manifest digest: %w", err)
	}
	return ir.Ref.Context().Digest(digest.String()).String(), nil
}

// InspectMetadata extracts OCI config JSON and total compressed size in milliseconds
func (ir *ImageReader) InspectMetadata() (*v1.ConfigFile, int64, error) {
	cfg, err := ir.Image.ConfigFile()
	if err != nil {
		return nil, 0, fmt.Errorf("failed retrieving OCI config file: %w", err)
	}

	layers, err := ir.Image.Layers()
	if err != nil {
		return cfg, 0, nil
	}

	var totalSize int64
	for _, l := range layers {
		sz, err := l.Size()
		if err == nil {
			totalSize += sz
		}
	}

	return cfg, totalSize, nil
}

const (
	// MaxIndexedFiles is the default cap on indexed entries. It exists to bound
	// the memory an image can make the indexer allocate (a decompression bomb
	// defense), not to select which images can be evaluated: an image above the
	// cap is excluded from a study, so the cap should sit well above real
	// images. Measured with 60-byte paths (BenchmarkFilesystemIndexMemory), the
	// peak heap is about 107 MiB at 250,000 entries (the earlier cap) and about
	// 470 MiB at 1,000,000 entries, with about 115 MiB retained. Both are small
	// next to the memory of an evaluation host, so the cap is raised fourfold.
	MaxIndexedFiles        = 1_000_000
	MaxAccountFileBytes    = 1 << 20
	MaxPrivateKeyFileBytes = 1 << 20
)

// Memory model of the filesystem index. The entry cap alone does not bound
// memory, because a path can be arbitrarily long, so every cap also implies a
// memory budget that is checked in estimated bytes.
const (
	// indexEntryOverheadBytes is the heap held per entry besides the path
	// bytes: the slots in the merged and per-layer maps and the per-layer
	// record. Measured at about 490 B per entry at peak with 60-byte paths,
	// rounded up so the estimate stays conservative.
	indexEntryOverheadBytes = 512
	// indexAveragePathBytes is the average path length the budget allows per
	// entry. Paths in real image trees average well under 100 bytes, so the
	// entry cap decides first and the budget only trips for pathological names.
	indexAveragePathBytes = 256
)

// indexBytes estimates the memory of an index with the given number of
// entries whose paths add up to pathBytes.
func indexBytes(entries int, pathBytes int64) int64 {
	return int64(entries)*indexEntryOverheadBytes + pathBytes
}

// indexByteBudget is the estimated-memory budget implied by an entry cap.
func indexByteBudget(maxEntries int) int64 {
	const perEntry = indexEntryOverheadBytes + indexAveragePathBytes
	if int64(maxEntries) > math.MaxInt64/perEntry {
		return math.MaxInt64
	}
	return int64(maxEntries) * perEntry
}

// IndexStats describes the size of a completed filesystem index. Entries are
// the distinct paths of the final merged view.
type IndexStats struct {
	Entries int
	Layers  int
	// PathBytes is the total length of the indexed paths.
	PathBytes int64
	// EstimatedBytes is the memory the index is modeled to need at peak.
	EstimatedBytes int64
	// ScannedBytes is the content size of the regular files read across all
	// layers, including files that a later layer replaced or removed.
	ScannedBytes int64
}

// StreamAndIndexFilesystem streams tarball layers in-memory to reconstruct paths and SUID bits
func (ir *ImageReader) StreamAndIndexFilesystem() (*FilesystemIndex, error) {
	return ir.streamAndIndexFilesystem(MaxIndexedFiles)
}

// StreamAndIndexFilesystemLimit is StreamAndIndexFilesystem with an explicit
// cap on the number of indexed entries. Exceeding the cap, or the memory
// budget derived from it, fails with an *IndexTooLargeError.
func (ir *ImageReader) StreamAndIndexFilesystemLimit(maxEntries int) (*FilesystemIndex, error) {
	return ir.streamAndIndexFilesystem(maxEntries)
}

type indexedEntry struct {
	mode     int64
	typeflag byte
	uid      int
	// effectiveRegular is true for a regular file and, after hard-link
	// resolution, for a hard link whose target is a regular file. The mode and
	// ownership checks use it, because a hard link is the same inode as its
	// target.
	effectiveRegular bool
	// emptyRegular is true for a regular file of zero bytes. A hard link is
	// never marked, so a link below a directory always counts as content.
	emptyRegular bool
	// linkTarget is the normalized target path of a hard-link entry.
	linkTarget string
	// keyScanned is true when the content of a key-file candidate was read.
	keyScanned bool

	privateKey           bool
	accountContent       []byte
	accountEvidenceIssue string
	keyEvidenceIssue     string
}

func isPrivateKeyCandidate(baseName string) bool {
	return strings.HasSuffix(baseName, ".key") ||
		strings.HasSuffix(baseName, ".pem") ||
		baseName == "id_rsa" ||
		baseName == "id_ed25519" ||
		baseName == "id_dsa" ||
		baseName == "id_ecdsa"
}

func isPublicCertificateCandidate(normPath, baseName, linkTarget string) bool {
	lowerBase := strings.ToLower(baseName)
	if lowerBase == "cert.pem" ||
		lowerBase == "cacert.pem" ||
		lowerBase == "ca-cert.pem" ||
		lowerBase == "ca.pem" ||
		lowerBase == "ca-bundle.pem" ||
		lowerBase == "chain.pem" ||
		lowerBase == "fullchain.pem" ||
		lowerBase == "tls.crt" ||
		strings.HasPrefix(lowerBase, "ca-certificates") {
		return true
	}
	lowerTarget := strings.ToLower(linkTarget)
	if strings.Contains(lowerTarget, "ca-certificates") ||
		strings.Contains(lowerTarget, "cert.pem") ||
		strings.Contains(lowerTarget, "cacert.pem") ||
		strings.HasSuffix(lowerTarget, ".crt") {
		return true
	}
	lowerPath := strings.ToLower(normPath)
	if (strings.HasPrefix(lowerPath, "/etc/ssl/") || strings.HasPrefix(lowerPath, "/etc/pki/")) &&
		(strings.Contains(lowerPath, "cert") || strings.HasSuffix(lowerTarget, ".crt")) {
		return true
	}
	return false
}

func isRegularFileType(typeflag byte) bool {
	return typeflag == tar.TypeReg || typeflag == tar.TypeRegA
}

func inspectPrivateKeyContent(content []byte) (bool, bool) {
	remaining := content
	foundPEM := false
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		foundPEM = true
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return true, true
		}
		remaining = rest
	}
	if foundPEM {
		if bytes.Contains(remaining, []byte("-----BEGIN ")) {
			return false, false
		}
		return false, true
	}

	trimmed := bytes.TrimSpace(content)
	if bytes.HasPrefix(trimmed, []byte("ssh-rsa ")) ||
		bytes.HasPrefix(trimmed, []byte("ssh-ed25519 ")) ||
		bytes.HasPrefix(trimmed, []byte("ecdsa-sha2-")) {
		return false, true
	}
	return false, false
}

func readIndexedEntry(normPath, baseName string, header *tar.Header, tarReader *tar.Reader) (indexedEntry, error) {
	entry := indexedEntry{
		mode:             header.Mode,
		typeflag:         header.Typeflag,
		uid:              header.Uid,
		effectiveRegular: isRegularFileType(header.Typeflag),
		emptyRegular:     isRegularFileType(header.Typeflag) && header.Size == 0,
	}
	if header.Typeflag == tar.TypeLink {
		entry.linkTarget = normalizePath(header.Linkname)
	}
	isAccountFile := normPath == "/etc/passwd" || normPath == "/etc/shadow" || normPath == groupFilePath
	isKeyFile := isPrivateKeyCandidate(baseName)
	isRegularFile := isRegularFileType(header.Typeflag)
	if isAccountFile && !isRegularFile {
		entry.accountEvidenceIssue = fmt.Sprintf("%s is not a regular file", normPath)
	}
	if isKeyFile && !isRegularFile {
		if header.Typeflag != tar.TypeDir && !isPublicCertificateCandidate(normPath, baseName, header.Linkname) {
			entry.keyEvidenceIssue = fmt.Sprintf("recognized key-file candidate %s is not a regular file", normPath)
		}
	}
	if (!isAccountFile && !isKeyFile) || !isRegularFile {
		return entry, nil
	}
	limit := int64(MaxPrivateKeyFileBytes)
	if isAccountFile {
		limit = MaxAccountFileBytes
	}
	content, err := io.ReadAll(io.LimitReader(tarReader, limit+1))
	if err != nil {
		return indexedEntry{}, fmt.Errorf("error reading layer entry %q: %w", normPath, err)
	}
	entry.keyScanned = isKeyFile
	if isAccountFile {
		entry.accountContent = content
		if header.Size > limit {
			entry.accountEvidenceIssue = fmt.Sprintf("%s exceeds the %d-byte complete-scan limit", normPath, limit)
		}
	}
	if isKeyFile && len(content) > 0 {
		var supported bool
		entry.privateKey, supported = inspectPrivateKeyContent(content)
		if !supported {
			entry.keyEvidenceIssue = fmt.Sprintf("recognized key-file candidate %s does not use a supported PEM/OpenSSH public-key encoding", normPath)
		}
	}
	if isKeyFile && header.Size > int64(MaxPrivateKeyFileBytes) {
		entry.keyEvidenceIssue = fmt.Sprintf("recognized key-file candidate %s exceeds the %d-byte complete-scan limit", normPath, MaxPrivateKeyFileBytes)
	}

	return entry, nil
}

// maxHardLinkChain bounds how many links are followed when a hard link names
// another hard link, so that a cycle ends as unresolved.
const maxHardLinkChain = 16

// followHardLink returns the entry that a hard-link target path finally names,
// looking only at the entries of one layer.
func followHardLink(entries map[string]indexedEntry, target string) (indexedEntry, bool) {
	for hops := 0; hops < maxHardLinkChain; hops++ {
		next, ok := entries[target]
		if !ok {
			return indexedEntry{}, false
		}
		if next.typeflag != tar.TypeLink {
			return next, true
		}
		target = next.linkTarget
	}
	return indexedEntry{}, false
}

// resolveHardLinks gives every hard-link entry of one layer the properties of
// the file it names. A hard link is another directory entry for the same
// inode, so the mode and owner that count are the target's, never the ones in
// the link's own header. The target is looked up among the entries of the
// same layer. The OCI image specification does not forbid a link to a file of
// a lower layer, but it warns that extracting a layer with hard-link
// references to files outside the layer may fail, and a lower layer's mode and
// owner are not kept here. Such a link is therefore reported as unresolved
// and never guessed. The result maps each link whose target could not be found
// to the reason.
func resolveHardLinks(entries map[string]indexedEntry) map[string]string {
	var unresolved map[string]string
	for linkPath, link := range entries {
		if link.typeflag != tar.TypeLink {
			continue
		}
		target, ok := followHardLink(entries, link.linkTarget)
		if !ok {
			if unresolved == nil {
				unresolved = make(map[string]string)
			}
			unresolved[linkPath] = fmt.Sprintf("hard link %s names %s, which is not a file of the same layer", linkPath, link.linkTarget)
			continue
		}
		link.mode = target.mode
		link.uid = target.uid
		link.effectiveRegular = target.effectiveRegular
		if isPrivateKeyCandidate(path.Base(linkPath)) {
			if target.keyScanned {
				link.keyScanned = true
				link.privateKey = target.privateKey
				link.keyEvidenceIssue = target.keyEvidenceIssue
			} else if link.keyEvidenceIssue != "" {
				link.keyEvidenceIssue = fmt.Sprintf("recognized key-file candidate %s is a hard link to %s, whose content was not scanned", linkPath, link.linkTarget)
			}
		}
		entries[linkPath] = link
	}
	return unresolved
}

// unresolvedLinkIssue describes the unresolved hard links of an image. It
// names the first few and counts the rest.
func unresolvedLinkIssue(paths []string, reasons map[string]string) string {
	const shown = 3
	listed := paths
	if len(listed) > shown {
		listed = listed[:shown]
	}
	parts := make([]string, 0, len(listed))
	for _, linkPath := range listed {
		reason := reasons[linkPath]
		if reason == "" {
			reason = fmt.Sprintf("hard link %s is not resolved", linkPath)
		}
		parts = append(parts, reason)
	}
	issue := fmt.Sprintf("%d hard link(s) have no target in the same layer, so their mode and owner cannot be read: %s", len(paths), strings.Join(parts, "; "))
	if len(paths) > shown {
		issue += fmt.Sprintf("; and %d more", len(paths)-shown)
	}
	return issue
}

func parsePasswdContent(content []byte) (map[string][]uint32, []string, error) {
	uids := make(map[string][]uint32)
	emptyPasswordAccounts := make(map[string]struct{})
	lineCount := 0
	for lineNumber, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineCount++
		fields := strings.Split(line, ":")
		if len(fields) != 7 || strings.TrimSpace(fields[0]) == "" {
			return uids, sortedKeys(emptyPasswordAccounts), fmt.Errorf("/etc/passwd line %d has an invalid record", lineNumber+1)
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return uids, sortedKeys(emptyPasswordAccounts), fmt.Errorf("/etc/passwd line %d has an invalid UID", lineNumber+1)
		}
		uids[fields[0]] = append(uids[fields[0]], uint32(uid))
		if fields[1] == "" {
			emptyPasswordAccounts[fields[0]] = struct{}{}
		}
	}
	if lineCount == 0 {
		return uids, nil, fmt.Errorf("/etc/passwd contains no account records")
	}
	return uids, sortedKeys(emptyPasswordAccounts), nil
}

func parseShadowContent(content []byte) ([]string, error) {
	emptyPasswordAccounts := make(map[string]struct{})
	lineCount := 0
	for lineNumber, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineCount++
		fields := strings.Split(line, ":")
		if len(fields) < 2 || strings.TrimSpace(fields[0]) == "" {
			return sortedKeys(emptyPasswordAccounts), fmt.Errorf("/etc/shadow line %d has an invalid record", lineNumber+1)
		}
		if fields[1] == "" {
			emptyPasswordAccounts[fields[0]] = struct{}{}
		}
	}
	if lineCount == 0 {
		return nil, fmt.Errorf("/etc/shadow contains no account records")
	}
	return sortedKeys(emptyPasswordAccounts), nil
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func (ir *ImageReader) streamAndIndexFilesystem(maxIndexedFiles int) (*FilesystemIndex, error) {
	if maxIndexedFiles <= 0 {
		return nil, fmt.Errorf("filesystem index limit must be greater than zero, got %d", maxIndexedFiles)
	}

	layers, err := ir.Image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed retrieving image layers: %w", err)
	}

	idx := &FilesystemIndex{
		Paths:              make(map[string]bool),
		SuidMap:            make(map[string]int64),
		WorldWritableFiles: make(map[string]int64),
		PrivateKeyFiles:    make(map[string]string),
		PasswdUIDs:         make(map[string][]uint32),
		Dirs:               make(map[string]struct{}),
		EmptyFiles:         make(map[string]struct{}),
	}

	// Capture OCI image build history for instruction analysis (SPEC-07)
	cfg, configErr := ir.Image.ConfigFile()
	if configErr != nil {
		idx.HistoryEvidenceIssue = fmt.Sprintf("failed retrieving OCI config history: %v", configErr)
	} else if cfg == nil {
		idx.HistoryEvidenceIssue = "OCI config history is unavailable"
	} else {
		for _, h := range cfg.History {
			idx.HistoryEntries = append(idx.HistoryEntries, h.CreatedBy)
			idx.History = append(idx.History, HistoryEntry{CreatedBy: h.CreatedBy, EmptyLayer: h.EmptyLayer})
		}
		if len(cfg.History) == 0 {
			idx.HistoryEvidenceIssue = "OCI image config contains no history entries"
		} else {
			for _, historyEntry := range cfg.History {
				if strings.TrimSpace(historyEntry.CreatedBy) == "" {
					idx.HistoryEvidenceIssue = "OCI image history contains an empty CreatedBy entry"
					break
				}
			}
		}
	}

	accountContentByPath := make(map[string][]byte)
	accountEvidenceByPath := make(map[string]string)
	keyEvidenceByPath := make(map[string]string)
	nonRootSystemBinariesByPath := make(map[string]string)
	// unresolvedLinks holds, per path of the merged view, the reason a hard
	// link could not be resolved to a file of its layer.
	unresolvedLinks := make(map[string]string)

	// Size accounting. mergedPathBytes is the total length of idx.Paths.
	// scannedBytes sums the content size of the regular files read so far.
	// layerNumber is the 1-based layer being read, for error reports.
	byteBudget := indexByteBudget(maxIndexedFiles)
	var mergedPathBytes, scannedBytes int64
	layerNumber := 0
	tooLarge := func(dimension string, entries int, pathBytes int64) *IndexTooLargeError {
		return &IndexTooLargeError{
			Dimension:      dimension,
			Limit:          maxIndexedFiles,
			ByteBudget:     byteBudget,
			Entries:        entries,
			EstimatedBytes: indexBytes(entries, pathBytes),
			Layer:          layerNumber,
			Layers:         len(layers),
			ScannedBytes:   scannedBytes,
		}
	}
	// exceeds reports which limit, if any, an index of the given size breaks.
	exceeds := func(entries int, pathBytes int64) string {
		switch {
		case entries > maxIndexedFiles:
			return IndexLimitEntries
		case indexBytes(entries, pathBytes) > byteBudget:
			return IndexLimitMemory
		}
		return ""
	}

	removePath := func(existing string) {
		if _, present := idx.Paths[existing]; present {
			mergedPathBytes -= int64(len(existing))
		}
		delete(idx.Paths, existing)
		delete(idx.Dirs, existing)
		delete(idx.EmptyFiles, existing)
		delete(idx.SuidMap, existing)
		delete(idx.WorldWritableFiles, existing)
		delete(idx.PrivateKeyFiles, existing)
		delete(accountContentByPath, existing)
		delete(accountEvidenceByPath, existing)
		delete(keyEvidenceByPath, existing)
		delete(nonRootSystemBinariesByPath, existing)
		delete(unresolvedLinks, existing)
	}

	// Process layers sequentially from base to top
	for _, layer := range layers {
		layerNumber++
		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("failed opening uncompressed layer stream: %w", err)
		}

		tarReader := tar.NewReader(rc)
		layerEntries := make(map[string]indexedEntry)
		var layerPathBytes int64
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = rc.Close()
				return nil, fmt.Errorf("error streaming layer tar: %w", err)
			}

			normPath := normalizePath(header.Name)
			dirName := path.Dir(normPath)
			baseName := path.Base(normPath)

			// Handle OCI / AUFS whiteouts (.wh.<filename>)
			if strings.HasPrefix(baseName, ".wh.") {
				if baseName == ".wh..wh..opq" {
					// Opaque whiteout: hides all children of this directory from lower layers
					prefix := dirName + "/"
					if dirName == "/" {
						prefix = "/"
					}
					for existing := range idx.Paths {
						if strings.HasPrefix(existing, prefix) && existing != dirName {
							removePath(existing)
						}
					}
				} else {
					targetName := strings.TrimPrefix(baseName, ".wh.")
					if targetName == "" {
						continue
					}
					targetDeleted := normalizePath(path.Join(dirName, targetName))
					deletedPrefix := targetDeleted + "/"
					for existing := range idx.Paths {
						if existing == targetDeleted || strings.HasPrefix(existing, deletedPrefix) {
							removePath(existing)
						}
					}
				}
				continue
			}

			// A new path in this layer must fit the limits on its own, before it
			// is held in memory. The merged index is checked after the layer.
			if _, exists := layerEntries[normPath]; !exists {
				if limit := exceeds(len(layerEntries)+1, layerPathBytes+int64(len(normPath))); limit != "" {
					_ = rc.Close()
					return nil, tooLarge(limit, len(layerEntries)+1, layerPathBytes+int64(len(normPath)))
				}
				layerPathBytes += int64(len(normPath))
			}
			if isRegularFileType(header.Typeflag) && header.Size > 0 {
				scannedBytes += header.Size
			}

			entry, err := readIndexedEntry(normPath, baseName, header, tarReader)
			if err != nil {
				_ = rc.Close()
				return nil, err
			}
			layerEntries[normPath] = entry
		}

		_ = rc.Close()

		// A hard link takes the mode and owner of its target. Links without a
		// target in this layer are kept as evidence issues.
		layerUnresolved := resolveHardLinks(layerEntries)

		finalPathCount := len(idx.Paths)
		finalPathBytes := mergedPathBytes
		for entryPath := range layerEntries {
			if _, exists := idx.Paths[entryPath]; !exists {
				finalPathCount++
				finalPathBytes += int64(len(entryPath))
			}
		}
		if limit := exceeds(finalPathCount, finalPathBytes); limit != "" {
			return nil, tooLarge(limit, finalPathCount, finalPathBytes)
		}

		// Apply entries after whiteouts so additions in the same layer survive regardless
		// of their order in the layer tar stream.
		for entryPath, entry := range layerEntries {
			if _, present := idx.Paths[entryPath]; !present {
				mergedPathBytes += int64(len(entryPath))
			}
			idx.Paths[entryPath] = true
			delete(idx.Dirs, entryPath)
			delete(idx.EmptyFiles, entryPath)
			if entry.typeflag == tar.TypeDir {
				idx.Dirs[entryPath] = struct{}{}
			}
			if entry.emptyRegular {
				idx.EmptyFiles[entryPath] = struct{}{}
			}

			// Replacements must clear findings derived from the lower-layer entry.
			delete(idx.SuidMap, entryPath)
			delete(idx.WorldWritableFiles, entryPath)
			delete(idx.PrivateKeyFiles, entryPath)
			delete(accountContentByPath, entryPath)
			delete(accountEvidenceByPath, entryPath)
			delete(keyEvidenceByPath, entryPath)
			delete(nonRootSystemBinariesByPath, entryPath)
			delete(unresolvedLinks, entryPath)
			if reason, unresolved := layerUnresolved[entryPath]; unresolved {
				unresolvedLinks[entryPath] = reason
			}

			// isRegularFile includes a hard link to a regular file, literalRegular
			// is true only for an entry that carries file content itself.
			literalRegular := isRegularFileType(entry.typeflag)
			isRegularFile := entry.effectiveRegular

			// Check for SUID (04000) or SGID (02000) bits
			if (entry.mode&04000 != 0 || entry.mode&02000 != 0) && isRegularFile {
				idx.SuidMap[entryPath] = entry.mode
			}

			// Check for World-Writable regular files (mode & 0002 != 0)
			if entry.mode&0002 != 0 && isRegularFile {
				idx.WorldWritableFiles[entryPath] = entry.mode
			}

			if entry.privateKey {
				idx.PrivateKeyFiles[entryPath] = "Contains private key material"
			}
			if entry.keyEvidenceIssue != "" {
				keyEvidenceByPath[entryPath] = entry.keyEvidenceIssue
			}
			if entry.accountEvidenceIssue != "" {
				accountEvidenceByPath[entryPath] = entry.accountEvidenceIssue
			}
			if (entryPath == "/etc/passwd" || entryPath == "/etc/shadow" || entryPath == groupFilePath) && literalRegular {
				accountContentByPath[entryPath] = entry.accountContent
			}

			// Check system directory binary ownership (FS-09, NIST SP 800-190 / Linux FHS)
			isSystemBin := strings.HasPrefix(entryPath, "/bin/") ||
				strings.HasPrefix(entryPath, "/usr/bin/") ||
				strings.HasPrefix(entryPath, "/sbin/") ||
				strings.HasPrefix(entryPath, "/usr/sbin/")
			if isSystemBin && isRegularFile && entry.uid != 0 {
				nonRootSystemBinariesByPath[entryPath] = fmt.Sprintf("%s (UID %d)", entryPath, entry.uid)
			}
		}
	}

	var passwdIssues []string
	var accountIssues []string
	for _, accountPath := range []string{"/etc/passwd", "/etc/shadow"} {
		if !idx.Paths[accountPath] {
			accountIssues = append(accountIssues, fmt.Sprintf("%s is missing from the final image", accountPath))
			if accountPath == "/etc/passwd" {
				passwdIssues = append(passwdIssues, fmt.Sprintf("%s is missing from the final image", accountPath))
			}
			continue
		}
		if issue := accountEvidenceByPath[accountPath]; issue != "" {
			accountIssues = append(accountIssues, issue)
			if accountPath == "/etc/passwd" {
				passwdIssues = append(passwdIssues, issue)
			}
		}
		content, exists := accountContentByPath[accountPath]
		if !exists {
			issue := fmt.Sprintf("%s contents are unavailable in the final image", accountPath)
			accountIssues = append(accountIssues, issue)
			if accountPath == "/etc/passwd" {
				passwdIssues = append(passwdIssues, issue)
			}
			continue
		}
		if accountPath == "/etc/passwd" {
			uids, emptyAccounts, parseErr := parsePasswdContent(content)
			idx.PasswdUIDs = uids
			idx.EmptyPasswordAccounts = append(idx.EmptyPasswordAccounts, emptyAccounts...)
			if parseErr != nil {
				passwdIssues = append(passwdIssues, parseErr.Error())
				accountIssues = append(accountIssues, parseErr.Error())
			}
		} else {
			emptyAccounts, parseErr := parseShadowContent(content)
			idx.EmptyPasswordAccounts = append(idx.EmptyPasswordAccounts, emptyAccounts...)
			if parseErr != nil {
				accountIssues = append(accountIssues, parseErr.Error())
			}
		}
	}
	idx.captureGroup(accountContentByPath, accountEvidenceByPath)
	if len(passwdIssues) > 0 {
		idx.PasswdEvidenceIssue = strings.Join(passwdIssues, "; ")
	}
	if len(accountIssues) > 0 {
		idx.AccountEvidenceIssue = strings.Join(accountIssues, "; ")
	}
	accountNames := make(map[string]struct{}, len(idx.EmptyPasswordAccounts))
	for _, accountName := range idx.EmptyPasswordAccounts {
		accountNames[accountName] = struct{}{}
	}
	idx.EmptyPasswordAccounts = sortedKeys(accountNames)

	keyPaths := make([]string, 0, len(keyEvidenceByPath))
	for keyPath := range keyEvidenceByPath {
		keyPaths = append(keyPaths, keyPath)
	}
	sort.Strings(keyPaths)
	if len(keyPaths) > 0 {
		keyIssues := make([]string, 0, len(keyPaths))
		idx.PrivateKeyIssues = make(map[string]string, len(keyPaths))
		for _, keyPath := range keyPaths {
			keyIssues = append(keyIssues, keyEvidenceByPath[keyPath])
			idx.PrivateKeyIssues[keyPath] = keyEvidenceByPath[keyPath]
		}
		idx.PrivateKeyEvidenceIssue = strings.Join(keyIssues, "; ")
	}

	nonRootPaths := make([]string, 0, len(nonRootSystemBinariesByPath))
	for entryPath := range nonRootSystemBinariesByPath {
		nonRootPaths = append(nonRootPaths, entryPath)
	}
	sort.Strings(nonRootPaths)
	for _, entryPath := range nonRootPaths {
		idx.NonRootSystemBinaries = append(idx.NonRootSystemBinaries, nonRootSystemBinariesByPath[entryPath])
	}

	if len(unresolvedLinks) > 0 {
		linkPaths := make([]string, 0, len(unresolvedLinks))
		for linkPath := range unresolvedLinks {
			linkPaths = append(linkPaths, linkPath)
		}
		sort.Strings(linkPaths)
		idx.UnresolvedHardLinks = linkPaths
		idx.UnresolvedHardLinkReasons = unresolvedLinks
	}

	idx.Stats = IndexStats{
		Entries:        len(idx.Paths),
		Layers:         len(layers),
		PathBytes:      mergedPathBytes,
		EstimatedBytes: indexBytes(len(idx.Paths), mergedPathBytes),
		ScannedBytes:   scannedBytes,
	}
	return idx, nil
}
