package acquire

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const fakeEngineScript = `#!/bin/sh
log() { printf '%s\n' "$*" >> "$FAKE_CALL_LOG"; }
if [ "$1" = "--version" ]; then echo "podman version 5.0.0"; exit 0; fi
case "$1:$2" in
  image:exists)
    log "image exists $3"
    if [ -f "$FAKE_PRESENT_MARKER" ]; then exit 0; fi
    exit 1 ;;
  image:inspect)
    log "image inspect $*"
    cat "$FAKE_INSPECT_JSON"
    exit 0 ;;
esac
case "$1" in
  pull)
    log "pull $*"
    touch "$FAKE_PRESENT_MARKER"
    exit "${FAKE_PULL_EXIT:-0}" ;;
  save)
    log "save $*"
    dest=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "-o" ]; then dest="$2"; fi
      shift
    done
    if [ "${FAKE_SAVE_EXIT:-0}" != "0" ]; then echo "save failed" >&2; exit "$FAKE_SAVE_EXIT"; fi
    echo "$dest" >> "$FAKE_SAVE_PATHS"
    cp "$FAKE_ARCHIVE" "$dest"
    exit 0 ;;
esac
log "unexpected $*"
exit 97
`

type fixture struct {
	t            *testing.T
	eng          *engine.Engine
	callLog      string
	savePaths    string
	configDigest string
}

type inspectJSON struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	Os          string   `json:"Os"`
	Arch        string   `json:"Architecture"`
}

func layerBytes(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for fileName, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: fileName, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// newFixture builds a docker-archive like the one `podman save` writes and a
// fake engine that serves it. The inspect output is configured per test.
func newFixture(t *testing.T, present bool, arch string) *fixture {
	t.Helper()
	dir := t.TempDir()
	layer, err := tarball.LayerFromReader(bytes.NewReader(layerBytes(t, map[string]string{"etc/hostname": "synthetic\n"})))
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg.OS, cfg.Architecture = "linux", arch
	cfg.Config.User = "1000"
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "source-archive.tar")
	ref, _ := name.ParseReference("example.test/synthetic:1")
	if err := tarball.WriteToFile(archive, ref, img); err != nil {
		t.Fatal(err)
	}
	digest, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{
		t:            t,
		callLog:      filepath.Join(dir, "calls.log"),
		savePaths:    filepath.Join(dir, "save-paths.log"),
		configDigest: digest.String(),
	}
	script := filepath.Join(dir, "fake-engine")
	if err := os.WriteFile(script, []byte(fakeEngineScript), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "present")
	if present {
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FAKE_CALL_LOG", f.callLog)
	t.Setenv("FAKE_SAVE_PATHS", f.savePaths)
	t.Setenv("FAKE_PRESENT_MARKER", marker)
	t.Setenv("FAKE_ARCHIVE", archive)
	t.Setenv("FAKE_INSPECT_JSON", filepath.Join(dir, "inspect.json"))
	f.eng = &engine.Engine{BinaryPath: script}
	f.setInspect(inspectJSON{ID: f.configDigest, Os: "linux", Arch: arch})
	return f
}

func (f *fixture) setInspect(in inspectJSON) {
	f.t.Helper()
	data, err := json.Marshal([]inspectJSON{in})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("FAKE_INSPECT_JSON"), data, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) calls() string {
	data, _ := os.ReadFile(f.callLog)
	return string(data)
}

func (f *fixture) savedPaths() []string {
	data, _ := os.ReadFile(f.savePaths)
	return strings.Fields(string(data))
}

const pinnedDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAutoReadsPresentImageFromLocalStoreWithoutPulling(t *testing.T) {
	f := newFixture(t, true, "amd64")
	res, err := Acquire(context.Background(), f.eng, "example.test/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyAuto})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if res.Source != spec.SourceLocalStore {
		t.Errorf("source = %q, want %q", res.Source, spec.SourceLocalStore)
	}
	if strings.Contains(f.calls(), "pull ") || res.Pulled {
		t.Errorf("an image that is present in the store must not be pulled:\n%s", f.calls())
	}
	if !strings.Contains(f.calls(), "save --format docker-archive -o ") {
		t.Errorf("podman style engines must export a docker-archive:\n%s", f.calls())
	}
	if res.ConfigDigest != f.configDigest || res.EngineImageID != f.configDigest {
		t.Errorf("identity = config %q engine %q, want %q", res.ConfigDigest, res.EngineImageID, f.configDigest)
	}
	if res.RegistryDigest != "" || res.ImmutableRef != "" {
		t.Errorf("a tag reference without RepoDigests must not receive a registry digest, got %q / %q", res.RegistryDigest, res.ImmutableRef)
	}
	paths := f.savedPaths()
	if len(paths) != 1 {
		t.Fatalf("save paths = %v", paths)
	}
	if _, statErr := os.Stat(paths[0]); statErr != nil {
		t.Fatalf("archive must exist while the reader is open: %v", statErr)
	}
	idx, err := res.Reader.StreamAndIndexFilesystem()
	if err != nil || !idx.HasPath("/etc/hostname") {
		t.Fatalf("archive content is not readable through the reader: %v", err)
	}
	res.Close()
	if _, statErr := os.Stat(paths[0]); !os.IsNotExist(statErr) {
		t.Errorf("the temporary archive must be removed on Close, stat error: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Dir(paths[0])); !os.IsNotExist(statErr) {
		t.Errorf("the temporary directory must be removed on Close, stat error: %v", statErr)
	}
}

func TestAutoPullsAbsentImageWithExplicitPlatformThenReadsStore(t *testing.T) {
	f := newFixture(t, false, "amd64")
	res, err := Acquire(context.Background(), f.eng, "example.test/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyAuto})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer res.Close()
	if !res.Pulled || res.Source != spec.SourceLocalStore {
		t.Errorf("pulled=%t source=%q, want a pull followed by a local-store read", res.Pulled, res.Source)
	}
	if !strings.Contains(f.calls(), "pull --platform linux/amd64 example.test/synthetic:1") {
		t.Errorf("pull must receive the platform explicitly:\n%s", f.calls())
	}
}

func TestLocalPolicyFailsWhenImageIsAbsentAndNeverPulls(t *testing.T) {
	f := newFixture(t, false, "amd64")
	_, err := Acquire(context.Background(), f.eng, "example.test/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyLocal})
	var notInStore *engine.ImageNotInStoreError
	if !errors.As(err, &notInStore) {
		t.Fatalf("error = %v, want *engine.ImageNotInStoreError", err)
	}
	if strings.Contains(f.calls(), "pull ") || strings.Contains(f.calls(), "save ") {
		t.Errorf("local policy must neither pull nor export an absent image:\n%s", f.calls())
	}
	var stage *ImageError
	if !errors.As(err, &stage) || stage.Stage != "pull" {
		t.Errorf("failure must report the pull stage, got %+v", stage)
	}
}

func TestExportFailureIsAnErrorNotARegistryFallback(t *testing.T) {
	f := newFixture(t, true, "amd64")
	t.Setenv("FAKE_SAVE_EXIT", "125")
	// The reference points at a host that can never be reached. A silent
	// fallback to the registry would show up as a network error or a pass.
	_, err := Acquire(context.Background(), f.eng, "registry.invalid/never/reached:1", Options{Platform: "linux/amd64", Policy: PolicyAuto})
	if err == nil || !strings.Contains(err.Error(), "failed to export image") {
		t.Fatalf("error = %v, want an export failure", err)
	}
	var stage *ImageError
	if !errors.As(err, &stage) || stage.ImageSource != spec.SourceLocalStore {
		t.Errorf("the failure must record the local-store source, got %+v", stage)
	}
	if paths := f.savedPaths(); len(paths) != 0 {
		t.Errorf("no archive may be left behind: %v", paths)
	}
}

func TestPinnedDigestIsVerifiedAgainstRepoDigests(t *testing.T) {
	ref := "example.test/library/synthetic@" + pinnedDigest

	t.Run("reports the pinned registry digest, never a synthesized one", func(t *testing.T) {
		f := newFixture(t, true, "amd64")
		f.setInspect(inspectJSON{ID: f.configDigest, Os: "linux", Arch: "amd64", RepoDigests: []string{"example.test/library/synthetic@" + pinnedDigest}})
		res, err := Acquire(context.Background(), f.eng, ref, Options{Platform: "linux/amd64", Policy: PolicyLocal})
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		defer res.Close()
		if res.RegistryDigest != pinnedDigest {
			t.Errorf("registry digest = %q, want the pinned digest %q", res.RegistryDigest, pinnedDigest)
		}
		if res.ImmutableRef != "example.test/library/synthetic@"+pinnedDigest {
			t.Errorf("immutable ref = %q", res.ImmutableRef)
		}
	})

	t.Run("digest mismatch is IDENTITY_MISMATCH and releases the archive", func(t *testing.T) {
		f := newFixture(t, true, "amd64")
		other := "sha256:" + strings.Repeat("b", 64)
		f.setInspect(inspectJSON{ID: f.configDigest, Os: "linux", Arch: "amd64", RepoDigests: []string{"example.test/library/synthetic@" + other}})
		_, err := Acquire(context.Background(), f.eng, ref, Options{Platform: "linux/amd64", Policy: PolicyLocal})
		var mismatch *oci.IdentityMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("error = %v, want *oci.IdentityMismatchError", err)
		}
		if !strings.Contains(err.Error(), pinnedDigest) || !strings.Contains(err.Error(), other) {
			t.Errorf("the message must name both digests: %v", err)
		}
		for _, p := range f.savedPaths() {
			if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
				t.Errorf("archive %s must be removed after a failed identity check", p)
			}
		}
	})

	t.Run("missing RepoDigests cannot verify a pin", func(t *testing.T) {
		f := newFixture(t, true, "amd64")
		_, err := Acquire(context.Background(), f.eng, ref, Options{Platform: "linux/amd64", Policy: PolicyLocal})
		var mismatch *oci.IdentityMismatchError
		if !errors.As(err, &mismatch) || !strings.Contains(err.Error(), "no RepoDigests") {
			t.Fatalf("error = %v, want an IDENTITY_MISMATCH explaining the missing RepoDigests", err)
		}
	})
}

func TestEngineImageIDMustMatchConfigDigest(t *testing.T) {
	f := newFixture(t, true, "amd64")
	f.setInspect(inspectJSON{ID: "sha256:" + strings.Repeat("c", 64), Os: "linux", Arch: "amd64"})
	_, err := Acquire(context.Background(), f.eng, "example.test/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyLocal})
	var mismatch *oci.IdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want *oci.IdentityMismatchError", err)
	}
}

func TestPodmanBareHexImageIDIsAccepted(t *testing.T) {
	f := newFixture(t, true, "amd64")
	f.setInspect(inspectJSON{ID: strings.TrimPrefix(f.configDigest, "sha256:"), Os: "linux", Arch: "amd64"})
	res, err := Acquire(context.Background(), f.eng, "example.test/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyLocal})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer res.Close()
	if res.EngineImageID != f.configDigest {
		t.Errorf("engine image id = %q, want normalized %q", res.EngineImageID, f.configDigest)
	}
}

func TestContainerdStoreImageIDInRepoDigestsIsAccepted(t *testing.T) {
	f := newFixture(t, true, "amd64")
	// Docker with the containerd image store reports the target manifest or
	// index digest as the image ID, which is not the config digest.
	id := pinnedDigest
	f.setInspect(inspectJSON{ID: id, Os: "linux", Arch: "amd64", RepoDigests: []string{"example.test/library/synthetic@" + id}})
	res, err := Acquire(context.Background(), f.eng, "example.test/library/synthetic@"+id, Options{Platform: "linux/amd64", Policy: PolicyLocal})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer res.Close()
	if res.EngineImageID != id || res.RegistryDigest != id || res.ConfigDigest != f.configDigest {
		t.Errorf("identity = engine %q registry %q config %q", res.EngineImageID, res.RegistryDigest, res.ConfigDigest)
	}
}

func TestRequestedPlatformMustMatchWhatTheEngineResolved(t *testing.T) {
	f := newFixture(t, true, "arm64")
	_, err := Acquire(context.Background(), f.eng, "example.test/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyLocal})
	var mismatch *oci.PlatformMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want *oci.PlatformMismatchError", err)
	}
	if strings.Contains(f.calls(), "save ") {
		t.Error("nothing may be exported after a platform mismatch")
	}
	// The engine's variant is compared only when both sides state one.
	if err := checkRequestedPlatform("x", "linux/arm64", &engine.ImageInspect{Os: "linux", Architecture: "arm64", Variant: "v8"}); err != nil {
		t.Errorf("a requested platform without variant must accept the engine variant: %v", err)
	}
	if err := checkRequestedPlatform("x", "linux/arm/v7", &engine.ImageInspect{Os: "linux", Architecture: "arm", Variant: "v6"}); err == nil {
		t.Error("conflicting variants must be a mismatch")
	}
}

func TestTagReferenceRegistryDigestOnlyFromAUniqueRepoDigest(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	cases := []struct {
		name        string
		repoDigests []string
		want        string
	}{
		{"none", nil, ""},
		{"one", []string{"docker.io/library/synthetic@" + digestA}, digestA},
		{"two different", []string{"docker.io/library/synthetic@" + digestA, "docker.io/library/synthetic@" + digestB}, ""},
		{"same digest twice", []string{"docker.io/library/synthetic@" + digestA, "index.docker.io/library/synthetic@" + digestA}, digestA},
		{"other repository ignored", []string{"quay.io/other/synthetic@" + digestA}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, true, "amd64")
			f.setInspect(inspectJSON{ID: f.configDigest, Os: "linux", Arch: "amd64", RepoDigests: tc.repoDigests})
			res, err := Acquire(context.Background(), f.eng, "docker.io/library/synthetic:1", Options{Platform: "linux/amd64", Policy: PolicyLocal})
			if err != nil {
				t.Fatalf("Acquire: %v", err)
			}
			defer res.Close()
			if res.RegistryDigest != tc.want {
				t.Errorf("registry digest = %q, want %q", res.RegistryDigest, tc.want)
			}
		})
	}
}

func TestTarballSourceClaimsNoRegistryDigest(t *testing.T) {
	f := newFixture(t, true, "amd64")
	tarPath := os.Getenv("FAKE_ARCHIVE")
	res, err := Acquire(context.Background(), f.eng, tarPath, Options{Platform: "linux/amd64", Policy: PolicyLocal})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer res.Close()
	if res.Source != spec.SourceTarball || res.RegistryDigest != "" || res.ImmutableRef != "" {
		t.Errorf("source=%q registry digest=%q ref=%q, want a tarball without registry claims", res.Source, res.RegistryDigest, res.ImmutableRef)
	}
	if strings.Contains(f.calls(), "save ") {
		t.Error("a tarball input must not trigger an engine export")
	}
}

func TestParsePolicy(t *testing.T) {
	for value, want := range map[string]Policy{"": PolicyAuto, "auto": PolicyAuto, "LOCAL": PolicyLocal, " registry ": PolicyRegistry} {
		if got, err := ParsePolicy(value); err != nil || got != want {
			t.Errorf("ParsePolicy(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
	if _, err := ParsePolicy("cloud"); err == nil {
		t.Error("an unknown policy must be rejected")
	}
}
