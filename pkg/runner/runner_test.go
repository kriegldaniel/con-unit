package runner_test

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type runnerLayerEntry struct {
	name string
	mode int64
	data []byte
}

func makeRunnerLayer(t *testing.T, entries ...runnerLayerEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     int64(len(entry.data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("Failed writing runner test layer header for %q: %v", entry.name, err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatalf("Failed writing runner test layer data for %q: %v", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Failed closing runner test layer: %v", err)
	}
	return buf.Bytes()
}

func writeRunnerImageTarball(t *testing.T, path string, layerData []byte) string {
	t.Helper()

	layer, err := tarball.LayerFromReader(bytes.NewReader(layerData))
	if err != nil {
		t.Fatalf("Failed creating runner test image layer: %v", err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("Failed creating runner test image: %v", err)
	}
	configFile, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("Failed reading runner test image config: %v", err)
	}
	configFile.Architecture = "amd64"
	configFile.OS = "linux"
	configFile.Config.User = "1000"
	configFile.Config.Entrypoint = []string{"/app"}
	img, err = mutate.ConfigFile(img, configFile)
	if err != nil {
		t.Fatalf("Failed setting runner test image platform: %v", err)
	}
	ref, err := name.ParseReference("example.test/conunit:test")
	if err != nil {
		t.Fatalf("Failed parsing runner test image reference: %v", err)
	}
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatalf("Failed writing runner test image tarball: %v", err)
	}
	configDigest, err := img.ConfigName()
	if err != nil {
		t.Fatalf("Failed reading runner test image config digest: %v", err)
	}
	return configDigest.String()
}

func makeFakeEngine(t *testing.T) (*engine.Engine, string) {
	t.Helper()

	dir := t.TempDir()
	unexpectedCalls := filepath.Join(dir, "unexpected-engine-calls")
	binaryPath := filepath.Join(dir, "fake-engine")
	script := `#!/bin/sh
case "$1:$2" in
  --version:*) echo "fake-engine version 1"; exit 0 ;;
  image:exists) exit 0 ;;
  image:inspect)
    printf '[{"Id":"%s","Os":"%s","Architecture":"%s","RepoTags":[],"Size":0,"Config":{"User":"1000","Entrypoint":["/app"],"Env":[],"ExposedPorts":{}}}]\n' "${FAKE_CONFIG_DIGEST:-sha256:synthetic}" "${FAKE_OS:-linux}" "${FAKE_ARCH:-amd64}"
    exit 0 ;;
esac
printf '%s\n' "$*" >> ` + strconv.Quote(unexpectedCalls) + `
exit 97
`
	if err := os.WriteFile(binaryPath, []byte(script), 0700); err != nil {
		t.Fatalf("Failed writing fake engine: %v", err)
	}
	return &engine.Engine{BinaryPath: binaryPath}, unexpectedCalls
}

func assertNoUnexpectedEngineCalls(t *testing.T, path string) {
	t.Helper()

	calls, err := os.ReadFile(path)
	if err == nil {
		t.Fatalf("Fake engine received unexpected command(s): %s", calls)
	}
	if !os.IsNotExist(err) {
		t.Fatalf("Failed checking fake engine calls: %v", err)
	}
}

func TestResolvePack(t *testing.T) {
	cases := []struct {
		name     string
		expected string
	}{
		{"cis", "PACK-CONUNIT-HARDENING"},
		{"hygiene", "PACK-PROD-HYGIENE"},
		{"kube", "PACK-KUBE-HARDENED"},
		{"nist", "PACK-NIST-800-190"},
		{"distroless", "PACK-DISTROLESS"},
	}

	for _, tc := range cases {
		pack, err := runner.ResolvePack(tc.name)
		if err != nil {
			t.Errorf("ResolvePack(%s) returned error: %v", tc.name, err)
			continue
		}
		if pack.ID() != tc.expected {
			t.Errorf("ResolvePack(%s) expected ID %s, got %s", tc.name, tc.expected, pack.ID())
		}
	}

	// Unknown pack returns error
	_, err := runner.ResolvePack("nonexistent")
	if err == nil {
		t.Error("Expected error for unknown pack name, got nil")
	}
}

func TestRunPack(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
	configDigest := writeRunnerImageTarball(t, imagePath, makeRunnerLayer(t, runnerLayerEntry{
		name: "usr/bin/gcc",
		mode: 0755,
		data: []byte("synthetic compiler"),
	}))
	t.Setenv("FAKE_CONFIG_DIGEST", configDigest)

	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack failed: %v", err)
	}
	pack = pack.Except("EXEC-01", "EXEC-02", "EXEC-03")

	res, err := runner.NewRunner(eng).RunPack(context.Background(), pack, imagePath)
	if err != nil {
		t.Fatalf("RunPack failed: %v", err)
	}

	if res.ImageName != imagePath {
		t.Errorf("Expected image name %s, got %s", imagePath, res.ImageName)
	}
	if res.Total == 0 {
		t.Error("Expected evaluated assertions, got total 0")
	}
	if res.ImageDigest != "" || res.ConfigDigest != configDigest || res.Platform != "linux/amd64" {
		t.Errorf("Expected result identity to match the resolved OCI image without a registry digest, got digest=%q config=%q platform=%q", res.ImageDigest, res.ConfigDigest, res.Platform)
	}
	if res.ImageSource != "tarball" || res.RequestedRef != imagePath {
		t.Errorf("Expected the record to state its tarball source and requested ref, got source=%q ref=%q", res.ImageSource, res.RequestedRef)
	}
	foundCompilerCheck := false
	for _, result := range res.Results {
		if result.ImageDigest != res.ImageDigest || result.ConfigDigest != res.ConfigDigest || result.Platform != res.Platform {
			t.Errorf("Assertion %s is not bound to suite image identity: %+v", result.TestID, result)
		}
		if result.TestID == "FS-03" {
			foundCompilerCheck = true
			if result.Passed {
				t.Error("Expected the OCI index to report the synthetic compiler binary")
			}
		}
	}
	if !foundCompilerCheck {
		t.Error("Expected RunPack to include the compiler filesystem check")
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}

func TestRunPackMarksEmptyPackUnverified(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath := filepath.Join(t.TempDir(), "empty-pack.tar")
	configDigest := writeRunnerImageTarball(t, imagePath, nil)
	t.Setenv("FAKE_CONFIG_DIGEST", configDigest)

	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack failed: %v", err)
	}
	pack = pack.Except("SPEC-01", "SPEC-02", "SPEC-03", "FS-01", "FS-03", "FS-04", "EXEC-01", "EXEC-02", "EXEC-03")
	result, err := runner.NewRunner(eng).RunPack(context.Background(), pack, imagePath)
	if err != nil {
		t.Fatalf("RunPack returned error: %v", err)
	}
	if result.Total != 1 || result.Passed != 0 || result.Failed != 0 || result.Unverified != 1 {
		t.Fatalf("empty pack counts = total:%d passed:%d failed:%d unverified:%d, want one unverified result", result.Total, result.Passed, result.Failed, result.Unverified)
	}
	if len(result.Results) != 1 || result.Results[0].EffectiveOutcome() != "UNVERIFIED" {
		t.Fatalf("empty pack results = %+v, want one UNVERIFIED result", result.Results)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}

func TestRunPackRejectsEngineOCIIdentityMismatch(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
	configDigest := writeRunnerImageTarball(t, imagePath, nil)
	t.Setenv("FAKE_CONFIG_DIGEST", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack failed: %v", err)
	}
	_, err = runner.NewRunner(eng).RunPack(context.Background(), pack.Except("EXEC-01", "EXEC-02", "EXEC-03"), imagePath)
	if err == nil || !strings.Contains(err.Error(), "image identity mismatch") {
		t.Fatalf("RunPack error = %v, want engine/OCI identity mismatch (OCI config %s)", err, configDigest)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}

func TestRunPackRejectsPlatformMismatch(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
	configDigest := writeRunnerImageTarball(t, imagePath, nil)
	t.Setenv("FAKE_CONFIG_DIGEST", configDigest)
	t.Setenv("FAKE_OS", "windows")

	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack failed: %v", err)
	}
	_, err = runner.NewRunner(eng).RunPack(context.Background(), pack.Except("EXEC-01", "EXEC-02", "EXEC-03"), imagePath)
	if err == nil || !strings.Contains(err.Error(), "platform mismatch") {
		t.Fatalf("RunPack error = %v, want platform mismatch", err)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}

func TestRunPackPropagatesResolveError(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack failed: %v", err)
	}
	pack = pack.Except("EXEC-01", "EXEC-02", "EXEC-03")

	res, err := runner.NewRunner(eng).RunPack(context.Background(), pack, "not a valid image reference")
	if err == nil {
		t.Fatal("Expected RunPack to propagate OCI image resolution failure")
	}
	if res != nil {
		t.Errorf("Expected no suite result when OCI image resolution fails, got: %+v", res)
	}
	if !strings.Contains(err.Error(), "failed resolving OCI image") {
		t.Errorf("Expected resolve-stage error, got: %v", err)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}

func TestRunPackPropagatesIndexError(t *testing.T) {
	eng, unexpectedCalls := makeFakeEngine(t)
	imagePath := filepath.Join(t.TempDir(), "invalid-layer.tar")
	configDigest := writeRunnerImageTarball(t, imagePath, bytes.Repeat([]byte("x"), 512))
	t.Setenv("FAKE_CONFIG_DIGEST", configDigest)

	pack, err := runner.ResolvePack("hygiene")
	if err != nil {
		t.Fatalf("ResolvePack failed: %v", err)
	}
	pack = pack.Except("EXEC-01", "EXEC-02", "EXEC-03")

	res, err := runner.NewRunner(eng).RunPack(context.Background(), pack, imagePath)
	if err == nil {
		t.Fatal("Expected RunPack to propagate OCI filesystem indexing failure")
	}
	if res != nil {
		t.Errorf("Expected no suite result when OCI filesystem indexing fails, got: %+v", res)
	}
	if !strings.Contains(err.Error(), "failed indexing OCI filesystem") {
		t.Errorf("Expected index-stage error, got: %v", err)
	}
	assertNoUnexpectedEngineCalls(t, unexpectedCalls)
}
