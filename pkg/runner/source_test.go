package runner_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

// storeEngine is a fake engine that holds one image and exports it like
// `podman save` would.
func storeEngine(t *testing.T, archive, configDigest string, repoDigests string) (*engine.Engine, string) {
	t.Helper()
	dir := t.TempDir()
	callLog := filepath.Join(dir, "calls")
	script := `#!/bin/sh
printf '%s\n' "$*" >> ` + strconv.Quote(callLog) + `
case "$1:$2" in
  --version:*) echo "podman version 5"; exit 0 ;;
  image:exists) exit 0 ;;
  image:inspect)
    printf '[{"Id":"%s","Os":"linux","Architecture":"amd64","RepoDigests":[` + repoDigests + `],"Config":{"User":"1000","Entrypoint":["/app"]}}]\n' ` + strconv.Quote(configDigest) + `
    exit 0 ;;
esac
if [ "$1" = "save" ]; then
  dest=""
  while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then dest="$2"; fi; shift; done
  cp ` + strconv.Quote(archive) + ` "$dest"
  exit 0
fi
exit 97
`
	path := filepath.Join(dir, "fake-engine")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &engine.Engine{BinaryPath: path}, callLog
}

func TestRunPackRecordsLocalStoreSourceAndPinnedRegistryDigest(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "image-from-store.tar")
	configDigest := writeRunnerImageTarball(t, archive, makeRunnerLayer(t, runnerLayerEntry{name: "usr/bin/tool", mode: 0o755, data: []byte("x")}))
	pinned := "sha256:" + strings.Repeat("a", 64)
	ref := "example.test/library/tool@" + pinned
	eng, callLog := storeEngine(t, archive, configDigest, `"example.test/library/tool@`+pinned+`"`)

	pack, _ := runner.ResolvePack("hygiene")
	pack = pack.Except("EXEC-01", "EXEC-02", "EXEC-03")
	res, err := runner.NewRunnerWithOptions(eng, runner.Options{Platform: "linux/amd64", ImageSource: "local"}).RunPack(context.Background(), pack, ref)
	if err != nil {
		t.Fatalf("RunPack: %v", err)
	}
	if res.ImageSource != spec.SourceLocalStore || res.RequestedRef != ref {
		t.Errorf("source=%q requested=%q, want the local-store source on the record", res.ImageSource, res.RequestedRef)
	}
	if res.ImageDigest != pinned {
		t.Errorf("image digest = %q, want the verified pinned digest %q and never a digest synthesized from the archive", res.ImageDigest, pinned)
	}
	if res.ConfigDigest != configDigest {
		t.Errorf("config digest = %q, want %q", res.ConfigDigest, configDigest)
	}
	for _, r := range res.Results {
		if r.ImageDigest != pinned {
			t.Errorf("result %s carries digest %q, want the pinned digest", r.TestID, r.ImageDigest)
		}
	}
	data, _ := os.ReadFile(callLog)
	if strings.Contains(string(data), "pull") {
		t.Errorf("an image already in the store must not be pulled:\n%s", data)
	}
	if res.Resources.UncompressedBytes < 0 || res.Resources.CompressedBytes != 0 {
		t.Errorf("compressed size is unknown for archive sources and must stay zero, got %+v", res.Resources)
	}
}

func TestRunPackRejectsPinnedDigestAbsentFromRepoDigests(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "image-from-store.tar")
	configDigest := writeRunnerImageTarball(t, archive, nil)
	pinned := "sha256:" + strings.Repeat("a", 64)
	other := "sha256:" + strings.Repeat("b", 64)
	eng, _ := storeEngine(t, archive, configDigest, `"example.test/library/tool@`+other+`"`)

	pack, _ := runner.ResolvePack("hygiene")
	_, err := runner.NewRunnerWithOptions(eng, runner.Options{Platform: "linux/amd64", ImageSource: "local"}).RunPack(context.Background(), pack, "example.test/library/tool@"+pinned)
	var mismatch *oci.IdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want *oci.IdentityMismatchError", err)
	}
	status, reason := runner.ClassifyError(err)
	if status != spec.StatusExecutionError || reason != spec.ReasonIdentityMismatch {
		t.Errorf("classified as %s/%s, want EXECUTION_ERROR/IDENTITY_MISMATCH", status, reason)
	}
	var imageErr *runner.ImageError
	if !errors.As(err, &imageErr) || imageErr.ImageSource != spec.SourceLocalStore {
		t.Errorf("the failure record must still name the local-store source, got %+v", imageErr)
	}
}
