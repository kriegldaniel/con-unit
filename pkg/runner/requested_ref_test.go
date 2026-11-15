package runner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

// requestedRefProbe is a pack that records the requested reference the runner
// hands to the container, so the tests can see what SPEC-13 would read.
type requestedRefProbe struct {
	conunit.RulePack
	seen *string
}

func (p requestedRefProbe) Apply(c *conunit.Container) {
	*p.seen = c.RequestedRef
	p.RulePack.Apply(c)
}

func TestRunPackHandsTheRequestedReferenceToTheContainer(t *testing.T) {
	t.Run("a local archive has no image reference", func(t *testing.T) {
		eng, _ := makeFakeEngine(t)
		imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
		configDigest := writeRunnerImageTarball(t, imagePath, makeRunnerLayer(t, runnerLayerEntry{name: "app", mode: 0o755, data: []byte("x")}))
		t.Setenv("FAKE_CONFIG_DIGEST", configDigest)

		var seen string
		base, _ := runner.ResolvePack("hygiene")
		pack := requestedRefProbe{RulePack: base.Except("EXEC-01", "EXEC-02", "EXEC-03"), seen: &seen}
		res, err := runner.NewRunner(eng).RunPack(context.Background(), pack, imagePath)
		if err != nil {
			t.Fatalf("RunPack: %v", err)
		}
		if res.ImageSource != spec.SourceTarball {
			t.Fatalf("source = %q, want tarball", res.ImageSource)
		}
		if seen != "" {
			t.Errorf("the container saw requested reference %q for a local archive, want none", seen)
		}
		if res.RequestedRef != imagePath {
			t.Errorf("the result record keeps the path as given, got %q", res.RequestedRef)
		}
	})

	t.Run("a store image keeps the reference as requested", func(t *testing.T) {
		archive := filepath.Join(t.TempDir(), "image-from-store.tar")
		configDigest := writeRunnerImageTarball(t, archive, makeRunnerLayer(t, runnerLayerEntry{name: "usr/bin/tool", mode: 0o755, data: []byte("x")}))
		pinned := "sha256:" + strings.Repeat("a", 64)
		for _, ref := range []string{"example.test/library/tool@" + pinned, "example.test/library/tool:1.2"} {
			eng, _ := storeEngine(t, archive, configDigest, `"example.test/library/tool@`+pinned+`"`)
			var seen string
			base, _ := runner.ResolvePack("hygiene")
			pack := requestedRefProbe{RulePack: base.Except("EXEC-01", "EXEC-02", "EXEC-03"), seen: &seen}
			if _, err := runner.NewRunnerWithOptions(eng, runner.Options{Platform: "linux/amd64", ImageSource: "local"}).RunPack(context.Background(), pack, ref); err != nil {
				t.Fatalf("RunPack(%s): %v", ref, err)
			}
			if seen != ref {
				t.Errorf("the container saw %q, want the reference exactly as requested %q", seen, ref)
			}
		}
	})
}
