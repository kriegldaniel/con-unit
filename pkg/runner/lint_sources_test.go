package runner_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

var lintPackMembers = []string{
	"SPEC-01", "CIS-4.6", "FS-04", "SPEC-07", "SPEC-03", "FS-06", "FS-08", "FS-01",
	"SPEC-09", "SPEC-10", "SPEC-11", "SPEC-12", "SPEC-13", "FS-10", "FS-11", "FS-12",
}

type lintTestFile struct {
	name     string
	typeflag byte
	data     string
}

func lintLayer(t *testing.T, files []lintTestFile) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		typeflag := f.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: f.name, Mode: 0o644, Typeflag: typeflag}
		if typeflag == tar.TypeDir {
			header.Mode = 0o755
		} else {
			header.Size = int64(len(f.data))
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(f.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// lintImage is a small image. With defects it fails SPEC-09, SPEC-10, SPEC-11,
// SPEC-12, FS-10, FS-11 and FS-12; without them it passes those seven checks.
func lintImage(t *testing.T, defects bool) v1.Image {
	t.Helper()
	passwd := "root:x:0:0:root:/root:/bin/sh\napp:x:10001:10001:app:/app:/sbin/nologin\n"
	files := []lintTestFile{
		{name: "etc/", typeflag: tar.TypeDir}, {name: "app/", typeflag: tar.TypeDir},
		{name: "etc/group", data: "root:x:0:\napp:x:10001:\n"},
		{name: "app/main", data: "binary"},
	}
	history := []v1.History{
		{CreatedBy: "ADD alpine-minirootfs.tar.gz / # buildkit"},
		{CreatedBy: "RUN /bin/sh -c apt-get update && apt-get install -y --no-install-recommends curl # buildkit"},
		{CreatedBy: `CMD ["/app/main"]`, EmptyLayer: true},
	}
	var volumes map[string]struct{}
	if defects {
		passwd += "toor:x:0:0:toor:/root:/bin/sh\n"
		files = append(files, lintTestFile{name: "app/.git/config", data: "[core]"}, lintTestFile{name: "app/config/credentials.json", data: "{}"})
		history = append(history,
			v1.History{CreatedBy: "RUN /bin/sh -c apt-get update # buildkit"},
			v1.History{CreatedBy: "RUN /bin/sh -c sudo make install # buildkit"},
			v1.History{CreatedBy: "RUN /bin/sh -c apt-get dist-upgrade -y # buildkit"})
		volumes = map[string]struct{}{"/sys": {}}
	}
	files = append(files, lintTestFile{name: "etc/passwd", data: passwd})

	img, err := mutate.AppendLayers(empty.Image, lintLayer(t, files))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = "linux", "amd64"
	cfg.History = history
	cfg.Config.User = "10001"
	cfg.Config.Volumes = volumes
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// lintFakeEngine answers the three calls that acquiring an image needs, exports
// an archive for `save`, logs every call and fails anything else with exit
// code 97, so that a probe container would show up in the log and as a failure.
func lintFakeEngine(t *testing.T, img v1.Image, archive string) (*engine.Engine, string) {
	t.Helper()
	configDigest, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	inspect, err := json.Marshal([]map[string]any{{
		"Id": configDigest.String(), "Os": "linux", "Architecture": "amd64", "RepoTags": []string{}, "RepoDigests": []string{},
		"Config": map[string]any{"User": cfg.Config.User, "Env": cfg.Config.Env, "Volumes": cfg.Config.Volumes, "Entrypoint": []string{"/app/main"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inspectFile, callLog := filepath.Join(dir, "inspect.json"), filepath.Join(dir, "calls")
	if err := os.WriteFile(inspectFile, inspect, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\n' "$*" >> ` + strconv.Quote(callLog) + `
case "$1:$2" in
  --version:*) echo "podman version 5"; exit 0 ;;
  image:exists) exit 0 ;;
  image:inspect) cat ` + strconv.Quote(inspectFile) + `; exit 0 ;;
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

func writeLintArchive(t *testing.T, img v1.Image, tag string) string {
	t.Helper()
	ref, err := name.NewTag(tag)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolvePackSelectsTheLintPackByBothNames(t *testing.T) {
	for _, requested := range []string{"lint", "image-lint", " Lint ", "pack=lint", `"image-lint"`} {
		pack, err := runner.ResolvePack(requested)
		if err != nil {
			t.Errorf("ResolvePack(%q): %v", requested, err)
			continue
		}
		if pack.ID() != "PACK-IMAGE-LINT" || pack.Name() != "Image Static Lint Pack" {
			t.Errorf("ResolvePack(%q) = %s / %s", requested, pack.ID(), pack.Name())
		}
	}
	if _, err := runner.ResolvePack("lints"); err == nil {
		t.Error("a near miss must not resolve to the lint pack")
	}
}

func TestLintPackRunsOnEveryImageSource(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")

	type source struct {
		name   string
		source string
		// run returns the engine, the image reference and the options for one
		// image, and the outcome SPEC-13 must have for it.
		prepare func(t *testing.T, img v1.Image, defects bool) (*engine.Engine, string, runner.Options, string, spec.Outcome)
	}
	sources := []source{
		{"tarball", spec.SourceTarball, func(t *testing.T, img v1.Image, defects bool) (*engine.Engine, string, runner.Options, string, spec.Outcome) {
			archive := writeLintArchive(t, img, "example.test/app:1.0")
			eng, log := lintFakeEngine(t, img, "")
			// A local archive has no image reference.
			return eng, archive, runner.Options{Platform: "linux/amd64"}, log, spec.OutcomeUnverified
		}},
		{"local-store", spec.SourceLocalStore, func(t *testing.T, img v1.Image, defects bool) (*engine.Engine, string, runner.Options, string, spec.Outcome) {
			ref, want := "example.test/app:1.0", spec.OutcomePass
			if defects {
				ref, want = "example.test/app:latest", spec.OutcomeFail
			}
			eng, log := lintFakeEngine(t, img, writeLintArchive(t, img, ref))
			return eng, ref, runner.Options{Platform: "linux/amd64", ImageSource: "local"}, log, want
		}},
		{"registry", spec.SourceRegistry, func(t *testing.T, img v1.Image, defects bool) (*engine.Engine, string, runner.Options, string, spec.Outcome) {
			repository, tag, want := "lint/control", "1.0", spec.OutcomePass
			if defects {
				repository, tag, want = "lint/defect", "latest", spec.OutcomeFail
			}
			ref := host + "/" + repository + ":" + tag
			parsed, err := name.ParseReference(ref)
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(parsed, img); err != nil {
				t.Fatalf("push to the in-process registry: %v", err)
			}
			eng, log := lintFakeEngine(t, img, "")
			return eng, ref, runner.Options{Platform: "linux/amd64", ImageSource: "registry"}, log, want
		}},
	}

	for _, src := range sources {
		for _, defects := range []bool{false, true} {
			label := src.name + "/control"
			if defects {
				label = src.name + "/defects"
			}
			t.Run(label, func(t *testing.T) {
				img := lintImage(t, defects)
				eng, ref, options, log, wantSPEC13 := src.prepare(t, img, defects)
				pack, err := runner.ResolvePack("lint")
				if err != nil {
					t.Fatal(err)
				}
				res, err := runner.NewRunnerWithOptions(eng, options).RunPack(context.Background(), pack, ref)
				if err != nil {
					t.Fatalf("RunPack: %v", err)
				}
				if res.ImageSource != src.source {
					t.Errorf("image source = %q, want %q", res.ImageSource, src.source)
				}
				ids := make([]string, 0, len(res.Results))
				outcomes := map[string]spec.Outcome{}
				for _, r := range res.Results {
					ids = append(ids, r.TestID)
					outcomes[r.TestID] = r.EffectiveOutcome()
					if r.Tier != spec.TierSpec && r.Tier != spec.TierFilesystem {
						t.Errorf("%s is a %v result, but the lint pack is static", r.TestID, r.Tier)
					}
				}
				if !slices.Equal(ids, lintPackMembers) {
					t.Fatalf("results = %v, want the members of the pack in order %v", ids, lintPackMembers)
				}

				wantFixed := spec.OutcomePass
				if defects {
					wantFixed = spec.OutcomeFail
				}
				for _, id := range []string{"SPEC-09", "SPEC-10", "SPEC-11", "SPEC-12", "FS-10", "FS-11", "FS-12"} {
					if outcomes[id] != wantFixed {
						t.Errorf("%s = %s on the %s image from the %s source, want %s", id, outcomes[id], strings.TrimPrefix(label, src.name+"/"), src.name, wantFixed)
					}
				}
				if outcomes["SPEC-13"] != wantSPEC13 {
					t.Errorf("SPEC-13 = %s from the %s source, want %s", outcomes["SPEC-13"], src.name, wantSPEC13)
				}
				if src.name == "tarball" {
					for _, r := range res.Results {
						if r.TestID == "SPEC-13" && r.Reason != spec.ReasonEvidenceIncomplete {
							t.Errorf("SPEC-13 reason = %q for a local archive, want EVIDENCE_INCOMPLETE", r.Reason)
						}
					}
				}

				// The pack is static: acquiring the image may ask the engine
				// whether it holds the image, inspect it and export it, and
				// nothing else, so no container was ever created.
				calls, _ := os.ReadFile(log)
				for _, call := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
					fields := strings.Fields(call)
					if len(fields) == 0 {
						continue
					}
					switch {
					case fields[0] == "--version", fields[0] == "save":
					case len(fields) > 1 && fields[0] == "image" && (fields[1] == "exists" || fields[1] == "inspect"):
					default:
						t.Errorf("the lint pack caused the engine call %q", call)
					}
				}
			})
		}
	}
}
