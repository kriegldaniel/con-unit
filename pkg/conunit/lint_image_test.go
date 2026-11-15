package conunit_test

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// layerFile is one entry of a test layer. A zero typeflag is a regular file.
type layerFile struct {
	name     string
	mode     int64
	typeflag byte
	linkname string
	data     string
}

func fileEntry(name, data string) layerFile { return layerFile{name: name, mode: 0o644, data: data} }
func dirEntry(name string) layerFile {
	return layerFile{name: name, mode: 0o755, typeflag: tar.TypeDir}
}
func whiteoutEntry(dirName, base string) layerFile {
	return layerFile{name: dirName + "/.wh." + base, mode: 0o644}
}

func buildLayer(t *testing.T, files []layerFile) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		typeflag := f.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), Typeflag: typeflag, Linkname: f.linkname}
		if typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("layer header %q: %v", f.name, err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(f.data)); err != nil {
				t.Fatalf("layer data %q: %v", f.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close layer: %v", err)
	}
	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("layer: %v", err)
	}
	return layer
}

// imageSpec describes a small image: its layers, its history and the parts of
// the config that the lint checks read.
type imageSpec struct {
	layers  [][]layerFile
	history []v1.History
	user    string
	env     []string
	volumes []string
	// ref is the requested reference handed to SPEC-13.
	ref string
}

// runHistory writes a history in the BuildKit form: a command becomes
// 'RUN <command> # buildkit', and an entry that starts with ENV, CMD, ADD, COPY
// or a hash stays as given and is flagged as an empty layer.
func runHistory(commands ...string) []v1.History {
	history := make([]v1.History, 0, len(commands))
	for _, command := range commands {
		isRun := !strings.HasPrefix(command, "ENV ") && !strings.HasPrefix(command, "CMD ") && !strings.HasPrefix(command, "ADD ") &&
			!strings.HasPrefix(command, "COPY ") && !strings.HasPrefix(command, "#")
		createdBy := command
		if isRun {
			createdBy = "RUN " + command + " # buildkit"
		}
		history = append(history, v1.History{CreatedBy: createdBy, EmptyLayer: !isRun})
	}
	return history
}

func (s imageSpec) build(t *testing.T) v1.Image {
	t.Helper()
	img := v1.Image(empty.Image)
	for _, files := range s.layers {
		var err error
		img, err = mutate.AppendLayers(img, buildLayer(t, files))
		if err != nil {
			t.Fatalf("append layer: %v", err)
		}
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = "linux", "amd64"
	cfg.History = s.history
	cfg.Config.User = s.user
	cfg.Config.Env = s.env
	if len(s.volumes) > 0 {
		cfg.Config.Volumes = map[string]struct{}{}
		for _, volume := range s.volumes {
			cfg.Config.Volumes[volume] = struct{}{}
		}
	}
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatalf("set config: %v", err)
	}
	return img
}

// container indexes the image the way the runner does and fills the engine
// inspection data from the same config, so the checks see what they would see
// in a run.
func (s imageSpec) container(t *testing.T) *conunit.Container {
	t.Helper()
	img := s.build(t)
	index, err := (&oci.ImageReader{Image: img}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	inspect := &engine.ImageInspect{Config: engine.ImageConfig{User: s.user, Env: s.env}}
	if len(s.volumes) > 0 {
		inspect.Config.Volumes = map[string]struct{}{}
		for _, volume := range s.volumes {
			inspect.Config.Volumes[volume] = struct{}{}
		}
	}
	return &conunit.Container{Inspect: inspect, OCIIndex: index, RequestedRef: s.ref}
}

const digestRef = "example.test/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// cleanSpec is the control image: all eight lint checks pass on it, and each
// seeded defect changes one aspect of it.
func cleanSpec() imageSpec {
	return imageSpec{
		layers: [][]layerFile{{
			dirEntry("etc/"), dirEntry("app/"),
			fileEntry("etc/passwd", "root:x:0:0:root:/root:/bin/sh\napp:x:10001:10001:app:/app:/sbin/nologin\n"),
			fileEntry("etc/group", "root:x:0:\napp:x:10001:\n"),
			fileEntry("app/main", "binary"),
		}},
		history: runHistory(
			"ADD alpine-minirootfs.tar.gz /",
			"apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*",
			`CMD ["/app/main"]`,
		),
		user: "10001",
		env:  []string{"PATH=/usr/local/bin:/usr/bin"},
		ref:  digestRef,
	}
}
