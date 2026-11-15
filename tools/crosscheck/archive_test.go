package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name string
	data string
	// dir marks a directory entry.
	dir bool
}

func writeTar(t *testing.T, entries []tarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.tar")
	writeTarAt(t, path, entries)
	return path
}

func writeTarAt(t *testing.T, path string, entries []tarEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
		if e.dir {
			hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeDir, 0, 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if !e.dir {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

const sampleConfig = `{"architecture":"amd64","os":"linux","config":{"User":"app"}}`

func TestArchiveConfigDigest(t *testing.T) {
	cfgName := strings.TrimPrefix(sha(sampleConfig), "sha256:") + ".json"
	manifest := `[{"Config":"` + cfgName + `","RepoTags":["x:1"],"Layers":["l1/layer.tar"]}]`
	cases := []struct {
		name    string
		entries []tarEntry
		want    string
		wantErr string
	}{
		{
			name: "config before manifest, as podman writes it",
			entries: []tarEntry{
				{name: "l1.tar", data: "layer"},
				{name: cfgName, data: sampleConfig},
				{name: "manifest.json", data: manifest},
			},
			want: sha(sampleConfig),
		},
		{
			name: "manifest before config",
			entries: []tarEntry{
				{name: "manifest.json", data: manifest},
				{name: cfgName, data: sampleConfig},
			},
			want: sha(sampleConfig),
		},
		{
			name: "dot slash prefixes are cleaned",
			entries: []tarEntry{
				{name: "./manifest.json", data: manifest},
				{name: "./" + cfgName, data: sampleConfig},
			},
			want: sha(sampleConfig),
		},
		{
			name: "directory entries are ignored",
			entries: []tarEntry{
				{name: "l1/", dir: true},
				{name: "manifest.json", data: manifest},
				{name: cfgName, data: sampleConfig},
			},
			want: sha(sampleConfig),
		},
		{
			name: "the digest comes from the bytes, not from the file name",
			entries: []tarEntry{
				{name: "manifest.json", data: `[{"Config":"renamed.json","Layers":[]}]`},
				{name: "renamed.json", data: sampleConfig},
			},
			want: sha(sampleConfig),
		},
		{
			name: "OCI blob inside a docker save",
			entries: []tarEntry{
				{name: "manifest.json", data: `[{"Config":"blobs/sha256/abc","Layers":[]}]`},
				{name: "blobs/sha256/abc", data: sampleConfig},
			},
			want: sha(sampleConfig),
		},
		{
			name:    "no manifest is not a docker archive",
			entries: []tarEntry{{name: cfgName, data: sampleConfig}},
			wantErr: "no manifest.json",
		},
		{
			name: "two images",
			entries: []tarEntry{
				{name: "manifest.json", data: `[{"Config":"a.json"},{"Config":"b.json"}]`},
				{name: "a.json", data: "{}"}, {name: "b.json", data: "{}"},
			},
			wantErr: "holds 2 images",
		},
		{
			name:    "empty manifest list",
			entries: []tarEntry{{name: "manifest.json", data: "[]"}},
			wantErr: "lists no image",
		},
		{
			name:    "manifest that is not json",
			entries: []tarEntry{{name: "manifest.json", data: "not json"}},
			wantErr: "not valid",
		},
		{
			name:    "manifest without a config name",
			entries: []tarEntry{{name: "manifest.json", data: `[{"Layers":[]}]`}},
			wantErr: "names no config file",
		},
		{
			name: "config file missing from the archive",
			entries: []tarEntry{
				{name: "manifest.json", data: `[{"Config":"gone.json"}]`},
			},
			wantErr: "not in the archive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ArchiveConfigDigest(writeTar(t, tc.entries))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("digest = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestArchiveConfigDigestFileErrors(t *testing.T) {
	if _, err := ArchiveConfigDigest(filepath.Join(t.TempDir(), "absent.tar")); err == nil {
		t.Error("a missing file must be an error")
	}
	notTar := filepath.Join(t.TempDir(), "x.tar")
	if err := os.WriteFile(notTar, []byte(strings.Repeat("this is not a tar archive ", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ArchiveConfigDigest(notTar); err == nil {
		t.Error("a file that is not a tar archive must be an error")
	}
	empty := filepath.Join(t.TempDir(), "empty.tar")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ArchiveConfigDigest(empty); err == nil {
		t.Error("an empty file must be an error")
	}
}

// TestArchiveConfigDigestMatchesFileNameOfPodmanLayout models the layout that
// `podman save --format docker-archive` writes: the config file is named by its
// own digest and manifest.json comes last. The engine-backed test in
// integration_test.go checks the same on a real archive.
func TestArchiveConfigDigestMatchesFileNameOfPodmanLayout(t *testing.T) {
	name := strings.TrimPrefix(sha(sampleConfig), "sha256:")
	entries := []tarEntry{
		{name: "a278e6f39431.tar", data: "layer one"},
		{name: name + ".json", data: sampleConfig},
		{name: "12c824db/layer.tar", data: "layer"},
		{name: "12c824db/VERSION", data: "1.0"},
		{name: "12c824db/json", data: "{}"},
		{name: "manifest.json", data: `[{"Config":"` + name + `.json","RepoTags":["localhost/x:t"],"Layers":["a278e6f39431.tar"]}]`},
	}
	got, err := ArchiveConfigDigest(writeTar(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	if got != "sha256:"+name {
		t.Errorf("digest = %s, want the digest that names the config file", got)
	}
}

func TestNormalizeDigest(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	cases := []struct{ in, want string }{
		{"sha256:" + hex64, "sha256:" + hex64},
		{"SHA256:" + strings.ToUpper(hex64), "sha256:" + hex64},
		{hex64, "sha256:" + hex64},
		{"  sha256:" + hex64 + "\n", "sha256:" + hex64},
		{"", ""},
	}
	for _, tc := range cases {
		if got := NormalizeDigest(tc.in); got != tc.want {
			t.Errorf("NormalizeDigest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
