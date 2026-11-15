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

// tarMember is one member of a test archive.
type tarMember struct {
	name string
	body string
	typ  byte // 0 means a regular file
}

// writeTar writes a tar file with the given members into dir and returns its
// path.
func writeTar(t *testing.T, dir string, members []tarMember) string {
	t.Helper()
	path := filepath.Join(dir, "image.tar")
	writeTarFile(t, path, members)
	return path
}

// writeTarFile writes a tar file with the given members to path.
func writeTarFile(t *testing.T, path string, members []tarMember) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, m := range members {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: m.name, Mode: 0o644, Typeflag: typ}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(m.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

func digestOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// dockerArchive returns the members of a docker-archive holding one image
// whose config is the given JSON, named by its digest as podman does.
func dockerArchive(config string) ([]tarMember, string) {
	hexDigest := digestOf(config)
	manifest := `[{"Config":"` + hexDigest + `.json","RepoTags":["localhost/x:rq1"],"Layers":["layer0/layer.tar"]}]`
	return []tarMember{
		{name: hexDigest + ".json", body: config},
		{name: "layer0/layer.tar", body: strings.Repeat("x", 600)},
		{name: "manifest.json", body: manifest},
	}, hexDigest
}

func TestReadArchiveConfigDigest(t *testing.T) {
	const config = `{"architecture":"arm64","config":{"User":"10001"}}`
	good, goodHex := dockerArchive(config)

	cases := []struct {
		name       string
		members    []tarMember
		wantDigest string
		wantName   string
		wantMiss   bool
		wantErr    string
	}{
		{name: "podman docker-archive", members: good, wantDigest: "sha256:" + goodHex, wantName: goodHex + ".json"},
		{
			name: "member names with a dot slash prefix",
			members: []tarMember{
				{name: "./" + goodHex + ".json", body: config},
				{name: "./manifest.json", body: `[{"Config":"./` + goodHex + `.json"}]`},
			},
			wantDigest: "sha256:" + goodHex, wantName: goodHex + ".json",
		},
		{
			name: "config in a blobs directory, named by a hex digest without extension",
			members: []tarMember{
				{name: "blobs/sha256/" + goodHex, body: config},
				{name: "manifest.json", body: `[{"Config":"blobs/sha256/` + goodHex + `"}]`},
			},
			wantDigest: "sha256:" + goodHex, wantName: "blobs/sha256/" + goodHex,
		},
		{
			name: "config name that is not a digest",
			members: []tarMember{
				{name: "config.json", body: config},
				{name: "manifest.json", body: `[{"Config":"config.json"}]`},
			},
			wantDigest: "sha256:" + goodHex, wantName: "config.json",
		},
		{
			name: "digest is computed from the content, a wrong name is reported",
			members: []tarMember{
				{name: strings.Repeat("a", 64) + ".json", body: config},
				{name: "manifest.json", body: `[{"Config":"` + strings.Repeat("a", 64) + `.json"}]`},
			},
			wantDigest: "sha256:" + goodHex, wantName: strings.Repeat("a", 64) + ".json", wantMiss: true,
		},
		{
			name: "directory members and links are ignored",
			members: append([]tarMember{
				{name: "layer0/", typ: tar.TypeDir},
				{name: "latest.json", typ: tar.TypeSymlink},
			}, good...),
			wantDigest: "sha256:" + goodHex, wantName: goodHex + ".json",
		},
		{name: "no manifest", members: []tarMember{{name: goodHex + ".json", body: config}}, wantErr: "no manifest.json"},
		{name: "empty archive", members: nil, wantErr: "no manifest.json"},
		{
			name:    "manifest that is not JSON",
			members: []tarMember{{name: "manifest.json", body: "not json"}},
			wantErr: "manifest.json is not valid",
		},
		{name: "manifest without an image", members: []tarMember{{name: "manifest.json", body: "[]"}}, wantErr: "lists no image"},
		{
			name: "manifest with two images",
			members: []tarMember{
				{name: "a.json", body: config},
				{name: "manifest.json", body: `[{"Config":"a.json"},{"Config":"a.json"}]`},
			},
			wantErr: "lists 2 images",
		},
		{
			name:    "manifest entry without a config",
			members: []tarMember{{name: "manifest.json", body: `[{"Layers":[]}]`}},
			wantErr: "names no config member",
		},
		{
			name:    "config member that is missing",
			members: []tarMember{{name: "manifest.json", body: `[{"Config":"gone.json"}]`}},
			wantErr: "is not in the archive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTar(t, t.TempDir(), tc.members)
			rec, err := ReadArchiveConfigDigest(path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if rec.ConfigDigest != "" {
					t.Errorf("a failed read must not report a digest, got %s", rec.ConfigDigest)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rec.ConfigDigest != tc.wantDigest || rec.ConfigName != tc.wantName || rec.Format != "docker-archive" {
				t.Errorf("record = %+v, want digest %s name %s", rec, tc.wantDigest, tc.wantName)
			}
			if got := rec.NameMismatch != ""; got != tc.wantMiss {
				t.Errorf("name mismatch reported = %t (%q), want %t", got, rec.NameMismatch, tc.wantMiss)
			}
			if rec.SizeBytes <= 0 {
				t.Errorf("size = %d, want the size of the archive file", rec.SizeBytes)
			}
		})
	}

	t.Run("not a tar file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.tar")
		if err := os.WriteFile(path, []byte(strings.Repeat("not a tar archive\n", 80)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadArchiveConfigDigest(path); err == nil {
			t.Error("a file that is not a tar archive must be an error")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if _, err := ReadArchiveConfigDigest(filepath.Join(t.TempDir(), "absent.tar")); err == nil {
			t.Error("a missing archive must be an error")
		}
	})
}

func TestNormalizeDigest(t *testing.T) {
	h := strings.Repeat("ab", 32)
	cases := []struct {
		in, want string
	}{
		{"sha256:" + h, "sha256:" + h},
		{h, "sha256:" + h},
		{"  sha256:" + h + "\n", "sha256:" + h},
		{"sha256:" + strings.ToUpper(h), "sha256:" + h},
		{"", ""},
		{"sha256:", ""},
		{"sha256:" + h[:63], ""},
		{"sha256:" + h + "0", ""},
		{"sha256:" + strings.Repeat("zz", 32), ""},
		{"sha512:" + h, ""},
	}
	for _, tc := range cases {
		if got := normalizeDigest(tc.in); got != tc.want {
			t.Errorf("normalizeDigest(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
