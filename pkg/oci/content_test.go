package oci

import (
	"archive/tar"
	"testing"
)

func dirEntry(name string) testLayerEntry {
	return testLayerEntry{name: name, mode: 0755, typeflag: tar.TypeDir}
}

func TestHasContentAtTreatsEmptyDirectoriesAsEmpty(t *testing.T) {
	cases := []struct {
		name   string
		layers [][]testLayerEntry
		path   string
		want   bool
	}{
		{
			name:   "empty directory",
			layers: [][]testLayerEntry{{dirEntry("var/cache/apk/")}},
			path:   "/var/cache/apk",
			want:   false,
		},
		{
			name:   "directory with a file",
			layers: [][]testLayerEntry{{dirEntry("var/cache/apk/"), {name: "var/cache/apk/APKINDEX.tar.gz", mode: 0644, data: []byte("x")}}},
			path:   "/var/cache/apk",
			want:   true,
		},
		{
			name:   "directory with a file in a nested directory",
			layers: [][]testLayerEntry{{dirEntry("var/cache/apt/"), dirEntry("var/cache/apt/archives/"), {name: "var/cache/apt/archives/pkg.deb", mode: 0644, data: []byte("x")}}},
			path:   "/var/cache/apt",
			want:   true,
		},
		{
			name:   "directory with only empty directories below",
			layers: [][]testLayerEntry{{dirEntry("var/cache/apt/"), dirEntry("var/cache/apt/archives/"), dirEntry("var/cache/apt/archives/partial/")}},
			path:   "/var/cache/apt",
			want:   false,
		},
		{
			name:   "directory with a link below",
			layers: [][]testLayerEntry{{dirEntry("root/.cache/"), {name: "root/.cache/latest", mode: 0777, typeflag: tar.TypeSymlink, linkname: "elsewhere"}}},
			path:   "/root/.cache",
			want:   true,
		},
		{
			name:   "regular file",
			layers: [][]testLayerEntry{{{name: ".env", mode: 0644, data: []byte("A=1")}}},
			path:   "/.env",
			want:   true,
		},
		{
			name:   "empty regular file still counts as a file",
			layers: [][]testLayerEntry{{{name: ".env", mode: 0644}}},
			path:   "/.env",
			want:   true,
		},
		{
			name:   "symbolic link",
			layers: [][]testLayerEntry{{{name: ".git", mode: 0777, typeflag: tar.TypeSymlink, linkname: "/data/git"}}},
			path:   "/.git",
			want:   true,
		},
		{
			name:   "absent path",
			layers: [][]testLayerEntry{{dirEntry("var/")}},
			path:   "/var/cache/apk",
			want:   false,
		},
		{
			name: "files removed by a whiteout leave an empty directory",
			layers: [][]testLayerEntry{
				{dirEntry("var/lib/apt/lists/"), {name: "var/lib/apt/lists/deb.debian.org_Packages", mode: 0644, data: []byte("x")}},
				{{name: "var/lib/apt/lists/.wh.deb.debian.org_Packages", mode: 0644}},
			},
			path: "/var/lib/apt/lists",
			want: false,
		},
		{
			name: "an opaque directory in a later layer empties the directory",
			layers: [][]testLayerEntry{
				{dirEntry("var/cache/apt/"), {name: "var/cache/apt/pkgcache.bin", mode: 0644, data: []byte("x")}},
				{dirEntry("var/cache/apt/"), {name: "var/cache/apt/.wh..wh..opq", mode: 0644}},
			},
			path: "/var/cache/apt",
			want: false,
		},
		{
			name: "a file added in a later layer fills the directory",
			layers: [][]testLayerEntry{
				{dirEntry("var/cache/apk/")},
				{{name: "var/cache/apk/APKINDEX.tar.gz", mode: 0644, data: []byte("x")}},
			},
			path: "/var/cache/apk",
			want: true,
		},
		{
			name: "an empty lock file below a directory does not fill it (apt after a cleaned install)",
			layers: [][]testLayerEntry{{
				dirEntry("var/cache/apt/"),
				dirEntry("var/cache/apt/archives/"),
				{name: "var/cache/apt/archives/lock", mode: 0640},
				dirEntry("var/cache/apt/archives/partial/"),
			}},
			path: "/var/cache/apt",
			want: false,
		},
		{
			name: "an empty file next to a file with bytes still fills the directory",
			layers: [][]testLayerEntry{{
				dirEntry("var/cache/apt/"),
				dirEntry("var/cache/apt/archives/"),
				{name: "var/cache/apt/archives/lock", mode: 0640},
				{name: "var/cache/apt/archives/curl.deb", mode: 0644, data: []byte("x")},
			}},
			path: "/var/cache/apt",
			want: true,
		},
		{
			name: "a hard link below a directory counts even though its own entry has no bytes",
			layers: [][]testLayerEntry{{
				{name: "srv/data", mode: 0644, data: []byte("x")},
				dirEntry("root/.cache/"),
				{name: "root/.cache/data", mode: 0644, typeflag: tar.TypeLink, linkname: "srv/data"},
			}},
			path: "/root/.cache",
			want: true,
		},
		{
			name: "an empty file that a later layer fills with bytes fills the directory",
			layers: [][]testLayerEntry{
				{dirEntry("var/cache/apt/"), {name: "var/cache/apt/state", mode: 0644}},
				{{name: "var/cache/apt/state", mode: 0644, data: []byte("x")}},
			},
			path: "/var/cache/apt",
			want: true,
		},
		{
			name: "a file that a later layer truncates to zero bytes no longer fills the directory",
			layers: [][]testLayerEntry{
				{dirEntry("var/cache/apt/"), {name: "var/cache/apt/state", mode: 0644, data: []byte("x")}},
				{{name: "var/cache/apt/state", mode: 0644}},
			},
			path: "/var/cache/apt",
			want: false,
		},
		{
			name:   "a directory that only shares a name prefix does not count",
			layers: [][]testLayerEntry{{dirEntry("var/cache/apk/"), {name: "var/cache/apk-old/index", mode: 0644, data: []byte("x")}}},
			path:   "/var/cache/apk",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			index, err := (&ImageReader{Image: makeTestImage(t, buildLayers(t, tc.layers)...)}).StreamAndIndexFilesystem()
			if err != nil {
				t.Fatalf("StreamAndIndexFilesystem: %v", err)
			}
			if got := index.HasContentAt(tc.path); got != tc.want {
				t.Errorf("HasContentAt(%q) = %t, want %t (paths: %v)", tc.path, got, tc.want, index.Paths)
			}
		})
	}
}

func TestHasContentAtOnAHandBuiltIndex(t *testing.T) {
	index := &FilesystemIndex{Paths: map[string]bool{"/var/cache/apk": true}}
	if !index.HasContentAt("/var/cache/apk") {
		t.Error("without directory types every existing path must count")
	}
	if index.HasContentAt("/var/cache/other") {
		t.Error("an absent path never counts")
	}
	withDirs := &FilesystemIndex{
		Paths: map[string]bool{"/var/cache/apk": true},
		Dirs:  map[string]struct{}{"/var/cache/apk": {}},
	}
	if withDirs.HasContentAt("/var/cache/apk") {
		t.Error("a known empty directory must not count")
	}
	withEmptyFile := &FilesystemIndex{
		Paths:      map[string]bool{"/var/cache/apt": true, "/var/cache/apt/lock": true},
		Dirs:       map[string]struct{}{"/var/cache/apt": {}},
		EmptyFiles: map[string]struct{}{"/var/cache/apt/lock": {}},
	}
	if withEmptyFile.HasContentAt("/var/cache/apt") {
		t.Error("a directory with only a known empty file must not count")
	}
	if !withEmptyFile.HasContentAt("/var/cache/apt/lock") {
		t.Error("an empty file asked for by its own path still counts")
	}
	withoutEmptyInfo := &FilesystemIndex{
		Paths: map[string]bool{"/var/cache/apt": true, "/var/cache/apt/lock": true},
		Dirs:  map[string]struct{}{"/var/cache/apt": {}},
	}
	if !withoutEmptyInfo.HasContentAt("/var/cache/apt") {
		t.Error("a file of unknown size must count")
	}
}
