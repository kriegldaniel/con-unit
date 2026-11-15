package oci

import (
	"archive/tar"
	"bytes"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestParseGroupContent(t *testing.T) {
	cases := []struct {
		name        string
		content     string
		want        map[string][]uint32
		errContains string
	}{
		{
			name:    "plain records",
			content: "root:x:0:\nbin:x:1:daemon\nstaff:x:50:alice,bob\n",
			want:    map[string][]uint32{"root": {0}, "bin": {1}, "staff": {50}},
		},
		{
			name:    "comments, blank lines and carriage returns are skipped",
			content: "# comment\r\n\r\nroot:x:0:\r\n   \nwheel:x:10:\r\n",
			want:    map[string][]uint32{"root": {0}, "wheel": {10}},
		},
		{
			name:    "a repeated name keeps both GIDs",
			content: "dup:x:5:\ndup:x:6:\n",
			want:    map[string][]uint32{"dup": {5, 6}},
		},
		{
			name:    "no trailing newline",
			content: "root:x:0:",
			want:    map[string][]uint32{"root": {0}},
		},
		{
			name:    "largest 32 bit GID",
			content: "big:x:4294967295:\n",
			want:    map[string][]uint32{"big": {4294967295}},
		},
		{
			name:        "empty file",
			content:     "",
			want:        map[string][]uint32{},
			errContains: "no group records",
		},
		{
			name:        "only comments",
			content:     "# nothing\n\n",
			want:        map[string][]uint32{},
			errContains: "no group records",
		},
		{
			name:        "too few fields",
			content:     "root:x:0:\nbroken:x:5\n",
			want:        map[string][]uint32{"root": {0}},
			errContains: "line 2 has an invalid record",
		},
		{
			name:        "too many fields",
			content:     "root:x:0:a:b\n",
			want:        map[string][]uint32{},
			errContains: "line 1 has an invalid record",
		},
		{
			name:        "empty name",
			content:     ":x:0:\n",
			want:        map[string][]uint32{},
			errContains: "line 1 has an invalid record",
		},
		{
			name:        "non numeric GID",
			content:     "root:x:zero:\n",
			want:        map[string][]uint32{},
			errContains: "line 1 has an invalid GID",
		},
		{
			name:        "negative GID",
			content:     "root:x:-1:\n",
			want:        map[string][]uint32{},
			errContains: "invalid GID",
		},
		{
			name:        "GID above 32 bits",
			content:     "root:x:4294967296:\n",
			want:        map[string][]uint32{},
			errContains: "invalid GID",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGroupContent([]byte(tc.content))
			if tc.errContains == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.errContains != "" && (err == nil || !strings.Contains(err.Error(), tc.errContains)) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.errContains)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("records = %v, want %v", got, tc.want)
			}
		})
	}
}

func indexLayers(t *testing.T, layers ...[]testLayerEntry) *FilesystemIndex {
	t.Helper()
	built := make([]v1.Layer, 0, len(layers))
	for _, entries := range layers {
		built = append(built, makeTestLayer(t, entries...))
	}
	index, err := (&ImageReader{Image: makeTestImage(t, built...)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}
	return index
}

func TestGroupEvidenceInTheFinalView(t *testing.T) {
	passwd := testLayerEntry{name: "etc/passwd", mode: 0644, data: []byte("root:x:0:0:root:/root:/bin/sh\n")}
	shadow := testLayerEntry{name: "etc/shadow", mode: 0640, data: []byte("root:*:19000:0:99999:7:::\n")}

	cases := []struct {
		name         string
		layers       [][]testLayerEntry
		wantGroups   map[string][]uint32
		wantIssueSub string
	}{
		{
			name:       "a regular group file is parsed",
			layers:     [][]testLayerEntry{{{name: "etc/group", mode: 0644, data: []byte("root:x:0:\nstaff:x:50:\n")}}},
			wantGroups: map[string][]uint32{"root": {0}, "staff": {50}},
		},
		{
			name: "a replacement in an upper layer wins",
			layers: [][]testLayerEntry{
				{{name: "etc/group", mode: 0644, data: []byte("root:x:0:\nold:x:7:\n")}},
				{{name: "etc/group", mode: 0644, data: []byte("root:x:0:\nnew:x:8:\n")}},
			},
			wantGroups: map[string][]uint32{"root": {0}, "new": {8}},
		},
		{
			name: "a whiteout removes the file and makes the evidence incomplete",
			layers: [][]testLayerEntry{
				{{name: "etc/group", mode: 0644, data: []byte("root:x:0:\n")}},
				{{name: "etc/.wh.group", mode: 0644}},
			},
			wantIssueSub: "/etc/group is missing from the final image",
		},
		{
			name:         "a missing file is incomplete evidence",
			layers:       [][]testLayerEntry{{{name: "etc/hosts", mode: 0644, data: []byte("127.0.0.1 localhost\n")}}},
			wantIssueSub: "/etc/group is missing from the final image",
		},
		{
			name: "a hard link has no content of its own",
			layers: [][]testLayerEntry{{
				{name: "usr/share/group.master", mode: 0644, data: []byte("root:x:0:\n")},
				{name: "etc/group", typeflag: tar.TypeLink, linkname: "usr/share/group.master"},
			}},
			wantIssueSub: "/etc/group is not a regular file",
		},
		{
			name:         "a symbolic link is not a regular file",
			layers:       [][]testLayerEntry{{{name: "etc/group", typeflag: tar.TypeSymlink, linkname: "/usr/etc/group"}}},
			wantIssueSub: "/etc/group is not a regular file",
		},
		{
			name:         "an oversized file is incomplete evidence",
			layers:       [][]testLayerEntry{{{name: "etc/group", mode: 0644, data: bytes.Repeat([]byte("a"), MaxAccountFileBytes+1)}}},
			wantIssueSub: "complete-scan limit",
		},
		{
			name:         "a malformed record is incomplete evidence",
			layers:       [][]testLayerEntry{{{name: "etc/group", mode: 0644, data: []byte("root:x:0:\nnot-a-record\n")}}},
			wantGroups:   map[string][]uint32{"root": {0}},
			wantIssueSub: "line 2 has an invalid record",
		},
		{
			name:         "an empty file is incomplete evidence",
			layers:       [][]testLayerEntry{{{name: "etc/group", mode: 0644}}},
			wantGroups:   map[string][]uint32{},
			wantIssueSub: "no group records",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			index := indexLayers(t, tc.layers...)
			if tc.wantIssueSub == "" && index.GroupEvidenceIssue != "" {
				t.Fatalf("GroupEvidenceIssue = %q, want none", index.GroupEvidenceIssue)
			}
			if tc.wantIssueSub != "" && !strings.Contains(index.GroupEvidenceIssue, tc.wantIssueSub) {
				t.Fatalf("GroupEvidenceIssue = %q, want it to contain %q", index.GroupEvidenceIssue, tc.wantIssueSub)
			}
			if tc.wantGroups != nil && !reflect.DeepEqual(index.GroupGIDs, tc.wantGroups) {
				t.Fatalf("GroupGIDs = %v, want %v", index.GroupGIDs, tc.wantGroups)
			}
		})
	}

	// FS-08 reads the account files only: the state of /etc/group must not
	// change its evidence.
	t.Run("the group file does not influence the account evidence", func(t *testing.T) {
		withGroup := indexLayers(t, []testLayerEntry{passwd, shadow, {name: "etc/group", mode: 0644, data: []byte("garbage\n")}})
		withoutGroup := indexLayers(t, []testLayerEntry{passwd, shadow})
		if withGroup.AccountEvidenceIssue != withoutGroup.AccountEvidenceIssue || withGroup.AccountEvidenceIssue != "" {
			t.Fatalf("account issue with group %q, without group %q, want both empty", withGroup.AccountEvidenceIssue, withoutGroup.AccountEvidenceIssue)
		}
		if withGroup.PasswdEvidenceIssue != "" || withoutGroup.PasswdEvidenceIssue != "" {
			t.Fatalf("passwd issue changed: %q / %q", withGroup.PasswdEvidenceIssue, withoutGroup.PasswdEvidenceIssue)
		}
	})
}

func TestDirectorySetOfTheFinalView(t *testing.T) {
	dir := func(name string) testLayerEntry { return testLayerEntry{name: name, mode: 0755, typeflag: tar.TypeDir} }
	file := func(name string) testLayerEntry { return testLayerEntry{name: name, mode: 0644, data: []byte("x")} }

	cases := []struct {
		name     string
		layers   [][]testLayerEntry
		wantDirs []string
		wantFile []string
		wantGone []string
	}{
		{
			name:     "directories and files are told apart",
			layers:   [][]testLayerEntry{{dir("app/"), file("app/main"), {name: "app/link", typeflag: tar.TypeSymlink, linkname: "main"}}},
			wantDirs: []string{"/app"},
			wantFile: []string{"/app/main", "/app/link"},
		},
		{
			name: "a file replacing a directory leaves the directory set",
			layers: [][]testLayerEntry{
				{dir("opt/tool/")},
				{file("opt/tool")},
			},
			wantFile: []string{"/opt/tool"},
			wantGone: []string{"/opt/tool"},
		},
		{
			name: "a directory replacing a file joins the directory set",
			layers: [][]testLayerEntry{
				{file("opt/tool")},
				{dir("opt/tool/")},
			},
			wantDirs: []string{"/opt/tool"},
		},
		{
			name: "a whiteout removes the directory and its children",
			layers: [][]testLayerEntry{
				{dir("var/cache/"), dir("var/cache/apt/"), file("var/cache/apt/pkg")},
				{{name: "var/.wh.cache", mode: 0644}},
			},
			wantGone: []string{"/var/cache", "/var/cache/apt", "/var/cache/apt/pkg"},
		},
		{
			name: "an opaque whiteout clears lower children but keeps the directory",
			layers: [][]testLayerEntry{
				{dir("data/"), dir("data/old/"), file("data/old/f")},
				{{name: "data/.wh..wh..opq", mode: 0644}, file("data/new")},
			},
			wantDirs: []string{"/data"},
			wantFile: []string{"/data/new"},
			wantGone: []string{"/data/old", "/data/old/f"},
		},
		{
			name:     "a trailing slash in the tar name is normalised",
			layers:   [][]testLayerEntry{{dir("srv/www/")}},
			wantDirs: []string{"/srv/www"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			index := indexLayers(t, tc.layers...)
			if index.Dirs == nil {
				t.Fatal("a streamed index must carry a directory set")
			}
			for _, p := range tc.wantDirs {
				if _, ok := index.Dirs[p]; !ok || !index.Paths[p] {
					t.Errorf("%s should be a directory of the final view (dirs %v)", p, index.Dirs)
				}
			}
			for _, p := range tc.wantFile {
				if _, isDir := index.Dirs[p]; isDir || !index.Paths[p] {
					t.Errorf("%s should be a non-directory entry of the final view (dirs %v)", p, index.Dirs)
				}
			}
			for _, p := range tc.wantGone {
				if _, ok := index.Dirs[p]; ok {
					t.Errorf("%s must not be in the directory set any more", p)
				}
			}
		})
	}
}
