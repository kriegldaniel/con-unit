package conunit_test

import (
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// fs01Index returns an index with the given paths. Paths in dirs are
// directories, the others are files.
func fs01Index(dirs []string, files []string) *oci.FilesystemIndex {
	index := &oci.FilesystemIndex{Paths: map[string]bool{}, Dirs: map[string]struct{}{}}
	for _, d := range dirs {
		index.Paths[d] = true
		index.Dirs[d] = struct{}{}
	}
	for _, f := range files {
		index.Paths[f] = true
	}
	return index
}

// withEmptyFiles marks the given files of the index as regular files of zero
// bytes.
func withEmptyFiles(index *oci.FilesystemIndex, paths ...string) *oci.FilesystemIndex {
	index.EmptyFiles = map[string]struct{}{}
	for _, p := range paths {
		index.EmptyFiles[p] = struct{}{}
	}
	return index
}

func TestPackageCacheCheckIgnoresEmptyDirectoriesAndKeepsRealContent(t *testing.T) {
	listed := []string{"/var/cache/apt", "/var/cache/apk", "/var/lib/apt/lists", "/root/.cache", "/.git", "/.env"}

	cases := []struct {
		name      string
		index     *oci.FilesystemIndex
		want      spec.Outcome
		wantNamed []string
		notNamed  []string
	}{
		{
			name:  "base image directories that are empty",
			index: fs01Index([]string{"/var/cache", "/var/cache/apk", "/var/lib/apt/lists", "/var/cache/apt", "/var/cache/apt/archives/partial"}, nil),
			want:  spec.OutcomePass,
		},
		{
			name:      "a cache directory with a file",
			index:     fs01Index([]string{"/var/cache/apt", "/var/cache/apt/archives"}, []string{"/var/cache/apt/archives/curl.deb"}),
			want:      spec.OutcomeFail,
			wantNamed: []string{"/var/cache/apt"},
			notNamed:  []string{"/var/cache/apk"},
		},
		{
			name:      "a regular file on the list",
			index:     fs01Index(nil, []string{"/.env"}),
			want:      spec.OutcomeFail,
			wantNamed: []string{"/.env"},
		},
		{
			name:      "an empty directory next to a full one names only the full one",
			index:     fs01Index([]string{"/var/cache/apk", "/var/lib/apt/lists"}, []string{"/var/lib/apt/lists/deb.debian.org_dists_bookworm_InRelease"}),
			want:      spec.OutcomeFail,
			wantNamed: []string{"/var/lib/apt/lists"},
			notNamed:  []string{"/var/cache/apk"},
		},
		{
			name:     "an empty .git directory holds nothing",
			index:    fs01Index([]string{"/.git"}, nil),
			want:     spec.OutcomePass,
			notNamed: []string{"/.git"},
		},
		{
			name:     "only apt's empty lock file below the cache directory",
			index:    withEmptyFiles(fs01Index([]string{"/var/cache/apt", "/var/cache/apt/archives", "/var/cache/apt/archives/partial"}, []string{"/var/cache/apt/archives/lock"}), "/var/cache/apt/archives/lock"),
			want:     spec.OutcomePass,
			notNamed: []string{"/var/cache/apt"},
		},
		{
			name:      "an empty file next to a package file still fails",
			index:     withEmptyFiles(fs01Index([]string{"/var/cache/apt", "/var/cache/apt/archives"}, []string{"/var/cache/apt/archives/lock", "/var/cache/apt/archives/curl.deb"}), "/var/cache/apt/archives/lock"),
			want:      spec.OutcomeFail,
			wantNamed: []string{"/var/cache/apt"},
		},
		{
			name:      "an empty file that is itself on the list still fails",
			index:     withEmptyFiles(fs01Index(nil, []string{"/.env"}), "/.env"),
			want:      spec.OutcomeFail,
			wantNamed: []string{"/.env"},
		},
		{
			name:  "nothing from the list exists",
			index: fs01Index([]string{"/usr"}, nil),
			want:  spec.OutcomePass,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &conunit.Container{OCIIndex: tc.index}
			c.AssertFilesystem().PathsNotExist(listed...)
			if len(c.Results) != 1 {
				t.Fatalf("recorded %d results, want one: %+v", len(c.Results), c.Results)
			}
			result := c.Results[0]
			if got := result.EffectiveOutcome(); got != tc.want {
				t.Fatalf("outcome = %s, want %s (message: %q)", got, tc.want, result.Message)
			}
			for _, p := range tc.wantNamed {
				if !strings.Contains(result.Message, p) {
					t.Errorf("message must name %s: %q", p, result.Message)
				}
			}
			for _, p := range tc.notNamed {
				if strings.Contains(result.Message, p) {
					t.Errorf("message must not name %s: %q", p, result.Message)
				}
			}
		})
	}
}

func TestPackageCacheCheckCountsEveryExistingPathWhenDirectoryTypesAreUnknown(t *testing.T) {
	// An index built by hand has no directory types. The check then cannot tell
	// an empty directory from a full one and keeps the earlier behavior.
	index := &oci.FilesystemIndex{Paths: map[string]bool{"/var/cache/apk": true}}
	c := &conunit.Container{OCIIndex: index}
	c.AssertFilesystem().PathsNotExist("/var/cache/apk")
	if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeFail {
		t.Fatalf("outcome = %s, want FAIL when the path type is unknown", got)
	}
}
