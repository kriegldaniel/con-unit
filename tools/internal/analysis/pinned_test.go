package analysis

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

func TestTagPart(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		want string
	}{
		{"plain tag", "nginx:1.30.6-alpine", "1.30.6-alpine"},
		{"base image named alpine", "alpine:3.24.3", "3.24.3"},
		{"no tag", "busybox", ""},
		{"registry port without tag", "registry.example:5000/app", ""},
		{"registry port with tag", "registry.example:5000/app:1-slim", "1-slim"},
		{"namespace and tag", "bitnami/redis:7.4", "7.4"},
		{"digest suffix is ignored", "app:1.2@sha256:" + strings.Repeat("a", 64), "1.2"},
		{"digest only", "index.docker.io/library/nginx@sha256:" + strings.Repeat("b", 64), ""},
		{"surrounding space", "  node:22-slim \n", "22-slim"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TagPart(tc.ref); got != tc.want {
				t.Errorf("TagPart(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

func TestHasVariantTag(t *testing.T) {
	cases := []struct {
		name string
		tag  string
		word string
		want bool
	}{
		{"alpine suffix", "nginx:1.30.6-alpine", "alpine", true},
		{"alpine with release suffix", "postgres:17.5-alpine3.22", "alpine", true},
		{"case is ignored", "app:1-Alpine", "alpine", true},
		{"slim", "python:3.13-slim", "slim", true},
		{"slim with distribution", "node:22-bookworm-slim", "slim", true},
		{"repository named alpine is not a variant", "alpine:3.24.3", "alpine", false},
		{"repository named slim is not a variant", "slim:1.0", "slim", false},
		{"neither", "traefik:v3.4", "alpine", false},
		{"no tag", "busybox", "slim", false},
		{"both words count for both", "app:1-slim-alpine", "slim", true},
		{"both words count for both (alpine)", "app:1-slim-alpine", "alpine", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasVariantTag(tc.tag, tc.word); got != tc.want {
				t.Errorf("HasVariantTag(%q, %q) = %v, want %v", tc.tag, tc.word, got, tc.want)
			}
		})
	}
}

func completedImage(ref, digest string) *spec.SuiteResult {
	return &spec.SuiteResult{ImageName: ref, RequestedRef: ref, ImageDigest: digest, Status: spec.StatusCompleted}
}

func TestCountTags(t *testing.T) {
	pinned := []PinnedEntry{
		{OriginalTag: "alpine:3.24.3", ImmutableRef: "r/alpine@sha256:1", ManifestDigest: "sha256:1"},
		{OriginalTag: "nginx:1.30-alpine", ImmutableRef: "r/nginx@sha256:2", ManifestDigest: "sha256:2"},
		{OriginalTag: "python:3.13-slim", ImmutableRef: "r/python@sha256:3", ManifestDigest: "sha256:3"},
		{OriginalTag: "node:22-slim-alpine", ImmutableRef: "r/node@sha256:4", ManifestDigest: "sha256:4"},
		{OriginalTag: "busybox", ImmutableRef: "r/busybox@sha256:5", ManifestDigest: "sha256:5"},
		{OriginalTag: "redis:8", ImmutableRef: "r/redis@sha256:6", ManifestDigest: "sha256:6"},
	}
	cases := []struct {
		name      string
		completed []*spec.SuiteResult
		pinned    []PinnedEntry
		want      TagStats
	}{
		{
			name: "matched by immutable reference",
			completed: []*spec.SuiteResult{
				completedImage("r/alpine@sha256:1", ""), completedImage("r/nginx@sha256:2", ""),
				completedImage("r/python@sha256:3", ""), completedImage("r/redis@sha256:6", ""),
			},
			pinned: pinned,
			want:   TagStats{Entries: 6, Completed: 4, Tagged: 4, Alpine: 1, Slim: 1},
		},
		{
			name:      "an image with both words counts in both columns",
			completed: []*spec.SuiteResult{completedImage("r/node@sha256:4", "")},
			pinned:    pinned,
			want:      TagStats{Entries: 6, Completed: 1, Tagged: 1, Alpine: 1, Slim: 1},
		},
		{
			name: "matched by manifest digest when the reference differs",
			completed: []*spec.SuiteResult{
				{ImageName: "other-name", RequestedRef: "other-ref", ImageDigest: "sha256:2", Status: spec.StatusCompleted},
			},
			pinned: pinned,
			want:   TagStats{Entries: 6, Completed: 1, Tagged: 1, Alpine: 1},
		},
		{
			name:      "an entry without a tag part is not tagged",
			completed: []*spec.SuiteResult{completedImage("r/busybox@sha256:5", "")},
			pinned:    pinned,
			want:      TagStats{Entries: 6, Completed: 1, NoTag: 1},
		},
		{
			name:      "an image without a pinned entry is unmatched and not tagged",
			completed: []*spec.SuiteResult{completedImage("r/unknown@sha256:9", "sha256:9")},
			pinned:    pinned,
			want:      TagStats{Entries: 6, Completed: 1, NoPinnedEntry: 1, Unmatched: []string{"r/unknown@sha256:9"}},
		},
		{
			name:      "an empty reference never matches an empty immutable reference",
			completed: []*spec.SuiteResult{{Status: spec.StatusCompleted}},
			pinned:    []PinnedEntry{{OriginalTag: "x:1-alpine"}},
			want:      TagStats{Entries: 1, Completed: 1, NoPinnedEntry: 1, Unmatched: []string{""}},
		},
		{
			name:      "no completed image",
			completed: nil,
			pinned:    pinned,
			want:      TagStats{Entries: 6},
		},
		{
			name:      "empty pinned file",
			completed: []*spec.SuiteResult{completedImage("r/nginx@sha256:2", "")},
			pinned:    []PinnedEntry{},
			want:      TagStats{Completed: 1, NoPinnedEntry: 1, Unmatched: []string{"r/nginx@sha256:2"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CountTags(tc.completed, tc.pinned)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CountTags = %+v\n want %+v", got, tc.want)
			}
		})
	}
}

func TestCountTagsListsAtMostTenUnmatched(t *testing.T) {
	var completed []*spec.SuiteResult
	for i := 0; i < 15; i++ {
		completed = append(completed, completedImage("r/x"+string(rune('a'+i)), ""))
	}
	got := CountTags(completed, []PinnedEntry{})
	if got.NoPinnedEntry != 15 || len(got.Unmatched) != MaxUnmatchedListed {
		t.Errorf("NoPinnedEntry = %d, listed = %d; want 15 and %d", got.NoPinnedEntry, len(got.Unmatched), MaxUnmatchedListed)
	}
}

func TestLoadPinned(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name    string
		path    string
		wantLen int
		wantErr string
	}{
		{"valid", write("ok.json", `[{"original_tag":"a:1-alpine","immutable_ref":"r/a@sha256:1","manifest_digest":"sha256:1","platform":"linux/amd64","status":"PINNED"}]`), 1, ""},
		{"empty array", write("empty.json", `[]`), 0, ""},
		{"null is rejected", write("null.json", `null`), 0, "got null"},
		{"object is rejected", write("obj.json", `{"entries":[]}`), 0, "parse"},
		{"malformed", write("bad.json", `[{`), 0, "parse"},
		{"missing file", filepath.Join(dir, "absent.json"), 0, "read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadPinned(tc.path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || len(got) != tc.wantLen {
				t.Errorf("entries = %v (nil=%v), want %d non-nil", got, got == nil, tc.wantLen)
			}
		})
	}
}

// The committed pinned dataset is the source of the alpine and slim
// counts. 28 alpine and 7 slim tags are counted by tag. A search over the
// whole reference gives 29 alpine, because the Alpine base image alpine:3.24.3
// is itself one of the entries, so the tag part is what must be searched.
func TestCommittedPinnedDatasetTagCounts(t *testing.T) {
	entries, err := LoadPinned(filepath.Join("..", "..", "..", "fixtures", "evaluation_dataset_pinned.json"))
	if err != nil {
		t.Skipf("pinned dataset not available: %v", err)
	}
	var byTag, byWholeRef, slimByTag int
	for _, e := range entries {
		if HasVariantTag(e.OriginalTag, "alpine") {
			byTag++
		}
		if strings.Contains(strings.ToLower(e.OriginalTag), "alpine") {
			byWholeRef++
		}
		if HasVariantTag(e.OriginalTag, "slim") {
			slimByTag++
		}
	}
	if byTag != 28 || slimByTag != 7 {
		t.Errorf("alpine by tag = %d, slim by tag = %d; want 28 and 7", byTag, slimByTag)
	}
	if byWholeRef != byTag+1 {
		t.Errorf("whole-reference alpine count = %d, want %d (tag count plus the alpine base image)", byWholeRef, byTag+1)
	}
}

func TestRuleKey(t *testing.T) {
	cases := []struct{ id, want string }{
		{"SPEC-09", "SPECZeroNine"},
		{"SPEC-01", "SPECZeroOne"},
		{"FS-10", "FSOneZero"},
		{"FS-12", "FSOneTwo"},
		{"CIS-4.6", "CISFourSix"},
		{"EXEC-02", "EXECZeroTwo"},
		{"SUP-02", "SUPZeroTwo"},
		{"", ""},
		{"a b_c", "abc"},
	}
	for _, tc := range cases {
		if got := RuleKey(tc.id); got != tc.want {
			t.Errorf("RuleKey(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestAnalyzeRecordsTagsOnlyWithPinnedFile(t *testing.T) {
	im := completedImage("r/nginx@sha256:2", "")
	im.Results = []spec.TestResult{r("FS-04", "SUID", spec.TierFilesystem, spec.OutcomePass, "")}
	pinned := []PinnedEntry{{OriginalTag: "nginx:1-alpine", ImmutableRef: "r/nginx@sha256:2"}}

	without := Analyze(load(t, im), Options{Classification: testClass})
	if without.Tags != nil {
		t.Errorf("Tags = %+v without a pinned file, want nil", without.Tags)
	}
	with := Analyze(load(t, im), Options{Classification: testClass, Pinned: pinned, PinnedSource: "pinned.json"})
	if with.Tags == nil || with.Tags.Alpine != 1 || with.Tags.Tagged != 1 || with.Tags.Source != "pinned.json" {
		t.Fatalf("Tags = %+v, want one tagged alpine image from pinned.json", with.Tags)
	}
	unmatched := Analyze(load(t, im), Options{Classification: testClass, Pinned: []PinnedEntry{}, PinnedSource: "pinned.json"})
	found := false
	for _, w := range unmatched.Warnings {
		if strings.Contains(w, "match no entry of the pinned dataset") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one about images without a pinned entry", unmatched.Warnings)
	}
}
