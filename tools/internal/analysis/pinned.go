package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// PinnedEntry is one object of fixtures/evaluation_dataset_pinned.json. Only
// the fields the analysis reads are listed.
type PinnedEntry struct {
	// OriginalTag is the reference as it was written in the candidate list,
	// for example "nginx:1.30.6-alpine". The pinned text list dropped it.
	OriginalTag    string `json:"original_tag"`
	ImmutableRef   string `json:"immutable_ref"`
	ManifestDigest string `json:"manifest_digest"`
	Platform       string `json:"platform"`
	Status         string `json:"status"`
}

// LoadPinned reads fixtures/evaluation_dataset_pinned.json. The file must be a
// JSON array. An empty array is valid and yields a non-nil empty slice.
func LoadPinned(path string) ([]PinnedEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var entries []PinnedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if entries == nil {
		// "null" decodes to a nil slice, which would mean "no file given".
		return nil, fmt.Errorf("parse %s: expected a JSON array of pinned entries, got null", path)
	}
	return entries, nil
}

// TagPart returns the tag of an image reference and "" when it has none. A
// digest suffix is ignored and a colon that belongs to a registry port is not
// a tag separator.
//
//	nginx:1.30.6-alpine                -> 1.30.6-alpine
//	alpine:3.24.3                      -> 3.24.3
//	registry.example:5000/app          -> ""
//	registry.example:5000/app:1-slim   -> 1-slim
//	app:1.2@sha256:...                 -> 1.2
func TagPart(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	segment := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		segment = ref[i+1:]
	}
	if i := strings.LastIndex(segment, ":"); i >= 0 {
		return segment[i+1:]
	}
	return ""
}

// TagStats counts the variant tags of the COMPLETED images, from the pinned
// dataset.
//
// An image counts as alpine or slim when the TAG part of its original tag
// contains "alpine" or "slim" (case-insensitive). The repository name is not
// searched: the base image "alpine:3.24.3" is the Alpine base itself, not an
// image published in an alpine variant, and a substring search over the whole
// reference would count it as one. An image whose tag contains both words
// counts in both columns.
type TagStats struct {
	Source string `json:"source,omitempty"`
	// Entries is the number of entries of the pinned file.
	Entries int `json:"entries"`
	// Completed is the number of COMPLETED images that were looked up.
	Completed int `json:"completed_images"`
	// Tagged counts COMPLETED images whose original tag is known and has a
	// tag part.
	Tagged int `json:"tagged"`
	Alpine int `json:"alpine"`
	Slim   int `json:"slim"`
	// NoPinnedEntry counts COMPLETED images that match no pinned entry, so
	// their tag is unknown.
	NoPinnedEntry int `json:"no_pinned_entry"`
	// NoTag counts COMPLETED images whose pinned entry carries no tag part.
	NoTag int `json:"no_tag"`
	// Unmatched lists up to MaxUnmatchedListed references without an entry.
	Unmatched []string `json:"unmatched_refs,omitempty"`
}

// MaxUnmatchedListed bounds TagStats.Unmatched.
const MaxUnmatchedListed = 10

// HasVariantTag reports whether the tag part of an original tag contains the
// word, ignoring case.
func HasVariantTag(originalTag, word string) bool {
	return strings.Contains(strings.ToLower(TagPart(originalTag)), strings.ToLower(word))
}

// CountTags looks every COMPLETED record up in the pinned entries and counts
// the variant tags. A record matches an entry when its requested reference
// (or image name) equals the entry's immutable reference, or when its image
// digest equals the entry's manifest digest.
func CountTags(completed []*spec.SuiteResult, pinned []PinnedEntry) TagStats {
	byRef := map[string]*PinnedEntry{}
	byDigest := map[string]*PinnedEntry{}
	for i := range pinned {
		e := &pinned[i]
		if e.ImmutableRef != "" {
			byRef[e.ImmutableRef] = e
		}
		if e.ManifestDigest != "" {
			byDigest[e.ManifestDigest] = e
		}
	}
	ts := TagStats{Entries: len(pinned), Completed: len(completed)}
	for _, rec := range completed {
		var entry *PinnedEntry
		for _, ref := range []string{rec.RequestedRef, rec.ImageName} {
			if e, ok := byRef[ref]; ok && ref != "" {
				entry = e
				break
			}
		}
		if entry == nil && rec.ImageDigest != "" {
			entry = byDigest[rec.ImageDigest]
		}
		if entry == nil {
			ts.NoPinnedEntry++
			if len(ts.Unmatched) < MaxUnmatchedListed {
				ts.Unmatched = append(ts.Unmatched, studyfile.RecordKey(rec))
			}
			continue
		}
		if TagPart(entry.OriginalTag) == "" {
			ts.NoTag++
			continue
		}
		ts.Tagged++
		if HasVariantTag(entry.OriginalTag, "alpine") {
			ts.Alpine++
		}
		if HasVariantTag(entry.OriginalTag, "slim") {
			ts.Slim++
		}
	}
	return ts
}
