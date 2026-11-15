// Package studyfile reads empirical_study.json for the evaluation tools.
//
// It decodes the current envelope (spec.Study) and the legacy array-only
// format written by earlier versions. For legacy input the run metadata is
// unknown and every record without an explicit status is treated as
// COMPLETED, which is what the old exporter did. For envelope input a record
// without a status is a tool defect and is reported as UNSPECIFIED so it
// cannot silently enter the statistics.
package studyfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
)

// StatusUnspecified labels envelope records that carry no status.
const StatusUnspecified = "UNSPECIFIED"

// Loaded is a decoded study file.
type Loaded struct {
	// Study is the decoded envelope. For legacy input, SchemaVersion is
	// empty and Run is the zero value.
	Study spec.Study
	// Legacy reports that the file used the array-only format.
	Legacy bool
	// SHA256 is the hex digest of the raw file content.
	SHA256 string
	// Records holds one record per attempted image in first-seen order. When
	// the same image appears more than once the last record wins, which
	// mirrors the journal rule in docs/CONTRACT.md.
	Records []*spec.SuiteResult
	// Warnings lists non-fatal problems found while loading.
	Warnings []string
}

// Load reads and decodes a study file from disk.
func Load(path string) (*Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	l, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return l, nil
}

// Decode decodes study JSON, either the envelope or the legacy array.
func Decode(data []byte) (*Loaded, error) {
	sum := sha256.Sum256(data)
	l := &Loaded{SHA256: hex.EncodeToString(sum[:])}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	switch trimmed[0] {
	case '[':
		var legacy []spec.SuiteResult
		if err := json.Unmarshal(trimmed, &legacy); err != nil {
			return nil, fmt.Errorf("parse legacy array: %w", err)
		}
		l.Legacy = true
		l.Study.Images = make([]*spec.SuiteResult, len(legacy))
		for i := range legacy {
			l.Study.Images[i] = &legacy[i]
		}
		l.Warnings = append(l.Warnings,
			"legacy array format: run metadata is unknown and records without a status are treated as COMPLETED")
	case '{':
		if err := json.Unmarshal(trimmed, &l.Study); err != nil {
			return nil, fmt.Errorf("parse envelope: %w", err)
		}
		if l.Study.SchemaVersion == "" {
			return nil, fmt.Errorf("not a study envelope: schema_version is missing")
		}
		if l.Study.SchemaVersion != spec.SchemaVersion {
			l.Warnings = append(l.Warnings, fmt.Sprintf(
				"schema_version %q differs from the version this tool was built for (%q)",
				l.Study.SchemaVersion, spec.SchemaVersion))
		}
	default:
		return nil, fmt.Errorf("unexpected leading character %q: expected '{' or '['", trimmed[0])
	}

	for i, img := range l.Study.Images {
		if img == nil {
			return nil, fmt.Errorf("images[%d] is null", i)
		}
	}
	l.dedupe()
	return l, nil
}

// RecordKey identifies an image record: the requested reference when present,
// otherwise the image name.
func RecordKey(s *spec.SuiteResult) string {
	if s.RequestedRef != "" {
		return s.RequestedRef
	}
	return s.ImageName
}

func (l *Loaded) dedupe() {
	index := map[string]int{}
	dupes := map[string]int{}
	var order []string
	for _, img := range l.Study.Images {
		key := RecordKey(img)
		if i, seen := index[key]; seen {
			l.Records[i] = img
			dupes[key]++
			continue
		}
		index[key] = len(l.Records)
		order = append(order, key)
		l.Records = append(l.Records, img)
	}
	for _, key := range order {
		if n := dupes[key]; n > 0 {
			l.Warnings = append(l.Warnings, fmt.Sprintf(
				"image %q has %d records; the last one is used (docs/CONTRACT.md requires exactly one)", key, n+1))
		}
	}
}

// Status returns the normalised status of a record.
func (l *Loaded) Status(s *spec.SuiteResult) string {
	if s.Status != "" {
		return s.Status
	}
	if l.Legacy {
		return spec.StatusCompleted
	}
	return StatusUnspecified
}

// Completed reports whether a record enters the statistics.
func (l *Loaded) Completed(s *spec.SuiteResult) bool {
	return l.Status(s) == spec.StatusCompleted
}

// UniqueResults returns the results of one image with repeated test IDs
// removed (the first result per ID is kept) and the list of IDs that were
// repeated. docs/CONTRACT.md allows at most one result per ID per image.
func UniqueResults(s *spec.SuiteResult) (results []spec.TestResult, repeated []string) {
	seen := map[string]bool{}
	reported := map[string]bool{}
	for _, r := range s.Results {
		if seen[r.TestID] {
			if !reported[r.TestID] {
				repeated = append(repeated, r.TestID)
				reported[r.TestID] = true
			}
			continue
		}
		seen[r.TestID] = true
		results = append(results, r)
	}
	return results, repeated
}

// RepoName reduces an image reference to the repository name used as key in
// fixtures/archetypes.json: tag and digest are removed, the registry host is
// dropped, and the implicit "library/" namespace of Docker Official Images is
// removed. For example "index.docker.io/library/nginx@sha256:..." becomes
// "nginx" and "bitnami/redis:7" becomes "bitnami/redis".
func RepoName(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A colon after the last slash starts the tag; earlier colons belong to
	// a registry port.
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		ref = ref[:colon]
	}
	parts := strings.Split(ref, "/")
	if len(parts) > 1 {
		host := parts[0]
		if strings.ContainsAny(host, ".:") || host == "localhost" {
			parts = parts[1:]
		}
	}
	if len(parts) > 1 && parts[0] == "library" {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}
