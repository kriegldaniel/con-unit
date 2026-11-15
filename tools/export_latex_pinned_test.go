package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/tools/internal/analysis"
)

// pinnedFor builds a pinned dataset for the synthetic study of
// export_latex_test.go. The images are alpine, nginx, postgres, python,
// redis, traefik, mystery and busybox, in that order:
//
//	alpine    alpine:3.24.3           tagged, repository name only (no variant)
//	nginx     nginx:1.30.6-alpine     alpine
//	postgres  postgres:17.5-alpine3.22 alpine
//	python    python:3.13-slim        slim
//	redis     redis:8.0.1-alpine      alpine
//	traefik   traefik:v3.4            tagged, neither
//	mystery   (no entry)              unknown tag
//	busybox   busybox                 matched by digest only, no tag part
func pinnedFor() []analysis.PinnedEntry {
	entry := func(name, tag string) analysis.PinnedEntry {
		return analysis.PinnedEntry{OriginalTag: tag, ImmutableRef: ref(name), ManifestDigest: "sha256:" + strings.Repeat("0", 63) + "f", Platform: "linux/amd64+arm64", Status: "PINNED"}
	}
	// The digest of every entry is a placeholder that no study image uses,
	// except busybox below, so matches in this fixture come from the reference.
	entries := []analysis.PinnedEntry{
		entry("alpine", "alpine:3.24.3"),
		entry("nginx", "nginx:1.30.6-alpine"),
		entry("postgres", "postgres:17.5-alpine3.22"),
		entry("python", "python:3.13-slim"),
		entry("redis", "redis:8.0.1-alpine"),
		entry("traefik", "traefik:v3.4"),
	}
	// busybox is image number 8 of the synthetic study: ImageDigest is
	// sha256:%064x of 8. The reference differs, so only the digest matches.
	entries = append(entries, analysis.PinnedEntry{
		OriginalTag: "busybox", ImmutableRef: "index.docker.io/library/busybox@sha256:" + strings.Repeat("9", 64),
		ManifestDigest: fmt.Sprintf("sha256:%064x", 8), Platform: "linux/amd64+arm64", Status: "PINNED",
	})
	return entries
}

func (e *testEnv) writePinned(t *testing.T, entries []analysis.PinnedEntry) string {
	t.Helper()
	path := filepath.Join(e.dir, "pinned.json")
	writeJSON(t, path, entries)
	return path
}

func TestPinnedFlagTagMacros(t *testing.T) {
	cases := []struct {
		name       string
		entries    []analysis.PinnedEntry
		wantMacros map[string]string
		wantWarn   string
	}{
		{
			name:    "alpine base image is not a variant, unknown and tagless images are not tagged",
			entries: pinnedFor(),
			wantMacros: map[string]string{
				"ConUnitNAlpineTag": "3", "ConUnitNSlimTag": "1", "ConUnitNTagged": "6",
			},
			wantWarn: "match no entry of the pinned dataset",
		},
		{
			name:    "an empty pinned file leaves every image without a tag",
			entries: []analysis.PinnedEntry{},
			wantMacros: map[string]string{
				"ConUnitNAlpineTag": "0", "ConUnitNSlimTag": "0", "ConUnitNTagged": "0",
			},
			wantWarn: "no completed image has a known tag",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, synthStudy())
			pinned := e.writePinned(t, tc.entries)
			code, _, stderr := export(t, e.args("-audit", e.audit, "-pinned", pinned)...)
			if code != 0 {
				t.Fatalf("exit %d, stderr:\n%s", code, stderr)
			}
			macros := read(t, filepath.Join(e.dir, fileMacros))
			for name, want := range tc.wantMacros {
				line := fmt.Sprintf(`\newcommand{\%s}{%s}`, name, want)
				if !strings.Contains(macros, line) {
					t.Errorf("macros lack %s", line)
				}
			}
			if !strings.Contains(stderr, tc.wantWarn) {
				t.Errorf("stderr lacks %q:\n%s", tc.wantWarn, stderr)
			}
			if strings.Contains(stderr, "no -pinned file given") {
				t.Errorf("the missing-file warning must not appear when -pinned is given:\n%s", stderr)
			}
		})
	}
}

func TestWithoutPinnedFlagTagMacrosAreNotAvailable(t *testing.T) {
	e := newEnv(t, synthStudy())
	code, _, stderr := export(t, e.args("-audit", e.audit)...)
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	macros := read(t, filepath.Join(e.dir, fileMacros))
	for _, name := range []string{"ConUnitNAlpineTag", "ConUnitNSlimTag", "ConUnitNTagged"} {
		line := fmt.Sprintf(`\newcommand{\%s}{n/a}`, name)
		if !strings.Contains(macros, line) {
			t.Errorf("macros lack %s", line)
		}
	}
	if !strings.Contains(stderr, "no -pinned file given") {
		t.Errorf("expected the warning about the missing -pinned file, got:\n%s", stderr)
	}
	stats := read(t, filepath.Join(e.dir, fileStatsJSON))
	if strings.Contains(stats, "pinned_tags") {
		t.Error("study_stats.json must not carry tag statistics without a pinned file")
	}
}

func TestPinnedFlagFailures(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, e *testEnv) string
		want    string
	}{
		{"missing file", func(t *testing.T, e *testEnv) string { return filepath.Join(e.dir, "absent.json") }, "cannot load pinned dataset"},
		{"not an array", func(t *testing.T, e *testEnv) string {
			p := filepath.Join(e.dir, "bad.json")
			if err := os.WriteFile(p, []byte(`{"entries": []}`), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}, "cannot load pinned dataset"},
		{"null", func(t *testing.T, e *testEnv) string {
			p := filepath.Join(e.dir, "null.json")
			if err := os.WriteFile(p, []byte(`null`), 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}, "got null"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, synthStudy())
			code, _, stderr := export(t, e.args("-audit", e.audit, "-pinned", tc.prepare(t, e))...)
			if code == 0 {
				t.Fatalf("exit 0, want a failure; stderr:\n%s", stderr)
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, stderr)
			}
		})
	}
}

func TestPinnedTagStatsInStudyStats(t *testing.T) {
	e := newEnv(t, synthStudy())
	pinned := e.writePinned(t, pinnedFor())
	if code, _, stderr := export(t, e.args("-audit", e.audit, "-pinned", pinned)...); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	stats := read(t, filepath.Join(e.dir, fileStatsJSON))
	for _, want := range []string{`"pinned_tags"`, `"alpine": 3`, `"slim": 1`, `"tagged": 6`, `"no_pinned_entry": 1`, `"no_tag": 1`, `"source": "pinned.json"`} {
		if !strings.Contains(stats, want) {
			t.Errorf("study_stats.json lacks %s", want)
		}
	}
}

// TestGoldenPinnedMacros pins the macro file of a run with -pinned. It is a
// new scenario, so the goldens of the other scenarios stay unchanged by it.
func TestGoldenPinnedMacros(t *testing.T) {
	e := newEnv(t, synthStudy())
	pinned := e.writePinned(t, pinnedFor())
	if code, _, stderr := export(t, e.args("-audit", e.audit, "-pinned", pinned)...); code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	goldenAll(t, "pinned", e.dir, fileMacros)
}

func TestListOutputsDoesNotNeedPinned(t *testing.T) {
	code, stdout, _ := export(t, "-list-outputs")
	if code != 0 || !strings.Contains(stdout, fileMacros) {
		t.Errorf("exit %d, stdout:\n%s", code, stdout)
	}
}
