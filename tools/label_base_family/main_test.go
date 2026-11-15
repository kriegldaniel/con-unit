package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestRepositoryOf(t *testing.T) {
	cases := map[string]string{
		"nginx:1.30.6-alpine":                      "nginx",
		"library/nginx:1.30":                       "nginx",
		"docker.io/library/nginx:1.30":             "nginx",
		"index.docker.io/library/traefik:v3.7":     "traefik",
		"rocket.chat:8.9.0":                        "rocket.chat",
		"haxe:latest":                              "haxe",
		"open-liberty:26.0.0.9-full-java17-openj9": "open-liberty",
	}
	for tag, want := range cases {
		if got := repositoryOf(tag); got != want {
			t.Errorf("repositoryOf(%q) = %q, want %q", tag, got, want)
		}
	}
}

func pinnedFixture() []pinnedRecord {
	return []pinnedRecord{
		{OriginalTag: "zookeeper:3.9.6", ImmutableRef: "index.docker.io/library/zookeeper@sha256:" + strings.Repeat("a", 64), Status: "PINNED"},
		{OriginalTag: "traefik:v3.7.17", ImmutableRef: "index.docker.io/library/traefik@sha256:" + strings.Repeat("b", 64), Status: "PINNED"},
		{OriginalTag: "nginx:1.30.6-alpine", ImmutableRef: "index.docker.io/library/nginx@sha256:" + strings.Repeat("c", 64), Status: "PINNED"},
		{OriginalTag: "bonita:11.1.0", Status: "EXCLUDED_SINGLE_ARCH"},
		{OriginalTag: "broken:1", Status: "PINNED"},
	}
}

func archetypesFixture() map[string]map[string]any {
	return map[string]map[string]any{
		"zookeeper": {"archetype": "other", "base_family": "unknown"},
		"traefik":   {"archetype": "web-ingress", "base_family": "unknown"},
		"nginx":     {"archetype": "web-ingress", "base_family": "alpine"},
		"bonita":    {"archetype": "application", "base_family": "unknown"},
		"broken":    {"archetype": "application", "base_family": "unknown"},
	}
}

func repositories(targets []target) []string {
	var names []string
	for _, tg := range targets {
		names = append(names, tg.repository)
	}
	return names
}

func TestSelectTargets(t *testing.T) {
	cases := []struct {
		name     string
		families []string
		only     []string
		want     []string
	}{
		{"unknown pinned images only, sorted", []string{"unknown"}, nil, []string{"traefik", "zookeeper"}},
		{"another current label", []string{"alpine"}, nil, []string{"nginx"}},
		{"several labels", []string{"unknown", "alpine"}, nil, []string{"nginx", "traefik", "zookeeper"}},
		{"all", []string{"all"}, nil, []string{"nginx", "traefik", "zookeeper"}},
		{"only restricts the selection", []string{"unknown"}, []string{"zookeeper"}, []string{"zookeeper"}},
		{"only never adds a repository of another label", []string{"unknown"}, []string{"nginx"}, nil},
		{"unlisted label selects nothing", []string{"debian"}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := repositories(selectTargets(pinnedFixture(), archetypesFixture(), tc.families, tc.only))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("selected %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyFamiliesOnlyChangesSelectedLabelsAndNeverSetsUnknown(t *testing.T) {
	archetypes := archetypesFixture()
	archetypes["nginx"]["extra"] = "kept"
	evidence := []Evidence{
		{Repository: "zookeeper", Status: statusOK, Family: familyDebian},
		{Repository: "traefik", Status: statusOK, Family: familyUnknown},
		{Repository: "nginx", Status: statusOK, Family: familyDebian},
		{Repository: "bonita", Status: statusError, Family: familyDebian},
		{Repository: "absent", Status: statusOK, Family: familyDebian},
	}
	changed := applyFamilies(archetypes, evidence, []string{"unknown"})

	if strings.Join(changed, ",") != "zookeeper" {
		t.Errorf("changed %v, want only zookeeper", changed)
	}
	if got := archetypes["zookeeper"]["base_family"]; got != familyDebian {
		t.Errorf("zookeeper = %v, want debian", got)
	}
	if got := archetypes["traefik"]["base_family"]; got != familyUnknown {
		t.Errorf("an unresolved image must keep unknown, got %v", got)
	}
	if got := archetypes["nginx"]["base_family"]; got != "alpine" {
		t.Errorf("a label outside the selection must not change, got %v", got)
	}
	if got := archetypes["bonita"]["base_family"]; got != familyUnknown {
		t.Errorf("an image that could not be read must keep its label, got %v", got)
	}
	if archetypes["nginx"]["extra"] != "kept" || archetypes["zookeeper"]["archetype"] != "other" {
		t.Error("other fields of the entries must be preserved")
	}
}

// fakeRegistry serves in-memory images by reference.
type fakeRegistry struct {
	images map[string]v1.Image
	errs   map[string]error
	calls  []string
}

func (f *fakeRegistry) source(_ context.Context, ref string, _ v1.Platform) (v1.Image, error) {
	f.calls = append(f.calls, ref)
	if err := f.errs[ref]; err != nil {
		return nil, err
	}
	if img, ok := f.images[ref]; ok {
		return img, nil
	}
	return nil, errors.New("manifest unknown")
}

type runFiles struct {
	dir                          string
	pinned, archetypes, evidence string
}

func setUpRunFiles(t *testing.T) runFiles {
	t.Helper()
	dir := t.TempDir()
	files := runFiles{
		dir:        dir,
		pinned:     filepath.Join(dir, "pinned.json"),
		archetypes: filepath.Join(dir, "archetypes.json"),
		evidence:   filepath.Join(dir, "evidence.json"),
	}
	for path, value := range map[string]any{files.pinned: pinnedFixture(), files.archetypes: archetypesFixture()} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func runTool(t *testing.T, files runFiles, registry *fakeRegistry, extra ...string) (int, string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	sleeps := 0
	args := append([]string{"-pinned", files.pinned, "-archetypes", files.archetypes, "-out", files.evidence}, extra...)
	code := run(context.Background(), args, &stdout, &stderr, registry.source, func(time.Duration) { sleeps++ })
	return code, stdout.String(), stderr.String(), sleeps
}

func debianImage(t *testing.T) v1.Image {
	return imageOf(t, []tarEntry{file("etc/os-release", debianOSRelease), file("bin/sh", "x")})
}

func TestRunWritesEvidenceAndAppliesTheLabels(t *testing.T) {
	files := setUpRunFiles(t)
	registry := &fakeRegistry{images: map[string]v1.Image{
		pinnedFixture()[0].ImmutableRef: debianImage(t),
		pinnedFixture()[1].ImmutableRef: imageOf(t, []tarEntry{file("traefik", "binary")}),
	}}

	code, stdout, stderr, sleeps := runTool(t, files, registry, "-apply", "-families", "unknown", "-only", "zookeeper,traefik")
	if code != exitOK {
		t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout, stderr)
	}
	if sleeps != 1 {
		t.Errorf("slept %d times, want once between two images", sleeps)
	}

	var file EvidenceFile
	data, err := os.ReadFile(files.evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.SchemaVersion != 1 || len(file.Rules) == 0 || len(file.Images) != 2 {
		t.Fatalf("unexpected evidence file: %+v", file)
	}
	byRepo := map[string]Evidence{}
	for _, ev := range file.Images {
		byRepo[ev.Repository] = ev
	}
	zk := byRepo["zookeeper"]
	if zk.Family != familyDebian || zk.OSRelease != debianOSRelease || zk.OSReleasePath != "/etc/os-release" || zk.ID != "debian" || !zk.HasShell {
		t.Errorf("zookeeper evidence = %+v", zk)
	}
	if zk.ConfigDigest == "" || zk.ImmutableRef != pinnedFixture()[0].ImmutableRef {
		t.Errorf("evidence must record the reference and the config digest: %+v", zk)
	}
	tr := byRepo["traefik"]
	if tr.Family != familyScratch || tr.OSRelease != "" || tr.OSReleaseNote == "" {
		t.Errorf("traefik evidence = %+v", tr)
	}

	var archetypes map[string]map[string]any
	data, _ = os.ReadFile(files.archetypes)
	if err := json.Unmarshal(data, &archetypes); err != nil {
		t.Fatal(err)
	}
	if archetypes["zookeeper"]["base_family"] != familyDebian || archetypes["traefik"]["base_family"] != familyScratch {
		t.Errorf("labels were not applied: %v", archetypes)
	}
	if archetypes["nginx"]["base_family"] != "alpine" || archetypes["bonita"]["base_family"] != familyUnknown {
		t.Errorf("labels outside the selection changed: %v", archetypes)
	}
	if !strings.Contains(stdout, "LABELED") {
		t.Errorf("output lacks the per-image lines:\n%s", stdout)
	}
}

func TestRunWithoutApplyLeavesTheArchetypesFileUntouched(t *testing.T) {
	files := setUpRunFiles(t)
	before, _ := os.ReadFile(files.archetypes)
	registry := &fakeRegistry{images: map[string]v1.Image{pinnedFixture()[0].ImmutableRef: debianImage(t)}}

	if code, _, stderr, _ := runTool(t, files, registry, "-only", "zookeeper"); code != exitOK {
		t.Fatalf("exit code %d\n%s", code, stderr)
	}
	after, _ := os.ReadFile(files.archetypes)
	if !bytes.Equal(before, after) {
		t.Error("the archetypes file changed without -apply")
	}
	if _, err := os.Stat(files.evidence); err != nil {
		t.Errorf("the evidence file must exist: %v", err)
	}
}

func TestRunStopsOnRateLimitAndWritesNothing(t *testing.T) {
	files := setUpRunFiles(t)
	before, _ := os.ReadFile(files.archetypes)
	limited := &transport.Error{StatusCode: http.StatusTooManyRequests, Errors: []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode}}}
	registry := &fakeRegistry{
		images: map[string]v1.Image{pinnedFixture()[0].ImmutableRef: debianImage(t)},
		errs:   map[string]error{pinnedFixture()[1].ImmutableRef: limited},
	}

	code, _, stderr, _ := runTool(t, files, registry, "-apply", "-only", "zookeeper,traefik")
	if code != exitIncomplete {
		t.Fatalf("exit code %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(stderr, "HTTP 429") || !strings.Contains(stderr, "traefik") {
		t.Errorf("stderr must name the rate limit and the image:\n%s", stderr)
	}
	if _, err := os.Stat(files.evidence); !os.IsNotExist(err) {
		t.Error("no evidence file may be written after a rate limit")
	}
	after, _ := os.ReadFile(files.archetypes)
	if !bytes.Equal(before, after) {
		t.Error("the archetypes file must stay untouched after a rate limit")
	}
}

func TestRunKeepsTheLabelOfAnImageThatCannotBeRead(t *testing.T) {
	files := setUpRunFiles(t)
	registry := &fakeRegistry{images: map[string]v1.Image{pinnedFixture()[0].ImmutableRef: debianImage(t)}}
	// traefik is not served and fails with a plain error.

	code, _, stderr, _ := runTool(t, files, registry, "-apply", "-only", "zookeeper,traefik")
	if code != exitIncomplete {
		t.Fatalf("exit code %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(stderr, "FAILED") {
		t.Errorf("stderr must report the failed image:\n%s", stderr)
	}
	var file EvidenceFile
	data, _ := os.ReadFile(files.evidence)
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, ev := range file.Images {
		statuses[ev.Repository] = ev.Status
	}
	if statuses["zookeeper"] != statusOK || statuses["traefik"] != statusError {
		t.Errorf("statuses = %v", statuses)
	}
	var archetypes map[string]map[string]any
	data, _ = os.ReadFile(files.archetypes)
	_ = json.Unmarshal(data, &archetypes)
	if archetypes["traefik"]["base_family"] != familyUnknown || archetypes["zookeeper"]["base_family"] != familyDebian {
		t.Errorf("labels = %v", archetypes)
	}
}

func TestRunReportsUnresolvedImagesAsIncomplete(t *testing.T) {
	files := setUpRunFiles(t)
	registry := &fakeRegistry{images: map[string]v1.Image{
		// A shell and no release data stays unknown.
		pinnedFixture()[0].ImmutableRef: imageOf(t, []tarEntry{file("bin/sh", "x")}),
	}}
	code, _, stderr, _ := runTool(t, files, registry, "-apply", "-only", "zookeeper")
	if code != exitIncomplete {
		t.Fatalf("exit code %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(stderr, "unresolved zookeeper") {
		t.Errorf("stderr must name the unresolved image:\n%s", stderr)
	}
	var archetypes map[string]map[string]any
	data, _ := os.ReadFile(files.archetypes)
	_ = json.Unmarshal(data, &archetypes)
	if archetypes["zookeeper"]["base_family"] != familyUnknown {
		t.Errorf("an unresolved image must keep unknown, got %v", archetypes["zookeeper"]["base_family"])
	}
}

func TestRunDryRunReadsManifestsOnly(t *testing.T) {
	files := setUpRunFiles(t)
	registry := &fakeRegistry{images: map[string]v1.Image{
		pinnedFixture()[0].ImmutableRef: debianImage(t),
		pinnedFixture()[1].ImmutableRef: debianImage(t),
	}}
	code, stdout, stderr, _ := runTool(t, files, registry, "-dry-run", "-apply")
	if code != exitOK {
		t.Fatalf("exit code %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "PLAN") || !strings.Contains(stdout, "layers") || !strings.Contains(stdout, "dry run complete") {
		t.Errorf("dry run output lacks the plan:\n%s", stdout)
	}
	if _, err := os.Stat(files.evidence); !os.IsNotExist(err) {
		t.Error("a dry run must not write the evidence file")
	}
}

func TestRunFromEvidenceReclassifiesWithoutTheRegistry(t *testing.T) {
	files := setUpRunFiles(t)
	stored := EvidenceFile{
		SchemaVersion: 1,
		Tool:          "label_base_family 0",
		Platform:      "linux/amd64",
		Images: []Evidence{
			// The stored family is stale: the raw evidence says alpine.
			{Repository: "zookeeper", Status: statusOK, OSReleasePath: "/etc/os-release", OSRelease: alpineOSRelease, Family: familyUnknown, Rule: "old rule"},
			{Repository: "traefik", Status: statusOK, OSReleaseNote: "no /etc/os-release and no /usr/lib/os-release in the final filesystem", HasShell: false, Family: familyUnknown},
			{Repository: "nginx", Status: statusError, Error: "manifest unknown"},
		},
	}
	source := filepath.Join(files.dir, "stored.json")
	data, _ := json.Marshal(stored)
	if err := os.WriteFile(source, data, 0o644); err != nil {
		t.Fatal(err)
	}
	registry := &fakeRegistry{}

	code, _, stderr, _ := runTool(t, files, registry, "-from-evidence", source, "-apply")
	if code != exitIncomplete {
		t.Fatalf("exit code %d, want %d because one record could not be read\n%s", code, exitIncomplete, stderr)
	}
	if len(registry.calls) != 0 {
		t.Errorf("offline mode made registry calls: %v", registry.calls)
	}

	var rewritten EvidenceFile
	data, _ = os.ReadFile(files.evidence)
	if err := json.Unmarshal(data, &rewritten); err != nil {
		t.Fatal(err)
	}
	families := map[string]string{}
	for _, ev := range rewritten.Images {
		families[ev.Repository] = ev.Family
	}
	if families["zookeeper"] != familyAlpine || families["traefik"] != familyScratch || families["nginx"] != "" {
		t.Errorf("families after reclassification = %v", families)
	}
	if rewritten.Tool != toolVersion || len(rewritten.Rules) == 0 {
		t.Errorf("tool and rules must be refreshed: %q %v", rewritten.Tool, rewritten.Rules)
	}
	if rewritten.Images[0].ID != "alpine" {
		t.Errorf("derived fields must be refreshed, ID = %q", rewritten.Images[0].ID)
	}

	var archetypes map[string]map[string]any
	data, _ = os.ReadFile(files.archetypes)
	_ = json.Unmarshal(data, &archetypes)
	if archetypes["zookeeper"]["base_family"] != familyAlpine || archetypes["traefik"]["base_family"] != familyScratch {
		t.Errorf("labels were not applied from the evidence: %v", archetypes)
	}
	if archetypes["nginx"]["base_family"] != "alpine" {
		t.Errorf("a label outside the selection changed: %v", archetypes["nginx"])
	}
}

func TestRunRejectsDryRunTogetherWithFromEvidence(t *testing.T) {
	files := setUpRunFiles(t)
	code, _, stderr, _ := runTool(t, files, &fakeRegistry{}, "-dry-run", "-from-evidence", filepath.Join(files.dir, "x.json"))
	if code != exitUsage || !strings.Contains(stderr, "-dry-run") {
		t.Errorf("code %d, stderr %q", code, stderr)
	}
}

const compactArchetypes = `{
  "adminer": {"archetype": "application", "base_family": "alpine"},
  "rocket.chat": {"archetype": "application", "base_family": "unknown"},
  "traefik": {"archetype": "web-ingress", "base_family": "unknown"},
  "zookeeper": {"archetype": "other", "base_family": "unknown"}
}
`

func changedLines(before, after string) []int {
	b, a := strings.Split(before, "\n"), strings.Split(after, "\n")
	if len(b) != len(a) {
		return []int{-1}
	}
	var lines []int
	for i := range b {
		if b[i] != a[i] {
			lines = append(lines, i+1)
		}
	}
	return lines
}

func TestPatchBaseFamiliesChangesOnlyTheNamedValues(t *testing.T) {
	patched, err := patchBaseFamilies([]byte(compactArchetypes), map[string]string{"zookeeper": familyDebian, "rocket.chat": familyUbuntu})
	if err != nil {
		t.Fatal(err)
	}
	got := string(patched)
	if lines := changedLines(compactArchetypes, got); len(lines) != 2 || lines[0] != 3 || lines[1] != 5 {
		t.Fatalf("changed lines %v, want only lines 3 and 5\n%s", lines, got)
	}
	want := strings.NewReplacer(
		`"rocket.chat": {"archetype": "application", "base_family": "unknown"}`, `"rocket.chat": {"archetype": "application", "base_family": "ubuntu"}`,
		`"zookeeper": {"archetype": "other", "base_family": "unknown"}`, `"zookeeper": {"archetype": "other", "base_family": "debian"}`,
	).Replace(compactArchetypes)
	if got != want {
		t.Errorf("patched text differs from the expected text:\n%s", got)
	}
}

func TestPatchBaseFamiliesWorksOnAnIndentedLayoutAndKeepsNeighbours(t *testing.T) {
	raw := "{\n  \"traefik\": {\n    \"archetype\": \"web-ingress\",\n    \"base_family\": \"unknown\"\n  },\n  \"traefik2\": {\n    \"archetype\": \"web-ingress\",\n    \"base_family\": \"unknown\"\n  }\n}\n"
	patched, err := patchBaseFamilies([]byte(raw), map[string]string{"traefik": familyAlpine})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]map[string]string
	if err := json.Unmarshal(patched, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["traefik"]["base_family"] != familyAlpine || decoded["traefik2"]["base_family"] != "unknown" {
		t.Errorf("a repository whose name starts like another must not be touched: %v", decoded)
	}
}

func TestPatchBaseFamiliesRefusesMissingAndAmbiguousEntries(t *testing.T) {
	if _, err := patchBaseFamilies([]byte(compactArchetypes), map[string]string{"absent": familyDebian}); err == nil || !strings.Contains(err.Error(), "found 0") {
		t.Errorf("missing repository error = %v", err)
	}
	duplicate := "{\n  \"traefik\": {\"base_family\": \"unknown\"},\n  \"traefik\": {\"base_family\": \"unknown\"}\n}\n"
	if _, err := patchBaseFamilies([]byte(duplicate), map[string]string{"traefik": familyDebian}); err == nil || !strings.Contains(err.Error(), "found 2") {
		t.Errorf("duplicate repository error = %v", err)
	}
}

func TestRunApplyKeepsTheLayoutOfTheArchetypesFile(t *testing.T) {
	files := setUpRunFiles(t)
	if err := os.WriteFile(files.archetypes, []byte(compactArchetypes), 0o644); err != nil {
		t.Fatal(err)
	}
	stored := EvidenceFile{SchemaVersion: 1, Images: []Evidence{
		{Repository: "zookeeper", Status: statusOK, OSReleasePath: "/etc/os-release", OSRelease: debianOSRelease, HasShell: true},
		{Repository: "traefik", Status: statusOK, OSReleasePath: "/etc/os-release", OSRelease: alpineOSRelease, HasShell: true},
	}}
	source := filepath.Join(files.dir, "stored.json")
	data, _ := json.Marshal(stored)
	if err := os.WriteFile(source, data, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr, _ := runTool(t, files, &fakeRegistry{}, "-from-evidence", source, "-apply")
	if code != exitOK {
		t.Fatalf("exit code %d\n%s", code, stderr)
	}
	after, _ := os.ReadFile(files.archetypes)
	if lines := changedLines(compactArchetypes, string(after)); len(lines) != 2 || lines[0] != 4 || lines[1] != 5 {
		t.Errorf("changed lines %v, want only the two labeled repositories (lines 4 and 5)\n%s", lines, after)
	}
	if !strings.Contains(string(after), `"rocket.chat": {"archetype": "application", "base_family": "unknown"}`) {
		t.Error("a repository without evidence must keep its label byte for byte")
	}
}

func TestRunWithNothingSelected(t *testing.T) {
	files := setUpRunFiles(t)
	registry := &fakeRegistry{}
	code, stdout, _, _ := runTool(t, files, registry, "-families", "debian")
	if code != exitOK || len(registry.calls) != 0 || !strings.Contains(stdout, "nothing to do") {
		t.Errorf("code %d, calls %v, stdout %q", code, registry.calls, stdout)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	files := setUpRunFiles(t)
	registry := &fakeRegistry{}
	for name, args := range map[string][]string{
		"platform without architecture": {"-platform", "linux"},
		"unknown flag":                  {"-nonsense"},
		"missing pinned file":           {"-pinned", filepath.Join(files.dir, "missing.json")},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), append([]string{"-archetypes", files.archetypes, "-out", files.evidence}, args...), &stdout, &stderr, registry.source, func(time.Duration) {})
			if code != exitUsage {
				t.Errorf("exit code %d, want %d", code, exitUsage)
			}
		})
	}
}

func TestHumanSizes(t *testing.T) {
	cases := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"}
	for in, want := range cases {
		if got := human(in); got != want {
			t.Errorf("human(%d) = %q, want %q", in, got, want)
		}
	}
}
