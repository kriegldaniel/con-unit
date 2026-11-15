package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/dataaudit"
)

func TestReadImageList(t *testing.T) {
	input := "# Comment 1\n\nalpine:latest\n# Comment 2\npython:3.11-slim\n"
	images, err := readImageList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readImageList error: %v", err)
	}
	if len(images) != 2 || images[0] != "alpine:latest" || images[1] != "python:3.11-slim" {
		t.Fatalf("unexpected images: %v", images)
	}
}

func TestPinnedImageRecordJSON(t *testing.T) {
	rec := PinnedImageRecord{OriginalTag: "alpine:3.24.3", ImmutableRef: "index.docker.io/library/alpine@sha256:be2656", Status: "PINNED"}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if !strings.Contains(string(data), `"status":"PINNED"`) {
		t.Errorf("expected status PINNED in JSON, got: %s", data)
	}
}

// ---------------------------------------------------------------------------
// Stub registry

func digestFor(tag string) string {
	return fmt.Sprintf("sha256:%064x", len(tag)*104729+int(tag[0]))
}

// stubRegistry resolves tags by their name: "single" is a single manifest,
// "amd64only" lacks arm64, "limited" answers 429, "broken" errors, and
// everything else is a dual-architecture index.
func stubRegistry(calls *[]string) resolver {
	return func(_ context.Context, ref name.Reference) (manifestInfo, error) {
		tag := ref.Identifier()
		repo := ref.Context().RepositoryStr()
		*calls = append(*calls, repo+":"+tag)
		switch {
		case strings.HasPrefix(repo, "library/single"):
			return manifestInfo{Digest: digestFor(repo + tag)}, nil
		case strings.HasPrefix(repo, "library/amd64only"):
			return manifestInfo{Digest: digestFor(repo + tag), IsIndex: true, Platforms: []string{"linux/amd64", "windows/amd64"}}, nil
		case strings.HasPrefix(repo, "library/limited"):
			return manifestInfo{}, fmt.Errorf("%w: HTTP 429", errRateLimited)
		case strings.HasPrefix(repo, "library/broken"):
			return manifestInfo{}, errors.New("boom")
		}
		return manifestInfo{Digest: digestFor(repo + tag), IsIndex: true, Platforms: []string{"linux/amd64", "linux/arm64"}}, nil
	}
}

func TestPinImageMultiArchOutcomes(t *testing.T) {
	var calls []string
	resolve := stubRegistry(&calls)
	ctx := context.Background()
	cases := []struct {
		tag, status string
	}{
		{"alpine:3.1", statusPinned},
		{"single:1", statusExcludedArch},
		{"amd64only:1", statusExcludedArch},
		{"broken:1", statusFailed},
		{"::not a ref", statusFailed},
	}
	for _, c := range cases {
		rec, err := pinImageMultiArch(ctx, c.tag, resolve)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.tag, err)
			continue
		}
		if rec.Status != c.status {
			t.Errorf("%s: status %s, want %s (%s)", c.tag, rec.Status, c.status, rec.Error)
		}
	}
	rec, _ := pinImageMultiArch(ctx, "alpine:3.1", resolve)
	if !strings.HasPrefix(rec.ImmutableRef, "index.docker.io/library/alpine@sha256:") || rec.ManifestDigest == "" {
		t.Errorf("pinned record lacks an immutable reference: %+v", rec)
	}
	if _, err := pinImageMultiArch(ctx, "limited:1", resolve); !errors.Is(err, errRateLimited) {
		t.Errorf("429 must be returned as errRateLimited, got %v", err)
	}
}

func TestIsRateLimit(t *testing.T) {
	if !isRateLimit(&transport.Error{StatusCode: 429}) {
		t.Error("HTTP 429 must be a rate limit")
	}
	if !isRateLimit(&transport.Error{StatusCode: 200, Errors: []transport.Diagnostic{{Code: transport.TooManyRequestsErrorCode}}}) {
		t.Error("TOOMANYREQUESTS must be a rate limit")
	}
	if !isRateLimit(fmt.Errorf("wrapped: %w", &transport.Error{StatusCode: 429})) {
		t.Error("a wrapped 429 must be a rate limit")
	}
	if isRateLimit(&transport.Error{StatusCode: 404}) || isRateLimit(errors.New("connection refused")) {
		t.Error("other errors must not be rate limits")
	}
}

func TestPinAllHonorsDelayAndStopsAtRateLimit(t *testing.T) {
	var calls []string
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d) }
	log := clilog.NewPlain(&bytes.Buffer{})
	images := []string{"alpine:1", "nginx:1", "limited:1", "redis:1"}
	records, stopAt, err := pinAll(context.Background(), images, stubRegistry(&calls), 1500*time.Millisecond, sleep, log)
	if !errors.Is(err, errRateLimited) {
		t.Fatalf("err = %v, want rate limit", err)
	}
	if stopAt != 2 || len(records) != 2 {
		t.Errorf("stopAt = %d, records = %d; want 2 and 2", stopAt, len(records))
	}
	if len(calls) != 3 {
		t.Errorf("registry calls = %v; nothing after the 429 may be requested", calls)
	}
	// One pause before every request except the first.
	if len(slept) != 2 || slept[0] != 1500*time.Millisecond {
		t.Errorf("sleeps = %v, want two pauses of 1.5s", slept)
	}
	// Zero delay never sleeps.
	slept = nil
	calls = nil
	if _, _, err := pinAll(context.Background(), []string{"alpine:1", "nginx:1"}, stubRegistry(&calls), 0, sleep, log); err != nil || len(slept) != 0 {
		t.Errorf("zero delay must not sleep: err %v sleeps %v", err, slept)
	}
}

// ---------------------------------------------------------------------------
// Command runs

type fixture struct {
	dir                                                           string
	input, outTxt, outJSON, outAudit, top10, outTop10, deprecated string
}

func newFixture(t *testing.T, candidates, top10 []string) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{
		dir: dir, input: filepath.Join(dir, "full.txt"), outTxt: filepath.Join(dir, "pinned.txt"),
		outJSON: filepath.Join(dir, "pinned.json"), outAudit: filepath.Join(dir, "audit.json"),
		top10: filepath.Join(dir, "top10.txt"), outTop10: filepath.Join(dir, "top10_pinned.txt"),
		deprecated: filepath.Join(dir, "deprecated.txt"),
	}
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(f.input, fmt.Sprintf("# Candidates (N = %d)\n\n%s\n", len(candidates), strings.Join(candidates, "\n")))
	write(f.top10, "# Top 10\n"+strings.Join(top10, "\n")+"\n")
	return f
}

func (f *fixture) args(extra ...string) []string {
	base := []string{
		"-input", f.input, "-out-txt", f.outTxt, "-out-json", f.outJSON, "-out-audit", f.outAudit,
		"-top10", f.top10, "-out-top10-txt", f.outTop10, "-deprecated", f.deprecated,
		"-frame-commit", "abc1234", "-frame-date", "2026-11-13", "-delay", "0",
	}
	return append(base, extra...)
}

var fixedNow = func() time.Time { return time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC) }

func runPin(t *testing.T, resolve resolver, args []string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, resolve, func(time.Duration) {}, fixedNow)
	return code, out.String(), errb.String()
}

func loadAudit(t *testing.T, path string) *dataaudit.Audit {
	t.Helper()
	a, err := dataaudit.Load(path)
	if err != nil {
		t.Fatalf("audit does not load or validate: %v", err)
	}
	return a
}

func TestRunWritesAuditAndDerivesTop10(t *testing.T) {
	f := newFixture(t, []string{"alpine:1", "nginx:1", "single:1", "amd64only:2", "redis:1"}, []string{"alpine:1", "redis:1"})
	if err := os.WriteFile(f.deprecated, []byte("# deprecated\nnginx\nredis:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	code, _, stderr := runPin(t, stubRegistry(&calls), f.args())
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(calls) != 5 {
		t.Errorf("one manifest GET per candidate expected, got %v", calls)
	}
	a := loadAudit(t, f.outAudit)
	if a.Counts.Candidates != 5 || a.Counts.Pinned != 3 || a.Counts.Excluded != 2 || a.Counts.Failed != 0 {
		t.Errorf("counts = %+v", a.Counts)
	}
	if a.Mode != "registry" || a.Frame.Commit != "abc1234" || a.Frame.Date != "2026-11-13" || !a.Frame.Recorded() {
		t.Errorf("mode/frame = %s %+v", a.Mode, a.Frame)
	}
	if a.GeneratedAt != "2026-11-14T09:00:00Z" || a.ToolVersion == "" || a.InclusionRule == "" || a.Platform != "linux/amd64" {
		t.Errorf("audit metadata incomplete: %+v", a)
	}
	if len(a.ExclusionLog) != 2 || a.ExclusionLog[0].OriginalTag != "single:1" || a.ExclusionLog[1].OriginalTag != "amd64only:2" {
		t.Errorf("exclusion log = %+v", a.ExclusionLog)
	}
	for _, e := range a.ExclusionLog {
		if e.Reason == "" || e.Status != statusExcludedArch {
			t.Errorf("exclusion entry lacks reason or status: %+v", e)
		}
	}
	// Hashes identify the files by content.
	for path, want := range map[string]string{f.input: a.Input.SHA256, f.outTxt: a.Outputs.PinnedTxt.SHA256} {
		got, err := sha256File(path)
		if err != nil || got != want {
			t.Errorf("sha256 of %s = %s, audit says %s", path, got, want)
		}
	}
	if a.Input.DeclaredN == nil || *a.Input.DeclaredN != 5 || a.Outputs.PinnedTxt.DeclaredN == nil || *a.Outputs.PinnedTxt.DeclaredN != 3 {
		t.Errorf("declared N not recorded: %+v %+v", a.Input, a.Outputs.PinnedTxt)
	}
	// Deprecated flags (by repository and by tag).
	if a.Counts.Deprecated != 2 || len(a.Deprecated) != 2 || a.Deprecated[0].OriginalTag != "nginx:1" || !a.Deprecated[0].Pinned {
		t.Errorf("deprecated = %+v", a.Deprecated)
	}
	// Top-10 derived from the main run, therefore contained.
	if a.Outputs.Top10 == nil || !a.Outputs.Top10.AllInMain || a.Outputs.Top10.Pinned.Entries != 2 {
		t.Fatalf("top10 = %+v", a.Outputs.Top10)
	}
	main, _ := readImageListFile(f.outTxt)
	derived, _ := readImageListFile(f.outTop10)
	if m := missingFrom(derived, main); len(m) != 0 {
		t.Errorf("derived top-10 not contained in the main list: %v", m)
	}
	if !strings.Contains(stderr, "deprecated image in the dataset: nginx:1") {
		t.Errorf("deprecated warning missing: %s", stderr)
	}
}

func TestRunRecordsUnrecordedFrame(t *testing.T) {
	f := newFixture(t, []string{"alpine:1"}, []string{"alpine:1"})
	var calls []string
	args := []string{"-input", f.input, "-out-txt", f.outTxt, "-out-json", f.outJSON, "-out-audit", f.outAudit,
		"-top10", f.top10, "-out-top10-txt", f.outTop10, "-deprecated", f.deprecated, "-delay", "0"}
	code, _, stderr := runPin(t, stubRegistry(&calls), args)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	a := loadAudit(t, f.outAudit)
	if a.Frame.Commit != dataaudit.Unrecorded || a.Frame.Recorded() {
		t.Errorf("missing frame flags must be recorded as unrecorded: %+v", a.Frame)
	}
	if !strings.Contains(stderr, "sampling frame not supplied") {
		t.Errorf("expected frame warning, got %s", stderr)
	}
}

func TestRunStopsOnRateLimitWithoutWritingOutputs(t *testing.T) {
	f := newFixture(t, []string{"alpine:1", "limited:1", "redis:1"}, []string{"alpine:1"})
	var calls []string
	code, _, stderr := runPin(t, stubRegistry(&calls), f.args())
	if code != 3 {
		t.Errorf("exit = %d, want 3", code)
	}
	for _, want := range []string{"HTTP 429", "candidate 2 of 3", "limited:1", "no output file was written", "6 hours"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("message lacks %q:\n%s", want, stderr)
		}
	}
	for _, p := range []string{f.outTxt, f.outJSON, f.outAudit, f.outTop10} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s must not be written after a rate limit", p)
		}
	}
	if len(calls) != 2 {
		t.Errorf("no request may follow the 429: %v", calls)
	}
}

func TestRunFailsWhenTop10EntryIsNotPinned(t *testing.T) {
	f := newFixture(t, []string{"alpine:1", "single:1"}, []string{"alpine:1", "single:1", "ghost:9"})
	var calls []string
	code, _, stderr := runPin(t, stubRegistry(&calls), f.args())
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	for _, want := range []string{"single:1 is not pinned", "ghost:9 is not a candidate"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("message lacks %q:\n%s", want, stderr)
		}
	}
	// The audit is still written so the failure is documented.
	a, err := dataaudit.Load(f.outAudit)
	if err != nil {
		t.Fatalf("audit must be written even when the top-10 derivation fails: %v", err)
	}
	if a.Outputs.Top10 == nil || a.Outputs.Top10.AllInMain || len(a.Outputs.Top10.MissingInMain) != 2 {
		t.Errorf("audit must record the failed top-10 assertion: %+v", a.Outputs.Top10)
	}
	if _, err := os.Stat(f.outTop10); err == nil {
		t.Error("no top-10 pinned file may be written when entries are missing")
	}
}

func TestAuditOnlyMakesNoRequestAndChecksTop10Containment(t *testing.T) {
	f := newFixture(t, []string{"alpine:1", "nginx:1", "single:1"}, []string{"alpine:1", "nginx:1"})
	var calls []string
	if code, _, stderr := runPin(t, stubRegistry(&calls), f.args()); code != 0 {
		t.Fatalf("setup run exit %d: %s", code, stderr)
	}
	if len(calls) != 3 {
		t.Fatalf("setup calls = %v", calls)
	}

	// Audit-only on consistent files: no registry call, containment holds.
	noNetwork := func(context.Context, name.Reference) (manifestInfo, error) {
		t.Error("audit-only must not call the registry")
		return manifestInfo{}, errors.New("network disabled")
	}
	if code, _, stderr := runPin(t, noNetwork, f.args("-audit-only")); code != 0 {
		t.Fatalf("audit-only exit %d: %s", code, stderr)
	}
	a := loadAudit(t, f.outAudit)
	if a.Mode != "audit-only" || a.Outputs.Top10 == nil || !a.Outputs.Top10.AllInMain {
		t.Errorf("audit-only result = %s %+v", a.Mode, a.Outputs.Top10)
	}

	// Corrupt the top-10 pinned list with a digest that is not in the main list.
	bad := "index.docker.io/library/nginx@sha256:" + strings.Repeat("0", 64)
	if err := os.WriteFile(f.outTop10, []byte("# (N = 2)\n"+mustLine(t, f.outTxt, "alpine")+"\n"+bad+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runPin(t, noNetwork, f.args("-audit-only"))
	if code != 1 {
		t.Errorf("exit = %d, want 1 for a top-10 entry outside the main list", code)
	}
	if !strings.Contains(stderr, "top-10 entry is not in the main pinned list: "+bad) {
		t.Errorf("missing entry not named:\n%s", stderr)
	}
	a = loadAudit(t, f.outAudit)
	if a.Outputs.Top10.AllInMain || len(a.Outputs.Top10.MissingInMain) != 1 {
		t.Errorf("audit must record the failed assertion: %+v", a.Outputs.Top10)
	}
}

func mustLine(t *testing.T, path, repo string) string {
	t.Helper()
	lines, err := readImageListFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if strings.Contains(l, "/library/"+repo+"@") {
			return l
		}
	}
	t.Fatalf("no %s entry in %s", repo, path)
	return ""
}

func TestDeriveTop10(t *testing.T) {
	records := []PinnedImageRecord{
		{OriginalTag: "a:1", Status: statusPinned, ImmutableRef: "index.docker.io/library/a@sha256:" + strings.Repeat("1", 64)},
		{OriginalTag: "b:1", Status: statusExcludedArch},
	}
	refs, problems := deriveTop10([]string{"a:1"}, records)
	if len(problems) != 0 || len(refs) != 1 || !strings.Contains(refs[0], "library/a@") {
		t.Errorf("deriveTop10 = %v %v", refs, problems)
	}
	_, problems = deriveTop10([]string{"a:1", "b:1", "c:1"}, records)
	if joined := strings.Join(problems, "; "); !strings.Contains(joined, "b:1 is not pinned") || !strings.Contains(joined, "c:1 is not a candidate") {
		t.Errorf("problems = %v", problems)
	}
}

func TestDuplicateAndRefChecks(t *testing.T) {
	if d := duplicates([]string{"a", "b", "a", "c", "b"}); strings.Join(d, ",") != "a,b" {
		t.Errorf("duplicates = %v", d)
	}
	good := "index.docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)
	if !pinnedRef.MatchString(good) || pinnedRef.MatchString("nginx:latest") || pinnedRef.MatchString("nginx@sha256:abc") {
		t.Error("pinnedRef must accept only full sha256 digests")
	}
}

// ---------------------------------------------------------------------------
// Real fixtures

func TestRealDatasetAuditReconciles(t *testing.T) {
	root := filepath.Join("..", "..")
	dir := t.TempDir()
	out := filepath.Join(dir, "audit.json")
	noNetwork := func(context.Context, name.Reference) (manifestInfo, error) {
		t.Error("audit-only must not call the registry")
		return manifestInfo{}, errors.New("network disabled")
	}
	fx := func(n string) string { return filepath.Join(root, "fixtures", n) }
	var outb, errb bytes.Buffer
	code := run([]string{
		"-audit-only", "-input", fx("evaluation_dataset_full.txt"), "-out-txt", fx("evaluation_dataset_pinned.txt"),
		"-out-json", fx("evaluation_dataset_pinned.json"), "-out-audit", out,
		"-top10", fx("evaluation_dataset_top10.txt"), "-out-top10-txt", fx("evaluation_dataset_top10_pinned.txt"),
		"-deprecated", fx("deprecated_images.txt"),
	}, &outb, &errb, noNetwork, func(time.Duration) {}, fixedNow)
	if code != 0 {
		t.Fatalf("audit of the repository dataset failed (exit %d):\n%s", code, errb.String())
	}
	a := loadAudit(t, out)
	if a.Counts.Candidates != *a.Input.DeclaredN || a.Counts.Pinned != *a.Outputs.PinnedTxt.DeclaredN {
		t.Errorf("counts %+v do not match the declared N of the lists (%d, %d)", a.Counts, *a.Input.DeclaredN, *a.Outputs.PinnedTxt.DeclaredN)
	}
	if a.Counts.Excluded != 8 || a.Counts.Failed != 0 {
		t.Errorf("expected 8 single-architecture exclusions and no failures, got %+v", a.Counts)
	}
	if a.Outputs.Top10 == nil || !a.Outputs.Top10.AllInMain || a.Outputs.Top10.Pinned.Entries != 10 {
		t.Errorf("top-10 must be a subset of the main pinned list: %+v", a.Outputs.Top10)
	}
	main, _ := readImageListFile(fx("evaluation_dataset_pinned.txt"))
	if d := duplicates(main); len(d) != 0 {
		t.Errorf("pinned list has duplicate entries: %v", d)
	}
	for _, r := range main {
		if !pinnedRef.MatchString(r) {
			t.Errorf("pinned entry is not digest-pinned: %s", r)
		}
	}
}
