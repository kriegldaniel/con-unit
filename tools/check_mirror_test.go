package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stubCurl imitates the three curl calls of check_mirror.sh: the token GET and
// the manifest HEAD. Behavior per repository comes from $STUB_DIR/rules, one
// "repo behavior" pair per line: ok, missing, mismatch, nodigest, error,
// 401once, or 429xN for N throttled answers before success. Repositories
// without a rule answer ok. Every call is logged.
const stubCurl = `#!/usr/bin/env bash
dir="$STUB_DIR"
url="${@: -1}"
printf '%s\n' "$*" >> "$dir/curl_args.log"
case "$url" in
  */token/*)
    n=$(cat "$dir/token_count" 2>/dev/null || echo 0)
    echo $((n + 1)) > "$dir/token_count"
    [ -f "$dir/token_fail" ] && exit 22
    printf '{"token":"stub-token-%s"}' "$((n + 1))"
    exit 0 ;;
esac
echo "$url" >> "$dir/urls.log"
case " $* " in *" -I "*) ;; *) echo "stub: manifest request without -I" >&2; exit 2 ;; esac
for media in application/vnd.oci.image.index.v1+json application/vnd.docker.distribution.manifest.list.v2+json application/vnd.oci.image.manifest.v1+json application/vnd.docker.distribution.manifest.v2+json; do
  case "$*" in *"$media"*) ;; *) printf 'HTTP/2 400 \r\n\r\n'; exit 0 ;; esac
done
case "$*" in *"Authorization: Bearer stub-token-"*) ;; *) printf 'HTTP/2 401 \r\n\r\n'; exit 0 ;; esac
rest="${url#*/library/}"
repo="${rest%%/manifests/*}"
digest="${rest##*/manifests/}"
behavior=ok
if [ -f "$dir/rules" ]; then
  line=$(grep "^$repo " "$dir/rules" | head -n 1)
  [ -n "$line" ] && behavior="${line#* }"
fi
count=$(cat "$dir/count_$repo" 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > "$dir/count_$repo"
reply() { printf 'HTTP/2 %s \r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n' "$1"; [ -n "$2" ] && printf 'Docker-Content-Digest: %s\r\n' "$2"; printf '\r\n'; }
case "$behavior" in
  ok) reply 200 "$digest" ;;
  missing) reply 404 "" ;;
  mismatch) reply 200 "sha256:0000000000000000000000000000000000000000000000000000000000000000" ;;
  nodigest) reply 200 "" ;;
  error) exit 7 ;;
  401once) if [ "$count" -eq 1 ]; then reply 401 ""; else reply 200 "$digest"; fi ;;
  429x*) n="${behavior#429x}"; if [ "$count" -le "$n" ]; then reply 429 ""; else reply 200 "$digest"; fi ;;
  *) reply 500 "" ;;
esac
`

const stubSleep = `#!/usr/bin/env bash
printf '%s\n' "$1" >> "$STUB_DIR/sleep.log"
`

type mirrorRun struct {
	dir, stub, outDir, dataset string
	exit                       int
	stdout, stderr             string
}

type mirrorResult struct {
	SchemaVersion string `json:"schema_version"`
	CheckedAt     string `json:"checked_at"`
	Mirror        string `json:"mirror"`
	DatasetSHA    string `json:"dataset_sha256"`
	Entries       []struct {
		Ref            string `json:"ref"`
		Repository     string `json:"repository"`
		Digest         string `json:"digest"`
		Status         string `json:"status"`
		HTTPStatus     int    `json:"http_status"`
		DigestMatch    bool   `json:"digest_match"`
		ReturnedDigest string `json:"returned_digest"`
	} `json:"entries"`
	Summary struct {
		Total, OK, Missing, Throttled, Error int
		InvalidRef                           int `json:"invalid_ref"`
		DigestMismatch                       int `json:"digest_mismatch"`
	} `json:"summary"`
}

func hex64(c string) string { return strings.Repeat(c, 64) }

func writeFileT(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// runMirror runs check_mirror.sh against dataset content with the stubs on
// PATH. rules is the content of the stub rules file; env adds or overrides
// variables.
func runMirror(t *testing.T, dataset, rules string, env map[string]string, extraStub func(stub string)) *mirrorRun {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	if err := os.MkdirAll(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFileT(t, filepath.Join(stub, "curl"), stubCurl, 0o755)
	writeFileT(t, filepath.Join(stub, "sleep"), stubSleep, 0o755)
	if rules != "" {
		writeFileT(t, filepath.Join(stub, "rules"), rules, 0o644)
	}
	if extraStub != nil {
		extraStub(stub)
	}
	r := &mirrorRun{dir: dir, stub: stub, outDir: filepath.Join(dir, "out"), dataset: filepath.Join(dir, "dataset.txt")}
	writeFileT(t, r.dataset, dataset, 0o644)

	cmd := exec.Command(bash, "check_mirror.sh", r.dataset)
	cmd.Env = append(os.Environ(),
		"PATH="+stub+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_DIR="+stub, "OUT_DIR="+r.outDir, "NO_COLOR=1",
		"MIRROR_BASE=http://mirror.test", "TOKEN_URL=http://mirror.test/token/",
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	r.stdout, r.stderr = out.String(), errb.String()
	if ee, ok := err.(*exec.ExitError); ok {
		r.exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run check_mirror.sh: %v", err)
	}
	return r
}

func (r *mirrorRun) result(t *testing.T) *mirrorResult {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.outDir, "mirror_check.json"))
	if err != nil {
		t.Fatalf("mirror_check.json missing: %v\nstdout:\n%s\nstderr:\n%s", err, r.stdout, r.stderr)
	}
	var res mirrorResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("mirror_check.json is not valid JSON: %v\n%s", err, data)
	}
	return &res
}

func (r *mirrorRun) log(t *testing.T, name string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.stub, name))
	if err != nil {
		return nil
	}
	return strings.Fields(strings.TrimSpace(string(data)))
}

func threeEntries() string {
	return "# pinned\n\n" +
		"index.docker.io/library/nginx@sha256:" + hex64("a") + "\n" +
		"library/redis@sha256:" + hex64("b") + "\n" +
		"alpine@sha256:" + hex64("c") + "\n"
}

func TestMirrorAllEntriesMatch(t *testing.T) {
	r := runMirror(t, threeEntries(), "", nil, nil)
	if r.exit != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.exit, r.stdout, r.stderr)
	}
	res := r.result(t)
	if res.SchemaVersion != "1" || res.CheckedAt == "" || res.Mirror != "http://mirror.test" || len(res.DatasetSHA) != 64 {
		t.Errorf("header fields wrong: %+v", res)
	}
	if res.Summary.Total != 3 || res.Summary.OK != 3 || len(res.Entries) != 3 {
		t.Fatalf("summary = %+v", res.Summary)
	}
	repos := []string{"nginx", "redis", "alpine"}
	for i, e := range res.Entries {
		if e.Status != "OK" || !e.DigestMatch || e.HTTPStatus != 200 || e.Repository != repos[i] || e.ReturnedDigest != e.Digest {
			t.Errorf("entry %d = %+v", i, e)
		}
	}
	// The request URL, token and Accept headers.
	urls := r.log(t, "urls.log")
	want := []string{
		"http://mirror.test/v2/docker/library/nginx/manifests/sha256:" + hex64("a"),
		"http://mirror.test/v2/docker/library/redis/manifests/sha256:" + hex64("b"),
		"http://mirror.test/v2/docker/library/alpine/manifests/sha256:" + hex64("c"),
	}
	if strings.Join(urls, "\n") != strings.Join(want, "\n") {
		t.Errorf("manifest URLs = %v, want %v", urls, want)
	}
	args, _ := os.ReadFile(filepath.Join(r.stub, "curl_args.log"))
	for _, must := range []string{"-I", "Authorization: Bearer stub-token-1",
		"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"} {
		if !strings.Contains(string(args), must) {
			t.Errorf("curl calls lack %q", must)
		}
	}
	// Default pacing: 1.1 s between requests, none before the first.
	if sleeps := r.log(t, "sleep.log"); strings.Join(sleeps, ",") != "1.1,1.1" {
		t.Errorf("sleeps = %v, want [1.1 1.1]", sleeps)
	}
	if !strings.Contains(r.stdout, "all 3 pinned digests resolve") {
		t.Errorf("success message missing:\n%s", r.stdout)
	}
}

func TestMirrorMissingAndMismatchFailTheRun(t *testing.T) {
	r := runMirror(t, threeEntries(), "nginx missing\nredis mismatch\n", map[string]string{"MIRROR_DELAY": "0"}, nil)
	if r.exit != 1 {
		t.Fatalf("exit = %d, want 1\n%s", r.exit, r.stderr)
	}
	res := r.result(t)
	byRepo := map[string]int{}
	for i, e := range res.Entries {
		byRepo[e.Repository] = i
	}
	nginx, redis, alpine := res.Entries[byRepo["nginx"]], res.Entries[byRepo["redis"]], res.Entries[byRepo["alpine"]]
	if nginx.Status != "MISSING" || nginx.HTTPStatus != 404 || nginx.DigestMatch {
		t.Errorf("nginx = %+v", nginx)
	}
	if redis.Status != "MISMATCH" || redis.DigestMatch || redis.ReturnedDigest != "sha256:"+hex64("0") {
		t.Errorf("redis = %+v", redis)
	}
	if alpine.Status != "OK" || !alpine.DigestMatch {
		t.Errorf("alpine = %+v", alpine)
	}
	if s := res.Summary; s.Total != 3 || s.OK != 1 || s.Missing != 1 || s.DigestMismatch != 1 {
		t.Errorf("summary = %+v", s)
	}
	for _, want := range []string{"MISSING: index.docker.io/library/nginx@", "MISMATCH: library/redis@", "2 of 3 entries failed"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
}

func TestMirrorMissingDigestHeaderIsAMismatch(t *testing.T) {
	r := runMirror(t, "nginx@sha256:"+hex64("a")+"\n", "nginx nodigest\n", map[string]string{"MIRROR_DELAY": "0"}, nil)
	if r.exit != 1 {
		t.Fatalf("exit = %d, want 1", r.exit)
	}
	if e := r.result(t).Entries[0]; e.Status != "MISMATCH" || e.DigestMatch || e.ReturnedDigest != "" {
		t.Errorf("entry = %+v", e)
	}
}

func TestMirrorRetriesHTTP429WithBackoff(t *testing.T) {
	r := runMirror(t, "nginx@sha256:"+hex64("a")+"\n", "nginx 429x2\n", map[string]string{"MIRROR_BACKOFF": "2"}, nil)
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	if e := r.result(t).Entries[0]; e.Status != "OK" {
		t.Errorf("entry after retries = %+v", e)
	}
	// Exponential backoff: 2 s, then 4 s.
	if sleeps := r.log(t, "sleep.log"); strings.Join(sleeps, ",") != "2,4" {
		t.Errorf("backoff sleeps = %v, want [2 4]", sleeps)
	}
	if got := len(r.log(t, "urls.log")); got != 3 {
		t.Errorf("requests = %d, want 3 (two 429 answers and one success)", got)
	}
	if !strings.Contains(r.stderr, "HTTP 429") {
		t.Errorf("a throttle warning is expected:\n%s", r.stderr)
	}
}

func TestMirrorGivesUpAfterTheRetryBudget(t *testing.T) {
	r := runMirror(t, "nginx@sha256:"+hex64("a")+"\n", "nginx 429x99\n",
		map[string]string{"MIRROR_BACKOFF": "2", "MIRROR_RETRIES": "2"}, nil)
	if r.exit != 1 {
		t.Fatalf("exit = %d, want 1", r.exit)
	}
	e := r.result(t).Entries[0]
	if e.Status != "THROTTLED" || e.HTTPStatus != 429 {
		t.Errorf("entry = %+v", e)
	}
	if got := len(r.log(t, "urls.log")); got != 3 {
		t.Errorf("requests = %d, want 3 (initial plus two retries)", got)
	}
	if r.result(t).Summary.Throttled != 1 {
		t.Errorf("summary = %+v", r.result(t).Summary)
	}
}

func TestMirrorRefreshesTheTokenOnceOn401(t *testing.T) {
	r := runMirror(t, "nginx@sha256:"+hex64("a")+"\n", "nginx 401once\n", nil, nil)
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	if e := r.result(t).Entries[0]; e.Status != "OK" {
		t.Errorf("entry = %+v", e)
	}
	if n := r.log(t, "token_count"); len(n) != 1 || n[0] != "2" {
		t.Errorf("token requests = %v, want 2 (initial and refresh)", n)
	}
	args, _ := os.ReadFile(filepath.Join(r.stub, "curl_args.log"))
	if !strings.Contains(string(args), "Bearer stub-token-2") {
		t.Error("the refreshed token must be used for the retry")
	}
}

func TestMirrorNetworkErrorIsAnError(t *testing.T) {
	r := runMirror(t, threeEntries(), "redis error\n", map[string]string{"MIRROR_DELAY": "0"}, nil)
	if r.exit != 1 {
		t.Fatalf("exit = %d, want 1", r.exit)
	}
	res := r.result(t)
	if e := res.Entries[1]; e.Status != "ERROR" || e.HTTPStatus != 0 || e.DigestMatch {
		t.Errorf("redis entry = %+v", e)
	}
	if res.Summary.Error != 1 || res.Summary.OK != 2 {
		t.Errorf("summary = %+v", res.Summary)
	}
}

func TestMirrorTokenFailureExitsWithUsageStatus(t *testing.T) {
	r := runMirror(t, threeEntries(), "", map[string]string{"MIRROR_RETRIES": "1"}, func(stub string) {
		writeFileT(t, filepath.Join(stub, "token_fail"), "x", 0o644)
	})
	if r.exit != 2 {
		t.Fatalf("exit = %d, want 2", r.exit)
	}
	if !strings.Contains(r.stderr, "could not obtain an anonymous token") {
		t.Errorf("stderr = %s", r.stderr)
	}
	if _, err := os.Stat(filepath.Join(r.outDir, "mirror_check.json")); err == nil {
		t.Error("no result file may be written when no token was obtained")
	}
	if len(r.log(t, "urls.log")) != 0 {
		t.Error("no manifest request may be sent without a token")
	}
}

func TestMirrorInvalidEntriesAreReportedNotSkipped(t *testing.T) {
	dataset := "nginx:latest\n" +
		"bitnami/redis@sha256:" + hex64("d") + "\n" +
		"nginx@sha256:" + hex64("a") + "\n"
	r := runMirror(t, dataset, "", map[string]string{"MIRROR_DELAY": "0"}, nil)
	if r.exit != 1 {
		t.Fatalf("exit = %d, want 1", r.exit)
	}
	res := r.result(t)
	if res.Summary.Total != 3 || res.Summary.InvalidRef != 2 || res.Summary.OK != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
	if res.Entries[0].Status != "INVALID_REF" || res.Entries[1].Status != "INVALID_REF" {
		t.Errorf("entries = %+v", res.Entries)
	}
	if got := len(r.log(t, "urls.log")); got != 1 {
		t.Errorf("only the valid entry may be requested, got %d requests", got)
	}
}

func TestMirrorUsageErrors(t *testing.T) {
	r := runMirror(t, "# nothing\n", "", nil, nil)
	if r.exit != 2 || !strings.Contains(r.stderr, "no entries") {
		t.Errorf("empty dataset: exit %d, stderr %s", r.exit, r.stderr)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	for name, args := range map[string][]string{
		"no argument":   {"check_mirror.sh"},
		"two arguments": {"check_mirror.sh", "a", "b"},
		"missing file":  {"check_mirror.sh", filepath.Join(t.TempDir(), "absent.txt")},
	} {
		cmd := exec.Command(bash, args...)
		cmd.Env = append(os.Environ(), "NO_COLOR=1")
		out, err := cmd.CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 2 {
			t.Errorf("%s: want exit 2, got %v\n%s", name, err, out)
		}
	}
	cmd := exec.Command(bash, "check_mirror.sh", "--help")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "Usage:") {
		t.Errorf("--help: %v\n%s", err, out)
	}
}

// TestMirrorRealPinnedList runs the script over the repository's pinned list
// against the stub: every entry must parse into one distinct request.
func TestMirrorRealPinnedList(t *testing.T) {
	pinned, err := os.ReadFile(filepath.Join("..", "fixtures", "evaluation_dataset_pinned.txt"))
	if err != nil {
		t.Skipf("pinned list not available: %v", err)
	}
	r := runMirror(t, string(pinned), "", map[string]string{"MIRROR_DELAY": "0"}, nil)
	if r.exit != 0 {
		t.Fatalf("exit %d\n%s", r.exit, r.stderr)
	}
	res := r.result(t)
	if res.Summary.Total != res.Summary.OK || res.Summary.Total < 100 {
		t.Errorf("summary = %+v", res.Summary)
	}
	urls := r.log(t, "urls.log")
	seen := map[string]bool{}
	for _, u := range urls {
		if seen[u] {
			t.Errorf("duplicate request %s", u)
		}
		seen[u] = true
		if !strings.HasPrefix(u, "http://mirror.test/v2/docker/library/") || !strings.Contains(u, "/manifests/sha256:") {
			t.Errorf("unexpected request URL %s", u)
		}
	}
	if len(urls) != res.Summary.Total {
		t.Errorf("%d requests for %d entries", len(urls), res.Summary.Total)
	}
	if sleeps := r.log(t, "sleep.log"); len(sleeps) != res.Summary.Total-1 {
		t.Errorf("%d pauses for %d entries, want one between each pair", len(sleeps), res.Summary.Total)
	}
}
