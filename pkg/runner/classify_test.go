package runner_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/retry"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

func TestClassifyErrorUsesTypedErrorsOnly(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status string
		reason spec.Reason
	}{
		{"nil", nil, spec.StatusCompleted, spec.ReasonNone},
		{"deadline", fmt.Errorf("stage: %w", context.DeadlineExceeded), spec.StatusTimeout, spec.ReasonDeadlineExceeded},
		{"engine 429", &engine.RateLimitError{Op: "pull"}, spec.StatusRateLimited, spec.ReasonRegistryThrottled},
		{"registry 429", fmt.Errorf("resolve: %w", &oci.RateLimitError{Err: errors.New("x")}), spec.StatusRateLimited, spec.ReasonRegistryThrottled},
		{"engine not found", &engine.NotFoundError{}, spec.StatusUnavailable, spec.ReasonManifestNotFound},
		{"registry not found", &oci.NotFoundError{Err: errors.New("x")}, spec.StatusUnavailable, spec.ReasonManifestNotFound},
		{"not in local store", &engine.ImageNotInStoreError{Image: "x"}, spec.StatusUnavailable, spec.ReasonManifestNotFound},
		{"index too large", &oci.IndexTooLargeError{Limit: 1}, spec.StatusIndexLimit, spec.ReasonIndexTooLarge},
		{"identity", &oci.IdentityMismatchError{}, spec.StatusExecutionError, spec.ReasonIdentityMismatch},
		{"platform", &oci.PlatformMismatchError{}, spec.StatusExecutionError, spec.ReasonPlatformMismatch},
		{"text that only looks typed", errors.New("429 toomanyrequests manifest unknown deadline exceeded"), spec.StatusExecutionError, spec.ReasonNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := runner.ClassifyError(tc.err)
			if status != tc.status || reason != tc.reason {
				t.Fatalf("ClassifyError = %s/%s, want %s/%s", status, reason, tc.status, tc.reason)
			}
		})
	}
}

// pullingEngine returns a fake engine whose image is absent from the store and
// whose pull fails with the given output for the first failures attempts.
func pullingEngine(t *testing.T, failures int, output string) (*engine.Engine, string) {
	t.Helper()
	dir := t.TempDir()
	counter := filepath.Join(dir, "pull-count")
	script := `#!/bin/sh
case "$1:$2" in
  image:exists) exit 1 ;;
  image:inspect)
    printf '[{"Id":"%s","Os":"linux","Architecture":"amd64","RepoTags":[],"Size":0,"Config":{"User":"1000","Entrypoint":["/app"],"Env":[],"ExposedPorts":{}}}]\n' "$FAKE_CONFIG_DIGEST"
    exit 0 ;;
esac
if [ "$1" = "pull" ]; then
  n=$(cat ` + strconv.Quote(counter) + ` 2>/dev/null || echo 0)
  n=$((n+1))
  echo $n > ` + strconv.Quote(counter) + `
  if [ "$n" -le ` + strconv.Itoa(failures) + ` ]; then
    printf '%s\n' ` + strconv.Quote(output) + ` >&2
    exit 125
  fi
  exit 0
fi
exit 97
`
	path := filepath.Join(dir, "fake-engine")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &engine.Engine{BinaryPath: path}, counter
}

func pullCount(t *testing.T, counter string) int {
	t.Helper()
	data, err := os.ReadFile(counter)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return n
}

func instantRetry(attempts int, waits *[]time.Duration) retry.Policy {
	return retry.Policy{
		MaxAttempts: attempts, BaseDelay: time.Second, MaxDelay: time.Minute, MaxRetryAfter: time.Minute,
		Sleep: func(_ context.Context, d time.Duration) error { *waits = append(*waits, d); return nil },
	}
}

func TestRunPackRetriesRateLimitedPullThenSucceeds(t *testing.T) {
	eng, counter := pullingEngine(t, 2, "Error: reading manifest latest: toomanyrequests: You have reached your pull rate limit.")
	imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
	t.Setenv("FAKE_CONFIG_DIGEST", writeRunnerImageTarball(t, imagePath, nil))
	pack, _ := runner.ResolvePack("hygiene")
	pack = pack.Except("EXEC-01", "EXEC-02", "EXEC-03")

	var waits []time.Duration
	res, err := runner.NewRunnerWithOptions(eng, runner.Options{Retry: instantRetry(5, &waits)}).RunPack(context.Background(), pack, imagePath)
	if err != nil || res == nil {
		t.Fatalf("RunPack = %v, %v; want success after two throttled pulls", res, err)
	}
	if got := pullCount(t, counter); got != 3 {
		t.Errorf("pull attempts = %d, want 3", got)
	}
	if len(waits) != 2 {
		t.Errorf("backoff waits = %v, want 2", waits)
	}
}

func TestRunPackStopsAfterBoundedRateLimitRetries(t *testing.T) {
	eng, counter := pullingEngine(t, 99, "toomanyrequests")
	imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
	t.Setenv("FAKE_CONFIG_DIGEST", writeRunnerImageTarball(t, imagePath, nil))
	pack, _ := runner.ResolvePack("hygiene")

	var waits []time.Duration
	_, err := runner.NewRunnerWithOptions(eng, runner.Options{Retry: instantRetry(3, &waits)}).RunPack(context.Background(), pack, imagePath)
	if err == nil {
		t.Fatal("expected the throttle error once retries are exhausted")
	}
	status, reason := runner.ClassifyError(err)
	if status != spec.StatusRateLimited || reason != spec.ReasonRegistryThrottled {
		t.Errorf("classified as %s/%s, want RATE_LIMITED/REGISTRY_THROTTLED (err: %v)", status, reason, err)
	}
	if got := pullCount(t, counter); got != 3 {
		t.Errorf("pull attempts = %d, want exactly the 3 allowed", got)
	}
}

func TestRunPackDoesNotRetryMissingImage(t *testing.T) {
	eng, counter := pullingEngine(t, 99, "Error: initializing source docker://x:1: reading manifest 1 in docker.io/library/x: manifest unknown")
	imagePath := filepath.Join(t.TempDir(), "synthetic.tar")
	t.Setenv("FAKE_CONFIG_DIGEST", writeRunnerImageTarball(t, imagePath, nil))
	pack, _ := runner.ResolvePack("hygiene")

	var waits []time.Duration
	_, err := runner.NewRunnerWithOptions(eng, runner.Options{Retry: instantRetry(5, &waits)}).RunPack(context.Background(), pack, imagePath)
	status, reason := runner.ClassifyError(err)
	if status != spec.StatusUnavailable || reason != spec.ReasonManifestNotFound {
		t.Fatalf("classified as %s/%s, want UNAVAILABLE/MANIFEST_NOT_FOUND (err: %v)", status, reason, err)
	}
	if got := pullCount(t, counter); got != 1 || len(waits) != 0 {
		t.Errorf("pull attempts = %d waits = %v, want a single attempt without backoff", got, waits)
	}
	var imageErr *runner.ImageError
	if !errors.As(err, &imageErr) || imageErr.Stage != "pull" {
		t.Errorf("failure must carry the failing stage, got %+v", imageErr)
	}
}

func TestRunPackReportsDeadlineForKilledEngineCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slow-engine")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	pack, _ := runner.ResolvePack("hygiene")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := runner.NewRunner(&engine.Engine{BinaryPath: path}).RunPack(ctx, pack, "example:latest")
	status, reason := runner.ClassifyError(err)
	if status != spec.StatusTimeout || reason != spec.ReasonDeadlineExceeded {
		t.Fatalf("classified as %s/%s, want TIMEOUT/DEADLINE_EXCEEDED (err: %v)", status, reason, err)
	}
}
