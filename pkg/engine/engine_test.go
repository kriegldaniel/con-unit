package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
)

func TestEngineCommandConstruction(t *testing.T) {
	eng := &engine.Engine{
		BinaryPath: "podman",
		ExtraArgs:  []string{"--root", "/tmp/custom-root"},
	}

	ctx := context.Background()
	cmd := eng.Command(ctx, "run", "--rm", "alpine:latest")

	args := cmd.Args
	fullCmd := strings.Join(args, " ")

	expectedPrefix := "podman --root /tmp/custom-root run --rm alpine:latest"
	if fullCmd != expectedPrefix {
		t.Errorf("Expected command '%s', got '%s'", expectedPrefix, fullCmd)
	}
}

func TestCheckPathExistsDistinguishesPathAndProbeErrors(t *testing.T) {
	const probePath = `/tmp/path with spaces;$(touch /tmp/con-unit-path-injection)'`
	const script = `
if [ "$1" = "run" ]; then
	printf '%s\n' "$@" > "$FAKE_ARGS_LOG"
	if [ -n "$FAKE_PATH_STDERR" ]; then
		printf '%s\n' "$FAKE_PATH_STDERR" >&2
	fi
	exit "$FAKE_PATH_EXIT"
fi
exit 99
`
	tests := []struct {
		name       string
		exitCode   string
		stderr     string
		wantExists bool
		wantError  bool
	}{
		{name: "path exists", exitCode: "0", wantExists: true},
		{name: "path absent", exitCode: "1", wantExists: false},
		{name: "engine error with exit one diagnostics", exitCode: "1", stderr: "engine unavailable", wantError: true},
		{name: "probe failure", exitCode: "2", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			argsLog := filepath.Join(t.TempDir(), "args")
			t.Setenv("FAKE_ARGS_LOG", argsLog)
			t.Setenv("FAKE_PATH_EXIT", test.exitCode)
			t.Setenv("FAKE_PATH_STDERR", test.stderr)
			eng := writeFakeEngine(t, script)

			exists, err := eng.CheckPathExists(context.Background(), "fixture:latest", probePath)
			if (err != nil) != test.wantError {
				t.Fatalf("CheckPathExists error = %v, wantError %t", err, test.wantError)
			}
			if exists != test.wantExists {
				t.Errorf("CheckPathExists = %t, want %t", exists, test.wantExists)
			}

			args, readErr := os.ReadFile(argsLog)
			if readErr != nil {
				t.Fatalf("read fake engine arguments: %v", readErr)
			}
			if !strings.Contains(string(args), probePath+"\n") {
				t.Errorf("path was not passed as one literal argument: %q", args)
			}
			if strings.Contains(string(args), "/bin/sh") || strings.Contains(string(args), "\n-c\n") {
				t.Errorf("path probe unexpectedly invoked a shell: %q", args)
			}
		})
	}
}

func TestCheckPathExistsPropagatesEngineErrors(t *testing.T) {
	eng := &engine.Engine{BinaryPath: filepath.Join(t.TempDir(), "missing-engine")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	exists, err := eng.CheckPathExists(ctx, "fixture:latest", "/tmp/missing'; touch /tmp/unwanted; '")
	if err == nil {
		t.Fatal("expected the engine execution error to be returned")
	}
	if exists {
		t.Fatal("an engine execution error must not report that the path exists")
	}
}

func TestFindSuidBinariesReturnsFindingsAndScanErrors(t *testing.T) {
	tests := []struct {
		name         string
		output       string
		exitCode     string
		wantFindings int
		wantError    bool
	}{
		{name: "no findings", output: "", exitCode: "0", wantFindings: 0},
		{name: "findings", output: "/usr/bin/suid-fixture\n/opt/sgid-fixture\n", exitCode: "0", wantFindings: 2},
		{name: "find failure", output: "permission denied", exitCode: "1", wantError: true},
	}
	const script = `
if [ "$1" = "run" ]; then
	printf '%s' "$FAKE_SCAN_OUTPUT"
	exit "$FAKE_SCAN_EXIT"
fi
exit 99
`

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("FAKE_SCAN_OUTPUT", test.output)
			t.Setenv("FAKE_SCAN_EXIT", test.exitCode)
			suids, err := writeFakeEngine(t, script).FindSuidBinaries(context.Background(), "fixture:latest")
			if (err != nil) != test.wantError {
				t.Fatalf("FindSuidBinaries error = %v, wantError %t", err, test.wantError)
			}
			if test.wantError {
				if suids != nil {
					t.Errorf("failed scan returned findings: %v", suids)
				}
				return
			}
			if len(suids) != test.wantFindings {
				t.Errorf("FindSuidBinaries returned %v, want %d findings", suids, test.wantFindings)
			}
		})
	}
}

func TestFindSuidBinariesPropagatesEngineErrors(t *testing.T) {
	eng := &engine.Engine{BinaryPath: filepath.Join(t.TempDir(), "missing-engine")}
	suids, err := eng.FindSuidBinaries(context.Background(), "fixture:latest")
	if err == nil {
		t.Fatal("expected the engine execution error to be returned")
	}
	if suids != nil {
		t.Errorf("engine execution error returned findings: %v", suids)
	}
}

func TestDetectEngine(t *testing.T) {
	dir := t.TempDir()
	podmanPath := filepath.Join(dir, "podman")
	if err := os.WriteFile(podmanPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write fake podman executable: %v", err)
	}
	t.Setenv("PATH", dir)
	eng, err := engine.DetectEngine("auto")
	if err != nil {
		t.Fatalf("DetectEngine failed: %v", err)
	}
	if eng.BinaryPath != podmanPath {
		t.Fatalf("DetectEngine path = %q, want %q", eng.BinaryPath, podmanPath)
	}
}

func TestValidateImageRefSecurity(t *testing.T) {
	// Rejects flag injection attempts
	injections := []string{
		"--privileged",
		"-v /etc:/etc",
		"--volume=/etc:/etc",
		"-it",
		"   -dangerous",
	}

	for _, inj := range injections {
		err := engine.ValidateImageRef(inj)
		if err == nil {
			t.Errorf("Expected security error for malicious image reference '%s', got nil", inj)
		}
	}

	// Allows valid OCI references
	validRefs := []string{
		"alpine:latest",
		"docker.io/library/ubuntu:24.04",
		"python:3.11-slim@sha256:abcdef1234567890",
		"localhost:5000/my-app:v1.0",
	}

	for _, ref := range validRefs {
		err := engine.ValidateImageRef(ref)
		if err != nil {
			t.Errorf("Expected valid reference '%s' to pass, got error: %v", ref, err)
		}
	}
}

func writeFakeEngine(t *testing.T, script string) *engine.Engine {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "fake-engine")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
		t.Fatalf("write fake engine command: %v", err)
	}
	return &engine.Engine{BinaryPath: binaryPath}
}

func TestEnsureImageWithOwnership(t *testing.T) {
	const script = `
case "$1" in
	image)
		if [ "$2" = "exists" ]; then
			printf '%s\n' "exists" >> "$FAKE_CALL_LOG"
			exit "$FAKE_EXISTS_EXIT"
		fi
		;;
	pull)
		printf '%s\n' "pull" >> "$FAKE_CALL_LOG"
		if [ "$FAKE_PULL_EXIT" != "0" ]; then
			printf '%s\n' "pull failed" >&2
		fi
		exit "$FAKE_PULL_EXIT"
		;;
esac
exit 99
`
	tests := []struct {
		name           string
		existsExit     string
		pullExit       string
		wantPulled     bool
		wantError      bool
		wantPullCalled bool
	}{
		{name: "image already present", existsExit: "0", pullExit: "0"},
		{name: "absent image pulled", existsExit: "1", pullExit: "0", wantPulled: true, wantPullCalled: true},
		{name: "pull failure", existsExit: "1", pullExit: "8", wantError: true, wantPullCalled: true},
		{name: "image check engine failure", existsExit: "125", pullExit: "0", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			callLog := filepath.Join(t.TempDir(), "calls")
			t.Setenv("FAKE_CALL_LOG", callLog)
			t.Setenv("FAKE_EXISTS_EXIT", test.existsExit)
			t.Setenv("FAKE_PULL_EXIT", test.pullExit)
			eng := writeFakeEngine(t, script)

			pulled, err := eng.EnsureImageWithOwnership(context.Background(), "fixture:latest")
			if (err != nil) != test.wantError {
				t.Fatalf("EnsureImageWithOwnership error = %v, wantError %t", err, test.wantError)
			}
			if pulled != test.wantPulled {
				t.Errorf("EnsureImageWithOwnership pulled = %t, want %t", pulled, test.wantPulled)
			}

			calls, readErr := os.ReadFile(callLog)
			if readErr != nil {
				t.Fatalf("read fake engine call log: %v", readErr)
			}
			pullCalled := strings.Contains(string(calls), "pull\n")
			if pullCalled != test.wantPullCalled {
				t.Errorf("pull called = %t, want %t; calls: %q", pullCalled, test.wantPullCalled, calls)
			}
		})
	}
}

func TestEnsureImageCompatibilityWrapper(t *testing.T) {
	t.Setenv("FAKE_EXISTS_EXIT", "0")
	t.Setenv("FAKE_PULL_EXIT", "0")
	t.Setenv("FAKE_CALL_LOG", filepath.Join(t.TempDir(), "calls"))
	eng := writeFakeEngine(t, `
if [ "$1" = "image" ] && [ "$2" = "exists" ]; then
	exit "$FAKE_EXISTS_EXIT"
fi
exit 99
`)

	if err := eng.EnsureImage(context.Background(), "fixture:latest"); err != nil {
		t.Fatalf("EnsureImage returned error: %v", err)
	}
}

// inspectHealthcheck runs InspectImage against a fake engine that prints the
// given inspect document.
func inspectHealthcheck(t *testing.T, document string) *engine.HealthConfig {
	t.Helper()
	t.Setenv("FAKE_INSPECT_JSON", document)
	eng := writeFakeEngine(t, `
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
	printf '%s\n' "$FAKE_INSPECT_JSON"
	exit 0
fi
exit 99
`)
	inspect, err := eng.InspectImage(context.Background(), "fixture:latest")
	if err != nil {
		t.Fatalf("InspectImage returned error: %v", err)
	}
	return inspect.Config.Healthcheck
}

func TestInspectImageReadsThePodmanHealthcheckFromTheTopLevel(t *testing.T) {
	// Shape of `podman image inspect` 5.8: the OCI config has no Healthcheck key
	// and the engine reports the image HEALTHCHECK at the top level.
	const podmanDocument = `[{"Id":"fixture","Architecture":"arm64","Os":"linux",
		"Config":{"Entrypoint":["/bin/true"],"Env":["PATH=/usr/bin"],"WorkingDir":"/"},
		"Healthcheck":{"Test":["CMD","true"],"Interval":30000000000,"Timeout":3000000000}}]`

	got := inspectHealthcheck(t, podmanDocument)
	if got == nil {
		t.Fatal("the healthcheck at the top level of the Podman document was not read")
	}
	if len(got.Test) != 2 || got.Test[0] != "CMD" || got.Test[1] != "true" {
		t.Errorf("unexpected healthcheck test: %v", got.Test)
	}
	if got.Interval != 30*time.Second || got.Timeout != 3*time.Second {
		t.Errorf("unexpected healthcheck timing: %+v", got)
	}
}

func TestInspectImageHealthcheckPrecedenceAndAbsence(t *testing.T) {
	t.Run("the config healthcheck wins over the top level key", func(t *testing.T) {
		got := inspectHealthcheck(t, `[{"Id":"fixture","Config":{"Healthcheck":{"Test":["CMD","config"]}},"Healthcheck":{"Test":["CMD","top"]}}]`)
		if got == nil || len(got.Test) != 2 || got.Test[1] != "config" {
			t.Errorf("healthcheck = %+v, want the one of the config", got)
		}
	})
	t.Run("no healthcheck anywhere stays absent", func(t *testing.T) {
		if got := inspectHealthcheck(t, `[{"Id":"fixture","Config":{"Cmd":["/bin/sh"]}}]`); got != nil {
			t.Errorf("healthcheck = %+v, want none", got)
		}
	})
	t.Run("a null top level key stays absent", func(t *testing.T) {
		if got := inspectHealthcheck(t, `[{"Id":"fixture","Config":{},"Healthcheck":null}]`); got != nil {
			t.Errorf("healthcheck = %+v, want none", got)
		}
	})
	t.Run("a disabled healthcheck is kept so that the check can judge it", func(t *testing.T) {
		got := inspectHealthcheck(t, `[{"Id":"fixture","Config":{},"Healthcheck":{"Test":["NONE"]}}]`)
		if got == nil || len(got.Test) != 1 || got.Test[0] != "NONE" {
			t.Errorf("healthcheck = %+v, want the NONE test", got)
		}
	})
}

func TestInspectImageParsesHealthcheck(t *testing.T) {
	eng := writeFakeEngine(t, `
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
	printf '%s\n' '[{"Id":"sha256:fixture","Config":{"Healthcheck":{"Test":["CMD-SHELL","curl -fsS http://localhost/health || exit 1"],"Interval":30000000000,"Timeout":3000000000,"StartPeriod":5000000000,"StartInterval":1000000000,"Retries":3}}}]'
	exit 0
fi
exit 99
`)

	inspect, err := eng.InspectImage(context.Background(), "fixture:latest")
	if err != nil {
		t.Fatalf("InspectImage returned error: %v", err)
	}
	if inspect.Config.Healthcheck == nil {
		t.Fatal("expected Config.Healthcheck to be parsed")
	}
	got := inspect.Config.Healthcheck
	if len(got.Test) != 2 || got.Test[0] != "CMD-SHELL" || got.Test[1] != "curl -fsS http://localhost/health || exit 1" {
		t.Errorf("unexpected healthcheck test: %v", got.Test)
	}
	if got.Interval != 30*time.Second || got.Timeout != 3*time.Second || got.StartPeriod != 5*time.Second || got.StartInterval != time.Second || got.Retries != 3 {
		t.Errorf("unexpected healthcheck timing/retries: %+v", got)
	}
}
