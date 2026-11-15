package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/runenv"
	"github.com/con-unit/con-unit/pkg/spec"
)

func TestEvalAndTestLogHostOnceAndWarnWhenEngineFactsAreMissing(t *testing.T) {
	withEngineFacts := func(name, version string) commandDeps {
		deps := offlineCommandDeps(&fakePackRunner{})
		deps.detectRun = func(_ context.Context, options runenv.Options) spec.RunMetadata {
			if options.EngineBinary != "offline-fake" {
				t.Errorf("Detect must receive the resolved engine binary, got %q", options.EngineBinary)
			}
			return spec.RunMetadata{EngineName: name, EngineVersion: version, HostOS: "linux", HostArch: "amd64", StartedAt: fixedClock}
		}
		return deps
	}

	for _, command := range []string{"eval", "test"} {
		run := func(deps commandDeps) (int, string) {
			var code int
			_, _, stderr := captureCLIStreams(t, func() int {
				if command == "eval" {
					code = runEvalCommandWithDeps([]string{"--images", writeImageListFile(t, "x:1\n"), "--out-dir", t.TempDir()}, deps)
				} else {
					code = runTestCommandWithDeps([]string{"x:1", "--format", "json", "--output", filepath.Join(t.TempDir(), "r.json")}, deps)
				}
				return code
			})
			return code, stderr
		}

		t.Run(command+" complete facts", func(t *testing.T) {
			code, stderr := run(withEngineFacts("podman", "5.2.0"))
			if code != spec.ExitOK {
				t.Fatalf("exit code = %d", code)
			}
			if strings.Count(stderr, "Environment: ") != 1 || !strings.Contains(stderr, "engine: podman 5.2.0") {
				t.Errorf("the run environment must be logged exactly once:\n%s", stderr)
			}
			if strings.Contains(stderr, "WARNING") {
				t.Errorf("no warning is due when the engine facts are known:\n%s", stderr)
			}
		})

		t.Run(command+" missing facts", func(t *testing.T) {
			code, stderr := run(withEngineFacts("", ""))
			if code != spec.ExitOK {
				t.Fatalf("a missing engine fact must not fail the run, exit code = %d", code)
			}
			if !strings.Contains(stderr, "WARNING: the run metadata is missing: engine name, engine version") {
				t.Errorf("missing engine facts must produce a loud warning:\n%s", stderr)
			}
		})

		t.Run(command+" missing version only", func(t *testing.T) {
			_, stderr := run(withEngineFacts("podman", ""))
			if !strings.Contains(stderr, "missing: engine version") || strings.Contains(stderr, "engine name") {
				t.Errorf("the warning must name exactly the missing facts:\n%s", stderr)
			}
		})
	}
}
