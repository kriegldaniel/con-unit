package runenv

import (
	"context"
	"strings"
	"sync"
)

// Values written to the Tools map when no version could be determined.
const (
	ToolAbsent         = "absent"                    // the binary is not on PATH
	ToolVersionUnknown = "present (version unknown)" // the binary exists but printed no usable version
)

// toolProbe lists, in order, the argument sets that make a tool print its
// version. The first one that yields a version wins.
type toolProbe struct {
	name string
	args [][]string
}

// toolProbes lists the external tools recorded in spec.RunMetadata.Tools.
var toolProbes = []toolProbe{
	{"syft", [][]string{{"--version"}, {"version"}}},
	{"cosign", [][]string{{"version"}, {"--version"}}},
	{"grype", [][]string{{"--version"}, {"version"}}},
	{"hadolint", [][]string{{"--version"}}},
	{"trivy", [][]string{{"--version"}, {"version"}}},
	{"container-structure-test", [][]string{{"version"}, {"--version"}}},
	// Dockle prints "dockle version <semver>" for --version. It is the image
	// linter the cross-check compares ConUnit against, so its version is part of
	// the run record. There is no second flag set on purpose: Dockle has no
	// version subcommand, so `dockle version` would be read as an image name
	// and start a scan.
	{"dockle", [][]string{{"--version"}}},
}

// probeTools returns the version of each external tool, or ToolAbsent. All
// tools are probed concurrently, each bounded by the command timeout.
func probeTools(ctx context.Context, env Env) map[string]string {
	out := make(map[string]string, len(toolProbes))
	var mu sync.Mutex
	fns := make([]func(), 0, len(toolProbes))
	for _, p := range toolProbes {
		fns = append(fns, func() {
			v := probeTool(ctx, env, p)
			mu.Lock()
			out[p.name] = v
			mu.Unlock()
		})
	}
	parallel(fns...)
	for _, p := range toolProbes {
		if _, ok := out[p.name]; !ok {
			out[p.name] = ToolVersionUnknown // the probe itself failed
		}
	}
	return out
}

func probeTool(ctx context.Context, env Env, p toolProbe) string {
	if _, err := env.LookPath(p.name); err != nil {
		return ToolAbsent
	}
	for _, args := range p.args {
		// Some tools print the version to stderr, so both streams are read.
		// Output of a failed invocation is usage text, never a version.
		res, err := env.run(ctx, p.name, args...)
		if err != nil {
			continue
		}
		if v := extractVersion(string(res.Stdout) + "\n" + string(res.Stderr)); v != "" {
			return v
		}
	}
	return ToolVersionUnknown
}

// extractVersion returns the first version-like token of a tool's output,
// verbatim (for example "1.55.0" or "v1.19.3"). Multi-line outputs such as
// `cosign version` and `trivy --version` carry the version near the top.
func extractVersion(output string) string {
	return firstVersion(strings.TrimSpace(output))
}
