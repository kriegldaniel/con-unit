package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

func TestParseSelection(t *testing.T) {
	cases := []struct {
		name    string
		list    string
		want    []string
		wantErr string
	}{
		{name: "empty list selects every tool", list: "", want: []string{"conunit", "cst", "dockle", "hadolint", "trivy"}},
		{name: "blank list selects every tool", list: "  ", want: []string{"conunit", "cst", "dockle", "hadolint", "trivy"}},
		{name: "dockle alone", list: "dockle", want: []string{"dockle"}},
		{name: "dockle with another tool", list: "conunit,dockle", want: []string{"conunit", "dockle"}},
		{name: "spaces around names", list: " dockle , trivy ", want: []string{"dockle", "trivy"}},
		{name: "empty items are skipped", list: "dockle,,trivy,", want: []string{"dockle", "trivy"}},
		{name: "a name twice", list: "dockle,dockle", want: []string{"dockle"}},
		{name: "docker is not dockle", list: "docker", wantErr: `unknown tool "docker"`},
		{name: "names are case sensitive", list: "Dockle", wantErr: `unknown tool "Dockle"`},
		{name: "one unknown name rejects the list", list: "dockle,grype", wantErr: `unknown tool "grype"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSelection(tc.list, allTools, "tool")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for name := range got {
				names = append(names, name)
			}
			sort.Strings(names)
			if !reflect.DeepEqual(names, tc.want) {
				t.Errorf("selected = %v, want %v", names, tc.want)
			}
		})
	}
}

func TestEveryToolHasABinaryAndAVersionProbe(t *testing.T) {
	if !reflect.DeepEqual(allTools, []string{ToolConUnit, ToolHadolint, ToolTrivy, ToolCST, ToolDockle}) {
		t.Fatalf("allTools = %v: the order is the column order of the table and Dockle is the fifth tool", allTools)
	}
	for _, tool := range allTools {
		if defaultBinaries[tool] == "" || len(versionArgs[tool]) == 0 {
			t.Errorf("%s: binary %q version arguments %v", tool, defaultBinaries[tool], versionArgs[tool])
		}
		// displayTool returns its argument for a tool it does not know.
		if displayTool(tool) == tool {
			t.Errorf("%s has no display name for the table header", tool)
		}
	}
	if defaultBinaries[ToolDockle] != "dockle" || !reflect.DeepEqual(versionArgs[ToolDockle], []string{"--version"}) {
		t.Errorf("dockle probe: binary %q args %v, want dockle --version", defaultBinaries[ToolDockle], versionArgs[ToolDockle])
	}
	if displayTool(ToolDockle) != "Dockle" {
		t.Errorf("display name = %q", displayTool(ToolDockle))
	}
}

// runRQ1 calls the command with the given arguments and returns its exit code
// and what it wrote to stderr.
func runRQ1(t *testing.T, args ...string) (int, string) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	code := run(args, f)
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(data)
}

func TestCommandLineAcceptsDockle(t *testing.T) {
	t.Run("the flag -dockle exists", func(t *testing.T) {
		// The oracle path is wrong on purpose. The run must get as far as
		// reading it, so the flag was parsed.
		code, stderr := runRQ1(t, "-dockle", "/opt/dockle", "-oracle", filepath.Join(t.TempDir(), "absent.json"))
		if code != spec.ExitUsage || !strings.Contains(stderr, "reading oracle") || strings.Contains(stderr, "not defined") {
			t.Errorf("code %d, stderr %q: -dockle must be a known flag", code, stderr)
		}
	})
	t.Run("an unknown flag is a usage error", func(t *testing.T) {
		code, stderr := runRQ1(t, "-grype", "/opt/grype")
		if code != spec.ExitUsage || !strings.Contains(stderr, "not defined") {
			t.Errorf("code %d, stderr %q", code, stderr)
		}
	})
	t.Run("-tools names dockle", func(t *testing.T) {
		code, stderr := runRQ1(t, "-oracle", realOraclePath, "-tools", "docker")
		if code != spec.ExitUsage || !strings.Contains(stderr, `unknown tool "docker"`) {
			t.Errorf("code %d, stderr %q: docker is not dockle", code, stderr)
		}
	})
	t.Run("-tools dockle is not rejected", func(t *testing.T) {
		code, stderr := runRQ1(t, "-oracle", realOraclePath, "-tools", "dockle", "-cases", "no-such-case")
		if code != spec.ExitUsage || strings.Contains(stderr, "unknown tool") || !strings.Contains(stderr, `unknown case "no-such-case"`) {
			t.Errorf("code %d, stderr %q: the tool list was valid, the case list was not", code, stderr)
		}
	})
	t.Run("the usage text names dockle", func(t *testing.T) {
		_, stderr := runRQ1(t, "-help")
		if !strings.Contains(stderr, "-dockle") || !strings.Contains(stderr, "conunit,hadolint,trivy,cst,dockle") {
			t.Errorf("usage text lacks dockle: %q", stderr)
		}
	})
}
