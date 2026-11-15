package runenv

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"syft (captured)", "syft 1.55.0\n", "1.55.0"},
		{"grype (captured)", "grype 0.120.0\n", "0.120.0"},
		{"hadolint (captured)", "Haskell Dockerfile Linter 2.14.0\n", "2.14.0"},
		{"podman client", "podman version 5.8.1\n", "5.8.1"},
		{"trivy", trivyVersionOut, "0.57.0"},
		{"dockle (urfave/cli printer, version without v)", dockleVersionOut, "0.4.15"},
		{"cosign skips ascii art and go version", cosignVersionOut, "v2.4.1"},
		{"container-structure-test", "v1.19.3\n", "v1.19.3"},
		{"pre-release suffix is kept", "tool 2.0.0-rc.1\n", "2.0.0-rc.1"},
		{"two components", "tool 3.2\n", "3.2"},
		{"go toolchain string is not a tool version", "go1.22.5\n", ""},
		{"no version at all", "usage: tool [flags]\n", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := extractVersion(tc.in); got != tc.want {
			t.Errorf("%s: extractVersion = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestProbeTools(t *testing.T) {
	cases := []struct {
		name      string
		installed []string
		cmds      map[string]reply
		want      map[string]string
	}{
		{
			name:      "six of seven installed",
			installed: toolBinaries,
			cmds:      toolReplies(),
			want:      installedTools(),
		},
		{
			name: "nothing installed",
			want: allToolsAbsent(),
		},
		{
			name:      "second flag set is tried when the first fails",
			installed: []string{"syft", "container-structure-test"},
			cmds: map[string]reply{
				"syft --version":                   {stderr: "unknown flag: --version", err: errExit1},
				"syft version":                     {stdout: "Application: syft\nVersion:    1.55.0\nBuildDate:  2026-10-01T00:00:00Z\n"},
				"container-structure-test version": {stdout: "v1.19.3\n"},
			},
			want: map[string]string{
				"syft": "1.55.0", "container-structure-test": "v1.19.3",
				"cosign": ToolAbsent, "grype": ToolAbsent, "hadolint": ToolAbsent, "trivy": ToolAbsent, "dockle": ToolAbsent,
			},
		},
		{
			name:      "version printed to stderr",
			installed: []string{"hadolint"},
			cmds:      map[string]reply{"hadolint --version": {stderr: "Haskell Dockerfile Linter 2.12.0\n"}},
			want: map[string]string{
				"hadolint": "2.12.0",
				"syft":     ToolAbsent, "cosign": ToolAbsent, "grype": ToolAbsent, "trivy": ToolAbsent, "container-structure-test": ToolAbsent, "dockle": ToolAbsent,
			},
		},
		{
			name:      "installed but unusable output",
			installed: []string{"grype", "trivy"},
			cmds: map[string]reply{
				"grype --version": {stdout: "no version here\n"},
				"grype version":   {err: errExit1},
				"trivy --version": {stdout: "usage: trivy\n"},
				"trivy version":   {stdout: ""},
			},
			want: map[string]string{
				"grype": ToolVersionUnknown, "trivy": ToolVersionUnknown,
				"syft": ToolAbsent, "cosign": ToolAbsent, "hadolint": ToolAbsent, "container-structure-test": ToolAbsent, "dockle": ToolAbsent,
			},
		},
		{
			name:      "a failed invocation never yields a version from its usage text",
			installed: []string{"cosign"},
			cmds: map[string]reply{
				"cosign version":   {stdout: "Error: see docs at version 9.9.9\n", err: errExit1},
				"cosign --version": {stderr: "unknown flag", err: errExit1},
			},
			want: map[string]string{
				"cosign": ToolVersionUnknown,
				"syft":   ToolAbsent, "grype": ToolAbsent, "hadolint": ToolAbsent, "trivy": ToolAbsent, "container-structure-test": ToolAbsent, "dockle": ToolAbsent,
			},
		},
		{
			// Dockle has no version subcommand: `dockle version` would be read as
			// an image name. Only --version is probed, so a failure of it leaves
			// the version unknown and never starts a scan.
			name:      "dockle is probed with --version only",
			installed: []string{"dockle"},
			cmds: map[string]reply{
				"dockle --version": {stderr: "flag provided but not defined", err: errExit1},
				"dockle version":   {stdout: "dockle version 9.9.9\n"},
			},
			want: map[string]string{
				"dockle": ToolVersionUnknown,
				"syft":   ToolAbsent, "cosign": ToolAbsent, "grype": ToolAbsent, "hadolint": ToolAbsent, "trivy": ToolAbsent, "container-structure-test": ToolAbsent,
			},
		},
		{
			name:      "dockle version is read from stdout",
			installed: []string{"dockle"},
			cmds:      map[string]reply{"dockle --version": {stdout: "dockle version 0.4.15\n"}},
			want: map[string]string{
				"dockle": "0.4.15",
				"syft":   ToolAbsent, "cosign": ToolAbsent, "grype": ToolAbsent, "hadolint": ToolAbsent, "trivy": ToolAbsent, "container-structure-test": ToolAbsent,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario{os: "linux", arch: "amd64", cpus: 2, installed: tc.installed, cmds: tc.cmds}
			got := probeTools(context.Background(), s.build(t).env.withDefaults())
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("probeTools = %v\n want %v", got, tc.want)
			}
		})
	}
}

func TestProbeToolsHangingToolDoesNotBlock(t *testing.T) {
	s := scenario{
		os: "linux", arch: "amd64", cpus: 2,
		installed: toolBinaries,
		cmds: mergeReplies(toolReplies(), map[string]reply{
			"trivy --version": {stuck: true},
			"grype --version": {hang: true},
		}),
	}
	be := s.build(t)
	be.env.CommandTimeout = 100 * time.Millisecond

	start := time.Now()
	got := probeTools(context.Background(), be.env.withDefaults())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("probeTools took %v with hanging tools, want about 100ms", elapsed)
	}
	if got["trivy"] != ToolVersionUnknown || got["grype"] != ToolVersionUnknown {
		t.Errorf("hanging tools = %q, %q; want %q", got["trivy"], got["grype"], ToolVersionUnknown)
	}
	if got["syft"] != "1.55.0" || got["hadolint"] != "2.14.0" {
		t.Errorf("healthy tools were affected: %v", got)
	}
}
