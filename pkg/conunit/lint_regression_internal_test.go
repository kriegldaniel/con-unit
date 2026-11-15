package conunit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/oci"
)

type sampleHistory struct {
	History []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

func loadSampleHistory(t *testing.T, name string) *oci.FilesystemIndex {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "lint", "official-"+name+".json"))
	if err != nil {
		t.Fatalf("sample %s: %v", name, err)
	}
	var sample sampleHistory
	if err := json.Unmarshal(raw, &sample); err != nil {
		t.Fatalf("sample %s: %v", name, err)
	}
	index := &oci.FilesystemIndex{}
	for _, entry := range sample.History {
		index.History = append(index.History, oci.HistoryEntry{CreatedBy: entry.CreatedBy, EmptyLayer: entry.EmptyLayer})
	}
	return index
}

// The RUN steps of the real histories, counted by hand from the history
// entries: the BuildKit images (python, nginx, postgres), the legacy form of
// the Ubuntu base image, the single comment entry of the Debian base image,
// the rootfs import of Alpine and the bare bazel commands of distroless.
func TestHistoryReaderOverRealOfficialImages(t *testing.T) {
	cases := []struct {
		sample    string
		wantSteps int
		// wantCommand is a command that must be found in some step.
		wantCommand string
	}{
		{"alpine", 0, ""},
		{"debian", 0, ""},
		{"ubuntu", 0, ""},
		{"python-slim", 3, "apt-get install"},
		{"nginx", 1, "groupadd"},
		{"postgres", 12, "apt-get update"},
		{"distroless", 12, "bazel"},
	}
	for _, tc := range cases {
		t.Run(tc.sample, func(t *testing.T) {
			scan := scanHistory(loadSampleHistory(t, tc.sample))
			if scan.Issue != "" {
				t.Errorf("a real history must be complete evidence, got the issue %q", scan.Issue)
			}
			if len(scan.Steps) != tc.wantSteps {
				t.Errorf("%d RUN steps, want %d", len(scan.Steps), tc.wantSteps)
			}
			if tc.wantCommand == "" {
				return
			}
			found := false
			for _, step := range scan.Steps {
				for _, command := range step.Commands {
					if strings.HasPrefix(command.String(), tc.wantCommand) {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("no command starting with %q was extracted", tc.wantCommand)
			}
		})
	}
}

// The python image runs 'set -eux; apt-get update; apt-get install ...;
// apt-get dist-clean' in one step with tabs and continuations. The reader must
// see the three apt commands, in order, and no sudo.
func TestRealPythonStepIsReadCommandByCommand(t *testing.T) {
	scan := scanHistory(loadSampleHistory(t, "python-slim"))
	var apt []string
	for _, command := range scan.Steps[0].Commands {
		if sub, ok := aptSubcommand(command); ok {
			apt = append(apt, sub)
		}
	}
	if got := strings.Join(apt, ","); got != "update,install,dist-clean" {
		t.Errorf("apt subcommands = %q, want update,install,dist-clean", got)
	}
	if len(updatesWithoutInstall(scan.Steps)) != 0 || len(sudoCommands(scan.Steps)) != 0 || len(distUpgradeCommands(scan.Steps)) != 0 {
		t.Error("the unmodified python image must have no finding")
	}
}
