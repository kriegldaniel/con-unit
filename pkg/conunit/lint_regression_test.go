package conunit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// The samples under testdata/lint hold the config values and the build history
// of real images of the Docker Official Images program and of the distroless
// project, read from their registries with the linux/amd64 platform manifest:
// alpine, debian, ubuntu, nginx, postgres, python and distroless static. They
// keep the command text of every history entry as the registry returned it
// (tabs and line continuations included) and nothing else of the image: no
// file content, no timestamp, no host path. The source digests are recorded in
// each file, so the sample can be traced to the exact image.

type officialSample struct {
	Source struct {
		Registry               string `json:"registry"`
		Repository             string `json:"repository"`
		TagAtFetch             string `json:"tag_at_fetch"`
		IndexOrManifestDigest  string `json:"index_or_manifest_digest"`
		PlatformManifestDigest string `json:"platform_manifest_digest"`
		ConfigDigest           string `json:"config_digest"`
	} `json:"source"`
	Platform string             `json:"platform"`
	Config   engine.ImageConfig `json:"config"`
	History  []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

var officialSamples = []string{"alpine", "debian", "ubuntu", "nginx", "postgres", "python-slim", "distroless"}

func loadOfficialSample(t *testing.T, name string) (officialSample, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "lint", "official-"+name+".json"))
	if err != nil {
		t.Fatalf("sample %s: %v", name, err)
	}
	var sample officialSample
	if err := json.Unmarshal(raw, &sample); err != nil {
		t.Fatalf("sample %s: %v", name, err)
	}
	return sample, raw
}

func (s officialSample) container(mutate func(index int, createdBy string) string) *conunit.Container {
	history := make([]oci.HistoryEntry, 0, len(s.History))
	for i, entry := range s.History {
		createdBy := entry.CreatedBy
		if mutate != nil {
			createdBy = mutate(i, createdBy)
		}
		history = append(history, oci.HistoryEntry{CreatedBy: createdBy, EmptyLayer: entry.EmptyLayer})
	}
	return &conunit.Container{
		Inspect:  &engine.ImageInspect{Config: s.Config},
		OCIIndex: &oci.FilesystemIndex{History: history},
	}
}

func (s officialSample) outcomes(t *testing.T, mutate func(int, string) string, acceptedKeys []string) map[string]spec.Outcome {
	t.Helper()
	c := s.container(mutate)
	a := c.AssertSpec()
	a.UserNotRoot()
	a.RequireHealthcheck()
	a.DisallowedEnvKeysExcept(acceptedKeys, "PASS", "PASSWD", "PASSWORD", "SECRET", "KEY", "ACCESS", "TOKEN")
	a.UpdateCombinedWithInstall()
	a.NoSudoInHistory()
	a.NoDistUpgradeInHistory()
	a.NoSensitiveVolumes()
	outcomes := map[string]spec.Outcome{}
	for _, r := range c.Results {
		outcomes[r.TestID] = r.EffectiveOutcome()
	}
	return outcomes
}

func TestOfficialSamplesCarryTheirProvenanceAndNoHostPath(t *testing.T) {
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hostPath := regexp.MustCompile(`/Users/|/private/var|/var/folders|/tmp/|C:\\|/home/runner|/nix/store`)
	for _, name := range officialSamples {
		t.Run(name, func(t *testing.T) {
			sample, raw := loadOfficialSample(t, name)
			src := sample.Source
			if src.Registry == "" || src.Repository == "" || src.TagAtFetch == "" {
				t.Errorf("source is incomplete: %+v", src)
			}
			for field, value := range map[string]string{"index or manifest": src.IndexOrManifestDigest, "platform manifest": src.PlatformManifestDigest, "config": src.ConfigDigest} {
				if !digest.MatchString(value) {
					t.Errorf("the %s digest %q is not a sha256 digest", field, value)
				}
			}
			if sample.Platform != "linux/amd64" {
				t.Errorf("platform = %q, want linux/amd64", sample.Platform)
			}
			if len(sample.History) == 0 {
				t.Error("a sample without history is no regression evidence")
			}
			if loc := hostPath.FindString(string(raw)); loc != "" {
				t.Errorf("the sample holds a host path or a temporary path: %q", loc)
			}
		})
	}
}

func TestLintChecksOverRealOfficialImages(t *testing.T) {
	// What the lint pack must say about the unmodified images. The pack runs
	// SPEC-03 with the accepted keys GPG_KEY and GPG_KEYS, which is why the
	// python image passes.
	want := map[string]map[string]spec.Outcome{}
	for _, name := range officialSamples {
		want[name] = map[string]spec.Outcome{
			"SPEC-01": spec.OutcomeFail, "CIS-4.6": spec.OutcomeFail, "SPEC-03": spec.OutcomePass,
			"SPEC-09": spec.OutcomePass, "SPEC-10": spec.OutcomePass, "SPEC-11": spec.OutcomePass, "SPEC-12": spec.OutcomePass,
		}
	}
	want["distroless"]["SPEC-01"] = spec.OutcomePass // runs as the numeric user 65532
	for _, name := range officialSamples {
		t.Run(name, func(t *testing.T) {
			sample, _ := loadOfficialSample(t, name)
			got := sample.outcomes(t, nil, []string{"GPG_KEY", "GPG_KEYS"})
			for id, outcome := range want[name] {
				if got[id] != outcome {
					t.Errorf("%s on %s = %s, want %s", id, name, got[id], outcome)
				}
			}
			if len(got) != len(want[name]) {
				t.Errorf("got results for %v, want %d rules", got, len(want[name]))
			}
		})
	}

	t.Run("without the accepted keys the python image fails SPEC-03 on GPG_KEY", func(t *testing.T) {
		sample, _ := loadOfficialSample(t, "python-slim")
		if got := sample.outcomes(t, nil, nil)["SPEC-03"]; got != spec.OutcomeFail {
			t.Errorf("SPEC-03 = %s, want FAIL: KEY matches GPG_KEY", got)
		}
	})
	t.Run("the postgres image declares a volume that is not sensitive", func(t *testing.T) {
		sample, _ := loadOfficialSample(t, "postgres")
		if _, ok := sample.Config.Volumes["/var/lib/postgresql/data"]; !ok {
			t.Fatalf("volumes = %v, want the data volume of the image", sample.Config.Volumes)
		}
	})
}

// A defect is injected into the real command text of a RUN step, so the
// tokenizer meets the formatting of real images: tabs, continuations, quoted
// substitutions and the BuildKit marker.
func TestLintChecksOnMutantsOfRealRunSteps(t *testing.T) {
	type mutant struct {
		name   string
		sample string
		entry  int
		mutate func(string) string
		want   map[string]spec.Outcome
	}
	replaceAll := func(old, new string) func(string) string {
		return func(text string) string { return strings.ReplaceAll(text, old, new) }
	}
	replaceFirst := func(old, new string) func(string) string {
		return func(text string) string { return strings.Replace(text, old, new, 1) }
	}
	cases := []mutant{
		{"python: the install is removed", "python-slim", 3, replaceAll("apt-get install", "apt-get autoremove"), map[string]spec.Outcome{"SPEC-09": spec.OutcomeFail, "SPEC-10": spec.OutcomePass, "SPEC-11": spec.OutcomePass}},
		{"nginx: the install is removed", "nginx", 8, replaceAll("apt-get install", "apt-get autoremove"), map[string]spec.Outcome{"SPEC-09": spec.OutcomeFail, "SPEC-10": spec.OutcomePass, "SPEC-11": spec.OutcomePass}},
		{"postgres: the install is removed", "postgres", 2, replaceAll("apt-get install", "apt-get autoremove"), map[string]spec.Outcome{"SPEC-09": spec.OutcomeFail, "SPEC-10": spec.OutcomePass, "SPEC-11": spec.OutcomePass}},
		{"python: sudo before the update", "python-slim", 3, replaceFirst("apt-get update", "sudo apt-get update"), map[string]spec.Outcome{"SPEC-09": spec.OutcomePass, "SPEC-10": spec.OutcomeFail, "SPEC-11": spec.OutcomePass}},
		{"nginx: sudo before the update", "nginx", 8, replaceFirst("apt-get update", "sudo apt-get update"), map[string]spec.Outcome{"SPEC-09": spec.OutcomePass, "SPEC-10": spec.OutcomeFail, "SPEC-11": spec.OutcomePass}},
		{"postgres: sudo before the update", "postgres", 2, replaceFirst("apt-get update", "sudo apt-get update"), map[string]spec.Outcome{"SPEC-09": spec.OutcomePass, "SPEC-10": spec.OutcomeFail, "SPEC-11": spec.OutcomePass}},
		{"python: dist-clean becomes dist-upgrade", "python-slim", 3, replaceFirst("apt-get dist-clean", "apt-get dist-upgrade -y"), map[string]spec.Outcome{"SPEC-09": spec.OutcomePass, "SPEC-10": spec.OutcomePass, "SPEC-11": spec.OutcomeFail}},
		{"python: sudo is only echoed", "python-slim", 3, replaceFirst("apt-get update", "echo sudo; apt-get update"), map[string]spec.Outcome{"SPEC-09": spec.OutcomePass, "SPEC-10": spec.OutcomePass, "SPEC-11": spec.OutcomePass}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sample, _ := loadOfficialSample(t, tc.sample)
			original := sample.History[tc.entry].CreatedBy
			if tc.mutate(original) == original {
				t.Fatalf("the mutation did not change history entry %d of %s: the test would prove nothing", tc.entry, tc.sample)
			}
			got := sample.outcomes(t, func(index int, createdBy string) string {
				if index == tc.entry {
					return tc.mutate(createdBy)
				}
				return createdBy
			}, []string{"GPG_KEY", "GPG_KEYS"})
			for id, outcome := range tc.want {
				if got[id] != outcome {
					t.Errorf("%s = %s, want %s", id, got[id], outcome)
				}
			}
		})
	}
}
