package conunit_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// historyContainer holds an index with the given history entries, as the
// config of an image records them.
func historyContainer(entries ...string) *conunit.Container {
	history := make([]oci.HistoryEntry, 0, len(entries))
	for _, entry := range entries {
		history = append(history, oci.HistoryEntry{CreatedBy: entry})
	}
	return &conunit.Container{OCIIndex: &oci.FilesystemIndex{History: history}}
}

type historyCase struct {
	name    string
	entries []string
	want    spec.Outcome
}

// runHistoryCases runs one history check over a table and checks, for every
// result, the reason and the rule metadata that the contract fixes.
func runHistoryCases(t *testing.T, ruleID string, assert func(*conunit.SpecAssertions), cases []historyCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := historyContainer(tc.entries...)
			assert(c.AssertSpec())
			r := onlyResult(t, c)
			if r.TestID != ruleID || r.EffectiveOutcome() != tc.want {
				t.Fatalf("result = %s %s (%s), want %s %s", r.TestID, r.EffectiveOutcome(), r.Message, ruleID, tc.want)
			}
			switch tc.want {
			case spec.OutcomeUnverified:
				if r.Reason != spec.ReasonEvidenceIncomplete {
					t.Errorf("reason = %q, want EVIDENCE_INCOMPLETE", r.Reason)
				}
			default:
				if r.Reason != spec.ReasonNone {
					t.Errorf("reason = %q, want none for %s", r.Reason, tc.want)
				}
			}
			if r.Tier != spec.TierSpec || r.Rule == nil {
				t.Errorf("tier = %v, rule = %v, want Tier 1 with a rule mapping", r.Tier, r.Rule)
			}
		})
	}
}

const buildkitPrefix = "RUN /bin/sh -c "

func TestSpec09UpdateCombinedWithInstall(t *testing.T) {
	runHistoryCases(t, "SPEC-09", func(s *conunit.SpecAssertions) { s.UpdateCombinedWithInstall() }, []historyCase{
		// History forms.
		{"legacy form, update alone", []string{"/bin/sh -c apt-get update"}, spec.OutcomeFail},
		{"legacy form, combined", []string{"/bin/sh -c apt-get update && apt-get install -y curl"}, spec.OutcomePass},
		{"legacy form with a build argument, update alone", []string{"|1 A=b /bin/sh -c apt-get update"}, spec.OutcomeFail},
		{"legacy form with a build argument, combined", []string{"|1 A=b /bin/sh -c apt-get update && apt-get install -y x"}, spec.OutcomePass},
		{"BuildKit form, update alone", []string{buildkitPrefix + "apt-get update # buildkit"}, spec.OutcomeFail},
		{"BuildKit form, combined with semicolons and tabs", []string{buildkitPrefix + "set -eux; \tapt-get update; \tapt-get install -y --no-install-recommends \\\n\t\tca-certificates \\\n\t; \tapt-get dist-clean # buildkit"}, spec.OutcomePass},
		{"BuildKit form without a shell", []string{"RUN apt-get update # buildkit"}, spec.OutcomeFail},

		// Multi-command lines, quoting and continuations.
		{"update followed by another command only", []string{buildkitPrefix + "set -eux; apt-get update; echo done # buildkit"}, spec.OutcomeFail},
		{"update after the install", []string{buildkitPrefix + "apt-get install -y x && apt-get update # buildkit"}, spec.OutcomeFail},
		{"words in quotes are no command", []string{buildkitPrefix + `echo "apt-get update" # buildkit`}, spec.OutcomePass},
		{"continuation between update and install", []string{buildkitPrefix + "apt-get update \\\n && apt-get install -y x # buildkit"}, spec.OutcomePass},
		{"a semicolon glued to the word", []string{buildkitPrefix + "apt-get update; make # buildkit"}, spec.OutcomeFail},
		{"update inside a nested shell", []string{buildkitPrefix + `bash -c "apt-get update" # buildkit`}, spec.OutcomeFail},
		{"install in a later step does not combine", []string{buildkitPrefix + "apt-get update # buildkit", buildkitPrefix + "apt-get install -y x # buildkit"}, spec.OutcomeFail},
		{"one good and one bad step", []string{buildkitPrefix + "apt-get update && apt-get install -y x # buildkit", buildkitPrefix + "apt-get update # buildkit"}, spec.OutcomeFail},

		// What is not scanned.
		{"metadata that mentions the words", []string{"ENV UPDATE=apt-get update", "LABEL cmd=apt-get update", `CMD ["apt-get" "update"]`}, spec.OutcomePass},
		{"a comment entry", []string{"# debian.sh --arch 'amd64' out/ 'bookworm'"}, spec.OutcomePass},
		{"apk is not covered", []string{buildkitPrefix + "apk update # buildkit"}, spec.OutcomePass},
		{"no RUN step at all", []string{"ADD alpine-minirootfs.tar.gz / # buildkit", `CMD ["/bin/sh"]`}, spec.OutcomePass},

		// Evidence that cannot carry a verdict.
		{"an empty history", nil, spec.OutcomeUnverified},
		{"an empty command", []string{"RUN make # buildkit", "   "}, spec.OutcomeUnverified},
		{"an unterminated quote", []string{buildkitPrefix + `echo "x # buildkit`}, spec.OutcomeUnverified},
		{"a finding stands next to an unreadable step", []string{buildkitPrefix + "apt-get update # buildkit", buildkitPrefix + `echo "x # buildkit`}, spec.OutcomeFail},
	})

	t.Run("the message names the entry and the command and the check is custom", func(t *testing.T) {
		c := historyContainer("ENV A=b", buildkitPrefix+"apt-get update -qq # buildkit")
		c.AssertSpec().UpdateCombinedWithInstall()
		r := onlyResult(t, c)
		if !strings.Contains(r.Message, "history entry 2: apt-get update -qq") {
			t.Errorf("message = %q, want entry 2 and the command", r.Message)
		}
		if r.Rule == nil || r.Rule.Mapping != spec.MappingCustom || r.Rule.ControlID != "" || r.Rule.Standard != "ConUnit" {
			t.Errorf("rule mapping = %+v, want a custom ConUnit check", r.Rule)
		}
	})
	t.Run("no OCI index", func(t *testing.T) {
		c := &conunit.Container{}
		c.AssertSpec().UpdateCombinedWithInstall()
		if r := onlyResult(t, c); r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonEvidenceIncomplete {
			t.Fatalf("result = %+v, want UNVERIFIED/EVIDENCE_INCOMPLETE", r)
		}
	})
}

func TestSpec10NoSudoInTheBuildHistory(t *testing.T) {
	runHistoryCases(t, "SPEC-10", func(s *conunit.SpecAssertions) { s.NoSudoInHistory() }, []historyCase{
		{"legacy form", []string{"/bin/sh -c sudo apt-get update"}, spec.OutcomeFail},
		{"BuildKit form", []string{buildkitPrefix + "sudo make install # buildkit"}, spec.OutcomeFail},
		{"build argument prefix", []string{"|1 A=b /bin/sh -c sudo make"}, spec.OutcomeFail},
		{"sudo after && in a multi-command line", []string{buildkitPrefix + "set -eux; apt-get update && sudo apt-get install -y x # buildkit"}, spec.OutcomeFail},
		{"sudo after a pipe", []string{buildkitPrefix + "echo x | sudo tee /etc/f # buildkit"}, spec.OutcomeFail},
		{"sudo after a newline and a continuation", []string{buildkitPrefix + "make \\\n  && echo ok\nsudo id # buildkit"}, spec.OutcomeFail},
		{"sudo behind a variable assignment", []string{buildkitPrefix + "DEBIAN_FRONTEND=noninteractive sudo apt-get install -y x # buildkit"}, spec.OutcomeFail},
		{"sudo inside a nested shell", []string{buildkitPrefix + `bash -c "sudo id" # buildkit`}, spec.OutcomeFail},
		{"quoted command word", []string{buildkitPrefix + `"sudo" id # buildkit`}, spec.OutcomeFail},
		{"a path to sudo", []string{buildkitPrefix + "/usr/bin/sudo -u app id # buildkit"}, spec.OutcomeFail},

		{"echo sudo is no finding", []string{buildkitPrefix + "echo sudo # buildkit"}, spec.OutcomePass},
		{"installing the package is no finding", []string{buildkitPrefix + "apt-get install -y sudo # buildkit"}, spec.OutcomePass},
		{"a sudoers file is no finding", []string{buildkitPrefix + "echo 'app ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers # buildkit"}, spec.OutcomePass},
		{"command -v sudo is no finding", []string{buildkitPrefix + "command -v sudo || true # buildkit"}, spec.OutcomePass},
		{"sudo in a comment is no finding", []string{buildkitPrefix + "make # sudo is not needed\nmake install # buildkit"}, spec.OutcomePass},
		{"sudo in a quoted argument is no finding", []string{buildkitPrefix + `echo "never run sudo" # buildkit`}, spec.OutcomePass},
		{"metadata that names sudo", []string{`ENTRYPOINT ["sudo" "app"]`, "ENV SUDO=sudo", "HEALTHCHECK CMD sudo -n true"}, spec.OutcomePass},
		{"a clean history", []string{"ADD rootfs.tar.gz / # buildkit", buildkitPrefix + "make # buildkit"}, spec.OutcomePass},

		{"an empty history", nil, spec.OutcomeUnverified},
		{"an empty command", []string{"  "}, spec.OutcomeUnverified},
		{"an unterminated quote", []string{buildkitPrefix + `echo 'x # buildkit`}, spec.OutcomeUnverified},
	})
}

func TestSpec11NoDistributionUpgradeInTheBuildHistory(t *testing.T) {
	runHistoryCases(t, "SPEC-11", func(s *conunit.SpecAssertions) { s.NoDistUpgradeInHistory() }, []historyCase{
		{"apt-get, legacy form", []string{"/bin/sh -c apt-get dist-upgrade -y"}, spec.OutcomeFail},
		{"apt, BuildKit form", []string{buildkitPrefix + "apt dist-upgrade -y # buildkit"}, spec.OutcomeFail},
		{"option before the subcommand", []string{buildkitPrefix + "apt-get -y dist-upgrade # buildkit"}, spec.OutcomeFail},
		{"after update in a multi-command line", []string{buildkitPrefix + "apt-get update && apt-get -o Dpkg::Options::=--force-confold dist-upgrade -y # buildkit"}, spec.OutcomeFail},
		{"after a semicolon and a continuation", []string{buildkitPrefix + "set -eux; \\\n  apt-get dist-upgrade # buildkit"}, spec.OutcomeFail},
		{"build argument prefix", []string{"|1 A=b /bin/sh -c apt-get dist-upgrade"}, spec.OutcomeFail},

		{"dist-clean is not dist-upgrade", []string{buildkitPrefix + "apt-get dist-clean # buildkit"}, spec.OutcomePass},
		{"upgrade is not dist-upgrade", []string{buildkitPrefix + "apt-get update && apt-get upgrade -y # buildkit"}, spec.OutcomePass},
		{"full-upgrade is not reported", []string{buildkitPrefix + "apt full-upgrade -y # buildkit"}, spec.OutcomePass},
		{"an echo of the words", []string{buildkitPrefix + `echo "apt-get dist-upgrade" # buildkit`}, spec.OutcomePass},
		{"metadata that mentions it", []string{"LABEL note=apt-get dist-upgrade"}, spec.OutcomePass},

		{"an empty history", nil, spec.OutcomeUnverified},
		{"an empty command", []string{"RUN make # buildkit", ""}, spec.OutcomeUnverified},
		{"an unterminated here-document", []string{buildkitPrefix + "cat <<EOF\nx # buildkit"}, spec.OutcomeUnverified},
	})
}

func volumeContainer(volumes ...string) *conunit.Container {
	inspect := &engine.ImageInspect{}
	if volumes != nil {
		inspect.Config.Volumes = map[string]struct{}{}
		for _, volume := range volumes {
			inspect.Config.Volumes[volume] = struct{}{}
		}
	}
	return &conunit.Container{Inspect: inspect}
}

func TestSpec12NoSensitiveHostPathsAsVolumes(t *testing.T) {
	cases := []struct {
		name      string
		volumes   []string
		want      spec.Outcome
		wantPaths []string
	}{
		{"no volume", nil, spec.OutcomePass, nil},
		{"an ordinary volume", []string{"/data"}, spec.OutcomePass, nil},
		{"several ordinary volumes", []string{"/data", "/var/log", "/var/lib/postgresql/data"}, spec.OutcomePass, nil},
		{"/proc", []string{"/proc"}, spec.OutcomeFail, []string{"/proc"}},
		{"/sys", []string{"/sys"}, spec.OutcomeFail, []string{"/sys"}},
		{"/dev", []string{"/dev"}, spec.OutcomeFail, []string{"/dev"}},
		{"a child of /proc", []string{"/proc/sys"}, spec.OutcomeFail, []string{"/proc/sys"}},
		{"a child of /dev", []string{"/dev/shm"}, spec.OutcomeFail, []string{"/dev/shm"}},
		{"a trailing slash", []string{"/proc/"}, spec.OutcomeFail, []string{"/proc/"}},
		{"a doubled separator", []string{"//sys"}, spec.OutcomeFail, []string{"//sys"}},
		{"dot dot back into /proc", []string{"/etc/../proc"}, spec.OutcomeFail, []string{"/etc/../proc"}},
		{"dot dot out of /proc", []string{"/proc/../data"}, spec.OutcomePass, nil},
		{"findings are sorted and ordinary volumes are left out", []string{"/sys", "/data", "/proc/1"}, spec.OutcomeFail, []string{"/proc/1", "/sys"}},
		{"a name that only starts like a root", []string{"/processing", "/devices", "/system", "/dev-data"}, spec.OutcomePass, nil},
		{"a relative path cannot be placed", []string{"data"}, spec.OutcomeUnverified, nil},
		{"an empty path cannot be placed", []string{""}, spec.OutcomeUnverified, nil},
		{"a finding stands next to an unplaceable path", []string{"data", "/proc"}, spec.OutcomeFail, []string{"/proc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := volumeContainer(tc.volumes...)
			c.AssertSpec().NoSensitiveVolumes()
			r := onlyResult(t, c)
			if r.TestID != "SPEC-12" || r.EffectiveOutcome() != tc.want {
				t.Fatalf("result = %s %s (%s), want %s", r.TestID, r.EffectiveOutcome(), r.Message, tc.want)
			}
			if tc.want == spec.OutcomeUnverified && r.Reason != spec.ReasonEvidenceIncomplete {
				t.Errorf("reason = %q, want EVIDENCE_INCOMPLETE", r.Reason)
			}
			if tc.want == spec.OutcomeFail && (r.Evidence == nil || !reflect.DeepEqual(r.Evidence.Paths, tc.wantPaths)) {
				t.Errorf("evidence = %+v, want paths %v", r.Evidence, tc.wantPaths)
			}
		})
	}
	t.Run("no inspection data", func(t *testing.T) {
		c := &conunit.Container{}
		c.AssertSpec().NoSensitiveVolumes()
		if r := onlyResult(t, c); r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonEvidenceIncomplete {
			t.Fatalf("result = %+v, want UNVERIFIED/EVIDENCE_INCOMPLETE", r)
		}
	})
}

func TestSpec13ExplicitNonLatestReference(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		ref  string
		want spec.Outcome
	}{
		// No tag and no digest, or latest.
		{"alpine", spec.OutcomeFail},
		{"alpine:latest", spec.OutcomeFail},
		{"docker.io/library/alpine", spec.OutcomeFail},
		{"ghcr.io/owner/repo", spec.OutcomeFail},
		{"localhost:5000/app", spec.OutcomeFail},
		{"localhost:5000/app:latest", spec.OutcomeFail},
		{"  alpine  ", spec.OutcomeFail},

		// Pinned, or an explicit tag.
		{"alpine:3.20", spec.OutcomePass},
		{"alpine:3.20-slim", spec.OutcomePass},
		{"localhost:5000/app:v1", spec.OutcomePass},
		{"alpine@" + digest, spec.OutcomePass},
		{"docker.io/library/alpine@" + digest, spec.OutcomePass},
		{"alpine:3.20@" + digest, spec.OutcomePass},
		{"alpine:latest@" + digest, spec.OutcomePass},
		{"alpine@sha512:" + strings.Repeat("b", 128), spec.OutcomePass},
		{digest, spec.OutcomePass},
		{strings.Repeat("c", 64), spec.OutcomePass},
		{"alpine:LATEST", spec.OutcomePass},
		{"alpine:latest-slim", spec.OutcomePass},

		// Evidence that cannot carry a verdict.
		{"", spec.OutcomeUnverified},
		{"   ", spec.OutcomeUnverified},
		{"alpine:", spec.OutcomeUnverified},
		{"alp ine", spec.OutcomeUnverified},
		{"alpine@sha256:xyz", spec.OutcomeUnverified},
		{"@" + digest, spec.OutcomeUnverified},
		{"Alpine", spec.OutcomeUnverified},
		{"alpine:bad tag", spec.OutcomeUnverified},
		{"alpine:-dash", spec.OutcomeUnverified},
		{"alpine@" + digest + "x", spec.OutcomeUnverified},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.ref), func(t *testing.T) {
			c := &conunit.Container{RequestedRef: tc.ref}
			c.AssertSpec().ExplicitNonLatestReference()
			r := onlyResult(t, c)
			if r.TestID != "SPEC-13" || r.EffectiveOutcome() != tc.want {
				t.Fatalf("result = %s %s (%s), want %s", r.TestID, r.EffectiveOutcome(), r.Message, tc.want)
			}
			if tc.want == spec.OutcomeUnverified && r.Reason != spec.ReasonEvidenceIncomplete {
				t.Errorf("reason = %q, want EVIDENCE_INCOMPLETE", r.Reason)
			}
			if tc.want != spec.OutcomeUnverified && r.Reason != spec.ReasonNone {
				t.Errorf("reason = %q, want none", r.Reason)
			}
		})
	}
	t.Run("a pass for a tag says that the tag can move", func(t *testing.T) {
		c := &conunit.Container{RequestedRef: "alpine:3.20"}
		c.AssertSpec().ExplicitNonLatestReference()
		if r := onlyResult(t, c); !strings.Contains(r.Message, "can still be moved") {
			t.Errorf("message = %q, want the note that an explicit tag is mutable", r.Message)
		}
	})
	t.Run("a pass for a digest names fixed content", func(t *testing.T) {
		c := &conunit.Container{RequestedRef: "alpine@" + digest}
		c.AssertSpec().ExplicitNonLatestReference()
		if r := onlyResult(t, c); !strings.Contains(r.Message, "fixed content") {
			t.Errorf("message = %q, want the digest note", r.Message)
		}
	})
}
