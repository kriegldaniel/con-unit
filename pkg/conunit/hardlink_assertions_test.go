package conunit_test

import (
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// unresolvedLinkIndex returns an index with unresolved hard links at the given
// paths and with the given findings applied by mutate.
func unresolvedLinkIndex(mutate func(*oci.FilesystemIndex), paths ...string) *oci.FilesystemIndex {
	index := &oci.FilesystemIndex{
		SuidMap:            map[string]int64{},
		WorldWritableFiles: map[string]int64{},
	}
	if len(paths) > 0 {
		index.UnresolvedHardLinks = paths
		index.UnresolvedHardLinkReasons = map[string]string{}
		for _, p := range paths {
			index.UnresolvedHardLinkReasons[p] = "hard link " + p + " names /elsewhere, which is not a file of the same layer"
		}
	}
	if mutate != nil {
		mutate(index)
	}
	return index
}

func TestModeAndOwnershipChecksAreUnverifiedWhenHardLinksAreUnresolved(t *testing.T) {
	checks := map[string]func(*conunit.Container){
		"FS-04": func(c *conunit.Container) { c.AssertFilesystem().NoSuidBinaries() },
		"FS-05": func(c *conunit.Container) { c.AssertFilesystem().NoWorldWritableFiles() },
		"FS-09": func(c *conunit.Container) { c.AssertFilesystem().NoNonRootSystemBinaries() },
	}
	findings := map[string]func(*oci.FilesystemIndex){
		"FS-04": func(i *oci.FilesystemIndex) { i.SuidMap["/usr/bin/su"] = 04755 },
		"FS-05": func(i *oci.FilesystemIndex) { i.WorldWritableFiles["/opt/data"] = 0666 },
		"FS-09": func(i *oci.FilesystemIndex) { i.NonRootSystemBinaries = []string{"/usr/bin/tool (UID 10001)"} },
	}

	cases := []struct {
		name        string
		rule        string
		linkPaths   []string
		withFinding bool
		want        spec.Outcome
		wantReason  spec.Reason
	}{
		{name: "FS-04 clean without links", rule: "FS-04", want: spec.OutcomePass},
		{name: "FS-04 clean with an unresolved link anywhere", rule: "FS-04", linkPaths: []string{"/opt/a"}, want: spec.OutcomeUnverified, wantReason: spec.ReasonEvidenceIncomplete},
		{name: "FS-04 finding stands despite an unresolved link", rule: "FS-04", linkPaths: []string{"/opt/a"}, withFinding: true, want: spec.OutcomeFail},

		{name: "FS-05 clean without links", rule: "FS-05", want: spec.OutcomePass},
		{name: "FS-05 clean with an unresolved link anywhere", rule: "FS-05", linkPaths: []string{"/opt/a"}, want: spec.OutcomeUnverified, wantReason: spec.ReasonEvidenceIncomplete},
		{name: "FS-05 finding stands despite an unresolved link", rule: "FS-05", linkPaths: []string{"/opt/a"}, withFinding: true, want: spec.OutcomeFail},

		{name: "FS-09 clean without links", rule: "FS-09", want: spec.OutcomePass},
		{name: "FS-09 clean with an unresolved link in /usr/bin", rule: "FS-09", linkPaths: []string{"/usr/bin/orphan"}, want: spec.OutcomeUnverified, wantReason: spec.ReasonEvidenceIncomplete},
		{name: "FS-09 clean with an unresolved link in /sbin", rule: "FS-09", linkPaths: []string{"/sbin/orphan"}, want: spec.OutcomeUnverified, wantReason: spec.ReasonEvidenceIncomplete},
		{name: "FS-09 ignores an unresolved link outside the system directories", rule: "FS-09", linkPaths: []string{"/opt/a"}, want: spec.OutcomePass},
		{name: "FS-09 finding stands despite an unresolved link", rule: "FS-09", linkPaths: []string{"/usr/bin/orphan"}, withFinding: true, want: spec.OutcomeFail},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mutate func(*oci.FilesystemIndex)
			if tc.withFinding {
				mutate = findings[tc.rule]
			}
			c := &conunit.Container{OCIIndex: unresolvedLinkIndex(mutate, tc.linkPaths...)}
			checks[tc.rule](c)

			if len(c.Results) != 1 {
				t.Fatalf("%s recorded %d results, want one: %+v", tc.rule, len(c.Results), c.Results)
			}
			result := c.Results[0]
			if got := result.EffectiveOutcome(); got != tc.want {
				t.Fatalf("%s outcome = %s, want %s (message: %q)", tc.rule, got, tc.want, result.Message)
			}
			if result.Reason != tc.wantReason {
				t.Errorf("%s reason = %q, want %q", tc.rule, result.Reason, tc.wantReason)
			}
			if tc.want == spec.OutcomeUnverified {
				if !strings.Contains(result.Message, "hard link") || !strings.Contains(result.Message, tc.linkPaths[0]) {
					t.Errorf("%s message must name the unresolved link %s: %q", tc.rule, tc.linkPaths[0], result.Message)
				}
			}
		})
	}
}
