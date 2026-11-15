package oci

import (
	"archive/tar"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var (
	hardLinkKeyPEM  = []byte("-----BEGIN RSA PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----\n")
	hardLinkCertPEM = []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")
)

func hardLink(name, target string, mode int64, uid int) testLayerEntry {
	return testLayerEntry{name: name, mode: mode, uid: uid, typeflag: tar.TypeLink, linkname: target}
}

// buildLayers turns the entries of each layer into an image layer, base first.
func buildLayers(t *testing.T, layers [][]testLayerEntry) []v1.Layer {
	t.Helper()
	built := make([]v1.Layer, 0, len(layers))
	for _, entries := range layers {
		built = append(built, makeTestLayer(t, entries...))
	}
	return built
}

func sameStrings(got, want []string) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	return slices.Equal(got, want)
}

// TestHardLinksTakeTheTargetPropertiesWithinOneLayer shows that a hard link is
// judged by the mode, owner and content of the file it names, never by the
// header of the link entry itself, and that a link without a target in its own
// layer is reported as unresolved instead of being guessed.
func TestHardLinksTakeTheTargetPropertiesWithinOneLayer(t *testing.T) {
	type want struct {
		suid       []string
		worldWrite []string
		nonRoot    []string
		keys       []string
		unresolved []string
		keyIssue   bool
	}
	cases := []struct {
		name   string
		layers [][]testLayerEntry
		want   want
	}{
		{
			name: "link to a setuid file inherits the bit",
			layers: [][]testLayerEntry{{
				{name: "usr/bin/real", mode: 04755, data: []byte("x")},
				hardLink("usr/bin/alias", "usr/bin/real", 0755, 0),
			}},
			want: want{suid: []string{"/usr/bin/alias", "/usr/bin/real"}},
		},
		{
			name: "mode bits in the link header are not trusted",
			layers: [][]testLayerEntry{{
				{name: "usr/bin/real", mode: 0755, data: []byte("x")},
				hardLink("usr/bin/alias", "usr/bin/real", 04777, 0),
			}},
			want: want{},
		},
		{
			name: "link to a world-writable file inherits the mode",
			layers: [][]testLayerEntry{{
				{name: "opt/data", mode: 0666, data: []byte("x")},
				hardLink("opt/data-link", "opt/data", 0600, 0),
			}},
			want: want{worldWrite: []string{"/opt/data", "/opt/data-link"}},
		},
		{
			name: "link to a file owned by an unprivileged user inherits the owner",
			layers: [][]testLayerEntry{{
				{name: "usr/bin/tool", mode: 0755, uid: 10001, data: []byte("x")},
				hardLink("usr/bin/tool2", "usr/bin/tool", 0755, 0),
			}},
			want: want{nonRoot: []string{"/usr/bin/tool (UID 10001)", "/usr/bin/tool2 (UID 10001)"}},
		},
		{
			name: "owner in the link header is not trusted",
			layers: [][]testLayerEntry{{
				{name: "usr/bin/tool", mode: 0755, uid: 0, data: []byte("x")},
				hardLink("usr/bin/tool2", "usr/bin/tool", 0755, 10001),
			}},
			want: want{},
		},
		{
			name: "chain of links resolves to the final file",
			layers: [][]testLayerEntry{{
				{name: "usr/bin/real", mode: 04755, data: []byte("x")},
				hardLink("usr/bin/l1", "usr/bin/real", 0755, 0),
				hardLink("usr/bin/l2", "usr/bin/l1", 0755, 0),
			}},
			want: want{suid: []string{"/usr/bin/l1", "/usr/bin/l2", "/usr/bin/real"}},
		},
		{
			name: "link stored before its target still resolves",
			layers: [][]testLayerEntry{{
				hardLink("usr/bin/alias", "usr/bin/real", 0755, 0),
				{name: "usr/bin/real", mode: 04755, data: []byte("x")},
			}},
			want: want{suid: []string{"/usr/bin/alias", "/usr/bin/real"}},
		},
		{
			name: "link to a symbolic link is not a regular file",
			layers: [][]testLayerEntry{{
				{name: "usr/bin/sym", mode: 04755, typeflag: tar.TypeSymlink, linkname: "elsewhere"},
				hardLink("usr/bin/alias", "usr/bin/sym", 0755, 0),
			}},
			want: want{},
		},
		{
			name: "private key found through a link",
			layers: [][]testLayerEntry{{
				{name: "etc/ssl/server.key", mode: 0600, data: hardLinkKeyPEM},
				hardLink("etc/ssl/copy.key", "etc/ssl/server.key", 0600, 0),
			}},
			want: want{keys: []string{"/etc/ssl/copy.key", "/etc/ssl/server.key"}},
		},
		{
			name: "link named like a key to a certificate is clean",
			layers: [][]testLayerEntry{{
				{name: "etc/ssl/ca.crt", mode: 0644, data: hardLinkCertPEM},
				hardLink("etc/ssl/cert.pem", "etc/ssl/ca.crt", 0644, 0),
			}},
			want: want{},
		},
		{
			name: "link named like a key to a file that was not scanned is an evidence issue",
			layers: [][]testLayerEntry{{
				{name: "opt/blob", mode: 0600, data: hardLinkKeyPEM},
				hardLink("opt/secrets/app.key", "opt/blob", 0600, 0),
			}},
			want: want{keyIssue: true},
		},
		{
			name: "missing target is unresolved",
			layers: [][]testLayerEntry{{
				hardLink("usr/bin/orphan", "usr/bin/missing", 04755, 0),
			}},
			want: want{unresolved: []string{"/usr/bin/orphan"}},
		},
		{
			name: "cycle is unresolved",
			layers: [][]testLayerEntry{{
				hardLink("opt/a", "opt/b", 0644, 0),
				hardLink("opt/b", "opt/a", 0644, 0),
			}},
			want: want{unresolved: []string{"/opt/a", "/opt/b"}},
		},
		{
			name: "target in a lower layer is unresolved and not guessed",
			layers: [][]testLayerEntry{
				{{name: "usr/bin/real", mode: 04755, data: []byte("x")}},
				{hardLink("usr/bin/alias", "usr/bin/real", 04755, 0)},
			},
			want: want{suid: []string{"/usr/bin/real"}, unresolved: []string{"/usr/bin/alias"}},
		},
		{
			name: "replacement by a regular file in a later layer clears the unresolved link",
			layers: [][]testLayerEntry{
				{hardLink("usr/bin/orphan", "usr/bin/missing", 0755, 0)},
				{{name: "usr/bin/orphan", mode: 0755, data: []byte("x")}},
			},
			want: want{},
		},
		{
			name: "whiteout in a later layer clears the unresolved link",
			layers: [][]testLayerEntry{
				{hardLink("usr/bin/orphan", "usr/bin/missing", 0755, 0)},
				{{name: "usr/bin/.wh.orphan", mode: 0644}},
			},
			want: want{},
		},
		{
			name: "directory whiteout clears the unresolved links below it",
			layers: [][]testLayerEntry{
				{hardLink("opt/pkg/orphan", "opt/pkg/missing", 0755, 0)},
				{{name: "opt/.wh.pkg", mode: 0644}},
			},
			want: want{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			index, err := (&ImageReader{Image: makeTestImage(t, buildLayers(t, tc.layers)...)}).StreamAndIndexFilesystem()
			if err != nil {
				t.Fatalf("StreamAndIndexFilesystem: %v", err)
			}

			if got := index.GetSuidBinaries(); !sameStrings(got, tc.want.suid) {
				t.Errorf("SUID findings = %v, want %v", got, tc.want.suid)
			}
			if got := index.GetWorldWritableFiles(); !sameStrings(got, tc.want.worldWrite) {
				t.Errorf("world-writable findings = %v, want %v", got, tc.want.worldWrite)
			}
			if got := index.GetNonRootSystemBinaries(); !sameStrings(got, tc.want.nonRoot) {
				t.Errorf("non-root system binaries = %v, want %v", got, tc.want.nonRoot)
			}
			if got := index.GetPrivateKeyFiles(); !sameStrings(got, tc.want.keys) {
				t.Errorf("private-key findings = %v, want %v", got, tc.want.keys)
			}
			if got := index.UnresolvedHardLinks; !sameStrings(got, tc.want.unresolved) {
				t.Errorf("unresolved hard links = %v, want %v", got, tc.want.unresolved)
			}
			if gotIssue := index.PrivateKeyEvidenceIssue != ""; gotIssue != tc.want.keyIssue {
				t.Errorf("key evidence issue = %q, want an issue: %t", index.PrivateKeyEvidenceIssue, tc.want.keyIssue)
			}
			linkErr := index.HardLinkEvidence()
			if (linkErr != nil) != (len(tc.want.unresolved) > 0) {
				t.Errorf("HardLinkEvidence error = %v, want an error: %t", linkErr, len(tc.want.unresolved) > 0)
			}
		})
	}
}

func TestHardLinkEvidenceIsScopedByPathPrefix(t *testing.T) {
	index, err := (&ImageReader{Image: makeTestImage(t, buildLayers(t, [][]testLayerEntry{{
		hardLink("usr/bin/orphan", "usr/bin/missing", 0755, 0),
		hardLink("opt/data-link", "opt/missing", 0644, 0),
	}})...)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}

	all := index.HardLinkEvidence()
	if all == nil || !strings.Contains(all.Error(), "2 hard link(s)") {
		t.Fatalf("unscoped evidence = %v, want both links counted", all)
	}

	system := index.HardLinkEvidence("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/")
	if system == nil || !strings.Contains(system.Error(), "1 hard link(s)") || !strings.Contains(system.Error(), "/usr/bin/orphan") {
		t.Fatalf("system-directory evidence = %v, want only /usr/bin/orphan", system)
	}
	if strings.Contains(system.Error(), "/opt/data-link") {
		t.Errorf("system-directory evidence names a link outside its scope: %v", system)
	}

	if err := index.HardLinkEvidence("/sbin/"); err != nil {
		t.Errorf("evidence for a directory without unresolved links = %v, want nil", err)
	}
}

func TestUnresolvedLinkIssueNamesTheFirstLinksAndCountsTheRest(t *testing.T) {
	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	reasons := map[string]string{"/a": "reason a", "/b": "reason b", "/c": "reason c", "/d": "reason d", "/e": "reason e"}

	issue := unresolvedLinkIssue(paths, reasons)
	for _, want := range []string{"5 hard link(s)", "reason a", "reason b", "reason c", "and 2 more"} {
		if !strings.Contains(issue, want) {
			t.Errorf("issue %q does not contain %q", issue, want)
		}
	}
	for _, unwanted := range []string{"reason d", "reason e"} {
		if strings.Contains(issue, unwanted) {
			t.Errorf("issue %q names a link beyond the first three: %q", issue, unwanted)
		}
	}

	if issue := unresolvedLinkIssue([]string{"/x"}, nil); !strings.Contains(issue, "/x") {
		t.Errorf("issue without a recorded reason must still name the link: %q", issue)
	}
}
