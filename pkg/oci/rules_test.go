package oci

import (
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func addsOf(t *testing.T, history []v1.History) []string {
	t.Helper()
	index, err := (&ImageReader{Image: imageWithHistory(t, makeTestImage(t), history)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}
	adds, err := index.AddInstructionEvidence()
	if err != nil {
		t.Fatalf("AddInstructionEvidence: %v", err)
	}
	return adds
}

func TestSpec07ExemptsOnlyTheBaseImageRootfsImport(t *testing.T) {
	cases := []struct {
		name    string
		history []v1.History
		want    []string
	}{
		{
			name: "alpine BuildKit rootfs import",
			history: []v1.History{
				{CreatedBy: "ADD alpine-minirootfs-3.24.4-aarch64.tar.gz / # buildkit"},
				{CreatedBy: `CMD ["/bin/sh"]`, EmptyLayer: true},
			},
		},
		{
			name: "alpine legacy rootfs import",
			history: []v1.History{
				{CreatedBy: "/bin/sh -c #(nop) ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in / "},
				{CreatedBy: `/bin/sh -c #(nop)  CMD ["/bin/sh"]`, EmptyLayer: true},
			},
		},
		{
			name: "debian rootfs comes from debian.sh and has no ADD at all",
			history: []v1.History{
				{CreatedBy: "# debian.sh --arch 'amd64' out/ 'bookworm' '@1731196800'"},
				{CreatedBy: `CMD ["bash"]`, EmptyLayer: true},
			},
		},
		{
			name: "debian base then an author ADD in a later layer",
			history: []v1.History{
				{CreatedBy: "# debian.sh --arch 'amd64' out/ 'bookworm' '@1731196800'"},
				{CreatedBy: "ADD app.tar.gz /opt/app # buildkit"},
			},
			want: []string{"ADD app.tar.gz /opt/app # buildkit"},
		},
		{
			name: "scratch image importing rootfs.tar",
			history: []v1.History{
				{CreatedBy: "ADD rootfs.tar / "},
				{CreatedBy: `CMD ["/bin/sh"]`, EmptyLayer: true},
			},
		},
		{
			name:    "scratch image importing rootfs.tar with BuildKit marker",
			history: []v1.History{{CreatedBy: "ADD rootfs.tar.xz / # buildkit"}},
		},
		{
			name: "author ADD in a later layer after an alpine base",
			history: []v1.History{
				{CreatedBy: "ADD alpine-minirootfs-3.24.4-aarch64.tar.gz / # buildkit"},
				{CreatedBy: `CMD ["/bin/sh"]`, EmptyLayer: true},
				{CreatedBy: "ADD config.tar.gz /etc/app/ # buildkit"},
			},
			want: []string{"ADD config.tar.gz /etc/app/ # buildkit"},
		},
		{
			name: "a second rootfs-looking ADD is not a base import",
			history: []v1.History{
				{CreatedBy: "ADD alpine-minirootfs-3.24.4-aarch64.tar.gz / # buildkit"},
				{CreatedBy: "ADD rootfs.tar / # buildkit"},
			},
			want: []string{"ADD rootfs.tar / # buildkit"},
		},
		{
			name: "metadata-only entries before the first layer do not use up the exemption",
			history: []v1.History{
				{CreatedBy: "ARG VERSION=1", EmptyLayer: true},
				{CreatedBy: "LABEL maintainer=ops", EmptyLayer: true},
				{CreatedBy: "ADD rootfs.tar.gz / # buildkit"},
			},
		},
		{
			name: "ADD from a URL is never a base import, even first",
			history: []v1.History{
				{CreatedBy: "ADD https://example.com/rootfs.tar.gz / # buildkit"},
			},
			want: []string{"ADD https://example.com/rootfs.tar.gz / # buildkit"},
		},
		{
			name: "ADD to a path other than the root is not a base import",
			history: []v1.History{
				{CreatedBy: "ADD app.tar.gz /app/ # buildkit"},
				{CreatedBy: "ADD file:abc in /srv"},
			},
			want: []string{"ADD app.tar.gz /app/ # buildkit", "ADD file:abc in /srv"},
		},
		{
			name: "a first layer that is not an ADD does not exempt a later rootfs ADD",
			history: []v1.History{
				{CreatedBy: "/bin/sh -c apt-get update"},
				{CreatedBy: "ADD rootfs.tar / # buildkit"},
			},
			want: []string{"ADD rootfs.tar / # buildkit"},
		},
		{
			name: "a source with a directory component is not a bare archive name",
			history: []v1.History{
				{CreatedBy: "ADD ./vendor/rootfs.tar / # buildkit"},
			},
			want: []string{"ADD ./vendor/rootfs.tar / # buildkit"},
		},
		{
			name: "COPY is not an ADD",
			history: []v1.History{
				{CreatedBy: "ADD alpine-minirootfs-3.24.4-aarch64.tar.gz / # buildkit"},
				{CreatedBy: "COPY app /app # buildkit"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := addsOf(t, tc.history)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ADD findings = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSpec07UsesTheEmptyLayerFlagOfTheIndexedHistory(t *testing.T) {
	// The flag must travel from the image config through the index, so build
	// the same history as a plain index without flags and compare.
	history := []v1.History{
		{CreatedBy: "LABEL a=b", EmptyLayer: true},
		{CreatedBy: "ADD rootfs.tar / # buildkit"},
	}
	index, err := (&ImageReader{Image: imageWithHistory(t, makeTestImage(t), history)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.History) != 2 || !index.History[0].EmptyLayer || index.History[1].EmptyLayer {
		t.Fatalf("History = %+v, want the EmptyLayer flags preserved", index.History)
	}
	// Without the flags the LABEL entry would be the first layer and the
	// rootfs ADD would be flagged.
	flagless := &FilesystemIndex{HistoryEntries: []string{"LABEL a=b", "ADD rootfs.tar / # buildkit"}}
	if got := flagless.GetAddInstructions(); len(got) != 1 {
		t.Fatalf("flagless history ADD findings = %q, want the ADD flagged because LABEL counts as the first layer", got)
	}
}

func TestIsFixtureLikePathMatchesWholeComponentsOnly(t *testing.T) {
	cases := map[string]bool{
		"/usr/local/go/src/crypto/tls/testdata/example-key.pem":     true,
		"/usr/local/go/src/compress/flate/testdata/huffman-rand.in": true,
		"/app/tests/server.key":                                     true,
		"/app/Test/server.key":                                      true,
		"/srv/examples/client.key":                                  true,
		"/srv/example/client.key":                                   true,
		"/srv/fixtures/a.pem":                                       true,
		"/srv/fixture/a.pem":                                        true,
		"/etc/ssl/private/ssl-cert-snakeoil.key":                    true,
		"/etc/ssl/certs/ssl-cert-snakeoil.pem":                      true,
		"/etc/ssl/private/ssl-cert-snakeoil.key.bak":                true,
		// The Go source tree key has no fixture-like component. It stays a
		// finding and is a documented limit of the path-based classification.
		"/usr/local/go/src/crypto/x509/platform_root_key.pem": false,
		"/app/contest/server.key":                             false,
		"/app/latest/server.key":                              false,
		"/opt/attestation/server.key":                         false,
		"/srv/example.com/server.key":                         false,
		"/srv/mytestdata/server.key":                          false,
		"/etc/ssl/private/ssl-cert-snakeoil-extra.key":        false,
		"/etc/ssl/private/server.key":                         false,
	}
	for p, want := range cases {
		if got := IsFixtureLikePath(p); got != want {
			t.Errorf("IsFixtureLikePath(%q) = %t, want %t", p, got, want)
		}
	}
}

func TestHarnessMatchingUsesComponentsAndExactBasenames(t *testing.T) {
	cases := []struct {
		path     string
		reported string
		matched  bool
	}{
		{"/app/tests/phpunit/TestCase.php", "/app/tests/phpunit", true},
		{"/app/tests/assets/logo.png", "/app/tests/assets", true},
		{"/usr/local/go/src/compress/flate/testdata/huffman-rand-max.in", "/usr/local/go/src/compress/flate/testdata", true},
		{"/usr/local/go/src/testdata/a/testdata/b", "/usr/local/go/src/testdata", true},
		{"/var/www/phpunit.xml", "/var/www/phpunit.xml", true},
		{"/var/www/phpunit.xml.dist", "/var/www/phpunit.xml.dist", true},
		{"/app/jest.config.js", "/app/jest.config.js", true},
		{"/app/pytest.ini", "/app/pytest.ini", true},
		{"/app/mytestdata/file", "", false},
		{"/app/contest/phpunit/file", "", false},
		{"/app/tests/other/file", "", false},
		{"/app/jest.config.json", "", false},
		{"/app/pytest.ini.bak", "", false},
		{"/app/old-phpunit.xml", "", false},
	}
	for _, tc := range cases {
		reported, matched := harnessMatch(tc.path)
		if matched != tc.matched || reported != tc.reported {
			t.Errorf("harnessMatch(%q) = %q, %t; want %q, %t", tc.path, reported, matched, tc.reported, tc.matched)
		}
	}
}

func TestGolangFalsePositivesAreClassifiedAsFixtureCandidates(t *testing.T) {
	privateKey := []byte("-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n")
	layer := makeTestLayer(t,
		testLayerEntry{name: "usr/local/go/src/crypto/tls/testdata/example-key.pem", mode: 0o644, data: privateKey},
		testLayerEntry{name: "usr/local/go/src/crypto/x509/platform_root_key.pem", mode: 0o644, data: privateKey},
		testLayerEntry{name: "usr/local/go/src/compress/flate/testdata/huffman-rand-max.in", mode: 0o644, data: []byte("data")},
		testLayerEntry{name: "usr/local/go/src/compress/flate/testdata/huffman-rand-1k.in", mode: 0o644, data: []byte("data")},
		testLayerEntry{name: "etc/ssl/private/ssl-cert-snakeoil.key", mode: 0o640, data: privateKey},
	)
	index, err := (&ImageReader{Image: makeTestImage(t, layer)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatalf("StreamAndIndexFilesystem: %v", err)
	}

	keys := index.ScanPrivateKeys()
	wantFindings := []string{"/usr/local/go/src/crypto/x509/platform_root_key.pem"}
	wantFixtures := []string{"/etc/ssl/private/ssl-cert-snakeoil.key", "/usr/local/go/src/crypto/tls/testdata/example-key.pem"}
	if !reflect.DeepEqual(keys.Findings, wantFindings) || !reflect.DeepEqual(keys.FixtureCandidates, wantFixtures) {
		t.Errorf("private-key scan = findings %v fixtures %v, want findings %v fixtures %v", keys.Findings, keys.FixtureCandidates, wantFindings, wantFixtures)
	}

	harness := index.ScanTestHarness()
	if len(harness.Findings) != 0 || !reflect.DeepEqual(harness.FixtureCandidates, []string{
		"/usr/local/go/src/compress/flate/testdata",
		"/usr/local/go/src/crypto/tls/testdata",
	}) {
		t.Errorf("test-harness scan = %+v, want only the two testdata directories as fixture candidates, each listed once", harness)
	}
}

func TestPrivateKeyEvidenceIssuesAreScopedByLocation(t *testing.T) {
	unsupported := []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n")
	layer := makeTestLayer(t,
		testLayerEntry{name: "app/testdata/odd.pem", mode: 0o644, data: unsupported},
		testLayerEntry{name: "app/config/odd.pem", mode: 0o644, data: unsupported},
	)
	index, err := (&ImageReader{Image: makeTestImage(t, layer)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatal(err)
	}
	scan := index.ScanPrivateKeys()
	if len(scan.Issues) != 1 {
		t.Fatalf("issues = %v, want only the issue outside the testdata fixture location", scan.Issues)
	}
	if index.PrivateKeyEvidenceIssue == "" || len(index.PrivateKeyIssues) != 2 {
		t.Errorf("the aggregate issue and the per-path map must both be kept: %q %v", index.PrivateKeyEvidenceIssue, index.PrivateKeyIssues)
	}
}

func TestIndexGettersAreSorted(t *testing.T) {
	layer := makeTestLayer(t,
		testLayerEntry{name: "usr/bin/zz", mode: 0o4755, data: []byte("x")},
		testLayerEntry{name: "usr/bin/aa", mode: 0o4755, data: []byte("x")},
		testLayerEntry{name: "var/zz", mode: 0o666, data: []byte("x")},
		testLayerEntry{name: "var/aa", mode: 0o666, data: []byte("x")},
	)
	index, err := (&ImageReader{Image: makeTestImage(t, layer)}).StreamAndIndexFilesystem()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if got := index.GetSuidBinaries(); !reflect.DeepEqual(got, []string{"/usr/bin/aa", "/usr/bin/zz"}) {
			t.Fatalf("GetSuidBinaries = %v", got)
		}
		if got := index.GetWorldWritableFiles(); !reflect.DeepEqual(got, []string{"/var/aa", "/var/zz"}) {
			t.Fatalf("GetWorldWritableFiles = %v", got)
		}
	}
}
