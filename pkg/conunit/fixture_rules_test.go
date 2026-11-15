package conunit_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

func TestFS06OutcomeDependsOnlyOnNonFixtureFindings(t *testing.T) {
	t.Run("fixture candidates alone pass and are counted", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{PrivateKeyFiles: map[string]string{
			"/usr/local/go/src/crypto/tls/testdata/example-key.pem": "k",
			"/etc/ssl/private/ssl-cert-snakeoil.key":                "k",
		}}}
		c.AssertFilesystem().NoPrivateKeysOrCertificates()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomePass {
			t.Fatalf("result = %+v, want PASS when only fixture candidates exist", r)
		}
		if !strings.Contains(r.Message, "2 fixture candidate(s)") {
			t.Errorf("the message must state the number of fixture candidates: %q", r.Message)
		}
		want := []string{"/etc/ssl/private/ssl-cert-snakeoil.key", "/usr/local/go/src/crypto/tls/testdata/example-key.pem"}
		if r.Evidence == nil || len(r.Evidence.Paths) != 0 || !reflect.DeepEqual(r.Evidence.FixtureCandidates, want) {
			t.Errorf("evidence = %+v, want sorted fixture_candidate_paths %v and no paths", r.Evidence, want)
		}
	})

	t.Run("a finding outside fixture locations fails and lists both groups sorted", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{PrivateKeyFiles: map[string]string{
			"/opt/zeta/server.key":                        "k",
			"/opt/alpha/server.key":                       "k",
			"/app/testdata/example-key.pem":               "k",
			"/etc/ssl/private/ssl-cert-snakeoil.key":      "k",
			"/app/contest/not-a-fixture-despite-test.key": "k",
		}}}
		c.AssertFilesystem().NoPrivateKeysOrCertificates()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeFail {
			t.Fatalf("result = %+v, want FAIL", r)
		}
		wantPaths := []string{"/app/contest/not-a-fixture-despite-test.key", "/opt/alpha/server.key", "/opt/zeta/server.key"}
		wantFixtures := []string{"/app/testdata/example-key.pem", "/etc/ssl/private/ssl-cert-snakeoil.key"}
		if !reflect.DeepEqual(r.Evidence.Paths, wantPaths) || !reflect.DeepEqual(r.Evidence.FixtureCandidates, wantFixtures) {
			t.Errorf("evidence = %+v, want paths %v and fixture candidates %v", r.Evidence, wantPaths, wantFixtures)
		}
	})

	t.Run("evidence problems under fixture locations do not make the check unverified", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{
			PrivateKeyIssues:        map[string]string{"/app/testdata/odd.pem": "unsupported encoding"},
			PrivateKeyEvidenceIssue: "unsupported encoding",
		}}
		c.AssertFilesystem().NoPrivateKeysOrCertificates()
		if r := onlyResult(t, c); r.EffectiveOutcome() != spec.OutcomePass {
			t.Fatalf("result = %+v, want PASS", r)
		}
	})

	t.Run("evidence problems outside fixture locations are EVIDENCE_INCOMPLETE", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{
			PrivateKeyIssues:        map[string]string{"/app/config/odd.pem": "exceeds the scan limit"},
			PrivateKeyEvidenceIssue: "exceeds the scan limit",
		}}
		c.AssertFilesystem().NoPrivateKeysOrCertificates()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeUnverified || r.Reason != spec.ReasonEvidenceIncomplete {
			t.Fatalf("result = %+v, want UNVERIFIED/EVIDENCE_INCOMPLETE", r)
		}
	})
}

func TestFS07OutcomeDependsOnlyOnNonFixtureFindings(t *testing.T) {
	c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: map[string]bool{
		"/usr/local/go/src/compress/flate/testdata/huffman-rand-max.in": true,
		"/usr/local/go/src/compress/flate/testdata/huffman-rand-1k.in":  true,
		"/app/tests/phpunit/TestCase.php":                               true,
	}}}
	c.AssertFilesystem().NoTestHarnessLeakage()
	r := onlyResult(t, c)
	if r.EffectiveOutcome() != spec.OutcomePass {
		t.Fatalf("result = %+v, want PASS: test data and test directories are fixture candidates", r)
	}
	want := []string{"/app/tests/phpunit", "/usr/local/go/src/compress/flate/testdata"}
	if !reflect.DeepEqual(r.Evidence.FixtureCandidates, want) || !strings.Contains(r.Message, "2 fixture candidate path(s)") {
		t.Errorf("fixture candidates = %v (message %q), want %v", r.Evidence.FixtureCandidates, r.Message, want)
	}

	failing := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: map[string]bool{
		"/var/www/phpunit.xml": true, "/srv/jest.config.js": true, "/app/tests/phpunit/TestCase.php": true,
	}}}
	failing.AssertFilesystem().NoTestHarnessLeakage()
	f := onlyResult(t, failing)
	if f.EffectiveOutcome() != spec.OutcomeFail || !reflect.DeepEqual(f.Evidence.Paths, []string{"/srv/jest.config.js", "/var/www/phpunit.xml"}) {
		t.Fatalf("result = %+v, want FAIL listing the two configuration files sorted", f)
	}
}

func TestSpec07Assertion(t *testing.T) {
	index := func(history ...oci.HistoryEntry) *oci.FilesystemIndex { return &oci.FilesystemIndex{History: history} }
	t.Run("alpine base rootfs import passes", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: index(
			oci.HistoryEntry{CreatedBy: "ADD alpine-minirootfs-3.24.4-aarch64.tar.gz / # buildkit"},
			oci.HistoryEntry{CreatedBy: `CMD ["/bin/sh"]`, EmptyLayer: true},
		)}
		c.AssertSpec().RequireCopyOverAdd()
		if r := onlyResult(t, c); r.EffectiveOutcome() != spec.OutcomePass {
			t.Fatalf("result = %+v, want PASS: the base rootfs import is exempt", r)
		}
	})
	t.Run("an author ADD fails", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: index(
			oci.HistoryEntry{CreatedBy: "ADD alpine-minirootfs-3.24.4-aarch64.tar.gz / # buildkit"},
			oci.HistoryEntry{CreatedBy: "ADD https://example.com/tool.tar.gz /opt/ # buildkit"},
		)}
		c.AssertSpec().RequireCopyOverAdd()
		r := onlyResult(t, c)
		if r.EffectiveOutcome() != spec.OutcomeFail || !strings.Contains(r.Message, "https://example.com/tool.tar.gz") || strings.Contains(r.Message, "alpine-minirootfs") {
			t.Fatalf("result = %+v", r)
		}
	})
}

// A rule has one stable name regardless of its outcome, so reports and
// exporters can key on it.
func TestRuleNamesAreStablePerIDAcrossOutcomes(t *testing.T) {
	names := map[string]map[string]bool{}
	collect := func(c *conunit.Container) {
		for _, r := range c.Results {
			if names[r.TestID] == nil {
				names[r.TestID] = map[string]bool{}
			}
			names[r.TestID][r.TestName] = true
		}
	}
	passAdd := &conunit.Container{OCIIndex: &oci.FilesystemIndex{History: []oci.HistoryEntry{{CreatedBy: "ADD rootfs.tar / # buildkit"}}}}
	failAdd := &conunit.Container{OCIIndex: &oci.FilesystemIndex{HistoryEntries: []string{"RUN true", "ADD x /y"}}}
	noHistory := &conunit.Container{OCIIndex: &oci.FilesystemIndex{HistoryEvidenceIssue: "no history"}}
	noIndex := &conunit.Container{}
	for _, c := range []*conunit.Container{passAdd, failAdd, noHistory, noIndex} {
		c.AssertSpec().RequireCopyOverAdd()
		collect(c)
	}

	passKey := &conunit.Container{OCIIndex: &oci.FilesystemIndex{}}
	failKey := &conunit.Container{OCIIndex: &oci.FilesystemIndex{PrivateKeyFiles: map[string]string{"/a/server.key": "k"}}}
	issueKey := &conunit.Container{OCIIndex: &oci.FilesystemIndex{PrivateKeyEvidenceIssue: "limit"}}
	for _, c := range []*conunit.Container{passKey, failKey, issueKey, noIndex} {
		c.AssertFilesystem().NoPrivateKeysOrCertificates()
		collect(c)
	}

	passAcct := &conunit.Container{OCIIndex: &oci.FilesystemIndex{}}
	failAcct := &conunit.Container{OCIIndex: &oci.FilesystemIndex{EmptyPasswordAccounts: []string{"root"}}}
	issueAcct := &conunit.Container{OCIIndex: &oci.FilesystemIndex{AccountEvidenceIssue: "shadow missing"}}
	for _, c := range []*conunit.Container{passAcct, failAcct, issueAcct, noIndex} {
		c.AssertFilesystem().NoEmptyPasswordAccounts()
		collect(c)
	}

	for _, id := range []string{"SPEC-07", "FS-06", "FS-08"} {
		if len(names[id]) != 1 {
			t.Errorf("%s emitted %d distinct test names %v, want exactly one", id, len(names[id]), names[id])
		}
	}
}
