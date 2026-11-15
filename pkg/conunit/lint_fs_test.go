package conunit_test

import (
	"archive/tar"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

// treeContainer indexes the layers like the runner does and returns the
// container, so the file checks see whiteouts, replacements and links as they
// are resolved in a real run.
func treeContainer(t *testing.T, layers ...[]layerFile) *conunit.Container {
	t.Helper()
	return imageSpec{layers: layers}.container(t)
}

func linkEntry(name, target string) layerFile {
	return layerFile{name: name, mode: 0o644, typeflag: tar.TypeLink, linkname: target}
}

func symlinkEntry(name, target string) layerFile {
	return layerFile{name: name, mode: 0o777, typeflag: tar.TypeSymlink, linkname: target}
}

func expectOutcome(t *testing.T, c *conunit.Container, id string, want spec.Outcome) spec.TestResult {
	t.Helper()
	r := onlyResult(t, c)
	if r.TestID != id || r.EffectiveOutcome() != want {
		t.Fatalf("result = %s %s (%s), want %s %s", r.TestID, r.EffectiveOutcome(), r.Message, id, want)
	}
	if want == spec.OutcomeUnverified && r.Reason != spec.ReasonEvidenceIncomplete {
		t.Errorf("reason = %q, want EVIDENCE_INCOMPLETE", r.Reason)
	}
	if want != spec.OutcomeUnverified && r.Reason != spec.ReasonNone {
		t.Errorf("reason = %q, want none for %s", r.Reason, want)
	}
	if r.Tier != spec.TierFilesystem || r.Rule == nil {
		t.Errorf("tier = %v, rule = %v, want Tier 2 with a rule mapping", r.Tier, r.Rule)
	}
	return r
}

func TestFS10UniqueAccountAndGroupIDs(t *testing.T) {
	passwd := func(lines ...string) layerFile { return fileEntry("etc/passwd", strings.Join(lines, "\n")+"\n") }
	group := func(lines ...string) layerFile { return fileEntry("etc/group", strings.Join(lines, "\n")+"\n") }
	root, app := "root:x:0:0:root:/root:/bin/sh", "app:x:10001:10001:app:/app:/sbin/nologin"
	groupRoot, groupApp := "root:x:0:", "app:x:10001:"

	cases := []struct {
		name      string
		layers    [][]layerFile
		want      spec.Outcome
		wantPaths []string
	}{
		{"unique IDs", [][]layerFile{{passwd(root, app), group(groupRoot, groupApp)}}, spec.OutcomePass, nil},
		{"two names share UID 0", [][]layerFile{{passwd(root, "toor:x:0:0:toor:/root:/bin/sh", app), group(groupRoot, groupApp)}}, spec.OutcomeFail,
			[]string{"/etc/passwd: UID 0 is shared by root, toor"}},
		{"two groups share a GID", [][]layerFile{{passwd(root), group(groupRoot, "staff:x:50:", "wheel:x:50:")}}, spec.OutcomeFail,
			[]string{"/etc/group: GID 50 is shared by staff, wheel"}},
		{"both files collide, accounts listed first", [][]layerFile{{passwd(root, "b:x:7:7::/:/bin/sh", "a:x:7:7::/:/bin/sh"), group(groupRoot, "x:x:9:", "y:x:9:")}}, spec.OutcomeFail,
			[]string{"/etc/passwd: UID 7 is shared by a, b", "/etc/group: GID 9 is shared by x, y"}},
		{"three names share one ID", [][]layerFile{{passwd(root, "a:x:5:5::/:/bin/sh", "b:x:5:5::/:/bin/sh", "c:x:5:5::/:/bin/sh"), group(groupRoot)}}, spec.OutcomeFail,
			[]string{"/etc/passwd: UID 5 is shared by a, b, c"}},
		{"one name listed twice with the same UID is one account", [][]layerFile{{passwd(root, app, app), group(groupRoot, groupApp)}}, spec.OutcomePass, nil},
		{"one name listed twice with different UIDs is no collision", [][]layerFile{{passwd(root, "app:x:1:1::/:/bin/sh", "app:x:2:2::/:/bin/sh"), group(groupRoot)}}, spec.OutcomePass, nil},
		{"a user and a group may share a number", [][]layerFile{{passwd(root, app), group(groupRoot, "other:x:10001:")}}, spec.OutcomePass, nil},
		{"comments and blank lines are skipped", [][]layerFile{{fileEntry("etc/passwd", "# header\n\n"+root+"\n"), fileEntry("etc/group", "# header\n"+groupRoot+"\n")}}, spec.OutcomePass, nil},

		{"/etc/group is missing", [][]layerFile{{passwd(root, app)}}, spec.OutcomeUnverified, nil},
		{"/etc/passwd is missing", [][]layerFile{{group(groupRoot, groupApp)}}, spec.OutcomeUnverified, nil},
		{"both files are missing", [][]layerFile{{fileEntry("etc/hosts", "x")}}, spec.OutcomeUnverified, nil},
		{"a whiteout removes /etc/group", [][]layerFile{{passwd(root, app), group(groupRoot, groupApp)}, {whiteoutEntry("etc", "group")}}, spec.OutcomeUnverified, nil},
		{"a replacement removes the collision", [][]layerFile{
			{passwd(root, app), group(groupRoot, "a:x:9:", "b:x:9:")},
			{group(groupRoot, "a:x:9:", "b:x:10:")}}, spec.OutcomePass, nil},
		{"a replacement adds a collision", [][]layerFile{
			{passwd(root, app), group(groupRoot, groupApp)},
			{passwd(root, "toor:x:0:0::/:/bin/sh")}}, spec.OutcomeFail, []string{"/etc/passwd: UID 0 is shared by root, toor"}},
		{"a whiteout under a replacement keeps the replacement", [][]layerFile{
			{passwd(root, app), group(groupRoot, groupApp)},
			{whiteoutEntry("etc", "group"), group(groupRoot, groupApp)}}, spec.OutcomePass, nil},
		{"a hard link has no content of its own", [][]layerFile{{passwd(root, app), fileEntry("usr/share/group.master", groupRoot+"\n"), linkEntry("etc/group", "usr/share/group.master")}}, spec.OutcomeUnverified, nil},
		{"a symbolic link has no content of its own", [][]layerFile{{passwd(root, app), symlinkEntry("etc/group", "/usr/etc/group")}}, spec.OutcomeUnverified, nil},
		{"a malformed group record", [][]layerFile{{passwd(root, app), group(groupRoot, "not-a-record")}}, spec.OutcomeUnverified, nil},
		{"a malformed passwd record", [][]layerFile{{passwd(root, "broken"), group(groupRoot)}}, spec.OutcomeUnverified, nil},
		{"an empty group file", [][]layerFile{{passwd(root, app), fileEntry("etc/group", "")}}, spec.OutcomeUnverified, nil},
		{"an oversized group file", [][]layerFile{{passwd(root, app), fileEntry("etc/group", strings.Repeat("a", oci.MaxAccountFileBytes+1))}}, spec.OutcomeUnverified, nil},
		{"a collision found before a malformed record still fails", [][]layerFile{{passwd(root, app), group("a:x:9:", "b:x:9:", "not-a-record")}}, spec.OutcomeFail,
			[]string{"/etc/group: GID 9 is shared by a, b"}},
		{"a collision stands next to a missing group file", [][]layerFile{{passwd(root, "toor:x:0:0::/:/bin/sh")}}, spec.OutcomeFail, []string{"/etc/passwd: UID 0 is shared by root, toor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := treeContainer(t, tc.layers...)
			c.AssertFilesystem().UniqueAccountAndGroupIDs()
			r := expectOutcome(t, c, "FS-10", tc.want)
			if tc.want == spec.OutcomeFail && (r.Evidence == nil || !reflect.DeepEqual(r.Evidence.Paths, tc.wantPaths)) {
				t.Errorf("evidence = %+v, want paths %q", r.Evidence, tc.wantPaths)
			}
		})
	}

	t.Run("no index", func(t *testing.T) {
		c := &conunit.Container{}
		c.AssertFilesystem().UniqueAccountAndGroupIDs()
		expectOutcome(t, c, "FS-10", spec.OutcomeUnverified)
	})
	t.Run("an index without any account data is not an empty pass", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: map[string]bool{"/app": true}}}
		c.AssertFilesystem().UniqueAccountAndGroupIDs()
		expectOutcome(t, c, "FS-10", spec.OutcomeUnverified)
	})
}

func TestFS11NoDevelopmentEditorCacheOrCloudLeftovers(t *testing.T) {
	cases := []struct {
		name      string
		layers    [][]layerFile
		want      spec.Outcome
		wantPaths []string
	}{
		{"a clean tree", [][]layerFile{{fileEntry("app/main", "x"), fileEntry("etc/hosts", "x")}}, spec.OutcomePass, nil},

		// Each directory name of the list.
		{".git", [][]layerFile{{fileEntry("app/.git/config", "x")}}, spec.OutcomeFail, []string{"/app/.git"}},
		{".cache", [][]layerFile{{fileEntry("root/.cache/pip/http/x", "x")}}, spec.OutcomeFail, []string{"/root/.cache"}},
		{".aws", [][]layerFile{{fileEntry("root/.aws/config", "x")}}, spec.OutcomeFail, []string{"/root/.aws"}},
		{".azure", [][]layerFile{{fileEntry("root/.azure/x", "x")}}, spec.OutcomeFail, []string{"/root/.azure"}},
		{".gcp", [][]layerFile{{fileEntry("root/.gcp/x", "x")}}, spec.OutcomeFail, []string{"/root/.gcp"}},
		{".vscode", [][]layerFile{{fileEntry("app/.vscode/settings.json", "x")}}, spec.OutcomeFail, []string{"/app/.vscode"}},
		{".idea", [][]layerFile{{fileEntry("app/.idea/workspace.xml", "x")}}, spec.OutcomeFail, []string{"/app/.idea"}},
		{".npm", [][]layerFile{{fileEntry("root/.npm/_cacache/x", "x")}}, spec.OutcomeFail, []string{"/root/.npm"}},
		{"an empty .git directory is reported here and not by Dockle", [][]layerFile{{dirEntry("app/.git/")}}, spec.OutcomeFail, []string{"/app/.git"}},
		{"a file named .git counts as a component", [][]layerFile{{fileEntry("app/sub/.git", "gitdir: ../.git/modules/sub")}}, spec.OutcomeFail, []string{"/app/sub/.git"}},

		// Each file name of the list.
		{"Dockerfile", [][]layerFile{{fileEntry("app/Dockerfile", "x")}}, spec.OutcomeFail, []string{"/app/Dockerfile"}},
		{"Dockerfile at the root", [][]layerFile{{fileEntry("Dockerfile", "x")}}, spec.OutcomeFail, []string{"/Dockerfile"}},
		{"docker-compose.yml", [][]layerFile{{fileEntry("srv/docker-compose.yml", "x")}}, spec.OutcomeFail, []string{"/srv/docker-compose.yml"}},
		{".vimrc", [][]layerFile{{fileEntry("root/.vimrc", "x")}}, spec.OutcomeFail, []string{"/root/.vimrc"}},
		{".DS_Store", [][]layerFile{{fileEntry("app/static/.DS_Store", "x")}}, spec.OutcomeFail, []string{"/app/static/.DS_Store"}},

		// Near misses.
		{"a directory named Dockerfile is no stray file", [][]layerFile{{dirEntry("app/Dockerfile/"), fileEntry("app/Dockerfile/readme", "x")}}, spec.OutcomePass, nil},
		{"Dockerfile.dev is another name", [][]layerFile{{fileEntry("app/Dockerfile.dev", "x")}}, spec.OutcomePass, nil},
		{"names are case sensitive", [][]layerFile{{fileEntry("app/dockerfile", "x"), fileEntry("app/.GIT/x", "x"), fileEntry("app/Docker-Compose.yml", "x")}}, spec.OutcomePass, nil},
		{"similar names", [][]layerFile{{fileEntry("app/.gitignore", "x"), fileEntry("app/.github/workflows/ci.yml", "x"), fileEntry("app/.gitlab-ci.yml", "x"), fileEntry("app/.cached/x", "x"), fileEntry("app/.git-credentials", "x")}}, spec.OutcomePass, nil},
		{"the name is a substring of a component", [][]layerFile{{fileEntry("app/my.git/x", "x"), fileEntry("app/dot.cache/x", "x")}}, spec.OutcomePass, nil},

		// node_modules and vendor trees are skipped.
		{"a .git below node_modules", [][]layerFile{{fileEntry("app/node_modules/foo/.git/config", "x")}}, spec.OutcomePass, nil},
		{"a Dockerfile below node_modules", [][]layerFile{{fileEntry("app/node_modules/foo/Dockerfile", "x")}}, spec.OutcomePass, nil},
		{"the .cache directory of node_modules", [][]layerFile{{fileEntry("app/node_modules/.cache/babel/x", "x")}}, spec.OutcomePass, nil},
		{"a .cache below vendor", [][]layerFile{{fileEntry("app/vendor/x/.cache/y", "x")}}, spec.OutcomePass, nil},
		{"the skip compares whole components", [][]layerFile{{fileEntry("app/my_node_modules/.git/config", "x")}}, spec.OutcomeFail, []string{"/app/my_node_modules/.git"}},
		{"a leftover above a node_modules tree is still reported", [][]layerFile{{fileEntry("app/.npm/node_modules/x/.git/config", "x")}}, spec.OutcomeFail, []string{"/app/.npm"}},
		{"a leftover next to a node_modules tree is still reported", [][]layerFile{{fileEntry("app/node_modules/x/y", "x"), fileEntry("app/.git/config", "x")}}, spec.OutcomeFail, []string{"/app/.git"}},

		// One finding per directory.
		{"many files below one directory", [][]layerFile{{fileEntry("app/.git/config", "x"), fileEntry("app/.git/HEAD", "x"), fileEntry("app/.git/hooks/pre-commit", "x")}}, spec.OutcomeFail, []string{"/app/.git"}},
		{"nested leftovers are reported at the shallowest directory", [][]layerFile{{fileEntry("app/.git/modules/sub/.git/config", "x"), fileEntry("app/.git/.cache/x", "x")}}, spec.OutcomeFail, []string{"/app/.git"}},
		{"files below a reported directory are not listed again", [][]layerFile{{fileEntry("app/.git/Dockerfile", "x"), fileEntry("app/.git/.DS_Store", "x")}}, spec.OutcomeFail, []string{"/app/.git"}},
		{"two directories, one finding each, sorted", [][]layerFile{{fileEntry("srv/.git/x", "x"), fileEntry("app/.git/y", "x"), fileEntry("app/Dockerfile", "x")}}, spec.OutcomeFail,
			[]string{"/app/.git", "/app/Dockerfile", "/srv/.git"}},

		// Whiteouts, replaced entries and links.
		{"a whiteout removes the directory", [][]layerFile{{fileEntry("app/.git/config", "x"), fileEntry("app/main", "x")}, {whiteoutEntry("app", ".git")}}, spec.OutcomePass, nil},
		{"a whiteout removes the file", [][]layerFile{{fileEntry("app/Dockerfile", "x"), fileEntry("app/main", "x")}, {whiteoutEntry("app", "Dockerfile")}}, spec.OutcomePass, nil},
		{"an opaque whiteout removes the lower content", [][]layerFile{{fileEntry("app/.git/config", "x")}, {{name: "app/.wh..wh..opq", mode: 0o644}, fileEntry("app/main", "x")}}, spec.OutcomePass, nil},
		{"a file replaced by a directory is no stray file any more", [][]layerFile{{fileEntry("app/Dockerfile", "x")}, {dirEntry("app/Dockerfile/")}}, spec.OutcomePass, nil},
		{"a directory replaced by a file is a stray file", [][]layerFile{{dirEntry("app/Dockerfile/")}, {fileEntry("app/Dockerfile", "x")}}, spec.OutcomeFail, []string{"/app/Dockerfile"}},
		{"a replacement in an upper layer keeps the finding", [][]layerFile{{fileEntry("app/Dockerfile", "old")}, {fileEntry("app/Dockerfile", "new")}}, spec.OutcomeFail, []string{"/app/Dockerfile"}},
		{"a whiteout and a re-added file in one layer", [][]layerFile{{fileEntry("app/Dockerfile", "x")}, {whiteoutEntry("app", "Dockerfile"), fileEntry("app/Dockerfile", "y")}}, spec.OutcomeFail, []string{"/app/Dockerfile"}},
		{"a hard link named Dockerfile counts under its own name", [][]layerFile{{fileEntry("app/base", "x"), linkEntry("app/Dockerfile", "app/base")}}, spec.OutcomeFail, []string{"/app/Dockerfile"}},
		{"a hard link without a target in the layer still counts", [][]layerFile{{linkEntry("app/Dockerfile", "lower/layer/file")}}, spec.OutcomeFail, []string{"/app/Dockerfile"}},
		{"a symbolic link named .vimrc counts", [][]layerFile{{symlinkEntry("root/.vimrc", "/etc/vimrc")}}, spec.OutcomeFail, []string{"/root/.vimrc"}},

		// Evidence that cannot carry a verdict.
		{"an image without entries", nil, spec.OutcomeUnverified, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := treeContainer(t, tc.layers...)
			c.AssertFilesystem().NoDevelopmentLeftovers()
			r := expectOutcome(t, c, "FS-11", tc.want)
			if tc.want == spec.OutcomeFail && (r.Evidence == nil || !reflect.DeepEqual(r.Evidence.Paths, tc.wantPaths)) {
				t.Errorf("evidence = %+v, want paths %q", r.Evidence, tc.wantPaths)
			}
		})
	}

	t.Run("an index built without a directory set treats every entry as a file", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: map[string]bool{"/app": true, "/app/Dockerfile": true}}}
		c.AssertFilesystem().NoDevelopmentLeftovers()
		expectOutcome(t, c, "FS-11", spec.OutcomeFail)
	})
	t.Run("no index", func(t *testing.T) {
		c := &conunit.Container{}
		c.AssertFilesystem().NoDevelopmentLeftovers()
		expectOutcome(t, c, "FS-11", spec.OutcomeUnverified)
	})
	t.Run("the evidence is capped and the message states the full count", func(t *testing.T) {
		paths := map[string]bool{"/app": true}
		for i := 0; i < 250; i++ {
			paths[fmt.Sprintf("/srv/site%03d/.git/config", i)] = true
		}
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: paths}}
		c.AssertFilesystem().NoDevelopmentLeftovers()
		r := expectOutcome(t, c, "FS-11", spec.OutcomeFail)
		if len(r.Evidence.Paths) != 200 || !strings.Contains(r.Message, "250 development") || !strings.Contains(r.Message, "and 240 more") {
			t.Errorf("evidence has %d paths, message %q, want 200 in the evidence and the full count in the message", len(r.Evidence.Paths), r.Message)
		}
		if r.Evidence.Paths[0] != "/srv/site000/.git" || r.Evidence.Paths[199] != "/srv/site199/.git" {
			t.Errorf("the evidence must hold the first 200 sorted paths, got %q ... %q", r.Evidence.Paths[0], r.Evidence.Paths[199])
		}
	})
}

// The contract lists, spelled out once more here so that a change of the code
// lists needs a change of the contract text too.
var (
	contractCredentialNames = []string{"credentials.json", "credential.json", "credentials", "credential", "password.txt", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "secret_token.rb", "carrierwave.rb", "omniauth.rb", "settings.py", "database.yml", "credentials.xml", ".env"}
	contractCredentialExts  = []string{".secret", ".ovpn", ".private_key", ".cscfg", ".rdp", ".mdf", ".sdf", ".bek", ".tpm", ".fve", ".jks", ".psafe3", ".agilekeychain", ".keychain", ".pcap", ".gnucache"}
)

func TestFS12NoCredentialNamedFiles(t *testing.T) {
	pass := func(name string, layers ...[]layerFile) struct {
		name   string
		layers [][]layerFile
		want   spec.Outcome
		paths  []string
		fixes  []string
	} {
		return struct {
			name   string
			layers [][]layerFile
			want   spec.Outcome
			paths  []string
			fixes  []string
		}{name, layers, spec.OutcomePass, nil, nil}
	}
	type fs12Case = struct {
		name   string
		layers [][]layerFile
		want   spec.Outcome
		paths  []string
		fixes  []string
	}
	cases := []fs12Case{
		pass("a clean tree", []layerFile{fileEntry("app/main", "x"), fileEntry("etc/hosts", "x")}),

		// Near misses that must pass.
		pass("a longer name", []layerFile{fileEntry("app/my_credentials.json", "x"), fileEntry("app/credentials.json.example", "x"), fileEntry("app/credentials2", "x")}),
		pass("public key and example files", []layerFile{fileEntry("root/.ssh/id_rsa.pub", "x"), fileEntry("app/.env.example", "x"), fileEntry("app/.environment", "x")}),
		pass("another extension of the same family", []layerFile{fileEntry("app/settings.pyc", "x"), fileEntry("app/database.yaml", "x"), fileEntry("app/a.secrets", "x")}),
		pass("names and extensions are case sensitive", []layerFile{fileEntry("app/Settings.py", "x"), fileEntry("app/CLIENT.OVPN", "x"), fileEntry("app/Credentials", "x"), fileEntry("app/.ENV", "x")}),
		pass("a directory named credentials is no file", []layerFile{dirEntry("app/credentials/"), fileEntry("app/credentials/readme.txt", "x")}),
		pass("a virtual environment directory named .env", []layerFile{dirEntry("app/.env/"), fileEntry("app/.env/bin/python", "x"), fileEntry("app/.env/pyvenv.cfg", "x")}),
		pass("a directory with a credential extension", []layerFile{dirEntry("app/keys.jks/"), fileEntry("app/keys.jks/readme", "x")}),

		// Mixed outcomes.
		{"a fixture next to a real finding", [][]layerFile{{fileEntry("app/testdata/credentials.json", "x"), fileEntry("app/config/credentials.json", "x")}}, spec.OutcomeFail,
			[]string{"/app/config/credentials.json"}, []string{"/app/testdata/credentials.json"}},
		{"the component is compared whole", [][]layerFile{{fileEntry("app/contest/id_rsa", "x"), fileEntry("app/latest/settings.py", "x")}}, spec.OutcomeFail,
			[]string{"/app/contest/id_rsa", "/app/latest/settings.py"}, nil},
		{"findings are sorted", [][]layerFile{{fileEntry("z/id_rsa", "x"), fileEntry("a/id_rsa", "x")}}, spec.OutcomeFail, []string{"/a/id_rsa", "/z/id_rsa"}, nil},
		{"a hidden file named like an extension", [][]layerFile{{fileEntry("root/.jks", "x")}}, spec.OutcomeFail, []string{"/root/.jks"}, nil},

		// Links, whiteouts and replaced entries.
		{"a hard link named id_rsa counts under its own name", [][]layerFile{{fileEntry("app/key", "x"), linkEntry("root/.ssh/id_rsa", "app/key")}}, spec.OutcomeFail, []string{"/root/.ssh/id_rsa"}, nil},
		{"a hard link without a target in the layer still counts", [][]layerFile{{linkEntry("root/credentials", "lower/file")}}, spec.OutcomeFail, []string{"/root/credentials"}, nil},
		{"a symbolic link named credentials counts", [][]layerFile{{symlinkEntry("root/.aws/credentials", "/run/secrets/aws")}}, spec.OutcomeFail, []string{"/root/.aws/credentials"}, nil},
		pass("a whiteout removes the file", []layerFile{fileEntry("app/id_rsa", "x"), fileEntry("app/main", "x")}, []layerFile{whiteoutEntry("app", "id_rsa")}),
		pass("a whiteout of the parent directory removes the file", []layerFile{fileEntry("app/keys/id_rsa", "x"), fileEntry("app/main", "x")}, []layerFile{whiteoutEntry("app", "keys")}),
		pass("an opaque whiteout removes the file", []layerFile{fileEntry("app/id_rsa", "x")}, []layerFile{{name: "app/.wh..wh..opq", mode: 0o644}, fileEntry("app/main", "x")}),
		pass("a file replaced by a directory", []layerFile{fileEntry("app/credentials", "x")}, []layerFile{dirEntry("app/credentials/")}),
		{"a directory replaced by a file", [][]layerFile{{dirEntry("app/credentials/")}, {fileEntry("app/credentials", "x")}}, spec.OutcomeFail, []string{"/app/credentials"}, nil},
		{"a replacement keeps the finding", [][]layerFile{{fileEntry("app/id_rsa", "old")}, {fileEntry("app/id_rsa", "new")}}, spec.OutcomeFail, []string{"/app/id_rsa"}, nil},

		// Evidence that cannot carry a verdict.
		{"an image without entries", nil, spec.OutcomeUnverified, nil, nil},
	}
	// Every name and every extension of the contract, each in its own tree.
	for _, name := range contractCredentialNames {
		cases = append(cases, fs12Case{"name " + name, [][]layerFile{{fileEntry("srv/app/"+name, "x")}}, spec.OutcomeFail, []string{"/srv/app/" + name}, nil})
	}
	for _, ext := range contractCredentialExts {
		cases = append(cases, fs12Case{"extension " + ext, [][]layerFile{{fileEntry("srv/app/client"+ext, "x")}}, spec.OutcomeFail, []string{"/srv/app/client" + ext}, nil})
	}
	// Every fixture-like component of FS-06: the file is a candidate and the
	// check passes.
	for _, component := range []string{"testdata", "test", "tests", "fixtures", "fixture", "examples", "example", "Tests"} {
		cases = append(cases, fs12Case{"fixture component " + component, [][]layerFile{{fileEntry("opt/lib/"+component+"/id_rsa", "x")}}, spec.OutcomePass, nil, []string{"/opt/lib/" + component + "/id_rsa"}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := treeContainer(t, tc.layers...)
			c.AssertFilesystem().NoCredentialNamedFiles()
			r := expectOutcome(t, c, "FS-12", tc.want)
			if tc.want == spec.OutcomeUnverified {
				return
			}
			var gotPaths, gotFixtures []string
			if r.Evidence != nil {
				gotPaths, gotFixtures = r.Evidence.Paths, r.Evidence.FixtureCandidates
			}
			if !reflect.DeepEqual(gotPaths, tc.paths) || !reflect.DeepEqual(gotFixtures, tc.fixes) {
				t.Errorf("evidence paths %q and fixture candidates %q, want %q and %q", gotPaths, gotFixtures, tc.paths, tc.fixes)
			}
		})
	}

	t.Run("fixture candidates are counted in the message", func(t *testing.T) {
		c := treeContainer(t, []layerFile{fileEntry("app/testdata/id_rsa", "x"), fileEntry("app/examples/credentials", "x")})
		c.AssertFilesystem().NoCredentialNamedFiles()
		r := expectOutcome(t, c, "FS-12", spec.OutcomePass)
		if !strings.Contains(r.Message, "2 fixture candidate(s)") {
			t.Errorf("message = %q, want the fixture count", r.Message)
		}
	})
	t.Run("the check is a custom ConUnit check without a control number", func(t *testing.T) {
		c := treeContainer(t, []layerFile{fileEntry("app/id_rsa", "x")})
		c.AssertFilesystem().NoCredentialNamedFiles()
		r := expectOutcome(t, c, "FS-12", spec.OutcomeFail)
		if r.Rule.Mapping != spec.MappingCustom || r.Rule.ControlID != "" || r.Rule.Scope != spec.ScopeImageContent {
			t.Errorf("rule = %+v, want a custom check with image_content scope and no control", r.Rule)
		}
	})
	t.Run("an index built without a directory set treats every entry as a file", func(t *testing.T) {
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: map[string]bool{"/app": true, "/app/.env": true}}}
		c.AssertFilesystem().NoCredentialNamedFiles()
		expectOutcome(t, c, "FS-12", spec.OutcomeFail)
	})
	t.Run("no index", func(t *testing.T) {
		c := &conunit.Container{}
		c.AssertFilesystem().NoCredentialNamedFiles()
		expectOutcome(t, c, "FS-12", spec.OutcomeUnverified)
	})
	t.Run("the evidence is capped and the message states the full count", func(t *testing.T) {
		paths := map[string]bool{"/app": true}
		for i := 0; i < 250; i++ {
			paths[fmt.Sprintf("/srv/site%03d/settings.py", i)] = true
		}
		c := &conunit.Container{OCIIndex: &oci.FilesystemIndex{Paths: paths}}
		c.AssertFilesystem().NoCredentialNamedFiles()
		r := expectOutcome(t, c, "FS-12", spec.OutcomeFail)
		if len(r.Evidence.Paths) != 200 || !strings.Contains(r.Message, "250 file(s)") || !strings.Contains(r.Message, "and 240 more") {
			t.Errorf("evidence has %d paths, message %q, want 200 in the evidence and the full count in the message", len(r.Evidence.Paths), r.Message)
		}
	})
}
