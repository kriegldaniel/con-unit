package conunit

import (
	"slices"
	"strings"
	"testing"
)

// The lists below are the lists of docs/INTERFACE_V2.md section 3, spelled out
// once more. A change of a code list must come with a change of the contract.
func TestListsEqualTheInterfaceContract(t *testing.T) {
	cases := []struct {
		name string
		got  []string
		want []string
	}{
		{"FS-11 directory names", leftoverDirNames, []string{".cache", ".aws", ".azure", ".gcp", ".git", ".vscode", ".idea", ".npm"}},
		{"FS-11 file names", leftoverFileNames, []string{"Dockerfile", "docker-compose.yml", ".vimrc", ".DS_Store"}},
		{"FS-11 skipped trees", leftoverSkipDirs, []string{"node_modules", "vendor"}},
		{"FS-12 file names", credentialFileNames, []string{
			"credentials.json", "credential.json", "credentials", "credential", "password.txt", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
			"secret_token.rb", "carrierwave.rb", "omniauth.rb", "settings.py", "database.yml", "credentials.xml", ".env"}},
		{"FS-12 extensions", credentialExtensions, []string{
			".secret", ".ovpn", ".private_key", ".cscfg", ".rdp", ".mdf", ".sdf", ".bek", ".tpm", ".fve", ".jks", ".psafe3", ".agilekeychain", ".keychain", ".pcap", ".gnucache"}},
		{"SPEC-12 roots", sensitiveVolumeRoots, []string{"/dev", "/proc", "/sys"}},
		{"SPEC-03 disallowed keys of the lint pack", lintSecretEnvKeys, []string{"PASS", "PASSWD", "PASSWORD", "SECRET", "KEY", "ACCESS", "TOKEN"}},
		{"SPEC-03 accepted keys of the lint pack", lintAcceptedEnvKeys, []string{"GPG_KEY", "GPG_KEYS"}},
		{"FS-01 paths of the lint pack", lintPaths, []string{"/var/cache/apt", "/var/cache/apk", "/root/.cache", "/.git", "/root/.ssh", "/.env", "/var/lib/apt/lists"}},
	}
	for _, tc := range cases {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestHygienePathsAreNotChangedByTheLintPack(t *testing.T) {
	want := []string{"/var/cache/apt", "/var/cache/apk", "/root/.cache", "/.git", "/root/.ssh", "/.env"}
	if !slices.Equal(hygienePaths, want) {
		t.Fatalf("hygiene paths = %v, want %v: the lint pack must clone the list, not extend it", hygienePaths, want)
	}
	if slices.Contains(hygienePaths, "/var/lib/apt/lists") {
		t.Fatal("the hygiene pack must not gain /var/lib/apt/lists through the lint pack")
	}
}

func TestCatalogOraclesPrintTheCodeLists(t *testing.T) {
	text := func(id string) string {
		rule, ok := RuleByID(id)
		if !ok {
			t.Fatalf("%s is not in the catalog", id)
		}
		return rule.Oracle
	}
	for id, lists := range map[string][][]string{
		"FS-11": {leftoverDirNames, leftoverFileNames, leftoverSkipDirs},
		"FS-12": {credentialFileNames, credentialExtensions},
	} {
		oracle := text(id)
		for _, list := range lists {
			if !strings.Contains(oracle, strings.Join(list, ", ")) {
				t.Errorf("the oracle of %s does not print %v:\n%s", id, list, oracle)
			}
		}
	}
}
