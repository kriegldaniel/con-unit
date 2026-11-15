package conunit

import (
	"path"
	"sort"
	"strings"

	"github.com/con-unit/con-unit/pkg/oci"
)

// The name lists of FS-11 and FS-12 are the checkpoint lists of Dockle v0.4.15
// (CHECKPOINT.md, DKL-LI-0003 and CIS-DI-0010). They are data, so the rule
// reference and the pack tables print exactly what runs.
var (
	leftoverDirNames  = []string{".cache", ".aws", ".azure", ".gcp", ".git", ".vscode", ".idea", ".npm"}
	leftoverFileNames = []string{"Dockerfile", "docker-compose.yml", ".vimrc", ".DS_Store"}
	leftoverSkipDirs  = []string{"node_modules", "vendor"}

	credentialFileNames = []string{
		"credentials.json", "credential.json", "credentials", "credential", "password.txt",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "secret_token.rb", "carrierwave.rb",
		"omniauth.rb", "settings.py", "database.yml", "credentials.xml", ".env",
	}
	credentialExtensions = []string{
		".secret", ".ovpn", ".private_key", ".cscfg", ".rdp", ".mdf", ".sdf", ".bek",
		".tpm", ".fve", ".jks", ".psafe3", ".agilekeychain", ".keychain", ".pcap", ".gnucache",
	}
)

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

// cleanTreePath returns the absolute, cleaned form of an index path.
func cleanTreePath(p string) string {
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}

// treeComponents splits a path into its components, without the empty root.
func treeComponents(p string) []string {
	trimmed := strings.Trim(cleanTreePath(p), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// isDirectoryEntry reports whether the cleaned path is a directory of the
// index. An index without a directory set cannot say, and then no path counts
// as a directory, so the name checks err on the side of reporting.
func isDirectoryEntry(dirs map[string]struct{}, cleaned string) bool {
	if dirs == nil {
		return false
	}
	_, ok := dirs[cleaned]
	return ok
}

// belowAny reports whether the path lies below one of the directories.
func belowAny(p string, dirs map[string]struct{}) bool {
	for i := len(p) - 1; i > 0; i-- {
		if p[i] == '/' {
			if _, ok := dirs[p[:i]]; ok {
				return true
			}
		}
	}
	return false
}

// leftoverFindings returns the paths that FS-11 reports, sorted.
//
// A path has a leftover directory when one of its components is in
// leftoverDirNames. The directory is reported once, at its shallowest
// occurrence, and nothing below a reported directory is listed again. A
// non-directory entry named like one of leftoverFileNames is reported by its
// path. Entries below a node_modules or vendor directory are skipped.
func leftoverFindings(paths map[string]bool, dirs map[string]struct{}) []string {
	dirNames, fileNames, skipDirs := stringSet(leftoverDirNames), stringSet(leftoverFileNames), stringSet(leftoverSkipDirs)
	foundDirs := map[string]struct{}{}
	foundFiles := map[string]struct{}{}
	for raw := range paths {
		components := treeComponents(raw)
		if len(components) == 0 {
			continue
		}
		// Read the components from the root. The first component that is a
		// leftover directory decides: the directory is reported and the rest of
		// the path is not read. The first node_modules or vendor directory that
		// has something below it skips the rest of the path, so a leftover above
		// such a tree is still reported and one inside it is not.
		skipped := false
		for i, component := range components {
			if _, ok := dirNames[component]; ok {
				foundDirs["/"+strings.Join(components[:i+1], "/")] = struct{}{}
				break
			}
			if _, ok := skipDirs[component]; ok && i < len(components)-1 {
				skipped = true
				break
			}
		}
		if skipped {
			continue
		}
		cleaned := "/" + strings.Join(components, "/")
		if _, ok := fileNames[components[len(components)-1]]; ok && !isDirectoryEntry(dirs, cleaned) {
			foundFiles[cleaned] = struct{}{}
		}
	}
	findings := make([]string, 0, len(foundDirs)+len(foundFiles))
	for dir := range foundDirs {
		findings = append(findings, dir)
	}
	for file := range foundFiles {
		if !belowAny(file, foundDirs) {
			findings = append(findings, file)
		}
	}
	sort.Strings(findings)
	return findings
}

// credentialFileScan is the outcome of the credential file name scan.
type credentialFileScan struct {
	// Findings are credential-named files outside fixture-like locations.
	Findings []string
	// FixtureCandidates are the same under fixture-like locations.
	FixtureCandidates []string
}

// scanCredentialFiles finds the non-directory entries whose name is in
// credentialFileNames or whose extension, taken from the last dot of the name,
// is in credentialExtensions.
func scanCredentialFiles(paths map[string]bool, dirs map[string]struct{}) credentialFileScan {
	names, extensions := stringSet(credentialFileNames), stringSet(credentialExtensions)
	var scan credentialFileScan
	for raw := range paths {
		cleaned := cleanTreePath(raw)
		if cleaned == "/" || isDirectoryEntry(dirs, cleaned) {
			continue
		}
		base := path.Base(cleaned)
		_, byName := names[base]
		_, byExtension := extensions[path.Ext(base)]
		if !byName && !byExtension {
			continue
		}
		if oci.IsFixtureLikePath(cleaned) {
			scan.FixtureCandidates = append(scan.FixtureCandidates, cleaned)
		} else {
			scan.Findings = append(scan.Findings, cleaned)
		}
	}
	sort.Strings(scan.Findings)
	sort.Strings(scan.FixtureCandidates)
	return scan
}

// sharedID is one ID that two or more different names carry.
type sharedID struct {
	ID    uint32
	Names []string
}

// sharedIDs returns the IDs that more than one different name carries, in
// ascending ID order with sorted names. A name listed twice with the same ID is
// one account and not a collision.
func sharedIDs(records map[string][]uint32) []sharedID {
	namesByID := map[uint32]map[string]struct{}{}
	for name, ids := range records {
		for _, id := range ids {
			if namesByID[id] == nil {
				namesByID[id] = map[string]struct{}{}
			}
			namesByID[id][name] = struct{}{}
		}
	}
	var shared []sharedID
	for id, names := range namesByID {
		if len(names) < 2 {
			continue
		}
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		shared = append(shared, sharedID{ID: id, Names: list})
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i].ID < shared[j].ID })
	return shared
}
