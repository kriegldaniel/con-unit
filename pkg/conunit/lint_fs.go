package conunit

import (
	"fmt"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

const (
	fs10Name = "Unique Account and Group IDs"
	fs11Name = "No Development, Editor, Cache or Cloud Leftovers"
	fs12Name = "No Credential-Named Files"
)

// maxMessagePaths bounds the paths named in a result message. The evidence
// holds up to maxEvidencePaths of them, and the message states the full count.
const maxMessagePaths = 10

func describePaths(paths []string) string {
	if len(paths) <= maxMessagePaths {
		return fmt.Sprintf("%v", paths)
	}
	return fmt.Sprintf("%v and %d more", paths[:maxMessagePaths], len(paths)-maxMessagePaths)
}

// UniqueAccountAndGroupIDs is FS-10. It fails when two different account names
// share a UID in /etc/passwd or two different group names share a GID in
// /etc/group.
func (fs *FilesystemAssertions) UniqueAccountAndGroupIDs() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-10", fs10Name, spec.TierFilesystem, start)
		return fs
	}
	index := fs.c.OCIIndex
	var findings []string
	for _, shared := range sharedIDs(index.PasswdUIDs) {
		findings = append(findings, fmt.Sprintf("/etc/passwd: UID %d is shared by %s", shared.ID, strings.Join(shared.Names, ", ")))
	}
	for _, shared := range sharedIDs(index.GroupGIDs) {
		findings = append(findings, fmt.Sprintf("/etc/group: GID %d is shared by %s", shared.ID, strings.Join(shared.Names, ", ")))
	}

	var issues []string
	if index.PasswdEvidenceIssue != "" {
		issues = append(issues, index.PasswdEvidenceIssue)
	} else if len(index.PasswdUIDs) == 0 {
		issues = append(issues, "/etc/passwd holds no account records")
	}
	if index.GroupEvidenceIssue != "" {
		issues = append(issues, index.GroupEvidenceIssue)
	} else if len(index.GroupGIDs) == 0 {
		issues = append(issues, "/etc/group holds no group records")
	}

	switch {
	case len(findings) > 0:
		fs.c.RecordFailureDetail("FS-10", fs10Name, spec.TierFilesystem, time.Since(start),
			fmt.Sprintf("Account or group IDs are shared by different names: %s", strings.Join(findings, "; ")),
			"Two names with one ID are one identity for the kernel and for file permissions, so a file of one account is also a file of the other.",
			"Give every account and every group of the image its own ID",
			dockleCheckpoints+"#dkl-li-0002",
			ResultDetail{Evidence: &spec.Evidence{Paths: capEvidencePaths(findings)}})
	case len(issues) > 0:
		fs.c.RecordUnverifiedDetail("FS-10", fs10Name, spec.TierFilesystem, time.Since(start),
			fmt.Sprintf("ID uniqueness is unverified: %s", strings.Join(issues, "; ")),
			"Ensure complete, well-formed /etc/passwd and /etc/group files are present in the final image", dockleCheckpoints+"#dkl-li-0002",
			ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
	default:
		fs.c.RecordPass("FS-10", fs10Name, spec.TierFilesystem, time.Since(start),
			fmt.Sprintf("No two different names share an ID in the %d account(s) of /etc/passwd and the %d group(s) of /etc/group", len(index.PasswdUIDs), len(index.GroupGIDs)))
	}
	return fs
}

// recordEmptyTree records UNVERIFIED for a name check over an index that holds
// no entries, and reports whether it did.
func (fs *FilesystemAssertions) recordEmptyTree(id, ruleName string, start time.Time, reference string) bool {
	if len(fs.c.OCIIndex.Paths) > 0 {
		return false
	}
	fs.c.RecordUnverifiedDetail(id, ruleName, spec.TierFilesystem, time.Since(start),
		"The merged filesystem index holds no entries, so the check is unverified",
		"Resolve and index the image successfully before running this assertion", reference,
		ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
	return true
}

// NoDevelopmentLeftovers is FS-11. It fails when the merged filesystem holds a
// development, editor, cache or cloud directory or a stray development file.
func (fs *FilesystemAssertions) NoDevelopmentLeftovers() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-11", fs11Name, spec.TierFilesystem, start)
		return fs
	}
	if fs.recordEmptyTree("FS-11", fs11Name, start, dockleCheckpoints+"#dkl-li-0003") {
		return fs
	}
	findings := leftoverFindings(fs.c.OCIIndex.Paths, fs.c.OCIIndex.Dirs)
	if len(findings) == 0 {
		fs.c.RecordPass("FS-11", fs11Name, spec.TierFilesystem, time.Since(start),
			"No development, editor, cache or cloud directory and no stray development file was found outside node_modules and vendor trees")
		return fs
	}
	fs.c.RecordFailureDetail("FS-11", fs11Name, spec.TierFilesystem, time.Since(start),
		fmt.Sprintf("%d development, editor, cache or cloud leftover(s) found: %s", len(findings), describePaths(findings)),
		"Directories such as .git, .cache or .aws and files such as Dockerfile in a production image add size, can leak history or credentials, and show how the image was built. The check matches names only.",
		"Exclude these paths from the build context with .dockerignore, or delete them in the layer that created them",
		dockleCheckpoints+"#dkl-li-0003",
		ResultDetail{Evidence: &spec.Evidence{Paths: capEvidencePaths(findings)}})
	return fs
}

// NoCredentialNamedFiles is FS-12. It fails when a non-directory entry has a
// file name or extension that usually holds credentials, outside fixture-like
// locations.
func (fs *FilesystemAssertions) NoCredentialNamedFiles() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-12", fs12Name, spec.TierFilesystem, start)
		return fs
	}
	const reference = "https://www.cisecurity.org/benchmark/docker (no secrets in build files, approximate); " + dockleCheckpoints + "#cis-di-0010"
	if fs.recordEmptyTree("FS-12", fs12Name, start, reference) {
		return fs
	}
	scan := scanCredentialFiles(fs.c.OCIIndex.Paths, fs.c.OCIIndex.Dirs)
	evidence := &spec.Evidence{Paths: capEvidencePaths(scan.Findings), FixtureCandidates: capEvidencePaths(scan.FixtureCandidates)}
	fixtureNote := ""
	if n := len(scan.FixtureCandidates); n > 0 {
		fixtureNote = fmt.Sprintf("; %d fixture candidate(s) under testdata, test, fixtures or examples locations or Debian snakeoil files are counted separately", n)
	}
	if len(scan.Findings) == 0 {
		fs.c.RecordPassDetail("FS-12", fs12Name, spec.TierFilesystem, time.Since(start),
			"No file with a credential-like name or extension was found outside fixture-like locations; file contents were not read"+fixtureNote,
			ResultDetail{Evidence: evidence})
		return fs
	}
	fs.c.RecordFailureDetail("FS-12", fs12Name, spec.TierFilesystem, time.Since(start),
		fmt.Sprintf("%d file(s) with a credential-like name or extension found outside fixture-like locations: %s%s", len(scan.Findings), describePaths(scan.Findings), fixtureNote),
		"Files named like credential stores, private keys or key containers usually hold secrets, and anyone who can pull the image can read them. The check matches file names only and does not read the content.",
		"Remove these files from the image and mount credentials at run time through secrets",
		reference,
		ResultDetail{Evidence: evidence})
	return fs
}
