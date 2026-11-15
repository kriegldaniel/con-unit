package oci

import (
	"fmt"
	"strconv"
	"strings"
)

// groupFilePath is the group database that FS-10 reads next to /etc/passwd.
const groupFilePath = "/etc/group"

// parseGroupContent reads the records of an /etc/group file into a map from
// group name to the GIDs recorded for that name. A record has exactly four
// colon separated fields: name, password field, GID and member list. Blank
// lines and comment lines are skipped. On a malformed record the records read
// so far are returned together with an error, so that the caller can still
// report what it saw but must not treat the file as completely inspected.
func parseGroupContent(content []byte) (map[string][]uint32, error) {
	gids := make(map[string][]uint32)
	lineCount := 0
	for lineNumber, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lineCount++
		fields := strings.Split(line, ":")
		if len(fields) != 4 || strings.TrimSpace(fields[0]) == "" {
			return gids, fmt.Errorf("%s line %d has an invalid record", groupFilePath, lineNumber+1)
		}
		gid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return gids, fmt.Errorf("%s line %d has an invalid GID", groupFilePath, lineNumber+1)
		}
		gids[fields[0]] = append(gids[fields[0]], uint32(gid))
	}
	if lineCount == 0 {
		return gids, fmt.Errorf("%s contains no group records", groupFilePath)
	}
	return gids, nil
}

// captureGroup fills GroupGIDs and GroupEvidenceIssue from the final view. It
// treats the file like the account files: a missing, non-regular, oversized or
// malformed file is an evidence issue, never an empty result. The issue is
// kept apart from AccountEvidenceIssue so that the empty-password check
// (FS-08) behaves exactly as it did before /etc/group was captured.
//
// contents and issues hold, per path of the final view, the bytes read from a
// regular file and the evidence issue found while reading the entry.
func (fi *FilesystemIndex) captureGroup(contents map[string][]byte, issues map[string]string) {
	if !fi.Paths[groupFilePath] {
		fi.GroupEvidenceIssue = fmt.Sprintf("%s is missing from the final image", groupFilePath)
		return
	}
	var problems []string
	if issue := issues[groupFilePath]; issue != "" {
		problems = append(problems, issue)
	}
	body, present := contents[groupFilePath]
	if !present {
		problems = append(problems, fmt.Sprintf("%s contents are unavailable in the final image", groupFilePath))
	} else {
		gids, err := parseGroupContent(body)
		fi.GroupGIDs = gids
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		fi.GroupEvidenceIssue = strings.Join(problems, "; ")
	}
}
