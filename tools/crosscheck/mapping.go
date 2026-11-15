package main

import (
	"path"
	"regexp"
	"strings"

	"github.com/con-unit/con-unit/tools/internal/analysis"
)

// Facets of a Dockle code that several ConUnit checks share. CIS-DI-0010 holds
// alerts about ENV keys of the build history and alerts about file names, and
// three ConUnit checks map to it.
const (
	FacetNone = ""
	FacetEnv  = "env"
	FacetFile = "file"
)

// Alert text prefixes of CIS-DI-0010 in Dockle v0.4.15 (pkg/assessor/manifest
// and pkg/assessor/credential).
const (
	alertEnvPrefix       = "Suspicious ENV key found"
	alertFilenamePrefix  = "Suspicious filename found"
	alertExtensionPrefix = "Suspicious file extension found"
)

// FacetOfAlert returns the facet of one CIS-DI-0010 alert, or FacetNone.
func FacetOfAlert(alert string) string {
	a := strings.TrimSpace(alert)
	switch {
	case strings.HasPrefix(a, alertEnvPrefix):
		return FacetEnv
	case strings.HasPrefix(a, alertFilenamePrefix), strings.HasPrefix(a, alertExtensionPrefix):
		return FacetFile
	}
	return FacetNone
}

// Difference is a documented design difference between a ConUnit check and a
// Dockle checkpoint that can produce a discordance of one direction.
//
// It is a candidate cause. Where the recorded evidence can decide, Applies
// says whether the difference explains this pair; when it says no, the
// discordance has no known intended difference and needs a look. Without
// Applies the difference is stated as a candidate that the adjudication
// confirms or rejects.
type Difference struct {
	// Short is a few words for the table.
	Short string
	// Text is the full explanation for discordances.csv.
	Text string
	// Applies, when set, checks the ConUnit evidence line and the Dockle alert
	// text of the pair.
	Applies func(conunitEvidence, dockleAlert string) bool
}

// fixtureLikeComponents are the path components under which FS-06 and FS-12
// count a finding as a fixture candidate instead of a failure.
var fixtureLikeComponents = map[string]bool{
	"testdata": true, "test": true, "tests": true, "fixtures": true, "fixture": true, "examples": true, "example": true,
}

var credentialAlertPath = regexp.MustCompile(`found : (\S+) \(`)

// onlyFixtureLikeCredentialPaths reports whether every credential file named in
// the Dockle alerts lies below a fixture-like path component, which is the
// case in which FS-12 passes where Dockle fails. An alert that names no path
// does not count as explained.
func onlyFixtureLikeCredentialPaths(_, dockleAlert string) bool {
	matches := credentialAlertPath.FindAllStringSubmatch(dockleAlert, -1)
	if len(matches) == 0 {
		return false
	}
	for _, m := range matches {
		dir := path.Dir(strings.TrimPrefix(m[1], "/"))
		like := false
		for _, comp := range strings.Split(dir, "/") {
			if fixtureLikeComponents[comp] {
				like = true
			}
		}
		if !like {
			return false
		}
	}
	return true
}

// underDependencyDirectory reports whether the Dockle alert names a path below
// node_modules or vendor, which ConUnit skips and Dockle skips for directory
// matches only.
func underDependencyDirectory(_, dockleAlert string) bool {
	return strings.Contains(dockleAlert, "node_modules/") || strings.Contains(dockleAlert, "vendor/")
}

var addAlertPrefix = regexp.MustCompile(`Use COPY : (?:/bin/sh -c )?(?:#\(nop\) )?(\S+)`)

// notAnADDInstruction reports whether the recorded command of a Dockle ADD
// alert does not start with the instruction ADD. Such a command is another
// instruction that merely contains the words ADD and in. A real ADD that
// ConUnit passes is not explained by the difference.
func notAnADDInstruction(_, dockleAlert string) bool {
	m := addAlertPrefix.FindStringSubmatch(dockleAlert)
	return m != nil && m[1] != "ADD"
}

// Mapping ties one ConUnit check to the Dockle codes that count for it. The
// rule of the contract is that an entry of any listed code is a finding.
type Mapping struct {
	// Check is the ConUnit rule ID.
	Check string
	// Codes are the Dockle codes. An entry of any of them is a finding.
	Codes []string
	// Facet is set when the codes hold alerts of several kinds and this check
	// covers one of them.
	Facet string
	// NotComparable is non-empty when the pair cannot be compared at all; the
	// text is the reason. Such a check is kept in the mapping and excluded
	// from the 2x2 table and from the agreement percentage.
	NotComparable string
	// OnlyConUnit explains ConUnit FAIL with no Dockle finding. OnlyDockle
	// explains a Dockle finding with ConUnit PASS. An empty Text means that no
	// intended difference is known for that direction.
	OnlyConUnit Difference
	OnlyDockle  Difference
}

// Key returns the letters-only macro key of the check.
func (m Mapping) Key() string { return analysis.RuleKey(m.Check) }

// Comparable reports whether the pair enters the 2x2 table.
func (m Mapping) Comparable() bool { return m.NotComparable == "" }

// notComparableLatest is the reason for SPEC-13 against DKL-DI-0006. Dockle
// reads the image reference from its image-name argument only (pkg/run.go
// lines 76 to 82 and 97 to 103). With --input the name is empty, so the
// checkpoint cannot fire for an archive.
const notComparableLatest = "Dockle evaluates DKL-DI-0006 only when it receives an image name; with --input the name is empty and the checkpoint never fires, so an archive cannot produce it"

// Mappings returns the mapping in the order of docs/INTERFACE_V2.md section 5.
func Mappings() []Mapping {
	return []Mapping{
		{
			Check: "SPEC-01", Codes: []string{"CIS-DI-0001"},
			OnlyConUnit: Difference{Short: "UID 0 by number or name", Text: "Dockle fails an empty USER or the literal string root. ConUnit resolves the configured user: a numeric UID 0 and any name that /etc/passwd maps to UID 0 also fail."},
			OnlyDockle:  Difference{Short: "root name maps to another UID", Text: "Dockle compares the configured user as a string. ConUnit resolves a name through the final /etc/passwd, so a user named root that maps to a non-zero UID passes in ConUnit and fails in Dockle."},
		},
		{
			Check: "CIS-4.6", Codes: []string{"CIS-DI-0006"},
			OnlyConUnit: Difference{Short: "HEALTHCHECK NONE", Text: "Dockle fails only when the image config has no Healthcheck object. ConUnit also fails a HEALTHCHECK whose test is NONE or empty, which is a present object that disables the check."},
		},
		{
			Check: "FS-04", Codes: []string{"CIS-DI-0008"},
			OnlyDockle: Difference{Short: "hard-link entries", Text: "Dockle reads the mode bits recorded on hard-link entries as it reads them on regular files. ConUnit takes the mode of a hard link from its target in the same layer and reports UNVERIFIED when the target is not there."},
		},
		{
			Check: "SPEC-07", Codes: []string{"CIS-DI-0009"},
			OnlyConUnit: Difference{Short: "only the base rootfs ADD is exempt", Text: "Dockle exempts the first ADD it finds, whatever that ADD adds. ConUnit exempts only the base image rootfs import, the first layer-producing history entry, so a later ADD after a base layer that is not an ADD fails in ConUnit only."},
			OnlyDockle:  Difference{Applies: notAnADDInstruction, Short: "tokens ADD and in in any command", Text: "Dockle matches the whitespace tokens ADD and in (or buildkit) anywhere in a recorded command, so a RUN line that contains those words is a finding. ConUnit reads the recorded instruction form."},
		},
		{
			Check: "SPEC-03", Codes: []string{"CIS-DI-0010"}, Facet: FacetEnv,
			OnlyConUnit: Difference{Short: "config ENV and value patterns", Text: "ConUnit reads the ENV of the image config, which includes variables inherited from the base image, flags a key even when its value is empty and also fails values that match AWS, GitHub, Slack or PEM private key patterns. Dockle reads NAME=value words of the recorded build commands and skips empty values."},
			OnlyDockle:  Difference{Short: "NAME=value words in build commands", Text: "Dockle reads NAME=value words of every recorded build command, including words in RUN lines and variables that are not in the final image config. ConUnit reads the final ENV of the image config only."},
		},
		{
			Check: "FS-06", Codes: []string{"CIS-DI-0010"}, Facet: FacetFile,
			OnlyConUnit: Difference{Short: "private key by content", Text: "FS-06 reads file content and fails on a PEM or OpenSSH private key block in files named *.key, *.pem, id_rsa, id_dsa, id_ecdsa or id_ed25519. Dockle matches file names only and its list has no .key or .pem entry."},
			OnlyDockle:  Difference{Short: "name match without content check", Text: "Dockle fails on a credential file name alone, for example id_rsa, with no content check and no fixture exemption. ConUnit passes when the file holds no private key block or when every finding is under a fixture-like path or is a Debian snakeoil key."},
		},
		{
			Check: "FS-12", Codes: []string{"CIS-DI-0010"}, Facet: FacetFile,
			OnlyDockle: Difference{Applies: onlyFixtureLikeCredentialPaths, Short: "fixture-like path", Text: "Dockle fails on a credential file name anywhere in the tree. FS-12 counts findings under testdata, test, tests, fixtures, fixture, examples and example path components as fixture candidates and does not fail on them."},
		},
		{
			Check: "FS-08", Codes: []string{"DKL-LI-0001"},
			OnlyConUnit: Difference{Short: "/etc/passwd password field", Text: "ConUnit reads the password field of /etc/passwd and of /etc/shadow. Dockle reads /etc/shadow or /etc/master.passwd only."},
			OnlyDockle:  Difference{Short: "/etc/master.passwd", Text: "Dockle also reads /etc/master.passwd. ConUnit reads /etc/passwd and /etc/shadow."},
		},
		{
			Check: "SPEC-09", Codes: []string{"CIS-DI-0007"},
			OnlyConUnit: Difference{Short: "same package manager required", Text: "ConUnit requires an install or upgrade of the same package manager as the update. Dockle accepts an install or upgrade of either apt-get or apt after an update."},
			OnlyDockle:  Difference{Short: "whitespace tokens, only && splits", Text: "Dockle splits a command on && only and matches any two of the tokens apt-get, apt and update in a segment, so mentions in echo, in arguments or after a semicolon count. ConUnit tokenizes on &&, ||, ; and | and newlines and counts a command in command position only."},
		},
		{
			Check: "SPEC-10", Codes: []string{"DKL-DI-0001"},
			OnlyConUnit: Difference{Short: "sudo attached to a separator", Text: "Dockle matches the whitespace token sudo, so a form such as a;sudo x has the token a;sudo and is missed. ConUnit splits on a semicolon first and finds sudo in command position."},
			OnlyDockle:  Difference{Short: "sudo as an argument", Text: "Dockle matches the token sudo anywhere in a segment, including arguments such as apt-get install sudo and echo sudo. ConUnit counts sudo in command position only."},
		},
		{
			Check: "SPEC-11", Codes: []string{"DKL-DI-0003"},
			OnlyConUnit: Difference{Short: "dist-upgrade attached to a separator", Text: "Dockle matches whitespace tokens, so a form such as a;apt-get dist-upgrade has the token a;apt-get and is missed. ConUnit splits on a semicolon first and finds the command."},
			OnlyDockle:  Difference{Short: "tokens outside command position", Text: "Dockle matches any two of the tokens apt-get, apt and dist-upgrade in a segment, so a mention in an argument or an echo counts. ConUnit requires the command form apt-get dist-upgrade or apt dist-upgrade."},
		},
		{
			Check: "SPEC-12", Codes: []string{"DKL-DI-0002"},
			OnlyConUnit: Difference{Short: "volume below /proc, /sys or /dev", Text: "ConUnit also fails a volume below /dev, /proc or /sys, for example /proc/self. Dockle compares the exact paths /dev, /proc and /sys, so a trailing slash or a subpath is missed."},
		},
		{
			Check: "SPEC-13", Codes: []string{"DKL-DI-0006"}, NotComparable: notComparableLatest,
		},
		{
			Check: "FS-10", Codes: []string{"DKL-LI-0002"},
			OnlyDockle: Difference{Short: "repeated ID with the same name", Text: "Dockle reports any repeated UID or GID value, including a repeated line for the same name. ConUnit reports two different names that share an ID."},
		},
		{
			Check: "FS-11", Codes: []string{"DKL-LI-0003"},
			OnlyConUnit: Difference{Short: "name at any depth", Text: "ConUnit matches the listed directory names as a path component at any depth. Dockle matches a file whose immediate parent directory has the listed name, so a directory that holds only subdirectories is missed."},
			OnlyDockle:  Difference{Applies: underDependencyDirectory, Short: "files below node_modules or vendor", Text: "Dockle applies the node_modules and vendor exemption to directory matches only and reports the files Dockerfile, docker-compose.yml, .vimrc and .DS_Store below them. ConUnit skips those subtrees."},
		},
		{
			Check: "FS-01", Codes: []string{"DKL-DI-0004", "DKL-DI-0005"},
			OnlyConUnit: Difference{Short: "outcome of the filesystem", Text: "FS-01 checks the merged filesystem for the cache and hygiene paths (/var/cache/apt, /var/cache/apk, /root/.cache, /.git, /root/.ssh, /.env and /var/lib/apt/lists), whatever step created them. Dockle's two checkpoints judge only the recorded apk add and apt commands."},
			OnlyDockle:  Difference{Short: "command judged, not the result", Text: "Dockle reports an apk add without --no-cache, or an apt update or install without a later removal of /var/lib/apt/lists, in the recorded commands. ConUnit passes when the final filesystem holds none of its listed paths, for example after a cleanup in a later step."},
		},
	}
}

// MappingFor returns the mapping of a ConUnit check.
func MappingFor(check string) (Mapping, bool) {
	for _, m := range Mappings() {
		if m.Check == check {
			return m, true
		}
	}
	return Mapping{}, false
}

// MappedCodes returns the set of Dockle codes that at least one check uses.
func MappedCodes() map[string]bool {
	out := map[string]bool{}
	for _, m := range Mappings() {
		for _, c := range m.Codes {
			out[c] = true
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// The Dockle catalog at the verified version

// CheckpointStatus tells whether and how Dockle v0.4.15 evaluates a documented
// checkpoint.
type CheckpointStatus string

const (
	// StatusImage: Dockle evaluates the checkpoint from the image.
	StatusImage CheckpointStatus = "image"
	// StatusHostEnvironment: Dockle evaluates the checkpoint from the
	// environment of the machine that runs Dockle, not from the image.
	StatusHostEnvironment CheckpointStatus = "host-environment"
	// StatusNoCodePath: the checkpoint is documented, but v0.4.15 has no code
	// that can emit it.
	StatusNoCodePath CheckpointStatus = "documented-no-code-path"
	// StatusNotSupported: Dockle documents the checkpoint as not supported.
	StatusNotSupported CheckpointStatus = "documented-not-supported"
)

// Checkpoint is one checkpoint of the Dockle catalog (CHECKPOINT.md and
// pkg/types/checkpoint.go of v0.4.15).
type Checkpoint struct {
	Code string
	// Short is a descriptor in the words of this project.
	Short string
	// Default is the level Dockle gives the checkpoint (DefaultLevelMap), empty
	// when Dockle never emits it.
	Default string
	Status  CheckpointStatus
	// Note states the source of the status.
	Note string
}

// DockleCatalog lists every checkpoint of Dockle v0.4.15: the eleven CIS-DI
// checkpoints, the six DKL-DI checkpoints and the three DKL-LI checkpoints.
func DockleCatalog() []Checkpoint {
	return []Checkpoint{
		{"CIS-DI-0001", "container has a non-root user", LevelWarn, StatusImage, "manifest assessor: config User empty or root"},
		{"CIS-DI-0002", "trusted base images", "", StatusNoCodePath, "CHECKPOINT.md says Dockle checks content trust, but no code emits this code; content trust is CIS-DI-0005"},
		{"CIS-DI-0003", "no unnecessary packages", "", StatusNotSupported, "CHECKPOINT.md: not supported"},
		{"CIS-DI-0004", "security patches", "", StatusNotSupported, "CHECKPOINT.md: not supported, refers to a vulnerability scanner"},
		{"CIS-DI-0005", "Docker content trust enabled", LevelInfo, StatusHostEnvironment, "contentTrust assessor reads DOCKER_CONTENT_TRUST of the scanning host"},
		{"CIS-DI-0006", "HEALTHCHECK present", LevelInfo, StatusImage, "manifest assessor: config Healthcheck is nil"},
		{"CIS-DI-0007", "update instruction not used alone", LevelFatal, StatusImage, "manifest assessor: tokens in the build history"},
		{"CIS-DI-0008", "setuid and setgid files", LevelInfo, StatusImage, "privilege assessor: mode bits of the merged files"},
		{"CIS-DI-0009", "COPY instead of ADD", LevelFatal, StatusImage, "manifest assessor: ADD tokens in the build history"},
		{"CIS-DI-0010", "no credentials in ENV or files", LevelFatal, StatusImage, "manifest assessor (ENV words of the history) and credential assessor (file names)"},
		{"CIS-DI-0011", "verified packages only", "", StatusNotSupported, "CHECKPOINT.md: not supported"},
		{"DKL-DI-0001", "no sudo", LevelFatal, StatusImage, "manifest assessor: token sudo in the build history"},
		{"DKL-DI-0002", "no sensitive directory as volume", LevelFatal, StatusImage, "manifest assessor: config Volumes /sys, /dev, /proc"},
		{"DKL-DI-0003", "no dist-upgrade", LevelWarn, StatusImage, "manifest assessor: tokens in the build history"},
		{"DKL-DI-0004", "apk add with --no-cache", LevelFatal, StatusImage, "manifest assessor: apk add tokens in the build history"},
		{"DKL-DI-0005", "apt caches cleared", LevelFatal, StatusImage, "manifest assessor: apt tokens and rm of /var/lib/apt/lists in the build history"},
		{"DKL-DI-0006", "no latest tag", LevelWarn, StatusImage, "run.go: only when Dockle receives an image name, never for --input"},
		{"DKL-LI-0001", "no empty password", LevelFatal, StatusImage, "passwd assessor: /etc/shadow or /etc/master.passwd"},
		{"DKL-LI-0002", "unique UID and GID", LevelFatal, StatusImage, "user and group assessors: /etc/passwd and /etc/group"},
		{"DKL-LI-0003", "no stray development files", LevelInfo, StatusImage, "cache assessor: fixed directory and file names"},
	}
}

// ExcludedCode is a Dockle code that the cross-check leaves out, with the
// reason.
type ExcludedCode struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// ExcludedCodes lists the codes that are not compared. The contract names
// CIS-DI-0002 and CIS-DI-0005 as the checkpoints that concern the scanner
// host. Verified against the source: CIS-DI-0005 reads DOCKER_CONTENT_TRUST of
// the host and is written for every image unless the host sets it; CIS-DI-0002
// is documented as content trust but is never emitted.
func ExcludedCodes() []ExcludedCode {
	return []ExcludedCode{
		{"CIS-DI-0002", "documented as content trust, concerns the scanning host, and has no code path in Dockle " + VerifiedDockleVersion + ", so it is never emitted"},
		{"CIS-DI-0005", "reads the environment variable DOCKER_CONTENT_TRUST of the scanning host, not the image"},
	}
}

// UncoveredCode is a Dockle code with no ConUnit counterpart in the mapping.
type UncoveredCode struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// UncoveredCodes lists the catalog codes that no ConUnit check maps to, each
// with the reason: excluded as host-dependent, or documented by Dockle as not
// supported.
func UncoveredCodes() []UncoveredCode {
	mapped := MappedCodes()
	excluded := map[string]string{}
	for _, e := range ExcludedCodes() {
		excluded[e.Code] = e.Reason
	}
	var out []UncoveredCode
	for _, c := range DockleCatalog() {
		if mapped[c.Code] {
			continue
		}
		reason := excluded[c.Code]
		if reason == "" {
			reason = c.Note
		}
		out = append(out, UncoveredCode{Code: c.Code, Reason: reason})
	}
	return out
}

// IsExcluded reports whether a code is excluded from the comparison.
func IsExcluded(code string) bool {
	for _, e := range ExcludedCodes() {
		if e.Code == code {
			return true
		}
	}
	return false
}

// KnownCode reports whether a code is part of the catalog.
func KnownCode(code string) bool {
	for _, c := range DockleCatalog() {
		if c.Code == code {
			return true
		}
	}
	return false
}
