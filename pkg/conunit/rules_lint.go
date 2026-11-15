package conunit

import (
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
)

// The checks of the lint pack are reimplemented from the documented behavior
// of Dockle v0.4.15 (CHECKPOINT.md and the checkpoint assessors in its source
// tree), not copied from it. Every Limits text states where this
// implementation departs from Dockle on purpose, because those departures show
// up as discordances when the two tools are run over the same images. All of
// them start as exploratory checks.
//
// Provenance of the references. The checkpoint codes are those of Dockle
// v0.4.15 (CHECKPOINT.md and the assessors of its source tree). The CIS-DI numbers of
// Dockle belong to its own checkpoint list, which refers to an older CIS Docker
// benchmark, so they identify a Dockle checkpoint and are not control numbers of any
// version of the benchmark. No check states a CIS control number (docs/DEVIATIONS.md,
// DEV-15).

// historyOracle is the shared description of how the history checks read the
// recorded build steps.
const historyOracle = "Reads the OCI image history. Only RUN steps are scanned: the legacy form '/bin/sh -c <script>' (also with a '|N NAME=value' build-argument prefix), the BuildKit form 'RUN <script> # buildkit' and a bare command text. " +
	"Metadata instructions (ENV, CMD, ENTRYPOINT, COPY, ADD, LABEL, HEALTHCHECK and so on) and comment entries are not scanned. " +
	"A script is split into simple commands on &&, ||, ;, |, a single &, parentheses, backticks and newlines, with quotes, comments, backslash continuations, here-documents and the script argument of sh -c handled. " +
	"A word counts as a command only in command position, after leading variable assignments, redirections, the keywords if, then, else, elif, do, while, until, ! and time, and the wrappers env, exec, command and nohup."

const historyEvidenceText = "The offending commands with the 1-based number of their history entry, at most five in the message with the count of the rest. The history text is not stored."

const historyLimits = "Sees only what the history records: squashed images, multi-stage builds, builds that strip the history and scripts that an entrypoint runs later are not seen. " +
	"The parse is a heuristic for shell text: variables that hold a command name, eval, xargs, find -exec, command substitution inside double quotes and aliases are not resolved. " +
	"UNVERIFIED (EVIDENCE_INCOMPLETE) when the history is missing, empty or malformed (an empty entry, an unterminated quote or here-document) and nothing was found. " +
	"The check is exploratory until adjudication shows adequate precision."

// listText joins a name list for the oracle text.
func listText(values []string) string { return strings.Join(values, ", ") }

// lintRuleCatalog lists the checks that the lint pack adds to the catalog of
// rules.go. They are kept in their own file so that the catalog of the
// hardening profile and the catalog of the lint pack evolve independently.
// RuleByID and Rules read both.
var lintRuleCatalog = []Rule{
	{
		ID: "SPEC-09", Name: spec09Name, Tier: spec.TierSpec,
		Meta: customRule(spec.ScopeMetadataDeclaration),
		Oracle: historyOracle + " A step fails when it runs apt-get or apt with the subcommand update and no later command of the same step runs install or upgrade of the same package manager. " +
			"apt-get and apt share one package index and count as one manager. Each update needs its own later install or upgrade. Corresponds to the Dockle checkpoint CIS-DI-0007.",
		Evidence: historyEvidenceText,
		Limits: "Covers the apt family only: apk, yum, dnf and zypper index updates are not seen. An install in a later RUN step does not count, which is the point of the check. dist-upgrade and full-upgrade do not count as an upgrade, as in Dockle. " +
			"Intended differences from Dockle v0.4.15, which splits a history line on && and on single spaces only: it finds an update in a line only when the words are separated by spaces, it reads words inside quoted text and arguments such as 'echo apt-get update', it scans every history entry including metadata instructions, " +
			"it does not recognize 'update;' as the word update because the semicolon stays on the word, and it stops at the first install or upgrade after the first update, so a second update at the end of a step is reported here and not there. " +
			historyLimits,
	},
	{
		ID: "SPEC-10", Name: spec10Name, Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   historyOracle + " A step fails when sudo, or a path ending in /sudo, is the command word of a simple command. Corresponds to the Dockle checkpoint DKL-DI-0001.",
		Evidence: historyEvidenceText,
		Limits: "Command position only: installing the package ('apt-get install sudo') and naming sudo as an argument ('echo sudo', 'which sudo', 'command -v sudo') are no findings, and neither is a sudo behind another wrapper such as xargs, find -exec or ssh. " +
			"Intended difference from Dockle v0.4.15, which matches the word sudo anywhere between spaces in the text of every history entry and so also reports those uses, metadata instructions included. A sudo that only an entrypoint script or a CMD runs is outside the history. " +
			historyLimits,
	},
	{
		ID: "SPEC-11", Name: spec11Name, Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   historyOracle + " A step fails when a simple command is apt-get or apt (or a path ending in either) whose subcommand is dist-upgrade. Options before the subcommand, such as -y and -o Name=value, are skipped. Corresponds to the Dockle checkpoint DKL-DI-0003.",
		Evidence: historyEvidenceText,
		Limits: "apt full-upgrade does the same work as dist-upgrade and is not reported, as in Dockle. Other package managers are not covered. " +
			"Intended difference from Dockle v0.4.15, which reports a history line when the words apt-get or apt and dist-upgrade occur together between two && separators, in any order and with any other words, so it also reports an echo of those words; here the subcommand must belong to a real apt-get or apt command. " +
			historyLimits,
	},
	{
		ID: "SPEC-12", Name: spec12Name, Tier: spec.TierSpec,
		Meta: customRule(spec.ScopeMetadataDeclaration),
		Oracle: "Reads the volumes that the image config declares (VOLUME instructions) from the engine inspection of the image. Each path is cleaned (repeated separators, dot and dot-dot components, a trailing slash). " +
			"Fails when a cleaned path is /dev, /proc or /sys or lies below one of them. Corresponds to the Dockle checkpoint DKL-DI-0002.",
		Evidence: "The offending volume paths as declared, sorted, in the message and in the evidence paths.",
		Limits: "Declared volumes only: mounts given at run time (docker run -v /sys:/sys) cannot be seen from the image, as Dockle also states. " +
			"Intended difference from Dockle v0.4.15, which compares each declared path with the three names exactly: a child such as /proc/sys and a spelling such as /proc/ are reported here and not there. " +
			"A declared path that is empty or not absolute cannot be placed in the tree, so when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE), as it is when the engine inspection data is unavailable. Exploratory.",
	},
	{
		ID: "SPEC-13", Name: spec13Name, Tier: spec.TierSpec,
		Meta: customRule(spec.ScopeMetadataDeclaration),
		Oracle: "Reads the image reference exactly as it was requested on the command line or in the dataset. Passes for a reference with a digest (whatever tag comes with it), for an image ID (64 hexadecimal characters, with or without the prefix sha256:) and for an explicit tag other than latest. " +
			"Fails when the reference has no tag and no digest, which the engine resolves to latest, or when the tag is latest. Corresponds to the Dockle checkpoint DKL-DI-0006.",
		Evidence: "The requested reference and how it pins the content, in the message.",
		Limits: "Judges the spelling of the request, not the image. An explicit tag such as 1.2 is still mutable, so a PASS for a tag does not say that the content cannot change; only a digest does. " +
			"A local archive has no image reference, so the result is UNVERIFIED (EVIDENCE_INCOMPLETE) for the tarball source, and for a reference that cannot be parsed. " +
			"Dockle v0.4.15 evaluates its latest-tag checkpoint only when it is given an image name, never when it reads an archive with --input, so a comparison over exported archives cannot reproduce this check. Like this check, Dockle reads a name without a tag as latest and does not report a digest-pinned reference. Exploratory.",
	},
	{
		ID: "FS-10", Name: fs10Name, Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Reads the final /etc/passwd and /etc/group (up to 1 MiB each, with whiteouts and replacements applied). Fails when two different account names share one UID in /etc/passwd, or two different group names share one GID in /etc/group. Corresponds to the Dockle checkpoint DKL-LI-0002.",
		Evidence: "The shared IDs with their names, sorted, in the message and in the evidence paths.",
		Limits: "A name that is listed twice with the same ID is one account and not a collision. Dockle v0.4.15 reports every repeated ID, that case included, takes the third field of every line without validating the record, and does not skip comment lines in /etc/passwd. " +
			"A shared ID can be intended, and the check cannot tell which. Only the two files are read: accounts that NSS modules, LDAP or the container runtime provide are not seen. " +
			"UNVERIFIED (EVIDENCE_INCOMPLETE) when either file is missing, not a regular file (a hard link included), oversized or malformed, or holds no records, and no collision was found in the part that was read. Exploratory.",
	},
	{
		ID: "FS-11", Name: fs11Name, Tier: spec.TierFilesystem,
		Meta: customRule(spec.ScopeImageContent),
		Oracle: "Looks at every path of the merged filesystem of the final image. Fails when a path has a component named " + listText(leftoverDirNames) + ", or when a non-directory entry is named " + listText(leftoverFileNames) + ". " +
			"Entries below a " + listText(leftoverSkipDirs) + " directory are skipped, while a leftover above such a directory is still reported. A matching directory is reported once, at its shallowest occurrence, and entries below a reported directory are not listed again. Corresponds to the Dockle checkpoint DKL-LI-0003.",
		Evidence: "The reported directories and files, sorted, in the message and in the evidence paths (at most 200; the message states the full count).",
		Limits: "Name based and case sensitive, so it also reports directories that are expected in a development image and empty ones, and it never judges content. " +
			"Intended differences from Dockle v0.4.15: Dockle sees regular files, symbolic links and hard links only, and reports a directory only through a file that is its direct child, so an empty directory or one that holds only subdirectories is reported here and not there. " +
			"Dockle applies its node_modules and vendor skip to directory matches only and tests the substring node_modules/ anywhere in the path, so it still reports a Dockerfile below node_modules, which is skipped here; here the skip compares whole components. " +
			"A file named .git (a submodule pointer) counts as a component here. A hard link counts as a file under its own name and its target is not needed. UNVERIFIED (EVIDENCE_INCOMPLETE) when the index holds no entries. Exploratory.",
	},
	{
		ID: "FS-12", Name: fs12Name, Tier: spec.TierFilesystem,
		Meta: customRule(spec.ScopeImageContent),
		Oracle: "Looks at every non-directory entry of the merged filesystem. Fails when the file name is one of " + listText(credentialFileNames) + ", or when its extension, taken from the last dot of the name, is one of " + listText(credentialExtensions) + ". " +
			"Findings under testdata, test, tests, fixtures, fixture, examples or example path components and Debian snakeoil files are fixture candidates (the rule of FS-06), counted separately; only the other findings fail the check. " +
			"Corresponds to the file name part of the Dockle checkpoint CIS-DI-0010.",
		Evidence: "Finding paths and fixture candidate paths, sorted (each list capped at 200 in the evidence; the message states the full counts).",
		Limits: "File names only: the content is not read, so an empty file and a documentation sample count, and a credential kept under another name is not seen (FS-06 reads the content of key files). " +
			"settings.py, credentials and database.yml are common names of files that hold no secret, so low precision is expected. Names and extensions are case sensitive, as in Dockle. A symbolic link or hard link named like a credential file counts under its own name. " +
			"Dockle v0.4.15 also matches NAME=value words of the build history for CIS-DI-0010 and can suppress names with accept-file options; that part is covered by SPEC-03 over the final environment, and this check has no suppression list besides the fixture rule. " +
			"No CIS control number is stated for this check. UNVERIFIED (EVIDENCE_INCOMPLETE) when the index holds no entries. Exploratory.",
	},
}
