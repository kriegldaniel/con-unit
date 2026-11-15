package conunit

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/con-unit/con-unit/pkg/oci"
)

// historyStep is one recorded RUN step of the image history with the commands
// its script runs.
type historyStep struct {
	// Entry is the 1-based position of the step in the image history.
	Entry    int
	Commands []simpleCommand
}

// historyScan is what the history checks read: the RUN steps and, when the
// history cannot be fully trusted, the reason.
type historyScan struct {
	Steps []historyStep
	// Issue is empty when the history is complete and well formed. A check
	// that finds nothing then passes. Otherwise a check that finds nothing is
	// UNVERIFIED (EVIDENCE_INCOMPLETE), because a step it could not read may
	// hold the finding.
	Issue string
}

// metadataInstructions are the instructions that change the image
// configuration or add files. Their text is not a shell script, so the history
// checks do not scan them.
var metadataInstructions = map[string]bool{
	"ADD": true, "ARG": true, "CMD": true, "COPY": true, "ENTRYPOINT": true,
	"ENV": true, "EXPOSE": true, "FROM": true, "HEALTHCHECK": true,
	"LABEL": true, "MAINTAINER": true, "ONBUILD": true, "SHELL": true,
	"STOPSIGNAL": true, "USER": true, "VOLUME": true, "WORKDIR": true,
}

var (
	buildArgPrefix = regexp.MustCompile(`^\|\d+\s+`)
	// shellInvocation finds the first shell command word followed by a flag, the
	// start of the script behind a build-argument prefix.
	shellInvocation = regexp.MustCompile(`(?:^|\s)((?:\S*/)?(?:sh|bash|dash|ash|zsh|ksh)\s+-)`)
)

// runScript returns the shell script of a history entry when the entry is a
// RUN step. It reads the forms that builders write:
//
//	legacy shell form    /bin/sh -c <script>
//	legacy with ARGs     |1 NAME=value /bin/sh -c <script>
//	legacy metadata      /bin/sh -c #(nop)  <INSTRUCTION> ...        (not a RUN)
//	BuildKit             RUN <script> # buildkit
//	BuildKit with shell  RUN /bin/sh -c <script> # buildkit
//	bare command         <script>                                   (some builders)
//
// A metadata instruction, a comment line (the Debian base image records one)
// and an empty entry give false.
func runScript(createdBy string) (string, bool) {
	text := strings.TrimSpace(createdBy)
	if text == "" {
		return "", false
	}
	if match := buildArgPrefix.FindString(text); match != "" {
		text = strings.TrimSpace(text[len(match):])
		// The prefix is followed by one NAME=value word per build argument and
		// then by the shell invocation. A value can hold spaces, so the script
		// is located by its shell, and only without one are the assignment
		// words dropped.
		if loc := shellInvocation.FindStringSubmatchIndex(text); loc != nil {
			text = text[loc[2]:]
		} else {
			for {
				word, rest, _ := strings.Cut(text, " ")
				if !assignmentWord.MatchString(word) {
					break
				}
				text = strings.TrimSpace(rest)
			}
		}
	}
	text = stripShellWrapper(text)
	if strings.HasPrefix(text, "#(nop)") {
		return "", false
	}
	if rest, ok := strings.CutPrefix(text, "RUN "); ok {
		text = strings.TrimSpace(rest)
		// Flags of RUN, such as --mount=type=cache,target=/x or --network=none.
		for strings.HasPrefix(text, "--") {
			_, rest, _ := strings.Cut(text, " ")
			text = strings.TrimSpace(rest)
		}
		text = stripShellWrapper(text)
	} else {
		first, _, _ := strings.Cut(text, " ")
		if metadataInstructions[first] {
			return "", false
		}
	}
	if text == "" || strings.HasPrefix(text, "#") {
		return "", false
	}
	return text, true
}

// stripShellWrapper removes a leading "<shell> [options] -c " so that the rest
// is the script. Builders write the script after -c without quoting, as one
// text, so it cannot be recovered as a single shell word.
func stripShellWrapper(text string) string {
	fields := strings.Fields(text)
	if len(fields) < 3 || !isShellName(path.Base(fields[0])) {
		return text
	}
	consumed := 1
	for consumed < len(fields) {
		field := fields[consumed]
		if !strings.HasPrefix(field, "-") {
			if consumed > 1 && fields[consumed-1] == "-o" {
				consumed++
				continue
			}
			return text
		}
		consumed++
		if shellFlagWithC.MatchString(field) {
			return skipFields(text, consumed)
		}
	}
	return text
}

// skipFields returns the text after its first n whitespace separated fields.
func skipFields(text string, n int) string {
	rest := strings.TrimLeft(text, " \t\r\n")
	for i := 0; i < n; i++ {
		end := strings.IndexAny(rest, " \t\r\n")
		if end < 0 {
			return ""
		}
		rest = strings.TrimLeft(rest[end:], " \t\r\n")
	}
	return rest
}

// historyEntries returns the history of an index, preferring the form with
// the empty-layer flag, as the index does itself.
func historyEntries(index *oci.FilesystemIndex) []oci.HistoryEntry {
	if len(index.History) > 0 {
		return index.History
	}
	entries := make([]oci.HistoryEntry, 0, len(index.HistoryEntries))
	for _, createdBy := range index.HistoryEntries {
		entries = append(entries, oci.HistoryEntry{CreatedBy: createdBy})
	}
	return entries
}

// scanHistory extracts the RUN steps of the index history and judges whether
// the history is complete enough to prove the absence of a finding.
func scanHistory(index *oci.FilesystemIndex) historyScan {
	scan := historyScan{}
	entries := historyEntries(index)
	if index.HistoryEvidenceIssue != "" {
		scan.Issue = index.HistoryEvidenceIssue
	} else if len(entries) == 0 {
		scan.Issue = "the image history holds no entries"
	}
	for i, entry := range entries {
		if strings.TrimSpace(entry.CreatedBy) == "" {
			if scan.Issue == "" {
				scan.Issue = fmt.Sprintf("history entry %d has an empty command", i+1)
			}
			continue
		}
		script, isRun := runScript(entry.CreatedBy)
		if !isRun {
			continue
		}
		commands, malformed := parseCommands(script)
		if malformed && scan.Issue == "" {
			scan.Issue = fmt.Sprintf("history entry %d ends inside a quote or a here-document", i+1)
		}
		scan.Steps = append(scan.Steps, historyStep{Entry: i + 1, Commands: commands})
	}
	return scan
}

// aptSubcommand returns the subcommand of an apt-get or apt command: the first
// word that is not an option. The options -o, -c and -t take the next word as
// their value. It returns false for any other command.
func aptSubcommand(cmd simpleCommand) (string, bool) {
	switch cmd.base() {
	case "apt-get", "apt":
	default:
		return "", false
	}
	for i := 0; i < len(cmd.Args); i++ {
		arg := cmd.Args[i]
		switch {
		case arg == "-o" || arg == "-c" || arg == "-t" || arg == "--option" || arg == "--config-file" || arg == "--target-release":
			i++
		case strings.HasPrefix(arg, "-"):
		default:
			return arg, true
		}
	}
	return "", false
}

// commandFinding is one command that a history check reports.
type commandFinding struct {
	Entry   int
	Command string
}

func (f commandFinding) String() string {
	return fmt.Sprintf("history entry %d: %s", f.Entry, excerpt(f.Command, 80))
}

// excerpt shortens text to at most limit runes and collapses white space.
func excerpt(text string, limit int) string {
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit]) + "..."
}

// describeFindings lists up to five findings and counts the rest.
func describeFindings(findings []commandFinding) string {
	const shown = 5
	parts := make([]string, 0, shown)
	for i, finding := range findings {
		if i == shown {
			break
		}
		parts = append(parts, finding.String())
	}
	text := strings.Join(parts, "; ")
	if len(findings) > shown {
		text += fmt.Sprintf("; and %d more", len(findings)-shown)
	}
	return text
}

// updatesWithoutInstall finds the apt index updates that no later install or
// upgrade of the same step follows. apt-get and apt share one package index
// and count as one package manager.
func updatesWithoutInstall(steps []historyStep) []commandFinding {
	var findings []commandFinding
	for _, step := range steps {
		for i, cmd := range step.Commands {
			if sub, ok := aptSubcommand(cmd); !ok || sub != "update" {
				continue
			}
			combined := false
			for _, later := range step.Commands[i+1:] {
				if sub, ok := aptSubcommand(later); ok && (sub == "install" || sub == "upgrade") {
					combined = true
					break
				}
			}
			if !combined {
				findings = append(findings, commandFinding{Entry: step.Entry, Command: cmd.String()})
			}
		}
	}
	return findings
}

// sudoCommands finds the commands whose command word is sudo.
func sudoCommands(steps []historyStep) []commandFinding {
	var findings []commandFinding
	for _, step := range steps {
		for _, cmd := range step.Commands {
			if cmd.base() == "sudo" {
				findings = append(findings, commandFinding{Entry: step.Entry, Command: cmd.String()})
			}
		}
	}
	return findings
}

// distUpgradeCommands finds the apt-get and apt commands with the subcommand
// dist-upgrade.
func distUpgradeCommands(steps []historyStep) []commandFinding {
	var findings []commandFinding
	for _, step := range steps {
		for _, cmd := range step.Commands {
			if sub, ok := aptSubcommand(cmd); ok && sub == "dist-upgrade" {
				findings = append(findings, commandFinding{Entry: step.Entry, Command: cmd.String()})
			}
		}
	}
	return findings
}
