package conunit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/oci"
)

func TestRunScript(t *testing.T) {
	cases := []struct {
		name      string
		createdBy string
		want      string
		wantRun   bool
	}{
		// RUN steps in the forms builders write.
		{"legacy shell form", "/bin/sh -c apt-get update && apt-get install -y curl", "apt-get update && apt-get install -y curl", true},
		{"legacy shell form with leading spaces", "  /bin/sh -c make  ", "make", true},
		{"legacy shell form with a compound flag", "/bin/sh -ec set -x; make", "set -x; make", true},
		{"legacy form with bash and pipefail", "/bin/bash -o pipefail -c curl -fsSL x | tar -x", "curl -fsSL x | tar -x", true},
		{"legacy form with a build argument", "|1 VERSION=1.2 /bin/sh -c apt-get install -y x", "apt-get install -y x", true},
		{"legacy form with two arguments, one with a space", "|2 NOTE=hello world B=z /bin/sh -c apt-get update", "apt-get update", true},
		{"legacy form with a zero argument prefix", "|0 /bin/sh -c make", "make", true},
		{"BuildKit RUN with its shell", "RUN /bin/sh -c set -eux; \tapt-get update # buildkit", "set -eux; \tapt-get update # buildkit", true},
		{"BuildKit RUN without a shell", "RUN apt-get update # buildkit", "apt-get update # buildkit", true},
		{"BuildKit RUN with flags", "RUN --mount=type=cache,target=/var/cache/apt --network=none apt-get update", "apt-get update", true},
		{"a bare command text", "bazel build //common:rootfs", "bazel build //common:rootfs", true},
		{"a script that only looks like an instruction", "USER=app make install", "USER=app make install", true},
		{"a shell without -c is no wrapper", "/bin/sh install.sh", "/bin/sh install.sh", true},

		// Entries that are not RUN steps.
		{"legacy metadata instruction", `/bin/sh -c #(nop)  CMD ["bash"]`, "", false},
		{"legacy ADD of the rootfs", "/bin/sh -c #(nop) ADD file:3c41cdb0a333e30d in / ", "", false},
		{"legacy metadata after build arguments", "|1 X=y /bin/sh -c #(nop)  ENV A=b", "", false},
		{"ENV", "ENV PATH=/usr/local/bin:/usr/bin", "", false},
		{"ARG", "ARG VERSION", "", false},
		{"COPY", "COPY app /app # buildkit", "", false},
		{"ADD", "ADD alpine-minirootfs.tar.gz / # buildkit", "", false},
		{"CMD", `CMD ["sudo" "app"]`, "", false},
		{"ENTRYPOINT", `ENTRYPOINT ["sudo"]`, "", false},
		{"HEALTHCHECK", "HEALTHCHECK CMD sudo -n true", "", false},
		{"VOLUME", "VOLUME [/data]", "", false},
		{"EXPOSE", "EXPOSE map[80/tcp:{}]", "", false},
		{"USER", "USER app", "", false},
		{"LABEL", "LABEL a=b", "", false},
		{"WORKDIR", "WORKDIR /app", "", false},
		{"ONBUILD", "ONBUILD RUN sudo make", "", false},
		{"SHELL", `SHELL ["/bin/bash" "-c"]`, "", false},
		{"a comment entry of the Debian base image", "# debian.sh --arch 'amd64' out/ 'bookworm' '@1793827419'", "", false},
		{"an empty entry", "", "", false},
		{"a blank entry", "  \t ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, isRun := runScript(tc.createdBy)
			if isRun != tc.wantRun || got != tc.want {
				t.Errorf("runScript(%q) = (%q, %v), want (%q, %v)", tc.createdBy, got, isRun, tc.want, tc.wantRun)
			}
		})
	}
}

func TestScanHistory(t *testing.T) {
	runEntry := func(script string) oci.HistoryEntry {
		return oci.HistoryEntry{CreatedBy: "RUN " + script + " # buildkit"}
	}
	meta := oci.HistoryEntry{CreatedBy: "ENV A=b", EmptyLayer: true}

	cases := []struct {
		name        string
		index       *oci.FilesystemIndex
		wantEntries []int
		wantIssue   string
	}{
		{"complete history keeps only the RUN steps, numbered from one",
			&oci.FilesystemIndex{History: []oci.HistoryEntry{meta, runEntry("a"), meta, runEntry("b")}}, []int{2, 4}, ""},
		{"only metadata is complete evidence", &oci.FilesystemIndex{History: []oci.HistoryEntry{meta}}, nil, ""},
		{"instruction text without the layer flag is read the same way",
			&oci.FilesystemIndex{HistoryEntries: []string{"ENV A=b", "RUN make # buildkit"}}, []int{2}, ""},
		{"no history at all", &oci.FilesystemIndex{}, nil, "holds no entries"},
		{"the issue of the index is passed on", &oci.FilesystemIndex{History: []oci.HistoryEntry{runEntry("a")}, HistoryEvidenceIssue: "OCI image config contains no history entries"}, []int{1}, "contains no history entries"},
		{"an empty command is malformed evidence", &oci.FilesystemIndex{History: []oci.HistoryEntry{runEntry("a"), {CreatedBy: "  "}}}, []int{1}, "history entry 2 has an empty command"},
		{"an unterminated quote is malformed evidence", &oci.FilesystemIndex{History: []oci.HistoryEntry{meta, runEntry(`echo "x`)}}, []int{2}, "history entry 2 ends inside a quote"},
		{"an unterminated here-document is malformed evidence", &oci.FilesystemIndex{History: []oci.HistoryEntry{{CreatedBy: "RUN cat <<EOF\nx"}}}, []int{1}, "ends inside a quote or a here-document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := scanHistory(tc.index)
			var entries []int
			for _, step := range scan.Steps {
				entries = append(entries, step.Entry)
			}
			if fmt.Sprint(entries) != fmt.Sprint(tc.wantEntries) {
				t.Errorf("steps = %v, want %v", entries, tc.wantEntries)
			}
			if tc.wantIssue == "" && scan.Issue != "" {
				t.Errorf("issue = %q, want none", scan.Issue)
			}
			if tc.wantIssue != "" && !strings.Contains(scan.Issue, tc.wantIssue) {
				t.Errorf("issue = %q, want it to contain %q", scan.Issue, tc.wantIssue)
			}
		})
	}
}

func TestAptSubcommand(t *testing.T) {
	cases := []struct {
		command string
		want    string
		wantOK  bool
	}{
		{"apt-get update", "update", true},
		{"apt update", "update", true},
		{"/usr/bin/apt-get update", "update", true},
		{"apt-get -y install curl", "install", true},
		{"apt-get -qq update", "update", true},
		{"apt-get --no-install-recommends install curl", "install", true},
		{"apt-get -o Acquire::Retries=3 update", "update", true},
		{"apt-get -o Dpkg::Options::=--force-confold -y dist-upgrade", "dist-upgrade", true},
		{"apt -t bookworm-backports install curl", "install", true},
		{"apt-get --option A=b update", "update", true},
		{"apt-get dist-clean", "dist-clean", true},
		{"apt-get", "", false},
		{"apt-get -y", "", false},
		{"aptitude update", "", false},
		{"apt-cache policy", "", false},
		{"apk update", "", false},
		{"echo apt-get update", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			commands, _ := parseCommands(tc.command)
			if len(commands) == 0 {
				t.Fatal("no command parsed")
			}
			got, ok := aptSubcommand(commands[0])
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("aptSubcommand(%q) = (%q, %v), want (%q, %v)", tc.command, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// stepsOf builds history steps from scripts, one RUN step per script.
func stepsOf(scripts ...string) []historyStep {
	steps := make([]historyStep, 0, len(scripts))
	for i, script := range scripts {
		commands, _ := parseCommands(script)
		steps = append(steps, historyStep{Entry: i + 1, Commands: commands})
	}
	return steps
}

func TestUpdatesWithoutInstall(t *testing.T) {
	cases := []struct {
		name    string
		scripts []string
		want    int
	}{
		{"update then install", []string{"apt-get update && apt-get install -y x"}, 0},
		{"update alone", []string{"apt-get update"}, 1},
		{"update, semicolon, install", []string{"apt-get update; apt-get install -y x"}, 0},
		{"update, newline, install", []string{"set -eux\napt-get update\napt-get install -y x"}, 0},
		{"update, continuation, install", []string{"apt-get update \\\n && apt-get install -y x"}, 0},
		{"install before update", []string{"apt-get install -y x && apt-get update"}, 1},
		{"a second update at the end", []string{"apt-get update && apt-get install -y a && apt-get update"}, 1},
		{"two updates each followed by an install", []string{"apt-get update && apt-get install a && apt-get update && apt-get install b"}, 0},
		{"apt on both sides", []string{"apt update && apt install -y x"}, 0},
		{"apt-get update then apt install share one index", []string{"apt-get update && apt install -y x"}, 0},
		{"upgrade counts", []string{"apt-get update && apt-get upgrade -y"}, 0},
		{"dist-upgrade does not count as an upgrade", []string{"apt-get update && apt-get dist-upgrade -y"}, 1},
		{"install in the next step does not count", []string{"apt-get update", "apt-get install -y x"}, 1},
		{"a pipe in between", []string{"apt-get update | tee log && apt-get install -y x"}, 0},
		{"options before the subcommand", []string{"apt-get -qq -o Acquire::Retries=3 update && apt-get -y install x"}, 0},
		{"the update is quoted", []string{`"apt-get" update`}, 1},
		{"nested shell with both", []string{`sh -c "apt-get update && apt-get install -y x"`}, 0},
		{"nested shell with an update alone", []string{`sh -c "apt-get update"`}, 1},
		{"echo of the words is no command", []string{"echo apt-get update"}, 0},
		{"apk is not covered", []string{"apk update && apk add x"}, 0},
		{"an update inside a here-document body is data", []string{"cat <<EOF\napt-get update\nEOF"}, 0},
		{"two steps, one defective", []string{"apt-get update && apt-get install -y x", "apt-get update"}, 1},
		{"no steps", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := updatesWithoutInstall(stepsOf(tc.scripts...)); len(got) != tc.want {
				t.Errorf("findings = %v, want %d", got, tc.want)
			}
		})
	}
}

func TestSudoCommands(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   int
	}{
		{"plain sudo", "sudo apt-get update", 1},
		{"sudo after a separator", "apt-get update && sudo apt-get install -y x", 1},
		{"sudo after a pipe", "echo x | sudo tee /etc/f", 1},
		{"a path to sudo", "/usr/bin/sudo -u app id", 1},
		{"sudo behind an assignment", "FOO=1 sudo id", 1},
		{"sudo behind env", "env FOO=1 sudo id", 1},
		{"sudo in a condition", "if sudo -n true; then echo ok; fi", 1},
		{"sudo in a nested shell", `bash -c "sudo id"`, 1},
		{"sudo in a subshell", "(sudo id)", 1},
		{"sudo in a command substitution", "x=$(sudo id)", 1},
		{"the word as an argument", "echo sudo", 0},
		{"installing the package", "apt-get install -y sudo", 0},
		{"asking where it is", "which sudo || true", 0},
		{"command -v", "command -v sudo >/dev/null", 0},
		{"sudoers file", "echo 'app ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", 0},
		{"visudo", "visudo -c", 0},
		{"sudo as a variable value", "SUDO=sudo make", 0},
		{"sudo in a comment", "make # sudo is not needed", 0},
		{"sudo in a here-document body", "cat <<EOF > /etc/motd\nuse sudo here\nEOF", 0},
		{"sudo in quoted text", `echo "run sudo id"`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sudoCommands(stepsOf(tc.script)); len(got) != tc.want {
				t.Errorf("findings = %v, want %d", got, tc.want)
			}
		})
	}
}

func TestDistUpgradeCommands(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   int
	}{
		{"apt-get", "apt-get dist-upgrade -y", 1},
		{"apt", "apt dist-upgrade", 1},
		{"option before the subcommand", "apt-get -y dist-upgrade", 1},
		{"after update", "apt-get update && apt-get -o Dpkg::Options::=--force-confold dist-upgrade -y", 1},
		{"dist-clean is not dist-upgrade", "apt-get dist-clean", 0},
		{"full-upgrade is not reported", "apt full-upgrade -y", 0},
		{"plain upgrade", "apt-get upgrade -y", 0},
		{"an echo of the words", "echo apt-get dist-upgrade", 0},
		{"another manager", "apk upgrade", 0},
		{"a here-document body is data", "cat <<'EOF'\napt-get dist-upgrade\nEOF", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := distUpgradeCommands(stepsOf(tc.script)); len(got) != tc.want {
				t.Errorf("findings = %v, want %d", got, tc.want)
			}
		})
	}
}

func TestFindingTextIsBoundedAndNamesTheEntry(t *testing.T) {
	long := "apt-get update " + strings.Repeat("x", 300)
	if got := excerpt(long, 80); len([]rune(got)) != 83 || !strings.HasSuffix(got, "...") {
		t.Errorf("excerpt = %q, want 80 runes and an ellipsis", got)
	}
	if got := excerpt("a \t b\n c", 80); got != "a b c" {
		t.Errorf("excerpt = %q, want collapsed white space", got)
	}
	var findings []commandFinding
	for i := 1; i <= 8; i++ {
		findings = append(findings, commandFinding{Entry: i, Command: "sudo id"})
	}
	text := describeFindings(findings)
	if !strings.Contains(text, "history entry 1: sudo id") || !strings.Contains(text, "history entry 5: sudo id") || strings.Contains(text, "history entry 6") {
		t.Errorf("describeFindings must list five entries: %q", text)
	}
	if !strings.HasSuffix(text, "and 3 more") {
		t.Errorf("describeFindings must count the rest: %q", text)
	}
	if got := describeFindings(findings[:2]); strings.Contains(got, "more") {
		t.Errorf("no count expected for two findings: %q", got)
	}
}

// FuzzRunScript runs its seeds as a normal test. No history text may make the
// step reader or the parser panic, and a text that is a RUN step must also
// survive the finders.
func FuzzRunScript(f *testing.F) {
	for _, seed := range []string{
		"", "RUN ", "RUN --mount=type=cache,target=/x", "|", "|1", "|1 A=b", "|2 A=b c=d /bin/sh -c x",
		"/bin/sh -c", "/bin/sh -c #(nop)", "/bin/bash -o -c", "#(nop) ADD file:x in /", "ENV A=b",
		"RUN /bin/sh -c apt-get update && sudo id # buildkit", "\x00", "RUN \"", "/bin/sh -c 'x",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, createdBy string) {
		script, isRun := runScript(createdBy)
		if !isRun {
			return
		}
		commands, _ := parseCommands(script)
		steps := []historyStep{{Entry: 1, Commands: commands}}
		_ = updatesWithoutInstall(steps)
		_ = sudoCommands(steps)
		_ = distUpgradeCommands(steps)
	})
}
