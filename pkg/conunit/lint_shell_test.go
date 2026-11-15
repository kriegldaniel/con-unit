package conunit

import (
	"reflect"
	"strings"
	"testing"
)

func commandStrings(script string) ([]string, bool) {
	commands, malformed := parseCommands(script)
	var out []string
	for _, command := range commands {
		out = append(out, command.String())
	}
	return out, malformed
}

func TestParseCommands(t *testing.T) {
	cases := []struct {
		name          string
		script        string
		want          []string
		wantMalformed bool
	}{
		// Separators.
		{"and list", "apt-get update && apt-get install -y curl", []string{"apt-get update", "apt-get install -y curl"}, false},
		{"all separators", "a; b || c | d & e && f", []string{"a", "b", "c", "d", "e", "f"}, false},
		{"newlines", "a\nb\n\nc", []string{"a", "b", "c"}, false},
		{"crlf newlines", "a\r\nb\r\n", []string{"a", "b"}, false},
		{"pipe with stderr", "a |& b", []string{"a", "b"}, false},
		{"tabs and spaces separate words", "set -eux; \tapt-get update; \tapt-get install -y x", []string{"set -eux", "apt-get update", "apt-get install -y x"}, false},
		{"redirection of stderr does not split", "a 2>&1 | b", []string{"a 2>&1", "b"}, false},
		{"ampersand redirection does not split", "a &> /dev/null && b", []string{"a &> /dev/null", "b"}, false},
		{"empty and blank scripts", "  \t \n ", nil, false},
		{"separators only", "&& ; ||", nil, false},

		// Quotes.
		{"double quotes protect separators", `echo "a && b; c | d"`, []string{"echo a && b; c | d"}, false},
		{"single quotes protect separators", `echo 'a && b; c | d' && x`, []string{"echo a && b; c | d", "x"}, false},
		{"single quotes keep backslashes", `echo 'a\nb'`, []string{`echo a\nb`}, false},
		{"escapes inside double quotes", `echo "say \"hi\" \$HOME \\ done"`, []string{`echo say "hi" $HOME \ done`}, false},
		{"a quoted command word is still the command", `"sudo" id`, []string{"sudo id"}, false},
		{"adjacent quotes join into one word", `echo 'a'"b"c`, []string{"echo abc"}, false},
		{"empty quotes are an empty word", `echo "" x`, []string{"echo  x"}, false},
		{"nested substitution inside double quotes stays one word", `dst="$(echo "$src" | tr -d 3)"; use`, []string{"use"}, false},

		// Backslashes and continuations.
		{"continuation joins lines", "apt-get \\\n  update", []string{"apt-get update"}, false},
		{"continuation without space joins words", "apt-get\\\nupdate", []string{"apt-getupdate"}, false},
		{"continuation with carriage return", "a \\\r\nb", []string{"a b"}, false},
		{"escaped semicolon is data", `echo a\;b`, []string{"echo a;b"}, false},
		{"escaped space is data", `echo a\ b`, []string{"echo a b"}, false},
		{"trailing backslash is ignored", `echo a\`, []string{"echo a"}, false},
		{"continuation inside double quotes", "echo \"a\\\nb\"", []string{"echo ab"}, false},

		// Comments.
		{"a comment line holds no command", "# sudo is only mentioned\napt-get update", []string{"apt-get update"}, false},
		{"a trailing builder marker is a comment", "apt-get update # buildkit", []string{"apt-get update"}, false},
		{"a hash inside a word is data", "echo a#b", []string{"echo a#b"}, false},
		{"a comment after a separator", "a;# b\nc", []string{"a", "c"}, false},
		{"quotes inside a comment do not matter", "a # it's not closed\nb", []string{"a", "b"}, false},

		// Command position.
		{"echo sudo is not sudo", "echo sudo", []string{"echo sudo"}, false},
		{"leading assignments are skipped", "FOO=bar BAZ=1 sudo id", []string{"sudo id"}, false},
		{"an assignment alone holds no command", "FOO=bar", nil, false},
		{"an assignment with a quoted value", `PS1="a b" sudo id`, []string{"sudo id"}, false},
		{"leading redirection is skipped", ">/dev/null apt-get update", []string{"apt-get update"}, false},
		{"a separate redirection target is skipped", "2> /tmp/err sudo id", []string{"sudo id"}, false},
		{"trailing redirection stays an argument", "echo x > f && sudo y", []string{"echo x > f", "sudo y"}, false},
		{"if then", "if sudo -n true; then echo ok; fi", []string{"sudo -n true", "echo ok", "fi"}, false},
		{"words after in are not commands", "for i in sudo x; do echo $i; done", []string{"for i in sudo x", "echo $i", "done"}, false},
		{"while and negation", "while ! sudo true; do sleep 1; done", []string{"sudo true", "sleep 1", "done"}, false},
		{"brace group", "{ sudo id; }", []string{"sudo id", "}"}, false},
		{"env wrapper", "env FOO=1 sudo id", []string{"sudo id"}, false},
		{"env with options", "env -i -u HOME sudo id", []string{"sudo id"}, false},
		{"exec wrapper", "exec sudo id", []string{"sudo id"}, false},
		{"nohup wrapper", "nohup sudo id", []string{"sudo id"}, false},
		{"time wrapper", "time sudo id", []string{"sudo id"}, false},
		{"command wrapper", "command sudo id", []string{"sudo id"}, false},
		{"command -v only describes", "command -v sudo >/dev/null", nil, false},
		{"which does not run", "which sudo || true", []string{"which sudo", "true"}, false},
		{"a path to the command", "/usr/bin/sudo -u app id", []string{"/usr/bin/sudo -u app id"}, false},

		// Nesting.
		{"sh -c script is parsed again", `sh -c "sudo id; echo hi"`, []string{"sh -c sudo id; echo hi", "sudo id", "echo hi"}, false},
		{"bash -lc script", `bash -lc 'apt-get update'`, []string{"bash -lc apt-get update", "apt-get update"}, false},
		{"shell options before -c", `/bin/bash -o pipefail -c "a && b"`, []string{"/bin/bash -o pipefail -c a && b", "a", "b"}, false},
		{"env in front of a shell", `env FOO=1 sh -c 'sudo id'`, []string{"sh -c sudo id", "sudo id"}, false},
		{"a shell without -c has no script", "sh install.sh", []string{"sh install.sh"}, false},
		{"command substitution starts a command", "x=$(sudo id)", []string{"sudo id"}, false},
		{"backticks start a command", "x=`sudo id`", []string{"sudo id"}, false},
		{"a subshell", "(sudo id) && b", []string{"sudo id", "b"}, false},
		{"a case branch", "case $x in a) sudo id;; esac", []string{"case $x in a", "sudo id", "esac"}, false},

		// Here-documents.
		{"body of a here-document is data", "cat <<EOF > /etc/x\nsudo hi\nEOF\napt-get update", []string{"cat > /etc/x", "apt-get update"}, false},
		{"quoted delimiter", "cat <<'EOF'\napt-get dist-upgrade\nEOF\nb", []string{"cat", "b"}, false},
		{"dash form strips tabs from the terminator", "cat <<-EOF\n\tsudo x\n\tEOF\nb", []string{"cat", "b"}, false},
		{"a shell here-document is a script", "sh <<EOF\nsudo id\nEOF", []string{"sh", "sudo id"}, false},
		{"a script that is itself a here-document", "<<EOF\nsudo id\nEOF", []string{"sudo id"}, false},
		{"a here-string is not a here-document", "cat <<< sudo", []string{"cat <<< sudo"}, false},

		// Evidence that cannot be read.
		{"unterminated double quote", `echo "unterminated`, []string{"echo unterminated"}, true},
		{"unterminated single quote", `echo 'unterminated && sudo id`, []string{"echo unterminated && sudo id"}, true},
		{"unterminated here-document", "cat <<EOF\nsudo id\n", []string{"cat"}, true},
		{"here-document without a delimiter", "cat <<\nx", []string{"cat", "x"}, true},
		{"malformed text inside a nested script", `sh -c 'echo "x'`, []string{`sh -c echo "x`, `echo x`}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, malformed := commandStrings(tc.script)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("commands = %q, want %q", got, tc.want)
			}
			if malformed != tc.wantMalformed {
				t.Errorf("malformed = %v, want %v", malformed, tc.wantMalformed)
			}
		})
	}
}

func TestParseCommandsBoundsNestingDepth(t *testing.T) {
	// Each level wraps the previous script in sh -c. The parse must end and
	// must not read deeper than the limit.
	script := "sudo id"
	for i := 0; i < 10; i++ {
		script = "sh -c '" + strings.ReplaceAll(script, "'", `'\''`) + "'"
	}
	commands, _ := parseCommands(script)
	if len(commands) == 0 || len(commands) > maxShellDepth+2 {
		t.Fatalf("got %d commands for a 10 level nesting, want between 1 and %d", len(commands), maxShellDepth+2)
	}
}

func TestSimpleCommandBaseAndString(t *testing.T) {
	command := simpleCommand{Name: "/usr/bin/apt-get", Args: []string{"update", "-qq"}}
	if command.base() != "apt-get" {
		t.Errorf("base = %q, want apt-get", command.base())
	}
	if got := command.String(); got != "/usr/bin/apt-get update -qq" {
		t.Errorf("String = %q", got)
	}
}

func TestShiftOperatorIsNoHereDocument(t *testing.T) {
	cases := []struct {
		name          string
		script        string
		wantSudo      bool
		wantMalformed bool
	}{
		{"arithmetic shift", "echo $((1<<3))", false, false},
		{"arithmetic shift with spaces", "x=$((1 << 20)); sudo id", true, false},
		{"a real here-document is still read", "cat <<EOF\nsudo id\nEOF", false, false},
		{"a here-document delimiter with letters and digits", "cat <<EOF2\nsudo id\nEOF2", false, false},
		{"a here-document that never ends is malformed", "cat <<END\nsudo id", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commands, malformed := parseCommands(tc.script)
			sudo := false
			for _, command := range commands {
				if command.base() == "sudo" {
					sudo = true
				}
			}
			if sudo != tc.wantSudo || malformed != tc.wantMalformed {
				t.Errorf("sudo = %v, malformed = %v, want %v and %v (commands %v)", sudo, malformed, tc.wantSudo, tc.wantMalformed, commands)
			}
		})
	}
}

// FuzzParseCommands runs its seeds as a normal test. The property is that no
// input makes the parser panic or run without end, whatever the quoting.
func FuzzParseCommands(f *testing.F) {
	for _, seed := range []string{
		"", "a && b", "echo 'x", `echo "x`, "cat <<EOF\nx", "a \\\n b", "$(sudo id)", "`a`", "((((",
		"sh -c 'sh -c \"sh -c x\"'", "a <<< b", "x=$((1<<3))", "# only a comment", "a;;b||c|&d",
		"RUN /bin/sh -c apt-get update # buildkit", "\x00\xff\xfe", "\\", "'", `"`, "<<", "<<-", "<<''",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, script string) {
		commands, _ := parseCommands(script)
		for _, command := range commands {
			_ = command.String()
			_ = command.base()
		}
	})
}
