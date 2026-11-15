package conunit

import (
	"path"
	"regexp"
	"strings"
)

// This file reads the command text of a recorded build step. It is not a shell
// and does not try to be one. It knows just enough of the syntax to answer one
// question reliably: which words are commands. A word is a command only in
// command position, so "echo sudo" holds the command echo and nothing else.
//
// What it handles:
//   - separators: &&, ||, ;, |, a single & and newlines end a simple command,
//     and so do parentheses, backticks and the opening of $( ... )
//   - quotes: single quotes keep everything, double quotes keep everything but
//     the escapes \" \\ \$ and \`, and a separator inside quotes does not split
//   - a backslash before a newline joins the lines, any other backslash quotes
//     the next character
//   - comments that start at the beginning of a word, up to the end of the line
//   - here-documents: the body is data, except when the command is a shell or
//     when the script itself is the here-document
//   - leading variable assignments, redirections, the keywords if, then, else,
//     elif, do, while, until, !, { and time, and the wrappers env, exec,
//     command and nohup in front of a command word
//   - the script argument of sh -c, bash -c and similar, parsed again
//
// What it does not handle: variables that hold a command name, aliases,
// functions, eval, xargs and find -exec, and any expansion. A text it cannot
// finish (an unterminated quote or here-document) is reported as malformed, so
// that a check can end UNVERIFIED instead of guessing.

// simpleCommand is one command of a script: the command word as written and the
// words after it, with quotes removed.
type simpleCommand struct {
	Name string
	Args []string
}

func (c simpleCommand) base() string { return path.Base(c.Name) }

// String joins the command with its arguments, for messages.
func (c simpleCommand) String() string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

// maxShellDepth bounds the nesting of sh -c scripts and here-document scripts.
const maxShellDepth = 4

// parseCommands splits a script into its simple commands, in order, with the
// scripts of nested shells inserted right after the command that runs them.
// malformed is true when the text ends inside a quote or a here-document.
func parseCommands(script string) (commands []simpleCommand, malformed bool) {
	lists, bad := lexShell(script, 0)
	commands = resolveCommands(lists, 0, &bad)
	return commands, bad
}

type heredoc struct {
	delimiter string
	stripTabs bool
	// asScript is true when the body is shell text: the owner of the
	// here-document is a shell or there is no owner.
	asScript bool
}

type lexer struct {
	text      string
	pos       int
	depth     int
	words     []string
	cur       strings.Builder
	inWord    bool
	commands  [][]string
	malformed bool
	pending   []heredoc
}

// lexShell cuts the text into commands, each a list of unquoted words.
func lexShell(text string, depth int) (commands [][]string, malformed bool) {
	lx := &lexer{text: text, depth: depth}
	lx.run()
	return lx.commands, lx.malformed
}

func (lx *lexer) flushWord() {
	if lx.inWord {
		lx.words = append(lx.words, lx.cur.String())
		lx.cur.Reset()
		lx.inWord = false
	}
}

func (lx *lexer) endCommand() {
	lx.flushWord()
	if len(lx.words) > 0 {
		lx.commands = append(lx.commands, lx.words)
		lx.words = nil
	}
}

func (lx *lexer) run() {
	t := lx.text
	for lx.pos < len(t) {
		c := t[lx.pos]
		switch {
		case c == '\\':
			lx.backslash()
		case c == '\'':
			lx.singleQuoted()
		case c == '"':
			lx.doubleQuoted()
		case c == '#' && !lx.inWord:
			for lx.pos < len(t) && t[lx.pos] != '\n' {
				lx.pos++
			}
		case c == '\n':
			lx.endCommand()
			lx.pos++
			lx.readHeredocBodies()
		case c == ';':
			lx.endCommand()
			lx.pos++
		case c == '&':
			lx.ampersand()
		case c == '|':
			lx.endCommand()
			lx.pos++
			if lx.pos < len(t) && (t[lx.pos] == '|' || t[lx.pos] == '&') {
				lx.pos++
			}
		case c == '(' || c == ')' || c == '`':
			lx.endCommand()
			lx.pos++
		case c == '$' && lx.pos+1 < len(t) && t[lx.pos+1] == '(':
			lx.endCommand()
			lx.pos += 2
		case c == '<' && strings.HasPrefix(t[lx.pos:], "<<<"):
			// A here-string is a redirection of one word, not a here-document.
			lx.cur.WriteString("<<<")
			lx.inWord = true
			lx.pos += 3
		case c == '<' && strings.HasPrefix(t[lx.pos:], "<<"):
			lx.heredocStart()
		case c == ' ' || c == '\t' || c == '\r':
			lx.flushWord()
			lx.pos++
		default:
			lx.cur.WriteByte(c)
			lx.inWord = true
			lx.pos++
		}
	}
	lx.endCommand()
	if len(lx.pending) > 0 {
		lx.malformed = true
	}
}

func (lx *lexer) backslash() {
	t := lx.text
	if lx.pos+1 >= len(t) {
		lx.pos++
		return
	}
	next := t[lx.pos+1]
	switch {
	case next == '\n':
		lx.pos += 2
	case next == '\r' && lx.pos+2 < len(t) && t[lx.pos+2] == '\n':
		lx.pos += 3
	default:
		lx.cur.WriteByte(next)
		lx.inWord = true
		lx.pos += 2
	}
}

func (lx *lexer) singleQuoted() {
	rest := lx.text[lx.pos+1:]
	lx.inWord = true
	end := strings.IndexByte(rest, '\'')
	if end < 0 {
		lx.malformed = true
		lx.cur.WriteString(rest)
		lx.pos = len(lx.text)
		return
	}
	lx.cur.WriteString(rest[:end])
	lx.pos += end + 2
}

func (lx *lexer) doubleQuoted() {
	t := lx.text
	lx.pos++
	lx.inWord = true
	for lx.pos < len(t) {
		c := t[lx.pos]
		if c == '\\' && lx.pos+1 < len(t) {
			switch e := t[lx.pos+1]; e {
			case '"', '\\', '$', '`':
				lx.cur.WriteByte(e)
				lx.pos += 2
			case '\n':
				lx.pos += 2
			default:
				lx.cur.WriteByte(c)
				lx.pos++
			}
			continue
		}
		if c == '"' {
			lx.pos++
			return
		}
		lx.cur.WriteByte(c)
		lx.pos++
	}
	lx.malformed = true
}

// ampersand handles &&, a lone & (background, so a separator) and the
// redirections &> and >& (which belong to the word).
func (lx *lexer) ampersand() {
	t := lx.text
	switch {
	case strings.HasPrefix(t[lx.pos:], "&&"):
		lx.endCommand()
		lx.pos += 2
	case (lx.pos+1 < len(t) && t[lx.pos+1] == '>') || (lx.inWord && lx.pos > 0 && (t[lx.pos-1] == '>' || t[lx.pos-1] == '<')):
		lx.cur.WriteByte('&')
		lx.inWord = true
		lx.pos++
	default:
		lx.endCommand()
		lx.pos++
	}
}

// heredocStart reads "<<[-]WORD" and queues the body to be read after the
// next newline. The operator and the delimiter are not words of the command.
func (lx *lexer) heredocStart() {
	lx.flushWord()
	t := lx.text
	i := lx.pos + 2
	strip := false
	if i < len(t) && t[i] == '-' {
		strip = true
		i++
	}
	for i < len(t) && (t[i] == ' ' || t[i] == '\t') {
		i++
	}
	var delimiter strings.Builder
scan:
	for i < len(t) {
		c := t[i]
		switch {
		case c == '\'' || c == '"':
			end := strings.IndexByte(t[i+1:], c)
			if end < 0 {
				lx.malformed = true
				i = len(t)
				break scan
			}
			delimiter.WriteString(t[i+1 : i+1+end])
			i += end + 2
		case c == '\\' && i+1 < len(t):
			delimiter.WriteByte(t[i+1])
			i += 2
		case strings.IndexByte(" \t\r\n;&|<>()", c) >= 0:
			break scan
		default:
			delimiter.WriteByte(c)
			i++
		}
	}
	if delimiter.Len() > 0 && strings.Trim(delimiter.String(), "0123456789") == "" {
		// A number after << is a shift in an arithmetic expression such as
		// $((1<<3)). A here-document delimiter that is only digits is too rare
		// to be worth reading a body that is not there.
		lx.cur.WriteString("<<")
		lx.inWord = true
		lx.pos += 2
		return
	}
	lx.pos = i
	if delimiter.Len() == 0 {
		lx.malformed = true
		return
	}
	asScript := len(lx.words) == 0
	for _, word := range lx.words {
		if isShellName(path.Base(word)) {
			asScript = true
		}
	}
	lx.pending = append(lx.pending, heredoc{delimiter: delimiter.String(), stripTabs: strip, asScript: asScript})
}

// readHeredocBodies consumes the bodies of the queued here-documents, which
// start on the line after the command that opened them.
func (lx *lexer) readHeredocBodies() {
	t := lx.text
	for len(lx.pending) > 0 {
		h := lx.pending[0]
		lx.pending = lx.pending[1:]
		var body strings.Builder
		found := false
		for lx.pos < len(t) {
			var line string
			if end := strings.IndexByte(t[lx.pos:], '\n'); end < 0 {
				line = t[lx.pos:]
				lx.pos = len(t)
			} else {
				line = t[lx.pos : lx.pos+end]
				lx.pos += end + 1
			}
			compare := strings.TrimSuffix(line, "\r")
			if h.stripTabs {
				compare = strings.TrimLeft(compare, "\t")
			}
			if compare == h.delimiter {
				found = true
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if !found {
			lx.malformed = true
		}
		if h.asScript && lx.depth < maxShellDepth {
			sub, bad := lexShell(body.String(), lx.depth+1)
			lx.commands = append(lx.commands, sub...)
			if bad {
				lx.malformed = true
			}
		}
	}
}

var (
	assignmentWord  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=`)
	redirectionHead = regexp.MustCompile(`^(?:[0-9]+)?(?:<<<|&>>|&>|>>|>\||>&|<&|<>|>|<)`)
	shellFlagWithC  = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)
)

// reservedPrefix are the words that can stand in front of a command word and
// are not commands themselves.
var reservedPrefix = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true,
	"do": true, "while": true, "until": true,
	"!": true, "{": true, "time": true,
	"exec": true, "nohup": true, "builtin": true,
}

func isShellName(name string) bool {
	switch name {
	case "sh", "bash", "dash", "ash", "zsh", "ksh":
		return true
	}
	return false
}

// commandOf finds the command word of a list of words: the first word that is
// not an assignment, a redirection, a reserved word or a wrapper. It returns
// false when the list holds no command, as in "FOO=bar" or "command -v sudo".
func commandOf(words []string) (simpleCommand, bool) {
	i := 0
	for i < len(words) {
		w := words[i]
		switch {
		case assignmentWord.MatchString(w):
			i++
		case redirectionHead.MatchString(w):
			if redirectionHead.FindString(w) == w {
				i += 2
			} else {
				i++
			}
		case reservedPrefix[w]:
			i++
		case w == "env":
			i++
			for i < len(words) && strings.HasPrefix(words[i], "-") {
				switch words[i] {
				case "-u", "-C", "--unset", "--chdir":
					i++
				}
				i++
			}
		case w == "command":
			i++
			for i < len(words) && strings.HasPrefix(words[i], "-") {
				if strings.ContainsAny(words[i], "vV") {
					return simpleCommand{}, false
				}
				i++
			}
		default:
			return simpleCommand{Name: w, Args: words[i+1:]}, true
		}
	}
	return simpleCommand{}, false
}

// shellScriptArg returns the script that a shell invocation runs, the word
// after the -c style flag.
func shellScriptArg(args []string) (string, bool) {
	for i, arg := range args {
		if shellFlagWithC.MatchString(arg) && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func resolveCommands(lists [][]string, depth int, malformed *bool) []simpleCommand {
	var out []simpleCommand
	for _, words := range lists {
		cmd, ok := commandOf(words)
		if !ok {
			continue
		}
		out = append(out, cmd)
		if depth < maxShellDepth && isShellName(cmd.base()) {
			if script, found := shellScriptArg(cmd.Args); found {
				sub, bad := lexShell(script, depth+1)
				if bad {
					*malformed = true
				}
				out = append(out, resolveCommands(sub, depth+1, malformed)...)
			}
		}
	}
	return out
}
