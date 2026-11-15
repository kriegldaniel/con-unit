// Package clilog provides the structured, human readable console output used
// by the evaluation tools. Every line starts with a fixed-width level tag so
// logs are easy to scan; the tag is colored only when the destination is a
// terminal and NO_COLOR is unset.
package clilog

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Logger writes tagged lines to a writer.
type Logger struct {
	w     io.Writer
	color bool
}

// New returns a logger for w. Color is enabled only for terminals.
func New(w io.Writer) *Logger {
	return &Logger{w: w, color: isTerminal(w) && os.Getenv("NO_COLOR") == ""}
}

// NewPlain returns a logger that never emits escape sequences.
func NewPlain(w io.Writer) *Logger { return &Logger{w: w} }

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
)

// tagWidth is the visible width every level tag is padded to.
const tagWidth = 10

func (l *Logger) tag(name, code string) string {
	plain := fmt.Sprintf("[%s]", name)
	pad := strings.Repeat(" ", max(0, tagWidth-len(plain)))
	if l.color {
		return bold + code + plain + reset + pad
	}
	return plain + pad
}

func (l *Logger) line(name, code, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.w, "%s %s\n", l.tag(name, code), msg)
}

// Info logs a neutral progress line.
func (l *Logger) Info(format string, args ...any) { l.line("INFO", cyan, format, args...) }

// Success logs a completed step.
func (l *Logger) Success(format string, args ...any) { l.line("SUCCESS", green, format, args...) }

// Warn logs a condition that does not stop the run but needs attention.
func (l *Logger) Warn(format string, args ...any) { l.line("WARNING", yellow, format, args...) }

// Error logs a failure.
func (l *Logger) Error(format string, args ...any) { l.line("ERROR", red, format, args...) }

// Section prints a visible heading.
func (l *Logger) Section(title string) {
	rule := strings.Repeat("-", len(title)+4)
	if l.color {
		fmt.Fprintf(l.w, "\n%s%s%s\n%s  %s%s\n%s%s%s\n", bold, rule, reset, bold, title, reset, bold, rule, reset)
		return
	}
	fmt.Fprintf(l.w, "\n%s\n  %s\n%s\n", rule, title, rule)
}
