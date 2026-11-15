package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Logger writes structured, scannable progress lines. Colors are used only
// when the destination is a terminal and NO_COLOR is not set.
type Logger struct {
	w     io.Writer
	color bool
}

// NewLogger creates a logger for w.
func NewLogger(w io.Writer) *Logger {
	color := false
	if f, ok := w.(*os.File); ok && os.Getenv("NO_COLOR") == "" {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			color = true
		}
	}
	return &Logger{w: w, color: color}
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

func (l *Logger) paint(code, text string) string {
	if !l.color {
		return text
	}
	return code + text + ansiReset
}

func (l *Logger) line(level, code, format string, args ...any) {
	stamp := time.Now().Format("15:04:05")
	fmt.Fprintf(l.w, "%s %s %s\n", stamp, l.paint(code, fmt.Sprintf("%-5s", level)), fmt.Sprintf(format, args...))
}

// Info logs a progress line.
func (l *Logger) Info(format string, args ...any) { l.line("INFO", ansiCyan, format, args...) }

// Ok logs a success line.
func (l *Logger) Ok(format string, args ...any) { l.line("OK", ansiGreen, format, args...) }

// Warn logs a warning line.
func (l *Logger) Warn(format string, args ...any) { l.line("WARN", ansiYellow, format, args...) }

// Error logs an error line.
func (l *Logger) Error(format string, args ...any) { l.line("ERROR", ansiRed, format, args...) }

// Section logs a bold heading line.
func (l *Logger) Section(format string, args ...any) {
	fmt.Fprintf(l.w, "\n%s\n", l.paint(ansiBold, fmt.Sprintf(format, args...)))
}
