package clilog

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainOutputHasFixedWidthTagsAndNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	l := NewPlain(&buf)
	l.Info("loaded %d images", 3)
	l.Warn("careful")
	l.Error("broken")
	l.Success("done")
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("plain logger must not emit escape sequences: %q", out)
	}
	want := []string{
		"[INFO]     loaded 3 images",
		"[WARNING]  careful",
		"[ERROR]    broken",
		"[SUCCESS]  done",
	}
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line != want[i] {
			t.Errorf("line %d = %q, want %q", i, line, want[i])
		}
	}
}

func TestNonTerminalWriterDisablesColor(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Info("x")
	if strings.Contains(buf.String(), "\x1b") {
		t.Errorf("buffer destination must not be colored: %q", buf.String())
	}
}

func TestColoredTagsKeepVisibleWidth(t *testing.T) {
	var buf bytes.Buffer
	l := &Logger{w: &buf, color: true}
	l.Warn("m")
	out := buf.String()
	if !strings.Contains(out, "\x1b[") {
		t.Fatalf("expected color codes: %q", out)
	}
	// Strip escapes and check the message starts at the same column as the
	// uncolored form.
	plain := stripANSI(out)
	if plain != "[WARNING]  m\n" {
		t.Errorf("visible text = %q", plain)
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
