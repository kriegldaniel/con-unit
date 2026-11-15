package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/spec"
)

func TestRulesCommandPrintsTheCommittedReference(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runRulesCommand(nil, &stdout, &stderr); code != spec.ExitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	committed, err := os.ReadFile(filepath.Join("..", "..", "docs", "RULES.md"))
	if err != nil {
		t.Fatalf("docs/RULES.md: %v", err)
	}
	if stdout.String() != string(committed) {
		t.Fatal("`con-unit rules` differs from docs/RULES.md. Regenerate it with: go run ./cmd/con-unit rules > docs/RULES.md")
	}
	if stderr.Len() != 0 {
		t.Errorf("the command must not write to stderr, got %q", stderr.String())
	}
}

func TestRulesCommandRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runRulesCommand([]string{"--format", "json"}, &stdout, &stderr); code != spec.ExitUsage {
		t.Fatalf("exit code = %d, want %d", code, spec.ExitUsage)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "takes no arguments") {
		t.Errorf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
