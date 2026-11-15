package main

import (
	"fmt"
	"io"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/spec"
)

// runRulesCommand prints the rule reference that is committed as
// docs/RULES.md. The text is generated from the rule catalog and the packs, so
// it needs no engine and no image.
func runRulesCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "error: 'rules' takes no arguments, got %q\n", args[0])
		return spec.ExitUsage
	}
	if _, err := io.WriteString(stdout, conunit.RulesMarkdown()); err != nil {
		fmt.Fprintf(stderr, "error: could not write the rule reference: %v\n", err)
		return spec.ExitIncomplete
	}
	return spec.ExitOK
}
