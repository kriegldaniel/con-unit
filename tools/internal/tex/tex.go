// Package tex holds the LaTeX text helpers shared by the generators.
package tex

import (
	"fmt"
	"strings"
)

// NotAvailable is printed where a statistic is undefined, for example the
// agreement of a check that was verified in no common image.
const NotAvailable = "n/a"

// Escape escapes text for use in LaTeX text mode.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\textbackslash{}`)
		case '&', '%', '$', '#', '_', '{', '}':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '~':
			b.WriteString(`\textasciitilde{}`)
		case '^':
			b.WriteString(`\textasciicircum{}`)
		case '<':
			b.WriteString(`\textless{}`)
		case '>':
			b.WriteString(`\textgreater{}`)
		case '|':
			b.WriteString(`\textbar{}`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Texttt returns s escaped and set in typewriter font.
func Texttt(s string) string { return `\texttt{` + Escape(s) + `}` }

// Percent formats a proportion in [0,1] as a percentage with one decimal and
// an escaped percent sign.
func Percent(x float64) string { return fmt.Sprintf(`%.1f\%%`, 100*x) }

// Float formats a number with two decimals, or NotAvailable when not defined.
func Float(x float64, defined bool) string {
	if !defined {
		return NotAvailable
	}
	return fmt.Sprintf("%.2f", x)
}
