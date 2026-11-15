package analysis

import "strings"

var digitWords = [...]string{"Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"}

// RuleKey converts a rule ID to the letters-only key used in macro names, as
// fixed in docs/INTERFACE_V2.md section 2: hyphens and dots are removed and
// every digit is spelled out. SPEC-09 becomes SPECZeroNine, FS-10 becomes
// FSOneZero and CIS-4.6 becomes CISFourSix. Any other character is dropped.
func RuleKey(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
			b.WriteString(digitWords[r-'0'])
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			b.WriteRune(r)
		}
	}
	return b.String()
}
