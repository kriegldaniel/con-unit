package tex

import "testing"

func TestEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"test_name", `test\_name`},
		{"A & B", `A \& B`},
		{"100%", `100\%`},
		{"a#b$c{d}", `a\#b\$c\{d\}`},
		{`a\b`, `a\textbackslash{}b`},
		{"x~y^z", `x\textasciitilde{}y\textasciicircum{}z`},
		{"a->b", `a-\textgreater{}b`},
		{"a<b|c", `a\textless{}b\textbar{}c`},
		{"plain text 1.2", "plain text 1.2"},
	}
	for _, c := range cases {
		if got := Escape(c.in); got != c.want {
			t.Errorf("Escape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHelpers(t *testing.T) {
	if got := Texttt("NO_TRUST"); got != `\texttt{NO\_TRUST}` {
		t.Errorf("Texttt = %q", got)
	}
	if got := Percent(0.8125); got != `81.2\%` && got != `81.3\%` {
		t.Errorf("Percent = %q", got)
	}
	if Float(0.4, true) != "0.40" || Float(0.4, false) != NotAvailable {
		t.Error("Float must print two decimals or n/a")
	}
}
