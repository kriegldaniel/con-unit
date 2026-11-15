package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// synthResults classifies every case of the oracle with a fixed pattern that
// uses all nine classes, so the matrix can be checked without running any
// tool. The pattern is chosen per property and tool, like a real scope
// declaration: correct, defect not detected, clean control flagged, out of
// scope, UNVERIFIED or tool error on the defect, not run, and not evaluated.
func synthResults(o *Oracle) *Results {
	res := &Results{SchemaVersion: ResultsSchemaVersion, Tools: map[string]ToolInfo{}, Summary: map[string]ToolSummary{}}
	for _, tool := range o.Tools {
		res.Tools[tool] = ToolInfo{Available: true, Selected: true, Version: "1.0"}
	}
	mode := map[string]int{}
	for i, p := range o.PropertyOrder() {
		for j, tool := range o.Tools {
			mode[p+"/"+tool] = (i*3 + j*5 + i/4) % 10
		}
	}
	for _, c := range o.Cases {
		cr := CaseResult{ID: c.ID, Property: c.Property, DefectPresent: c.DefectPresent, Tools: map[string]ToolCaseResult{}}
		for _, tool := range o.Tools {
			var class string
			switch mode[c.Property+"/"+tool] {
			case 0, 1, 2, 3:
				class = pick(c.DefectPresent, ClassTP, ClassTN)
			case 4:
				class = pick(c.DefectPresent, ClassFN, ClassTN)
			case 5:
				class = pick(c.DefectPresent, ClassTP, ClassFP)
			case 6:
				class = ClassOutOfScope
			case 7:
				class = ClassNotRun
			case 9:
				class = pick(c.DefectPresent, ClassNotEvaluated, ClassTN)
			default:
				class = pick(c.DefectPresent, ClassUnverified, ClassToolError)
			}
			cr.Tools[tool] = ToolCaseResult{Class: class}
		}
		res.Cases = append(res.Cases, cr)
	}
	for _, tool := range o.Tools {
		res.Summary[tool] = summarize(tool, res.Cases)
	}
	return res
}

// allClasses lists every classification of the matrix.
var allClasses = []string{ClassTP, ClassTN, ClassFN, ClassFP, ClassOutOfScope, ClassNotRun, ClassToolError, ClassUnverified, ClassNotEvaluated}

func pick(first bool, a, b string) string {
	if first {
		return a
	}
	return b
}

// matrixRows returns the data rows of the matrix keyed by property.
func matrixRows(t *testing.T, o *Oracle, table string) map[string][]string {
	t.Helper()
	rows := map[string][]string{}
	for _, l := range strings.Split(table, "\n") {
		if !strings.HasPrefix(l, `\texttt{`) {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(l, ` \\`), " & ")
		prop := strings.TrimSuffix(strings.TrimPrefix(parts[0], `\texttt{`), `}`)
		rows[prop] = parts[1:]
	}
	if len(rows) != len(o.PropertyOrder()) {
		t.Fatalf("matrix has %d property rows, the corpus has %d properties", len(rows), len(o.PropertyOrder()))
	}
	return rows
}

var cellColorPattern = regexp.MustCompile(`^\\cellcolor\{[^}]*\}`)

// symbolsOf strips the shade and the footnote marker of a cell.
func symbolsOf(cell string) string {
	cell = cellColorPattern.ReplaceAllString(cell, "")
	cell = strings.TrimSuffix(cell, `\textsuperscript{a}`)
	cell = strings.TrimSuffix(cell, `\textsuperscript{b}`)
	return cell
}

func TestMatrixHasOneSymbolPerCase(t *testing.T) {
	o := loadRealOracle(t)
	res := synthResults(o)
	table := RenderTable(o, res)
	rows := matrixRows(t, o, table)
	byID := map[string]CaseResult{}
	for _, c := range res.Cases {
		byID[c.ID] = c
	}
	// The synthetic pattern must exercise every class, or this test proves less.
	seen := map[string]bool{}
	for _, c := range res.Cases {
		for _, tr := range c.Tools {
			seen[tr.Class] = true
		}
	}
	for _, class := range allClasses {
		if !seen[class] {
			t.Errorf("class %s does not occur in the synthetic results", class)
		}
	}
	for _, prop := range o.PropertyOrder() {
		cells := rows[prop]
		// Each tool has a defect and a control column. A tool that is out of
		// scope or not run for the property spans both columns in one cell.
		columns, idx := 0, 0
		for _, tool := range o.Tools {
			var defects []string
			control := ""
			for _, c := range o.CasesOf(prop) {
				class := byID[c.ID].Tools[tool].Class
				if c.DefectPresent {
					defects = append(defects, class)
				} else {
					control = class
				}
			}
			all := append(append([]string{}, defects...), control)
			if allEqual(all) && (all[0] == ClassOutOfScope || all[0] == ClassNotRun) {
				want := `\multicolumn{2}{c}{` + shade(classTone(all[0]), classSymbol(all[0])) + `}`
				if cells[idx] != want {
					t.Errorf("%s/%s: cell %q, want %q", prop, tool, cells[idx], want)
				}
				columns += 2
				idx++
				continue
			}
			var syms []string
			for _, d := range defects {
				syms = append(syms, classSymbol(d))
			}
			if got := symbolsOf(cells[idx]); got != strings.Join(syms, `\,`) {
				t.Errorf("%s/%s: defect cell shows %q, want one symbol per defect case %q", prop, tool, got, strings.Join(syms, `\,`))
			}
			if got := symbolsOf(cells[idx+1]); got != classSymbol(control) {
				t.Errorf("%s/%s: control cell shows %q, want %q", prop, tool, got, classSymbol(control))
			}
			columns += 2
			idx += 2
		}
		if columns != 2*len(o.Tools) || idx != len(cells) {
			t.Errorf("%s: row has %d columns in %d cells, want %d columns", prop, columns, len(cells), 2*len(o.Tools))
		}
	}
}

func TestMatrixKeepsTheSummaryCounts(t *testing.T) {
	o := loadRealOracle(t)
	res := synthResults(o)
	table := RenderTable(o, res)
	for label, cell := range map[string]func(ToolSummary) string{
		"Recall (in scope)":    func(s ToolSummary) string { return metricCell(s, s.Recall) },
		"False positives":      func(s ToolSummary) string { return metricCell(s, s.FalsePositiveRate) },
		"Out of scope (cases)": nil,
	} {
		var want []string
		for _, tool := range o.Tools {
			s := res.Summary[tool]
			if cell == nil {
				want = append(want, `\multicolumn{2}{c}{`+strconv.Itoa(s.Counts[ClassOutOfScope])+`/`+strconv.Itoa(len(res.Cases))+`}`)
				continue
			}
			want = append(want, `\multicolumn{2}{c}{`+cell(s)+`}`)
		}
		line := label + " & " + strings.Join(want, " & ") + ` \\`
		if !strings.Contains(table, line+"\n") {
			t.Errorf("summary row missing:\n%s", line)
		}
	}
}

func TestMatrixShadingAndSymbols(t *testing.T) {
	// Every class has its own symbol, so no meaning rests on color alone.
	symbols := map[string]string{}
	for _, class := range allClasses {
		s := classSymbol(class)
		if s == symbolUnknown {
			t.Errorf("class %s has no symbol", class)
		}
		if other, dup := symbols[s]; dup {
			t.Errorf("classes %s and %s share the symbol %s", other, class, s)
		}
		symbols[s] = class
	}
	if classSymbol("SOMETHING_ELSE") != symbolUnknown {
		t.Error("an unknown class must print the unknown symbol")
	}
	for class, want := range map[string]tone{
		ClassTP: toneGood, ClassTN: toneGood, ClassFN: toneBad, ClassFP: toneBad, ClassToolError: toneBad,
		ClassOutOfScope: toneNeutral, ClassNotRun: toneNeutral, ClassUnverified: toneNeutral, ClassNotEvaluated: toneNeutral,
	} {
		if got := classTone(class); got != want {
			t.Errorf("classTone(%s) = %d, want %d", class, got, want)
		}
	}
	for _, c := range []struct {
		classes []string
		want    tone
	}{
		{[]string{ClassTP}, toneGood},
		{[]string{ClassFN, ClassTP}, toneBad},
		{[]string{ClassTP, ClassTP}, toneGood},
		{[]string{ClassTP, ClassUnverified}, toneNeutral},
		{[]string{ClassTP, ClassNotEvaluated}, toneNeutral},
		{[]string{ClassFN, ClassNotEvaluated}, toneBad},
		{[]string{ClassOutOfScope}, toneNeutral},
		{nil, toneNeutral},
	} {
		if got := cellTone(c.classes); got != c.want {
			t.Errorf("cellTone(%v) = %d, want %d", c.classes, got, c.want)
		}
	}
	// UNVERIFIED and not evaluated are never counted as a pass: they are not
	// shaded as correct.
	for _, class := range []string{ClassUnverified, ClassNotEvaluated} {
		if classTone(class) == toneGood {
			t.Errorf("%s must not be shaded as a correct outcome", class)
		}
	}
	if classSymbol(ClassNotEvaluated) != `n/e` {
		t.Errorf("not evaluated symbol = %q", classSymbol(ClassNotEvaluated))
	}
}

func TestMatrixStructure(t *testing.T) {
	o := loadRealOracle(t)
	res := synthResults(o)
	table := RenderTable(o, res)
	if table != RenderTable(o, res) {
		t.Error("rendering is not deterministic")
	}
	lines := strings.Split(table, "\n")
	if !strings.HasPrefix(lines[0], "% Generated by tools/rq1") || !strings.HasPrefix(lines[1], `% Requires: \usepackage[table]{xcolor}`) {
		t.Errorf("header comments wrong: %q, %q", lines[0], lines[1])
	}
	for _, want := range []string{
		`\providecolor{cuPass}{HTML}{009E73}`, `\providecolor{cuFail}{HTML}{D55E00}`, `\providecolor{cuUnver}{HTML}{7F7F7F}`,
		"\\begin{table}[t]\n\\centering\n\\caption{", "\\label{tab:rq1_detection}\n", `\multicolumn{2}{c}{\textbf{ConUnit}}`,
		`\cmidrule(lr){2-3}\cmidrule(lr){4-5}\cmidrule(lr){6-7}\cmidrule(lr){8-9}\cmidrule(lr){10-11}`,
		`\textbf{Property} & \textbf{D} & \textbf{C} & \textbf{D} & \textbf{C}`,
		"\\bottomrule\n\\end{tabular}}\n", "\\end{table}\n",
		`\begin{tabular}{lcc@{\hspace{3pt}}cc@{\hspace{3pt}}cc@{\hspace{3pt}}cc@{\hspace{3pt}}cc}`,
		`\multicolumn{2}{c}{\textbf{Dockle}}`,
	} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q", want)
		}
	}
	// The caption states every symbol and the shading.
	caption := table[strings.Index(table, `\caption{`):strings.Index(table, `\label{`)]
	for _, want := range []string{symbolTP + ` TP`, symbolFN + ` FN (defect not detected)`, symbolFP + ` FP (clean control flagged)`, symbolTN + ` TN`, symbolOutOfScope + ` out of scope`,
		symbolUnverified + ` UNVERIFIED`, symbolNotEval + ` not evaluated by the tool`, symbolNotRun + ` not run`, symbolToolError + ` no usable verdict`, `D: defect cases, C: clean control`, `Shade: green correct, vermilion wrong, gray not scored`} {
		if !strings.Contains(caption, want) {
			t.Errorf("caption lacks %q", want)
		}
	}
	// The table is not scaled, has no preamble command and no double dash.
	for _, banned := range []string{`\resizebox`, `\scalebox`, `\usepackage`, `\newcommand`, `\tiny`, "--"} {
		for _, l := range lines {
			if strings.HasPrefix(l, "%") {
				continue
			}
			if strings.Contains(l, banned) {
				t.Errorf("table contains %q: %s", banned, l)
			}
		}
	}
	// Every shade is followed by a symbol, so a cell is never color alone.
	shaded := strings.Count(table, `\cellcolor{`)
	withSymbol := len(regexp.MustCompile(`\\cellcolor\{[^}]*\}(?:[^&\s\\}]|\\[a-zA-Z]+)`).FindAllString(table, -1))
	if shaded == 0 || shaded != withSymbol {
		t.Errorf("%d shaded cells, %d of them with a symbol", shaded, withSymbol)
	}
	// Footnotes and versions are kept.
	for _, want := range []string{"Versions: ", "ConUnit 1.0", "Hadolint 1.0", "Dockle 1.0"} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q", want)
		}
	}
}

// resultsWith classifies every case of the oracle with the class that
// classFor returns.
func resultsWith(o *Oracle, classFor func(tool string, c Case) string) *Results {
	res := &Results{SchemaVersion: ResultsSchemaVersion, Tools: map[string]ToolInfo{}, Summary: map[string]ToolSummary{}}
	for _, tool := range o.Tools {
		res.Tools[tool] = ToolInfo{Available: true, Selected: true, Version: "1.0"}
	}
	for _, c := range o.Cases {
		cr := CaseResult{ID: c.ID, Property: c.Property, DefectPresent: c.DefectPresent, Tools: map[string]ToolCaseResult{}}
		for _, tool := range o.Tools {
			cr.Tools[tool] = ToolCaseResult{Class: classFor(tool, c)}
		}
		res.Cases = append(res.Cases, cr)
	}
	for _, tool := range o.Tools {
		res.Summary[tool] = summarize(tool, res.Cases)
	}
	return res
}

// TestMatrixFootnoteListsTheNonDefaultPacks checks that the footnote names the
// packs that the ConUnit column really ran, not a fixed text.
func TestMatrixFootnoteListsTheNonDefaultPacks(t *testing.T) {
	o := loadRealOracle(t)
	correct := func(tool string, c Case) string { return pick(c.DefectPresent, ClassTP, ClassTN) }
	footnote := func(packs string) string {
		return `\textsuperscript{b} Run with a pack other than the hardening profile (` + packs + `).`
	}

	t.Run("hygiene and lint", func(t *testing.T) {
		table := RenderTable(o, resultsWith(o, correct))
		if !strings.Contains(table, footnote("hygiene, lint")) {
			t.Errorf("footnote lacks the two packs:\n%s", table)
		}
		// The marker sits on the defect cell of a lint property.
		row := matrixRows(t, o, table)["update-alone"]
		if !strings.HasSuffix(symbolsWithMarker(row[0]), `\textsuperscript{b}`) {
			t.Errorf("update-alone row of ConUnit = %q, want the pack marker", row[0])
		}
	})
	t.Run("only hygiene when ConUnit is out of scope for the lint properties", func(t *testing.T) {
		res := resultsWith(o, func(tool string, c Case) string {
			if tool == ToolConUnit && o.Properties[c.Property].Tools[ToolConUnit].Pack == "lint" {
				return ClassOutOfScope
			}
			return correct(tool, c)
		})
		table := RenderTable(o, res)
		if !strings.Contains(table, footnote("hygiene")) || strings.Contains(table, "hygiene, lint") {
			t.Errorf("footnote must list only hygiene:\n%s", table)
		}
	})
	t.Run("no footnote when ConUnit did not run", func(t *testing.T) {
		table := RenderTable(o, resultsWith(o, func(tool string, c Case) string {
			if tool == ToolConUnit {
				return ClassNotRun
			}
			return correct(tool, c)
		}))
		if strings.Contains(table, "textsuperscript{b}") {
			t.Error("no pack footnote expected when ConUnit did not run")
		}
	})
}

// symbolsWithMarker strips only the shade of a cell and keeps the markers.
func symbolsWithMarker(cell string) string {
	return cellColorPattern.ReplaceAllString(cell, "")
}

// findTeX returns pdflatex, honoring PDFLATEX, or "".
func findTeX() string {
	if p := os.Getenv("PDFLATEX"); p != "" {
		return p
	}
	if p, err := exec.LookPath("pdflatex"); err == nil {
		return p
	}
	return ""
}

const matrixTestDocument = `\documentclass[10pt,conference]{IEEEtran}
\usepackage[utf8]{inputenc}
\usepackage[table]{xcolor}
\usepackage{booktabs}
\usepackage{hyperref}
\begin{document}
\typeout{COLUMNWIDTH \the\columnwidth}
See Table~\ref{tab:rq1_detection}.
\let\centering\relax
\input{table_rq1_detection.tex}
\end{document}
`

// TestMatrixCompilesAtColumnWidth compiles the table in a minimal IEEEtran
// document. \centering is disabled, so a table wider than the column is an
// overfull box in the log. It runs without pdflatex, IEEEtran or colortbl.
func TestMatrixCompilesAtColumnWidth(t *testing.T) {
	tex := findTeX()
	if tex == "" {
		t.Skip("pdflatex not found; set PDFLATEX to compile the table")
	}
	o := loadRealOracle(t)
	hadolint, err := Analyze(o, "testdata/hadolint_only")
	if err != nil {
		t.Fatal(err)
	}
	for name, res := range map[string]*Results{"all classes": synthResults(o), "hadolint only": hadolint} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "table_rq1_detection.tex"), []byte(RenderTable(o, res)), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "doc.tex"), []byte(matrixTestDocument), 0o644); err != nil {
				t.Fatal(err)
			}
			var out []byte
			for pass := 0; pass < 2; pass++ {
				cmd := exec.Command(tex, "-interaction=nonstopmode", "-halt-on-error", "doc.tex")
				cmd.Dir = dir
				var err error
				if out, err = cmd.CombinedOutput(); err != nil {
					if regexp.MustCompile(`File .(IEEEtran\.cls|colortbl\.sty|booktabs\.sty). not found`).Match(out) {
						t.Skipf("TeX installation lacks a package of the test document")
					}
					t.Fatalf("pdflatex failed: %v\n%s", err, tail(string(out), 3000))
				}
			}
			log := string(out)
			for _, bad := range []string{"Overfull", "Underfull", "Undefined control", "LaTeX Warning", "Package xcolor Warning"} {
				if strings.Contains(log, bad) {
					t.Errorf("TeX log contains %q", bad)
				}
			}
		})
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
