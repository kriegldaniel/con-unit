package reporter

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// ANSI color escape codes for high-clarity terminal rendering
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

// ConsoleOptions controls optional detail in human-readable output.
type ConsoleOptions struct {
	Verbose bool
}

// PrintConsole writes a compact, human-readable report.
func PrintConsole(w io.Writer, res *spec.SuiteResult) {
	PrintConsoleWithOptions(w, res, ConsoleOptions{})
}

// PrintConsoleWithOptions writes a compact report, or includes all check
// details when Verbose is enabled.
func PrintConsoleWithOptions(w io.Writer, res *spec.SuiteResult, options ConsoleOptions) {
	if res == nil {
		fmt.Fprintln(w, "ConUnit: no suite result")
		return
	}

	useColor := consoleColorEnabled(w)
	status := spec.OutcomePass
	if res.Failed > 0 {
		status = spec.OutcomeFail
	} else if res.Unverified > 0 {
		status = spec.OutcomeUnverified
	}

	fmt.Fprintln(w, styleConsole("╭─ CONUNIT · IMAGE REPORT ─────────────────────────────────────", ansiBold+ansiCyan, useColor))
	fmt.Fprintf(w, "│ IMAGE      %s\n", res.ImageName)
	fmt.Fprintf(w, "│ STATUS     %s\n", consoleOutcomeTag(status, useColor))
	fmt.Fprintf(w, "│ SUITE      %s\n", res.SuiteName)
	if res.ImageDigest != "" || res.Platform != "" {
		fmt.Fprintf(w, "│ IDENTITY   %s", res.ImageDigest)
		if res.Platform != "" {
			fmt.Fprintf(w, " (%s)", res.Platform)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, styleConsole("├─ SUMMARY ─────────────────────────────────────────────────────", ansiBold+ansiCyan, useColor))
	fmt.Fprintf(w, "│  %s %d/%d checks passed · %.1f%%\n",
		consoleOutcomeTagPadded(spec.OutcomePass, useColor),
		res.Passed,
		res.Total,
		calculatePassRate(res.Passed, res.Total),
	)
	if res.Failed > 0 {
		fmt.Fprintf(w, "│  %s %d checks need attention\n", consoleOutcomeTagPadded(spec.OutcomeFail, useColor), res.Failed)
	}
	if res.Unverified > 0 {
		fmt.Fprintf(w, "│  %s %d checks need evidence\n", consoleOutcomeTagPadded(spec.OutcomeUnverified, useColor), res.Unverified)
	}
	fmt.Fprintf(w, "│  DURATION       %s\n", res.Duration.Round(time.Millisecond))
	fmt.Fprintln(w, styleConsole("╰───────────────────────────────────────────────────────────────", ansiDim, useColor))

	printConsoleSection(w, "PASSED CHECKS", spec.OutcomePass, res.Passed, res.Results, options, useColor)
	printConsoleSection(w, "FAILURES", spec.OutcomeFail, res.Failed, res.Results, options, useColor)
	printConsoleSection(w, "UNVERIFIED", spec.OutcomeUnverified, res.Unverified, res.Results, options, useColor)
}

func consoleOutcomeTag(outcome spec.Outcome, useColor bool) string {
	return styleConsole(consoleOutcomeTagText(outcome), ansiBold+consoleOutcomeColor(outcome), useColor)
}

func consoleOutcomeTagPadded(outcome spec.Outcome, useColor bool) string {
	return styleConsole(fmt.Sprintf("%-13s", consoleOutcomeTagText(outcome)), ansiBold+consoleOutcomeColor(outcome), useColor)
}

func consoleOutcomeTagText(outcome spec.Outcome) string {
	return "[ " + string(outcome) + " ]"
}

func consoleOutcomeColor(outcome spec.Outcome) string {
	switch outcome {
	case spec.OutcomePass:
		return ansiGreen
	case spec.OutcomeFail:
		return ansiRed
	case spec.OutcomeUnverified:
		return ansiYellow
	default:
		return ansiDim
	}
}

func printConsoleSection(w io.Writer, title string, outcome spec.Outcome, count int, results []spec.TestResult, options ConsoleOptions, useColor bool) {
	if count == 0 {
		return
	}

	sectionHeader := fmt.Sprintf("╭─ %s · %d ─────────────────────────────────────", title, count)
	fmt.Fprintln(w)
	fmt.Fprintln(w, styleConsole(sectionHeader, ansiBold+consoleOutcomeColor(outcome), useColor))
	tagText := consoleOutcomeTagText(outcome)
	detailIndent := strings.Repeat(" ", len(tagText)+1)

	printed := 0
	for _, result := range results {
		if result.EffectiveOutcome() != outcome {
			continue
		}
		printed++
		fmt.Fprintf(w, "│  %s [%s] %s\n", consoleOutcomeTag(outcome, useColor), result.TestID, result.TestName)
		showDetails := outcome != spec.OutcomePass || options.Verbose
		if showDetails && result.Message != "" {
			fmt.Fprintf(w, "│  %s%s\n", detailIndent, result.Message)
		}
		if showDetails && result.Remediation != "" {
			fmt.Fprintf(w, "│  %sNext: %s\n", detailIndent, result.Remediation)
		}
		if options.Verbose {
			if result.Explanation != "" {
				fmt.Fprintf(w, "│  %sWhy: %s\n", detailIndent, result.Explanation)
			}
			if result.Reference != "" {
				fmt.Fprintf(w, "│  %sReference: %s\n", detailIndent, result.Reference)
			}
			if result.Tier.String() != "" {
				fmt.Fprintf(w, "│  %sTier: %s\n", detailIndent, result.Tier.String())
			}
			fmt.Fprintf(w, "│  %sDuration: %s\n", detailIndent, styleConsole(result.Duration.String(), ansiDim, useColor))
		}
	}
	if printed < count {
		fmt.Fprintf(w, "│  %d result details unavailable\n", count-printed)
	}
	fmt.Fprintln(w, styleConsole("╰───────────────────────────────────────────────────────────────", ansiDim, useColor))
}

func consoleColorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func styleConsole(text, style string, enabled bool) string {
	if !enabled {
		return text
	}
	return style + text + ansiReset
}

type JUnitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
	Content string `xml:",chardata"`
}

func calculatePassRate(passed, total int) float64 {
	if total == 0 {
		return 100.0
	}
	return (float64(passed) / float64(total)) * 100.0
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// JUnit XML Schema structures
type JUnitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Suites   []JUnitTestSuite `xml:"testsuite"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Skipped  int              `xml:"skipped,attr"`
	Time     float64          `xml:"time,attr"`
}

type JUnitTestSuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Errors     int             `xml:"errors,attr"`
	Time       float64         `xml:"time,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	Name       string          `xml:"name,attr"`
	ClassName  string          `xml:"classname,attr"`
	Time       float64         `xml:"time,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	Failure    *JUnitFailure   `xml:"failure,omitempty"`
	Skipped    *JUnitSkipped   `xml:"skipped,omitempty"`
}

type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// WriteJUnitXML writes a standard JUnit XML report including explanations and references
func WriteJUnitXML(destPath string, res *spec.SuiteResult) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tests := res.Total
	failures := res.Failed
	skipped := res.Unverified
	if len(res.Results) > 0 {
		tests = len(res.Results)
		failures = 0
		skipped = 0
		for _, result := range res.Results {
			switch result.EffectiveOutcome() {
			case spec.OutcomeFail:
				failures++
			case spec.OutcomeUnverified:
				skipped++
			}
		}
	}

	jSuite := JUnitTestSuite{
		Name:     res.SuiteName,
		Tests:    tests,
		Failures: failures,
		Skipped:  skipped,
		Errors:   0,
		Time:     res.Duration.Seconds(),
		Properties: []JUnitProperty{
			{Name: "imageDigest", Value: res.ImageDigest},
			{Name: "configDigest", Value: res.ConfigDigest},
			{Name: "platform", Value: res.Platform},
		},
	}

	for _, tr := range res.Results {
		imageDigest := tr.ImageDigest
		if imageDigest == "" {
			imageDigest = res.ImageDigest
		}
		configDigest := tr.ConfigDigest
		if configDigest == "" {
			configDigest = res.ConfigDigest
		}
		platform := tr.Platform
		if platform == "" {
			platform = res.Platform
		}
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("[%s] %s", tr.TestID, tr.TestName),
			ClassName: fmt.Sprintf("%s.%s", res.ImageName, tr.Tier.String()),
			Time:      tr.Duration.Seconds(),
			Properties: []JUnitProperty{
				{Name: "ruleType", Value: tr.RuleType},
				{Name: "tier", Value: tr.Tier.String()},
				{Name: "outcome", Value: string(tr.EffectiveOutcome())},
				{Name: "imageDigest", Value: imageDigest},
				{Name: "configDigest", Value: configDigest},
				{Name: "platform", Value: platform},
			},
		}
		switch tr.EffectiveOutcome() {
		case spec.OutcomeUnverified:
			tc.Skipped = &JUnitSkipped{
				Message: tr.Message,
				Content: tr.Message,
			}
		case spec.OutcomeFail:
			var contentBuilder strings.Builder
			contentBuilder.WriteString(fmt.Sprintf("Violation:   %s\n", tr.Message))
			if tr.Explanation != "" {
				contentBuilder.WriteString(fmt.Sprintf("Explanation: %s\n", tr.Explanation))
			}
			if tr.Remediation != "" {
				contentBuilder.WriteString(fmt.Sprintf("Remediation: %s\n", tr.Remediation))
			}
			if tr.Reference != "" {
				contentBuilder.WriteString(fmt.Sprintf("Reference:   %s\n", tr.Reference))
			}

			tc.Failure = &JUnitFailure{
				Message: tr.Message,
				Type:    tr.RuleType,
				Content: contentBuilder.String(),
			}
		}
		jSuite.TestCases = append(jSuite.TestCases, tc)
	}

	root := JUnitTestSuites{
		Suites:   []JUnitTestSuite{jSuite},
		Tests:    tests,
		Failures: failures,
		Skipped:  skipped,
		Time:     res.Duration.Seconds(),
	}

	data, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}

	xmlHeader := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	return os.WriteFile(destPath, append(xmlHeader, data...), 0644)
}

// WriteJSON writes structured test results for research data analysis
func WriteJSON(destPath string, data any) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, bytes, 0644)
}

// GenerateRemediationPatch generates a copy-pasteable Dockerfile hardening patch based on test failures
func GenerateRemediationPatch(res *spec.SuiteResult) string {
	needsRoot := false
	hasUserFix := false
	hasPortFix := false
	hasCacheFix := false
	hasSuidFix := false
	hasWorldWritableFix := false

	for _, r := range res.Results {
		if r.EffectiveOutcome() == spec.OutcomeFail {
			switch r.TestID {
			case "SPEC-01":
				hasUserFix = true
			case "SPEC-05":
				hasPortFix = true
			case "FS-01":
				hasCacheFix = true
				needsRoot = true
			case "FS-04":
				hasSuidFix = true
				needsRoot = true
			case "FS-05":
				hasWorldWritableFix = true
				needsRoot = true
			}
		}
	}

	if !hasUserFix && !hasPortFix && !hasCacheFix && !hasSuidFix && !hasWorldWritableFix {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n# ==============================================================================\n")
	sb.WriteString(fmt.Sprintf("# ConUnit Auto-Generated Hardening Patch for: %s\n", res.ImageName))
	sb.WriteString("# Apply the instructions below to the final stage of your Dockerfile to resolve defects\n")
	sb.WriteString("# ==============================================================================\n\n")

	if needsRoot {
		sb.WriteString("USER 0:0\n")
		var runCommands []string
		if hasCacheFix {
			runCommands = append(runCommands, "rm -rf /var/cache/apt/* /var/lib/apt/lists/* /var/cache/apk/* /root/.cache 2>/dev/null || true")
		}
		if hasSuidFix {
			runCommands = append(runCommands, "find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true")
		}
		if hasWorldWritableFix {
			runCommands = append(runCommands, "chmod -R o-w /app 2>/dev/null || true")
		}
		if len(runCommands) > 0 {
			sb.WriteString("RUN " + strings.Join(runCommands, " && \\\n    ") + "\n\n")
		}
	}

	if hasPortFix {
		sb.WriteString("EXPOSE 8080\n")
	}

	if hasUserFix {
		sb.WriteString("USER 10001:10001\n")
	}

	return sb.String()
}
