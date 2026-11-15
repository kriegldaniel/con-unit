// Command reliability summarizes repeated runs of a small image subset into
// the reliability numbers of the evaluation (docs/ANALYSIS_PLAN.md and
// docs/INTERFACE_V2.md section 6).
//
//	reliability -runs r1=<dir>,r2=<dir>,r3=<dir> -windows w3=<dir>,w10=<dir>,w30=<dir> -out-dir <dir>
//
// Every directory holds the empirical_study.json of one run over the same
// images. A value of -runs or -windows is a comma separated list of
// label=directory pairs. A path to a study file is accepted in place of a
// directory.
//
// -runs are the repeats at one window of the probe (3 s in the evaluation). The
// tool reports how many pairs of check and image have a PASS or FAIL verdict in
// every repeat, how many of them flip, and how many images have a flip. A pair
// with an UNVERIFIED verdict in some repeat is in neither number and is counted
// apart.
//
// -windows are runs with different windows (3, 10 and 30 s in the evaluation).
// The tool reports how many pairs have a verdict that is not the same at every
// window. A window run can be the same directory as a repeat. The window of
// each run is read from its run metadata, and a label of the form w<seconds>
// must agree with it.
//
// Outputs in -out-dir: reliability.json, table_reliability.tex (label
// tab:reliability) and macros_reliability.tex. The macros ConUnitRelWindowShort,
// ConUnitRelWindowMid and ConUnitRelWindowLong are plain numbers in seconds
// without a unit.
//
// Exit codes: 0 compared, 2 usage or input error, 3 incomplete (an image did not
// complete in every run of a set, or the outputs could not be written).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// labeled is one label=path pair of a command line list.
type labeled struct {
	label string
	path  string
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// parseLabeled parses "a=dir,b=dir". An empty text gives an empty list.
func parseLabeled(text string) ([]labeled, error) {
	var out []labeled
	seen := map[string]bool{}
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		label, path, ok := strings.Cut(part, "=")
		label, path = strings.TrimSpace(label), strings.TrimSpace(path)
		switch {
		case !ok || path == "":
			return nil, fmt.Errorf("%q is not label=directory", part)
		case !labelPattern.MatchString(label):
			return nil, fmt.Errorf("%q is not a usable label: use letters, digits, hyphen and underscore", label)
		case seen[label]:
			return nil, fmt.Errorf("label %q is given twice", label)
		}
		seen[label] = true
		out = append(out, labeled{label, path})
	}
	return out, nil
}

// studyPath resolves a directory to its study file. A path that ends in .json
// is a study file already.
func studyPath(path string) string {
	if strings.HasSuffix(path, ".json") {
		return path
	}
	return filepath.Join(path, studyFileName)
}

func loadRuns(items []labeled) ([]*Run, error) {
	var runs []*Run
	for _, it := range items {
		path := studyPath(it.path)
		l, err := studyfile.Load(path)
		if err != nil {
			return nil, fmt.Errorf("run %s: %w", it.label, err)
		}
		runs = append(runs, &Run{Label: it.label, Path: path, Loaded: l})
	}
	return runs, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reliability", flag.ContinueOnError)
	fs.SetOutput(stderr)
	runsFlag := fs.String("runs", "", "Repeats at one window: label=dir pairs, for example r1=dir,r2=dir,r3=dir (at least two)")
	windowsFlag := fs.String("windows", "", "Runs at different windows: label=dir pairs, for example w3=dir,w10=dir,w30=dir")
	outDir := fs.String("out-dir", "", "Output directory")
	if err := fs.Parse(args); err != nil {
		return spec.ExitUsage
	}
	log, problem := clilog.New(stdout), clilog.New(stderr)
	usage := func(format string, a ...any) int {
		problem.Error(format, a...)
		return spec.ExitUsage
	}
	if fs.NArg() > 0 {
		return usage("unexpected argument %q", fs.Arg(0))
	}
	if *outDir == "" {
		return usage("-out-dir is required")
	}
	runItems, err := parseLabeled(*runsFlag)
	if err != nil {
		return usage("-runs: %v", err)
	}
	if len(runItems) < 2 {
		return usage("-runs needs at least two repeats, for example -runs r1=dir,r2=dir,r3=dir")
	}
	windowItems, err := parseLabeled(*windowsFlag)
	if err != nil {
		return usage("-windows: %v", err)
	}
	if len(windowItems) == 1 {
		return usage("-windows needs at least two runs to compare, or none")
	}

	runs, err := loadRuns(runItems)
	if err != nil {
		return usage("%v", err)
	}
	windows, err := loadRuns(windowItems)
	if err != nil {
		return usage("%v", err)
	}
	rep, err := Build(runs, windows)
	if err != nil {
		return usage("%v", err)
	}

	log.Section("Reliability of the verdicts")
	d := rep.RepeatDetail
	log.Info("repeats %d (%s) at %s, %d images completed in all of them", rep.Repeats, strings.Join(d.Labels, ", "), windowText(d.WindowMs), rep.Images)
	log.Info("pairs   %d with a verified verdict in every repeat, %d flipped, in %d images", rep.Pairs, rep.FlippedChecks, rep.FlippedImages)
	log.Info("         %d pairs unverified in some repeat, in neither number", rep.PairsUnverifiedInSomeRepeat)
	log.Info("tier 3  %d pairs, %d flipped in %d images", d.TierThreePairs, d.TierThreeFlippedPairs, d.TierThreeFlippedImages)
	for _, f := range d.Flipped {
		log.Warn("flip %-10s %-40s %s", f.Check, f.Image, verdictText(f.Verdicts, d.Labels))
	}
	if w := rep.WindowDetail; w != nil {
		log.Info("windows %s: %d images, %d pairs, %d changed (%d with an unverified verdict)",
			strings.Join(w.Labels, ", "), w.Images, w.Pairs, w.Changed, w.ChangedWithUnverified)
	}
	for _, w := range rep.Warnings {
		problem.Warn("%s", w)
	}
	if err := WriteAll(*outDir, rep); err != nil {
		problem.Error("writing outputs: %v", err)
		return spec.ExitIncomplete
	}
	for _, name := range []string{jsonFile, tableFile, macrosFile} {
		log.Success("wrote %s", filepath.Join(*outDir, name))
	}
	if rep.Incomplete() {
		problem.Error("incomplete: some image did not complete in every run of a set, see the warnings")
		return spec.ExitIncomplete
	}
	return spec.ExitOK
}

func windowText(ms int64) string {
	if ms <= 0 {
		return "an unknown window"
	}
	return "W = " + seconds(ms) + " s"
}

func verdictText(verdicts map[string]string, order []string) string {
	parts := make([]string, 0, len(order))
	for _, label := range order {
		parts = append(parts, label+"="+verdicts[label])
	}
	return strings.Join(parts, " ")
}
