// Command agreement compares two evaluation runs of the same dataset, made on
// separate instances, as the reliability analysis of docs/ANALYSIS_PLAN.md
// section 7.
//
//	agreement -a RUN_A/empirical_study.json -b RUN_B/empirical_study.json [-out-dir DIR] [-headline FILE]
//
// Per check it reports the raw percent agreement over the images that are
// verified (PASS or FAIL) in both runs, how many images are verified in only
// one run, and the images whose verdict flipped between the runs. A flipped
// image is one that is verified in both runs and gets a different verdict for
// at least one check. Cohen's kappa is not computed here: two runs of the same
// tool are not two independent raters, so the run-to-run result is the raw
// agreement and the flip list. Kappa stays in tools/adjudication, where it
// compares the two human raters.
//
// Outputs in -out-dir (default: the directory of run A): agreement.json,
// table_agreement.tex (label tab:agreement) and macros_agreement.tex.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/analysis"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

const (
	jsonName   = "agreement.json"
	tableName  = "table_agreement.tex"
	macrosName = "macros_agreement.tex"

	// SchemaVersion of agreement.json. Version 2 replaced kappa by the flip
	// list.
	SchemaVersion = "2"
)

// RunInfo identifies one input run.
type RunInfo struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	StartedAt     string `json:"started_at,omitempty"`
	InstanceType  string `json:"instance_type,omitempty"`
	AMIID         string `json:"ami_id,omitempty"`
	Engine        string `json:"engine,omitempty"`
	Commit        string `json:"commit,omitempty"`
	DatasetSHA256 string `json:"dataset_sha256,omitempty"`
	Attempted     int    `json:"attempted"`
	Completed     int    `json:"completed"`
}

// ImageOverlap counts images across the two runs.
type ImageOverlap struct {
	InBoth        int `json:"records_in_both"`
	CompletedBoth int `json:"completed_in_both"`
	OnlyInA       int `json:"records_only_in_a"`
	OnlyInB       int `json:"records_only_in_b"`
}

// CheckAgreement is the agreement of one check between the two runs.
type CheckAgreement struct {
	Rule string `json:"rule"`
	Name string `json:"name"`
	Tier int    `json:"tier"`
	// Role is headline, exploratory or excluded when a classification was
	// given.
	Role string `json:"role,omitempty"`

	VerifiedBoth int `json:"verified_in_both"`
	Agree        int `json:"agree"`
	// Cells of the PASS/FAIL agreement matrix, run A by run B.
	PassPass int `json:"pass_pass"`
	PassFail int `json:"pass_fail"`
	FailPass int `json:"fail_pass"`
	FailFail int `json:"fail_fail"`

	// PercentAgreement is Agree over VerifiedBoth, a proportion in [0,1]. It
	// is null when no image is verified in both runs.
	PercentAgreement *float64 `json:"percent_agreement"`

	VerifiedOnlyA int `json:"verified_only_in_a"`
	VerifiedOnlyB int `json:"verified_only_in_b"`

	// Flipped is the number of images whose verdict for this check differs
	// between the runs, and FlippedImages lists them in sorted order.
	Flipped       int      `json:"flipped"`
	FlippedImages []string `json:"flipped_images,omitempty"`
}

// Flip is one check whose verdict differs between the runs for an image.
type Flip struct {
	Rule string `json:"rule"`
	RunA string `json:"run_a"`
	RunB string `json:"run_b"`
}

// FlippedImage is an image with at least one flipped check.
type FlippedImage struct {
	Image  string `json:"image"`
	Checks []Flip `json:"checks"`
}

// FlippedSummary is the list and the count of flipped images. A flipped image
// is verified in both runs and has a different verdict for at least one check.
type FlippedSummary struct {
	Count  int            `json:"count"`
	Images []FlippedImage `json:"images"`
	// Pairs counts the flipped image and check pairs.
	Pairs int `json:"pairs"`
}

// Report is agreement.json.
type Report struct {
	SchemaVersion string           `json:"schema_version"`
	RunA          RunInfo          `json:"run_a"`
	RunB          RunInfo          `json:"run_b"`
	Images        ImageOverlap     `json:"images"`
	Checks        []CheckAgreement `json:"checks"`
	Flipped       FlippedSummary   `json:"flipped"`
	// PooledAgreement is the share of agreeing verdicts over all checks and
	// images verified in both runs. It is descriptive only.
	PooledAgreement *float64 `json:"pooled_percent_agreement"`
	Warnings        []string `json:"warnings,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("agreement", flag.ContinueOnError)
	fset.SetOutput(stderr)
	pathA := fset.String("a", "", "study file of run A")
	pathB := fset.String("b", "", "study file of run B")
	outDir := fset.String("out-dir", "", "output directory (default: directory of run A)")
	headline := fset.String("headline", "", "optional headline_checks.json to label each check's role")
	if err := fset.Parse(args); err != nil {
		return spec.ExitUsage
	}
	log, problem := clilog.New(stdout), clilog.New(stderr)
	if *pathA == "" || *pathB == "" {
		fmt.Fprintln(stderr, "usage: agreement -a RUN_A/empirical_study.json -b RUN_B/empirical_study.json [-out-dir DIR] [-headline FILE]")
		return spec.ExitUsage
	}
	a, err := studyfile.Load(*pathA)
	if err != nil {
		problem.Error("run A: %v", err)
		return spec.ExitFindings
	}
	b, err := studyfile.Load(*pathB)
	if err != nil {
		problem.Error("run B: %v", err)
		return spec.ExitFindings
	}
	var class *analysis.Classification
	if *headline != "" {
		if class, err = analysis.LoadClassification(*headline); err != nil {
			problem.Error("%v", err)
			return spec.ExitFindings
		}
	}

	report := Compare(a, b, *pathA, *pathB, class)
	macros, err := RenderMacros(report)
	if err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	dir := *outDir
	if dir == "" {
		dir = filepath.Dir(*pathA)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		problem.Error("%v", err)
		return spec.ExitFindings
	}
	for _, f := range []struct {
		name    string
		content []byte
	}{
		{jsonName, append(data, '\n')},
		{tableName, []byte(RenderTable(report))},
		{macrosName, []byte(macros)},
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.content, 0o644); err != nil {
			problem.Error("cannot write %s: %v", f.name, err)
			return spec.ExitFindings
		}
	}

	log.Section("Run agreement")
	log.Info("run A: %d attempted, %d completed | run B: %d attempted, %d completed", report.RunA.Attempted, report.RunA.Completed, report.RunB.Attempted, report.RunB.Completed)
	log.Info("images: %d completed in both, %d only in A, %d only in B", report.Images.CompletedBoth, report.Images.OnlyInA, report.Images.OnlyInB)
	anyOverlap := false
	for _, c := range report.Checks {
		if c.VerifiedBoth > 0 {
			anyOverlap = true
		}
		log.Info("%-9s verified in both %3d  agreement %6s  flipped %3d  only A %3d  only B %3d",
			c.Rule, c.VerifiedBoth, pctText(c.PercentAgreement), c.Flipped, c.VerifiedOnlyA, c.VerifiedOnlyB)
	}
	log.Info("flipped images: %d (%d image and check pairs)", report.Flipped.Count, report.Flipped.Pairs)
	for _, w := range report.Warnings {
		problem.Warn("%s", w)
	}
	log.Success("wrote %s, %s and %s in %s", jsonName, tableName, macrosName, dir)
	if !anyOverlap {
		problem.Error("no check has an image verified in both runs; agreement is undefined")
		return spec.ExitIncomplete
	}
	return spec.ExitOK
}

func runInfo(l *studyfile.Loaded, path string) RunInfo {
	r := l.Study.Run
	info := RunInfo{
		Path: path, SHA256: l.SHA256, InstanceType: r.InstanceType, AMIID: r.AMIID,
		Engine: strings.TrimSpace(r.EngineName + " " + r.EngineVersion), Commit: r.Commit,
		DatasetSHA256: r.DatasetSHA256, Attempted: len(l.Records),
	}
	if !r.StartedAt.IsZero() {
		info.StartedAt = r.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	for _, rec := range l.Records {
		if l.Completed(rec) {
			info.Completed++
		}
	}
	return info
}

// verdicts maps image key to rule ID to PASS or FAIL, for COMPLETED images
// and verified results only, together with the names and tiers of the rules.
type verdicts struct {
	byImage map[string]map[string]spec.Outcome
	names   map[string]string
	tiers   map[string]int
}

func collect(l *studyfile.Loaded) verdicts {
	v := verdicts{byImage: map[string]map[string]spec.Outcome{}, names: map[string]string{}, tiers: map[string]int{}}
	for _, rec := range l.Records {
		if !l.Completed(rec) {
			continue
		}
		key := studyfile.RecordKey(rec)
		results, _ := studyfile.UniqueResults(rec)
		m := map[string]spec.Outcome{}
		for _, r := range results {
			if _, ok := v.names[r.TestID]; !ok {
				v.names[r.TestID], v.tiers[r.TestID] = r.TestName, int(r.Tier)
			}
			switch o := r.EffectiveOutcome(); o {
			case spec.OutcomePass, spec.OutcomeFail:
				m[r.TestID] = o
			}
		}
		v.byImage[key] = m
	}
	return v
}

// Compare computes the agreement of two runs. class may be nil.
func Compare(a, b *studyfile.Loaded, pathA, pathB string, class *analysis.Classification) *Report {
	rep := &Report{SchemaVersion: SchemaVersion, RunA: runInfo(a, pathA), RunB: runInfo(b, pathB)}
	warn := func(format string, args ...any) { rep.Warnings = append(rep.Warnings, fmt.Sprintf(format, args...)) }
	rep.Warnings = append(rep.Warnings, a.Warnings...)
	rep.Warnings = append(rep.Warnings, b.Warnings...)
	if rep.RunA.SHA256 == rep.RunB.SHA256 {
		warn("run A and run B are the same file; agreement is trivially perfect")
	}
	if da, db := rep.RunA.DatasetSHA256, rep.RunB.DatasetSHA256; da != "" && db != "" && da != db {
		warn("the runs used different datasets (dataset_sha256 %s versus %s)", short(da), short(db))
	}

	// Image overlap.
	recA, recB := map[string]bool{}, map[string]bool{}
	for _, r := range a.Records {
		recA[studyfile.RecordKey(r)] = true
	}
	for _, r := range b.Records {
		recB[studyfile.RecordKey(r)] = true
	}
	va, vb := collect(a), collect(b)
	for k := range recA {
		switch {
		case !recB[k]:
			rep.Images.OnlyInA++
		default:
			rep.Images.InBoth++
		}
	}
	for k := range recB {
		if !recA[k] {
			rep.Images.OnlyInB++
		}
	}
	for k := range va.byImage {
		if _, ok := vb.byImage[k]; ok {
			rep.Images.CompletedBoth++
		}
	}

	rules := map[string]bool{}
	for _, v := range []verdicts{va, vb} {
		for id := range v.names {
			rules[id] = true
		}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ti, tj := tierOf(va, vb, ids[i]), tierOf(va, vb, ids[j])
		if ti != tj {
			return ti < tj
		}
		return analysis.NaturalLess(ids[i], ids[j])
	})

	images := unionKeys(va.byImage, vb.byImage)
	flipsByImage := map[string][]Flip{}
	totalAgree, totalBoth := 0, 0
	for _, id := range ids {
		c := CheckAgreement{Rule: id, Name: firstNonEmpty(va.names[id], vb.names[id]), Tier: tierOf(va, vb, id)}
		if class != nil {
			role, _ := class.Lookup(id)
			c.Role = string(role)
		}
		for _, img := range images {
			oa, okA := va.byImage[img][id]
			ob, okB := vb.byImage[img][id]
			switch {
			case okA && okB:
				c.VerifiedBoth++
				switch {
				case oa == spec.OutcomePass && ob == spec.OutcomePass:
					c.PassPass++
				case oa == spec.OutcomePass && ob == spec.OutcomeFail:
					c.PassFail++
				case oa == spec.OutcomeFail && ob == spec.OutcomePass:
					c.FailPass++
				default:
					c.FailFail++
				}
				if oa == ob {
					c.Agree++
					continue
				}
				c.FlippedImages = append(c.FlippedImages, img)
				flipsByImage[img] = append(flipsByImage[img], Flip{Rule: id, RunA: string(oa), RunB: string(ob)})
			case okA:
				c.VerifiedOnlyA++
			case okB:
				c.VerifiedOnlyB++
			}
		}
		c.Flipped = len(c.FlippedImages)
		if c.VerifiedBoth > 0 {
			p := float64(c.Agree) / float64(c.VerifiedBoth)
			c.PercentAgreement = &p
		}
		totalAgree += c.Agree
		totalBoth += c.VerifiedBoth
		rep.Checks = append(rep.Checks, c)
	}
	if totalBoth > 0 {
		p := float64(totalAgree) / float64(totalBoth)
		rep.PooledAgreement = &p
	}

	// The flip list. Images are in sorted order (images is sorted) and the
	// checks of an image follow the report order of the checks.
	rep.Flipped.Images = []FlippedImage{}
	for _, img := range images {
		flips := flipsByImage[img]
		if len(flips) == 0 {
			continue
		}
		rep.Flipped.Images = append(rep.Flipped.Images, FlippedImage{Image: img, Checks: flips})
		rep.Flipped.Pairs += len(flips)
	}
	rep.Flipped.Count = len(rep.Flipped.Images)
	return rep
}

func tierOf(a, b verdicts, id string) int {
	if t, ok := a.tiers[id]; ok {
		return t
	}
	return b.tiers[id]
}

func unionKeys(a, b map[string]map[string]spec.Outcome) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func pctText(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100**p)
}

// RenderTable renders table_agreement.tex.
func RenderTable(rep *Report) string {
	withRole := false
	for _, c := range rep.Checks {
		if c.Role != "" {
			withRole = true
		}
	}
	cols := "llrrrrr"
	head := `\textbf{Rule} & \textbf{Property} & \textbf{Both} & \textbf{Agreement} & \textbf{Flipped} & \textbf{Only A} & \textbf{Only B}`
	if withRole {
		cols = "lllrrrrr"
		head = `\textbf{Rule} & \textbf{Role} & \textbf{Property} & \textbf{Both} & \textbf{Agreement} & \textbf{Flipped} & \textbf{Only A} & \textbf{Only B}`
	}
	var w strings.Builder
	w.WriteString("% Generated by tools/agreement. Do not edit.\n")
	w.WriteString("\\begin{table*}[t]\n\\centering\n\\small\n")
	fmt.Fprintf(&w, "\\caption{Agreement between two complete runs on separate instances, per check. "+
		"Both: images verified (PASS or FAIL) in both runs, over which the raw percent agreement is computed; "+
		"Flipped: images whose verdict differs between the two runs; "+
		"Only A and Only B: images verified in one run only. "+
		"No chance-corrected statistic is reported, because two runs of one tool are not independent raters.}\n")
	w.WriteString("\\label{tab:agreement}\n\\resizebox{\\textwidth}{!}{%\n")
	fmt.Fprintf(&w, "\\begin{tabular}{%s}\n\\toprule\n%s \\\\\n\\midrule\n", cols, head)
	if len(rep.Checks) == 0 {
		fmt.Fprintf(&w, "\\multicolumn{%d}{c}{no checks} \\\\\n", len(cols))
	}
	for _, c := range rep.Checks {
		agree := tex.NotAvailable
		if c.PercentAgreement != nil {
			agree = tex.Percent(*c.PercentAgreement)
		}
		fmt.Fprintf(&w, "%s", tex.Texttt(c.Rule))
		if withRole {
			fmt.Fprintf(&w, " & %s", tex.Escape(c.Role))
		}
		fmt.Fprintf(&w, " & %s & %d & %s & %d & %d & %d \\\\\n",
			tex.Escape(c.Name), c.VerifiedBoth, agree, c.Flipped, c.VerifiedOnlyA, c.VerifiedOnlyB)
	}
	w.WriteString("\\bottomrule\n\\end{tabular}}\n\\end{table*}\n")
	return w.String()
}

// RenderMacros renders macros_agreement.tex: ConUnitAgrImages (images
// completed in both runs), ConUnitAgrFlipped (flipped images) and, per check,
// ConUnitAgrPct<key> (raw percent agreement, one decimal). A value that is not
// defined prints n/a: the agreement of a check without an image verified in
// both runs, and the flip count when no check has such an image.
func RenderMacros(rep *Report) (string, error) {
	type macro struct{ name, value string }
	anyOverlap := false
	for _, c := range rep.Checks {
		if c.VerifiedBoth > 0 {
			anyOverlap = true
		}
	}
	flipped := tex.NotAvailable
	if anyOverlap {
		flipped = fmt.Sprint(rep.Flipped.Count)
	}
	list := []macro{
		{"ConUnitAgrImages", fmt.Sprint(rep.Images.CompletedBoth)},
		{"ConUnitAgrFlipped", flipped},
	}
	for _, c := range rep.Checks {
		value := tex.NotAvailable
		if c.PercentAgreement != nil {
			value = tex.Percent(*c.PercentAgreement)
		}
		list = append(list, macro{"ConUnitAgrPct" + analysis.RuleKey(c.Rule), value})
	}
	var w strings.Builder
	w.WriteString("% Generated by tools/agreement. Do not edit.\n")
	w.WriteString("% Run-to-run agreement macros: raw percent agreement and flipped images\n")
	seen := map[string]bool{}
	for _, m := range list {
		for _, r := range m.name {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return "", fmt.Errorf("macro name %q is not letters only", m.name)
			}
		}
		if seen[m.name] {
			return "", fmt.Errorf("macro %s is defined twice", m.name)
		}
		seen[m.name] = true
		fmt.Fprintf(&w, "\\newcommand{\\%s}{%s}\n", m.name, m.value)
	}
	return w.String(), nil
}
