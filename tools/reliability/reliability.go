package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/studyfile"
)

// A pair is one check on one image. A repeat is a complete run of the same
// image list with the same settings. The analysis answers two questions about
// the pairs of the images that completed in every run of a set.
//
// Repeats: does a repeated run give another verdict? Only pairs with a PASS or
// FAIL verdict in every repeat count. A pair with an UNVERIFIED verdict in any
// repeat is in neither the denominator nor the number of flips and is reported
// apart, so a flip is always a change between two verified verdicts.
//
// Windows: does a longer or shorter observation window W give another verdict?
// A pair counts as changed when its three-state verdict is not the same at every
// window, so a verdict that turns UNVERIFIED at another window is a change.
// The number of changed pairs among them that stay verified is reported apart.

// Names of the files and labels that the tool reads and writes.
const (
	studyFileName = "empirical_study.json"
)

// Run is one study file with the label it was given on the command line.
type Run struct {
	Label  string
	Path   string
	Loaded *studyfile.Loaded
}

// WindowMs is the window recorded in the run metadata, 0 when it is unknown.
func (r *Run) WindowMs() int64 { return r.Loaded.Study.Run.ProbeWindowMs }

// InputInfo identifies one input run in reliability.json.
type InputInfo struct {
	Label         string `json:"label"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	WindowMs      int64  `json:"window_ms"`
	StartedAt     string `json:"started_at,omitempty"`
	Engine        string `json:"engine,omitempty"`
	Commit        string `json:"commit,omitempty"`
	DatasetSHA256 string `json:"dataset_sha256,omitempty"`
	Attempted     int    `json:"attempted"`
	Completed     int    `json:"completed"`
}

func inputInfo(r *Run) InputInfo {
	run := r.Loaded.Study.Run
	info := InputInfo{
		Label: r.Label, Path: r.Path, SHA256: r.Loaded.SHA256, WindowMs: run.ProbeWindowMs,
		Engine: strings.TrimSpace(run.EngineName + " " + run.EngineVersion), Commit: run.Commit,
		DatasetSHA256: run.DatasetSHA256, Attempted: len(r.Loaded.Records),
	}
	if !run.StartedAt.IsZero() {
		info.StartedAt = run.StartedAt.UTC().Format(time.RFC3339)
	}
	for _, rec := range r.Loaded.Records {
		if r.Loaded.Completed(rec) {
			info.Completed++
		}
	}
	return info
}

// ExcludedImage is an image that could not be compared because it did not
// complete in every run of the set.
type ExcludedImage struct {
	Image  string `json:"image"`
	Detail string `json:"detail"`
}

// PairChange lists the verdicts of one pair per run label.
type PairChange struct {
	Image    string            `json:"image"`
	Check    string            `json:"check"`
	Tier     int               `json:"tier"`
	Verdicts map[string]string `json:"verdicts"`
}

// CheckStat counts the pairs of one check.
type CheckStat struct {
	Rule string `json:"rule"`
	Name string `json:"name,omitempty"`
	Tier int    `json:"tier"`
	// Pairs, Flipped, UnverifiedInSomeRepeat and MissingInSomeRepeat are the
	// repeat counts. Pairs are those with a PASS or FAIL verdict in every repeat.
	Pairs                  int `json:"pairs"`
	Flipped                int `json:"flipped"`
	UnverifiedInSomeRepeat int `json:"unverified_in_some_repeat"`
	MissingInSomeRepeat    int `json:"missing_in_some_repeat"`
	// WindowPairs and WindowChanged are the window counts. Pairs are those
	// that exist at every window.
	WindowPairs   int `json:"window_pairs"`
	WindowChanged int `json:"window_changed"`
}

// TierThree reports whether the check belongs to Tier 3.
func (c CheckStat) TierThree() bool {
	return c.Tier == int(spec.TierContract) || strings.HasPrefix(c.Rule, "EXEC-")
}

// RepeatResult is the comparison of the repeats.
type RepeatResult struct {
	Labels   []string `json:"labels"`
	WindowMs int64    `json:"window_ms"`
	Images   int      `json:"images"`
	// Pairs are the pairs with a PASS or FAIL verdict in every repeat.
	Pairs                  int `json:"pairs"`
	FlippedPairs           int `json:"flipped_pairs"`
	FlippedImages          int `json:"flipped_images"`
	UnverifiedInSomeRepeat int `json:"pairs_unverified_in_some_repeat"`
	MissingInSomeRepeat    int `json:"pairs_missing_in_some_repeat"`
	// TierThreePairs and the two counts after it restate the numbers for the
	// Tier 3 checks alone, the checks that depend on the observation window.
	TierThreePairs         int             `json:"tier3_pairs"`
	TierThreeFlippedPairs  int             `json:"tier3_flipped_pairs"`
	TierThreeFlippedImages int             `json:"tier3_flipped_images"`
	Flipped                []PairChange    `json:"flipped"`
	UnverifiedPairs        []PairChange    `json:"unverified_pairs"`
	Excluded               []ExcludedImage `json:"excluded_images"`
}

// WindowResult is the comparison of the windows.
type WindowResult struct {
	Labels    []string `json:"labels"`
	WindowsMs []int64  `json:"windows_ms"`
	Images    int      `json:"images"`
	Pairs     int      `json:"pairs"`
	Changed   int      `json:"changed"`
	Unchanged int      `json:"unchanged"`
	// ChangedVerified counts the changed pairs with a PASS or FAIL verdict at
	// every window. ChangedWithUnverified counts those that are UNVERIFIED at
	// some window.
	ChangedVerified       int             `json:"changed_verified"`
	ChangedWithUnverified int             `json:"changed_with_unverified"`
	TierThreePairs        int             `json:"tier3_pairs"`
	TierThreeChanged      int             `json:"tier3_changed"`
	Changes               []PairChange    `json:"changes"`
	Excluded              []ExcludedImage `json:"excluded_images"`
}

// Report is reliability.json. The flat fields at the top are the numbers of
// the macros, the detail blocks below explain them.
type Report struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`

	Repeats       int `json:"repeats"`
	Images        int `json:"images"`
	Pairs         int `json:"pairs"`
	FlippedImages int `json:"flipped_images"`
	FlippedChecks int `json:"flipped_checks"`
	// PairsUnverifiedInSomeRepeat counts pairs that are UNVERIFIED in at least
	// one repeat. They are in neither Pairs nor FlippedChecks.
	PairsUnverifiedInSomeRepeat int    `json:"pairs_unverified_in_some_repeat"`
	WindowChanged               *int   `json:"window_changed"`
	WindowShortS                string `json:"window_short_s"`
	WindowMidS                  string `json:"window_mid_s"`
	WindowLongS                 string `json:"window_long_s"`

	Method string `json:"method"`

	Inputs       []InputInfo   `json:"inputs"`
	RepeatDetail *RepeatResult `json:"repeat_detail"`
	WindowInputs []InputInfo   `json:"window_inputs"`
	WindowDetail *WindowResult `json:"window_detail"`
	Checks       []CheckStat   `json:"checks"`
	Warnings     []string      `json:"warnings"`
	incomplete   bool
}

// Incomplete reports whether an image could not be compared.
func (r *Report) Incomplete() bool { return r.incomplete }

// methodText states how the numbers are computed, so that the file explains
// itself.
const methodText = "A pair is one check on one image, over the images that completed in every run of the set. " +
	"Repeats: only pairs with a PASS or FAIL verdict in every repeat are counted (pairs). A pair is flipped when those verdicts are not all the same. " +
	"A pair with an UNVERIFIED verdict in any repeat is in neither number and is counted in pairs_unverified_in_some_repeat. " +
	"Windows: a pair is changed when its verdict (PASS, FAIL or UNVERIFIED) is not the same at every window. " +
	"Window values are read from the run metadata of each study."

var windowLabelPattern = regexp.MustCompile(`^w(\d+)$`)

// Build validates the runs and analyzes them. runs are the repeats at one
// window, windows the runs at different windows (empty is allowed).
func Build(runs, windows []*Run) (*Report, error) {
	if len(runs) < 2 {
		return nil, fmt.Errorf("at least two repeats are needed to compare them, got %d", len(runs))
	}
	rep := &Report{
		SchemaVersion: "1", GeneratedAt: time.Now().UTC().Format(time.RFC3339), Method: methodText,
		Inputs: []InputInfo{}, WindowInputs: []InputInfo{}, Checks: []CheckStat{}, Warnings: []string{},
	}
	warn := func(format string, args ...any) { rep.Warnings = append(rep.Warnings, fmt.Sprintf(format, args...)) }

	// The repeats must be different files with one window.
	seen := map[string]string{}
	for _, r := range runs {
		if other, dup := seen[r.Loaded.SHA256]; dup {
			return nil, fmt.Errorf("repeats %s and %s are the same study file, so no flip can show; give three separate runs", other, r.Label)
		}
		seen[r.Loaded.SHA256] = r.Label
		warnings(r, warn)
	}
	windowMs := runs[0].WindowMs()
	for _, r := range runs[1:] {
		if r.WindowMs() != windowMs {
			return nil, fmt.Errorf("repeats %s and %s were run with different windows (%d ms and %d ms)", runs[0].Label, r.Label, windowMs, r.WindowMs())
		}
	}
	if windowMs == 0 {
		warn("the repeats record no probe window, the window of the repeats is unknown")
	}

	// The windows must be different files with different windows.
	seenWindow := map[string]string{}
	seenMs := map[int64]string{}
	for _, w := range windows {
		if other, dup := seenWindow[w.Loaded.SHA256]; dup {
			return nil, fmt.Errorf("windows %s and %s are the same study file", other, w.Label)
		}
		seenWindow[w.Loaded.SHA256] = w.Label
		if ms := w.WindowMs(); ms > 0 {
			if other, dup := seenMs[ms]; dup {
				return nil, fmt.Errorf("windows %s and %s were both run with a window of %d ms", other, w.Label, ms)
			}
			seenMs[ms] = w.Label
			if m := windowLabelPattern.FindStringSubmatch(w.Label); m != nil {
				if secs, _ := strconv.ParseInt(m[1], 10, 64); secs*1000 != ms {
					return nil, fmt.Errorf("window %s was run with a window of %d ms, not %d s as its label says", w.Label, ms, secs)
				}
			}
		} else {
			warn("window %s records no probe window", w.Label)
		}
		warnings(w, warn)
	}
	checkDatasets(append(append([]*Run{}, runs...), windows...), warn)

	stats := &checkStats{byRule: map[string]*CheckStat{}}
	rep.RepeatDetail = analyzeRepeats(runs, windowMs, stats)
	for _, r := range runs {
		rep.Inputs = append(rep.Inputs, inputInfo(r))
	}
	if len(windows) > 0 {
		rep.WindowDetail = analyzeWindows(windows, stats)
		for _, w := range windows {
			rep.WindowInputs = append(rep.WindowInputs, inputInfo(w))
		}
	}
	rep.Checks = stats.sorted()

	d := rep.RepeatDetail
	rep.Repeats, rep.Images, rep.Pairs = len(runs), d.Images, d.Pairs
	rep.FlippedImages, rep.FlippedChecks, rep.PairsUnverifiedInSomeRepeat = d.FlippedImages, d.FlippedPairs, d.UnverifiedInSomeRepeat
	rep.incomplete = len(d.Excluded) > 0
	if rep.WindowDetail != nil {
		if rep.WindowDetail.Pairs > 0 {
			changed := rep.WindowDetail.Changed
			rep.WindowChanged = &changed
		}
		rep.incomplete = rep.incomplete || len(rep.WindowDetail.Excluded) > 0
		rep.WindowShortS, rep.WindowMidS, rep.WindowLongS = windowValues(rep.WindowDetail.WindowsMs)
	}
	for _, ex := range d.Excluded {
		warn("repeat comparison skips image %s: %s", ex.Image, ex.Detail)
	}
	if rep.WindowDetail != nil {
		for _, ex := range rep.WindowDetail.Excluded {
			warn("window comparison skips image %s: %s", ex.Image, ex.Detail)
		}
	}
	return rep, nil
}

func warnings(r *Run, warn func(string, ...any)) {
	for _, w := range r.Loaded.Warnings {
		warn("%s: %s", r.Label, w)
	}
}

// checkDatasets warns when the runs used different datasets.
func checkDatasets(runs []*Run, warn func(string, ...any)) {
	first := ""
	firstLabel := ""
	for _, r := range runs {
		d := r.Loaded.Study.Run.DatasetSHA256
		if d == "" {
			continue
		}
		if first == "" {
			first, firstLabel = d, r.Label
		} else if d != first {
			warn("%s and %s used different datasets (dataset_sha256 %s and %s)", firstLabel, r.Label, shortSum(first), shortSum(d))
			return
		}
	}
}

func shortSum(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// windowValues returns the shortest, the middle and the longest window in
// seconds as text. The middle one exists only for exactly three windows. A
// window of unknown length makes all three n/a.
func windowValues(ms []int64) (short, mid, long string) {
	const na = "n/a"
	short, mid, long = na, na, na
	if len(ms) < 2 {
		return
	}
	sorted := append([]int64(nil), ms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if sorted[0] <= 0 {
		return
	}
	short, long = seconds(sorted[0]), seconds(sorted[len(sorted)-1])
	if len(sorted) == 3 {
		mid = seconds(sorted[1])
	}
	return
}

// seconds writes milliseconds as seconds in the shortest exact form.
func seconds(ms int64) string {
	return strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)
}

// checkStats collects the counts per check over both analyses.
type checkStats struct {
	byRule map[string]*CheckStat
}

func (s *checkStats) get(r spec.TestResult) *CheckStat {
	c, ok := s.byRule[r.TestID]
	if !ok {
		c = &CheckStat{Rule: r.TestID, Name: r.TestName, Tier: int(r.Tier)}
		s.byRule[r.TestID] = c
	}
	return c
}

func (s *checkStats) sorted() []CheckStat {
	out := make([]CheckStat, 0, len(s.byRule))
	for _, c := range s.byRule {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		return naturalLess(out[i].Rule, out[j].Rule)
	})
	return out
}

var digitRun = regexp.MustCompile(`\d+|\D+`)

// naturalLess orders rule IDs so that FS-2 comes before FS-10.
func naturalLess(a, b string) bool {
	pa, pb := digitRun.FindAllString(a, -1), digitRun.FindAllString(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		if errA == nil && errB == nil {
			return na < nb
		}
		return pa[i] < pb[i]
	}
	return len(pa) < len(pb)
}

// completedEverywhere returns the keys of the images that completed in every
// run, sorted, and the images that did not with the reason.
func completedEverywhere(runs []*Run) (keys []string, excluded []ExcludedImage) {
	all := map[string]bool{}
	byRun := make([]map[string]*spec.SuiteResult, len(runs))
	for i, r := range runs {
		byRun[i] = map[string]*spec.SuiteResult{}
		for _, rec := range r.Loaded.Records {
			key := studyfile.RecordKey(rec)
			byRun[i][key] = rec
			all[key] = true
		}
	}
	names := make([]string, 0, len(all))
	for k := range all {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, key := range names {
		var problems []string
		for i, r := range runs {
			rec, ok := byRun[i][key]
			switch {
			case !ok:
				problems = append(problems, r.Label+" has no record")
			case !r.Loaded.Completed(rec):
				problems = append(problems, fmt.Sprintf("%s is %s", r.Label, r.Loaded.Status(rec)))
			}
		}
		if len(problems) > 0 {
			excluded = append(excluded, ExcludedImage{Image: key, Detail: strings.Join(problems, ", ")})
			continue
		}
		keys = append(keys, key)
	}
	return keys, excluded
}

// resultsOf indexes the results of one image record by check ID.
func resultsOf(rec *spec.SuiteResult) map[string]spec.TestResult {
	unique, _ := studyfile.UniqueResults(rec)
	m := make(map[string]spec.TestResult, len(unique))
	for _, r := range unique {
		m[r.TestID] = r
	}
	return m
}

func recordsByKey(r *Run) map[string]*spec.SuiteResult {
	m := map[string]*spec.SuiteResult{}
	for _, rec := range r.Loaded.Records {
		m[studyfile.RecordKey(rec)] = rec
	}
	return m
}

// pairsOfImage returns the results of one image in every run, indexed by check
// ID, and the sorted union of the check IDs.
func pairsOfImage(records []map[string]*spec.SuiteResult, key string) (perRun []map[string]spec.TestResult, ids []string) {
	perRun = make([]map[string]spec.TestResult, len(records))
	union := map[string]bool{}
	for i := range records {
		perRun[i] = resultsOf(records[i][key])
		for id := range perRun[i] {
			union[id] = true
		}
	}
	for id := range union {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return naturalLess(ids[i], ids[j]) })
	return perRun, ids
}

func recordsOf(runs []*Run) []map[string]*spec.SuiteResult {
	records := make([]map[string]*spec.SuiteResult, len(runs))
	for i, r := range runs {
		records[i] = recordsByKey(r)
	}
	return records
}

func isTierThree(r spec.TestResult) bool {
	return r.Tier == spec.TierContract || strings.HasPrefix(r.TestID, "EXEC-")
}

func verified(o spec.Outcome) bool { return o == spec.OutcomePass || o == spec.OutcomeFail }

// pairOutcomes gathers the outcomes of one check on one image over the runs. ok
// is false when some run has no result for the check.
func pairOutcomes(results []map[string]spec.TestResult, id string) (outcomes []spec.Outcome, sample spec.TestResult, ok bool) {
	ok = true
	found := false
	for _, res := range results {
		r, has := res[id]
		if !has {
			ok = false
			continue
		}
		if !found {
			sample, found = r, true
		}
		outcomes = append(outcomes, r.EffectiveOutcome())
	}
	return outcomes, sample, ok
}

func allSame(o []spec.Outcome) bool {
	for _, x := range o[1:] {
		if x != o[0] {
			return false
		}
	}
	return true
}

func verdictMap(runs []*Run, outcomes []spec.Outcome) map[string]string {
	m := make(map[string]string, len(runs))
	for i, r := range runs {
		m[r.Label] = string(outcomes[i])
	}
	return m
}

func analyzeRepeats(runs []*Run, windowMs int64, stats *checkStats) *RepeatResult {
	keys, excluded := completedEverywhere(runs)
	res := &RepeatResult{WindowMs: windowMs, Images: len(keys), Excluded: excluded,
		Flipped: []PairChange{}, UnverifiedPairs: []PairChange{}}
	if res.Excluded == nil {
		res.Excluded = []ExcludedImage{}
	}
	for _, r := range runs {
		res.Labels = append(res.Labels, r.Label)
	}
	records := recordsOf(runs)
	flippedImages, tier3FlippedImages := map[string]bool{}, map[string]bool{}
	for _, key := range keys {
		perRun, sortedIDs := pairsOfImage(records, key)
		for _, id := range sortedIDs {
			outcomes, sample, ok := pairOutcomes(perRun, id)
			stat := stats.get(sample)
			change := PairChange{Image: key, Check: id, Tier: int(sample.Tier)}
			switch {
			case !ok:
				stat.MissingInSomeRepeat++
				res.MissingInSomeRepeat++
				continue
			case anyUnverified(outcomes):
				stat.UnverifiedInSomeRepeat++
				res.UnverifiedInSomeRepeat++
				change.Verdicts = verdictMap(runs, outcomes)
				res.UnverifiedPairs = append(res.UnverifiedPairs, change)
				continue
			}
			stat.Pairs++
			res.Pairs++
			tier3 := isTierThree(sample)
			if tier3 {
				res.TierThreePairs++
			}
			if allSame(outcomes) {
				continue
			}
			stat.Flipped++
			res.FlippedPairs++
			flippedImages[key] = true
			if tier3 {
				res.TierThreeFlippedPairs++
				tier3FlippedImages[key] = true
			}
			change.Verdicts = verdictMap(runs, outcomes)
			res.Flipped = append(res.Flipped, change)
		}
	}
	res.FlippedImages, res.TierThreeFlippedImages = len(flippedImages), len(tier3FlippedImages)
	return res
}

func anyUnverified(o []spec.Outcome) bool {
	for _, x := range o {
		if !verified(x) {
			return true
		}
	}
	return false
}

func analyzeWindows(windows []*Run, stats *checkStats) *WindowResult {
	keys, excluded := completedEverywhere(windows)
	res := &WindowResult{Images: len(keys), Excluded: excluded, Changes: []PairChange{}}
	if res.Excluded == nil {
		res.Excluded = []ExcludedImage{}
	}
	for _, w := range windows {
		res.Labels = append(res.Labels, w.Label)
		res.WindowsMs = append(res.WindowsMs, w.WindowMs())
	}
	records := recordsOf(windows)
	for _, key := range keys {
		perRun, sortedIDs := pairsOfImage(records, key)
		for _, id := range sortedIDs {
			outcomes, sample, ok := pairOutcomes(perRun, id)
			if !ok {
				continue
			}
			stat := stats.get(sample)
			stat.WindowPairs++
			res.Pairs++
			tier3 := isTierThree(sample)
			if tier3 {
				res.TierThreePairs++
			}
			if allSame(outcomes) {
				res.Unchanged++
				continue
			}
			stat.WindowChanged++
			res.Changed++
			if tier3 {
				res.TierThreeChanged++
			}
			if anyUnverified(outcomes) {
				res.ChangedWithUnverified++
			} else {
				res.ChangedVerified++
			}
			res.Changes = append(res.Changes, PairChange{Image: key, Check: id, Tier: int(sample.Tier), Verdicts: verdictMap(windows, outcomes)})
		}
	}
	return res
}
