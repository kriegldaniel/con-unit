package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// LoadedStudy is a study document read from disk.
type LoadedStudy struct {
	Path          string
	SHA256        string
	SchemaVersion string // empty for the legacy array format
	Run           *spec.RunMetadata
	Images        []*spec.SuiteResult
}

// LoadStudy reads empirical_study.json: the envelope of spec.Study, or the
// earlier array-only format of old artifacts.
func LoadStudy(path string) (*LoadedStudy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading study: %w", err)
	}
	sum := sha256.Sum256(data)
	st := &LoadedStudy{Path: path, SHA256: hex.EncodeToString(sum[:])}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("study %s is empty", path)
	}
	if trimmed[0] == '[' {
		var legacy []*spec.SuiteResult
		if err := json.Unmarshal(trimmed, &legacy); err != nil {
			return nil, fmt.Errorf("parsing legacy study %s: %w", path, err)
		}
		st.Images = legacy
		return st, nil
	}
	var doc spec.Study
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return nil, fmt.Errorf("parsing study %s: %w", path, err)
	}
	st.SchemaVersion = doc.SchemaVersion
	run := doc.Run
	st.Run = &run
	st.Images = doc.Images
	return st, nil
}

// SelectTargets returns the image and rule pairs with a FAIL outcome among the
// COMPLETED images, in study order. Rules are visited in the order given.
// images restricts the selection to the listed references when not empty.
func SelectTargets(images []*spec.SuiteResult, rules []string, only map[string]bool) []Target {
	var out []Target
	for _, img := range images {
		if img == nil || (img.Status != "" && img.Status != spec.StatusCompleted) {
			continue
		}
		ref := img.RequestedRef
		if ref == "" {
			ref = img.ImageName
		}
		if ref == "" || (len(only) > 0 && !only[ref] && !only[img.ImageName]) {
			continue
		}
		for _, rule := range rules {
			if hasFail(img, rule) {
				out = append(out, Target{Image: ref, Rule: rule})
			}
		}
	}
	return out
}

func hasFail(img *spec.SuiteResult, rule string) bool {
	for _, r := range img.Results {
		if r.TestID == rule && r.EffectiveOutcome() == spec.OutcomeFail {
			return true
		}
	}
	return false
}

// RuleSummary counts the outcomes of one rule.
type RuleSummary struct {
	// Examined is the number of image and rule pairs.
	Examined int `json:"examined"`
	// Attributable is the number of pairs whose failure reproduced with a
	// running baseline. The four counts below add up to it.
	Attributable int `json:"attributable"`
	// ResolvedBySingle counts pairs that one candidate resolves alone.
	ResolvedBySingle int `json:"resolved_by_single"`
	// ResolvedByMinimal counts pairs that no single candidate resolves but a
	// minimal set found by minimization does.
	ResolvedByMinimal int `json:"resolved_by_minimal"`
	// ResolvedByUnionOnly counts pairs that only the union resolves and that
	// were not shrunk (minimization off or stopped early).
	ResolvedByUnionOnly int `json:"resolved_by_union_only"`
	Unresolved          int `json:"unresolved"`
	// Pairs that could not be interpreted, by reason.
	NotReproduced  int `json:"not_reproduced"`
	BaselineFailed int `json:"baseline_failed"`
	NotObservable  int `json:"not_observable"`
	ImageAbsent    int `json:"image_absent"`
	Error          int `json:"error"`
	// BySingleCandidate counts, per single candidate, the pairs it resolved.
	// A pair resolved by several candidates is counted for each of them.
	BySingleCandidate map[string]int `json:"by_single_candidate,omitempty"`
	// ByMinimalSet counts, per minimal set written as "A + B" in sorted order,
	// the pairs that were resolved by exactly that set.
	ByMinimalSet map[string]int `json:"by_minimal_set,omitempty"`
}

// Summary aggregates the attribution.
type Summary struct {
	Total  RuleSummary            `json:"total"`
	ByRule map[string]RuleSummary `json:"by_rule"`
}

// Summarize counts the attributions.
func Summarize(attrs []Attribution) Summary {
	s := Summary{ByRule: map[string]RuleSummary{}}
	add := func(rs *RuleSummary, a Attribution) {
		rs.Examined++
		switch a.Status {
		case StatusResolvedSingle:
			rs.Attributable++
			rs.ResolvedBySingle++
			for _, c := range a.ResolvedBy {
				if rs.BySingleCandidate == nil {
					rs.BySingleCandidate = map[string]int{}
				}
				rs.BySingleCandidate[c]++
			}
			countMinimalSet(rs, a)
		case StatusResolvedMinimal:
			rs.Attributable++
			rs.ResolvedByMinimal++
			countMinimalSet(rs, a)
		case StatusResolvedUnion:
			rs.Attributable++
			rs.ResolvedByUnionOnly++
		case StatusUnresolved:
			rs.Attributable++
			rs.Unresolved++
		case StatusNotReproduced:
			rs.NotReproduced++
		case StatusBaselineFailed:
			rs.BaselineFailed++
		case StatusNotObservable:
			rs.NotObservable++
		case StatusImageAbsent:
			rs.ImageAbsent++
		default:
			rs.Error++
		}
	}
	for _, a := range attrs {
		rs := s.ByRule[a.Rule]
		add(&rs, a)
		s.ByRule[a.Rule] = rs
		add(&s.Total, a)
	}
	return s
}

// countMinimalSet counts the minimal set of a resolved attribution.
func countMinimalSet(rs *RuleSummary, a Attribution) {
	if len(a.MinimalSet) == 0 {
		return
	}
	if rs.ByMinimalSet == nil {
		rs.ByMinimalSet = map[string]int{}
	}
	rs.ByMinimalSet[setLabel(a.MinimalSet)]++
}

// setLabel writes a set in sorted order as "A + B".
func setLabel(set []string) string {
	return strings.Join(sortedCopy(set), " + ")
}

// documentSchemaVersion is the schema_version of attribution.json. Version 2
// adds the status RESOLVED_MINIMAL, the minimal set, the seeded block and the
// carried_over list.
const documentSchemaVersion = "2"

// Document is attribution.json. The study block (source, run, protocol,
// summary and attributions) holds the attribution of the real EXEC-01 and
// EXEC-02 failures of a study and is present when source.study_path is not
// empty. The seeded block holds the cases of a truth file. Each block can come
// from a different invocation: an invocation that does not produce a block
// keeps the one that the file already holds and lists it in carried_over.
type Document struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// Complete says whether the study block is complete. The seeded block
	// states its own completeness.
	Complete     bool             `json:"complete"`
	Source       Source           `json:"source"`
	Run          spec.RunMetadata `json:"run"`
	Protocol     Protocol         `json:"protocol"`
	Summary      Summary          `json:"summary"`
	Attributions []Attribution    `json:"attributions"`
	Seeded       *SeededReport    `json:"seeded,omitempty"`
	// CarriedOver names the blocks ("study" or "seeded") that this invocation
	// did not compute and took over from the previous attribution.json.
	CarriedOver []string `json:"carried_over,omitempty"`
}

// HasStudy reports whether the document holds a study block.
func (d *Document) HasStudy() bool { return d != nil && d.Source.StudyPath != "" }

// Source identifies the study the attribution is based on.
type Source struct {
	StudyPath          string `json:"study_path,omitempty"`
	StudySHA256        string `json:"study_sha256,omitempty"`
	StudySchemaVersion string `json:"study_schema_version,omitempty"`
}

// LoadDocument reads an attribution.json written by this tool.
func LoadDocument(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &doc, nil
}

// Protocol records the profile used so the result can be reproduced.
type Protocol struct {
	WindowMs        int64               `json:"window_ms"`
	DefensiveFlags  []string            `json:"defensive_flags"`
	MockEnv         []string            `json:"mock_env"`
	Treatments      map[string][]string `json:"treatments"`
	CapCandidates   []string            `json:"cap_candidates"`
	TmpfsCandidates []string            `json:"tmpfs_candidates"`
	TmpfsNote       string              `json:"tmpfs_note"`
	Survival        string              `json:"survival_criterion"`
	// Minimize records whether the resolving union was shrunk to a minimal
	// set, and MinimizeNote how.
	Minimize     bool   `json:"minimize"`
	MinimizeNote string `json:"minimize_note"`
}

// minimizeNote states the minimization method in the output, so that the file
// describes itself.
const minimizeNote = "When a union of candidates resolves a failure that no single candidate resolves, the union is shrunk in one pass: its elements are left out one at a time, in candidate order, and an element stays out when the container still survives the window. The empty set is the treatment alone, which failed, so it is not tested. The minimal set is sorted by name. Several minimal sets of the same size can exist and the one reached through the fixed candidate order is reported."

// NewProtocol describes the profile of this tool.
func NewProtocol(window time.Duration) Protocol {
	treatments := map[string][]string{}
	for _, rule := range []string{RuleReadOnly, RuleDropCaps} {
		flags, _ := treatmentFlags(rule)
		treatments[rule] = flags
	}
	return Protocol{
		WindowMs:        window.Milliseconds(),
		DefensiveFlags:  defensiveFlags,
		MockEnv:         mockEnv,
		Treatments:      treatments,
		CapCandidates:   capCandidates,
		TmpfsCandidates: tmpfsCandidates,
		TmpfsNote:       "Candidate mounts are tmpfs with " + candidateTmpfsOptions + ", added next to the treatment's own /tmp mount, which has the same options.",
		Survival:        "The container is running when the observation window ends.",
		MinimizeNote:    minimizeNote,
	}
}

// csvHeader is the column list of attribution.csv. The scope is "real" for the
// failures of a study and "seeded" for the cases of a truth file, whose rows
// also carry the verdict.
var csvHeader = []string{
	"image", "rule", "attribution_status", "kind", "candidate", "state", "exit_code",
	"survived", "resolved", "flags", "log_tail", "minimal_set", "scope", "verdict",
}

// Scopes of a CSV row.
const (
	scopeReal   = "real"
	scopeSeeded = "seeded"
)

// WriteOutputs writes attribution.json and attribution.csv into dir. Files are
// written atomically.
func WriteOutputs(dir string, doc *Document) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, attributionJSON), append(data, '\n')); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := WriteCSVDocument(&buf, doc); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, attributionCSV), buf.Bytes())
}

// Output file names of the attribution (docs/INTERFACE_V2.md section 6).
const (
	attributionJSON = "attribution.json"
	attributionCSV  = "attribution.csv"
)

// csvBlock is a list of attributions that share a scope. Verdicts is empty or
// parallel to Attributions.
type csvBlock struct {
	scope    string
	attrs    []Attribution
	verdicts []string
}

// WriteCSV writes one row per image, rule and attempt of the real failures: the
// baseline, the treatment, every single candidate, the union and every removal
// of the minimization. Targets that stopped before any container ran (image
// absent) get one row with an empty kind.
func WriteCSV(w *bytes.Buffer, attrs []Attribution) error {
	return writeCSV(w, csvBlock{scope: scopeReal, attrs: attrs})
}

// WriteCSVDocument writes the rows of the real failures, then those of the
// seeded cases.
func WriteCSVDocument(w *bytes.Buffer, doc *Document) error {
	blocks := []csvBlock{{scope: scopeReal, attrs: doc.Attributions}}
	if doc.Seeded != nil {
		seeded := csvBlock{scope: scopeSeeded}
		for _, c := range doc.Seeded.Cases {
			seeded.attrs = append(seeded.attrs, c.Attribution)
			seeded.verdicts = append(seeded.verdicts, c.Verdict)
		}
		blocks = append(blocks, seeded)
	}
	return writeCSV(w, blocks...)
}

func writeCSV(w *bytes.Buffer, blocks ...csvBlock) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, b := range blocks {
		for i, a := range b.attrs {
			verdict := ""
			if i < len(b.verdicts) {
				verdict = b.verdicts[i]
			}
			tail := []string{setLabel(a.MinimalSet), b.scope, verdict}
			if len(a.Attempts) == 0 {
				row := append([]string{a.Image, a.Rule, a.Status, "", "", "", "", "", "", "", oneLine(a.Detail, 160)}, tail...)
				if err := cw.Write(row); err != nil {
					return err
				}
				continue
			}
			for _, at := range a.Attempts {
				code := ""
				if at.Obs.ExitCode != nil {
					code = strconv.Itoa(*at.Obs.ExitCode)
				}
				row := append([]string{
					a.Image, a.Rule, a.Status, at.Kind, at.Candidate, at.Obs.State, code,
					strconv.FormatBool(at.Survived), strconv.FormatBool(at.Resolved),
					strings.Join(at.Flags, " "), oneLine(at.Obs.LogTail, 160),
				}, tail...)
				if err := cw.Write(row); err != nil {
					return err
				}
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// sortedCandidates returns the keys of a candidate count map in order.
func sortedCandidates(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedKeys returns the keys of a map with string keys in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
