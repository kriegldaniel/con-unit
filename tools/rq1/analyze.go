package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// ResultsSchemaVersion identifies the layout of rq1_results.json.
const ResultsSchemaVersion = 1

// ToolCaseResult is the classification of one tool on one case plus the
// evidence needed to audit it.
type ToolCaseResult struct {
	Class       string   `json:"class"`
	InScope     bool     `json:"in_scope"`
	Pack        string   `json:"pack,omitempty"`
	Args        []string `json:"args,omitempty"`
	DetectIDs   []string `json:"detect_ids,omitempty"`
	Detected    []string `json:"detected_ids,omitempty"`
	ObservedIDs []string `json:"observed_ids,omitempty"` // every finding or failed test the tool reported
	// NotEvaluated lists the checkpoints the tool reported as not evaluated on
	// this image. ObservedLevels keeps the level Dockle printed per code. Both
	// are audit data: a level never decides a detection.
	NotEvaluated   []string          `json:"not_evaluated_ids,omitempty"`
	ObservedLevels map[string]string `json:"observed_levels,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Error          string            `json:"error,omitempty"`
	ExitCode       int               `json:"exit_code,omitempty"`
	Command        string            `json:"command,omitempty"`
	Notes          []string          `json:"notes,omitempty"`
	RawPath        string            `json:"raw_path,omitempty"` // relative to the output directory
}

// CaseResult is one corpus case with the verdict of every tool.
type CaseResult struct {
	ID            string      `json:"id"`
	Property      string      `json:"property"`
	Dockerfile    string      `json:"dockerfile"`
	DefectPresent bool        `json:"defect_present"`
	Build         BuildRecord `json:"build"`
	// Archive is the docker-archive export that Trivy and Dockle read, with
	// its config digest. It is absent when neither tool ran on the case.
	Archive *ArchiveRecord            `json:"archive,omitempty"`
	Tools   map[string]ToolCaseResult `json:"tools"`
}

// Metric is a ratio with its numerator and denominator. Value is nil when the
// denominator is zero.
type Metric struct {
	Numerator   int      `json:"numerator"`
	Denominator int      `json:"denominator"`
	Value       *float64 `json:"value"`
}

func newMetric(num, den int) Metric {
	m := Metric{Numerator: num, Denominator: den}
	if den > 0 {
		v := float64(num) / float64(den)
		m.Value = &v
	}
	return m
}

// ToolSummary aggregates the verdicts of one tool over all cases.
type ToolSummary struct {
	Status string         `json:"status"` // RAN, PARTIAL or NOT_RUN
	Counts map[string]int `json:"counts"`
	// Recall is TP/(TP+FN) over in-scope defect cases. Precision is
	// TP/(TP+FP). FalsePositiveRate is FP/(FP+TN) over clean controls. Out of
	// scope, not run, error and unverified cases enter none of them.
	Recall            Metric `json:"recall"`
	Precision         Metric `json:"precision"`
	FalsePositiveRate Metric `json:"false_positive_rate"`
	// OutOfScopeFlagged counts out-of-scope cases where a watched identifier
	// was reported anyway, to audit the scope declarations.
	OutOfScopeFlagged int `json:"out_of_scope_flagged"`
}

// Catalog version states.
const (
	catalogMatch     = "match"      // the binary reports the version the catalog was read at
	catalogMismatch  = "mismatch"   // the binary reports another version, so the scope entries may not describe it
	catalogNotRun    = "not_run"    // no version was observed
	catalogNotPinned = "not_pinned" // the catalog has no pinned version (ConUnit, the tool under test)
)

// CatalogStatus is a catalog of the oracle with the version the tool reported
// in this run. A mismatch does not stop the run, but the scope entries of that
// tool then describe a different version than the one that was measured.
type CatalogStatus struct {
	Catalog
	ObservedVersion string `json:"observed_version,omitempty"`
	State           string `json:"state"`
}

// Results is rq1_results.json.
type Results struct {
	SchemaVersion int                      `json:"schema_version"`
	GeneratedAt   time.Time                `json:"generated_at"`
	OraclePath    string                   `json:"oracle_path"`
	OracleSHA256  string                   `json:"oracle_sha256"`
	Run           *spec.RunMetadata        `json:"run,omitempty"`
	Engine        ToolInfo                 `json:"engine"`
	Tools         map[string]ToolInfo      `json:"tools"`
	Catalogs      map[string]CatalogStatus `json:"catalogs"`
	Cases         []CaseResult             `json:"cases"`
	Summary       map[string]ToolSummary   `json:"summary"`
}

// catalogStatuses compares the version each tool reported with the version its
// catalog was read at.
func catalogStatuses(o *Oracle, tools map[string]ToolInfo) map[string]CatalogStatus {
	out := map[string]CatalogStatus{}
	for name, cat := range o.Catalogs {
		st := CatalogStatus{Catalog: cat}
		info, ok := tools[name]
		switch {
		case cat.Version == "":
			st.State = catalogNotPinned
		case !ok || !info.Available || info.Version == "":
			st.State = catalogNotRun
		case versionMentioned(info.Version, cat.Version):
			st.ObservedVersion, st.State = info.Version, catalogMatch
		default:
			st.ObservedVersion, st.State = info.Version, catalogMismatch
		}
		out[name] = st
	}
	return out
}

// Analyze classifies every oracle case from the raw directory. It never runs a
// tool: the same raw directory always yields the same results, so the
// classification can be repeated offline.
func Analyze(o *Oracle, outDir string) (*Results, error) {
	rawDir := filepath.Join(outDir, "raw")
	var tools ToolsFile
	if err := readJSON(filepath.Join(rawDir, toolsFileName), &tools); err != nil {
		return nil, fmt.Errorf("reading %s (was the benchmark executed?): %w", toolsFileName, err)
	}
	res := &Results{
		SchemaVersion: ResultsSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		OracleSHA256:  o.SHA256,
		Engine:        tools.Engine,
		Tools:         tools.Tools,
		Catalogs:      catalogStatuses(o, tools.Tools),
		Summary:       map[string]ToolSummary{},
	}
	for _, c := range o.Cases {
		cr := CaseResult{
			ID:            c.ID,
			Property:      c.Property,
			Dockerfile:    c.Dockerfile,
			DefectPresent: c.DefectPresent,
			Tools:         map[string]ToolCaseResult{},
		}
		var run CaseRun
		haveRun := readJSON(filepath.Join(rawDir, c.ID, runFileName), &run) == nil
		if haveRun {
			cr.Build = run.Build
			cr.Archive = run.Archive
		} else {
			cr.Build = BuildRecord{Status: "skipped", Error: "no raw output for this case"}
		}
		for _, name := range o.Tools {
			cr.Tools[name] = classifyToolCase(o, c, name, tools, run, haveRun, rawDir, outDir)
		}
		res.Cases = append(res.Cases, cr)
	}
	for _, name := range o.Tools {
		res.Summary[name] = summarize(name, res.Cases)
	}
	return res, nil
}

func classifyToolCase(o *Oracle, c Case, tool string, tools ToolsFile, run CaseRun, haveRun bool, rawDir, outDir string) ToolCaseResult {
	scope := o.Scope(c, tool)
	out := ToolCaseResult{
		InScope:   scope.InScope,
		Pack:      scope.Pack,
		Args:      scope.Args,
		DetectIDs: scope.DetectIDs,
	}
	var obs Observation
	tr, ok := run.Tools[tool]
	switch {
	case !haveRun:
		obs.NotRunReason = "no raw output for this case"
	case !ok:
		obs.NotRunReason = "tool was not executed"
	default:
		out.ExitCode = tr.ExitCode
		out.Command = tr.Command
		out.Notes = tr.Notes
		switch tr.Status {
		case runStatusNotRun:
			obs.NotRunReason = tr.Reason
		case runStatusSkipped:
			// Deliberately skipped because the property has no policy for this
			// tool. The scope check in Classify turns this into OUT_OF_SCOPE.
		case runStatusError:
			obs.Error = tr.Error
		case runStatusRan:
			rel := filepath.Join("raw", c.ID, tr.Output)
			out.RawPath = rel
			raw, err := os.ReadFile(filepath.Join(outDir, rel))
			if err != nil {
				obs.Error = "raw output unreadable: " + err.Error()
				break
			}
			parsed, perr := parseTool(tool, raw)
			if perr != nil {
				obs.Error = perr.Error()
				break
			}
			obs = parsed
		default:
			obs.Error = fmt.Sprintf("unknown run status %q", tr.Status)
		}
	}
	// A tool that is globally absent is NOT_RUN in every row, whatever run.json says.
	if info, found := tools.Tools[tool]; found && (!info.Available || !info.Selected) && obs.NotRunReason == "" {
		obs.NotRunReason = info.Reason
	}
	v := Classify(scope, c.DefectPresent, obs)
	out.Class = v.Class
	out.Detected = v.Detected
	out.Reason = v.Reason
	out.Error = obs.Error
	out.ObservedIDs = obs.Flagged
	out.NotEvaluated = obs.NotEvaluated
	out.ObservedLevels = obs.Levels
	return out
}

func parseTool(tool string, raw []byte) (Observation, error) {
	switch tool {
	case ToolConUnit:
		return ParseConUnit(raw)
	case ToolHadolint:
		return ParseHadolint(raw)
	case ToolTrivy:
		return ParseTrivy(raw)
	case ToolCST:
		return ParseCST(raw)
	case ToolDockle:
		return ParseDockle(raw)
	}
	return Observation{}, fmt.Errorf("no parser for tool %q", tool)
}

func summarize(tool string, cases []CaseResult) ToolSummary {
	counts := map[string]int{}
	for _, c := range []string{ClassTP, ClassFP, ClassFN, ClassTN, ClassOutOfScope, ClassNotRun, ClassToolError, ClassUnverified, ClassNotEvaluated} {
		counts[c] = 0
	}
	flagged := 0
	for _, c := range cases {
		r := c.Tools[tool]
		counts[r.Class]++
		if r.Class == ClassOutOfScope && len(r.Detected) > 0 {
			flagged++
		}
	}
	status := "RAN"
	switch {
	case counts[ClassNotRun] == len(cases):
		status = "NOT_RUN"
	case counts[ClassNotRun] > 0 || counts[ClassToolError] > 0:
		status = "PARTIAL"
	}
	return ToolSummary{
		Status:            status,
		Counts:            counts,
		Recall:            newMetric(counts[ClassTP], counts[ClassTP]+counts[ClassFN]),
		Precision:         newMetric(counts[ClassTP], counts[ClassTP]+counts[ClassFP]),
		FalsePositiveRate: newMetric(counts[ClassFP], counts[ClassFP]+counts[ClassTN]),
		OutOfScopeFlagged: flagged,
	}
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
