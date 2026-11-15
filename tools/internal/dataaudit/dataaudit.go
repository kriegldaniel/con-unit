// Package dataaudit defines fixtures/evaluation_dataset_audit.json, the
// record of how the evaluation dataset was sampled, filtered and pinned.
//
// tools/pin_dataset writes the file. tools/export_latex.go reads the
// candidate and pinned counts and the exclusion log from it for the flow
// table, and tools/verify_eval_integrity.sh reconciles it with the lists.
package dataaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// SchemaVersion is the layout version of the audit file.
const SchemaVersion = "1"

// Unrecorded is written for sampling frame fields that were not supplied.
const Unrecorded = "unrecorded"

// ListInfo identifies one list file by content.
type ListInfo struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Entries int    `json:"entries"`
	// DeclaredN is the N stated in the list header comment, when present.
	DeclaredN *int `json:"declared_n,omitempty"`
}

// Frame is the sampling frame: the Docker Official Images library state the
// candidate list was drawn from.
type Frame struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Date       string `json:"date"`
}

// Recorded reports whether both commit and date were supplied.
func (f Frame) Recorded() bool {
	return f.Commit != "" && f.Commit != Unrecorded && f.Date != "" && f.Date != Unrecorded
}

// Exclusion is one candidate that did not enter the pinned list.
type Exclusion struct {
	OriginalTag string `json:"original_tag"`
	Status      string `json:"status"` // EXCLUDED_SINGLE_ARCH or FAILED
	Reason      string `json:"reason"`
}

// Deprecated flags a candidate that appears in the optional deprecated list.
type Deprecated struct {
	OriginalTag string `json:"original_tag"`
	Pinned      bool   `json:"pinned"`
}

// Counts summarises the dataset flow.
type Counts struct {
	Candidates int `json:"candidates"`
	Pinned     int `json:"pinned"`
	Excluded   int `json:"excluded"`
	Failed     int `json:"failed"`
	Deprecated int `json:"deprecated_flagged"`
}

// Top10Info records the subset check of the fast evaluation list.
type Top10Info struct {
	Input         ListInfo `json:"input"`
	Pinned        ListInfo `json:"pinned"`
	AllInMain     bool     `json:"all_in_main_pinned_list"`
	MissingInMain []string `json:"missing_in_main_pinned_list,omitempty"`
}

// Outputs lists the files produced by the pinning run.
type Outputs struct {
	PinnedTxt  ListInfo   `json:"pinned_txt"`
	PinnedJSON ListInfo   `json:"pinned_json"`
	Top10      *Top10Info `json:"top10,omitempty"`
}

// Audit is the complete audit document.
type Audit struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          string       `json:"tool"`
	ToolVersion   string       `json:"tool_version"`
	GeneratedAt   string       `json:"generated_at"`
	Mode          string       `json:"mode"` // "registry" or "audit-only"
	Frame         Frame        `json:"sampling_frame"`
	InclusionRule string       `json:"inclusion_rule"`
	Platform      string       `json:"evaluation_platform"`
	Input         ListInfo     `json:"input"`
	Outputs       Outputs      `json:"outputs"`
	Counts        Counts       `json:"counts"`
	ExclusionLog  []Exclusion  `json:"exclusion_log"`
	Deprecated    []Deprecated `json:"deprecated,omitempty"`
}

// Load reads and validates an audit file.
func Load(path string) (*Audit, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var a Audit
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if problems := a.Validate(); len(problems) > 0 {
		return &a, fmt.Errorf("invalid audit %s: %s", path, problems[0])
	}
	return &a, nil
}

// Validate checks internal consistency and returns every problem found.
func (a *Audit) Validate() []string {
	var p []string
	if a.SchemaVersion != SchemaVersion {
		p = append(p, fmt.Sprintf("schema_version %q, want %q", a.SchemaVersion, SchemaVersion))
	}
	c := a.Counts
	if c.Candidates != c.Pinned+c.Excluded+c.Failed {
		p = append(p, fmt.Sprintf("counts do not reconcile: candidates %d != pinned %d + excluded %d + failed %d",
			c.Candidates, c.Pinned, c.Excluded, c.Failed))
	}
	if len(a.ExclusionLog) != c.Excluded+c.Failed {
		p = append(p, fmt.Sprintf("exclusion_log has %d entries, counts say %d", len(a.ExclusionLog), c.Excluded+c.Failed))
	}
	if a.Input.Entries != c.Candidates {
		p = append(p, fmt.Sprintf("input has %d entries, counts say %d candidates", a.Input.Entries, c.Candidates))
	}
	if a.Outputs.PinnedTxt.Entries != c.Pinned {
		p = append(p, fmt.Sprintf("pinned list has %d entries, counts say %d pinned", a.Outputs.PinnedTxt.Entries, c.Pinned))
	}
	if t := a.Outputs.Top10; t != nil && !t.AllInMain && len(t.MissingInMain) == 0 {
		p = append(p, "top10 marked as not contained but lists no missing entries")
	}
	return p
}

// ExclusionsByStatus returns the exclusion log grouped by status, with the
// statuses sorted.
func (a *Audit) ExclusionsByStatus() (statuses []string, counts map[string]int) {
	counts = map[string]int{}
	for _, e := range a.ExclusionLog {
		counts[e.Status]++
	}
	for s := range counts {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	return statuses, counts
}
