package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Tool names used as keys throughout the benchmark. The order is the column
// order of the generated table.
const (
	ToolConUnit  = "conunit"
	ToolHadolint = "hadolint"
	ToolTrivy    = "trivy"
	ToolCST      = "cst"
	ToolDockle   = "dockle"
)

// allTools lists every tool in table column order.
var allTools = []string{ToolConUnit, ToolHadolint, ToolTrivy, ToolCST, ToolDockle}

// minNoteLength is the shortest note that can state a reason. An out-of-scope
// entry without a stated reason would read as an unexplained gap.
const minNoteLength = 15

// ToolScope states whether a property is in scope for one tool and which
// reported identifiers count as a detection. Source names the published
// catalog entry the scope was taken from and the version it was read at.
type ToolScope struct {
	InScope   bool     `json:"in_scope"`
	Pack      string   `json:"pack,omitempty"`   // conunit only: rule pack the property runs with
	Args      []string `json:"args,omitempty"`   // extra tool arguments (for example to enable an opt-in rule)
	Config    string   `json:"config,omitempty"` // cst only: test config relative to the oracle directory
	DetectIDs []string `json:"detect_ids,omitempty"`
	Source    string   `json:"source"`
	Note      string   `json:"note,omitempty"`
}

// Catalog records which published document a tool's scope entries were read
// from. Version is the tool version that document describes, and the run
// compares it with the version the binary reports. ConUnit is the tool under
// test, so its catalog is the rule catalog of the evaluated build and has no
// pinned version.
type Catalog struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ref       string `json:"ref,omitempty"` // immutable reference of the document, for example a commit
	URL       string `json:"url"`
	Retrieved string `json:"retrieved"` // date the document was read, YYYY-MM-DD
	Note      string `json:"note,omitempty"`
}

var retrievedDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// versionMentioned reports whether text names the version as a whole token, so
// that 0.4.15 is not found inside 10.4.150 or 0.4.151.
func versionMentioned(text, version string) bool {
	if version == "" {
		return false
	}
	re := regexp.MustCompile(`(^|[^0-9.])` + regexp.QuoteMeta(version) + `($|[^0-9])`)
	return re.MatchString(text)
}

// ImageRef is the local image reference of a corpus case: <prefix>/<case>:rq1.
// tier3_truth.json and the Tier 3 attribution tool use the same form.
func ImageRef(prefix, caseID string) string {
	return fmt.Sprintf("%s/%s:rq1", strings.TrimSuffix(prefix, "/"), caseID)
}

// Property is one defect class of the corpus.
type Property struct {
	Title string               `json:"title"`
	Tools map[string]ToolScope `json:"tools"`
}

// Case is one Dockerfile of the corpus with its ground truth.
type Case struct {
	ID            string `json:"id"`
	Dockerfile    string `json:"dockerfile"` // relative to the oracle directory
	Property      string `json:"property"`
	DefectPresent bool   `json:"defect_present"`
	Description   string `json:"description,omitempty"`
}

// Oracle is the ground truth document at fixtures/rq1/oracle.json.
type Oracle struct {
	SchemaVersion int                 `json:"schema_version"`
	Description   string              `json:"description,omitempty"`
	Tools         []string            `json:"tools"`
	Catalogs      map[string]Catalog  `json:"catalogs"`
	Properties    map[string]Property `json:"properties"`
	Cases         []Case              `json:"cases"`

	// Dir is the directory of the oracle file. Case and config paths are
	// relative to it. SHA256 identifies the exact oracle used for a run.
	Dir    string `json:"-"`
	SHA256 string `json:"-"`
}

// LoadOracle reads and validates an oracle file.
func LoadOracle(path string) (*Oracle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading oracle: %w", err)
	}
	var o Oracle
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("parsing oracle %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	o.SHA256 = hex.EncodeToString(sum[:])
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	o.Dir = filepath.Dir(abs)
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return &o, nil
}

// Validate checks the structural invariants of the oracle. It does not touch
// the file system; ValidateFiles does.
func (o *Oracle) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if len(o.Tools) == 0 {
		add("tools list is empty")
	}
	known := map[string]bool{}
	for _, t := range o.Tools {
		if known[t] {
			add("tool %q listed twice", t)
		}
		known[t] = true
	}
	for _, t := range allTools {
		if !known[t] {
			add("tool %q missing from tools list", t)
		}
	}

	for _, t := range o.Tools {
		cat, ok := o.Catalogs[t]
		if !ok {
			add("tool %q has no catalog entry", t)
			continue
		}
		if strings.TrimSpace(cat.Name) == "" || strings.TrimSpace(cat.URL) == "" {
			add("catalog of tool %q needs a name and a url", t)
		}
		if !retrievedDate.MatchString(cat.Retrieved) {
			add("catalog of tool %q needs a retrieved date (YYYY-MM-DD), has %q", t, cat.Retrieved)
		}
		if t != ToolConUnit && cat.Version == "" {
			add("catalog of tool %q needs the pinned version it was read at", t)
		}
	}
	for t := range o.Catalogs {
		if !known[t] {
			add("catalog declared for unknown tool %q", t)
		}
	}

	propIDs := make([]string, 0, len(o.Properties))
	for id := range o.Properties {
		propIDs = append(propIDs, id)
	}
	sort.Strings(propIDs)
	for _, id := range propIDs {
		p := o.Properties[id]
		if strings.TrimSpace(p.Title) == "" {
			add("property %q has no title", id)
		}
		for _, t := range o.Tools {
			scope, ok := p.Tools[t]
			if !ok {
				add("property %q has no scope entry for tool %q", id, t)
				continue
			}
			if strings.TrimSpace(scope.Note) == "" {
				add("property %q tool %q has no note", id, t)
			} else if !scope.InScope && len(strings.TrimSpace(scope.Note)) < minNoteLength {
				add("property %q tool %q is out of scope without a stated reason", id, t)
			}
			if strings.TrimSpace(scope.Source) == "" {
				add("property %q tool %q has no source", id, t)
			} else if cat := o.Catalogs[t]; cat.Version != "" && !versionMentioned(scope.Source, cat.Version) {
				add("property %q tool %q: source does not name the pinned catalog version %s", id, t, cat.Version)
			}
			if scope.InScope && len(scope.DetectIDs) == 0 {
				add("property %q tool %q is in scope but declares no detect_ids", id, t)
			}
			if scope.InScope && t == ToolConUnit && scope.Pack == "" {
				add("property %q conunit is in scope but declares no pack", id)
			}
			if scope.InScope && t == ToolCST && scope.Config == "" {
				add("property %q cst is in scope but declares no config", id)
			}
		}
		for t := range p.Tools {
			if !known[t] {
				add("property %q declares unknown tool %q", id, t)
			}
		}
	}

	seen := map[string]bool{}
	defects := map[string]int{}
	controls := map[string]int{}
	for _, c := range o.Cases {
		if c.ID == "" {
			add("a case has no id")
			continue
		}
		if seen[c.ID] {
			add("case id %q is not unique", c.ID)
		}
		seen[c.ID] = true
		if strings.TrimSpace(c.Dockerfile) == "" {
			add("case %q has no dockerfile", c.ID)
		}
		if _, ok := o.Properties[c.Property]; !ok {
			add("case %q references unknown property %q", c.ID, c.Property)
			continue
		}
		if c.DefectPresent {
			defects[c.Property]++
		} else {
			controls[c.Property]++
		}
	}
	for _, id := range propIDs {
		if defects[id] == 0 {
			add("property %q has no defect case", id)
		}
		if controls[id] != 1 {
			add("property %q must have exactly one clean control, has %d", id, controls[id])
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid oracle:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// ValidateFiles checks that every referenced Dockerfile and CST config exists.
func (o *Oracle) ValidateFiles() error {
	var problems []string
	for _, c := range o.Cases {
		if _, err := os.Stat(o.Path(c.Dockerfile)); err != nil {
			problems = append(problems, fmt.Sprintf("case %q: %v", c.ID, err))
		}
	}
	for id, p := range o.Properties {
		if s, ok := p.Tools[ToolCST]; ok && s.InScope {
			if _, err := os.Stat(o.Path(s.Config)); err != nil {
				problems = append(problems, fmt.Sprintf("property %q: %v", id, err))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("oracle references missing files:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// Path resolves a path that is relative to the oracle directory.
func (o *Oracle) Path(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(o.Dir, rel)
}

// Scope returns the tool scope of a case, inherited from its property.
func (o *Oracle) Scope(c Case, tool string) ToolScope {
	return o.Properties[c.Property].Tools[tool]
}

// PropertyOrder returns property IDs in order of first appearance in the
// case list, so the table follows the corpus order.
func (o *Oracle) PropertyOrder() []string {
	var order []string
	seen := map[string]bool{}
	for _, c := range o.Cases {
		if !seen[c.Property] {
			seen[c.Property] = true
			order = append(order, c.Property)
		}
	}
	return order
}

// CasesOf returns the cases of a property: defect cases first in file order,
// then the control.
func (o *Oracle) CasesOf(property string) []Case {
	var defects, controls []Case
	for _, c := range o.Cases {
		if c.Property != property {
			continue
		}
		if c.DefectPresent {
			defects = append(defects, c)
		} else {
			controls = append(controls, c)
		}
	}
	return append(defects, controls...)
}

// MatchID reports whether an observed identifier satisfies a detect pattern.
// A pattern is an exact identifier or a prefix followed by a single *.
func MatchID(pattern, id string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(id, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == id
}

// matchAny returns the sorted, de-duplicated observed identifiers that match
// at least one pattern.
func matchAny(patterns, observed []string) []string {
	set := map[string]bool{}
	for _, id := range observed {
		for _, p := range patterns {
			if MatchID(p, id) {
				set[id] = true
				break
			}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
