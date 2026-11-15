package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

// Sources of the coverage matrix. Everything in the matrix that is not about
// ConUnit comes from these primary sources, read at the stated versions.
const (
	DockleSourceURL    = "https://github.com/goodwithtech/dockle"
	DockleSourceTag    = "v" + VerifiedDockleVersion
	DockleSourceCommit = "54368575d2a0c34a82fb05c904b8207284a64891"

	AnchorePackURL      = "https://docs.anchore.com/current/docs/compliance_management/policies/packs/cis/"
	AnchorePackVersion  = "Anchore CIS Docker Benchmark V1.8.0 v2026.1"
	AnchorePackModified = "September 22, 2026"
	AnchorePackRead     = "2026-11-15"
)

// Relation is how ConUnit stands to another tool for one property.
type Relation string

const (
	// RelOverlap: both tools check the property.
	RelOverlap Relation = "overlap"
	// RelConUnitOnly: ConUnit checks the property, the other tool does not.
	RelConUnitOnly Relation = "ConUnit-only"
	// RelDockleOnly: Dockle evaluates the property, ConUnit has no check.
	RelDockleOnly Relation = "Dockle-only"
	// RelAnchoreOnly: the Anchore pack has a control, ConUnit has no check.
	RelAnchoreOnly Relation = "Anchore-only"
	// RelNeither: the other tool names the property but does not evaluate it,
	// and ConUnit has no check either.
	RelNeither Relation = "neither"
	// RelOverlapNotComparable: both tools address the property, but the
	// cross-check on archives cannot compare them, because the other tool does
	// not report the checkpoint for an archive.
	RelOverlapNotComparable Relation = "overlap, not comparable"
)

// hardeningMembers are the 17 checks of PACK-CONUNIT-HARDENING in execution
// order (pkg/conunit/packs.go). A test compares this list with the pack.
var hardeningMembers = []string{
	"SPEC-01", "CIS-4.6", "FS-04", "SPEC-07", "SPEC-03", "FS-06", "FS-08", "FS-05", "FS-09", "FS-07",
	"SUP-02", "EXEC-02", "SPEC-05", "SPEC-06", "EXEC-07", "EXEC-01", "EXEC-04",
}

// lintMembers are the 16 checks of PACK-IMAGE-LINT in execution order, as fixed
// in docs/INTERFACE_V2.md section 3. A test compares this list with the pack.
var lintMembers = []string{
	"SPEC-01", "CIS-4.6", "FS-04", "SPEC-07", "SPEC-03", "FS-06", "FS-08", "FS-01",
	"SPEC-09", "SPEC-10", "SPEC-11", "SPEC-12", "SPEC-13", "FS-10", "FS-11", "FS-12",
}

// CoverageRow is one property of the matrix with the ConUnit check, the Dockle
// checkpoints and the Anchore control that address it.
type CoverageRow struct {
	Property string
	// Check is the ConUnit rule ID, empty when ConUnit has no check. Name is
	// the name of the rule in the rule catalog.
	Check string
	Name  string
	Tier  int
	// Dockle lists the checkpoint codes that address the property.
	Dockle []string
	// Anchore is the control number of the Anchore pack, empty when the pack
	// has no control for the property.
	Anchore   string
	VsDockle  Relation
	VsAnchore Relation
	Note      string
}

// InHardening reports whether the check is in the hardening profile.
func (r CoverageRow) InHardening() bool { return r.Check != "" && contains(hardeningMembers, r.Check) }

// InLint reports whether the check is in the lint pack.
func (r CoverageRow) InLint() bool { return r.Check != "" && contains(lintMembers, r.Check) }

// CoverageRows returns the matrix. ConUnit rows come first, in the order of the
// pack tables; then the checkpoints and controls that ConUnit has no check for.
//
// The Dockle side of a ConUnit row is the mapping of the cross-check, so the
// matrix and the cross-check cannot drift apart. The Anchore side is a
// judgement from the control texts of the pack documentation: the rule bodies
// of the pack are not public. A ConUnit check overlaps a control when the
// control text names the same property.
func CoverageRows() []CoverageRow {
	rows := []CoverageRow{
		{Property: "container runs as a non-root user", Check: "SPEC-01", Name: "Non-Root Execution Identity", Tier: 1, Anchore: "4.1"},
		{Property: "HEALTHCHECK instruction present", Check: "CIS-4.6", Name: "Image HEALTHCHECK", Tier: 1, Anchore: "4.6"},
		{Property: "setuid and setgid files removed", Check: "FS-04", Name: "SUID/SGID Privilege Escalation Vectors", Tier: 2, Anchore: "4.8"},
		{Property: "COPY used instead of ADD", Check: "SPEC-07", Name: "Instruction Hygiene (COPY over ADD)", Tier: 1, Anchore: "4.9"},
		{Property: "no secrets in the image environment", Check: "SPEC-03", Name: "Clean Ambient Environment", Tier: 1, Anchore: "4.10",
			Note: "Dockle shares CIS-DI-0010 between the environment part and the file-name part"},
		{Property: "no private key material in files", Check: "FS-06", Name: "Private Key Material Scan", Tier: 2, Anchore: "4.10",
			Note: "ConUnit reads file content, Dockle matches file names"},
		{Property: "no credential-named files", Check: "FS-12", Name: "No Credential-Named Files", Tier: 2, Anchore: "4.10",
			Note: "same file-name lists as Dockle; Dockle has no fixture exemption"},
		{Property: "no account with an empty password", Check: "FS-08", Name: "Account Security (Empty Passwords)", Tier: 2,
			Note: "the control text of the Anchore pack names secrets in Dockerfiles, not account passwords"},
		{Property: "update instruction not used alone", Check: "SPEC-09", Name: "Update Instruction Combined With Install", Tier: 1, Anchore: "4.7"},
		{Property: "no sudo in the build history", Check: "SPEC-10", Name: "No Sudo in the Build History", Tier: 1},
		{Property: "no distribution upgrade in the build history", Check: "SPEC-11", Name: "No Distribution Upgrade in the Build History", Tier: 1},
		{Property: "no sensitive host path declared as volume", Check: "SPEC-12", Name: "No Sensitive Host Paths as Volumes", Tier: 1},
		{Property: "image reference is not latest", Check: "SPEC-13", Name: "Explicit Non-Latest Image Reference", Tier: 1,
			Note: "Dockle reports DKL-DI-0006 only for an image name, never for an archive, so the pair is not comparable in the cross-check"},
		{Property: "package manager caches removed", Check: "FS-01", Name: "Package Manager Cache Elimination", Tier: 2,
			Note: "ConUnit checks the resulting filesystem, Dockle judges the recorded commands"},
		{Property: "account and group IDs are unique", Check: "FS-10", Name: "Unique Account and Group IDs", Tier: 2},
		{Property: "no development, editor, cache or cloud leftovers", Check: "FS-11", Name: "No Development, Editor, Cache or Cloud Leftovers", Tier: 2},
		{Property: "declared ports are not privileged", Check: "SPEC-05", Name: "Non-Privileged Declared Image Ports", Tier: 1, Anchore: "5.8",
			Note: "ConUnit reads declared ports, the control concerns ports mapped at run time"},
		{Property: "no debug port declared", Check: "SPEC-06", Name: "Dangling Debug Port Exclusion", Tier: 1},
		{Property: "no world-writable regular file", Check: "FS-05", Name: "World-Writable File Elimination", Tier: 2},
		{Property: "system directory files owned by root", Check: "FS-09", Name: "System Directory Ownership Hygiene", Tier: 2},
		{Property: "no test harness files", Check: "FS-07", Name: "Development and Test Harness Leakage", Tier: 2},
		{Property: "image signature verifies", Check: "SUP-02", Name: "Cryptographic Image Provenance & Signature", Tier: 4,
			Note: "verifies a signature with a configured trust policy; it is not the content-trust setting of CIS-DI-0005"},
		{Property: "starts with a read-only root filesystem", Check: "EXEC-01", Name: "Read-Only Root Filesystem Conformance", Tier: 3},
		{Property: "starts with all capabilities dropped", Check: "EXEC-02", Name: "Dropped Linux Capabilities Conformance", Tier: 3},
		{Property: "starts with no-new-privileges", Check: "EXEC-04", Name: "No-New-Privileges Kernel Contract", Tier: 3},
		{Property: "starts within a memory limit", Check: "EXEC-07", Name: "Resource Constraint Conformance", Tier: 3},
	}
	// The Dockle side of a ConUnit row comes from the mapping.
	for i := range rows {
		if m, ok := MappingFor(rows[i].Check); ok {
			rows[i].Dockle = append([]string(nil), m.Codes...)
			rows[i].VsDockle = RelOverlap
			if !m.Comparable() {
				rows[i].VsDockle = RelOverlapNotComparable
			}
		} else {
			rows[i].VsDockle = RelConUnitOnly
		}
		if rows[i].Anchore != "" {
			rows[i].VsAnchore = RelOverlap
		} else {
			rows[i].VsAnchore = RelConUnitOnly
		}
	}
	// Properties that ConUnit has no check for. The CIS-DI number of Dockle
	// follows the number of the control in section 4 of the CIS Docker
	// Benchmark that the Anchore pack also uses: both sources list the same
	// eleven titles in the same order.
	rows = append(rows,
		CoverageRow{Property: "trusted base images", Dockle: []string{"CIS-DI-0002"}, Anchore: "4.2",
			VsDockle: RelNeither, VsAnchore: RelAnchoreOnly,
			Note: "Dockle documents content trust under this code but no code emits it; the Anchore control needs a site configuration"},
		CoverageRow{Property: "no unnecessary packages", Dockle: []string{"CIS-DI-0003"}, Anchore: "4.3",
			VsDockle: RelNeither, VsAnchore: RelAnchoreOnly,
			Note: "Dockle documents it as not supported; the Anchore control needs a site configuration; ConUnit has such checks outside both packs"},
		CoverageRow{Property: "images scanned and rebuilt for security patches", Dockle: []string{"CIS-DI-0004"}, Anchore: "4.4",
			VsDockle: RelNeither, VsAnchore: RelAnchoreOnly,
			Note: "Dockle documents it as not supported and points to a vulnerability scanner; ConUnit has no vulnerability check"},
		CoverageRow{Property: "Docker content trust enabled", Dockle: []string{"CIS-DI-0005"},
			VsDockle: RelDockleOnly, VsAnchore: RelNeither,
			Note: "Dockle reads DOCKER_CONTENT_TRUST of the scanning host, not the image, so the checkpoint is excluded from the cross-check"},
		CoverageRow{Property: "only verified packages installed", Dockle: []string{"CIS-DI-0011"},
			VsDockle: RelNeither, VsAnchore: RelNeither,
			Note: "Dockle documents it as not supported; the Anchore pack does not list control 4.11"},
	)
	return rows
}

// ---------------------------------------------------------------------------
// Statements derived from the data

// CoverageSummary holds the counts that the documentation states. They are
// computed from the rows, never typed.
type CoverageSummary struct {
	// Hardening profile.
	HardeningChecks       int
	HardeningStatic       int // tier 1 and tier 2
	HardeningStaticDockle int // static checks with a Dockle counterpart
	HardeningStaticOnly   []string
	HardeningOther        []string // tier 3 and 4 checks
	// Dockle.
	DockleCheckpoints    int // catalog entries
	DockleCISDI          int
	DockleDKLDI          int
	DockleDKLLI          int
	DockleCISDIEvaluated int
	DockleImageLevel     []string // checkpoints evaluated from the image
	DockleImageCovered   []string // of those, with a check in the lint pack
	DockleImageUncovered []string
	// NotComparable lists the checks that have a Dockle counterpart which the
	// cross-check on archives cannot compare.
	NotComparable []string
	// Lint pack.
	LintChecks int
	// Anchore pack.
	AnchoreControls  int
	AnchoreCovered   []string
	AnchoreUncovered []string
}

// Summarize derives the counts from the matrix.
func Summarize(rows []CoverageRow) CoverageSummary {
	var s CoverageSummary
	s.HardeningChecks = len(hardeningMembers)
	s.LintChecks = len(lintMembers)
	for _, r := range rows {
		if r.Check != "" && r.VsDockle == RelOverlapNotComparable {
			s.NotComparable = append(s.NotComparable, r.Check)
		}
		if r.Check != "" && r.InHardening() {
			if r.Tier == 1 || r.Tier == 2 {
				s.HardeningStatic++
				if len(r.Dockle) > 0 {
					s.HardeningStaticDockle++
				} else {
					s.HardeningStaticOnly = append(s.HardeningStaticOnly, r.Check)
				}
			} else {
				s.HardeningOther = append(s.HardeningOther, r.Check)
			}
		}
	}
	lintByCode := map[string]string{}
	for _, r := range rows {
		if r.Check != "" && r.InLint() {
			for _, c := range r.Dockle {
				lintByCode[c] = r.Check
			}
		}
	}
	for _, c := range DockleCatalog() {
		s.DockleCheckpoints++
		switch {
		case strings.HasPrefix(c.Code, "CIS-DI-"):
			s.DockleCISDI++
			if c.Status == StatusImage || c.Status == StatusHostEnvironment {
				s.DockleCISDIEvaluated++
			}
		case strings.HasPrefix(c.Code, "DKL-DI-"):
			s.DockleDKLDI++
		case strings.HasPrefix(c.Code, "DKL-LI-"):
			s.DockleDKLLI++
		}
		if c.Status != StatusImage {
			continue
		}
		s.DockleImageLevel = append(s.DockleImageLevel, c.Code)
		if _, ok := lintByCode[c.Code]; ok {
			s.DockleImageCovered = append(s.DockleImageCovered, c.Code)
		} else {
			s.DockleImageUncovered = append(s.DockleImageUncovered, c.Code)
		}
	}
	// Anchore controls, in the order of the pack page.
	for _, c := range AnchoreControls() {
		s.AnchoreControls++
		covered := false
		for _, r := range rows {
			if r.Check != "" && r.Anchore == c.Control && (r.InHardening() || r.InLint()) {
				covered = true
			}
		}
		if covered {
			s.AnchoreCovered = append(s.AnchoreCovered, c.Control)
		} else {
			s.AnchoreUncovered = append(s.AnchoreUncovered, c.Control)
		}
	}
	return s
}

// AnchoreControl is one control of the Anchore CIS pack.
type AnchoreControl struct {
	Control string
	// Short is a descriptor in the words of this project.
	Short string
	// NeedsConfiguration is true when the pack page marks the rule set as
	// required to configure for the environment.
	NeedsConfiguration bool
}

// AnchoreControls lists the controls of the pack as the documentation page
// states them for the pack version AnchorePackVersion.
func AnchoreControls() []AnchoreControl {
	return []AnchoreControl{
		{"4.1", "container user created", false},
		{"4.2", "trusted base images", true},
		{"4.3", "no unnecessary packages", true},
		{"4.4", "images scanned and rebuilt for patches", false},
		{"4.6", "HEALTHCHECK present", false},
		{"4.7", "update instruction not used alone", false},
		{"4.8", "setuid and setgid removed", false},
		{"4.9", "COPY instead of ADD", false},
		{"4.10", "secrets not stored", false},
		{"5.8", "privileged ports not mapped", true},
	}
}

// ---------------------------------------------------------------------------
// Markdown

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func list(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, ", ")
}

func codes(c []string) string {
	if len(c) == 0 {
		return "none"
	}
	return strings.Join(c, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// RenderCoverageMarkdown renders docs/COVERAGE_MATRIX.md.
func RenderCoverageMarkdown() string {
	rows := CoverageRows()
	sum := Summarize(rows)
	var w strings.Builder
	w.WriteString("# Coverage matrix: ConUnit, Dockle and the Anchore CIS pack\n\n")
	w.WriteString("Generated by `go run ./tools/crosscheck coverage -md docs/COVERAGE_MATRIX.md`. Do not edit by hand: a test fails when this file differs from the generator output. The same data produces `table_coverage.tex` (label `tab:coverage`).\n\n")

	w.WriteString("## What it compares\n\n")
	w.WriteString("Every check of the ConUnit hardening profile (`PACK-CONUNIT-HARDENING`, 17 checks) and of the planned `lint` pack (`PACK-IMAGE-LINT`, 16 checks) against every checkpoint of Dockle and every control of the Anchore CIS policy pack. A row is a property. For each row the matrix says whether ConUnit and the other tool both check it (overlap), only ConUnit does (ConUnit-only), only Dockle evaluates it (Dockle-only) or only the Anchore pack has a control for it (Anchore-only). `neither` marks a property that another tool names but does not evaluate while ConUnit has no check either. `overlap, not comparable` marks a property that both tools address but that the cross-check on archives cannot compare.\n\n")

	w.WriteString("## Sources\n\n")
	fmt.Fprintf(&w, "- Dockle: %s, tag `%s`, commit `%s`. Read: `CHECKPOINT.md`, `README.md`, `pkg/types/checkpoint.go`, `pkg/report/json.go`, `pkg/report/writer.go`, `pkg/run.go` and the assessors under `pkg/assessor`. The catalog and the behaviours are those of this version only.\n", DockleSourceURL, DockleSourceTag, DockleSourceCommit)
	fmt.Fprintf(&w, "- Anchore CIS policy pack: %s, page \"CIS\" of the Anchore Enterprise documentation, pack version \"%s\", page last modified %s, read on %s. The page lists ten controls. The rule bodies of the pack are delivered to customers and are not public, so the Anchore column is a judgement from the control texts. Control titles are described in our own words.\n", AnchorePackURL, AnchorePackVersion, AnchorePackModified, AnchorePackRead)
	w.WriteString("- ConUnit: the rule catalog of this repository (`pkg/conunit/rules.go`, `pkg/conunit/packs.go`) for the hardening profile. For the `lint` pack, the member list and the eight new checks are taken from `docs/INTERFACE_V2.md` section 3. A test compares the lists here with the pack.\n")
	w.WriteString("- Dockle checkpoints of the form CIS-DI-00NN carry the number NN of the control in section 4 of the CIS Docker Benchmark: the Dockle checkpoint list and the Anchore control list give the same titles in the same order. The numbers of the Anchore pack are those of the Docker Benchmark 1.8.\n\n")

	w.WriteString("## Matrix\n\n")
	w.WriteString("H: in the hardening profile. L: in the lint pack. Tier is the ConUnit tier of the check.\n\n")
	w.WriteString("| Property | ConUnit check | Tier | H | L | Dockle checkpoint | vs Dockle | Anchore control | vs Anchore |\n")
	w.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, r := range rows {
		check, tier, h, l := "none", "", "", ""
		if r.Check != "" {
			check, tier, h, l = fmt.Sprintf("`%s` %s", r.Check, r.Name), fmt.Sprint(r.Tier), yesNo(r.InHardening()), yesNo(r.InLint())
		}
		fmt.Fprintf(&w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.Property, check, tier, h, l, codes(r.Dockle), r.VsDockle, orNone(r.Anchore), r.VsAnchore)
	}
	w.WriteString("\nNotes on single rows:\n\n")
	for _, r := range rows {
		if r.Note == "" {
			continue
		}
		label := r.Check
		if label == "" {
			label = strings.Join(r.Dockle, ", ")
		}
		fmt.Fprintf(&w, "- %s: %s.\n", label, r.Note)
	}

	w.WriteString("\n## What the matrix shows\n\n")
	fmt.Fprintf(&w, "- Hardening profile: %d of the %d static checks (tier 1 and 2) have a Dockle counterpart (%s). %d have none (%s). The other %d checks of the profile are tier 3 and tier 4 checks (%s) and have no counterpart in Dockle or in the Anchore pack. This answers the statement of an external review that Dockle covers roughly 7 of ConUnit's 11 static checks: the matrix counts %d static checks in the profile where that review counts 11, and %d of them overlap.\n",
		sum.HardeningStaticDockle, sum.HardeningStatic, listOverlap(rows), len(sum.HardeningStaticOnly), list(sum.HardeningStaticOnly), len(sum.HardeningOther), list(sum.HardeningOther),
		sum.HardeningStatic, sum.HardeningStaticDockle)
	fmt.Fprintf(&w, "- Dockle documents %d checkpoints: %d CIS-DI, %d DKL-DI and %d DKL-LI. Of the %d CIS-DI checkpoints, %d have a code path in Dockle %s and the rest are documented without one or as not supported. This second \"%d of %d\" is a fact about Dockle, not about ConUnit, and is not the figure of the external review.\n",
		sum.DockleCheckpoints, sum.DockleCISDI, sum.DockleDKLDI, sum.DockleDKLLI, sum.DockleCISDI, sum.DockleCISDIEvaluated, VerifiedDockleVersion, sum.DockleCISDIEvaluated, sum.DockleCISDI)
	fmt.Fprintf(&w, "- Image-level checkpoints: Dockle evaluates %d checkpoints from the image (%s). With the lint pack, every one of them has a ConUnit check: %d of %d are covered (uncovered: %s).\n",
		len(sum.DockleImageLevel), list(sum.DockleImageLevel), len(sum.DockleImageCovered), len(sum.DockleImageLevel), list(sum.DockleImageUncovered))
	fmt.Fprintf(&w, "- Not comparable from an archive: %s. Dockle evaluates DKL-DI-0006 only when it receives an image name, so the cross-check of this work cannot compare it, although the property is covered.\n", list(sum.NotComparable))
	fmt.Fprintf(&w, "- Excluded checkpoints: %s. CIS-DI-0005 reads the DOCKER_CONTENT_TRUST variable of the scanning host, not the image. CIS-DI-0002 is documented as content trust and has no code path, so it is never emitted. Neither is an image-level checkpoint.\n", list(excludedCodeNames()))
	fmt.Fprintf(&w, "- Checkpoints that Dockle documents as not supported and that ConUnit has no check for: %s.\n", list(notSupportedCodes()))
	fmt.Fprintf(&w, "- Anchore pack: %d controls. ConUnit has a check for %d of them in the two packs (%s). No ConUnit check addresses %s.\n",
		sum.AnchoreControls, len(sum.AnchoreCovered), list(sum.AnchoreCovered), list(sum.AnchoreUncovered))
	fmt.Fprintf(&w, "- Checks that neither Dockle nor the Anchore pack has a counterpart for: %s. The tier 3 checks among them start the image; Dockle and the Anchore pack only read it.\n", list(onlyConUnit(rows)))
	fmt.Fprintf(&w, "- Checkpoints that only Dockle evaluates: %s. They concern the scanning host and are excluded from the cross-check.\n\n", list(onlyDockle(rows)))

	w.WriteString("## Controls of the Anchore pack\n\n")
	w.WriteString("| Control | Descriptor | Site configuration required | ConUnit checks | Dockle checkpoint |\n| --- | --- | --- | --- | --- |\n")
	for _, c := range AnchoreControls() {
		var checks, dockle []string
		for _, r := range rows {
			if r.Anchore != c.Control {
				continue
			}
			if r.Check != "" && (r.InHardening() || r.InLint()) {
				checks = append(checks, r.Check)
			}
			for _, d := range r.Dockle {
				if !contains(dockle, d) {
					dockle = append(dockle, d)
				}
			}
		}
		fmt.Fprintf(&w, "| %s | %s | %s | %s | %s |\n", c.Control, c.Short, yesNo(c.NeedsConfiguration), list(checks), list(dockle))
	}
	w.WriteString("\n")

	w.WriteString("## Dockle catalog at the verified version\n\n")
	w.WriteString("| Code | Descriptor | Default level | Status | Source |\n| --- | --- | --- | --- | --- |\n")
	for _, c := range DockleCatalog() {
		level := c.Default
		if level == "" {
			level = "never emitted"
		}
		fmt.Fprintf(&w, "| %s | %s | %s | %s | %s |\n", c.Code, c.Short, level, c.Status, c.Note)
	}

	w.WriteString("\n## Limits\n\n")
	w.WriteString("- The matrix compares what the checks are designed to find. It says nothing about how often two checks agree on real images; that is the cross-check (`crosscheck.json`, `tab:crosscheck`).\n")
	w.WriteString("- Overlap means the same property, not the same implementation. Where the implementations differ on purpose, `discordances.csv` of the cross-check states the difference.\n")
	w.WriteString("- The Anchore column rests on ten control texts. A pack rule that is stricter or looser than its control text is not visible here.\n")
	w.WriteString("- The Dockle catalog is that of one release. A later release can add or change checkpoints.\n")
	return w.String()
}

func excludedCodeNames() []string {
	var out []string
	for _, e := range ExcludedCodes() {
		out = append(out, e.Code)
	}
	return out
}

func notSupportedCodes() []string {
	var out []string
	for _, c := range DockleCatalog() {
		if c.Status == StatusNotSupported {
			out = append(out, c.Code)
		}
	}
	return out
}

// onlyConUnit lists the ConUnit checks that neither Dockle nor the Anchore pack
// has a counterpart for.
func onlyConUnit(rows []CoverageRow) []string {
	var out []string
	for _, r := range rows {
		if r.Check != "" && r.VsDockle == RelConUnitOnly && r.VsAnchore == RelConUnitOnly {
			out = append(out, r.Check)
		}
	}
	return out
}

// onlyDockle lists the checkpoints that only Dockle evaluates.
func onlyDockle(rows []CoverageRow) []string {
	var out []string
	for _, r := range rows {
		if r.Check == "" && r.VsDockle == RelDockleOnly {
			out = append(out, r.Dockle...)
		}
	}
	return out
}

// listOverlap names the static checks of the hardening profile that have a
// Dockle counterpart.
func listOverlap(rows []CoverageRow) string {
	var out []string
	for _, r := range rows {
		if r.InHardening() && (r.Tier == 1 || r.Tier == 2) && len(r.Dockle) > 0 {
			out = append(out, r.Check)
		}
	}
	return strings.Join(out, ", ")
}

// ---------------------------------------------------------------------------
// LaTeX

func relationTex(r Relation) string { return tex.Escape(string(r)) }

// RenderCoverageTable renders table_coverage.tex, label tab:coverage.
func RenderCoverageTable() string {
	rows := CoverageRows()
	var w strings.Builder
	w.WriteString("% Generated by tools/crosscheck. Do not edit.\n")
	w.WriteString("\\begin{table*}[t]\n\\centering\n\\footnotesize\n")
	fmt.Fprintf(&w, "\\caption{Coverage of the properties that ConUnit checks, that Dockle %s checks and that the Anchore CIS policy pack lists. "+
		"H: the check is in the hardening profile. L: the check is in the lint pack. "+
		"Overlap: both tools check the property. ConUnit-only: only ConUnit checks it. Dockle-only: only Dockle evaluates it. Anchore-only: only the Anchore pack has a control for it. "+
		"Neither: the other tool names the property but does not evaluate it. "+
		"Overlap, not comparable: both tools address the property, but Dockle does not report the checkpoint for an archive, so the cross-check cannot compare them. "+
		"The Dockle checkpoint %s reads the scanning host and is excluded from the cross-check. "+
		"The rule bodies of the Anchore pack (%s) are not public, so its column is judged from the control texts. "+
		"Sources: Dockle %s at commit %s and the Anchore documentation read on %s.}\n",
		tex.Escape(DockleSourceTag), tex.Texttt("CIS-DI-0005"), tex.Escape(AnchorePackVersion), tex.Escape(DockleSourceTag), tex.Texttt(DockleSourceCommit[:8]), tex.Escape(AnchorePackRead))
	w.WriteString("\\label{tab:coverage}\n")
	w.WriteString("\\begin{tabular}{@{}p{4.1cm}lccp{2.9cm}lll@{}}\n\\toprule\n")
	w.WriteString(`\textbf{Property} & \textbf{ConUnit} & \textbf{H} & \textbf{L} & \textbf{Dockle} & \textbf{vs Dockle} & \textbf{Anchore} & \textbf{vs Anchore}`)
	w.WriteString(" \\\\\n\\midrule\n")
	for _, r := range rows {
		check, h, l := "none", "", ""
		if r.Check != "" {
			check, h, l = tex.Texttt(r.Check), yesNoMark(r.InHardening()), yesNoMark(r.InLint())
		}
		dockle := "none"
		if len(r.Dockle) > 0 {
			dockle = tex.Texttt(strings.Join(r.Dockle, ", "))
		}
		anchore := "none"
		if r.Anchore != "" {
			anchore = tex.Escape(r.Anchore)
		}
		fmt.Fprintf(&w, "%s & %s & %s & %s & %s & %s & %s & %s \\\\\n",
			tex.Escape(r.Property), check, h, l, dockle, relationTex(r.VsDockle), anchore, relationTex(r.VsAnchore))
	}
	w.WriteString("\\bottomrule\n\\end{tabular}\n\\end{table*}\n")
	return w.String()
}

func yesNoMark(b bool) string {
	if b {
		return "x"
	}
	return "-"
}

// ---------------------------------------------------------------------------
// Command

func runCoverage(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("crosscheck coverage", flag.ContinueOnError)
	fset.SetOutput(stderr)
	md := fset.String("md", "", "write the Markdown matrix to this file")
	texOut := fset.String("tex", "", "write the LaTeX table to this file")
	if err := fset.Parse(args); err != nil {
		return spec.ExitUsage
	}
	log, problem := clilog.New(stdout), clilog.New(stderr)
	if *md == "" && *texOut == "" {
		fmt.Fprintln(stderr, "usage: crosscheck coverage [-md FILE] [-tex FILE]")
		return spec.ExitUsage
	}
	for _, f := range []struct{ path, content string }{
		{*md, RenderCoverageMarkdown()},
		{*texOut, RenderCoverageTable()},
	} {
		if f.path == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			problem.Error("%v", err)
			return spec.ExitFindings
		}
		if err := os.WriteFile(f.path, []byte(f.content), 0o644); err != nil {
			problem.Error("cannot write %s: %v", f.path, err)
			return spec.ExitFindings
		}
		log.Success("wrote %s", f.path)
	}
	return spec.ExitOK
}
