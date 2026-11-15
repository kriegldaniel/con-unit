// Command pin_dataset resolves the candidate image tags of the evaluation
// dataset to immutable multi-architecture index digests and records how the
// dataset came to be in fixtures/evaluation_dataset_audit.json.
//
// Registry use: the tool issues one manifest GET per candidate, so a run of
// about 108 candidates costs about 108 anonymous Docker Hub pulls. Docker Hub
// allows 100 anonymous pulls per six hours, so run the tool at most once per
// six hours and keep -delay above zero. On HTTP 429 the run stops, reports
// the candidate it reached and leaves every output file untouched.
//
// Offline use: with -audit-only the tool performs no network request. It
// rebuilds the audit file from the existing pinned list, pinned JSON and
// input list, which also repeats the top-10 containment check.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/clilog"
	"github.com/con-unit/con-unit/tools/internal/dataaudit"
)

// toolVersion identifies the pinning protocol written to the audit file.
const toolVersion = "pin_dataset 2"

// Statuses of a candidate after pinning.
const (
	statusPinned       = "PINNED"
	statusExcludedArch = "EXCLUDED_SINGLE_ARCH"
	statusFailed       = "FAILED"
)

const (
	evaluationPlatform = "linux/amd64"
	defaultFrameRepo   = "docker-library/official-images"

	// inclusionRuleFormat is the inclusion rule recorded in the audit file.
	inclusionRuleFormat = "A candidate is included when its tag resolves to a multi-platform OCI index or Docker manifest list that contains " +
		"both linux/amd64 and linux/arm64 manifests. The index digest is pinned. Single-architecture candidates are excluded and logged. " +
		"The evaluation itself runs on %s."
)

// Exit codes follow docs/CONTRACT.md.
const (
	exitOK         = spec.ExitOK
	exitFailure    = spec.ExitFindings
	exitUsage      = spec.ExitUsage
	exitIncomplete = spec.ExitIncomplete
)

// PinnedImageRecord is one entry of fixtures/evaluation_dataset_pinned.json.
type PinnedImageRecord struct {
	OriginalTag    string `json:"original_tag"`
	ImmutableRef   string `json:"immutable_ref,omitempty"`
	ManifestDigest string `json:"manifest_digest,omitempty"`
	Platform       string `json:"platform,omitempty"`
	Status         string `json:"status"` // PINNED, EXCLUDED_SINGLE_ARCH, or FAILED
	Error          string `json:"error,omitempty"`
}

// manifestInfo is what the pinning logic needs to know about a tag.
type manifestInfo struct {
	Digest    string
	IsIndex   bool
	Platforms []string // "os/arch" of every manifest in an index
}

// resolver fetches manifestInfo for a reference. The real implementation
// performs one manifest GET; tests substitute a stub.
type resolver func(ctx context.Context, ref name.Reference) (manifestInfo, error)

// errRateLimited marks an HTTP 429 or TOOMANYREQUESTS answer.
var errRateLimited = errors.New("registry rate limit reached")

func registryResolver(ctx context.Context, ref name.Reference) (manifestInfo, error) {
	desc, err := remote.Get(ref, remote.WithContext(ctx))
	if err != nil {
		if isRateLimit(err) {
			return manifestInfo{}, fmt.Errorf("%w: %v", errRateLimited, err)
		}
		return manifestInfo{}, err
	}
	info := manifestInfo{Digest: desc.Digest.String(), IsIndex: desc.MediaType.IsIndex()}
	if !info.IsIndex {
		return info, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return manifestInfo{}, fmt.Errorf("index parse error: %w", err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return manifestInfo{}, fmt.Errorf("index manifest error: %w", err)
	}
	for _, m := range im.Manifests {
		if m.Platform != nil {
			info.Platforms = append(info.Platforms, strings.ToLower(m.Platform.OS+"/"+m.Platform.Architecture))
		}
	}
	return info, nil
}

// isRateLimit reports whether err is an HTTP 429 or a TOOMANYREQUESTS error.
func isRateLimit(err error) bool {
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode == http.StatusTooManyRequests {
			return true
		}
		for _, d := range te.Errors {
			if d.Code == transport.TooManyRequestsErrorCode {
				return true
			}
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "toomanyrequests")
}

func readImageList(input io.Reader) ([]string, error) {
	var images []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}
	return images, scanner.Err()
}

func readImageListFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readImageList(f)
}

// pinImageMultiArch pins one candidate. A rate limit is returned as the
// error so the caller can stop; all other outcomes are encoded in the record.
func pinImageMultiArch(ctx context.Context, imageTag string, resolve resolver) (PinnedImageRecord, error) {
	record := PinnedImageRecord{OriginalTag: imageTag}

	ref, err := name.ParseReference(imageTag)
	if err != nil {
		record.Status = statusFailed
		record.Error = fmt.Sprintf("invalid reference: %v", err)
		return record, nil
	}
	info, err := resolve(ctx, ref)
	if err != nil {
		if errors.Is(err, errRateLimited) {
			return record, err
		}
		record.Status = statusFailed
		record.Error = fmt.Sprintf("fetch error: %v", err)
		return record, nil
	}
	if !info.IsIndex {
		record.Status = statusExcludedArch
		record.Error = "image manifest is single-architecture and does not support both linux/amd64 and linux/arm64"
		return record, nil
	}
	has := func(p string) bool {
		for _, x := range info.Platforms {
			if x == p {
				return true
			}
		}
		return false
	}
	amd64, arm64 := has("linux/amd64"), has("linux/arm64")
	if !amd64 || !arm64 {
		record.Status = statusExcludedArch
		record.Error = fmt.Sprintf("lacks dual-architecture support (amd64: %t, arm64: %t)", amd64, arm64)
		return record, nil
	}
	record.Status = statusPinned
	record.ImmutableRef = fmt.Sprintf("%s@%s", ref.Context().Name(), info.Digest)
	record.ManifestDigest = info.Digest
	record.Platform = "linux/amd64+arm64"
	return record, nil
}

// pinAll pins every candidate, sleeping delay between requests. It stops at
// the first rate limit and returns the records produced so far together with
// the index of the candidate that was rate limited.
func pinAll(ctx context.Context, images []string, resolve resolver, delay time.Duration, sleep func(time.Duration), log *clilog.Logger) ([]PinnedImageRecord, int, error) {
	var records []PinnedImageRecord
	for i, img := range images {
		if i > 0 && delay > 0 {
			sleep(delay)
		}
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		rec, err := pinImageMultiArch(reqCtx, img, resolve)
		cancel()
		if err != nil {
			return records, i, err
		}
		records = append(records, rec)
		switch rec.Status {
		case statusPinned:
			log.Info("[%3d/%3d] PINNED    %-40s %s", i+1, len(images), img, rec.ImmutableRef)
		case statusExcludedArch:
			log.Warn("[%3d/%3d] EXCLUDED  %-40s %s", i+1, len(images), img, rec.Error)
		default:
			log.Error("[%3d/%3d] FAILED    %-40s %s", i+1, len(images), img, rec.Error)
		}
	}
	return records, len(images), nil
}

// ---------------------------------------------------------------------------
// Files and hashes

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

var declaredN = regexp.MustCompile(`\(N = (\d+)\)`)

// listInfo describes a list file by content: sha256, number of entries and
// the N declared in its header comment.
func listInfo(path string) (dataaudit.ListInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return dataaudit.ListInfo{}, err
	}
	sum := sha256.Sum256(data)
	entries, err := readImageList(strings.NewReader(string(data)))
	if err != nil {
		return dataaudit.ListInfo{}, err
	}
	info := dataaudit.ListInfo{Path: filepath.ToSlash(path), SHA256: hex.EncodeToString(sum[:]), Entries: len(entries)}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			if m := declaredN.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				info.DeclaredN = &n
				break
			}
		}
	}
	return info, nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func pinnedTxt(refs []string, now time.Time) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Pinned Multi-Architecture Empirical Evaluation Dataset (N = %d)\n", len(refs))
	sb.WriteString("# Sourced from Docker Hub Official Images with verified dual linux/amd64 and linux/arm64 support\n")
	fmt.Fprintf(&sb, "# Generated on %s\n\n", now.Format(time.RFC3339))
	for _, r := range refs {
		sb.WriteString(r + "\n")
	}
	return sb.String()
}

func top10Txt(refs []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Pinned Empirical Evaluation Dataset (N = %d)\n", len(refs))
	sb.WriteString("# Derived from fixtures/evaluation_dataset_pinned.json, so it comes from the same pin run as the main list\n")
	sb.WriteString("# Multi-architecture index digests supporting both linux/amd64 and linux/arm64\n\n")
	for _, r := range refs {
		sb.WriteString(r + "\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Top-10 derivation and containment

// deriveTop10 maps each top-10 tag to its pinned reference from the main
// run. A tag that is not a candidate or not pinned is reported as a problem,
// so a derived list can only contain entries that exist in the main pinned
// list.
func deriveTop10(tags []string, records []PinnedImageRecord) (refs, problems []string) {
	byTag := map[string]PinnedImageRecord{}
	for _, r := range records {
		byTag[r.OriginalTag] = r
	}
	for _, tag := range tags {
		r, ok := byTag[tag]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s is not a candidate of the main list", tag))
		case r.Status != statusPinned:
			problems = append(problems, fmt.Sprintf("%s is not pinned (%s)", tag, r.Status))
		default:
			refs = append(refs, r.ImmutableRef)
		}
	}
	return refs, problems
}

// missingFrom returns the entries of sub that are not in main.
func missingFrom(sub, main []string) []string {
	have := map[string]bool{}
	for _, m := range main {
		have[m] = true
	}
	var missing []string
	for _, s := range sub {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	return missing
}

func duplicates(entries []string) []string {
	seen := map[string]bool{}
	var dup []string
	for _, e := range entries {
		if seen[e] {
			dup = append(dup, e)
		}
		seen[e] = true
	}
	return dup
}

var pinnedRef = regexp.MustCompile(`^[^@\s]+@sha256:[a-f0-9]{64}$`)

// ---------------------------------------------------------------------------
// Audit

type auditParams struct {
	Mode          string
	FrameRepo     string
	FrameCommit   string
	FrameDate     string
	InputPath     string
	PinnedTxt     string
	PinnedJSON    string
	Top10Input    string // empty when not used
	Top10Pinned   string // empty when not used
	DeprecatedTxt string // empty when not used
	Records       []PinnedImageRecord
	Now           time.Time
}

func orUnrecorded(s string) string {
	if strings.TrimSpace(s) == "" {
		return dataaudit.Unrecorded
	}
	return s
}

// buildAudit assembles the audit document from files on disk and the pin
// records. It reports the top-10 containment result inside the document.
func buildAudit(p auditParams) (*dataaudit.Audit, error) {
	in, err := listInfo(p.InputPath)
	if err != nil {
		return nil, fmt.Errorf("input list: %w", err)
	}
	pt, err := listInfo(p.PinnedTxt)
	if err != nil {
		return nil, fmt.Errorf("pinned list: %w", err)
	}
	pjSum, err := sha256File(p.PinnedJSON)
	if err != nil {
		return nil, fmt.Errorf("pinned json: %w", err)
	}
	a := &dataaudit.Audit{
		SchemaVersion: dataaudit.SchemaVersion,
		Tool:          "pin_dataset",
		ToolVersion:   toolVersion,
		GeneratedAt:   p.Now.UTC().Format(time.RFC3339),
		Mode:          p.Mode,
		Frame: dataaudit.Frame{
			Repository: orDefault(p.FrameRepo, defaultFrameRepo),
			Commit:     orUnrecorded(p.FrameCommit),
			Date:       orUnrecorded(p.FrameDate),
		},
		InclusionRule: fmt.Sprintf(inclusionRuleFormat, evaluationPlatform),
		Platform:      evaluationPlatform,
		Input:         in,
		Outputs: dataaudit.Outputs{
			PinnedTxt:  pt,
			PinnedJSON: dataaudit.ListInfo{Path: filepath.ToSlash(p.PinnedJSON), SHA256: pjSum, Entries: len(p.Records)},
		},
		ExclusionLog: []dataaudit.Exclusion{},
	}
	for _, r := range p.Records {
		switch r.Status {
		case statusPinned:
			a.Counts.Pinned++
		case statusExcludedArch:
			a.Counts.Excluded++
			a.ExclusionLog = append(a.ExclusionLog, dataaudit.Exclusion{OriginalTag: r.OriginalTag, Status: r.Status, Reason: r.Error})
		default:
			a.Counts.Failed++
			a.ExclusionLog = append(a.ExclusionLog, dataaudit.Exclusion{OriginalTag: r.OriginalTag, Status: r.Status, Reason: r.Error})
		}
	}
	a.Counts.Candidates = len(p.Records)

	if p.DeprecatedTxt != "" {
		dep, err := deprecatedFlags(p.DeprecatedTxt, p.Records)
		if err != nil {
			return nil, err
		}
		a.Deprecated = dep
		a.Counts.Deprecated = len(dep)
	}

	if p.Top10Input != "" && p.Top10Pinned != "" {
		t10in, err := listInfo(p.Top10Input)
		if err != nil {
			return nil, fmt.Errorf("top-10 input list: %w", err)
		}
		t10pin, err := listInfo(p.Top10Pinned)
		if err != nil {
			return nil, fmt.Errorf("top-10 pinned list: %w", err)
		}
		mainRefs, err := readImageListFile(p.PinnedTxt)
		if err != nil {
			return nil, err
		}
		t10refs, err := readImageListFile(p.Top10Pinned)
		if err != nil {
			return nil, err
		}
		missing := missingFrom(t10refs, mainRefs)
		a.Outputs.Top10 = &dataaudit.Top10Info{
			Input: t10in, Pinned: t10pin, AllInMain: len(missing) == 0, MissingInMain: missing,
		}
	}
	return a, nil
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// deprecatedFlags reads an optional list of deprecated images, one tag or
// repository name per line, and flags the candidates that match.
func deprecatedFlags(path string, records []PinnedImageRecord) ([]dataaudit.Deprecated, error) {
	lines, err := readImageListFile(path)
	if err != nil {
		return nil, fmt.Errorf("deprecated list: %w", err)
	}
	set := map[string]bool{}
	for _, l := range lines {
		set[l] = true
	}
	flagged := []dataaudit.Deprecated{}
	for _, r := range records {
		repo := strings.SplitN(r.OriginalTag, ":", 2)[0]
		if set[r.OriginalTag] || set[repo] {
			flagged = append(flagged, dataaudit.Deprecated{OriginalTag: r.OriginalTag, Pinned: r.Status == statusPinned})
		}
	}
	return flagged, nil
}

func writeAudit(path string, a *dataaudit.Audit) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(data, '\n'))
}

// ---------------------------------------------------------------------------
// Command

type options struct {
	Input, OutTxt, OutJSON, OutAudit  string
	Top10, OutTop10                   string
	Deprecated                        string
	FrameRepo, FrameCommit, FrameDate string
	Delay                             time.Duration
	AuditOnly                         bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, registryResolver, time.Sleep, time.Now))
}

func run(args []string, stdout, stderr io.Writer, resolve resolver, sleep func(time.Duration), now func() time.Time) int {
	var o options
	fset := flag.NewFlagSet("pin_dataset", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.StringVar(&o.Input, "input", "fixtures/evaluation_dataset_full.txt", "file with input image tags")
	fset.StringVar(&o.OutTxt, "out-txt", "fixtures/evaluation_dataset_pinned.txt", "output pinned text file")
	fset.StringVar(&o.OutJSON, "out-json", "fixtures/evaluation_dataset_pinned.json", "output pinned JSON file")
	fset.StringVar(&o.OutAudit, "out-audit", "fixtures/evaluation_dataset_audit.json", "output dataset audit file")
	fset.StringVar(&o.Top10, "top10", "fixtures/evaluation_dataset_top10.txt", "file with the top-10 input tags (empty to skip)")
	fset.StringVar(&o.OutTop10, "out-top10-txt", "fixtures/evaluation_dataset_top10_pinned.txt", "top-10 pinned list derived from the main run (empty to skip)")
	fset.StringVar(&o.Deprecated, "deprecated", "fixtures/deprecated_images.txt", "optional list of deprecated images, one tag or repository per line")
	fset.StringVar(&o.FrameRepo, "frame-repo", defaultFrameRepo, "sampling frame repository")
	fset.StringVar(&o.FrameCommit, "frame-commit", "", "commit of the docker-library/official-images library the candidates were drawn from")
	fset.StringVar(&o.FrameDate, "frame-date", "", "date of that commit (YYYY-MM-DD)")
	fset.DurationVar(&o.Delay, "delay", 1500*time.Millisecond, "pause between registry requests")
	fset.BoolVar(&o.AuditOnly, "audit-only", false, "no network: rebuild the audit file from the existing pinned list and JSON")
	if err := fset.Parse(args); err != nil {
		return exitUsage
	}
	info, problem := clilog.New(stdout), clilog.New(stderr)

	// An absent deprecated list is normal; an absent top-10 list only skips
	// the top-10 steps.
	if o.Deprecated != "" {
		if _, err := os.Stat(o.Deprecated); err != nil {
			o.Deprecated = ""
		}
	}
	top10Tags := []string(nil)
	if o.Top10 != "" {
		tags, err := readImageListFile(o.Top10)
		if err != nil {
			problem.Warn("top-10 list %s not readable (%v); the top-10 steps are skipped", o.Top10, err)
			o.Top10, o.OutTop10 = "", ""
		} else {
			top10Tags = tags
		}
	}
	if !(o.FrameCommit != "" && o.FrameDate != "") {
		problem.Warn("sampling frame not supplied (-frame-commit, -frame-date); the audit will record it as %q", dataaudit.Unrecorded)
	}

	var records []PinnedImageRecord
	mode := "registry"
	if o.AuditOnly {
		mode = "audit-only"
		data, err := os.ReadFile(o.OutJSON)
		if err != nil {
			problem.Error("cannot read %s: %v", o.OutJSON, err)
			return exitFailure
		}
		if err := json.Unmarshal(data, &records); err != nil {
			problem.Error("cannot parse %s: %v", o.OutJSON, err)
			return exitFailure
		}
		info.Info("audit-only: %d records read from %s, no network request is made", len(records), o.OutJSON)
	} else {
		images, err := readImageListFile(o.Input)
		if err != nil {
			problem.Error("cannot read %s: %v", o.Input, err)
			return exitFailure
		}
		info.Section("Pinning dataset")
		info.Info("%d candidates, one manifest GET each (about %d anonymous Docker Hub pulls)", len(images), len(images))
		info.Info("Docker Hub allows 100 anonymous pulls per 6 hours: run this at most once per 6 hours")
		var stopAt int
		records, stopAt, err = pinAll(context.Background(), images, resolve, o.Delay, sleep, info)
		if errors.Is(err, errRateLimited) {
			problem.Error("HTTP 429 from the registry at candidate %d of %d (%s)", stopAt+1, len(images), images[stopAt])
			problem.Error("%v", err)
			problem.Error("Stopped. %d candidates were resolved, no output file was written or modified.", len(records))
			problem.Error("Wait at least 6 hours (anonymous Docker Hub limit) or raise -delay, then rerun.")
			return exitIncomplete
		}
		if err != nil {
			problem.Error("%v", err)
			return exitFailure
		}
		var refs []string
		for _, r := range records {
			if r.Status == statusPinned {
				refs = append(refs, r.ImmutableRef)
			}
		}
		if dup := duplicates(refs); len(dup) > 0 {
			problem.Error("duplicate pinned references, refusing to write: %s", strings.Join(dup, ", "))
			return exitFailure
		}
		for _, r := range refs {
			if !pinnedRef.MatchString(r) {
				problem.Error("pinned reference is not digest-pinned: %s", r)
				return exitFailure
			}
		}
		if err := writeFile(o.OutTxt, []byte(pinnedTxt(refs, now()))); err != nil {
			problem.Error("cannot write %s: %v", o.OutTxt, err)
			return exitFailure
		}
		jsonData, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			problem.Error("%v", err)
			return exitFailure
		}
		if err := writeFile(o.OutJSON, jsonData); err != nil {
			problem.Error("cannot write %s: %v", o.OutJSON, err)
			return exitFailure
		}
		info.Success("wrote %d pinned references to %s and %d records to %s", len(refs), o.OutTxt, len(records), o.OutJSON)
	}

	// Top-10 derivation (registry mode only; audit-only checks the file as is).
	var top10Problems []string
	if o.Top10 != "" && o.OutTop10 != "" && !o.AuditOnly {
		var refs []string
		refs, top10Problems = deriveTop10(top10Tags, records)
		if len(top10Problems) == 0 {
			if err := writeFile(o.OutTop10, []byte(top10Txt(refs))); err != nil {
				problem.Error("cannot write %s: %v", o.OutTop10, err)
				return exitFailure
			}
			info.Success("derived %d top-10 references into %s", len(refs), o.OutTop10)
		}
	}

	params := auditParams{
		Mode: mode, FrameRepo: o.FrameRepo, FrameCommit: o.FrameCommit, FrameDate: o.FrameDate,
		InputPath: o.Input, PinnedTxt: o.OutTxt, PinnedJSON: o.OutJSON,
		Top10Input: o.Top10, Top10Pinned: o.OutTop10, DeprecatedTxt: o.Deprecated,
		Records: records, Now: now(),
	}
	if len(top10Problems) > 0 {
		// No derived file exists; the audit records the failed assertion.
		params.Top10Pinned = ""
	}
	audit, err := buildAudit(params)
	if err != nil {
		problem.Error("cannot build audit: %v", err)
		return exitFailure
	}
	if len(top10Problems) > 0 {
		t10in, err := listInfo(o.Top10)
		if err != nil {
			problem.Error("top-10 input list: %v", err)
			return exitFailure
		}
		audit.Outputs.Top10 = &dataaudit.Top10Info{Input: t10in, AllInMain: false, MissingInMain: top10Problems}
	}
	if problems := audit.Validate(); len(problems) > 0 {
		for _, p := range problems {
			problem.Error("audit inconsistency: %s", p)
		}
		return exitFailure
	}
	if err := writeAudit(o.OutAudit, audit); err != nil {
		problem.Error("cannot write %s: %v", o.OutAudit, err)
		return exitFailure
	}

	info.Section("Dataset audit")
	info.Info("candidates %d | pinned %d | excluded %d | failed %d | deprecated flagged %d",
		audit.Counts.Candidates, audit.Counts.Pinned, audit.Counts.Excluded, audit.Counts.Failed, audit.Counts.Deprecated)
	info.Info("input sha256 %s", audit.Input.SHA256)
	info.Info("pinned sha256 %s", audit.Outputs.PinnedTxt.SHA256)
	if !audit.Frame.Recorded() {
		problem.Warn("sampling frame is not recorded in the audit")
	}
	for _, d := range audit.Deprecated {
		problem.Warn("deprecated image in the dataset: %s (pinned: %t)", d.OriginalTag, d.Pinned)
	}
	info.Success("wrote %s", o.OutAudit)

	if t := audit.Outputs.Top10; t != nil && !t.AllInMain {
		for _, m := range t.MissingInMain {
			if len(top10Problems) > 0 {
				problem.Error("top-10 entry missing from the pinned dataset: %s", m)
			} else {
				problem.Error("top-10 entry is not in the main pinned list: %s", m)
			}
		}
		problem.Error("top-10 list is not a subset of the main pinned list; rerun pin_dataset without -audit-only to derive it from the main run")
		return exitFailure
	}
	if audit.Outputs.Top10 != nil {
		info.Success("top-10 list is a subset of the main pinned list (%d of %d entries)",
			audit.Outputs.Top10.Pinned.Entries, audit.Outputs.PinnedTxt.Entries)
	}
	return exitOK
}
