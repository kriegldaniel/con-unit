// Command label_base_family derives the base family of evaluation images from
// the os-release file of the image itself and stores the raw evidence.
//
// For each selected image of the pinned dataset it reads the layers of the
// linux/amd64 image from its digest-pinned reference, applies whiteouts and
// replacements, and reads /etc/os-release (or /usr/lib/os-release when the
// first does not exist). The family follows from the ID and ID_LIKE fields by
// the rules documented in classify. Images without any os-release file are
// labeled from release marker files, or as scratch-or-distroless when they
// have no shell, and stay unknown otherwise. Nothing is guessed from the
// repository name.
//
// The output is fixtures/base_family_evidence.json. It holds the raw os-release
// text, the marker lines and the rule that decided, per image, so that every
// label can be checked without a registry. With -apply the tool also writes the
// derived family into fixtures/archetypes.json, but only for repositories whose
// current label is one of -families (default unknown) and never to unknown.
//
// Registry use: two manifest requests per image (index and platform manifest)
// plus the layer blobs. Docker Hub allows 100 anonymous pulls per six hours, so
// keep -delay above zero. On HTTP 429 the run stops, reports the image it
// reached and leaves every output file untouched. With -dry-run the tool reads
// manifests only and reports the number and size of the layers it would read.
//
// Offline use: with -from-evidence the tool makes no registry request. It reads
// an evidence file, derives the families again from the stored raw evidence and
// rewrites the file, which lets a changed rule be applied and reviewed without
// reading the images a second time. -apply works the same way in this mode.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/con-unit/con-unit/tools/internal/clilog"
)

const toolVersion = "label_base_family 1"

const (
	exitOK         = spec.ExitOK
	exitUsage      = spec.ExitUsage
	exitIncomplete = spec.ExitIncomplete
)

// Statuses of one evidence record.
const (
	statusOK    = "OK"
	statusError = "ERROR"
)

// classificationRules are written into the evidence file, so that a reader sees
// how a family follows from the evidence.
var classificationRules = []string{
	"1. os-release exists and ID, or else the first matching token of ID_LIKE, is alpine, debian, ubuntu or one of rhel, fedora and centos (family fedora-rhel): that family.",
	"2. os-release exists and names no listed family: other.",
	"3. os-release exists but has no ID: unknown.",
	"4. No os-release, but a release marker file exists (/etc/alpine-release, /etc/debian_version, /etc/redhat-release, /etc/system-release): the family of the marker.",
	"5. No os-release, no marker and no shell (/bin/sh, /usr/bin/sh, /busybox/sh): scratch-or-distroless.",
	"6. Anything else, and every os-release path that could not be resolved: unknown.",
}

// pinnedRecord is the part of a fixtures/evaluation_dataset_pinned.json entry
// that this tool reads.
type pinnedRecord struct {
	OriginalTag  string `json:"original_tag"`
	ImmutableRef string `json:"immutable_ref"`
	Status       string `json:"status"`
}

// Evidence is the record of one image.
type Evidence struct {
	Repository   string `json:"repository"`
	OriginalTag  string `json:"original_tag"`
	ImmutableRef string `json:"immutable_ref"`
	Platform     string `json:"platform"`
	ConfigDigest string `json:"config_digest,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`

	OSReleasePath string            `json:"os_release_path,omitempty"`
	OSRelease     string            `json:"os_release,omitempty"`
	OSReleaseNote string            `json:"os_release_note,omitempty"`
	ID            string            `json:"id,omitempty"`
	IDLike        string            `json:"id_like,omitempty"`
	PrettyName    string            `json:"pretty_name,omitempty"`
	Markers       map[string]string `json:"markers,omitempty"`
	HasShell      bool              `json:"has_shell"`

	Family string `json:"family,omitempty"`
	Rule   string `json:"rule,omitempty"`
}

// EvidenceFile is fixtures/base_family_evidence.json.
type EvidenceFile struct {
	SchemaVersion int        `json:"schema_version"`
	Tool          string     `json:"tool"`
	Platform      string     `json:"platform"`
	Rules         []string   `json:"classification_rules"`
	Images        []Evidence `json:"images"`
}

// imageSource resolves a digest-pinned reference to an image of one platform.
type imageSource func(ctx context.Context, ref string, platform v1.Platform) (v1.Image, error)

func registrySource(ctx context.Context, ref string, platform v1.Platform) (v1.Image, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid reference %q: %w", ref, err)
	}
	return remote.Image(parsed, remote.WithContext(ctx), remote.WithPlatform(platform))
}

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

// repositoryOf returns the repository name of a tag the way archetypes.json
// keys it: no registry, no library prefix and no tag.
func repositoryOf(originalTag string) string {
	repo, _, _ := strings.Cut(originalTag, ":")
	repo = strings.TrimPrefix(repo, "docker.io/")
	repo = strings.TrimPrefix(repo, "index.docker.io/")
	return strings.TrimPrefix(repo, "library/")
}

// target is one image to read.
type target struct {
	repository string
	record     pinnedRecord
}

// selectTargets returns the pinned images whose repository currently carries
// one of the families, sorted by repository. families "all" selects every
// pinned image. only restricts the selection to the named repositories.
func selectTargets(pinned []pinnedRecord, archetypes map[string]map[string]any, families, only []string) []target {
	wanted := map[string]bool{}
	for _, f := range families {
		wanted[strings.TrimSpace(f)] = true
	}
	onlySet := map[string]bool{}
	for _, r := range only {
		onlySet[strings.TrimSpace(r)] = true
	}
	var targets []target
	for _, rec := range pinned {
		if rec.Status != "PINNED" || rec.ImmutableRef == "" {
			continue
		}
		repo := repositoryOf(rec.OriginalTag)
		if len(onlySet) > 0 && !onlySet[repo] {
			continue
		}
		current, _ := archetypes[repo]["base_family"].(string)
		if !wanted["all"] && !wanted[current] {
			continue
		}
		targets = append(targets, target{repository: repo, record: rec})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].repository < targets[j].repository })
	return targets
}

// evidenceFor builds the record of one image from its final view.
func evidenceFor(t target, platform string, configDigest string, view *finalView) Evidence {
	osr := readOSRelease(view)
	markers := markersOf(view)
	shell := hasShell(view)
	verdict := classify(osr, markers, shell)

	ev := Evidence{
		Repository:    t.repository,
		OriginalTag:   t.record.OriginalTag,
		ImmutableRef:  t.record.ImmutableRef,
		Platform:      platform,
		ConfigDigest:  configDigest,
		Status:        statusOK,
		OSReleasePath: osr.Path,
		OSRelease:     osr.Content,
		OSReleaseNote: osr.Note,
		Markers:       markers,
		HasShell:      shell,
		Family:        verdict.Family,
		Rule:          verdict.Rule,
	}
	if osr.Content != "" {
		fields := parseOSRelease(osr.Content)
		ev.ID, ev.IDLike, ev.PrettyName = fields["ID"], fields["ID_LIKE"], fields["PRETTY_NAME"]
	}
	if len(ev.Markers) == 0 {
		ev.Markers = nil
	}
	return ev
}

type options struct {
	pinnedPath     string
	archetypesPath string
	outPath        string
	fromEvidence   string
	families       string
	only           string
	platform       string
	delay          time.Duration
	dryRun         bool
	apply          bool
}

// reclassify derives the family of every readable record again from the raw
// evidence it stores. Records that could not be read are left as they are.
func reclassify(file *EvidenceFile) {
	for i := range file.Images {
		ev := &file.Images[i]
		if ev.Status != statusOK {
			continue
		}
		osr := osRelease{Path: ev.OSReleasePath, Content: ev.OSRelease, Note: ev.OSReleaseNote}
		verdict := classify(osr, ev.Markers, ev.HasShell)
		ev.Family, ev.Rule = verdict.Family, verdict.Rule
		ev.ID, ev.IDLike, ev.PrettyName = "", "", ""
		if osr.Content != "" {
			fields := parseOSRelease(osr.Content)
			ev.ID, ev.IDLike, ev.PrettyName = fields["ID"], fields["ID_LIKE"], fields["PRETTY_NAME"]
		}
	}
	file.Tool = toolVersion
	file.Rules = classificationRules
}

func parsePlatform(s string) (v1.Platform, error) {
	osName, arch, ok := strings.Cut(s, "/")
	if !ok || osName == "" || arch == "" || strings.Contains(arch, "/") {
		return v1.Platform{}, fmt.Errorf("platform %q must look like linux/amd64", s)
	}
	return v1.Platform{OS: osName, Architecture: arch}, nil
}

func readJSON(p string, into any) error {
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	return nil
}

// writeJSONAtomic writes indented JSON with a trailing newline through a
// temporary file, so that a failed run never leaves a partial file.
func writeJSONAtomic(p string, value any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return err
	}
	return writeAtomic(p, buf.Bytes())
}

// writeAtomic writes the bytes through a temporary file in the same directory.
func writeAtomic(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".label_base_family-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// applyFamilies writes the derived families into the archetype entries. It
// changes only entries whose current label is selected, and never sets
// unknown. It returns the changed repositories, sorted.
func applyFamilies(archetypes map[string]map[string]any, evidence []Evidence, families []string) []string {
	selected := map[string]bool{}
	for _, f := range families {
		selected[strings.TrimSpace(f)] = true
	}
	var changed []string
	for _, ev := range evidence {
		if ev.Status != statusOK || ev.Family == "" || ev.Family == familyUnknown {
			continue
		}
		entry, ok := archetypes[ev.Repository]
		if !ok {
			continue
		}
		current, _ := entry["base_family"].(string)
		if !selected["all"] && !selected[current] {
			continue
		}
		if current != ev.Family {
			entry["base_family"] = ev.Family
			changed = append(changed, ev.Repository)
		}
	}
	sort.Strings(changed)
	return changed
}

// patchBaseFamilies sets the base_family value of the named repositories in
// the raw text of the archetypes file and changes nothing else, so that the
// layout of the file and the diff of a labeling stay as small as the labeling
// itself. Every repository must have exactly one base_family entry.
func patchBaseFamilies(raw []byte, families map[string]string) ([]byte, error) {
	repositories := make([]string, 0, len(families))
	for repo := range families {
		repositories = append(repositories, repo)
	}
	sort.Strings(repositories)

	out := append([]byte(nil), raw...)
	for _, repo := range repositories {
		pattern := regexp.MustCompile(`("` + regexp.QuoteMeta(repo) + `"\s*:\s*\{[^{}]*"base_family"\s*:\s*")([^"]*)(")`)
		matches := pattern.FindAllSubmatchIndex(out, -1)
		if len(matches) != 1 {
			return nil, fmt.Errorf("expected exactly one base_family entry for %q, found %d", repo, len(matches))
		}
		value, err := json.Marshal(families[repo])
		if err != nil {
			return nil, err
		}
		// Submatch 2 is the current value between the quotes.
		valueStart, valueEnd := matches[0][4], matches[0][5]
		patched := append([]byte(nil), out[:valueStart]...)
		patched = append(patched, value[1:len(value)-1]...) // json.Marshal wraps the text in quotes
		patched = append(patched, out[valueEnd:]...)
		out = patched
	}
	return out, nil
}

// patchArchetypesFile applies the changed labels of the in-memory archetypes to
// the file in place. It refuses to write when the patched text does not decode
// to exactly the intended content.
func patchArchetypesFile(p string, archetypes map[string]map[string]any, changed []string) error {
	if len(changed) == 0 {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	families := make(map[string]string, len(changed))
	for _, repo := range changed {
		family, _ := archetypes[repo]["base_family"].(string)
		families[repo] = family
	}
	patched, err := patchBaseFamilies(raw, families)
	if err != nil {
		return err
	}
	var decoded map[string]map[string]any
	if err := json.Unmarshal(patched, &decoded); err != nil {
		return fmt.Errorf("the patched file is not valid JSON: %w", err)
	}
	if !reflect.DeepEqual(decoded, archetypes) {
		return errors.New("the patched file does not hold the intended labels, nothing was written")
	}
	return writeAtomic(p, patched)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func human(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	value, suffix := float64(bytes), []string{"KiB", "MiB", "GiB", "TiB"}
	i := -1
	for value >= unit && i < len(suffix)-1 {
		value /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", value, suffix[i])
}

func layerSize(img v1.Image) (layers int, size int64, err error) {
	ls, err := img.Layers()
	if err != nil {
		return 0, 0, err
	}
	for _, l := range ls {
		s, err := l.Size()
		if err != nil {
			return 0, 0, err
		}
		size += s
	}
	return len(ls), size, nil
}

// run is the testable body of the command.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, source imageSource, sleep func(time.Duration)) int {
	info, problem := clilog.New(stdout), clilog.New(stderr)

	var opt options
	fs := flag.NewFlagSet("label_base_family", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opt.pinnedPath, "pinned", "fixtures/evaluation_dataset_pinned.json", "pinned dataset")
	fs.StringVar(&opt.archetypesPath, "archetypes", "fixtures/archetypes.json", "archetype and base family labels")
	fs.StringVar(&opt.outPath, "out", "fixtures/base_family_evidence.json", "evidence file to write")
	fs.StringVar(&opt.fromEvidence, "from-evidence", "", "derive the families again from this evidence file without any registry access")
	fs.StringVar(&opt.families, "families", "unknown", "comma separated current labels to evaluate, or all")
	fs.StringVar(&opt.only, "only", "", "comma separated repositories to restrict the run to")
	fs.StringVar(&opt.platform, "platform", "linux/amd64", "platform whose layers are read")
	fs.DurationVar(&opt.delay, "delay", time.Second, "pause between two images")
	fs.BoolVar(&opt.dryRun, "dry-run", false, "read manifests only and report layer counts and sizes")
	fs.BoolVar(&opt.apply, "apply", false, "write the derived families into the archetypes file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	platform, err := parsePlatform(opt.platform)
	if err != nil {
		problem.Error("%v", err)
		return exitUsage
	}
	if opt.dryRun && opt.fromEvidence != "" {
		problem.Error("-dry-run reads manifests and -from-evidence reads no registry, use one of them")
		return exitUsage
	}

	var pinned []pinnedRecord
	if err := readJSON(opt.pinnedPath, &pinned); err != nil {
		problem.Error("reading the pinned dataset: %v", err)
		return exitUsage
	}
	archetypes := map[string]map[string]any{}
	if err := readJSON(opt.archetypesPath, &archetypes); err != nil {
		problem.Error("reading the archetypes file: %v", err)
		return exitUsage
	}

	families := splitList(opt.families)
	info.Section("Base family labeling")
	info.Info("tool       %s", toolVersion)
	info.Info("families   %s", strings.Join(families, ", "))

	file := EvidenceFile{
		SchemaVersion: 1,
		Tool:          toolVersion,
		Platform:      opt.platform,
		Rules:         classificationRules,
	}
	failures := 0
	var totalSize int64

	var targets []target
	if opt.fromEvidence != "" {
		if err := readJSON(opt.fromEvidence, &file); err != nil {
			problem.Error("reading the evidence file: %v", err)
			return exitUsage
		}
		reclassify(&file)
		for _, ev := range file.Images {
			if ev.Status != statusOK {
				failures++
			}
		}
		info.Info("evidence   %s (no registry access)", opt.fromEvidence)
		info.Info("images     %d", len(file.Images))
	} else {
		targets = selectTargets(pinned, archetypes, families, splitList(opt.only))
		info.Info("platform   %s", opt.platform)
		info.Info("images     %d", len(targets))
		if len(targets) == 0 {
			info.Warn("no pinned image matches the selection, nothing to do")
			return exitOK
		}
	}
	for i, t := range targets {
		if i > 0 && opt.delay > 0 {
			sleep(opt.delay)
		}
		tag := fmt.Sprintf("[%3d/%3d]", i+1, len(targets))
		img, err := source(ctx, t.record.ImmutableRef, platform)
		if err == nil && opt.dryRun {
			var layers int
			var size int64
			if layers, size, err = layerSize(img); err == nil {
				totalSize += size
				info.Info("%s PLAN      %-26s %2d layers %10s", tag, t.repository, layers, human(size))
				continue
			}
		}
		var configDigest string
		var view *finalView
		if err == nil {
			if hash, hashErr := img.ConfigName(); hashErr == nil {
				configDigest = hash.String()
			}
			view, err = scanImage(img)
		}
		if err != nil {
			if isRateLimit(err) {
				problem.Error("HTTP 429 from the registry at image %d of %d (%s), no file was written", i+1, len(targets), t.repository)
				return exitIncomplete
			}
			failures++
			problem.Error("%s FAILED    %-26s %v", tag, t.repository, err)
			file.Images = append(file.Images, Evidence{
				Repository: t.repository, OriginalTag: t.record.OriginalTag, ImmutableRef: t.record.ImmutableRef,
				Platform: opt.platform, Status: statusError, Error: err.Error(),
			})
			continue
		}
		ev := evidenceFor(t, opt.platform, configDigest, view)
		file.Images = append(file.Images, ev)
		info.Info("%s LABELED   %-26s %-22s %s", tag, ev.Repository, ev.Family, ev.Rule)
	}

	if opt.dryRun {
		info.Success("dry run complete: %d images, %s of layers would be read", len(targets), human(totalSize))
		return exitOK
	}

	if err := writeJSONAtomic(opt.outPath, file); err != nil {
		problem.Error("writing %s: %v", opt.outPath, err)
		return exitIncomplete
	}
	info.Success("wrote %s", opt.outPath)

	counts := map[string]int{}
	for _, ev := range file.Images {
		if ev.Status == statusOK {
			counts[ev.Family]++
		}
	}
	var names []string
	for family := range counts {
		names = append(names, family)
	}
	sort.Strings(names)
	for _, family := range names {
		info.Info("family     %-22s %d", family, counts[family])
	}

	if opt.apply {
		changed := applyFamilies(archetypes, file.Images, families)
		if err := patchArchetypesFile(opt.archetypesPath, archetypes, changed); err != nil {
			problem.Error("writing %s: %v", opt.archetypesPath, err)
			return exitIncomplete
		}
		info.Success("updated %d labels in %s", len(changed), opt.archetypesPath)
	}

	if failures > 0 {
		problem.Warn("%d images could not be read and keep their label", failures)
		return exitIncomplete
	}
	unresolved := 0
	for _, ev := range file.Images {
		if ev.Family == familyUnknown {
			unresolved++
			problem.Warn("unresolved %s: %s", ev.Repository, ev.Rule)
		}
	}
	if unresolved > 0 {
		return exitIncomplete
	}
	return exitOK
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, registrySource, time.Sleep)
	stop()
	os.Exit(code)
}
