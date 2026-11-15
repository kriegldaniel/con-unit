package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File names inside the raw directory.
const (
	toolsFileName = "tools.json" // raw/tools.json
	runFileName   = "run.json"   // raw/<case>/run.json
)

// Status values of one tool run recorded in run.json.
const (
	runStatusRan     = "ran"
	runStatusNotRun  = "not_run" // tool absent, not selected, or its prerequisite failed
	runStatusSkipped = "skipped" // tool available, deliberately not run because it has no policy for the property
	runStatusError   = "error"   // tool ran but failed (exit code, timeout, start failure)
)

// ToolInfo describes one tool binary found (or not) on this host.
type ToolInfo struct {
	Name      string `json:"name"`
	Binary    string `json:"binary"` // command name looked up on PATH, or the explicit path
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"` // first line of the version output, verbatim
	Available bool   `json:"available"`
	Selected  bool   `json:"selected"`
	Reason    string `json:"reason,omitempty"` // why the tool is not available or not selected
}

// ToolsFile is raw/tools.json: the tools and engine of one run.
type ToolsFile struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Engine      ToolInfo            `json:"engine"`
	Tools       map[string]ToolInfo `json:"tools"`
}

// BuildRecord is the image build of one case.
type BuildRecord struct {
	Status  string `json:"status"` // built | failed | skipped
	Image   string `json:"image,omitempty"`
	ImageID string `json:"image_id,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ToolRun records how one tool was executed for one case.
type ToolRun struct {
	Status   string   `json:"status"` // ran | not_run | error
	Reason   string   `json:"reason,omitempty"`
	ExitCode int      `json:"exit_code"`
	Command  string   `json:"command,omitempty"`
	Error    string   `json:"error,omitempty"`
	Output   string   `json:"output,omitempty"` // primary raw file name relative to the case directory
	Notes    []string `json:"notes,omitempty"`  // how the run was isolated from the host, for audit
}

// CaseRun is raw/<case>/run.json.
type CaseRun struct {
	Case  string      `json:"case"`
	Build BuildRecord `json:"build"`
	// Archive describes the docker-archive that Trivy and Dockle read. It is
	// absent when neither tool ran on the case.
	Archive *ArchiveRecord     `json:"archive,omitempty"`
	Tools   map[string]ToolRun `json:"tools"`
}

// RunConfig holds everything the execution phase needs.
type RunConfig struct {
	Oracle *Oracle
	OutDir string

	// Engine is the container engine binary used to build, save and remove
	// images. Empty means no engine: image-based tools are NOT_RUN.
	Engine string
	// Binaries maps tool name to the binary to run, empty when absent.
	Binaries map[string]string
	// Selected restricts the tools to run. Nil means all.
	Selected map[string]bool
	// Cases restricts the cases to run. Nil means all.
	Cases map[string]bool

	ConUnitFlags    []string
	TrivyConfigArgs []string
	TrivyImageArgs  []string
	CSTDockerHost   string
	ImagePrefix     string
	KeepImages      bool
	Timeout         time.Duration
	Log             *Logger
}

// RawDir is the directory that receives raw tool outputs.
func (c *RunConfig) RawDir() string { return filepath.Join(c.OutDir, "raw") }

// versionArgs maps each tool to the arguments that print its version.
var versionArgs = map[string][]string{
	ToolConUnit:  {"version"},
	ToolHadolint: {"--version"},
	ToolTrivy:    {"--version"},
	ToolCST:      {"version"},
	ToolDockle:   {"--version"}, // prints "dockle version 0.4.15"; there is no version subcommand
}

// defaultBinaries are the command names looked up on PATH.
var defaultBinaries = map[string]string{
	ToolConUnit:  "con-unit",
	ToolHadolint: "hadolint",
	ToolTrivy:    "trivy",
	ToolCST:      "container-structure-test",
	ToolDockle:   "dockle",
}

// dockleEnvPrefix names the environment variables Dockle reads its options
// from (DOCKLE_IGNORES, DOCKLE_ACCEPT_KEYS and others). All of them are
// removed for the run, because they change which checkpoints report.
const dockleEnvPrefix = "DOCKLE_"

// DetectTools resolves every tool binary and records its version string.
// Absent tools are kept in the result with Available false so the report can
// say so.
func DetectTools(ctx context.Context, ex Executor, binaries map[string]string, selected map[string]bool, engine string) ToolsFile {
	file := ToolsFile{GeneratedAt: time.Now().UTC(), Tools: map[string]ToolInfo{}}
	probe := func(name, bin string, args []string) ToolInfo {
		info := ToolInfo{Name: name, Binary: bin}
		path, err := ex.LookPath(bin)
		if err != nil {
			info.Reason = "binary not found on PATH"
			return info
		}
		info.Path = path
		info.Available = true
		res, err := ex.Run(ctx, Command{Name: path, Args: args})
		if err != nil {
			info.Reason = "version probe failed: " + err.Error()
			return info
		}
		info.Version = firstLine(res.Stdout, res.Stderr)
		return info
	}
	if engine != "" {
		file.Engine = probe("engine", engine, []string{"--version"})
	} else {
		file.Engine = ToolInfo{Name: "engine", Reason: "no container engine found (podman or docker)"}
	}
	for _, name := range allTools {
		bin := binaries[name]
		if bin == "" {
			bin = defaultBinaries[name]
		}
		info := probe(name, bin, versionArgs[name])
		info.Selected = selected == nil || selected[name]
		if !info.Selected && info.Reason == "" {
			info.Reason = "not selected with -tools"
		}
		file.Tools[name] = info
	}
	return file
}

// Execute builds the corpus images and runs every selected tool on every
// selected case. Raw outputs and run.json files are written below RawDir.
// Failures of single cases or tools are recorded, never fatal.
func Execute(ctx context.Context, ex Executor, cfg *RunConfig) (*ToolsFile, error) {
	if err := os.MkdirAll(cfg.RawDir(), 0o755); err != nil {
		return nil, fmt.Errorf("creating raw directory: %w", err)
	}
	tools := DetectTools(ctx, ex, cfg.Binaries, cfg.Selected, cfg.Engine)
	if err := writeJSON(filepath.Join(cfg.RawDir(), toolsFileName), tools); err != nil {
		return nil, err
	}
	for _, name := range allTools {
		info := tools.Tools[name]
		switch {
		case !info.Selected:
			cfg.Log.Warn("%-9s not selected", name)
		case !info.Available:
			cfg.Log.Warn("%-9s NOT_RUN: %s", name, info.Reason)
		default:
			cfg.Log.Info("%-9s %s", name, info.Version)
		}
	}
	if !tools.Engine.Available {
		cfg.Log.Warn("engine    unavailable, image-based tools are NOT_RUN: %s", tools.Engine.Reason)
	} else {
		cfg.Log.Info("engine    %s", tools.Engine.Version)
	}

	var cases []Case
	for _, c := range cfg.Oracle.Cases {
		if cfg.Cases == nil || cfg.Cases[c.ID] {
			cases = append(cases, c)
		}
	}
	for i, c := range cases {
		if err := ctx.Err(); err != nil {
			return &tools, err
		}
		cfg.Log.Section("[%d/%d] %s (%s, defect_present=%t)", i+1, len(cases), c.ID, c.Property, c.DefectPresent)
		if err := runCase(ctx, ex, cfg, &tools, c); err != nil {
			cfg.Log.Error("case %s: %v", c.ID, err)
		}
	}
	return &tools, nil
}

func runCase(ctx context.Context, ex Executor, cfg *RunConfig, tools *ToolsFile, c Case) error {
	caseDir := filepath.Join(cfg.RawDir(), c.ID)
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		return err
	}
	run := CaseRun{Case: c.ID, Tools: map[string]ToolRun{}}
	dockerfile := cfg.Oracle.Path(c.Dockerfile)
	contextDir := filepath.Dir(dockerfile)
	image := ImageRef(cfg.ImagePrefix, c.ID)

	// Build. Hadolint only needs the Dockerfile, the other tools need the image.
	imageReady := false
	switch {
	case !tools.Engine.Available:
		run.Build = BuildRecord{Status: "skipped", Error: "no container engine"}
	default:
		run.Build = buildImage(ctx, ex, cfg, tools.Engine.Path, caseDir, image, dockerfile, contextDir)
		imageReady = run.Build.Status == "built"
		if imageReady {
			cfg.Log.Info("built %s (%s)", image, shortID(run.Build.ImageID))
		} else {
			cfg.Log.Error("build failed: %s", run.Build.Error)
		}
	}

	// Trivy and Dockle read the same docker-archive export of the image. It is
	// written once, its config digest is recorded in run.json, and it is
	// deleted when the case is done.
	var arch *archiveExport
	if imageReady && (toolRunnable(tools, ToolTrivy) || toolRunnable(tools, ToolDockle)) {
		arch = exportArchive(ctx, ex, cfg, tools.Engine.Path, caseDir, image, run.Build.ImageID)
		defer os.Remove(arch.Path)
		rec := arch.Record
		run.Archive = &rec
		switch {
		case arch.Err != "":
			cfg.Log.Error("archive export failed: %s", arch.Err)
		case rec.DigestError != "":
			cfg.Log.Warn("archive config digest unreadable: %s", rec.DigestError)
		default:
			cfg.Log.Info("archive   config %s", shortID(rec.ConfigDigest))
			if rec.MatchesImageID != nil && !*rec.MatchesImageID {
				cfg.Log.Warn("archive config digest differs from the engine image ID %s", shortID(rec.ImageID))
			}
		}
	}

	for _, name := range allTools {
		info := tools.Tools[name]
		scope := cfg.Oracle.Scope(c, name)
		switch {
		case !info.Selected:
			run.Tools[name] = ToolRun{Status: runStatusNotRun, Reason: info.Reason}
			continue
		case !info.Available:
			run.Tools[name] = ToolRun{Status: runStatusNotRun, Reason: info.Reason}
			continue
		case name != ToolHadolint && !imageReady:
			run.Tools[name] = ToolRun{Status: runStatusNotRun, Reason: "image build " + run.Build.Status}
			continue
		}
		var tr ToolRun
		switch name {
		case ToolHadolint:
			tr = runHadolint(ctx, ex, cfg, info, scope, caseDir, dockerfile)
		case ToolTrivy:
			tr = runTrivy(ctx, ex, cfg, info, caseDir, arch, contextDir)
		case ToolDockle:
			tr = runDockle(ctx, ex, cfg, info, caseDir, arch)
		case ToolConUnit:
			tr = runConUnit(ctx, ex, cfg, info, scope, caseDir, image)
		case ToolCST:
			tr = runCST(ctx, ex, cfg, info, scope, caseDir, image)
		}
		run.Tools[name] = tr
		switch tr.Status {
		case runStatusRan:
			cfg.Log.Info("%-9s exit=%d", name, tr.ExitCode)
		case runStatusSkipped:
			cfg.Log.Info("%-9s skipped: %s", name, tr.Reason)
		default:
			cfg.Log.Error("%-9s %s: %s", name, tr.Status, tr.Error)
		}
	}

	if imageReady && !cfg.KeepImages {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, _ = ex.Run(cctx, Command{Name: tools.Engine.Path, Args: []string{"rmi", "-f", image}})
		cancel()
	}
	return writeJSON(filepath.Join(caseDir, runFileName), run)
}

func buildImage(ctx context.Context, ex Executor, cfg *RunConfig, engine, caseDir, image, dockerfile, contextDir string) BuildRecord {
	args := []string{"build"}
	// HEALTHCHECK is dropped by the default OCI image format of Podman, so the
	// Docker image format is required for the corpus to mean what it says.
	if filepath.Base(engine) == "podman" {
		args = append(args, "--format", "docker")
	}
	args = append(args, "-t", image, "-f", dockerfile, contextDir)
	cmd := Command{Name: engine, Args: args}
	res, err := runWithTimeout(ctx, ex, cfg.Timeout, cmd)
	writeLog(filepath.Join(caseDir, "build.log.txt"), cmd, res, err)
	if err != nil {
		return BuildRecord{Status: "failed", Image: image, Error: err.Error()}
	}
	if res.ExitCode != 0 {
		return BuildRecord{Status: "failed", Image: image, Error: fmt.Sprintf("exit code %d: %s", res.ExitCode, firstLine(res.Stderr, res.Stdout))}
	}
	rec := BuildRecord{Status: "built", Image: image}
	idRes, idErr := runWithTimeout(ctx, ex, cfg.Timeout, Command{Name: engine, Args: []string{"image", "inspect", "--format", "{{.Id}}", image}})
	if idErr == nil && idRes.ExitCode == 0 {
		rec.ImageID = strings.TrimSpace(string(idRes.Stdout))
	}
	return rec
}

func runHadolint(ctx context.Context, ex Executor, cfg *RunConfig, info ToolInfo, scope ToolScope, caseDir, dockerfile string) ToolRun {
	args := []string{"--no-color", "--format", "json"}
	args = append(args, scope.Args...)
	args = append(args, dockerfile)
	cmd := Command{Name: info.Path, Args: args}
	return runSimpleTool(ctx, ex, cfg, caseDir, "hadolint", cmd, []int{0, 1})
}

func runConUnit(ctx context.Context, ex Executor, cfg *RunConfig, info ToolInfo, scope ToolScope, caseDir, image string) ToolRun {
	outFile := filepath.Join(caseDir, "conunit.txt")
	args := []string{"test", image, "--pack", scope.Pack, "--format", "json", "--output", outFile}
	args = append(args, cfg.ConUnitFlags...)
	cmd := Command{Name: info.Path, Args: args}
	// The JSON report is written by con-unit itself to the raw file. A stale
	// file from an earlier run must not be mistaken for fresh output.
	_ = os.Remove(outFile)
	res, err := runWithTimeout(ctx, ex, cfg.Timeout, cmd)
	writeLog(filepath.Join(caseDir, "conunit.log.txt"), cmd, res, err)
	tr := ToolRun{Status: runStatusRan, ExitCode: res.ExitCode, Command: cmd.String(), Output: "conunit.txt"}
	if err != nil {
		tr.Status, tr.Error = runStatusError, err.Error()
		return tr
	}
	if res.ExitCode != 0 && res.ExitCode != 1 {
		tr.Status, tr.Error = runStatusError, fmt.Sprintf("unexpected exit code %d: %s", res.ExitCode, firstLine(res.Stderr))
		return tr
	}
	if _, statErr := os.Stat(outFile); statErr != nil {
		tr.Status, tr.Error = runStatusError, "con-unit wrote no JSON report: "+firstLine(res.Stderr)
	}
	return tr
}

func runCST(ctx context.Context, ex Executor, cfg *RunConfig, info ToolInfo, scope ToolScope, caseDir, image string) ToolRun {
	if !scope.InScope {
		// No CST policy exists for this property. The tool is not executed and
		// the classifier reports OUT_OF_SCOPE.
		return ToolRun{Status: runStatusSkipped, Reason: "no container-structure-test policy for this property"}
	}
	args := []string{"test", "--image", image, "--config", cfg.Oracle.Path(scope.Config), "--output", "json"}
	cmd := Command{Name: info.Path, Args: args}
	if cfg.CSTDockerHost != "" {
		cmd.Env = []string{"DOCKER_HOST=" + cfg.CSTDockerHost}
	}
	return runSimpleTool(ctx, ex, cfg, caseDir, "cst", cmd, []int{0, 1})
}

// toolRunnable reports whether a tool is selected and was found on this host.
func toolRunnable(tools *ToolsFile, name string) bool {
	info, ok := tools.Tools[name]
	return ok && info.Selected && info.Available
}

// archiveExport is the docker-archive export of one image, shared by Trivy and
// Dockle. Err is set when the export failed; Record then carries the reason.
type archiveExport struct {
	Path   string
	Record ArchiveRecord
	Err    string
}

// exportArchive saves the image once with `save --format docker-archive`
// (podman) or `save` (docker), reads the config digest from the archive and
// writes the engine call to archive.log.txt. The caller removes the file.
func exportArchive(ctx context.Context, ex Executor, cfg *RunConfig, engine, caseDir, image, imageID string) *archiveExport {
	arch := &archiveExport{Path: filepath.Join(os.TempDir(), fmt.Sprintf("rq1-%d-%s.tar", os.Getpid(), filepath.Base(caseDir)))}
	saveArgs := []string{"save"}
	if filepath.Base(engine) == "podman" {
		saveArgs = append(saveArgs, "--format", "docker-archive")
	}
	saveArgs = append(saveArgs, "-o", arch.Path, image)
	saveCmd := Command{Name: engine, Args: saveArgs}
	saveRes, err := runWithTimeout(ctx, ex, cfg.Timeout, saveCmd)
	writeLog(filepath.Join(caseDir, "archive.log.txt"), saveCmd, saveRes, err)
	if err != nil || saveRes.ExitCode != 0 {
		arch.Err = "saving the image archive failed: " + firstError(err, saveRes)
		arch.Record = ArchiveRecord{Format: "docker-archive", ExportError: arch.Err}
		return arch
	}
	rec, digestErr := ReadArchiveConfigDigest(arch.Path)
	if digestErr != nil {
		rec.DigestError = digestErr.Error()
	}
	if id := normalizeDigest(imageID); id != "" {
		rec.ImageID = id
		if rec.ConfigDigest != "" {
			match := rec.ConfigDigest == id
			rec.MatchesImageID = &match
		}
	}
	arch.Record = rec
	return arch
}

// runDockle runs Dockle on the docker-archive export, as
// `dockle --input <archive> --format json --exit-code 0`. Three things keep
// the result independent of the host. The working directory is empty, because
// Dockle reads .dockleignore from it. Every DOCKLE_ variable is removed from
// the environment, because they set the same options as flags (ignored
// checkpoints, accepted keys, sensitive words). No flag is passed that
// changes what is reported. Which of these applied is recorded in the notes of
// the run.
func runDockle(ctx context.Context, ex Executor, cfg *RunConfig, info ToolInfo, caseDir string, arch *archiveExport) ToolRun {
	tr := ToolRun{Status: runStatusError, Output: "dockle.txt"}
	switch {
	case arch == nil:
		tr.Error = "no image archive was exported"
		return tr
	case arch.Err != "":
		tr.Error = arch.Err
		return tr
	case arch.Record.DigestError != "":
		tr.Error = "the config digest of the archive could not be read, so the archive is not tied to the image: " + arch.Record.DigestError
		return tr
	}
	workDir, err := os.MkdirTemp("", "rq1-dockle-")
	if err != nil {
		tr.Error = "creating an empty working directory: " + err.Error()
		return tr
	}
	defer os.RemoveAll(workDir)

	cmd := Command{
		Name:          info.Path,
		Args:          []string{"--input", arch.Path, "--format", "json", "--exit-code", "0"},
		Dir:           workDir,
		UnsetPrefixes: []string{dockleEnvPrefix},
	}
	tr = runSimpleTool(ctx, ex, cfg, caseDir, "dockle", cmd, []int{0})
	tr.Notes = []string{
		"working directory was an empty temporary directory, so no .dockleignore applied",
		"config digest of the archive " + arch.Record.ConfigDigest,
		"checkpoint DKL-DI-0006 is evaluated only for an image name, so it cannot report for --input",
	}
	if removed := envNamesWithPrefix(os.Environ(), dockleEnvPrefix); len(removed) > 0 {
		tr.Notes = append(tr.Notes, "removed from the environment: "+strings.Join(removed, ", "))
	} else {
		tr.Notes = append(tr.Notes, "no "+dockleEnvPrefix+" variable was set in the environment")
	}
	return tr
}

func runTrivy(ctx context.Context, ex Executor, cfg *RunConfig, info ToolInfo, caseDir string, arch *archiveExport, contextDir string) ToolRun {
	tr := ToolRun{Status: runStatusRan, Output: "trivy.txt"}
	if arch == nil || arch.Err != "" {
		tr.Status = runStatusError
		tr.Error = "no image archive was exported"
		if arch != nil {
			tr.Error = arch.Err
		}
		return tr
	}
	archive := arch.Path

	configCmd := Command{Name: info.Path, Args: append(append([]string{"config"}, cfg.TrivyConfigArgs...), contextDir)}
	imageCmd := Command{Name: info.Path, Args: append(append([]string{"image"}, cfg.TrivyImageArgs...), "--input", archive)}

	var raw, log strings.Builder
	for _, cmd := range []Command{configCmd, imageCmd} {
		res, runErr := runWithTimeout(ctx, ex, cfg.Timeout, cmd)
		code := res.ExitCode
		if runErr != nil {
			code = -1
		}
		raw.WriteString(FormatSection(cmd.String(), code, string(res.Stdout)))
		fmt.Fprintf(&log, "$ %s\nexit: %d\n", cmd.String(), code)
		if runErr != nil {
			fmt.Fprintf(&log, "error: %v\n", runErr)
		}
		fmt.Fprintf(&log, "--- stderr ---\n%s\n", strings.TrimRight(string(res.Stderr), "\n"))
		if runErr != nil || res.ExitCode != 0 {
			tr.Status = runStatusError
			tr.Error = fmt.Sprintf("%s %s: %s", filepath.Base(cmd.Name), cmd.Args[0], firstError(runErr, res))
		}
		tr.ExitCode = code
	}
	tr.Command = configCmd.String() + " ; " + imageCmd.String()
	_ = os.WriteFile(filepath.Join(caseDir, "trivy.txt"), []byte(raw.String()), 0o644)
	_ = os.WriteFile(filepath.Join(caseDir, "trivy.log.txt"), []byte(log.String()), 0o644)
	return tr
}

// runSimpleTool runs one command, stores stdout as <tool>.txt and the
// command line, exit code and stderr as <tool>.log.txt.
func runSimpleTool(ctx context.Context, ex Executor, cfg *RunConfig, caseDir, tool string, cmd Command, okCodes []int) ToolRun {
	res, err := runWithTimeout(ctx, ex, cfg.Timeout, cmd)
	writeLog(filepath.Join(caseDir, tool+".log.txt"), cmd, res, err)
	_ = os.WriteFile(filepath.Join(caseDir, tool+".txt"), res.Stdout, 0o644)
	tr := ToolRun{Status: runStatusRan, ExitCode: res.ExitCode, Command: cmd.String(), Output: tool + ".txt"}
	if err != nil {
		tr.Status, tr.Error = runStatusError, err.Error()
		return tr
	}
	for _, ok := range okCodes {
		if res.ExitCode == ok {
			return tr
		}
	}
	tr.Status = runStatusError
	tr.Error = fmt.Sprintf("unexpected exit code %d: %s", res.ExitCode, firstLine(res.Stderr, res.Stdout))
	return tr
}

func runWithTimeout(ctx context.Context, ex Executor, timeout time.Duration, cmd Command) (CommandResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return ex.Run(ctx, cmd)
}

func writeLog(path string, cmd Command, res CommandResult, err error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "$ %s\n", cmd.String())
	fmt.Fprintf(&sb, "exit: %d\n", res.ExitCode)
	if err != nil {
		fmt.Fprintf(&sb, "error: %v\n", err)
	}
	fmt.Fprintf(&sb, "--- stderr ---\n%s\n", strings.TrimRight(string(res.Stderr), "\n"))
	_ = os.WriteFile(path, []byte(sb.String()), 0o644)
}

func firstError(err error, res CommandResult) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("exit code %d: %s", res.ExitCode, firstLine(res.Stderr, res.Stdout))
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
