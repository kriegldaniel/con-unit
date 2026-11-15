package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Command is one process invocation.
type Command struct {
	Name string
	Args []string
	Dir  string
	// Env holds additional KEY=VALUE entries on top of the current environment.
	Env []string
	// UnsetPrefixes removes every inherited variable whose name starts with one
	// of these prefixes, for tools that read configuration from the
	// environment and would silently change their result (Dockle reads
	// DOCKLE_IGNORES and others). It is applied before Env is added.
	UnsetPrefixes []string
}

// buildEnv returns the environment of a child process: base without the
// variables that match an unset prefix, followed by the extra entries.
func buildEnv(base, unsetPrefixes, extra []string) []string {
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		drop := false
		for _, p := range unsetPrefixes {
			if p != "" && strings.HasPrefix(name, p) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

// envNamesWithPrefix returns the sorted names, never the values, of the
// variables in env that start with the prefix.
func envNamesWithPrefix(env []string, prefix string) []string {
	var names []string
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if prefix != "" && strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// String renders the command for logs. It is not shell-escaped.
func (c Command) String() string {
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}

// CommandResult is the outcome of a process that ran to completion.
type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Executor runs external processes. The benchmark logic only talks to this
// interface so tests can replay canned outputs without any tool installed.
type Executor interface {
	// LookPath finds a binary on PATH.
	LookPath(name string) (string, error)
	// Run starts a process and waits for it. A non-zero exit code is not an
	// error. An error means the process could not be started or the context
	// ended before it finished.
	Run(ctx context.Context, cmd Command) (CommandResult, error)
}

// osExecutor is the production Executor.
type osExecutor struct{}

func (osExecutor) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (osExecutor) Run(ctx context.Context, c Command) (CommandResult, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Dir = c.Dir
	if len(c.Env) > 0 || len(c.UnsetPrefixes) > 0 {
		cmd.Env = buildEnv(os.Environ(), c.UnsetPrefixes, c.Env)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return res, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return res, fmt.Errorf("%s: %w", c.Name, ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	return res, fmt.Errorf("%s: %w", c.Name, err)
}

// firstLine returns the first non-empty line of the given texts.
func firstLine(texts ...[]byte) string {
	for _, t := range texts {
		for _, line := range strings.Split(string(t), "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}
