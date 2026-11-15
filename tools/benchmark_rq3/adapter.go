package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/runner"
	"github.com/con-unit/con-unit/pkg/spec"
)

// This file is the only place that knows how to configure and call
// pkg/runner. It uses runner.NewRunnerWithOptions for the contract options
// --platform, --image-source and --probe-window, runner.ResolvePack, the
// runner's RunPack and runner.ClassifyError for typed status classification.
//
// Applied records which options the evaluator actually applied. Unsupported
// still guards against a harness that cannot apply a requested option: main
// refuses to run instead of ignoring it, so the telemetry never claims a
// configuration that did not take effect.

// EvalOptions are the requested run options.
type EvalOptions struct {
	Platform    string        // for example linux/amd64, empty for the host platform
	ImageSource string        // auto, local or registry
	ProbeWindow time.Duration // Tier 3 observation window W
}

// Applied lists the options the evaluator actually applies. A zero value
// means the option was not applied. It is what the run metadata records, so
// the telemetry never claims a configuration that did not take effect.
type Applied struct {
	Platform    string
	ImageSource string
	ProbeWindow time.Duration
}

// Unsupported returns the requested options that the evaluator cannot apply.
// Options at their documented default (empty platform, image source auto) are
// not reported. explicitProbeWindow tells whether -probe-window was given.
func (o EvalOptions) Unsupported(applied Applied, explicitProbeWindow bool) []string {
	var out []string
	if o.Platform != "" && o.Platform != applied.Platform {
		out = append(out, "platform")
	}
	if o.ImageSource != "" && o.ImageSource != "auto" && o.ImageSource != applied.ImageSource {
		out = append(out, "image-source")
	}
	if explicitProbeWindow && o.ProbeWindow != applied.ProbeWindow {
		out = append(out, "probe-window")
	}
	return out
}

// Evaluator runs one rule pack against one image reference.
type Evaluator interface {
	RunPack(ctx context.Context, pack conunit.RulePack, image string) (*spec.SuiteResult, error)
}

// runnerEvaluator adapts runner.Runner to the Harness interface.
type runnerEvaluator struct {
	runner Evaluator
	pack   conunit.RulePack
	eng    *engine.Engine
}

// Run evaluates one image.
func (e *runnerEvaluator) Run(ctx context.Context, image string) (*spec.SuiteResult, error) {
	return e.runner.RunPack(ctx, e.pack, image)
}

// Purge removes the image from the local store of the engine so that the next
// Run has to fetch it from the registry. Used only by cold trials.
func (e *runnerEvaluator) Purge(ctx context.Context, image string) error {
	if e.eng == nil {
		return errors.New("no container engine configured")
	}
	out, err := e.eng.Command(ctx, "rmi", "-f", image).CombinedOutput()
	if err != nil {
		return fmt.Errorf("engine rmi %s: %s (%w)", image, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// newEvaluator builds the production harness and reports which options it
// applies.
func newEvaluator(eng *engine.Engine, pack conunit.RulePack, opts EvalOptions) (Harness, Applied) {
	r := runner.NewRunnerWithOptions(eng, runner.Options{
		Platform:    opts.Platform,
		ImageSource: opts.ImageSource,
		ProbeWindow: opts.ProbeWindow,
	})
	return &runnerEvaluator{runner: r, pack: pack, eng: eng}, Applied{
		Platform:    opts.Platform,
		ImageSource: opts.ImageSource,
		ProbeWindow: opts.ProbeWindow,
	}
}

// resolvePack resolves a pack name through pkg/runner.
func resolvePack(name string) (conunit.RulePack, error) {
	return runner.ResolvePack(name)
}

// classifyError maps a failed trial to a status and reason of the shared
// vocabulary. Classification is typed and lives in pkg/runner, so rate
// limiting, missing images, deadlines and index limits are told apart without
// matching any error text.
func classifyError(err error) (string, spec.Reason) {
	return runner.ClassifyError(err)
}
