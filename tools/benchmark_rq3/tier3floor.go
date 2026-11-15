package main

import (
	"strconv"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/tools/internal/tex"
)

// The Tier 3 floor is the least time that Tier 3 takes for an image whose
// containers all stay running. ConUnit runs the checks of a pack one after
// another (basePack.Apply visits them in order, and the runner evaluates one
// image after the other). The first Tier 3 check starts the baseline container
// and observes it for the window W. Every baseline-gated check then starts its
// own container with its treatment and observes it for W as well, and the
// graceful-signal check starts one more container for W before it sends the
// signal. Nothing overlaps, so an image whose containers are all still running
// when their window ends spends at least (1 + N) times W in Tier 3, with N the
// number of treatments of the pack. An image whose baseline or treatment exits
// early takes less. TestTier3RunsOneAfterAnother runs the real pack against a
// fake engine and checks this assumption, and checks that N is the number of
// containers beyond the baseline.

// tier3Treatments are the Tier 3 checks that start one container for the
// window each. Every one of them waits for the baseline gate, which is the
// first container of the image.
var tier3Treatments = map[string]bool{
	"EXEC-01": true, // read-only root filesystem
	"EXEC-02": true, // all capabilities dropped
	"EXEC-03": true, // SIGTERM: a container observed for W before the signal
	"EXEC-04": true, // no-new-privileges
	"EXEC-05": true, // arbitrary non-root UID
	"EXEC-07": true, // memory limit
	"EXEC-08": true, // Kubernetes PSS restricted profile
}

// tier3NotWindowBound are the Tier 3 checks that start no container for the
// window. EXEC-06 polls an HTTP endpoint and is part of no shipped pack.
// TestEveryTier3RuleIsClassified makes a new Tier 3 check in the catalog fail
// until it is sorted into one of the two lists.
var tier3NotWindowBound = map[string]bool{
	"EXEC-06": true,
}

// Tier3Treatments returns the checks of the pack that are Tier 3 treatments in
// the order in which the pack runs them. The result is never nil. It lists the
// checks that the pack defines. The benchmark resolves a pack by name and never
// excludes a check, so these are the checks that run.
func Tier3Treatments(pack conunit.RulePack) []string {
	treatments := []string{}
	for _, check := range pack.Checks() {
		if tier3Treatments[check.ID] {
			treatments = append(treatments, check.ID)
		}
	}
	return treatments
}

// Tier3FloorText returns the Tier 3 floor in seconds as a plain number, or n/a
// when the treatments or the window are unknown. A pack without a Tier 3
// treatment starts no container, so its floor is 0. treatments is nil when the
// telemetry does not say.
func Tier3FloorText(treatments []string, windowMs int64) string {
	if treatments == nil || windowMs <= 0 {
		return tex.NotAvailable
	}
	if len(treatments) == 0 {
		return "0"
	}
	return strconv.FormatFloat(float64(1+len(treatments))*float64(windowMs)/1000, 'f', -1, 64)
}

// tier3FloorNote states the assumption behind the floor in the output files.
const tier3FloorNote = "Tier 3 floor in seconds: (1 + N) x W, with N the number of Tier 3 treatments of the pack and W the probe window. " +
	"It assumes that the baseline and the treatments run one after another, each container observed for the whole window: the runner evaluates the checks of a pack in order and one image after the other. " +
	"An image whose containers stay running needs at least this long. An image whose baseline or a treatment exits earlier needs less."
