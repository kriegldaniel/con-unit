package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

func TestTier3TreatmentsOfTheShippedPacks(t *testing.T) {
	want := map[string]string{
		"PACK-CONUNIT-HARDENING": "EXEC-02,EXEC-07,EXEC-01,EXEC-04",
		"PACK-PROD-HYGIENE":      "EXEC-01,EXEC-02,EXEC-03",
		"PACK-KUBE-HARDENED":     "EXEC-01,EXEC-02,EXEC-05,EXEC-04,EXEC-03,EXEC-08",
		"PACK-NIST-800-190":      "EXEC-01,EXEC-02,EXEC-03",
		"PACK-DISTROLESS":        "EXEC-01,EXEC-02",
		"PACK-IMAGE-LINT":        "", // static checks only, no container is started
	}
	packs := conunit.AllPacks()
	if len(packs) != len(want) {
		t.Fatalf("%d shipped packs, the table knows %d: classify the new pack", len(packs), len(want))
	}
	for _, p := range packs {
		got := strings.Join(Tier3Treatments(p), ",")
		if got != want[p.ID()] {
			t.Errorf("%s: treatments %q, want %q", p.ID(), got, want[p.ID()])
		}
	}
}

// TestEveryTier3RuleIsClassified makes a new Tier 3 check fail here until
// someone decides whether it starts a container for the window.
func TestEveryTier3RuleIsClassified(t *testing.T) {
	catalog := map[string]bool{}
	for _, r := range conunit.Rules() {
		catalog[r.ID] = true
		if r.Tier != spec.TierContract {
			if tier3Treatments[r.ID] || tier3NotWindowBound[r.ID] {
				t.Errorf("%s is not a Tier 3 rule and must not be in the floor tables", r.ID)
			}
			continue
		}
		if tier3Treatments[r.ID] == tier3NotWindowBound[r.ID] {
			t.Errorf("Tier 3 rule %s must be in exactly one of tier3Treatments and tier3NotWindowBound (in treatments %t, in not window bound %t)",
				r.ID, tier3Treatments[r.ID], tier3NotWindowBound[r.ID])
		}
	}
	for id := range tier3Treatments {
		if !catalog[id] {
			t.Errorf("%s is in tier3Treatments and not in the rule catalog", id)
		}
	}
	for id := range tier3NotWindowBound {
		if !catalog[id] {
			t.Errorf("%s is in tier3NotWindowBound and not in the rule catalog", id)
		}
	}
}

func TestTier3FloorText(t *testing.T) {
	four := []string{"EXEC-02", "EXEC-07", "EXEC-01", "EXEC-04"}
	cases := []struct {
		name       string
		treatments []string
		windowMs   int64
		want       string
	}{
		{"hardening profile at W of 3 s", four, 3000, "15"},
		{"six treatments at W of 10 s", append(append([]string{}, four...), "EXEC-05", "EXEC-08"), 10000, "70"},
		{"a fractional window", four, 2500, "12.5"},
		{"one treatment", []string{"EXEC-01"}, 3000, "6"},
		{"a pack without Tier 3 starts no container", []string{}, 3000, "0"},
		{"treatments unknown", nil, 3000, "n/a"},
		{"window unknown", four, 0, "n/a"},
		{"negative window", four, -1, "n/a"},
	}
	for _, tc := range cases {
		if got := Tier3FloorText(tc.treatments, tc.windowMs); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTierThreeFloorMacroIsDerivedFromThePackAndTheWindow(t *testing.T) {
	pack, err := resolvePack("cis")
	if err != nil {
		t.Fatal(err)
	}
	treatments := Tier3Treatments(pack)
	images := []ImageResult{imageWith("a", 1, 1, 3)}

	tel := telemetryWith(t, images, treatments, 3000)
	text := RenderMacros(tel)
	got := macrosOf(t, text)
	if got["ConUnitTierThreeFloor"] != "15" {
		t.Errorf("floor = %q, want (1 + 4) x 3 = 15 for the hardening profile at W of 3 s", got["ConUnitTierThreeFloor"])
	}
	// The same pack at another window gives another floor: nothing is typed.
	if got := macrosOf(t, RenderMacros(telemetryWith(t, images, treatments, 5000)))["ConUnitTierThreeFloor"]; got != "25" {
		t.Errorf("floor at W of 5 s = %q, want 25", got)
	}
	// Another pack gives another floor.
	hygiene, _ := resolvePack("hygiene")
	if got := macrosOf(t, RenderMacros(telemetryWith(t, images, Tier3Treatments(hygiene), 3000)))["ConUnitTierThreeFloor"]; got != "12" {
		t.Errorf("floor of the hygiene pack = %q, want (1 + 3) x 3 = 12", got)
	}
	// Without the treatments in the telemetry the value is not available.
	if got := macrosOf(t, RenderMacros(telemetryWith(t, images, nil, 3000)))["ConUnitTierThreeFloor"]; got != "n/a" {
		t.Errorf("floor without treatments = %q, want n/a", got)
	}
	for _, want := range []string{"one after another", "plain number without a unit", "read from the run, not typed"} {
		if !strings.Contains(text, want) {
			t.Errorf("the macro comments must say %q:\n%s", want, text)
		}
	}
}

// ---------------------------------------------------------------------------
// The sequence of the Tier 3 containers, against the real pack and a fake engine

const fakeEngineScript = `#!/usr/bin/env bash
echo "$@" >> "$FAKE_LOG"
case "$1" in
  run)
    echo "running 0" > "$FAKE_STATE"
    echo "0123456789ab"
    ;;
  container)
    cat "$FAKE_STATE"
    ;;
  kill)
    echo "exited 143" > "$FAKE_STATE"
    ;;
esac
exit 0
`

// fakeRun is what the fake engine saw while a pack ran.
type fakeRun struct {
	lines     []string
	elapsed   time.Duration
	container *conunit.Container
}

// runPack applies the pack to a container whose engine is a fake that keeps
// every container running until it receives SIGTERM.
func runPack(t *testing.T, pack conunit.RulePack, window time.Duration) fakeRun {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "podman") // the name makes the engine a podman
	if err := os.WriteFile(script, []byte(fakeEngineScript), 0o755); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "calls.log")
	t.Setenv("FAKE_LOG", logFile)
	t.Setenv("FAKE_STATE", filepath.Join(dir, "state"))

	c := &conunit.Container{Context: context.Background(), Image: "sha256:abc", Engine: &engine.Engine{BinaryPath: script}, ProbeWindow: window}
	start := time.Now()
	pack.Apply(c)
	elapsed := time.Since(start)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	return fakeRun{lines: strings.Split(strings.TrimSpace(string(data)), "\n"), elapsed: elapsed, container: c}
}

// isTierThreeContainer reports whether an engine call starts a Tier 3 container:
// a detached container named by the probe, which observes it for the window.
// The checks of the other tiers run short `run --rm` probes when the test gives
// them no filesystem index. A real run has the index and starts none of them.
func isTierThreeContainer(call string) bool {
	return strings.HasPrefix(call, "run -d --name con-unit-probe-") || strings.HasPrefix(call, "run -d --name con-unit-sigterm-")
}

// treatmentOf names the treatment flag of a run call, or "" for a run with the
// defensive flags only.
func treatmentOf(call string) string {
	for _, flag := range []string{"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=256m", "--user"} {
		if strings.Contains(call, " "+flag) {
			return flag
		}
	}
	return ""
}

// containerEvents returns the sequence of start and removal events of the Tier 3
// containers by name.
func containerEvents(lines []string) (events []string) {
	for _, l := range lines {
		fields := strings.Fields(l)
		switch {
		case len(fields) > 3 && isTierThreeContainer(l):
			events = append(events, "start "+fields[3])
		case len(fields) > 1 && fields[0] == "rm":
			events = append(events, "remove "+fields[len(fields)-1])
		}
	}
	return events
}

func TestTier3RunsOneAfterAnother(t *testing.T) {
	const window = 120 * time.Millisecond
	cases := []struct {
		name string
		pack conunit.RulePack
		// order is the treatment flag of every container in the order the
		// engine started them: the baseline first, which has none. The SIGTERM
		// check starts a container with the baseline flags.
		order []string
	}{
		{"hardening profile", conunit.CISBenchmark(), []string{"", "--cap-drop=ALL", "--memory=256m", "--read-only", "--security-opt=no-new-privileges:true"}},
		{"production hygiene pack", conunit.ProductionHygiene(), []string{"", "--read-only", "--cap-drop=ALL", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := runPack(t, tc.pack, window)
			var runs []string
			for _, l := range fr.lines {
				if isTierThreeContainer(l) {
					runs = append(runs, l)
				}
			}
			treatments := Tier3Treatments(tc.pack)

			// The baseline plus the treatments of the pack are all the containers.
			if len(runs) != 1+len(treatments) {
				t.Fatalf("%d containers started, want the baseline plus %d treatments %v:\n%s", len(runs), len(treatments), treatments, strings.Join(fr.lines, "\n"))
			}
			var order []string
			for _, r := range runs {
				order = append(order, treatmentOf(r))
			}
			if strings.Join(order, "|") != strings.Join(tc.order, "|") {
				t.Errorf("container order %q, want %q", order, tc.order)
			}
			if order[0] != "" {
				t.Error("the first container must be the baseline with the defensive flags only")
			}

			// Never two containers at the same time: every container is removed
			// before the next one starts.
			alive, most := map[string]bool{}, 0
			for _, e := range containerEvents(fr.lines) {
				kind, name, _ := strings.Cut(e, " ")
				if kind == "start" {
					alive[name] = true
				} else {
					delete(alive, name)
				}
				most = max(most, len(alive))
			}
			if most != 1 || len(alive) != 0 {
				t.Errorf("at most %d containers alive at once and %d left at the end, want 1 and 0", most, len(alive))
			}

			// Every container is observed for the whole window, so the Tier 3 time
			// of an image whose containers stay running is at least the floor.
			floor := time.Duration(1+len(treatments)) * window
			if fr.elapsed < floor {
				t.Errorf("Tier 3 took %s, less than the floor of %d x %s = %s", fr.elapsed, 1+len(treatments), window, floor)
			}
			for _, r := range fr.container.Results {
				if r.Tier == spec.TierContract && r.EffectiveOutcome() != spec.OutcomePass {
					t.Errorf("%s = %s (%s), the fake keeps every container running", r.TestID, r.EffectiveOutcome(), r.Message)
				}
			}
			// The macro of this run states the floor that the run just met.
			windowMs := window.Milliseconds()
			if got := Tier3FloorText(treatments, windowMs); got == "n/a" || got == "0" {
				t.Errorf("floor text = %q", got)
			}
		})
	}
}
