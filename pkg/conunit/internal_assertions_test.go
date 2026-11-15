package conunit

import (
	"errors"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

func TestProbeEvidenceHelperFailsClosedOnIncompleteResults(t *testing.T) {
	c := &Container{}
	start := time.Now()
	if !recordUnverifiedProbe(c, "EXEC-01", "probe", spec.TierContract, start, nil, nil) {
		t.Fatal("nil probe with nil error must be treated as unverified")
	}
	if got := probeExitCode(nil); got != -1 {
		t.Fatalf("nil probe exit code = %d, want -1", got)
	}
	if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
		t.Fatalf("nil probe outcome = %s, want %s", got, spec.OutcomeUnverified)
	}
	if recordUnverifiedProbe(c, "EXEC-01", "probe", spec.TierContract, start, &engine.ExecResult{ExitCode: 0, EvidenceComplete: true}, nil) {
		t.Fatal("complete successful probe evidence must not be marked unverified")
	}
	if !recordUnverifiedProbe(c, "EXEC-01", "probe", spec.TierContract, start, &engine.ExecResult{ExitCode: 0}, errors.New("context canceled")) {
		t.Fatal("probe errors must be unverified even when the returned result has exit code zero")
	}
}
