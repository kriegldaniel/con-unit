package runner

import (
	"os/exec"
	"runtime"
	"testing"
	"time"
)

var cpuSink uint64

// burnCPU keeps one thread busy for at least the given wall time.
func burnCPU(d time.Duration) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); {
		for i := 0; i < 1_000_000; i++ {
			cpuSink += uint64(i) * 2654435761
		}
	}
}

func TestProcessUsageSeparatesOwnCPUFromChildCPU(t *testing.T) {
	start := readProcessUsage()
	burnCPU(100 * time.Millisecond)
	afterSelf := readProcessUsage()
	self, children := afterSelf.since(start)
	if self < 0.02 {
		t.Errorf("own CPU = %.3f s after 100 ms of busy work, want at least 0.02 s", self)
	}
	if children != 0 {
		t.Errorf("child CPU = %.3f s before any child ran, want 0", children)
	}

	// A terminated child that was waited for is counted as child CPU.
	cmd := exec.Command("sh", "-c", "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run CPU-bound child: %v", err)
	}
	selfAfterChild, childAfter := readProcessUsage().since(afterSelf)
	if childAfter <= 0 {
		t.Errorf("child CPU = %.3f s after a CPU-bound child, want more than 0", childAfter)
	}
	if selfAfterChild > childAfter {
		t.Errorf("waiting for the child cost %.3f s of own CPU, more than the child's %.3f s: the two are mixed up", selfAfterChild, childAfter)
	}
}

func TestProcessUsageSinceNeverGoesNegative(t *testing.T) {
	self, children := processUsage{selfSeconds: 1, childrenSeconds: 1}.since(processUsage{selfSeconds: 2, childrenSeconds: 3})
	if self != 0 || children != 0 {
		t.Fatalf("since = %v, %v; a clock that went backwards must give 0", self, children)
	}
}

func TestLiveHeapCountsReachableDataAndNotGarbage(t *testing.T) {
	keep := make([]byte, 64<<20)
	for i := 0; i < len(keep); i += 4096 {
		keep[i] = 1 // touch every page so the allocation is real
	}
	with := liveHeapMB()
	runtime.KeepAlive(keep)
	keep = nil
	without := liveHeapMB()
	if with < 60 {
		t.Errorf("live heap = %.1f MiB with a 64 MiB slice reachable, want at least 60", with)
	}
	if with-without < 60 {
		t.Errorf("live heap fell from %.1f to %.1f MiB after the slice became garbage, want a drop of about 64", with, without)
	}
}

func TestProcessPeakRSSIsACeilingThatNeverDecreases(t *testing.T) {
	first := processPeakRSSMB()
	if first <= 0 {
		t.Fatalf("peak RSS = %.1f MiB, want a positive figure", first)
	}
	burst := make([]byte, 96<<20)
	for i := 0; i < len(burst); i += 4096 {
		burst[i] = 1
	}
	runtime.KeepAlive(burst)
	burst = nil
	runtime.GC()
	if second := processPeakRSSMB(); second < first {
		t.Errorf("peak RSS fell from %.1f to %.1f MiB, a peak must not decrease", first, second)
	}
}
