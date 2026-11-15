package runner

import (
	"runtime"
	"syscall"
)

// All figures in this file describe the ConUnit process only. They never
// include the container engine daemon, the containers it runs for Tier 3, or
// anything else outside this process and the CLI children it waited for.

const bytesPerMiB = 1024 * 1024

// processUsage is a snapshot of the CPU time consumed by this process and by
// the children it has started and waited for (the engine CLI, Syft).
type processUsage struct {
	selfSeconds     float64
	childrenSeconds float64
}

func timevalSeconds(tv syscall.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}

func cpuSeconds(usage syscall.Rusage) float64 {
	return timevalSeconds(usage.Utime) + timevalSeconds(usage.Stime)
}

// readProcessUsage returns the CPU time so far. A failed system call yields
// zero, which shows up as an absent figure and not as a wrong one.
func readProcessUsage() processUsage {
	var snapshot processUsage
	var self, children syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &self); err == nil {
		snapshot.selfSeconds = cpuSeconds(self)
	}
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &children); err == nil {
		snapshot.childrenSeconds = cpuSeconds(children)
	}
	return snapshot
}

// since returns the CPU time consumed after the earlier snapshot, for this
// process and for its terminated children.
func (u processUsage) since(earlier processUsage) (self, children float64) {
	self = u.selfSeconds - earlier.selfSeconds
	children = u.childrenSeconds - earlier.childrenSeconds
	if self < 0 {
		self = 0
	}
	if children < 0 {
		children = 0
	}
	return self, children
}

// liveHeapMB forces a collection and returns the heap still in use. It is the
// memory the evaluation keeps reachable (mainly the filesystem index), free of
// garbage that the collector had not yet reclaimed. The collection costs time,
// so callers take it after all phase timers have stopped.
func liveHeapMB() float64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return float64(stats.HeapAlloc) / bytesPerMiB
}

// processPeakRSSMB is the highest resident set size of this process so far. It
// never decreases, so a value read at the end of one image says nothing about
// that image: it is a ceiling over everything the process has done. Reports
// use only its maximum over a whole batch.
func processPeakRSSMB() float64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return float64(usage.Maxrss) / bytesPerMiB // bytes on macOS
	}
	return float64(usage.Maxrss) / 1024 // kibibytes on Linux
}
