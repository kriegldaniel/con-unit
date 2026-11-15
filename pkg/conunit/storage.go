package conunit

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/con-unit/con-unit/pkg/engine"
)

// ResourceTracker tracks images acquired by this run and allocated resources for cleanup.
type ResourceTracker struct {
	mu             sync.Mutex
	Engine         *engine.Engine
	Policy         StoragePolicy
	AcquiredImages []string
	TempRoots      []string
	cleaned        bool
}

// NewResourceTracker creates a new tracker with OS interrupt hooks
func NewResourceTracker(eng *engine.Engine, policy StoragePolicy) *ResourceTracker {
	tracker := &ResourceTracker{
		Engine: eng,
		Policy: policy,
	}

	// Trap SIGINT and SIGTERM to guarantee host cleanup even on abrupt exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		tracker.Cleanup()
		os.Exit(130)
	}()

	return tracker
}

// RegisterAcquiredImage marks an image newly pulled during this session.
func (rt *ResourceTracker) RegisterAcquiredImage(image string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, acquired := range rt.AcquiredImages {
		if acquired == image {
			return
		}
	}
	rt.AcquiredImages = append(rt.AcquiredImages, image)
}

// RegisterTempRoot tracks an ephemeral graphroot directory
func (rt *ResourceTracker) RegisterTempRoot(dir string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.TempRoots = append(rt.TempRoots, dir)
}

// Cleanup purges resources based on storage policy
func (rt *ResourceTracker) Cleanup() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.cleaned {
		return
	}
	rt.cleaned = true

	// If policy is Ephemeral, remove only images this run newly acquired.
	if rt.Policy == StorageEphemeral && rt.Engine != nil && rt.Engine.BinaryPath != "" {
		for _, img := range rt.AcquiredImages {
			cmd := exec.Command(rt.Engine.BinaryPath, "rmi", img)
			_ = cmd.Run()
		}
	}

	// If temporary roots were created, delete them completely
	for _, dir := range rt.TempRoots {
		_ = os.RemoveAll(dir)
	}
}

// CreateTempGraphRoot creates an isolated directory for rootless podman/docker storage
func (rt *ResourceTracker) CreateTempGraphRoot() (string, error) {
	dir, err := os.MkdirTemp("", "conunit-graphroot-*")
	if err != nil {
		return "", fmt.Errorf("failed creating temp graphroot: %w", err)
	}
	rt.RegisterTempRoot(dir)
	return dir, nil
}
