package conunit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
)

func TestStoragePoliciesAndCleanup(t *testing.T) {
	tracker := &conunit.ResourceTracker{Policy: conunit.StoragePreserve}

	// Test registration
	tracker.RegisterAcquiredImage("test-image:1.0")
	if len(tracker.AcquiredImages) != 1 {
		t.Fatalf("Expected 1 tracked image, got %d", len(tracker.AcquiredImages))
	}

	// Test temp root creation
	dir, err := tracker.CreateTempGraphRoot()
	if err != nil {
		t.Fatalf("Failed creating temp graph root: %v", err)
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("Expected temp directory to exist on disk: %s", dir)
	}

	// Test cleanup removes temp directory
	tracker.Cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Expected temp graph root to be removed upon cleanup, but it still exists: %s", dir)
	}
}

func TestEphemeralCleanupRemovesOnlyNewlyAcquiredImages(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "fake-engine")
	logPath := filepath.Join(dir, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FAKE_CLEANUP_LOG\"\n"
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake engine: %v", err)
	}
	t.Setenv("FAKE_CLEANUP_LOG", logPath)

	tracker := &conunit.ResourceTracker{
		Engine: &engine.Engine{BinaryPath: binaryPath},
		Policy: conunit.StorageEphemeral,
	}
	tracker.RegisterAcquiredImage("new-image:latest")
	tracker.RegisterAcquiredImage("new-image:latest")
	tracker.Cleanup()
	tracker.Cleanup()

	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read fake engine calls: %v", err)
	}
	if got, want := string(calls), "rmi new-image:latest\n"; got != want {
		t.Fatalf("cleanup calls = %q, want exactly %q", got, want)
	}
	if strings.Contains(string(calls), "-f") || strings.Contains(string(calls), "prune") {
		t.Fatalf("cleanup used force-removal or global prune: %q", calls)
	}
}

func TestEphemeralCleanupWithoutEngineIsSafe(t *testing.T) {
	tracker := &conunit.ResourceTracker{Policy: conunit.StorageEphemeral}
	tracker.RegisterAcquiredImage("new-image:latest")
	tracker.Cleanup()
}
