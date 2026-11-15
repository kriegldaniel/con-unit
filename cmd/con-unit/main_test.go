package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIPrintHelpAndVersion(t *testing.T) {
	// 1. Verify printHelp does not panic
	printHelp()

	// 2. Test command dispatch for help and version
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"con-unit", "version"}
	main()

	os.Args = []string{"con-unit", "help"}
	main()
}

func TestCLIRunTestCommand(t *testing.T) {
	if os.Getenv("CONUNIT_INTEGRATION") != "1" {
		t.Skip("set CONUNIT_INTEGRATION=1 to run container-engine integration tests")
	}
	tempDir := t.TempDir()
	jsonOut := filepath.Join(tempDir, "cli-test-output.json")
	xmlOut := filepath.Join(tempDir, "cli-test-output.xml")

	// 1. Run basic test command with json format output
	runTestCommand([]string{
		"alpine:latest",
		"--pack", "hygiene",
		"--format", "json",
		"--output", jsonOut,
	})

	if _, err := os.Stat(jsonOut); os.IsNotExist(err) {
		t.Errorf("Expected CLI to generate JSON report at %s", jsonOut)
	}

	// 2. Run with junit format output and --fix flag
	runTestCommand([]string{
		"alpine:latest",
		"--pack", "cis",
		"--fix",
		"--format", "junit",
		"--output", xmlOut,
	})

	if _, err := os.Stat(xmlOut); os.IsNotExist(err) {
		t.Errorf("Expected CLI to generate JUnit XML report at %s", xmlOut)
	}
}

func TestCLIRunEvalCommand(t *testing.T) {
	if os.Getenv("CONUNIT_INTEGRATION") != "1" {
		t.Skip("set CONUNIT_INTEGRATION=1 to run container-engine integration tests")
	}
	tempDir := t.TempDir()
	sampleImages := filepath.Join(tempDir, "sample_images.txt")
	content := "alpine:latest\n"
	if err := os.WriteFile(sampleImages, []byte(content), 0644); err != nil {
		t.Fatalf("Failed creating sample images file: %v", err)
	}

	runEvalCommand([]string{
		"--images", sampleImages,
		"--pack", "hygiene",
		"--out-dir", tempDir,
	})

	jsonSummary := filepath.Join(tempDir, "empirical_study.json")
	mdSummary := filepath.Join(tempDir, "EMPIRICAL_SUMMARY.md")

	if _, err := os.Stat(jsonSummary); os.IsNotExist(err) {
		t.Errorf("Expected evaluation JSON at %s", jsonSummary)
	}
	if _, err := os.Stat(mdSummary); os.IsNotExist(err) {
		t.Errorf("Expected evaluation Markdown at %s", mdSummary)
	}
}
