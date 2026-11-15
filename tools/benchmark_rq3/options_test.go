package main

import (
	"reflect"
	"testing"
	"time"
)

func testApplied() Applied {
	return Applied{Platform: "linux/amd64", ImageSource: "auto", ProbeWindow: 3 * time.Second}
}

// TestDetectOptionsCarryTheRegistryRemap guards the one value of the run metadata that the host
// cannot reveal: the AWS run installs a registry remap and states it through the environment.
// Without it the RQ3 telemetry would not say where its images came from.
func TestDetectOptionsCarryTheRegistryRemap(t *testing.T) {
	const remap = "docker.io/library -> public.ecr.aws/docker/library"
	t.Setenv(registryRemapEnv, remap)
	args := []string{"-iterations", "3"}
	opts := detectOptions("/usr/bin/podman", "images.txt", "cis", "PACK-CONUNIT-HARDENING", testApplied(), args)

	if opts.RegistryRemap != remap {
		t.Errorf("RegistryRemap = %q, want %q", opts.RegistryRemap, remap)
	}
	if opts.EngineBinary != "/usr/bin/podman" || opts.DatasetPath != "images.txt" || opts.Pack != "cis" || opts.PackID != "PACK-CONUNIT-HARDENING" {
		t.Errorf("options lost a field: %+v", opts)
	}
	if opts.Platform != "linux/amd64" || opts.ImageSource != "auto" || opts.ProbeWindow != 3*time.Second {
		t.Errorf("the applied options must be what the metadata records: %+v", opts)
	}
	if !reflect.DeepEqual(opts.Flags, args) {
		t.Errorf("Flags = %v, want %v", opts.Flags, args)
	}
}

// TestDetectOptionsWithoutARemap checks the other direction: a host without a remap, such as a
// developer laptop, must not state one.
func TestDetectOptionsWithoutARemap(t *testing.T) {
	t.Setenv(registryRemapEnv, "")
	opts := detectOptions("podman", "images.txt", "cis", "PACK-CONUNIT-HARDENING", testApplied(), nil)
	if opts.RegistryRemap != "" {
		t.Errorf("RegistryRemap = %q, want none", opts.RegistryRemap)
	}
}
