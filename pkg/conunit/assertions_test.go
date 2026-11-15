package conunit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/oci"
	"github.com/con-unit/con-unit/pkg/spec"
)

func installFakeSyft(t *testing.T, output, exitCode string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' \"$FAKE_SYFT_OUTPUT\"\nexit \"${FAKE_SYFT_EXIT:-0}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "syft"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake Syft executable: %v", err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FAKE_SYFT_OUTPUT", output)
	t.Setenv("FAKE_SYFT_EXIT", exitCode)
}

func TestUserNotRootAssertion(t *testing.T) {
	cases := []struct {
		user        string
		index       *oci.FilesystemIndex
		outcome     spec.Outcome
		description string
	}{
		{user: "", outcome: spec.OutcomeFail, description: "Empty user defaults to root"},
		{user: "0", outcome: spec.OutcomeFail, description: "Explicit UID 0"},
		{user: "root", index: &oci.FilesystemIndex{PasswdUIDs: map[string][]uint32{"root": {0}}}, outcome: spec.OutcomeFail, description: "Explicit user root"},
		{user: "0:0", outcome: spec.OutcomeFail, description: "UID 0 with group"},
		{user: "root:1000", index: &oci.FilesystemIndex{PasswdUIDs: map[string][]uint32{"root": {0}}}, outcome: spec.OutcomeFail, description: "Root username with non-root group"},
		{user: "0000:1000", outcome: spec.OutcomeFail, description: "Numeric root UID with non-root group"},
		{user: "10001", outcome: spec.OutcomePass, description: "Unprivileged numeric UID"},
		{user: "10001:10001", outcome: spec.OutcomePass, description: "Unprivileged UID and GID"},
		{user: "appuser", index: &oci.FilesystemIndex{PasswdUIDs: map[string][]uint32{"appuser": {10001}}}, outcome: spec.OutcomePass, description: "Named non-root user resolved from passwd"},
		{user: "appuser:1000", index: &oci.FilesystemIndex{PasswdUIDs: map[string][]uint32{"appuser": {10001}}}, outcome: spec.OutcomePass, description: "Named non-root user with group resolved from passwd"},
		{user: "appuser", index: &oci.FilesystemIndex{PasswdUIDs: map[string][]uint32{"appuser": {0}}}, outcome: spec.OutcomeFail, description: "Named alias for UID 0"},
		{user: "missing", index: &oci.FilesystemIndex{}, outcome: spec.OutcomeUnverified, description: "Named user missing from passwd"},
		{user: "appuser", index: &oci.FilesystemIndex{PasswdUIDs: map[string][]uint32{"appuser": {10001, 10002}}}, outcome: spec.OutcomeUnverified, description: "Ambiguous passwd mapping"},
		{user: "appuser", index: &oci.FilesystemIndex{PasswdEvidenceIssue: "malformed passwd"}, outcome: spec.OutcomeUnverified, description: "Malformed passwd evidence"},
	}

	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			c := &conunit.Container{
				Image:    "mock:latest",
				OCIIndex: tc.index,
				Inspect: &engine.ImageInspect{
					Config: engine.ImageConfig{
						User: tc.user,
					},
				},
			}

			c.AssertSpec().UserNotRoot()
			if len(c.Results) != 1 {
				t.Fatalf("User %q produced %d results, want one: %+v", tc.user, len(c.Results), c.Results)
			}
			if got := c.Results[0].EffectiveOutcome(); got != tc.outcome {
				t.Errorf("User %q outcome = %s, want %s (result: %+v)", tc.user, got, tc.outcome, c.Results[0])
			}
		})
	}
}

func TestRequireEntrypointAssertion(t *testing.T) {
	t.Run("Fails when both Entrypoint and Cmd are empty", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{},
			},
		}
		c.AssertSpec().RequireEntrypoint()
		if len(c.Failures) == 0 {
			t.Error("Expected failure for empty entrypoint/cmd, but assertion passed")
		}
	})

	t.Run("Passes when Entrypoint is defined", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					Entrypoint: []string{"/app/server"},
				},
			},
		}
		c.AssertSpec().RequireEntrypoint()
		if len(c.Failures) > 0 {
			t.Errorf("Expected pass when Entrypoint is defined, got: %v", c.Failures)
		}
	})

	t.Run("Passes when Cmd is defined", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					Cmd: []string{"python3", "main.py"},
				},
			},
		}
		c.AssertSpec().RequireEntrypoint()
		if len(c.Failures) > 0 {
			t.Errorf("Expected pass when Cmd is defined, got: %v", c.Failures)
		}
	})
}

func TestDisallowedEnvKeysAssertion(t *testing.T) {
	c := &conunit.Container{
		Inspect: &engine.ImageInspect{
			Config: engine.ImageConfig{
				Env: []string{
					"PATH=/usr/local/bin:/bin",
					"DATABASE_PASSWORD=supersecret",
					"API_TOKEN=xyz123",
				},
			},
		},
	}

	c.AssertSpec().DisallowedEnvKeys("PASSWORD", "TOKEN")

	if len(c.Failures) == 0 {
		t.Fatal("Expected failures for leaked secrets in ENV, but none recorded")
	}
	if len(c.Failures) != 1 {
		t.Errorf("Expected 1 aggregated failure report, got %d", len(c.Failures))
	}
}

func TestMaxSizeMBAssertion(t *testing.T) {
	c := &conunit.Container{
		Inspect: &engine.ImageInspect{
			Size: 500 * 1024 * 1024, // 500 MB
		},
	}

	// Case 1: Limit 1000 MB -> Pass
	c.AssertSpec().MaxSizeMB(1000)
	if len(c.Failures) > 0 {
		t.Errorf("Expected 500MB to pass 1000MB limit, got: %v", c.Failures)
	}

	// Case 2: Limit 200 MB -> Fail
	c.AssertSpec().MaxSizeMB(200)
	if len(c.Failures) != 1 {
		t.Errorf("Expected 1 failure for exceeding 200MB limit, got %d", len(c.Failures))
	}
}

func TestSoftAssertionsAccumulation(t *testing.T) {
	// A container with multiple defects should record all of them without halting
	c := &conunit.Container{
		Inspect: &engine.ImageInspect{
			Size: 900 * 1024 * 1024,
			Config: engine.ImageConfig{
				User: "root",                         // Defect 1
				Env:  []string{"PRIVATE_KEY=secret"}, // Defect 2
			},
		},
	}

	c.Should().
		NotRunAsRoot().
		HaveEntrypoint() // Defect 3: empty entrypoint

	c.AssertSpec().
		DisallowedEnvKeys("PRIVATE_KEY").
		MaxSizeMB(500) // Defect 4: size > 500MB

	if len(c.Failures) != 4 {
		t.Fatalf("Expected exactly 4 soft assertion failures accumulated, got %d: %v", len(c.Failures), c.Failures)
	}
}

func TestPrivilegedAndDebugPortsAssertion(t *testing.T) {
	t.Run("Fails when privileged port 80 is exposed", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					ExposedPorts: map[string]struct{}{
						"80/tcp": {},
					},
				},
			},
		}

		c.AssertSpec().RequireNonPrivilegedPorts()

		if len(c.Failures) != 1 {
			t.Fatalf("Expected 1 failure for exposed port 80, got %d", len(c.Failures))
		}
	})

	t.Run("Passes when only unprivileged port 8080 is exposed", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					ExposedPorts: map[string]struct{}{
						"8080/tcp": {},
						"8443/tcp": {},
					},
				},
			},
		}

		c.AssertSpec().RequireNonPrivilegedPorts()

		if len(c.Failures) != 0 {
			t.Errorf("Expected pass for unprivileged ports, got: %v", c.Failures)
		}
	})

	t.Run("Detects exposed debugger port 5005", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					ExposedPorts: map[string]struct{}{
						"5005/tcp": {},
					},
				},
			},
		}

		c.AssertSpec().DisallowDebugPorts()

		if len(c.Failures) != 1 {
			t.Fatalf("Expected 1 failure for exposed JDWP debug port 5005, got %d", len(c.Failures))
		}
	})
}

func TestCloudTokenRegexDetection(t *testing.T) {
	c := &conunit.Container{
		Inspect: &engine.ImageInspect{
			Config: engine.ImageConfig{
				Env: []string{
					"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
					"GH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
				},
			},
		},
	}

	c.AssertSpec().DisallowedEnvKeys()

	if len(c.Failures) != 1 {
		t.Fatalf("Expected failure detecting cloud credential patterns, got %d", len(c.Failures))
	}
}

func TestRequireCopyOverAddAssertion(t *testing.T) {
	t.Run("Fails when OCI history contains ADD instructions", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				HistoryEntries: []string{
					"/bin/sh -c #(nop) ADD https://example.com/tar.gz in /",
				},
			},
		}

		c.AssertSpec().RequireCopyOverAdd()

		if len(c.Failures) != 1 {
			t.Fatalf("Expected 1 failure for ADD instruction, got %d", len(c.Failures))
		}
	})

	t.Run("Passes when OCI history contains only COPY instructions", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				HistoryEntries: []string{
					"/bin/sh -c #(nop) COPY file:abc in /app",
				},
			},
		}

		c.AssertSpec().RequireCopyOverAdd()

		if len(c.Failures) != 0 {
			t.Errorf("Expected pass for clean COPY instructions, got: %v", c.Failures)
		}
	})

	t.Run("Unverifies when OCI history is absent", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				HistoryEvidenceIssue: "OCI image config contains no history entries",
			},
		}
		c.AssertSpec().RequireCopyOverAdd()
		if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
			t.Fatalf("history outcome = %s, want %s", got, spec.OutcomeUnverified)
		}
	})
}

func TestRequireOCIProvenanceAssertion(t *testing.T) {
	t.Run("Fails when required OCI labels are missing", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					Labels: map[string]string{},
				},
			},
		}

		c.AssertSpec().RequireOCIProvenance("source", "revision")

		if len(c.Failures) != 1 {
			t.Fatalf("Expected failure for missing OCI provenance labels, got %d", len(c.Failures))
		}
	})

	t.Run("Passes when required OCI provenance labels are present", func(t *testing.T) {
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					Labels: map[string]string{
						"org.opencontainers.image.source":   "https://github.com/my-org/my-app",
						"org.opencontainers.image.revision": "a1b2c3d4e5f6",
					},
				},
			},
		}

		c.AssertSpec().RequireOCIProvenance("source", "revision")

		if len(c.Failures) != 0 {
			t.Errorf("Expected pass when provenance labels exist, got: %v", c.Failures)
		}
	})
}

func TestEmptyPasswordAccountsAssertion(t *testing.T) {
	t.Run("Fails when empty password accounts exist in /etc/shadow", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				EmptyPasswordAccounts: []string{"root", "guest"},
			},
		}

		c.AssertFilesystem().NoEmptyPasswordAccounts()

		if len(c.Failures) != 1 {
			t.Fatalf("Expected failure for empty password accounts, got %d", len(c.Failures))
		}
	})

	t.Run("Passes when /etc/shadow has zero empty password accounts", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				EmptyPasswordAccounts: []string{},
			},
		}

		c.AssertFilesystem().NoEmptyPasswordAccounts()

		if len(c.Failures) != 0 {
			t.Errorf("Expected pass when no empty password accounts exist, got: %v", c.Failures)
		}
	})

	t.Run("Unverifies when final account evidence is incomplete", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				AccountEvidenceIssue: "final /etc/shadow is missing",
			},
		}
		c.AssertFilesystem().NoEmptyPasswordAccounts()
		if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
			t.Fatalf("account evidence outcome = %s, want %s", got, spec.OutcomeUnverified)
		}
	})
}

func TestNonRootSystemBinariesAssertion(t *testing.T) {
	t.Run("Fails when system binaries are owned by unprivileged UID", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				NonRootSystemBinaries: []string{"/usr/bin/node (UID 10001)"},
			},
		}

		c.AssertFilesystem().NoNonRootSystemBinaries()

		if len(c.Failures) != 1 {
			t.Fatalf("Expected failure for non-root system binaries, got %d", len(c.Failures))
		}
	})

	t.Run("Passes when system binaries are owned by root", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				NonRootSystemBinaries: []string{},
			},
		}

		c.AssertFilesystem().NoNonRootSystemBinaries()

		if len(c.Failures) != 0 {
			t.Errorf("Expected pass when all system binaries are root-owned, got: %v", c.Failures)
		}
	})
}

func TestRequireApprovedLicensesAssertion(t *testing.T) {
	t.Run("Passes when every SBOM package has an approved license", func(t *testing.T) {
		installFakeSyft(t, `{"artifacts":[{"name":"libfoo","licenses":["Apache-2.0"]},{"name":"libbar","licenses":[{"value":"MIT","spdxExpression":"MIT"}]}]}`, "0")
		c := &conunit.Container{Image: "mock:latest"}
		c.AssertSupplyChain().RequireApprovedLicenses("Apache-2.0", "MIT")
		if len(c.Failures) != 0 {
			t.Errorf("Expected approved package licenses to pass, got: %v", c.Failures)
		}
	})

	t.Run("Rejects an unapproved package even when the image label is approved", func(t *testing.T) {
		installFakeSyft(t, `{"artifacts":[{"name":"libfoo","licenses":["GPL-3.0-only"]}]}`, "0")
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{Labels: map[string]string{"org.opencontainers.image.licenses": "MIT"}},
			},
		}
		c.AssertSupplyChain().RequireApprovedLicenses("MIT")
		if len(c.Failures) != 1 {
			t.Fatalf("Expected failure for unapproved SBOM license, got %d", len(c.Failures))
		}
		if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeFail {
			t.Fatalf("unapproved-license outcome = %s, want %s", got, spec.OutcomeFail)
		}
	})

	t.Run("Marks missing license metadata unverified", func(t *testing.T) {
		installFakeSyft(t, `{"artifacts":[{"name":"libfoo","licenses":[]}]}`, "0")
		c := &conunit.Container{Image: "mock:latest"}
		c.AssertSupplyChain().RequireApprovedLicenses("MIT")
		if len(c.Failures) != 1 {
			t.Fatalf("Expected unverified license failure, got %d", len(c.Failures))
		}
		if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
			t.Fatalf("missing-license outcome = %s, want %s", got, spec.OutcomeUnverified)
		}
	})

	t.Run("Records one result when a violation and missing metadata occur together", func(t *testing.T) {
		installFakeSyft(t, `{"artifacts":[{"name":"known","licenses":["GPL-3.0-only"]},{"name":"unknown","licenses":[]}]}`, "0")
		c := &conunit.Container{Image: "mock:latest"}
		c.AssertSupplyChain().RequireApprovedLicenses("MIT")
		// A rule has one result per image. The measured violation decides the
		// outcome and the message still states that the evidence was incomplete.
		if len(c.Results) != 1 || c.Results[0].EffectiveOutcome() != spec.OutcomeFail {
			t.Fatalf("Expected one FAIL result, got %+v", c.Results)
		}
		message := c.Results[0].Message
		if !strings.Contains(message, "known: GPL-3.0-only") || !strings.Contains(message, "unknown: no license metadata") {
			t.Errorf("the message must state the violation and the incomplete evidence: %q", message)
		}
	})
}
func TestPackagesNotExistUsesStructuredSBOMAndFailsClosed(t *testing.T) {
	t.Run("ignores nested metadata names", func(t *testing.T) {
		installFakeSyft(t, `{"artifacts":[{"name":"library","metadata":{"name":"netcat"}}]}`, "0")
		c := &conunit.Container{Image: "mock:latest"}
		c.AssertSupplyChain().PackagesNotExist("netcat")
		if len(c.Failures) != 0 {
			t.Errorf("Expected metadata.name not to be treated as a package, got: %v", c.Failures)
		}
	})

	t.Run("detects compact JSON package names", func(t *testing.T) {
		installFakeSyft(t, `{"artifacts":[{"name":"netcat"}]}`, "0")
		c := &conunit.Container{Image: "mock:latest"}
		c.AssertSupplyChain().PackagesNotExist("netcat")
		if len(c.Failures) != 1 {
			t.Fatalf("Expected prohibited package detection, got %v", c.Failures)
		}
	})

	for _, test := range []struct {
		name     string
		output   string
		exitCode string
		hideSyft bool
	}{
		{name: "invalid JSON", output: "not json", exitCode: "0"},
		{name: "missing artifacts", output: `{"source":"fixture"}`, exitCode: "0"},
		{name: "empty inventory", output: `{"artifacts":[]}`, exitCode: "0"},
		{name: "Syft exits unsuccessfully", output: `{"artifacts":[]}`, exitCode: "9"},
		{name: "Syft unavailable", hideSyft: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.hideSyft {
				t.Setenv("PATH", t.TempDir())
			} else {
				installFakeSyft(t, test.output, test.exitCode)
			}
			c := &conunit.Container{Image: "mock:latest"}
			c.AssertSupplyChain().PackagesNotExist("netcat")
			if len(c.Failures) != 1 {
				t.Fatalf("Expected package check to fail closed, got %v", c.Failures)
			}
			if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
				t.Errorf("package evidence outcome = %s, want %s", got, spec.OutcomeUnverified)
			}
		})
	}
}

func TestRequireHealthcheckAssertion(t *testing.T) {
	for _, test := range []struct {
		name       string
		inspect    *engine.ImageInspect
		shouldFail bool
	}{
		{name: "missing inspect", inspect: nil, shouldFail: true},
		{name: "missing healthcheck", inspect: &engine.ImageInspect{}, shouldFail: true},
		{name: "disabled healthcheck", inspect: &engine.ImageInspect{Config: engine.ImageConfig{Healthcheck: &engine.HealthConfig{Test: []string{"NONE"}}}}, shouldFail: true},
		{name: "configured healthcheck", inspect: &engine.ImageInspect{Config: engine.ImageConfig{Healthcheck: &engine.HealthConfig{Test: []string{"CMD", "true"}}}}, shouldFail: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &conunit.Container{Inspect: test.inspect}
			c.AssertSpec().RequireHealthcheck()
			if got := len(c.Failures) > 0; got != test.shouldFail {
				t.Errorf("healthcheck failure = %t, want %t (results: %v)", got, test.shouldFail, c.Results)
			}
		})
	}
}

func TestAssertionsFailClosedWhenEvidenceIsMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	c := &conunit.Container{}
	c.AssertSpec().
		UserNotRoot().
		RequireEntrypoint().
		DisallowedEnvKeys().
		MaxSizeMB(100).
		RequireNonPrivilegedPorts().
		RequireHealthcheck().
		DisallowDebugPorts().
		RequireCopyOverAdd().
		RequireOCIProvenance()
	c.AssertFilesystem().
		PathsNotExist("/tmp/cache").
		BinariesNotExist("gcc").
		NoSuidBinaries().
		NoWorldWritableFiles().
		NoPrivateKeysOrCertificates().
		NoTestHarnessLeakage().
		NoEmptyPasswordAccounts().
		NoNonRootSystemBinaries().
		NoInteractiveShells().
		NoPackageManagers()
	c.AssertSupplyChain().
		PackagesNotExist("netcat").
		RequireApprovedLicenses("MIT").
		HasCryptographicSignature()

	if len(c.Results) != 22 {
		t.Fatalf("Expected 22 assertions to record a result, got %d", len(c.Results))
	}
	for _, result := range c.Results {
		if result.Passed {
			t.Errorf("%s passed without required image evidence: %s", result.TestID, result.Message)
		}
	}
}

func TestPathAssertionsPropagateRuntimeProbeErrors(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "fake-engine")
	script := "#!/bin/sh\nif [ \"$1\" = \"run\" ]; then\n  printf '%s\\n' 'engine unavailable' >&2\n  exit 125\nfi\nexit 99\n"
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake engine: %v", err)
	}
	c := &conunit.Container{
		Image:  "mock:latest",
		Engine: &engine.Engine{BinaryPath: binaryPath},
	}

	c.AssertFilesystem().PathsNotExist("/missing")
	c.AssertFilesystem().BinariesNotExist("gcc")
	if len(c.Results) != 2 {
		t.Fatalf("Expected each failed path scan to record a result, got %v", c.Results)
	}
	for _, result := range c.Results {
		if result.EffectiveOutcome() != spec.OutcomeUnverified {
			t.Errorf("Expected probe error to be unverified, got %s: %q", result.EffectiveOutcome(), result.Message)
		}
		if !strings.Contains(strings.ToLower(result.Message), "unverified") {
			t.Errorf("Expected probe error details in unverified message, got %q", result.Message)
		}
	}
}

func TestFilesystemAndSupplyChainAssertionsUnit(t *testing.T) {
	t.Run("WorldWritableFiles detects world-writable paths", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				WorldWritableFiles: map[string]int64{"/app/secret.json": 0777},
			},
		}
		c.AssertFilesystem().NoWorldWritableFiles()
		if len(c.Failures) != 1 {
			t.Errorf("Expected failure for world writable file, got %d", len(c.Failures))
		}
	})

	t.Run("PrivateKeysOrCertificates detects private key files", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				PrivateKeyFiles: map[string]string{"/etc/ssl/server.key": "Private key"},
			},
		}
		c.AssertFilesystem().NoPrivateKeysOrCertificates()
		if len(c.Failures) != 1 {
			t.Errorf("Expected failure for private key, got %d", len(c.Failures))
		}
	})

	t.Run("InteractiveShells detects shell interpreters", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				Paths: map[string]bool{"/bin/bash": true},
			},
		}
		c.AssertFilesystem().NoInteractiveShells()
		if len(c.Failures) != 1 {
			t.Errorf("Expected failure for shell interpreter, got %d", len(c.Failures))
		}
	})

	t.Run("PackageManagers detects package manager utilities", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				Paths: map[string]bool{"/usr/bin/apt": true},
			},
		}
		c.AssertFilesystem().NoPackageManagers()
		if len(c.Failures) != 1 {
			t.Errorf("Expected failure for package manager, got %d", len(c.Failures))
		}
	})

	t.Run("TestHarnessLeakage detects test runner configuration outside fixture locations", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				Paths: map[string]bool{"/app/phpunit.xml": true},
			},
		}
		c.AssertFilesystem().NoTestHarnessLeakage()
		if len(c.Failures) != 1 {
			t.Errorf("Expected failure for test harness configuration, got %d", len(c.Failures))
		}
	})

	t.Run("TestHarnessLeakage counts test directories as fixture candidates without failing", func(t *testing.T) {
		c := &conunit.Container{
			OCIIndex: &oci.FilesystemIndex{
				Paths: map[string]bool{"/app/tests/phpunit": true},
			},
		}
		c.AssertFilesystem().NoTestHarnessLeakage()
		if len(c.Failures) != 0 || len(c.Results) != 1 || c.Results[0].EffectiveOutcome() != spec.OutcomePass {
			t.Fatalf("Expected a PASS for fixture-only test directories, got %+v", c.Results)
		}
		if c.Results[0].Evidence == nil || len(c.Results[0].Evidence.FixtureCandidates) != 1 || len(c.Results[0].Evidence.Paths) != 0 {
			t.Errorf("fixture candidates must be reported separately: %+v", c.Results[0].Evidence)
		}
	})

	t.Run("Signature tags never count as verification", func(t *testing.T) {
		for _, tag := range []string{"app:latest.sig", "app:sha256-abc"} {
			c := &conunit.Container{Image: tag, Inspect: &engine.ImageInspect{RepoTags: []string{tag}}}
			c.AssertSupplyChain().HasCryptographicSignature()
			if len(c.Failures) != 1 {
				t.Errorf("Expected tag %q to remain unverified, got failures: %v", tag, c.Failures)
			}
			if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
				t.Errorf("tag %q outcome = %s, want %s", tag, got, spec.OutcomeUnverified)
			}
		}
	})

	t.Run("Passes only after configured verifier accepts trusted image", func(t *testing.T) {
		immutableImage := "app@sha256:" + strings.Repeat("a", 64)
		c := &conunit.Container{Image: "app:latest", ImmutableImageRef: immutableImage}
		called := false
		config := conunit.SignatureVerificationConfig{
			TrustPolicy: conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"},
			Verifier: func(ctx context.Context, image string, policy conunit.SignatureTrustPolicy) error {
				called = ctx != nil && image == immutableImage && policy.KeyPath == "/keys/cosign.pub"
				return nil
			},
		}
		c.AssertSupplyChain().HasCryptographicSignature(config)
		if !called || len(c.Failures) != 0 {
			t.Errorf("Expected configured signature verification to pass (called=%t, failures=%v)", called, c.Failures)
		}
	})

	t.Run("Rejects invalid trust policy and verifier errors", func(t *testing.T) {
		immutableImage := "app@sha256:" + strings.Repeat("b", 64)
		c := &conunit.Container{Image: "app:latest", ImmutableImageRef: immutableImage}
		called := false
		c.AssertSupplyChain().HasCryptographicSignature(conunit.SignatureVerificationConfig{
			TrustPolicy: conunit.SignatureTrustPolicy{CertificateIdentity: "builder@example.test"},
			Verifier: func(context.Context, string, conunit.SignatureTrustPolicy) error {
				called = true
				return nil
			},
		})
		if called || len(c.Failures) != 1 {
			t.Errorf("Expected invalid trust policy to fail before verification (called=%t, failures=%v)", called, c.Failures)
		}
		if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
			t.Fatalf("invalid-policy outcome = %s, want %s", got, spec.OutcomeUnverified)
		}

		c.AssertSupplyChain().HasCryptographicSignature(conunit.SignatureVerificationConfig{
			TrustPolicy: conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"},
			Verifier: func(context.Context, string, conunit.SignatureTrustPolicy) error {
				return errors.New("signature mismatch")
			},
		})
		if len(c.Failures) != 2 {
			t.Errorf("Expected verifier rejection to record a failure, got %v", c.Failures)
		}
		if got := c.Results[1].EffectiveOutcome(); got != spec.OutcomeFail {
			t.Fatalf("rejected-signature outcome = %s, want %s", got, spec.OutcomeFail)
		}
	})

	t.Run("Treats an unavailable verifier as unverified", func(t *testing.T) {
		c := &conunit.Container{
			ImmutableImageRef: "app@sha256:" + strings.Repeat("c", 64),
		}
		c.AssertSupplyChain().HasCryptographicSignature(conunit.SignatureVerificationConfig{
			TrustPolicy: conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"},
			Verifier: func(context.Context, string, conunit.SignatureTrustPolicy) error {
				return &conunit.SignatureVerificationUnavailableError{Err: errors.New("cosign not installed")}
			},
		})
		if got := c.Results[0].EffectiveOutcome(); got != spec.OutcomeUnverified {
			t.Fatalf("unavailable-verifier outcome = %s, want %s", got, spec.OutcomeUnverified)
		}
	})
}

func TestFluentAssertionsShortcuts(t *testing.T) {
	c := &conunit.Container{
		Inspect: &engine.ImageInspect{
			Config: engine.ImageConfig{
				User: "10001",
				Cmd:  []string{"node", "app.js"},
			},
		},
		OCIIndex: &oci.FilesystemIndex{
			Paths:              make(map[string]bool),
			SuidMap:            make(map[string]int64),
			WorldWritableFiles: make(map[string]int64),
			PrivateKeyFiles:    make(map[string]string),
		},
	}

	c.Should().
		NotRunAsRoot().
		HaveEntrypoint().
		HaveNoSuidBinaries().
		HaveNoWorldWritableFiles().
		HaveNoPrivateKeys().
		HaveNoShells().
		HaveNoPackageManagers().
		HaveNoTestHarnesses()

	c.Must().
		NotRunAsRoot().
		HaveEntrypoint()

	if len(c.Failures) != 0 {
		t.Errorf("Expected all clean fluent shortcuts to pass, got failures: %v", c.Failures)
	}
}

func TestContractAssertionsUnitAndAntipatterns(t *testing.T) {
	// 1. When Engine is nil, contract assertions should safely record failure without panic
	cNil := &conunit.Container{Engine: nil}
	cNil.AssertContract().ReadOnlyRootfsCompatible()
	cNil.AssertContract().DropAllCapabilitiesCompatible()
	cNil.AssertContract().HandlesSigtermGracefully(5 * time.Second)
	cNil.AssertContract().ComplyWithNoNewPrivileges()
	cNil.AssertContract().ComplyWithArbitraryNonRootUID(10001)
	cNil.AssertContract().ComplyWithResourceLimits("256m", 100)
	cNil.AssertContract().ComplyWithKubernetesPSS()
	cNil.AssertContract().ProbeHTTP(8080, "/", 200, 5*time.Second)

	if len(cNil.Failures) != 8 {
		t.Errorf("Expected 8 failures recorded for nil engine, got %d", len(cNil.Failures))
	}
}
