package tests

import (
	"os"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
)

func TestContainerComplianceSuite(t *testing.T) {
	if os.Getenv("CONUNIT_INTEGRATION") != "1" {
		t.Skip("set CONUNIT_INTEGRATION=1 to run container-engine integration tests")
	}
	suite := conunit.NewSuite("Production Security & Hygiene Suite", func(s *conunit.Suite) {

		// 1. Target container matrix
		s.ForImages("alpine:latest")

		// 2. Storage strategy: Clean host storage after tests
		s.WithStoragePolicy(conunit.StoragePreserve)

		// 3. Lifecycle Hooks
		s.BeforeAll(func(ctx *conunit.SuiteContext) {
			ctx.Log("[INFO] Starting container test suite for target images")
		})

		s.BeforeEach(func(ctx *conunit.TestContext) {
			// Runs before each individual test
		})

		s.AfterAll(func(ctx *conunit.SuiteContext) {
			// Teardown logic
		})

		// 4. Custom Unit Tests using Fluent English-like DSL
		s.Test("CUSTOM-01", "Application must have deterministic entrypoint and clean env", func(c *conunit.Container) {
			c.Should().
				HaveEntrypoint().
				NotContainPaths("/.git", "/root/.ssh", "/.env")
		})

		s.Test("CUSTOM-02", "Container must comply with dynamic execution contracts", func(c *conunit.Container) {
			c.Must().
				ComplyWithReadOnlyRootfs().
				ComplyWithDropAllCapabilities().
				TerminateOnSigtermWithin(5 * time.Second)
		})

		// 5. Pre-packaged Compliance Packs with fine-grained customization
		// (e.g. Include ProductionHygiene, but exempt SPEC-01 and FS-01 since alpine base runs as root and keeps apk cache)
		s.Include(
			conunit.ProductionHygiene().
				Except("SPEC-01", "FS-01").
				AllowBinaries("sh"),
		)
	})

	// Executes natively with 'go test', outputs logs, and writes reports/go-test-junit.xml
	suite.Run(t)
}
