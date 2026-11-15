package conunit_test

import (
	"os"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
)

func TestSuiteExecutionAndLifecycle(t *testing.T) {
	if os.Getenv("CONUNIT_INTEGRATION") != "1" {
		t.Skip("set CONUNIT_INTEGRATION=1 to run container-engine integration tests")
	}
	_, err := engine.DetectEngine("auto")
	if err != nil {
		t.Skip("Skipping TestSuiteExecutionAndLifecycle: container engine not available")
	}

	beforeAllCalled := false
	beforeEachCalled := false
	afterEachCalled := false
	afterAllCalled := false

	suite := conunit.NewSuite("Lifecycle Verification Suite", func(s *conunit.Suite) {
		s.ForImages("alpine:latest")
		s.WithStoragePolicy(conunit.StoragePreserve)

		s.BeforeAll(func(ctx *conunit.SuiteContext) {
			beforeAllCalled = true
			ctx.Log("BeforeAll executed")
		})

		s.BeforeEach(func(ctx *conunit.TestContext) {
			beforeEachCalled = true
		})

		s.AfterEach(func(ctx *conunit.TestContext) {
			afterEachCalled = true
		})

		s.AfterAll(func(ctx *conunit.SuiteContext) {
			afterAllCalled = true
		})

		s.Test("UNIT-01", "Verifies basic container properties", func(c *conunit.Container) {
			c.Should().
				HaveEntrypoint().
				ComplyWithReadOnlyRootfs().
				TerminateOnSigtermWithin(3 * time.Second)
		})
	})

	suite.Run(t)

	if !beforeAllCalled {
		t.Error("Expected BeforeAll hook to be executed")
	}
	if !beforeEachCalled {
		t.Error("Expected BeforeEach hook to be executed")
	}
	if !afterEachCalled {
		t.Error("Expected AfterEach hook to be executed")
	}
	if !afterAllCalled {
		t.Error("Expected AfterAll hook to be executed")
	}
}
