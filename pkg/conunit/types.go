package conunit

import (
	"context"

	"github.com/con-unit/con-unit/pkg/spec"
)

// StoragePolicy determines how images and container artifacts are handled on the host
type StoragePolicy int

const (
	// StoragePreserve retains pulled images and cache in local storage (fastest for repetitive local tests)
	StoragePreserve StoragePolicy = iota

	// StorageEphemeral purges pulled images from host storage immediately after tests complete
	StorageEphemeral

	// StorageIsolatedTempRoot executes using a temporary isolated graphroot (/tmp) for zero host contamination
	StorageIsolatedTempRoot
)

func (s StoragePolicy) String() string {
	switch s {
	case StoragePreserve:
		return "StoragePreserve"
	case StorageEphemeral:
		return "StorageEphemeral"
	case StorageIsolatedTempRoot:
		return "StorageIsolatedTempRoot"
	default:
		return "UnknownStoragePolicy"
	}
}

// SuiteContext provides context and utilities during suite-level lifecycle hooks
type SuiteContext struct {
	Context       context.Context
	SuiteName     string
	Images        []string
	StoragePolicy StoragePolicy
	Logs          []string
}

// Log records an informational message into the suite logs
func (sc *SuiteContext) Log(msg string) {
	sc.Logs = append(sc.Logs, msg)
}

// TestContext provides context during individual test execution
type TestContext struct {
	Context   context.Context
	ImageName string
	TestID    string
	TestName  string
}

// Lifecycle function types
type BeforeAllFunc func(ctx *SuiteContext)
type BeforeEachFunc func(ctx *TestContext)
type AfterEachFunc func(ctx *TestContext)
type AfterAllFunc func(ctx *SuiteContext)

// TestFunc is the signature for an executable container test definition
type TestFunc func(c *Container)

// TestCaseDefinition represents a registered test inside a Suite
type TestCaseDefinition struct {
	ID          string
	Name        string
	Description string
	Tier        spec.Tier
	Fn          TestFunc
}
