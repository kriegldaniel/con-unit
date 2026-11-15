package conunit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/acquire"
	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/reporter"
	"github.com/con-unit/con-unit/pkg/spec"
)

// Suite represents a programmatic container test suite in Go
type Suite struct {
	Name                  string
	Images                []string
	StoragePolicy         StoragePolicy
	SignatureVerification *SignatureVerificationConfig
	beforeAll             []BeforeAllFunc
	beforeEach            []BeforeEachFunc
	afterEach             []AfterEachFunc
	afterAll              []AfterAllFunc
	tests                 []TestCaseDefinition
	packs                 []RulePack
}

// NewSuite initializes and configures a container testing suite
func NewSuite(name string, initFn func(s *Suite)) *Suite {
	s := &Suite{
		Name:          name,
		StoragePolicy: StoragePreserve, // Default to preserve, easily switchable to StorageEphemeral
	}
	initFn(s)
	return s
}

// ForImages sets the target image matrix to test against
func (s *Suite) ForImages(images ...string) *Suite {
	s.Images = append(s.Images, images...)
	return s
}

// WithStoragePolicy sets host storage and cleanup behavior
func (s *Suite) WithStoragePolicy(policy StoragePolicy) *Suite {
	s.StoragePolicy = policy
	return s
}

// WithSignatureVerification configures the verifier and trust policy used by
// signature assertions in this suite.
func (s *Suite) WithSignatureVerification(config SignatureVerificationConfig) *Suite {
	s.SignatureVerification = &config
	return s
}

// BeforeAll registers a hook executed once before any tests start
func (s *Suite) BeforeAll(fn BeforeAllFunc) *Suite {
	s.beforeAll = append(s.beforeAll, fn)
	return s
}

// BeforeEach registers a hook executed prior to each test case
func (s *Suite) BeforeEach(fn BeforeEachFunc) *Suite {
	s.beforeEach = append(s.beforeEach, fn)
	return s
}

// AfterEach registers a hook executed immediately after each test case
func (s *Suite) AfterEach(fn AfterEachFunc) *Suite {
	s.afterEach = append(s.afterEach, fn)
	return s
}

// AfterAll registers a hook executed once after all tests complete
func (s *Suite) AfterAll(fn AfterAllFunc) *Suite {
	s.afterAll = append(s.afterAll, fn)
	return s
}

// Test registers an individual container test assertion
func (s *Suite) Test(id, name string, fn TestFunc) *Suite {
	s.tests = append(s.tests, TestCaseDefinition{
		ID:   id,
		Name: name,
		Fn:   fn,
	})
	return s
}

// Include attaches a pre-packaged compliance RulePack to the suite
func (s *Suite) Include(pack RulePack) *Suite {
	s.packs = append(s.packs, pack)
	return s
}
func (s *Suite) hasAssertions() bool {
	return len(s.tests) > 0 || len(s.packs) > 0
}

// Run executes the suite using Go's testing.T runner
func (s *Suite) Run(t *testing.T) {
	if len(s.Images) == 0 {
		t.Fatal("[FAILURE] No target images configured. Use s.ForImages(...)")
	}
	if !s.hasAssertions() {
		t.Fatalf("[UNVERIFIED] Suite %q has no registered tests or rule packs", s.Name)
	}

	eng, err := engine.DetectEngine("auto")
	if err != nil {
		t.Fatalf("[FAILURE] OCI engine error: %v", err)
	}

	tracker := NewResourceTracker(eng, s.StoragePolicy)
	defer tracker.Cleanup()

	// If isolated temp root policy is selected, configure engine with ephemeral graphroot
	if s.StoragePolicy == StorageIsolatedTempRoot {
		tempRoot, err := tracker.CreateTempGraphRoot()
		if err != nil {
			t.Fatalf("[FAILURE] Failed creating temp graphroot: %v", err)
		}
		eng.ExtraArgs = append(eng.ExtraArgs, "--root", tempRoot)
	}

	ctx := context.Background()
	suiteCtx := &SuiteContext{
		Context:       ctx,
		SuiteName:     s.Name,
		Images:        s.Images,
		StoragePolicy: s.StoragePolicy,
	}

	// 1. Run BeforeAll hooks
	for _, fn := range s.beforeAll {
		fn(suiteCtx)
	}
	defer func() {
		// 4. Run AfterAll hooks
		for _, fn := range s.afterAll {
			fn(suiteCtx)
		}
	}()

	totalFailed := 0
	totalPassed := 0
	totalUnverified := 0
	var suiteResults []spec.TestResult
	recordResults := func(subT *testing.T, container *Container, fallbackID, fallbackName string) {
		if len(container.Results) == 0 {
			container.RecordUnverified(fallbackID, fallbackName, spec.TierSpec, 0, "Test completed without recording an assertion result", "Record at least one explicit assertion result", "")
		}
		for _, result := range container.Results {
			suiteResults = append(suiteResults, result)
			switch result.EffectiveOutcome() {
			case spec.OutcomePass:
				totalPassed++
			case spec.OutcomeUnverified:
				totalUnverified++
				subT.Errorf("[UNVERIFIED] [%s] %s (Image: %s): %s", result.TestID, result.TestName, container.Image, result.Message)
			default:
				totalFailed++
				subT.Errorf("[FAILURE] [%s] %s (Image: %s): %s", result.TestID, result.TestName, container.Image, result.Message)
			}
		}
	}

	for _, image := range s.Images {
		t.Run(fmt.Sprintf("Image=%s", image), func(t *testing.T) {
			imgStart := time.Now()

			// Make the image available, read it from the engine store and verify
			// its identity. The acquisition logic is shared with the evaluation runner.
			acquired, err := acquire.Acquire(ctx, eng, image, acquire.Options{Policy: acquire.PolicyAuto})
			if acquired != nil && acquired.Pulled {
				tracker.RegisterAcquiredImage(image)
			}
			if err != nil {
				t.Fatalf("[FAILURE] Failed acquiring image %s: %v", image, err)
				return
			}
			defer acquired.Close()
			ociIndex, err := acquired.Reader.StreamAndIndexFilesystem()
			if err != nil {
				t.Fatalf("[FAILURE] Failed indexing OCI filesystem for %s: %v", image, err)
				return
			}
			// Tier 3 baselines are computed once per image and shared by every
			// pack and test that runs against it.
			baseline := &BaselineCache{}
			newContainer := func() *Container {
				return &Container{
					Context:               ctx,
					Image:                 acquired.EngineImageID,
					ImmutableImageRef:     acquired.ImmutableRef,
					ImageDigest:           acquired.RegistryDigest,
					ConfigDigest:          acquired.ConfigDigest,
					Platform:              acquired.Platform,
					SignatureVerification: s.SignatureVerification,
					Inspect:               acquired.Inspect,
					Engine:                eng,
					OCIIndex:              ociIndex,
					Baseline:              baseline,
				}
			}

			// Run custom registered tests
			for _, tc := range s.tests {
				t.Run(fmt.Sprintf("%s_%s", tc.ID, tc.Name), func(subT *testing.T) {
					testCtx := &TestContext{
						Context:   ctx,
						ImageName: image,
						TestID:    tc.ID,
						TestName:  tc.Name,
					}

					for _, bEach := range s.beforeEach {
						bEach(testCtx)
					}
					defer func() {
						for _, aEach := range s.afterEach {
							aEach(testCtx)
						}
					}()

					container := newContainer()

					tc.Fn(container)
					recordResults(subT, container, tc.ID, tc.Name)
				})
			}

			// Run pre-packaged compliance RulePacks
			for _, pack := range s.packs {
				t.Run(fmt.Sprintf("Pack_%s", pack.ID()), func(subT *testing.T) {
					container := newContainer()

					pack.Apply(container)
					recordResults(subT, container, pack.ID(), pack.Name())
				})
			}

			t.Logf("[INFO] Image %s test run completed in %v", image, time.Since(imgStart).Round(time.Millisecond))
		})
	}

	// Generate JUnit XML for native CI reporting
	xmlReportPath := filepath.Join("reports", "go-test-junit.xml")
	if _, err := os.Stat(".."); err == nil {
		if _, err := os.Stat("../reports"); err == nil {
			xmlReportPath = filepath.Join("..", "reports", "go-test-junit.xml")
		}
	}
	_ = reporter.WriteJUnitXML(xmlReportPath, &spec.SuiteResult{
		ImageName:  strings.Join(s.Images, ","),
		SuiteName:  s.Name,
		Total:      totalPassed + totalFailed + totalUnverified,
		Passed:     totalPassed,
		Failed:     totalFailed,
		Unverified: totalUnverified,
		Results:    suiteResults,
	})
}
