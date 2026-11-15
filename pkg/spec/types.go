package spec

import "time"

// Tier classifies the level of inspection in the container unit testing pyramid
type Tier int

const (
	TierSpec        Tier = 1 // Specification & Manifest Invariants
	TierFilesystem  Tier = 2 // Filesystem State & Artifact Hygiene
	TierContract    Tier = 3 // Dynamic Execution & Behavioral Contracts
	TierSupplyChain Tier = 4 // Supply Chain & Dependency Integrity
)

// Outcome records whether an assertion passed, found a policy violation, or
// could not be verified from complete evidence.
type Outcome string

const (
	OutcomePass       Outcome = "PASS"
	OutcomeFail       Outcome = "FAIL"
	OutcomeUnverified Outcome = "UNVERIFIED"
)

func (t Tier) String() string {
	switch t {
	case TierSpec:
		return "Tier 1: Specification"
	case TierFilesystem:
		return "Tier 2: Filesystem Hygiene"
	case TierContract:
		return "Tier 3: Execution Contract"
	case TierSupplyChain:
		return "Tier 4: Supply Chain"
	default:
		return "Unknown Tier"
	}
}

// TestSuite represents an entire collection of container test cases
type TestSuite struct {
	Name        string     `yaml:"name" json:"name"`
	Description string     `yaml:"description,omitempty" json:"description,omitempty"`
	Target      string     `yaml:"target,omitempty" json:"target,omitempty"` // e.g. "production", "development"
	Tests       []TestCase `yaml:"tests" json:"tests"`
}

// TestCase represents an individual unit test assertion against a container
type TestCase struct {
	ID          string    `yaml:"id" json:"id"`
	Name        string    `yaml:"name" json:"name"`
	Tier        Tier      `yaml:"tier" json:"tier"`
	Description string    `yaml:"description,omitempty" json:"description,omitempty"`
	Assertion   Assertion `yaml:"assertion" json:"assertion"`
}

// Assertion defines the rule and criteria to verify
type Assertion struct {
	Type string `yaml:"type" json:"type"`

	// Tier 1: Spec assertions
	DisallowedUsers           []string `yaml:"disallowed_users,omitempty" json:"disallowed_users,omitempty"`
	RequireUser               string   `yaml:"require_user,omitempty" json:"require_user,omitempty"`
	RequireEntrypoint         bool     `yaml:"require_entrypoint,omitempty" json:"require_entrypoint,omitempty"`
	RequireNonPrivilegedPorts bool     `yaml:"require_non_privileged_ports,omitempty" json:"require_non_privileged_ports,omitempty"`
	DisallowDebugPorts        bool     `yaml:"disallow_debug_ports,omitempty" json:"disallow_debug_ports,omitempty"`
	DisallowedPorts           []int    `yaml:"disallowed_ports,omitempty" json:"disallowed_ports,omitempty"`
	DisallowedEnvKeys         []string `yaml:"disallowed_env_keys,omitempty" json:"disallowed_env_keys,omitempty"`
	MaxSizeMB                 int64    `yaml:"max_size_mb,omitempty" json:"max_size_mb,omitempty"`

	// Tier 2: Filesystem & Hygiene assertions
	DisallowedPaths      []string `yaml:"disallowed_paths,omitempty" json:"disallowed_paths,omitempty"`
	DisallowedBinaries   []string `yaml:"disallowed_binaries,omitempty" json:"disallowed_binaries,omitempty"`
	NoSuidBinaries       bool     `yaml:"no_suid_binaries,omitempty" json:"no_suid_binaries,omitempty"`
	NoWorldWritableFiles bool     `yaml:"no_world_writable_files,omitempty" json:"no_world_writable_files,omitempty"`
	NoPrivateKeys        bool     `yaml:"no_private_keys,omitempty" json:"no_private_keys,omitempty"`
	NoInteractiveShells  bool     `yaml:"no_interactive_shells,omitempty" json:"no_interactive_shells,omitempty"`
	NoPackageManagers    bool     `yaml:"no_package_managers,omitempty" json:"no_package_managers,omitempty"`

	// Tier 3: Dynamic Execution Contracts
	ReadOnlyRootfs        bool     `yaml:"read_only_rootfs,omitempty" json:"read_only_rootfs,omitempty"`
	DropAllCapabilities   bool     `yaml:"drop_all_capabilities,omitempty" json:"drop_all_capabilities,omitempty"`
	NoNewPrivileges       bool     `yaml:"no_new_privileges,omitempty" json:"no_new_privileges,omitempty"`
	ArbitraryNonRootUID   int      `yaml:"arbitrary_non_root_uid,omitempty" json:"arbitrary_non_root_uid,omitempty"`
	HandlesSigtermTimeout int      `yaml:"handles_sigterm_timeout_sec,omitempty" json:"handles_sigterm_timeout_sec,omitempty"`
	ProbeHTTPPort         int      `yaml:"probe_http_port,omitempty" json:"probe_http_port,omitempty"`
	ProbeHTTPPath         string   `yaml:"probe_http_path,omitempty" json:"probe_http_path,omitempty"`
	ProbeHTTPStatus       int      `yaml:"probe_http_status,omitempty" json:"probe_http_status,omitempty"`
	ProbeHTTPTimeout      int      `yaml:"probe_http_timeout_sec,omitempty" json:"probe_http_timeout_sec,omitempty"`
	Command               []string `yaml:"command,omitempty" json:"command,omitempty"`
	ExpectedExitCode      int      `yaml:"expected_exit_code,omitempty" json:"expected_exit_code,omitempty"`
	OutputContains        string   `yaml:"output_contains,omitempty" json:"output_contains,omitempty"`
	OutputNotContains     string   `yaml:"output_not_contains,omitempty" json:"output_not_contains,omitempty"`

	// Tier 4: Supply Chain
	DisallowedPackages []string `yaml:"disallowed_packages,omitempty" json:"disallowed_packages,omitempty"`
}

// TestResult records the execution outcome of a TestCase
type TestResult struct {
	TestID       string        `json:"test_id"`
	TestName     string        `json:"test_name"`
	Tier         Tier          `json:"tier"`
	Outcome      Outcome       `json:"outcome"`
	Passed       bool          `json:"passed"`
	ImageDigest  string        `json:"image_digest,omitempty"`
	ConfigDigest string        `json:"config_digest,omitempty"`
	Platform     string        `json:"platform,omitempty"`
	Duration     time.Duration `json:"duration"`
	Message      string        `json:"message,omitempty"`
	Details      string        `json:"details,omitempty"`
	RuleType     string        `json:"rule_type"`
	Explanation  string        `json:"explanation,omitempty"`
	Remediation  string        `json:"remediation,omitempty"`
	Reference    string        `json:"reference,omitempty"`

	// Reason is a machine-readable cause for UNVERIFIED outcomes (and for
	// FAIL outcomes that need qualification). Empty for plain PASS and FAIL.
	Reason Reason `json:"reason,omitempty"`
	// Hint is a non-authoritative, keyword-derived suggestion. It must never
	// be used as a root-cause claim or counted in prevalence tables.
	Hint string `json:"hint,omitempty"`
	// Evidence carries the observations that justify the outcome.
	Evidence *Evidence `json:"evidence,omitempty"`
	// Rule describes the standard mapping of the check that produced this result.
	Rule *RuleMeta `json:"rule,omitempty"`
}

// EffectiveOutcome returns the explicit outcome, falling back to the legacy
// Passed field for results created before outcomes were introduced.
func (r TestResult) EffectiveOutcome() Outcome {
	switch r.Outcome {
	case OutcomePass, OutcomeFail, OutcomeUnverified:
		return r.Outcome
	default:
		if r.Passed {
			return OutcomePass
		}
		return OutcomeFail
	}
}

// SuiteResult records all test results for a given target container image
type SuiteResult struct {
	ImageName    string `json:"image_name"`
	ImageDigest  string `json:"image_digest"`
	ConfigDigest string `json:"config_digest"`
	Platform     string `json:"platform"`
	SuiteName    string `json:"suite_name"`
	Status       string `json:"status,omitempty"` // one of the Status* constants in contract.go
	Reason       Reason `json:"reason,omitempty"` // machine-readable cause for non-COMPLETED statuses
	ErrorMessage string `json:"error_message,omitempty"`
	// RequestedRef is the reference exactly as given on the command line or
	// in the dataset (for example a digest-pinned name).
	RequestedRef string `json:"requested_ref,omitempty"`
	// ImageSource records where layer content was read from: SourceLocalStore,
	// SourceRegistry or SourceTarball.
	ImageSource string            `json:"image_source,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Duration    time.Duration     `json:"duration"`
	Total       int               `json:"total"`
	Passed      int               `json:"passed"`
	Failed      int               `json:"failed"`
	Unverified  int               `json:"unverified"`
	Phases      PhaseBreakdown    `json:"phases,omitempty"`
	Resources   ResourceTelemetry `json:"resources,omitempty"`
	Results     []TestResult      `json:"results"`
}

// PhaseBreakdown records execution durations for each distinct evaluation stage
type PhaseBreakdown struct {
	PullDuration    time.Duration `json:"pull_duration"`    // Engine image pull/ingress check
	InspectDuration time.Duration `json:"inspect_duration"` // Engine image inspection
	ResolveDuration time.Duration `json:"resolve_duration"` // OCI manifest resolution and identity check
	StreamDuration  time.Duration `json:"stream_duration"`  // In-memory layer streaming and tar indexing
	Tier1Duration   time.Duration `json:"tier1_duration"`   // Spec assertions (metadata invariants)
	Tier2Duration   time.Duration `json:"tier2_duration"`   // Filesystem assertions (tar scan)
	Tier3Duration   time.Duration `json:"tier3_duration"`   // Dynamic execution contracts (container probes)
	Tier4Duration   time.Duration `json:"tier4_duration"`   // Supply chain assertions
	// ProbeWindow is the Tier 3 observation window W. Tier 3 latency is
	// bounded below by W by design and is not a performance claim.
	ProbeWindow time.Duration `json:"probe_window,omitempty"`
}

// ResourceTelemetry records memory and host resource metrics during image evaluation
type ResourceTelemetry struct {
	AllocMB           float64 `json:"alloc_mb"`           // In-use heap memory in megabytes
	TotalAllocMB      float64 `json:"total_alloc_mb"`     // Cumulative heap memory allocated in megabytes
	SysMB             float64 `json:"sys_mb"`             // System memory obtained by Go runtime in megabytes
	PeakRSSMB         float64 `json:"peak_rss_mb"`        // Peak resident set size of the process in megabytes
	NumGC             uint32  `json:"num_gc"`             // Completed GC cycles during evaluation
	LayerCount        int     `json:"layer_count"`        // Number of layers in image
	UncompressedBytes int64   `json:"uncompressed_bytes"` // Uncompressed filesystem bytes scanned

	// Fields below are part of the frozen contract. They are filled by the
	// runner and describe the ConUnit process only, never the container
	// engine or the probe containers.
	CompressedBytes int64   `json:"compressed_bytes,omitempty"`  // Sum of compressed layer blob sizes
	LiveHeapMB      float64 `json:"live_heap_mb,omitempty"`      // Heap in use after a forced GC, outside phase timers
	SelfCPUSeconds  float64 `json:"self_cpu_seconds,omitempty"`  // User plus system CPU time of this process for the image
	ChildCPUSeconds float64 `json:"child_cpu_seconds,omitempty"` // CPU time of child processes (engine CLI, Syft) for the image
	IndexedEntries  int     `json:"indexed_entries,omitempty"`   // Number of filesystem entries held in the merged index
}
