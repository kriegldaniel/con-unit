package spec

import "time"

// SchemaVersion identifies the layout of the study envelope written by
// `con-unit eval`. Bump it on any breaking change.
const SchemaVersion = "2"

// Image record statuses. Every attempted image gets exactly one record with
// exactly one of these statuses. Only StatusCompleted records enter
// prevalence statistics; all others are reported in the attrition flow.
const (
	StatusCompleted      = "COMPLETED"
	StatusTimeout        = "TIMEOUT"
	StatusUnavailable    = "UNAVAILABLE"     // image or manifest not found at the source
	StatusRateLimited    = "RATE_LIMITED"    // registry throttled the request (HTTP 429)
	StatusIndexLimit     = "INDEX_LIMIT"     // filesystem index exceeded the configured entry cap
	StatusExecutionError = "EXECUTION_ERROR" // any other infrastructure or tool failure
	StatusExcluded       = "EXCLUDED"        // excluded by documented protocol rule before execution
)

// Image sources recorded in SuiteResult.ImageSource.
const (
	SourceLocalStore = "local-store"
	SourceRegistry   = "registry"
	SourceTarball    = "tarball"
)

// Reason is a machine-readable cause attached to results and image records.
type Reason string

const (
	ReasonNone Reason = ""

	// Tier 3 probe reasons.
	ReasonBaselineFailed Reason = "BASELINE_FAILED" // baseline run (defensive flags only) failed or did not start
	ReasonNotObservable  Reason = "NOT_OBSERVABLE"  // baseline exited 0 early, no long-running process to observe
	ReasonProbeTimeout   Reason = "PROBE_TIMEOUT"   // engine did not reach an observable state in time
	ReasonProbeError     Reason = "PROBE_ERROR"     // engine invocation failed

	// Evidence reasons shared by all tiers.
	ReasonEvidenceIncomplete Reason = "EVIDENCE_INCOMPLETE" // required evidence missing, truncated or unparsable
	ReasonNoTrustPolicy      Reason = "NO_TRUST_POLICY"     // signature verification not configured
	ReasonToolUnavailable    Reason = "TOOL_UNAVAILABLE"    // an external tool (syft, cosign) is not installed
	ReasonFileMissing        Reason = "FILE_MISSING"        // a required file is absent from the final image

	// Image-level reasons (SuiteResult.Reason).
	ReasonRegistryThrottled Reason = "REGISTRY_THROTTLED"
	ReasonManifestNotFound  Reason = "MANIFEST_NOT_FOUND"
	ReasonIdentityMismatch  Reason = "IDENTITY_MISMATCH"
	ReasonPlatformMismatch  Reason = "PLATFORM_MISMATCH"
	ReasonDeadlineExceeded  Reason = "DEADLINE_EXCEEDED"
	ReasonIndexTooLarge     Reason = "INDEX_TOO_LARGE"
)

// Evidence records the observations behind a result. All fields are optional.
type Evidence struct {
	BaselineState     string   `json:"baseline_state,omitempty"` // running | exited0 | exited_nonzero | start_failed
	BaselineExitCode  *int     `json:"baseline_exit_code,omitempty"`
	TreatmentState    string   `json:"treatment_state,omitempty"`
	TreatmentExitCode *int     `json:"treatment_exit_code,omitempty"`
	WindowMillis      int64    `json:"window_ms,omitempty"`
	LogTail           string   `json:"log_tail,omitempty"`
	Paths             []string `json:"paths,omitempty"`                   // sorted finding paths
	FixtureCandidates []string `json:"fixture_candidate_paths,omitempty"` // sorted, counted separately from Paths
}

// MappingType states how closely a check corresponds to a standard control.
type MappingType string

const (
	MappingExact       MappingType = "exact"
	MappingApproximate MappingType = "approximate"
	MappingCustom      MappingType = "custom"
)

// RuleScope states what kind of property a check observes.
type RuleScope string

const (
	ScopeImageContent        RuleScope = "image_content"
	ScopeRuntimeCompat       RuleScope = "runtime_compatibility"
	ScopeMetadataDeclaration RuleScope = "metadata_declaration"
)

// RuleMeta documents how a check relates to a standard. Paper tables derive
// their "standard" column from this, never from hard-coded strings.
type RuleMeta struct {
	Standard        string      `json:"standard,omitempty"`         // for example "CIS Docker Benchmark"
	StandardVersion string      `json:"standard_version,omitempty"` // for example "1.8.0"
	ControlID       string      `json:"control_id,omitempty"`       // for example "4.8"
	ControlTitle    string      `json:"control_title,omitempty"`
	Mapping         MappingType `json:"mapping,omitempty"`
	Scope           RuleScope   `json:"scope,omitempty"`
}

// RunMetadata describes the environment and configuration of one evaluation
// run. It is written once at the top of the study envelope and is also used
// by the RQ3 benchmark, so both artifacts describe their host the same way.
type RunMetadata struct {
	// Tool identity.
	ConUnitVersion string `json:"conunit_version"`
	Commit         string `json:"commit,omitempty"`
	CommitDirty    bool   `json:"commit_dirty,omitempty"`
	GoVersion      string `json:"go_version,omitempty"`
	Tainted        bool   `json:"tainted,omitempty"` // dirty tree or --allow-dirty bundle

	// Experiment configuration.
	DatasetPath   string   `json:"dataset_path,omitempty"`
	DatasetSHA256 string   `json:"dataset_sha256,omitempty"`
	Pack          string   `json:"pack,omitempty"`
	PackID        string   `json:"pack_id,omitempty"`
	Platform      string   `json:"platform,omitempty"` // requested platform, for example linux/amd64
	ImageSource   string   `json:"image_source_policy,omitempty"`
	ProbeWindowMs int64    `json:"probe_window_ms,omitempty"`
	Flags         []string `json:"flags,omitempty"`

	// Container engine.
	EngineName      string   `json:"engine_name,omitempty"`
	EngineVersion   string   `json:"engine_version,omitempty"`
	Rootless        *bool    `json:"rootless,omitempty"`
	CgroupVersion   string   `json:"cgroup_version,omitempty"`
	StorageDriver   string   `json:"storage_driver,omitempty"`
	OCIRuntime      string   `json:"oci_runtime,omitempty"`
	SecurityOptions []string `json:"security_options,omitempty"`
	RegistryRemap   string   `json:"registry_remap,omitempty"` // for example docker.io/library -> public.ecr.aws/docker/library

	// Host.
	HostOS         string `json:"host_os,omitempty"`
	HostArch       string `json:"host_arch,omitempty"`
	LinuxKernel    string `json:"linux_kernel,omitempty"` // kernel the containers run on (the VM kernel on macOS)
	CPUModel       string `json:"cpu_model,omitempty"`
	VCPUs          int    `json:"vcpus,omitempty"`
	MemoryBytes    int64  `json:"memory_bytes,omitempty"`
	Virtualization string `json:"virtualization,omitempty"` // for example aws-nitro-kvm, apple-virtualization, bare-metal, unknown
	ExecutionMode  string `json:"execution_mode,omitempty"` // derived from detected facts, never assumed
	CloudProvider  string `json:"cloud_provider,omitempty"`
	InstanceType   string `json:"instance_type,omitempty"`
	AMIID          string `json:"ami_id,omitempty"`
	Region         string `json:"region,omitempty"`
	Zone           string `json:"zone,omitempty"`

	// External tools, name to version, or "absent".
	Tools map[string]string `json:"tools,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// Study is the top-level document written to empirical_study.json.
type Study struct {
	SchemaVersion string         `json:"schema_version"`
	Run           RunMetadata    `json:"run"`
	Images        []*SuiteResult `json:"images"`
}

// Exit codes of `con-unit eval`. The `test` command keeps its CI-gate
// semantics (non-zero when findings exist) unless noted in docs/CONTRACT.md.
const (
	ExitOK         = 0 // every attempted image produced a COMPLETED record
	ExitFindings   = 1 // `test` only, or `eval --fail-on-findings` with findings present
	ExitUsage      = 2 // invalid flags or configuration
	ExitIncomplete = 3 // at least one image ended in a non-COMPLETED status, or output could not be written
)
