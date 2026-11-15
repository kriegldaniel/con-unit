package conunit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// SignatureTrustPolicy identifies the trust anchor or keyless identity that an
// image signature verifier must enforce.
type SignatureTrustPolicy struct {
	KeyPath             string
	CertificateIdentity string
	CertificateIssuer   string
}

// Validate verifies that the trust policy contains one supported trust mode.
func (p SignatureTrustPolicy) Validate() error {
	hasKey := strings.TrimSpace(p.KeyPath) != ""
	hasIdentity := strings.TrimSpace(p.CertificateIdentity) != ""
	hasIssuer := strings.TrimSpace(p.CertificateIssuer) != ""
	if hasKey && !hasIdentity && !hasIssuer {
		return nil
	}
	if !hasKey && hasIdentity && hasIssuer {
		return nil
	}
	return fmt.Errorf("configure either a key path or both certificate identity and issuer")
}

// SignatureVerifier verifies that the image has a valid signature under the
// supplied trust policy. A nil error must mean the signature was verified.
type SignatureVerifier func(context.Context, string, SignatureTrustPolicy) error

// SignatureVerificationConfig supplies both verification and trust policy.
type SignatureVerificationConfig struct {
	Verifier    SignatureVerifier
	TrustPolicy SignatureTrustPolicy
}

func isRootUser(user string) bool {
	user = strings.TrimSpace(user)
	if user == "" {
		return true
	}
	username, _, _ := strings.Cut(user, ":")
	if username == "" {
		return true
	}
	uid, err := strconv.ParseUint(username, 10, 32)
	return err == nil && uid == 0
}

// sortedPortDeclarations returns the EXPOSE declarations of the image config
// in a fixed order. The config holds them in a map, and the order of a map is
// random, which would make the message of a result, and which unrecognized
// declaration is named first, differ between runs on the same image.
func sortedPortDeclarations(declared map[string]struct{}) []string {
	keys := make([]string, 0, len(declared))
	for key := range declared {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func parseExposedPort(exposedPort string) (int, bool) {
	portText, protocol, ok := strings.Cut(exposedPort, "/")
	if !ok || (protocol != "tcp" && protocol != "udp" && protocol != "sctp") {
		return 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// AssertSpec returns fluent Tier 1 specification assertions
func (c *Container) AssertSpec() *SpecAssertions {
	return &SpecAssertions{c: c}
}

// AssertFilesystem returns fluent Tier 2 filesystem assertions
func (c *Container) AssertFilesystem() *FilesystemAssertions {
	return &FilesystemAssertions{c: c}
}

// AssertContract returns fluent Tier 3 runtime execution contract assertions
func (c *Container) AssertContract() *ContractAssertions {
	return &ContractAssertions{c: c}
}

// AssertSupplyChain returns fluent Tier 4 supply chain assertions
func (c *Container) AssertSupplyChain() *SupplyChainAssertions {
	return &SupplyChainAssertions{c: c}
}

// Should provides natural English fluent soft assertions
func (c *Container) Should() *FluentAssertions {
	return &FluentAssertions{c: c}
}

// Must provides fluent assertions that operate with same soft assertion reporting
func (c *Container) Must() *FluentAssertions {
	return &FluentAssertions{c: c}
}

// FluentAssertions wraps all tiers into an English-like fluent API
type FluentAssertions struct {
	c *Container
}

func (f *FluentAssertions) NotRunAsRoot() *FluentAssertions {
	f.c.AssertSpec().UserNotRoot()
	return f
}

func (f *FluentAssertions) HaveEntrypoint() *FluentAssertions {
	f.c.AssertSpec().RequireEntrypoint()
	return f
}

func (f *FluentAssertions) NotContainPaths(paths ...string) *FluentAssertions {
	f.c.AssertFilesystem().PathsNotExist(paths...)
	return f
}

func (f *FluentAssertions) NotContainBinaries(bins ...string) *FluentAssertions {
	f.c.AssertFilesystem().BinariesNotExist(bins...)
	return f
}

func (f *FluentAssertions) HaveNoSuidBinaries() *FluentAssertions {
	f.c.AssertFilesystem().NoSuidBinaries()
	return f
}

func (f *FluentAssertions) HaveNoWorldWritableFiles() *FluentAssertions {
	f.c.AssertFilesystem().NoWorldWritableFiles()
	return f
}

func (f *FluentAssertions) HaveNoPrivateKeys() *FluentAssertions {
	f.c.AssertFilesystem().NoPrivateKeysOrCertificates()
	return f
}

func (f *FluentAssertions) HaveNoShells() *FluentAssertions {
	f.c.AssertFilesystem().NoInteractiveShells()
	return f
}

func (f *FluentAssertions) HaveNoPackageManagers() *FluentAssertions {
	f.c.AssertFilesystem().NoPackageManagers()
	return f
}

func (f *FluentAssertions) HaveNoEmptyPasswords() *FluentAssertions {
	f.c.AssertFilesystem().NoEmptyPasswordAccounts()
	return f
}

func (f *FluentAssertions) HaveRootOwnedSystemBinaries() *FluentAssertions {
	f.c.AssertFilesystem().NoNonRootSystemBinaries()
	return f
}

func (f *FluentAssertions) ComplyWithKubernetesPSS() *FluentAssertions {
	f.c.AssertContract().ComplyWithKubernetesPSS()
	return f
}

func (f *FluentAssertions) HaveOCIProvenance(keys ...string) *FluentAssertions {
	f.c.AssertSpec().RequireOCIProvenance(keys...)
	return f
}

func (f *FluentAssertions) HaveApprovedLicenses(licenses ...string) *FluentAssertions {
	f.c.AssertSupplyChain().RequireApprovedLicenses(licenses...)
	return f
}

func (f *FluentAssertions) HaveNoTestHarnesses() *FluentAssertions {
	f.c.AssertFilesystem().NoTestHarnessLeakage()
	return f
}

func (f *FluentAssertions) ComplyWithReadOnlyRootfs() *FluentAssertions {
	f.c.AssertContract().ReadOnlyRootfsCompatible()
	return f
}

func (f *FluentAssertions) ComplyWithDropAllCapabilities() *FluentAssertions {
	f.c.AssertContract().DropAllCapabilitiesCompatible()
	return f
}

func (f *FluentAssertions) ComplyWithNoNewPrivileges() *FluentAssertions {
	f.c.AssertContract().ComplyWithNoNewPrivileges()
	return f
}

func (f *FluentAssertions) ComplyWithArbitraryNonRootUID(uid int) *FluentAssertions {
	f.c.AssertContract().ComplyWithArbitraryNonRootUID(uid)
	return f
}

func (f *FluentAssertions) NotExposePrivilegedPorts() *FluentAssertions {
	f.c.AssertSpec().RequireNonPrivilegedPorts()
	return f
}

func (f *FluentAssertions) RequireCopyOverAdd() *FluentAssertions {
	f.c.AssertSpec().RequireCopyOverAdd()
	return f
}

func (f *FluentAssertions) ComplyWithResourceLimits(memory string, pids int) *FluentAssertions {
	f.c.AssertContract().ComplyWithResourceLimits(memory, pids)
	return f
}

func (f *FluentAssertions) HaveCryptographicSignature(config ...SignatureVerificationConfig) *FluentAssertions {
	f.c.AssertSupplyChain().HasCryptographicSignature(config...)
	return f
}

func (f *FluentAssertions) TerminateOnSigtermWithin(d time.Duration) *FluentAssertions {
	f.c.AssertContract().HandlesSigtermGracefully(d)
	return f
}

func (f *FluentAssertions) NotContainPackages(pkgs ...string) *FluentAssertions {
	f.c.AssertSupplyChain().PackagesNotExist(pkgs...)
	return f
}

// ==========================================
// TIER 1: SPECIFICATION ASSERTIONS
// ==========================================
type SpecAssertions struct {
	c *Container
}

func (s *SpecAssertions) UserNotRoot() *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-01", "Non-Root Execution Identity", spec.TierSpec, start)
		return s
	}
	u := strings.TrimSpace(s.c.Inspect.Config.User)
	if isRootUser(u) {
		s.c.RecordFailure(
			"SPEC-01",
			"Non-Root Execution Identity",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Image runs as root user (configured user: '%s')", u),
			"Running as root increases blast radius of container breakouts (e.g. CVE-2019-5736) to host-level root compromise.",
			"Add 'USER 10001:10001' to your Dockerfile or container build specification",
			"https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
		)
		return s
	}
	username, _, _ := strings.Cut(u, ":")
	if _, err := strconv.ParseUint(username, 10, 32); err == nil {
		s.c.RecordPass("SPEC-01", "Non-Root Execution Identity", spec.TierSpec, time.Since(start), fmt.Sprintf("Image config selects numeric non-root UID %s", username))
		return s
	}
	if s.c.OCIIndex == nil {
		s.c.RecordUnverifiedDetail("SPEC-01", "Non-Root Execution Identity", spec.TierSpec, time.Since(start), fmt.Sprintf("Configured user %q cannot be resolved without final-image /etc/passwd evidence", username), "Provide a complete OCI filesystem index containing /etc/passwd", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return s
	}
	uid, err := s.c.OCIIndex.ResolveUserUID(u)
	if err != nil {
		s.c.RecordUnverifiedDetail("SPEC-01", "Non-Root Execution Identity", spec.TierSpec, time.Since(start), fmt.Sprintf("Configured user %q could not be verified: %v", username, err), "Ensure the final image has a valid, unambiguous /etc/passwd entry for the configured user", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return s
	}
	if uid == 0 {
		s.c.RecordFailure("SPEC-01", "Non-Root Execution Identity", spec.TierSpec, time.Since(start), fmt.Sprintf("Configured user %q resolves to UID 0", username), "Any username mapped to UID 0 runs with root identity.", "Use a user mapped to a nonzero UID", "https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)")
		return s
	}
	s.c.RecordPass("SPEC-01", "Non-Root Execution Identity", spec.TierSpec, time.Since(start), fmt.Sprintf("Configured user %q resolves to non-root UID %d", username, uid))
	return s
}

func (s *SpecAssertions) RequireEntrypoint() *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-02", "Deterministic Entrypoint or Command", spec.TierSpec, start)
		return s
	}
	ep := s.c.Inspect.Config.Entrypoint
	cmd := s.c.Inspect.Config.Cmd
	if len(ep) == 0 && len(cmd) == 0 {
		s.c.RecordFailure(
			"SPEC-02",
			"Deterministic Entrypoint or Command",
			spec.TierSpec,
			time.Since(start),
			"Neither ENTRYPOINT nor CMD is defined in image metadata",
			"Containers without an explicit entrypoint exhibit non-deterministic startup behavior in orchestrators.",
			"Define an explicit ENTRYPOINT or CMD to ensure deterministic startup behavior",
			"https://docs.docker.com/engine/reference/builder/#entrypoint",
		)
	} else {
		s.c.RecordPass(
			"SPEC-02",
			"Deterministic Entrypoint or Command",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Entrypoint configured: %v %v", ep, cmd),
		)
	}
	return s
}

func (s *SpecAssertions) DisallowedEnvKeys(keys ...string) *SpecAssertions {
	return s.DisallowedEnvKeysExcept(nil, keys...)
}

// DisallowedEnvKeysExcept is DisallowedEnvKeys with a list of accepted keys.
// An accepted key is a variable name that is compared whole and with its case,
// and it is exempt from the name match only: its value is still checked for
// credential formats. An empty list gives exactly the behavior of
// DisallowedEnvKeys.
func (s *SpecAssertions) DisallowedEnvKeysExcept(accepted []string, keys ...string) *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-03", "Clean Ambient Environment", spec.TierSpec, start)
		return s
	}
	var violations []string

	// Cloud token high-entropy signatures
	awsRegex := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	githubRegex := regexp.MustCompile(`(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})`)
	slackRegex := regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`)
	privateKeyRegex := regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY`)

	for _, envVar := range s.c.Inspect.Config.Env {
		parts := strings.SplitN(envVar, "=", 2)
		key := parts[0]
		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}

		// Check disallowed keys
		for _, disallowed := range keys {
			if envKeyAccepted(key, accepted) {
				break
			}
			matched, _ := filepath.Match(strings.ToUpper(disallowed), strings.ToUpper(key))
			if matched || strings.Contains(strings.ToUpper(key), strings.ToUpper(disallowed)) {
				violations = append(violations, fmt.Sprintf("Key=%s", key))
				break
			}
		}

		// Check values for concrete cloud credentials
		if awsRegex.MatchString(val) {
			violations = append(violations, fmt.Sprintf("Key=%s (matches AWS Access Key pattern)", key))
		} else if githubRegex.MatchString(val) {
			violations = append(violations, fmt.Sprintf("Key=%s (matches GitHub Personal Access Token)", key))
		} else if slackRegex.MatchString(val) {
			violations = append(violations, fmt.Sprintf("Key=%s (matches Slack API Token)", key))
		} else if privateKeyRegex.MatchString(val) {
			violations = append(violations, fmt.Sprintf("Key=%s (contains unencrypted private key)", key))
		}
	}
	if len(violations) > 0 {
		s.c.RecordFailure(
			"SPEC-03",
			"Clean Ambient Environment",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Sensitive or prohibited environment variable credentials found: %v", violations),
			"Environment variables persist permanently in immutable image layer metadata and are readable by anyone with pull access.",
			"Remove static secrets from environment variables; inject credentials dynamically at runtime",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final (NIST SP 800-190 Section 3.1.2)",
		)
	} else {
		s.c.RecordPass(
			"SPEC-03",
			"Clean Ambient Environment",
			spec.TierSpec,
			time.Since(start),
			"No prohibited or secret environment variables detected",
		)
	}
	return s
}

func (s *SpecAssertions) MaxSizeMB(maxMB int64) *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-04", "Image Size Hygiene Budget", spec.TierSpec, start)
		return s
	}
	limitBytes := maxMB * 1024 * 1024
	actualBytes := s.c.Inspect.Size
	actualMB := actualBytes / (1024 * 1024)
	if actualBytes > limitBytes {
		s.c.RecordFailure(
			"SPEC-04",
			"Image Size Hygiene Budget",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Image size (%d MB) exceeds limit of %d MB", actualMB, maxMB),
			"Bloated images increase cold-start latency, memory overhead, and expand vulnerability surface.",
			"Adopt multi-stage builds, minimal base images (e.g. distroless, alpine), or purge build dependencies",
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#minimize-the-number-of-layers",
		)
	} else {
		s.c.RecordPass(
			"SPEC-04",
			"Image Size Hygiene Budget",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Image size (%d MB) is within allowed limit (%d MB)", actualMB, maxMB),
		)
	}
	return s
}

func (s *SpecAssertions) RequireNonPrivilegedPorts() *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-05", "Non-Privileged Declared Image Ports", spec.TierSpec, start)
		return s
	}
	var privPorts []string
	for _, p := range sortedPortDeclarations(s.c.Inspect.Config.ExposedPorts) {
		portNum, ok := parseExposedPort(p)
		if !ok {
			privPorts = append(privPorts, fmt.Sprintf("unrecognized declaration %q", p))
		} else if portNum < 1024 {
			privPorts = append(privPorts, p)
		}
	}
	if len(privPorts) > 0 {
		s.c.RecordFailure(
			"SPEC-05",
			"Non-Privileged Declared Image Ports",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Image metadata declares privileged or unrecognized ports: %v", privPorts),
			"This assertion inspects image-declared ExposedPorts only; it does not observe runtime listeners or published ports.",
			"Declare valid application ports and use non-privileged ports where required",
			"https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated; declared ports, not ports mapped at run time)",
		)
	} else {
		s.c.RecordPass(
			"SPEC-05",
			"Non-Privileged Declared Image Ports",
			spec.TierSpec,
			time.Since(start),
			"No privileged or unrecognized image-declared ports; runtime listeners and port publishing were not inspected",
		)
	}
	return s
}

func (s *SpecAssertions) RequireHealthcheck() *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("CIS-4.6", "Image HEALTHCHECK", spec.TierSpec, start)
		return s
	}
	healthcheck := s.c.Inspect.Config.Healthcheck
	if healthcheck == nil ||
		len(healthcheck.Test) < 2 ||
		strings.EqualFold(healthcheck.Test[0], "NONE") ||
		strings.TrimSpace(healthcheck.Test[1]) == "" {
		s.c.RecordFailure("CIS-4.6", "Image HEALTHCHECK", spec.TierSpec, time.Since(start), "Image metadata does not define an enabled HEALTHCHECK", "A configured health check allows the container runtime to report application health.", "Add an appropriate HEALTHCHECK instruction to the image", "https://www.cisecurity.org/benchmark/docker")
		return s
	}
	s.c.RecordPass("CIS-4.6", "Image HEALTHCHECK", spec.TierSpec, time.Since(start), "Image metadata defines a HEALTHCHECK")
	return s
}

func (s *SpecAssertions) DisallowDebugPorts(disallowed ...int) *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-06", "Dangling Debug Port Exclusion", spec.TierSpec, start)
		return s
	}
	if len(disallowed) == 0 {
		disallowed = []int{5005, 9229, 2375, 22, 6006}
	}
	var found []int
	for _, p := range sortedPortDeclarations(s.c.Inspect.Config.ExposedPorts) {
		portNum, ok := parseExposedPort(p)
		if !ok {
			s.c.RecordFailure("SPEC-06", "Dangling Debug Port Exclusion", spec.TierSpec, time.Since(start), fmt.Sprintf("Image metadata contains an unrecognized exposed-port declaration: %q", p), "This assertion inspects image-declared ExposedPorts only; it does not observe runtime listeners or published ports.", "Correct the image's exposed-port metadata", "")
			return s
		}
		for _, d := range disallowed {
			if portNum == d {
				found = append(found, d)
			}
		}
	}
	if len(found) > 0 {
		s.c.RecordFailure(
			"SPEC-06",
			"Dangling Debug Port Exclusion",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Dangerous debugging or administration ports exposed in production: %v", found),
			"Debuggers (JDWP 5005, Node 9229) and Docker sockets (2375) allow remote arbitrary code execution.",
			"Remove EXPOSE instructions for debuggers and administrative daemon ports",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final",
		)
	} else {
		s.c.RecordPass(
			"SPEC-06",
			"Dangling Debug Port Exclusion",
			spec.TierSpec,
			time.Since(start),
			"No dangerous debug or administration ports exposed",
		)
	}
	return s
}

func (s *SpecAssertions) RequireCopyOverAdd() *SpecAssertions {
	start := time.Now()
	if s.c.OCIIndex == nil {
		s.c.recordMissingOCIIndex("SPEC-07", spec07Name, spec.TierSpec, start)
		return s
	}
	addViolations, evidenceErr := s.c.OCIIndex.AddInstructionEvidence()
	if len(addViolations) == 0 && evidenceErr != nil {
		s.c.RecordUnverifiedDetail("SPEC-07", spec07Name, spec.TierSpec, time.Since(start), fmt.Sprintf("ADD instruction status is unverified: %v", evidenceErr), "Use a build process that preserves complete OCI history; this check cannot prove that all Dockerfile instructions were recorded", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return s
	}

	if len(addViolations) > 0 {
		s.c.RecordFailure(
			"SPEC-07",
			spec07Name,
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Detected %d ADD instructions in the recorded image history (the base image rootfs import is exempt): %v", len(addViolations), addViolations),
			"ADD can implicitly fetch remote unverified archives or perform non-deterministic extractions, violating supply chain provenance. Only ADD instructions that are visible in the OCI history are observed.",
			"Replace 'ADD' with 'COPY' for local files, or use verified curl/wget with checksum verification in a builder stage",
			"https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
		)
	} else {
		s.c.RecordPass(
			"SPEC-07",
			spec07Name,
			spec.TierSpec,
			time.Since(start),
			"No ADD instruction other than the base image rootfs import was found in the recorded OCI history; the history may be incomplete and does not prove all Dockerfile instructions",
		)
	}
	return s
}

const (
	spec07Name = "Instruction Hygiene (COPY over ADD)"
	fs06Name   = "Private Key Material Scan"
	fs07Name   = "Development and Test Harness Leakage"
	fs08Name   = "Account Security (Empty Passwords)"
)

// maxEvidencePaths bounds the paths listed in one result's evidence. The
// message always states the full count.
const maxEvidencePaths = 200

func capEvidencePaths(paths []string) []string {
	if len(paths) <= maxEvidencePaths {
		return paths
	}
	return paths[:maxEvidencePaths]
}

func (s *SpecAssertions) RequireOCIProvenance(requiredKeys ...string) *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-08", "Supply-Chain OCI Provenance Annotations", spec.TierSpec, start)
		return s
	}
	if len(requiredKeys) == 0 {
		requiredKeys = []string{"source", "revision"}
	}
	var missing []string
	labels := s.c.Inspect.Config.Labels
	for _, k := range requiredKeys {
		fullKey := "org.opencontainers.image." + k
		if labels == nil || labels[fullKey] == "" {
			missing = append(missing, fullKey)
		}
	}
	if len(missing) > 0 {
		s.c.RecordFailure(
			"SPEC-08",
			"Supply-Chain OCI Provenance Annotations",
			spec.TierSpec,
			time.Since(start),
			fmt.Sprintf("Missing required OCI provenance metadata labels: %v", missing),
			"In OpenSSF Scorecard and SLSA v1.0, container images must declare source repository and git commit revision provenance labels.",
			"Add LABEL org.opencontainers.image.source=... and org.opencontainers.image.revision=... in your Dockerfile",
			"https://github.com/opencontainers/image-spec/blob/main/annotations.md",
		)
	} else {
		s.c.RecordPass(
			"SPEC-08",
			"Supply-Chain OCI Provenance Annotations",
			spec.TierSpec,
			time.Since(start),
			"All required OCI provenance annotations are defined",
		)
	}
	return s
}

// ==========================================
// TIER 2: FILESYSTEM & HYGIENE ASSERTIONS
// ==========================================
type FilesystemAssertions struct {
	c *Container
}

// PathsNotExist is FS-01. A path counts as present when it holds content: a
// file, a link, or a directory with an entry below it that is neither a
// directory nor a regular file of zero bytes. An empty directory is not a
// package cache, and base images ship such directories (the Alpine image has
// an empty /var/cache/apk). A directory with only empty files below it is not
// one either: apt leaves an empty lock file under /var/cache/apt/archives
// after every run. Neither fails the check.
// The engine probe used without an index cannot tell an empty directory from a
// full one and reports every existing path.
func (fs *FilesystemAssertions) PathsNotExist(paths ...string) *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil && fs.c.Engine == nil {
		fs.c.recordMissingOCIIndex("FS-01", "Package Manager Cache Elimination", spec.TierFilesystem, start)
		return fs
	}
	var foundPaths []string
	if fs.c.OCIIndex != nil {
		for _, p := range paths {
			if fs.c.OCIIndex.HasContentAt(p) {
				foundPaths = append(foundPaths, p)
			}
		}
	} else if fs.c.Engine != nil {
		for _, p := range paths {
			exists, err := fs.c.Engine.CheckPathExists(fs.c.context(), fs.c.Image, p)
			if err != nil {
				fs.c.RecordUnverified("FS-01", "Package Manager Cache Elimination", spec.TierFilesystem, time.Since(start), fmt.Sprintf("Path scan is unverified for %q: %v", p, err), "Resolve the runtime probe error and rerun the filesystem check", "")
				return fs
			}
			if exists {
				foundPaths = append(foundPaths, p)
			}
		}
	}
	if len(foundPaths) > 0 {
		fs.c.RecordFailure(
			"FS-01",
			"Package Manager Cache Elimination",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Prohibited build caches or sensitive paths hold content in the image: %v", foundPaths),
			"Package manager caches needlessly bloat image storage footprint and expand vulnerability attack surfaces.",
			"Purge package caches (e.g. rm -rf /var/cache/apt/* /var/lib/apt/lists/*) in multi-stage builds",
			"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
		)
	} else {
		fs.c.RecordPass(
			"FS-01",
			"Package Manager Cache Elimination",
			spec.TierFilesystem,
			time.Since(start),
			"All hygiene path checks passed",
		)
	}
	return fs
}

func (fs *FilesystemAssertions) BinariesNotExist(binaries ...string) *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil && fs.c.Engine == nil {
		fs.c.recordMissingOCIIndex("FS-03", "Exclusion of Build Compilers from Production", spec.TierFilesystem, start)
		return fs
	}
	var foundBinaries []string
	if fs.c.OCIIndex != nil {
		for _, bin := range binaries {
			if fs.c.OCIIndex.HasBinary(bin) {
				foundBinaries = append(foundBinaries, bin)
			}
		}
	} else if fs.c.Engine != nil {
		for _, bin := range binaries {
			p1 := fmt.Sprintf("/usr/bin/%s", bin)
			p2 := fmt.Sprintf("/bin/%s", bin)
			e1, err := fs.c.Engine.CheckPathExists(fs.c.context(), fs.c.Image, p1)
			if err != nil {
				fs.c.RecordUnverified("FS-03", "Exclusion of Build Compilers from Production", spec.TierFilesystem, time.Since(start), fmt.Sprintf("Binary scan is unverified for %q: %v", bin, err), "Resolve the runtime probe error and rerun the filesystem check", "")
				return fs
			}
			e2, err := fs.c.Engine.CheckPathExists(fs.c.context(), fs.c.Image, p2)
			if err != nil {
				fs.c.RecordUnverified("FS-03", "Exclusion of Build Compilers from Production", spec.TierFilesystem, time.Since(start), fmt.Sprintf("Binary scan is unverified for %q: %v", bin, err), "Resolve the runtime probe error and rerun the filesystem check", "")
				return fs
			}
			if e1 || e2 {
				foundBinaries = append(foundBinaries, bin)
			}
		}
	}
	if len(foundBinaries) > 0 {
		fs.c.RecordFailure(
			"FS-03",
			"Exclusion of Build Compilers from Production",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Prohibited build toolchains / utilities detected in production image: %v", foundBinaries),
			"Leaving compiler toolchains (gcc, make) in production images facilitates living-off-the-land attacks and runtime malware compilation.",
			"Discard build compilers and package managers via multi-stage builds",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final (NIST SP 800-190 Section 3.1.3)",
		)
	} else {
		fs.c.RecordPass(
			"FS-03",
			"Exclusion of Build Compilers from Production",
			spec.TierFilesystem,
			time.Since(start),
			"No prohibited compiler binaries present",
		)
	}
	return fs
}

// systemBinaryPrefixes are the directories that FS-09 reads, as path prefixes.
var systemBinaryPrefixes = []string{"/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"}

// recordHardLinkUnverified records an UNVERIFIED result for a mode or ownership
// check that found nothing but could not read the mode and owner of some hard
// links. A finding behind such a link cannot be excluded, so the check must not
// pass.
func (fs *FilesystemAssertions) recordHardLinkUnverified(id, name string, start time.Time, linkErr error) {
	fs.c.RecordUnverifiedDetail(id, name, spec.TierFilesystem, time.Since(start),
		fmt.Sprintf("No finding was observed, but the result is unverified: %v", linkErr),
		"Build the image so that hard links and their targets are part of the same layer, or rebuild without hard links", "",
		ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
}

func (fs *FilesystemAssertions) NoSuidBinaries() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil && fs.c.Engine == nil {
		fs.c.recordMissingOCIIndex("FS-04", "SUID/SGID Privilege Escalation Vectors", spec.TierFilesystem, start)
		return fs
	}
	var suids []string
	if fs.c.OCIIndex != nil {
		suids = fs.c.OCIIndex.GetSuidBinaries()
		if len(suids) == 0 {
			if linkErr := fs.c.OCIIndex.HardLinkEvidence(); linkErr != nil {
				fs.recordHardLinkUnverified("FS-04", "SUID/SGID Privilege Escalation Vectors", start, linkErr)
				return fs
			}
		}
	} else if fs.c.Engine != nil {
		s, err := fs.c.Engine.FindSuidBinaries(fs.c.context(), fs.c.Image)
		if err != nil {
			fs.c.RecordUnverified("FS-04", "SUID/SGID Privilege Escalation Vectors", spec.TierFilesystem, time.Since(start), fmt.Sprintf("SUID/SGID scan is unverified: %v", err), "Resolve the runtime scan error and rerun the filesystem check", "")
			return fs
		}
		suids = s
	}

	if len(suids) > 0 {
		fs.c.RecordFailure(
			"FS-04",
			"SUID/SGID Privilege Escalation Vectors",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Found %d SUID/SGID binaries (potential privilege escalation risk): %v", len(suids), suids),
			"SUID/SGID executables run with file-owner permissions, enabling local privilege escalation exploits.",
			"Remove unnecessary SUID/SGID bits during image build: find / -perm /6000 -type f -exec chmod a-s {} +",
			"https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
		)
	} else {
		fs.c.RecordPass(
			"FS-04",
			"SUID/SGID Privilege Escalation Vectors",
			spec.TierFilesystem,
			time.Since(start),
			"Zero SUID/SGID binaries detected",
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoWorldWritableFiles() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-05", "World-Writable File Elimination", spec.TierFilesystem, start)
		return fs
	}
	var wwFiles []string
	if fs.c.OCIIndex != nil {
		wwFiles = fs.c.OCIIndex.GetWorldWritableFiles()
	}
	if len(wwFiles) == 0 {
		if linkErr := fs.c.OCIIndex.HardLinkEvidence(); linkErr != nil {
			fs.recordHardLinkUnverified("FS-05", "World-Writable File Elimination", start, linkErr)
			return fs
		}
	}
	if len(wwFiles) > 0 {
		fs.c.RecordFailure(
			"FS-05",
			"World-Writable File Elimination",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Found %d world-writable regular files (privilege tampering risk): %v", len(wwFiles), wwFiles),
			"World-writable files can be modified by any unprivileged user or shared volume process, allowing binary tampering.",
			"Remove world-writable bits during image build: chmod -R o-w /app",
			"",
		)
	} else {
		fs.c.RecordPass(
			"FS-05",
			"World-Writable File Elimination",
			spec.TierFilesystem,
			time.Since(start),
			"Zero world-writable regular files detected",
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoPrivateKeysOrCertificates() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-06", fs06Name, spec.TierFilesystem, start)
		return fs
	}
	scan := fs.c.OCIIndex.ScanPrivateKeys()
	evidence := &spec.Evidence{
		Paths:             scan.Findings,
		FixtureCandidates: capEvidencePaths(scan.FixtureCandidates),
	}
	fixtureNote := ""
	if n := len(scan.FixtureCandidates); n > 0 {
		fixtureNote = fmt.Sprintf("; %d fixture candidate(s) under testdata, test, fixtures or examples locations or Debian snakeoil files are counted separately", n)
	}
	if len(scan.Findings) == 0 && len(scan.Issues) > 0 {
		fs.c.RecordUnverifiedDetail("FS-06", fs06Name, spec.TierFilesystem, time.Since(start),
			fmt.Sprintf("Private-key scan is unverified: %s", strings.Join(scan.Issues, "; ")),
			"Ensure recognized .key, .pem, and id_* candidate files use complete PEM/OpenSSH formats within the scan limit", "",
			ResultDetail{Reason: spec.ReasonEvidenceIncomplete, Evidence: evidence})
		return fs
	}
	if len(scan.Findings) > 0 {
		fs.c.RecordFailureDetail(
			"FS-06",
			fs06Name,
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Private key material found in %d recognized key file(s) outside fixture-like locations: %v%s", len(scan.Findings), scan.Findings, fixtureNote),
			"Private keys stored in image layers can be extracted by anyone with container image pull access. The detector covers PEM and OpenSSH private-key blocks in files named *.key, *.pem or id_*; it does not scan arbitrary file formats and does not know whether a key is a test key.",
			"Purge private key files from image layers and mount credentials at runtime via secrets",
			"https://www.cisecurity.org/benchmark/docker (related topic of the CIS Docker Benchmark, no control number stated)",
			ResultDetail{Evidence: evidence},
		)
	} else {
		fs.c.RecordPassDetail(
			"FS-06",
			fs06Name,
			spec.TierFilesystem,
			time.Since(start),
			"No private-key block was found outside fixture-like locations in completely scanned recognized key files (*.key, *.pem, id_*); arbitrary files and non-PEM formats are outside this detector's scope"+fixtureNote,
			ResultDetail{Evidence: evidence},
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoTestHarnessLeakage() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-07", fs07Name, spec.TierFilesystem, start)
		return fs
	}
	scan := fs.c.OCIIndex.ScanTestHarness()
	evidence := &spec.Evidence{
		Paths:             scan.Findings,
		FixtureCandidates: capEvidencePaths(scan.FixtureCandidates),
	}
	fixtureNote := ""
	if n := len(scan.FixtureCandidates); n > 0 {
		fixtureNote = fmt.Sprintf("; %d fixture candidate path(s) (test directories and test data) are counted separately", n)
	}
	if len(scan.Findings) > 0 {
		fs.c.RecordFailureDetail(
			"FS-07",
			fs07Name,
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Test runner configuration found outside fixture-like locations in %d place(s): %v%s", len(scan.Findings), scan.Findings, fixtureNote),
			"Production containers should not bundle test runner configuration. The check matches whole path components and exact file names; test directories and test data are fixture candidates and never fail the check on their own.",
			"Exclude test directories in multi-stage builds via .dockerignore or selective COPY",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final (NIST SP 800-190 Section 3.1.3)",
			ResultDetail{Evidence: evidence},
		)
	} else {
		fs.c.RecordPassDetail(
			"FS-07",
			fs07Name,
			spec.TierFilesystem,
			time.Since(start),
			"No test runner configuration was found outside fixture-like locations"+fixtureNote,
			ResultDetail{Evidence: evidence},
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoEmptyPasswordAccounts() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-08", fs08Name, spec.TierFilesystem, start)
		return fs
	}
	emptyUsers, evidenceErr := fs.c.OCIIndex.EmptyPasswordAccountsEvidence()
	if len(emptyUsers) == 0 && evidenceErr != nil {
		fs.c.RecordUnverifiedDetail("FS-08", fs08Name, spec.TierFilesystem, time.Since(start), fmt.Sprintf("Empty-password account status is unverified: %v", evidenceErr), "Ensure complete, well-formed /etc/passwd and /etc/shadow files are present in the final image", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return fs
	}
	if len(emptyUsers) > 0 {
		fs.c.RecordFailureDetail(
			"FS-08",
			fs08Name,
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Identified accounts with empty password fields in /etc/passwd or /etc/shadow: %v", emptyUsers),
			"Accounts with empty password fields allow passwordless logins. The check reads the final image account files only.",
			"Lock unprivileged system accounts in /etc/shadow using 'passwd -l <user>' or set a strong password hash",
			"",
			ResultDetail{Evidence: &spec.Evidence{Paths: emptyUsers}},
		)
	} else {
		fs.c.RecordPass(
			"FS-08",
			fs08Name,
			spec.TierFilesystem,
			time.Since(start),
			"No empty password fields were found in completely scanned final-image /etc/passwd and /etc/shadow records",
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoNonRootSystemBinaries() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("FS-09", "System Directory Ownership Hygiene", spec.TierFilesystem, start)
		return fs
	}
	var nonRootBins []string
	if fs.c.OCIIndex != nil {
		nonRootBins = fs.c.OCIIndex.GetNonRootSystemBinaries()
	}
	if len(nonRootBins) == 0 {
		if linkErr := fs.c.OCIIndex.HardLinkEvidence(systemBinaryPrefixes...); linkErr != nil {
			fs.recordHardLinkUnverified("FS-09", "System Directory Ownership Hygiene", start, linkErr)
			return fs
		}
	}
	if len(nonRootBins) > 0 {
		fs.c.RecordFailure(
			"FS-09",
			"System Directory Ownership Hygiene",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Found system binaries in /bin or /usr/bin owned by non-root UIDs: %v", nonRootBins),
			"System binaries must be owned by root (UID 0). Non-root ownership allows an unprivileged application process to overwrite system binaries.",
			"Ensure system binaries remain owned by root (UID 0:0): chown -R 0:0 /bin /usr/bin /sbin /usr/sbin",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final (NIST SP 800-190 Section 3.1.2)",
		)
	} else {
		fs.c.RecordPass(
			"FS-09",
			"System Directory Ownership Hygiene",
			spec.TierFilesystem,
			time.Since(start),
			"All system binaries in /bin and /usr/bin are owned by root (UID 0)",
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoInteractiveShells() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("DISTRO-02", "Interactive Shell Elimination", spec.TierFilesystem, start)
		return fs
	}
	var shells []string
	if fs.c.OCIIndex != nil {
		shells = fs.c.OCIIndex.GetInstalledShells()
	}
	if len(shells) > 0 {
		fs.c.RecordFailure(
			"DISTRO-02",
			"Interactive Shell Elimination",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Interactive shells detected in distroless image: %v", shells),
			"Interactive shells in production containers facilitate attacker shell-spawning and post-exploitation command execution.",
			"Adopt true distroless or scratch base images devoid of shell interpreters",
			"https://github.com/GoogleContainerTools/distroless",
		)
	} else {
		fs.c.RecordPass(
			"DISTRO-02",
			"Interactive Shell Elimination",
			spec.TierFilesystem,
			time.Since(start),
			"Zero interactive shells detected in image",
		)
	}
	return fs
}

func (fs *FilesystemAssertions) NoPackageManagers() *FilesystemAssertions {
	start := time.Now()
	if fs.c.OCIIndex == nil {
		fs.c.recordMissingOCIIndex("DISTRO-03", "Package Manager Utility Elimination", spec.TierFilesystem, start)
		return fs
	}
	var pms []string
	if fs.c.OCIIndex != nil {
		pms = fs.c.OCIIndex.GetInstalledPackageManagers()
	}
	if len(pms) > 0 {
		fs.c.RecordFailure(
			"DISTRO-03",
			"Package Manager Utility Elimination",
			spec.TierFilesystem,
			time.Since(start),
			fmt.Sprintf("Package manager utilities detected in production image: %v", pms),
			"Package managers in production images allow attackers to download external malicious packages directly inside the container.",
			"Strip package manager binaries (e.g. apk, apt, dpkg, pip) from final runtime stage",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final",
		)
	} else {
		fs.c.RecordPass(
			"DISTRO-03",
			"Package Manager Utility Elimination",
			spec.TierFilesystem,
			time.Since(start),
			"Zero package manager binaries detected in image",
		)
	}
	return fs
}

// ==========================================
// TIER 4: SUPPLY CHAIN ASSERTIONS
// ==========================================
type SupplyChainAssertions struct {
	c *Container
}

func parseSyftLicense(raw json.RawMessage) (string, error) {
	var license string
	if err := json.Unmarshal(raw, &license); err == nil {
		license = strings.TrimSpace(license)
		if license != "" {
			return license, nil
		}
		return "", fmt.Errorf("license entry is empty")
	}
	var metadata struct {
		Value          string `json:"value"`
		SPDXExpression string `json:"spdxExpression"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return "", fmt.Errorf("license entry is neither a string nor an object: %w", err)
	}
	license = strings.TrimSpace(metadata.SPDXExpression)
	if license == "" {
		license = strings.TrimSpace(metadata.Value)
	}
	if license == "" {
		return "", fmt.Errorf("license object has no SPDX expression or value")
	}
	return license, nil
}

func (sc *SupplyChainAssertions) PackagesNotExist(pkgs ...string) *SupplyChainAssertions {
	start := time.Now()
	artifacts, err := sc.c.sbomPackages()
	if err != nil {
		sc.c.RecordUnverifiedDetail("SUP-01", "Prohibited Network Reconnaissance Tools", spec.TierSupplyChain, time.Since(start), fmt.Sprintf("Package check is unverified: %v", err), "Install Syft and provide a valid immutable image reference so the package inventory can be checked", "", ResultDetail{Reason: sbomReason(err)})
		return sc
	}
	if len(artifacts) == 0 {
		sc.c.RecordUnverifiedDetail("SUP-01", "Prohibited Network Reconnaissance Tools", spec.TierSupplyChain, time.Since(start), "Package check is unverified: the SBOM contains no artifacts", "Generate a complete package inventory before evaluating prohibited-package policy", "", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return sc
	}
	var foundViolations []string
	for _, prohibited := range pkgs {
		for _, pkg := range artifacts {
			if strings.EqualFold(pkg.Name, prohibited) {
				foundViolations = append(foundViolations, prohibited)
				break
			}
		}
	}
	if len(foundViolations) > 0 {
		sc.c.RecordFailure(
			"SUP-01",
			"Prohibited Network Reconnaissance Tools",
			spec.TierSupplyChain,
			time.Since(start),
			fmt.Sprintf("Prohibited packages detected in SBOM: %v", foundViolations),
			"Network reconnaissance and packet capture utilities (netcat, nmap, tcpdump) should not be bundled in production containers.",
			"Exclude prohibited packages from base images or builder stages",
			"https://csrc.nist.gov/publications/detail/sp/800-190/final (NIST SP 800-190 Section 3.1.3)",
		)
	} else {
		sc.c.RecordPass(
			"SUP-01",
			"Prohibited Network Reconnaissance Tools",
			spec.TierSupplyChain,
			time.Since(start),
			"SBOM verified: no prohibited packages present",
		)
	}
	return sc
}

func (sc *SupplyChainAssertions) RequireApprovedLicenses(allowed ...string) *SupplyChainAssertions {
	start := time.Now()
	if len(allowed) == 0 {
		allowed = []string{"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0"}
	}
	artifacts, err := sc.c.sbomPackages()
	if err != nil {
		sc.c.RecordUnverifiedDetail("SUP-03", "SPDX License Compliance", spec.TierSupplyChain, time.Since(start), fmt.Sprintf("License status is unverified: %v", err), "Install Syft and provide a valid immutable image reference so package licenses can be checked", "https://spdx.org/licenses/", ResultDetail{Reason: sbomReason(err)})
		return sc
	}
	if len(artifacts) == 0 {
		sc.c.RecordUnverifiedDetail("SUP-03", "SPDX License Compliance", spec.TierSupplyChain, time.Since(start), "License status is unverified: the SBOM contains no packages", "Generate a complete package inventory before evaluating licenses", "https://spdx.org/licenses/", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return sc
	}

	approved := make(map[string]struct{}, len(allowed))
	for _, license := range allowed {
		license = strings.TrimSpace(license)
		if license != "" {
			approved[strings.ToLower(license)] = struct{}{}
		}
	}
	var violations []string
	var evidenceIssues []string
	for _, pkg := range artifacts {
		if len(pkg.Licenses) == 0 {
			evidenceIssues = append(evidenceIssues, fmt.Sprintf("%s: no license metadata", pkg.Name))
			continue
		}
		for _, rawLicense := range pkg.Licenses {
			license, err := parseSyftLicense(rawLicense)
			if err != nil {
				evidenceIssues = append(evidenceIssues, fmt.Sprintf("%s: %v", pkg.Name, err))
				continue
			}
			if _, ok := approved[strings.ToLower(license)]; !ok {
				violations = append(violations, fmt.Sprintf("%s: %s", pkg.Name, license))
			}
		}
	}
	// One result per image: a violation fails the check even when other
	// packages lack usable metadata, and incomplete evidence alone makes it
	// UNVERIFIED. The lists are sorted so the message does not depend on the
	// order in which Syft reports packages.
	sort.Strings(violations)
	sort.Strings(evidenceIssues)
	switch {
	case len(violations) > 0:
		message := fmt.Sprintf("Packages have non-approved licenses: %v", violations)
		if len(evidenceIssues) > 0 {
			message += fmt.Sprintf("; license evidence is also incomplete for %d package entries: %v", len(evidenceIssues), evidenceIssues)
		}
		sc.c.RecordFailure("SUP-03", "SPDX License Compliance", spec.TierSupplyChain, time.Since(start), message, "Every identified package license must be approved by policy.", "Review the affected dependency licenses or update the approved SPDX allowlist", "https://spdx.org/licenses/")
	case len(evidenceIssues) > 0:
		sc.c.RecordUnverifiedDetail("SUP-03", "SPDX License Compliance", spec.TierSupplyChain, time.Since(start), fmt.Sprintf("License evidence is incomplete for packages: %v", evidenceIssues), "Provide complete, parseable license metadata for every SBOM package", "https://spdx.org/licenses/", ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
	default:
		sc.c.RecordPass("SUP-03", "SPDX License Compliance", spec.TierSupplyChain, time.Since(start), fmt.Sprintf("All %d SBOM packages have approved license metadata", len(artifacts)))
	}
	return sc
}

func (sc *SupplyChainAssertions) HasCryptographicSignature(config ...SignatureVerificationConfig) *SupplyChainAssertions {
	start := time.Now()
	// The reason says why the signature could not be judged, so the exporter
	// can report the UNVERIFIED results by cause: without a usable trust
	// policy (the default), without evidence, or without the verifier tool.
	recordUnverified := func(reason spec.Reason, message string) {
		sc.c.RecordUnverifiedDetail("SUP-02", "Cryptographic Image Provenance & Signature", spec.TierSupplyChain, time.Since(start), message, "Configure a signature verifier with a trusted key or keyless identity and issuer", "https://www.cisecurity.org/benchmark/docker", ResultDetail{Reason: reason})
	}
	if len(config) > 1 {
		recordUnverified(spec.ReasonNoTrustPolicy, "Signature status is unverified: configure at most one cryptographic verifier and trust policy")
		return sc
	}
	verification := sc.c.SignatureVerification
	if len(config) == 1 {
		verification = &config[0]
	}
	if verification == nil || verification.Verifier == nil {
		recordUnverified(spec.ReasonNoTrustPolicy, "Signature status is unverified: provide a cryptographic verifier and an explicit trust policy")
		return sc
	}
	if !isImmutableDigestReference(sc.c.ImmutableImageRef) {
		recordUnverified(spec.ReasonEvidenceIncomplete, "Signature status is unverified: the resolved image has no immutable repository digest reference")
		return sc
	}
	if err := verification.TrustPolicy.Validate(); err != nil {
		recordUnverified(spec.ReasonNoTrustPolicy, fmt.Sprintf("Signature status is unverified: invalid trust policy: %v", err))
		return sc
	}
	if err := verification.Verifier(sc.c.context(), sc.c.ImmutableImageRef, verification.TrustPolicy); err != nil {
		var unavailable *SignatureVerificationUnavailableError
		if errors.As(err, &unavailable) {
			recordUnverified(spec.ReasonToolUnavailable, fmt.Sprintf("Signature status is unverified: %v", err))
			return sc
		}
		sc.c.RecordFailure("SUP-02", "Cryptographic Image Provenance & Signature", spec.TierSupplyChain, time.Since(start), fmt.Sprintf("Cryptographic signature verification failed: %v", err), "The supplied verifier did not validate the image signature under the configured trust policy.", "Verify the image signature and confirm the configured trust anchor or keyless identity", "https://www.cisecurity.org/benchmark/docker")
		return sc
	}
	sc.c.RecordPass("SUP-02", "Cryptographic Image Provenance & Signature", spec.TierSupplyChain, time.Since(start), "Cryptographic signature verified under the configured trust policy")
	return sc
}

func isImmutableDigestReference(image string) bool {
	separator := strings.LastIndex(image, "@sha256:")
	if separator < 1 || len(image)-separator-len("@sha256:") != 64 {
		return false
	}
	for _, r := range image[separator+len("@sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
