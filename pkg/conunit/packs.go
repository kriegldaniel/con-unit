package conunit

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// RulePack defines a pre-composed, reusable bundle of container unit test assertions.
//
// A pack lists its checks by the IDs that appear in the results, so Except takes
// those IDs (for example "FS-04"). Each pack also accepts its older pack-level
// handles (for example "CIS-4.10", which stands for SPEC-03, FS-06 and FS-08)
// as aliases that disable the checks they used to cover.
type RulePack interface {
	ID() string
	Name() string
	// Description states what the pack is for and what it does not claim.
	Description() string
	// Checks lists the checks of the pack in execution order.
	Checks() []PackCheck
	Apply(c *Container)
	Except(ruleIDs ...string) RulePack
	AllowBinaries(binaries ...string) RulePack
	AllowPaths(paths ...string) RulePack
	AllowPrivilegedPorts() RulePack
}

// PackCheck describes one check of a pack for documentation and tests.
type PackCheck struct {
	// ID is the rule ID that the check emits and that Except accepts.
	ID string
	// Params states the parameters the pack gives the check.
	Params string
	// LegacyIDs are older pack-level exclusion handles that also disable it.
	LegacyIDs []string
}

type packCheck struct {
	id     string
	params string
	legacy []string
	run    func(p *basePack, c *Container)
}

type basePack struct {
	id                   string
	name                 string
	description          string
	excludedRules        []string
	allowedBinaries      []string
	allowedPaths         []string
	allowPrivilegedPorts bool
	checks               []packCheck
}

func (bp *basePack) ID() string          { return bp.id }
func (bp *basePack) Name() string        { return bp.name }
func (bp *basePack) Description() string { return bp.description }

func (bp *basePack) Checks() []PackCheck {
	checks := make([]PackCheck, 0, len(bp.checks))
	for _, check := range bp.checks {
		checks = append(checks, PackCheck{ID: check.id, Params: check.params, LegacyIDs: slices.Clone(check.legacy)})
	}
	return checks
}

func (bp *basePack) Except(ruleIDs ...string) RulePack {
	bp.excludedRules = append(bp.excludedRules, ruleIDs...)
	return bp
}

func (bp *basePack) AllowBinaries(binaries ...string) RulePack {
	bp.allowedBinaries = append(bp.allowedBinaries, binaries...)
	return bp
}

func (bp *basePack) AllowPaths(paths ...string) RulePack {
	bp.allowedPaths = append(bp.allowedPaths, paths...)
	return bp
}

func (bp *basePack) AllowPrivilegedPorts() RulePack {
	bp.allowPrivilegedPorts = true
	return bp
}

// skips reports whether the check is excluded, by its own ID or by one of its
// legacy pack-level handles.
func (bp *basePack) skips(check packCheck) bool {
	if slices.Contains(bp.excludedRules, check.id) {
		return true
	}
	for _, legacy := range check.legacy {
		if slices.Contains(bp.excludedRules, legacy) {
			return true
		}
	}
	return false
}

func (bp *basePack) Apply(c *Container) {
	for _, check := range bp.checks {
		if !bp.skips(check) {
			check.run(bp, c)
		}
	}
}

// Parameters shared between the checks and their documentation, so that the
// generated rule reference states exactly what runs.
var (
	secretEnvKeys     = []string{"PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY"}
	nistSecretEnvKeys = []string{"PASSWORD", "SECRET", "TOKEN", "AWS_SECRET"}
	hygienePaths      = []string{"/var/cache/apt", "/var/cache/apk", "/root/.cache", "/.git", "/root/.ssh", "/.env"}
	nistPaths         = []string{"/var/cache/apt", "/var/cache/apk", "/root/.cache"}
	hygieneBinaries   = []string{"gcc", "g++", "make"}
	nistBinaries      = []string{"gcc", "g++", "make", "gdb", "strace"}
)

const (
	sigtermTimeout = 5 * time.Second
	kubeUID        = 10001
	memoryLimit    = "256m"
)

func listParam(label string, values []string) string {
	return label + ": " + strings.Join(values, ", ")
}

// without returns the values that the operator has not allowed.
func without(values, allowed []string) []string {
	var kept []string
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			kept = append(kept, value)
		}
	}
	return kept
}

// withLegacy returns the check with an older pack-level exclusion handle added.
func (pc packCheck) withLegacy(ids ...string) packCheck {
	pc.legacy = append(slices.Clone(pc.legacy), ids...)
	return pc
}

// Check constructors. Each one is the use of one assertion by a pack.

func checkUserNotRoot() packCheck {
	return packCheck{id: "SPEC-01", run: func(_ *basePack, c *Container) { c.AssertSpec().UserNotRoot() }}
}

func checkEntrypoint() packCheck {
	return packCheck{id: "SPEC-02", run: func(_ *basePack, c *Container) { c.AssertSpec().RequireEntrypoint() }}
}

func checkEnv(keys []string) packCheck {
	return packCheck{id: "SPEC-03", params: listParam("disallowed keys", keys),
		run: func(_ *basePack, c *Container) { c.AssertSpec().DisallowedEnvKeys(keys...) }}
}

func checkPrivilegedPorts() packCheck {
	return packCheck{id: "SPEC-05", params: "skipped when the pack allows privileged ports", run: func(p *basePack, c *Container) {
		if !p.allowPrivilegedPorts {
			c.AssertSpec().RequireNonPrivilegedPorts()
		}
	}}
}

func checkDebugPorts() packCheck {
	return packCheck{id: "SPEC-06", params: "ports: 5005, 9229, 2375, 22, 6006", run: func(_ *basePack, c *Container) { c.AssertSpec().DisallowDebugPorts() }}
}

func checkCopyOverAdd() packCheck {
	return packCheck{id: "SPEC-07", run: func(_ *basePack, c *Container) { c.AssertSpec().RequireCopyOverAdd() }}
}

func checkHealthcheck() packCheck {
	return packCheck{id: "CIS-4.6", run: func(_ *basePack, c *Container) { c.AssertSpec().RequireHealthcheck() }}
}

func checkPaths(paths []string) packCheck {
	return packCheck{id: "FS-01", params: listParam("paths", paths) + " (minus the paths the operator allows)", run: func(p *basePack, c *Container) {
		if active := without(paths, p.allowedPaths); len(active) > 0 {
			c.AssertFilesystem().PathsNotExist(active...)
		}
	}}
}

func checkBinaries(binaries []string) packCheck {
	return packCheck{id: "FS-03", params: listParam("binaries", binaries) + " (minus the binaries the operator allows)", run: func(p *basePack, c *Container) {
		if active := without(binaries, p.allowedBinaries); len(active) > 0 {
			c.AssertFilesystem().BinariesNotExist(active...)
		}
	}}
}

func checkSuid() packCheck {
	return packCheck{id: "FS-04", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoSuidBinaries() }}
}

func checkWorldWritable() packCheck {
	return packCheck{id: "FS-05", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoWorldWritableFiles() }}
}

func checkPrivateKeys() packCheck {
	return packCheck{id: "FS-06", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoPrivateKeysOrCertificates() }}
}

func checkTestHarness() packCheck {
	return packCheck{id: "FS-07", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoTestHarnessLeakage() }}
}

func checkEmptyPasswords() packCheck {
	return packCheck{id: "FS-08", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoEmptyPasswordAccounts() }}
}

func checkSystemOwnership() packCheck {
	return packCheck{id: "FS-09", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoNonRootSystemBinaries() }}
}

func checkShells() packCheck {
	return packCheck{id: "DISTRO-02", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoInteractiveShells() }}
}

func checkPackageManagers() packCheck {
	return packCheck{id: "DISTRO-03", run: func(_ *basePack, c *Container) { c.AssertFilesystem().NoPackageManagers() }}
}

func checkReadOnly() packCheck {
	return packCheck{id: "EXEC-01", run: func(_ *basePack, c *Container) { c.AssertContract().ReadOnlyRootfsCompatible() }}
}

func checkDropCapabilities() packCheck {
	return packCheck{id: "EXEC-02", run: func(_ *basePack, c *Container) { c.AssertContract().DropAllCapabilitiesCompatible() }}
}

func checkSigterm() packCheck {
	return packCheck{id: "EXEC-03", params: fmt.Sprintf("timeout: %s", sigtermTimeout), run: func(_ *basePack, c *Container) {
		c.AssertContract().HandlesSigtermGracefully(sigtermTimeout)
	}}
}

func checkNoNewPrivileges() packCheck {
	return packCheck{id: "EXEC-04", run: func(_ *basePack, c *Container) { c.AssertContract().ComplyWithNoNewPrivileges() }}
}

func checkArbitraryUID() packCheck {
	return packCheck{id: "EXEC-05", params: fmt.Sprintf("uid: %d", kubeUID), run: func(_ *basePack, c *Container) {
		c.AssertContract().ComplyWithArbitraryNonRootUID(kubeUID)
	}}
}

func checkMemoryLimit() packCheck {
	// The baseline already runs with --pids-limit=256, so the treatment adds
	// the memory limit only (a pids value of 0 keeps the baseline value).
	return packCheck{id: "EXEC-07", params: "memory: " + memoryLimit + "; the PID limit stays at the baseline value", run: func(_ *basePack, c *Container) {
		c.AssertContract().ComplyWithResourceLimits(memoryLimit, 0)
	}}
}

func checkPSS() packCheck {
	return packCheck{id: "EXEC-08", run: func(_ *basePack, c *Container) { c.AssertContract().ComplyWithKubernetesPSS() }}
}

// checkSignature is SUP-02. It runs with the trust policy of the container, so
// it is UNVERIFIED (NO_TRUST_POLICY) when none is configured.
func checkSignature() packCheck {
	return packCheck{id: "SUP-02", params: "uses the trust policy configured for the run", run: func(_ *basePack, c *Container) {
		c.AssertSupplyChain().HasCryptographicSignature()
	}}
}

// ProductionHygiene returns a standard rule pack for production OCI container images
func ProductionHygiene() RulePack {
	return &basePack{
		id:          "PACK-PROD-HYGIENE",
		name:        "Production Container Hygiene & Security Baseline",
		description: "A short baseline for production images that includes the signal handling and package cache checks. It is a ConUnit profile, not an implementation of a standard.",
		checks: []packCheck{
			checkUserNotRoot(),
			checkEntrypoint(),
			checkEnv(secretEnvKeys),
			checkPaths(hygienePaths),
			checkBinaries(hygieneBinaries),
			checkSuid(),
			checkReadOnly(),
			checkDropCapabilities(),
			checkSigterm(),
		},
	}
}

// CISBenchmark returns the CIS-informed container hardening profile, which is
// also resolvable as "cis". It selects checks that relate to topics of the
// CIS Docker Benchmark. No check states a control number (see Rules and
// docs/DEVIATIONS.md, DEV-15). It is not a CIS compliance assessment.
func CISBenchmark() RulePack {
	return &basePack{
		id:   "PACK-CONUNIT-HARDENING",
		name: "ConUnit Container Hardening Profile (CIS-informed)",
		description: "Checks selected for their relation to topics of the CIS Docker Benchmark. No check states a control number, so every check is a custom ConUnit check with a scope. " +
			"The profile is not a CIS compliance assessment: topics are only approximated, runtime topics are tested as image compatibility, and the benchmark covers many topics that this profile does not. " +
			"The identifier was PACK-CIS-DOCKER before result schema version 2. The names cis, cis-docker, cisbenchmark and hardening resolve to this pack.",
		checks: []packCheck{
			checkUserNotRoot().withLegacy("CIS-4.1"),
			checkHealthcheck(),
			checkSuid().withLegacy("CIS-4.8"),
			checkCopyOverAdd().withLegacy("CIS-4.9"),
			checkEnv(secretEnvKeys).withLegacy("CIS-4.10"),
			checkPrivateKeys().withLegacy("CIS-4.10"),
			checkEmptyPasswords().withLegacy("CIS-4.10"),
			checkWorldWritable().withLegacy("CIS-4.11"),
			checkSystemOwnership().withLegacy("CIS-4.11"),
			checkTestHarness().withLegacy("CIS-4.3"),
			checkSignature().withLegacy("CIS-4.5"),
			checkDropCapabilities().withLegacy("CIS-5.3"),
			checkPrivilegedPorts().withLegacy("CIS-5.7"),
			checkDebugPorts().withLegacy("CIS-5.7"),
			checkMemoryLimit().withLegacy("CIS-5.10"),
			checkReadOnly().withLegacy("CIS-5.12"),
			checkNoNewPrivileges().withLegacy("CIS-5.25"),
		},
	}
}

// NIST_SP_800_190 returns container security controls based on NIST Special Publication 800-190
func NIST_SP_800_190() RulePack {
	return &basePack{
		id:          "PACK-NIST-800-190",
		name:        "NIST SP 800-190 Application Container Security Guide",
		description: "Checks chosen to reflect themes of NIST SP 800-190 for images. The mapping to the publication is thematic: it has no numbered controls to map to.",
		checks: []packCheck{
			checkUserNotRoot().withLegacy("NIST-IMG-1"),
			checkEnv(nistSecretEnvKeys).withLegacy("NIST-IMG-2"),
			checkPrivateKeys().withLegacy("NIST-IMG-2"),
			checkBinaries(nistBinaries).withLegacy("NIST-IMG-3"),
			checkPaths(nistPaths).withLegacy("NIST-IMG-3"),
			checkSuid().withLegacy("NIST-IMG-4"),
			checkWorldWritable().withLegacy("NIST-IMG-4"),
			checkReadOnly().withLegacy("NIST-RT-1"),
			checkDropCapabilities().withLegacy("NIST-RT-1"),
			checkSigterm().withLegacy("NIST-RT-1"),
		},
	}
}

// KubeHardened returns strict checks aligned with NSA/CISA Kubernetes Hardening & OpenShift restricted-v2
func KubeHardened() RulePack {
	return &basePack{
		id:          "PACK-KUBE-HARDENED",
		name:        "NSA/CISA Kubernetes & OpenShift Restricted-v2 Baseline",
		description: "Checks for running an image under restrictive Kubernetes or OpenShift settings. The runtime checks show whether the image still starts under them. They do not evaluate a cluster.",
		checks: []packCheck{
			checkUserNotRoot().withLegacy("KUBE-01"),
			checkReadOnly().withLegacy("KUBE-02"),
			checkDropCapabilities().withLegacy("KUBE-03"),
			checkArbitraryUID().withLegacy("KUBE-04"),
			checkNoNewPrivileges().withLegacy("KUBE-05"),
			checkSigterm().withLegacy("KUBE-06"),
			checkPrivilegedPorts().withLegacy("KUBE-07"),
			checkPSS().withLegacy("KUBE-08"),
		},
	}
}

// DistrolessHardening returns strict assertions for distroless/scratch runtime containers
func DistrolessHardening() RulePack {
	return &basePack{
		id:          "PACK-DISTROLESS",
		name:        "Distroless Image Hardening Pack",
		description: "Checks for images that are meant to ship without a shell or a package manager.",
		checks: []packCheck{
			checkUserNotRoot().withLegacy("DISTRO-01"),
			checkShells(),
			checkPackageManagers(),
			checkSuid().withLegacy("DISTRO-04"),
			checkWorldWritable().withLegacy("DISTRO-04"),
			checkReadOnly().withLegacy("DISTRO-05"),
			checkDropCapabilities().withLegacy("DISTRO-05"),
		},
	}
}

// AllPacks returns a fresh instance of every shipped pack, in the order they
// are documented.
func AllPacks() []RulePack {
	return []RulePack{CISBenchmark(), ProductionHygiene(), KubeHardened(), NIST_SP_800_190(), DistrolessHardening(), ImageLint()}
}
