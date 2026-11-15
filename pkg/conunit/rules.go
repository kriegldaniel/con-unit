package conunit

import (
	"sort"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Rule is the documented definition of one check: its stable identity, how it
// relates to a standard, and the oracle behind it. The catalog is the single
// source for the standard column of the result tables and for docs/RULES.md,
// so neither is ever typed by hand.
type Rule struct {
	ID   string
	Name string // stable display name, identical in every result of this rule
	Tier spec.Tier
	Meta spec.RuleMeta

	// Oracle states what is observed and how a verdict follows from it.
	Oracle string
	// Evidence states what a result records.
	Evidence string
	// Limits states what the check cannot establish.
	Limits string
}

const (
	standardPSS     = "Kubernetes Pod Security Standards"
	standardConUnit = "ConUnit"
)

// No check of the catalog states a control number of the CIS Docker Benchmark. The
// numbers were checked against third party audit lists only and never against the
// official document, so the numbers are left empty and every such check is a custom
// ConUnit check. docs/DEVIATIONS.md (DEV-15) keeps the candidate number of each check
// for the day they are confirmed.

// customRule is a check that corresponds to no control of a standard.
func customRule(scope spec.RuleScope) spec.RuleMeta {
	return spec.RuleMeta{Standard: standardConUnit, Mapping: spec.MappingCustom, Scope: scope}
}

const tier3OracleText = "Baseline-controlled run. The image's own entrypoint is started once with only the defensive flags (--network=none, --pids-limit=256) and a fixed mock environment, and observed for the window W (default 3 s). " +
	"If that baseline is not running at the end of W the result is UNVERIFIED (BASELINE_FAILED, or NOT_OBSERVABLE when it exited 0). Otherwise the treatment is started with the same flags plus its own: PASS if it is also running at the end of W, FAIL if not."

const tier3EvidenceText = "Baseline and treatment state (running, exited0, exited_nonzero, start_failed), exit codes, the window W and the last 50 log lines. A keyword hint may be present; it is never a diagnosis."

const tier3LimitsText = "FAIL means the container was not running at the end of W under this profile although the baseline was. It is not a defect claim and not a root cause, and the check says nothing about the image's behavior after W or under other flags. Latency is bounded below by W and is not a performance result."

// ruleCatalog lists every check ConUnit can emit, in no particular order;
// Rules returns it sorted.
var ruleCatalog = []Rule{
	{
		ID: "SPEC-01", Name: "Non-Root Execution Identity", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Reads USER from the image config. A numeric UID other than 0 passes. A user name is resolved through the final image /etc/passwd. An empty USER, root and any name that resolves to UID 0 fail.",
		Evidence: "The configured user and the resolved UID, in the message.",
		Limits:   "Observes the default user only. A process can change user at run time (gosu, su-exec) and an operator can pass --user. UNVERIFIED when a name cannot be resolved from complete /etc/passwd evidence.",
	},
	{
		ID: "SPEC-02", Name: "Deterministic Entrypoint or Command", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Passes when the image config defines ENTRYPOINT or CMD.",
		Evidence: "The configured entrypoint and command, in the message.",
		Limits:   "Presence only. It does not examine whether the command starts a useful or stable process.",
	},
	{
		ID: "SPEC-03", Name: "Clean Ambient Environment", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Matches the names of the image ENV variables against the pack's disallowed keys (case-insensitive, pattern or substring) and the values against AWS access key, GitHub token, Slack token and PEM private key patterns.",
		Evidence: "The offending variable names and the pattern that matched, in the message. Values are not recorded.",
		Limits:   "Name matching also flags variables that hold no secret (a path to a token file, for example). Value matching knows only the listed token formats. Only ENV in the image config is read, not build arguments, files or Dockerfile text.",
	},
	{
		ID: "SPEC-04", Name: "Image Size Hygiene Budget", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Compares the engine-reported image size with a limit in MB that the caller supplies.",
		Evidence: "The size and the limit, in the message.",
		Limits:   "The limit is a policy choice, not a standard. The engine-reported size can differ between engines and storage drivers. No shipped pack uses this check.",
	},
	{
		ID: "SPEC-05", Name: "Non-Privileged Declared Image Ports", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Parses the EXPOSE declarations of the image config. A port below 1024, or a declaration that cannot be parsed, fails.",
		Evidence: "The offending declarations, sorted, in the message.",
		Limits:   "Declared ports only. Neither listeners nor the ports published at run time are observed, and the related benchmark recommendation concerns ports mapped at run time.",
	},
	{
		ID: "SPEC-06", Name: "Dangling Debug Port Exclusion", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Fails when the image config declares one of the ports 5005, 9229, 2375, 22 or 6006, or a declaration that cannot be parsed.",
		Evidence: "The offending ports, in the message.",
		Limits:   "Declared ports only. The port numbers are conventions, and an application can legitimately use one of them.",
	},
	{
		ID: "SPEC-07", Name: spec07Name, Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Reads the OCI image history. Every ADD instruction fails except the base image rootfs import, which is the first layer-producing history entry in the legacy form 'ADD file:<digest> in /' or the BuildKit form 'ADD <name>.tar* / # buildkit'.",
		Evidence: "The reported ADD instructions, in the message.",
		Limits:   "Sees only the instructions the history records. Multi-stage builds, squashed images and history that was stripped hide instructions. UNVERIFIED (EVIDENCE_INCOMPLETE) when the history is missing or malformed.",
	},
	{
		ID: "SPEC-08", Name: "Supply-Chain OCI Provenance Annotations", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Passes when the image labels org.opencontainers.image.source and org.opencontainers.image.revision (or the keys the caller names) are present and not empty.",
		Evidence: "The missing label names, in the message.",
		Limits:   "Presence only. It does not check that a label is true or that it resolves.",
	},
	{
		ID: "CIS-4.6", Name: "Image HEALTHCHECK", Tier: spec.TierSpec,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Passes when the image config defines a HEALTHCHECK whose test is not NONE and not empty.",
		Evidence: "None beyond the verdict.",
		Limits:   "Presence only. It does not run the health check or judge its quality.",
	},

	{
		ID: "FS-01", Name: "Package Manager Cache Elimination", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Checks that no path of a fixed list holds content in the merged filesystem of the final image, rebuilt from the layers with whiteouts applied. A path holds content when it is a file or a link (a file of zero bytes included, because then the path itself is the finding), or a directory with at least one entry below it, at any depth, that is neither a directory nor a regular file of zero bytes. An empty directory does not count, because base images ship empty directories such as /var/cache/apk and /var/lib/apt/lists. A directory that holds only empty files does not count either, because apt leaves an empty lock file under /var/cache/apt/archives after every run. The list of a pack is shown in its table below.",
		Evidence: "The paths that hold content, in the message.",
		Limits:   "A fixed list: other caches are not seen. A zero-byte file that lies below a listed directory is ignored, so a cache that consists of empty marker files only is not seen, and a hard link below a listed directory always counts. Without a filesystem index the engine probe reports every existing path, empty or not.",
	},
	{
		ID: "FS-03", Name: "Exclusion of Build Compilers from Production", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Checks the file names of a fixed list of build tools (for example gcc, g++, make) in /bin, /usr/bin, /usr/local/bin, /sbin and /usr/sbin of the merged filesystem.",
		Evidence: "The tools that were found, in the message.",
		Limits:   "Name based. A renamed or versioned binary (gcc-12) is not seen, other toolchains are not covered, and a build tool that the application needs counts as a failure.",
	},
	{
		ID: "FS-04", Name: "SUID/SGID Privilege Escalation Vectors", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Fails when the merged filesystem holds a regular file with the setuid or setgid mode bit. A hard link takes the mode of the file it names in the same layer, because both are one inode.",
		Evidence: "The paths, sorted, in the message.",
		Limits:   "Some executables legitimately need the bits. The check cannot know which do, so every such file counts. Mode bits are those recorded in the layers. A hard link whose target is not a file of the same layer has no readable mode: when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE), because the OCI image specification warns that such links may not extract and a lower layer's mode is not kept.",
	},
	{
		ID: "FS-05", Name: "World-Writable File Elimination", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Fails when the merged filesystem holds a regular file whose mode has the world-writable bit. Directories and symbolic links are not counted. A hard link takes the mode of the file it names in the same layer, because both are one inode.",
		Evidence: "The paths, sorted, in the message.",
		Limits:   "Mode bits as recorded in the layers, not effective permissions (ACLs, mount options and user namespaces are not considered). A hard link whose target is not a file of the same layer has no readable mode: when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE).",
	},
	{
		ID: "FS-06", Name: fs06Name, Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Reads the content of files named *.key, *.pem, id_rsa, id_ed25519, id_dsa or id_ecdsa (up to 1 MiB) and looks for a PEM or OpenSSH private-key block. Findings under testdata, test, tests, fixtures, fixture, examples or example path components, and Debian snakeoil files, are fixture candidates and are counted separately. Only the other findings fail the check.",
		Evidence: "Finding paths and fixture candidate paths, sorted. The list of fixture candidates is capped at 200 entries; the message states the full counts.",
		Limits:   "Covers the named file patterns and PEM/OpenSSH formats only, not arbitrary files or other encodings. It does not know whether a key is a test key, and the fixture rule is a path heuristic. UNVERIFIED when a candidate is truncated or uses an unsupported encoding.",
	},
	{
		ID: "FS-07", Name: fs07Name, Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Matches the exact file names phpunit.xml, phpunit.xml.dist, jest.config.js and pytest.ini and the whole path component sequences testdata, tests/phpunit and tests/assets. A test directory is reported once, as the shallowest match. Matches under fixture-like components are fixture candidates, counted separately. Only the other matches fail the check.",
		Evidence: "Finding paths and fixture candidate paths, sorted.",
		Limits:   "A fixed list of four file names and three directory patterns, so most test frameworks are not covered. The fixture split is a path heuristic. The check is exploratory unless adjudication shows adequate precision.",
	},
	{
		ID: "FS-08", Name: fs08Name, Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Reads the final /etc/passwd and /etc/shadow (up to 1 MiB each). An account with an empty password field fails.",
		Evidence: "The account names, sorted.",
		Limits:   "Reads the account files of the final image only. It does not judge hash strength. UNVERIFIED (EVIDENCE_INCOMPLETE) when a file is missing, oversized or malformed.",
	},
	{
		ID: "FS-09", Name: "System Directory Ownership Hygiene", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Fails when a regular file in /bin, /usr/bin, /sbin or /usr/sbin has an owner UID other than 0 in the layer metadata. A hard link takes the owner of the file it names in the same layer, because both are one inode.",
		Evidence: "The paths with their UIDs, sorted.",
		Limits:   "The owner recorded in the layers. User namespace remapping and later ownership changes by the runtime are not considered. A hard link in one of the four directories whose target is not a file of the same layer has no readable owner: when nothing else fails the result is UNVERIFIED (EVIDENCE_INCOMPLETE). Unresolved links elsewhere in the tree do not affect this check.",
	},
	{
		ID: "DISTRO-02", Name: "Interactive Shell Elimination", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Fails when sh, bash, zsh, dash, ash, csh or tcsh exists in /bin, /usr/bin, /usr/local/bin, /sbin or /usr/sbin of the merged filesystem.",
		Evidence: "The shell names that were found.",
		Limits:   "Name based and limited to the listed shells. A path counts even if it is a link to a multi-call binary.",
	},
	{
		ID: "DISTRO-03", Name: "Package Manager Utility Elimination", Tier: spec.TierFilesystem,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Fails when apk, apt, apt-get, dpkg, yum, rpm, dnf, microdnf, pacman, pip or npm exists in the standard binary directories of the merged filesystem.",
		Evidence: "The utility names that were found.",
		Limits:   "Name based and limited to the listed utilities.",
	},

	{
		ID: "EXEC-01", Name: "Read-Only Root Filesystem Conformance", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   tier3OracleText + " Treatment: --read-only with a 64 MiB writable tmpfs at /tmp.",
		Evidence: tier3EvidenceText,
		Limits:   tier3LimitsText + " The related hardening recommendation concerns how an operator runs a container. This check shows whether the image still starts that way.",
	},
	{
		ID: "EXEC-02", Name: "Dropped Linux Capabilities Conformance", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   tier3OracleText + " Treatment: --cap-drop=ALL.",
		Evidence: tier3EvidenceText,
		Limits:   tier3LimitsText + " The related hardening recommendation concerns how an operator runs a container. This check shows whether the image still starts without capabilities, not which capability it needs.",
	},
	{
		ID: "EXEC-03", Name: "Graceful Signal Handling (SIGTERM)", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   "Same baseline gate as the other Tier 3 checks. A container that is running at the end of W receives SIGTERM. It passes when it exits with code 0 or 143 within the timeout (5 s in the shipped packs) and fails when it stays running or exits with another code.",
		Evidence: tier3EvidenceText,
		Limits:   "Observes one signal after the window under the baseline profile. An image whose entrypoint is a shell may forward or swallow the signal for reasons that depend on the process tree, which the check does not examine.",
	},
	{
		ID: "EXEC-04", Name: "No-New-Privileges Kernel Contract", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   tier3OracleText + " Treatment: --security-opt=no-new-privileges:true.",
		Evidence: tier3EvidenceText,
		Limits:   tier3LimitsText + " The related hardening recommendation concerns how an operator runs a container. This check shows whether the image still starts that way.",
	},
	{
		ID: "EXEC-05", Name: "Arbitrary Non-Root UID Conformance", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   tier3OracleText + " Treatment: --user 10001:10001 (the UID of the shipped Kubernetes pack).",
		Evidence: tier3EvidenceText,
		Limits:   tier3LimitsText + " It models the arbitrary-UID rule of OpenShift restricted SCC without the group ownership that the platform adds.",
	},
	{
		ID: "EXEC-06", Name: "HTTP Operational Readiness Contract", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   "Starts the container with the given port published on a free local port and polls the given path until the expected status or a timeout.",
		Evidence: "The last status or error, in the message.",
		Limits:   "Not baseline controlled, and not part of any shipped pack. The result depends on the port, path and timeout the caller chooses.",
	},
	{
		ID: "EXEC-07", Name: "Resource Constraint Conformance", Tier: spec.TierContract,
		Meta:     customRule(spec.ScopeRuntimeCompat),
		Oracle:   tier3OracleText + " Treatment: --memory=256m. The PID limit is part of the baseline profile, so the treatment differs from the baseline by memory only.",
		Evidence: tier3EvidenceText,
		Limits:   tier3LimitsText + " The 256 MiB limit is a property of the profile: a different limit can give a different verdict.",
	},
	{
		ID: "EXEC-08", Name: "Kubernetes PSS Restricted Profile Conformance", Tier: spec.TierContract,
		Meta: spec.RuleMeta{
			Standard: standardPSS, ControlTitle: "Restricted profile (container runtime settings)",
			Mapping: spec.MappingApproximate, Scope: spec.ScopeRuntimeCompat,
		},
		Oracle:   tier3OracleText + " Treatment: read-only root with a 64 MiB tmpfs at /tmp, --cap-drop=ALL, no-new-privileges and --user 10001:10001 together.",
		Evidence: tier3EvidenceText,
		Limits:   tier3LimitsText + " Only four of the settings of the Restricted profile are applied. The profile also constrains volumes, seccomp and other pod fields that a container run cannot show.",
	},

	{
		ID: "SUP-01", Name: "Prohibited Network Reconnaissance Tools", Tier: spec.TierSupplyChain,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Generates a package inventory with Syft (run once per image and cached) and fails when a package name of the caller's list is present, compared case-insensitively.",
		Evidence: "The prohibited package names that were found, in the message.",
		Limits:   "Only as complete as the Syft inventory. UNVERIFIED (TOOL_UNAVAILABLE) when Syft is missing or fails. No shipped pack uses this check.",
	},
	{
		ID: "SUP-02", Name: "Cryptographic Image Provenance & Signature", Tier: spec.TierSupplyChain,
		Meta:     customRule(spec.ScopeMetadataDeclaration),
		Oracle:   "Verifies the signature of the immutable image reference with the verifier and trust policy that the caller configures (a cosign key, or a keyless identity and issuer).",
		Evidence: "The verifier error, in the message, when verification fails.",
		Limits:   "UNVERIFIED (NO_TRUST_POLICY) whenever no trust policy is configured, which is the default, so the result is excluded from prevalence statistics unless a policy is given. It does not cover the Docker Content Trust setting of the scanning host.",
	},
	{
		ID: "SUP-03", Name: "SPDX License Compliance", Tier: spec.TierSupplyChain,
		Meta:     customRule(spec.ScopeImageContent),
		Oracle:   "Reads the package licenses from the cached Syft inventory and fails when a license is outside the allowlist (default Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0). When no license is violated but a package has no or unparsable license metadata, the result is UNVERIFIED. A violation takes precedence.",
		Evidence: "The violating packages with their licenses and the packages without usable metadata, sorted, in the message.",
		Limits:   "Only as complete as the Syft license metadata. The allowlist is a policy choice. No shipped pack uses this check.",
	},
}

var ruleIndex = func() map[string]*Rule {
	index := make(map[string]*Rule, len(ruleCatalog)+len(lintRuleCatalog))
	for i := range ruleCatalog {
		index[ruleCatalog[i].ID] = &ruleCatalog[i]
	}
	for i := range lintRuleCatalog {
		index[lintRuleCatalog[i].ID] = &lintRuleCatalog[i]
	}
	return index
}()

// Rules returns a copy of the rule catalog sorted by tier and ID. The catalog
// of the lint pack checks (rules_lint.go) is part of it.
func Rules() []Rule {
	rules := append(append([]Rule(nil), ruleCatalog...), lintRuleCatalog...)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Tier != rules[j].Tier {
			return rules[i].Tier < rules[j].Tier
		}
		return rules[i].ID < rules[j].ID
	})
	return rules
}

// RuleByID returns the catalog entry of a rule ID.
func RuleByID(id string) (Rule, bool) {
	rule, ok := ruleIndex[id]
	if !ok {
		return Rule{}, false
	}
	return *rule, true
}

// ruleMetaFor returns the standard mapping of a rule, or nil for an ID that is
// not in the catalog. Every result carries its own copy.
func ruleMetaFor(id string) *spec.RuleMeta {
	rule, ok := ruleIndex[id]
	if !ok {
		return nil
	}
	meta := rule.Meta
	return &meta
}

// canonicalRuleName returns the stable name of a catalogued rule, so that one
// ID always has one name in the results. Callers that use an ID outside the
// catalog (custom tests) keep the name they gave.
func canonicalRuleName(id, name string) string {
	if rule, ok := ruleIndex[id]; ok {
		return rule.Name
	}
	return name
}
