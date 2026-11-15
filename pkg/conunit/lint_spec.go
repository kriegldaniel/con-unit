package conunit

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
	"github.com/google/go-containerregistry/pkg/name"
)

// The names are stable per rule ID and identical in the catalog, so reports
// and exporters can key on them.
const (
	spec09Name = "Update Instruction Combined With Install"
	spec10Name = "No Sudo in the Build History"
	spec11Name = "No Distribution Upgrade in the Build History"
	spec12Name = "No Sensitive Host Paths as Volumes"
	spec13Name = "Explicit Non-Latest Image Reference"
)

const dockleCheckpoints = "https://github.com/goodwithtech/dockle/blob/v0.4.15/CHECKPOINT.md"

// historyEvidence returns the scanned history of the container index, or
// records UNVERIFIED and returns false when there is no index.
func (s *SpecAssertions) historyEvidence(id, ruleName string, start time.Time) (historyScan, bool) {
	if s.c.OCIIndex == nil {
		s.c.recordMissingOCIIndex(id, ruleName, spec.TierSpec, start)
		return historyScan{}, false
	}
	return scanHistory(s.c.OCIIndex), true
}

// recordHistoryVerdict is the shared ending of the three history checks. A
// finding fails the check even when the history is otherwise incomplete,
// because a finding is an observation. Without a finding, incomplete evidence
// makes the check UNVERIFIED.
func (s *SpecAssertions) recordHistoryVerdict(id, ruleName string, start time.Time, scan historyScan, findings []commandFinding, failMessage, explanation, remediation, reference, passMessage string) {
	switch {
	case len(findings) > 0:
		s.c.RecordFailure(id, ruleName, spec.TierSpec, time.Since(start),
			fmt.Sprintf("%s: %s", failMessage, describeFindings(findings)), explanation, remediation, reference)
	case scan.Issue != "":
		s.c.RecordUnverifiedDetail(id, ruleName, spec.TierSpec, time.Since(start),
			fmt.Sprintf("The recorded build history cannot be read completely, so the check is unverified: %s", scan.Issue),
			"Build the image so that its OCI history records every RUN instruction, and do not strip the history", reference,
			ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
	default:
		s.c.RecordPass(id, ruleName, spec.TierSpec, time.Since(start), passMessage)
	}
}

// UpdateCombinedWithInstall is SPEC-09. It fails when a recorded RUN step
// refreshes the apt package index without a later install or upgrade in the
// same step.
func (s *SpecAssertions) UpdateCombinedWithInstall() *SpecAssertions {
	start := time.Now()
	scan, ok := s.historyEvidence("SPEC-09", spec09Name, start)
	if !ok {
		return s
	}
	s.recordHistoryVerdict("SPEC-09", spec09Name, start, scan, updatesWithoutInstall(scan.Steps),
		"Recorded build steps update the package index without a later install or upgrade in the same step",
		"A package index update in a step of its own is cached as a layer, so a later build can reuse a stale index and install outdated packages.",
		"Run the update and the install in one RUN instruction, for example apt-get update && apt-get install -y <packages>",
		"https://www.cisecurity.org/benchmark/docker (update instructions combined with install); "+dockleCheckpoints+"#cis-di-0007",
		"No recorded RUN step refreshes the apt package index without a later install or upgrade in the same step; the history can be incomplete and does not prove every Dockerfile instruction")
	return s
}

// NoSudoInHistory is SPEC-10. It fails when sudo is the command of a simple
// command of a recorded RUN step.
func (s *SpecAssertions) NoSudoInHistory() *SpecAssertions {
	start := time.Now()
	scan, ok := s.historyEvidence("SPEC-10", spec10Name, start)
	if !ok {
		return s
	}
	s.recordHistoryVerdict("SPEC-10", spec10Name, start, scan, sudoCommands(scan.Steps),
		"Recorded build steps run sudo",
		"sudo has unpredictable TTY and signal forwarding behavior in containers, and a build that needs it usually runs as the wrong user.",
		"Run the step as root before the USER instruction, or use a purpose built helper such as gosu or su-exec",
		"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user ; "+dockleCheckpoints+"#dkl-di-0001",
		"No recorded RUN step runs sudo as a command; the history can be incomplete and does not prove every Dockerfile instruction")
	return s
}

// NoDistUpgradeInHistory is SPEC-11. It fails when apt-get or apt runs the
// subcommand dist-upgrade in a recorded RUN step.
func (s *SpecAssertions) NoDistUpgradeInHistory() *SpecAssertions {
	start := time.Now()
	scan, ok := s.historyEvidence("SPEC-11", spec11Name, start)
	if !ok {
		return s
	}
	s.recordHistoryVerdict("SPEC-11", spec11Name, start, scan, distUpgradeCommands(scan.Steps),
		"Recorded build steps run a distribution upgrade",
		"A distribution upgrade changes the base image packages in bulk. Many essential packages cannot be upgraded inside an unprivileged container, and the result is not reproducible.",
		"Start from a newer base image instead of upgrading the distribution inside the build",
		"https://github.com/docker/docker.github.io/pull/12571 ; "+dockleCheckpoints+"#dkl-di-0003",
		"No recorded RUN step runs a distribution upgrade with apt-get or apt; the history can be incomplete and does not prove every Dockerfile instruction")
	return s
}

// sensitiveVolumeRoots are the host paths that an image must not declare as a
// volume or below one.
var sensitiveVolumeRoots = []string{"/dev", "/proc", "/sys"}

func sensitiveVolume(clean string) bool {
	for _, root := range sensitiveVolumeRoots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return true
		}
	}
	return false
}

// NoSensitiveVolumes is SPEC-12. It fails when the image config declares a
// volume at /dev, /proc or /sys or below one of them.
func (s *SpecAssertions) NoSensitiveVolumes() *SpecAssertions {
	start := time.Now()
	if s.c.Inspect == nil {
		s.c.recordMissingInspect("SPEC-12", spec12Name, spec.TierSpec, start)
		return s
	}
	declared := make([]string, 0, len(s.c.Inspect.Config.Volumes))
	for volume := range s.c.Inspect.Config.Volumes {
		declared = append(declared, volume)
	}
	sort.Strings(declared)

	var findings, unplaceable []string
	for _, volume := range declared {
		trimmed := strings.TrimSpace(volume)
		if !strings.HasPrefix(trimmed, "/") {
			unplaceable = append(unplaceable, fmt.Sprintf("%q", volume))
			continue
		}
		if sensitiveVolume(path.Clean(trimmed)) {
			findings = append(findings, volume)
		}
	}
	switch {
	case len(findings) > 0:
		s.c.RecordFailureDetail("SPEC-12", spec12Name, spec.TierSpec, time.Since(start),
			fmt.Sprintf("Image declares volumes at sensitive host paths: %v", findings),
			"A volume at /dev, /proc or /sys, or below them, lets the container hide or replace kernel interfaces of the host once the volume is mounted.",
			"Remove the VOLUME instruction for these paths",
			dockleCheckpoints+"#dkl-di-0002",
			ResultDetail{Evidence: &spec.Evidence{Paths: findings}})
	case len(unplaceable) > 0:
		s.c.RecordUnverifiedDetail("SPEC-12", spec12Name, spec.TierSpec, time.Since(start),
			fmt.Sprintf("Declared volume paths that are empty or not absolute cannot be placed in the file tree, so the check is unverified: %s", strings.Join(unplaceable, ", ")),
			"Declare volumes with absolute paths", dockleCheckpoints+"#dkl-di-0002",
			ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
	default:
		s.c.RecordPass("SPEC-12", spec12Name, spec.TierSpec, time.Since(start),
			fmt.Sprintf("None of the %d declared volume(s) is at or below /dev, /proc or /sys; mounts given at run time were not inspected", len(declared)))
	}
	return s
}

var (
	digestSyntax  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[+._-][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}$`)
	tagSyntax     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	imageIDSyntax = regexp.MustCompile(`^(?:sha256:)?[0-9a-f]{64}$`)
)

// referenceKind says how a requested image reference pins the content.
type referenceKind string

const (
	referenceDigest   referenceKind = "digest"
	referenceImageID  referenceKind = "image ID"
	referenceTag      referenceKind = "tag"
	referenceUntagged referenceKind = "no tag"
)

// classifyReference reads a requested image reference. A reference with a
// digest is pinned whatever tag comes with it. Without a digest it has an
// explicit tag, or none, which the engine reads as latest.
func classifyReference(ref string) (kind referenceKind, tag string, err error) {
	if strings.ContainsAny(ref, " \t\r\n") {
		return "", "", fmt.Errorf("the reference %q contains white space", ref)
	}
	if imageIDSyntax.MatchString(ref) {
		return referenceImageID, "", nil
	}
	repository, digest, hasDigest := strings.Cut(ref, "@")
	if hasDigest && !digestSyntax.MatchString(digest) {
		return "", "", fmt.Errorf("the digest of %q is malformed", ref)
	}
	if lastColon := strings.LastIndex(repository, ":"); lastColon > strings.LastIndex(repository, "/") {
		tag = repository[lastColon+1:]
		repository = repository[:lastColon]
		if !tagSyntax.MatchString(tag) {
			return "", "", fmt.Errorf("the tag of %q is malformed", ref)
		}
	}
	if _, parseErr := name.NewRepository(repository, name.WeakValidation); parseErr != nil || repository == "" {
		return "", "", fmt.Errorf("the repository of %q is malformed", ref)
	}
	switch {
	case hasDigest:
		return referenceDigest, tag, nil
	case tag == "":
		return referenceUntagged, "", nil
	}
	return referenceTag, tag, nil
}

// ExplicitNonLatestReference is SPEC-13. It fails when the requested image
// reference has no tag and no digest, or when its tag is latest.
func (s *SpecAssertions) ExplicitNonLatestReference() *SpecAssertions {
	start := time.Now()
	unverified := func(message string) *SpecAssertions {
		s.c.RecordUnverifiedDetail("SPEC-13", spec13Name, spec.TierSpec, time.Since(start), message,
			"Evaluate the image by its registry reference, not by a local archive path", dockleCheckpoints+"#dkl-di-0006",
			ResultDetail{Reason: spec.ReasonEvidenceIncomplete})
		return s
	}
	ref := strings.TrimSpace(s.c.RequestedRef)
	if ref == "" {
		return unverified("No requested image reference is recorded (a local archive has no image reference), so the check is unverified")
	}
	kind, tag, err := classifyReference(ref)
	if err != nil {
		return unverified(fmt.Sprintf("The requested reference cannot be read, so the check is unverified: %v", err))
	}
	switch {
	case kind == referenceUntagged || (kind == referenceTag && tag == "latest"):
		detail := "has no tag and no digest, so the engine resolves it to latest"
		if kind == referenceTag {
			detail = "uses the tag latest"
		}
		s.c.RecordFailure("SPEC-13", spec13Name, spec.TierSpec, time.Since(start),
			fmt.Sprintf("The requested reference %q %s", ref, detail),
			"latest is a moving name: the same reference can resolve to different content on different days, so a result cannot be reproduced from it.",
			"Request the image with an explicit version tag, or better with its digest (name@sha256:...)",
			dockleCheckpoints+"#dkl-di-0006")
	default:
		pinned := "an explicit tag, which can still be moved"
		if kind == referenceDigest || kind == referenceImageID {
			pinned = "a " + string(kind) + ", which names fixed content"
		}
		s.c.RecordPass("SPEC-13", spec13Name, spec.TierSpec, time.Since(start),
			fmt.Sprintf("The requested reference %q carries %s", ref, pinned))
	}
	return s
}
