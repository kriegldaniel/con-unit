// Package runenv detects the environment of an evaluation run so that every
// result artifact can state exactly where and how it was produced.
//
// The contract (field names and semantics) is frozen in pkg/spec and
// docs/CONTRACT.md. Facts are detected, never assumed. Every external probe
// (engine CLI, sysctl, systemd-detect-virt, tool version flags, AWS instance
// metadata) is bounded in time and can only fail by leaving its facts empty,
// so Detect never fails the run. Probes run concurrently, so Detect finishes
// within a few seconds even when everything hangs.
//
// Bounds: external commands at most 2 s each, the whole IMDSv2 exchange at
// most 1 s. Detect is built from small seams (Env) for files, commands and
// HTTP, which tests replace with fixtures through DetectWith.
package runenv

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

// Build identity. The AWS bundle is built from `git archive`, which carries no
// VCS metadata, so the build script injects the identity:
//
//	go build -ldflags "-X github.com/con-unit/con-unit/pkg/runenv.BuildCommit=<sha> \
//	                   -X github.com/con-unit/con-unit/pkg/runenv.BuildTainted=<true|false>"
//
// When set, these take precedence over the Go build info.
var (
	BuildCommit  string // full commit SHA of the source tree
	BuildTainted string // "true" or "1" when the bundle was built with --allow-dirty or from a dirty tree
)

// Options carries the run configuration that cannot be detected from the host.
type Options struct {
	Version       string        // ConUnit version string
	EngineBinary  string        // path of the container engine binary, empty if none
	DatasetPath   string        // image list given to eval, empty for single-image runs
	Pack          string        // pack name as given on the command line
	PackID        string        // resolved pack ID
	Platform      string        // requested platform, for example linux/amd64
	ImageSource   string        // auto | local | registry
	ProbeWindow   time.Duration // Tier 3 observation window W
	Flags         []string      // raw command line flags
	AllowDirty    bool          // the bundle was built from a dirty tree
	RegistryRemap string        // active registry remap, if any
}

// Detect gathers run metadata from the real host. StartedAt is set to the
// current time; FinishedAt is left to the caller.
func Detect(ctx context.Context, opts Options) spec.RunMetadata {
	return DetectWith(ctx, opts, DefaultEnv())
}

// DetectWith is Detect with an injectable environment, used by tests.
func DetectWith(ctx context.Context, opts Options, env Env) spec.RunMetadata {
	if ctx == nil {
		ctx = context.Background()
	}
	env = env.withDefaults()

	meta := spec.RunMetadata{
		ConUnitVersion: opts.Version,
		GoVersion:      runtime.Version(),
		DatasetPath:    opts.DatasetPath,
		Pack:           opts.Pack,
		PackID:         opts.PackID,
		Platform:       opts.Platform,
		ImageSource:    opts.ImageSource,
		ProbeWindowMs:  opts.ProbeWindow.Milliseconds(),
		Flags:          append([]string(nil), opts.Flags...),
		RegistryRemap:  opts.RegistryRemap,
		HostOS:         env.OS,
		HostArch:       env.Arch,
		StartedAt:      env.Now().UTC(),
	}
	applyBuildIdentity(&meta, opts, env)

	engineBin := strings.TrimSpace(opts.EngineBinary)
	podmanBin := isPodmanBinary(engineBin)

	// Stage 1: independent probes, concurrent.
	var (
		eng     engineFacts
		host    hostFacts
		dmi     dmiFacts
		sdv     string
		imds    imdsFacts
		tools   map[string]string
		machine machineFacts
		dataSHA string
	)
	parallel(
		func() { eng = probeEngine(ctx, env, engineBin) },
		func() { host = probeHost(ctx, env) },
		func() {
			if env.OS != "linux" {
				return
			}
			dmi = readDMI(env)
			// IMDS is only queried when DMI or systemd-detect-virt point to
			// EC2, so other hosts never wait on the link-local address.
			if awsSuspected(dmi) {
				parallel(
					func() { sdv = probeSystemdVirt(ctx, env) },
					func() { imds = probeIMDS(ctx, env) },
				)
				return
			}
			sdv = probeSystemdVirt(ctx, env)
			if sdv == systemdVirtAmazon {
				imds = probeIMDS(ctx, env)
			}
		},
		func() { tools = probeTools(ctx, env) },
		func() {
			if env.OS == "darwin" && podmanBin {
				machine = probeMachine(ctx, env, engineBin)
			}
		},
		func() {
			if opts.DatasetPath != "" {
				if sum, err := SHA256File(opts.DatasetPath); err == nil {
					dataSHA = sum
				}
			}
		},
	)
	meta.DatasetSHA256 = dataSHA
	meta.Tools = tools

	// Stage 2: derive facts that depend on several probes.
	remote := engineIsRemote(eng, env.OS, env.Getenv)

	meta.EngineName = eng.Name
	meta.EngineVersion = eng.Version
	meta.Rootless = eng.Rootless
	meta.CgroupVersion = eng.Cgroup
	meta.StorageDriver = eng.Storage
	meta.OCIRuntime = eng.Runtime
	meta.SecurityOptions = eng.Security

	if remote {
		// The host being inspected is not where the containers run, so its
		// CPU, memory, DMI and cloud identity must not be reported as such.
		meta.LinuxKernel = eng.Kernel
		meta.VCPUs = eng.CPUs
		meta.MemoryBytes = eng.MemBytes
	} else {
		meta.LinuxKernel = firstNonEmpty(eng.Kernel, host.Kernel)
		if meta.LinuxKernel == "" && env.OS == "darwin" && podmanBin {
			meta.LinuxKernel = probeMachineKernel(ctx, env, engineBin)
		}
		meta.CPUModel = host.CPUModel
		meta.VCPUs = host.VCPUs
		meta.MemoryBytes = host.MemBytes
		if meta.CgroupVersion == "" && env.OS == "linux" {
			if _, ok := env.readFile("/sys/fs/cgroup/cgroup.controllers"); ok {
				meta.CgroupVersion = "v2"
			}
		}
	}

	instanceType := ""
	if !remote && env.OS == "linux" && isAWS(dmi, sdv, imds.InstanceType) {
		meta.CloudProvider = CloudAWS
		instanceType = imds.InstanceType
		if instanceType == "" && awsSuspected(dmi) {
			instanceType = dmiInstanceType(dmi)
		}
		meta.InstanceType = instanceType
		meta.AMIID = imds.AMIID
		meta.Region = imds.Region
		meta.Zone = imds.Zone
	}

	meta.Virtualization = deriveVirtualization(virtInputs{
		OS:            env.OS,
		DMI:           dmi,
		SystemdVirt:   sdv,
		InstanceType:  instanceType,
		Engine:        eng,
		MachineVMType: machine.VMType,
		Remote:        remote,
	})
	meta.ExecutionMode = deriveExecutionMode(modeInputs{
		Virtualization: meta.Virtualization,
		Remote:         remote,
		EngineName:     meta.EngineName,
		Rootless:       meta.Rootless,
		Cgroup:         meta.CgroupVersion,
	})
	return meta
}

// applyBuildIdentity fills commit, dirty and tainted flags. Values injected
// with -ldflags win over the Go build info, which is absent for bundles built
// from a git archive.
func applyBuildIdentity(meta *spec.RunMetadata, opts Options, env Env) {
	injectedTaint := isTruthy(BuildTainted)
	if commit := strings.TrimSpace(BuildCommit); commit != "" {
		meta.Commit = commit
		meta.CommitDirty = injectedTaint
	} else if info, ok := env.BuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				meta.Commit = setting.Value
			case "vcs.modified":
				meta.CommitDirty = setting.Value == "true"
			}
		}
	}
	meta.Tainted = opts.AllowDirty || injectedTaint || meta.CommitDirty
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "dirty", "tainted":
		return true
	}
	return false
}

func isPodmanBinary(binary string) bool {
	if binary == "" {
		return false
	}
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(binary), ".exe"))
	return strings.Contains(base, enginePodman)
}
