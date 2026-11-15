package runenv

import (
	"fmt"
	"strings"

	"github.com/con-unit/con-unit/pkg/spec"
)

// modeInputs are the detected facts ExecutionMode is derived from.
type modeInputs struct {
	Virtualization string
	Remote         bool
	EngineName     string
	Rootless       *bool
	Cgroup         string
}

// deriveExecutionMode renders a human-readable summary such as
// "Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2". Every
// phrase comes from a detected fact. A fact that is unknown is said to be
// unknown or left out, never filled in.
func deriveExecutionMode(in modeInputs) string {
	parts := []string{hostPhrase(in)}
	parts = append(parts, enginePhrase(in.EngineName, in.Rootless))
	if in.Cgroup != "" {
		parts = append(parts, "cgroup "+in.Cgroup)
	}
	return strings.Join(parts, ", ")
}

func hostPhrase(in modeInputs) string {
	if in.Remote {
		return "Remote container engine (host not inspected)"
	}
	switch in.Virtualization {
	case VirtAWSNitroKVM:
		return "Virtualized host (AWS Nitro, KVM)"
	case VirtAWSNitroMetal:
		return "Bare-metal host (AWS Nitro metal instance)"
	case VirtAWSNitro:
		return "AWS Nitro host (virtual machine or metal undetermined)"
	case VirtAWSXen:
		return "Virtualized host (AWS, Xen)"
	case VirtAppleVirtualization:
		return "Virtualized host (Linux VM on macOS, Apple Virtualization)"
	case VirtAppleHypervisorLibkrun:
		return "Virtualized host (Linux VM on macOS, libkrun on Apple Hypervisor)"
	case VirtQEMUHVF:
		return "Virtualized host (Linux VM on macOS, QEMU with HVF)"
	case VirtMacOSVM:
		return "Virtualized host (Linux VM on macOS, hypervisor undetermined)"
	case VirtVMOther:
		return "Virtualized host (hypervisor not identified)"
	case VirtBareMetal:
		return "Bare-metal host"
	case VirtUnknown, "":
		return "Host of unknown virtualization"
	}
	return "Virtualized host (" + in.Virtualization + ")"
}

func enginePhrase(name string, rootless *bool) string {
	display := ""
	switch name {
	case "":
		return "no container engine detected"
	case enginePodman:
		display = "Podman"
	case engineDocker:
		display = "Docker Engine"
	default:
		display = name
	}
	switch {
	case rootless == nil:
		return display + " (rootless state unknown)"
	case *rootless:
		return "rootless " + display
	}
	return "rootful " + display
}

// DescribeHost renders the run environment as one compact line for logs, for
// example:
//
//	mode: Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2 | cloud: aws c6i.2xlarge eu-central-1b | os: linux/amd64 kernel 6.8.0-1018-aws | cpu: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz, 8 vCPU, 15.5 GiB | engine: podman 4.9.3 (overlay, crun 1.14.1) | commit: 0123456789ab
//
// Segments without detected facts are left out.
func DescribeHost(meta spec.RunMetadata) string {
	var segs []string
	add := func(label, value string) {
		if value != "" {
			segs = append(segs, label+": "+value)
		}
	}

	add("mode", meta.ExecutionMode)
	if meta.ExecutionMode == "" {
		add("virt", meta.Virtualization)
	}
	add("cloud", joinNonEmpty(" ", meta.CloudProvider, meta.InstanceType, firstNonEmpty(meta.Zone, meta.Region), meta.AMIID))

	osArch := joinNonEmpty("/", meta.HostOS, meta.HostArch)
	if meta.LinuxKernel != "" {
		osArch = joinNonEmpty(" ", osArch, "kernel "+meta.LinuxKernel)
	}
	add("os", osArch)

	var cpu []string
	if meta.CPUModel != "" {
		cpu = append(cpu, meta.CPUModel)
	}
	if meta.VCPUs > 0 {
		cpu = append(cpu, fmt.Sprintf("%d vCPU", meta.VCPUs))
	}
	if meta.MemoryBytes > 0 {
		cpu = append(cpu, fmt.Sprintf("%.1f GiB", float64(meta.MemoryBytes)/(1<<30)))
	}
	add("cpu", strings.Join(cpu, ", "))

	if meta.EngineName != "" {
		engine := joinNonEmpty(" ", meta.EngineName, meta.EngineVersion)
		var details []string
		if meta.StorageDriver != "" {
			details = append(details, meta.StorageDriver)
		}
		if meta.OCIRuntime != "" {
			details = append(details, meta.OCIRuntime)
		}
		if len(details) > 0 {
			engine += " (" + strings.Join(details, ", ") + ")"
		}
		add("engine", engine)
	}

	if meta.Commit != "" {
		commit := meta.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		switch {
		case meta.CommitDirty:
			commit += " (dirty)"
		case meta.Tainted:
			commit += " (tainted)"
		}
		add("commit", commit)
	}

	if len(segs) == 0 {
		return "host: unknown"
	}
	return strings.Join(segs, " | ")
}

func joinNonEmpty(sep string, parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
