package runenv

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

func boolPtr(b bool) *bool { return &b }

func rootlessString(p *bool) string {
	switch {
	case p == nil:
		return "unknown"
	case *p:
		return "rootless"
	}
	return "rootful"
}

// wantFacts lists the detected facts a scenario must produce.
type wantFacts struct {
	virtualization string
	executionMode  string
	cloud          string
	instanceType   string
	amiID          string
	region         string
	zone           string
	engineName     string
	engineVersion  string
	rootless       string // rootful | rootless | unknown
	cgroup         string
	storage        string
	ociRuntime     string
	security       []string
	kernel         string
	cpuModel       string
	vcpus          int
	memoryBytes    int64
	tools          map[string]string
	hostOS         string
	hostArch       string
}

func checkFacts(t *testing.T, meta spec.RunMetadata, want wantFacts) {
	t.Helper()
	check := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	check("Virtualization", meta.Virtualization, want.virtualization)
	check("ExecutionMode", meta.ExecutionMode, want.executionMode)
	check("CloudProvider", meta.CloudProvider, want.cloud)
	check("InstanceType", meta.InstanceType, want.instanceType)
	check("AMIID", meta.AMIID, want.amiID)
	check("Region", meta.Region, want.region)
	check("Zone", meta.Zone, want.zone)
	check("EngineName", meta.EngineName, want.engineName)
	check("EngineVersion", meta.EngineVersion, want.engineVersion)
	check("Rootless", rootlessString(meta.Rootless), want.rootless)
	check("CgroupVersion", meta.CgroupVersion, want.cgroup)
	check("StorageDriver", meta.StorageDriver, want.storage)
	check("OCIRuntime", meta.OCIRuntime, want.ociRuntime)
	check("SecurityOptions", meta.SecurityOptions, want.security)
	check("LinuxKernel", meta.LinuxKernel, want.kernel)
	check("CPUModel", meta.CPUModel, want.cpuModel)
	check("VCPUs", meta.VCPUs, want.vcpus)
	check("MemoryBytes", meta.MemoryBytes, want.memoryBytes)
	check("Tools", meta.Tools, want.tools)
	check("HostOS", meta.HostOS, want.hostOS)
	check("HostArch", meta.HostArch, want.hostArch)
}

func allToolsAbsent() map[string]string {
	return map[string]string{
		"syft": ToolAbsent, "cosign": ToolAbsent, "grype": ToolAbsent,
		"hadolint": ToolAbsent, "trivy": ToolAbsent, "container-structure-test": ToolAbsent,
		"dockle": ToolAbsent,
	}
}

func installedTools() map[string]string {
	return map[string]string{
		"syft": "1.55.0", "cosign": "v2.4.1", "grype": "0.120.0",
		"hadolint": "2.14.0", "trivy": "0.57.0", "container-structure-test": ToolAbsent,
		"dockle": "0.4.15",
	}
}

func TestDetectHostScenarios(t *testing.T) {
	const seccompDefault = "seccomp(profile=/usr/share/containers/seccomp.json)"

	// The bare-metal host reports a generic kernel instead of the AWS one.
	bareMetal := scenarioBareMetalDocker(t)
	bareMetal.cmds["docker info --format {{json .}}"] = reply{
		stdout: strings.ReplaceAll(readFixture(t, "docker_info_overlay2.out"), "6.8.0-1018-aws", "6.8.0-45-generic"),
	}
	bareMetal.imds = &fakeIMDS{token: fakeToken, answers: map[string]string{"instance-type": "must-not-be-read"}}

	cases := []struct {
		name         string
		scenario     scenario
		engineBinary string
		want         wantFacts
		imdsExpected bool // whether the link-local address may be contacted
	}{
		{
			name:         "aws c6i.2xlarge on ubuntu 24.04 with rootful podman",
			scenario:     scenarioC6i2xlarge(t),
			engineBinary: "/usr/bin/podman",
			imdsExpected: true,
			want: wantFacts{
				virtualization: "aws-nitro-kvm",
				executionMode:  "Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2",
				cloud:          "aws",
				instanceType:   "c6i.2xlarge",
				amiID:          "ami-0f1e2d3c4b5a69788",
				region:         "eu-central-1",
				zone:           "eu-central-1b",
				engineName:     "podman",
				engineVersion:  "4.9.3",
				rootless:       "rootful",
				cgroup:         "v2",
				storage:        "overlay",
				ociRuntime:     "crun 1.14.1",
				security:       []string{"apparmor", seccompDefault},
				kernel:         "6.8.0-1018-aws",
				cpuModel:       xeon8375C,
				vcpus:          8,
				memoryBytes:    16029392 * 1024,
				tools:          installedTools(),
				hostOS:         "linux",
				hostArch:       "amd64",
			},
		},
		{
			name:         "aws c6i.metal",
			scenario:     scenarioC6iMetal(t),
			engineBinary: "/usr/bin/podman",
			imdsExpected: true,
			want: wantFacts{
				virtualization: "aws-nitro-metal",
				executionMode:  "Bare-metal host (AWS Nitro metal instance), rootful Podman, cgroup v2",
				cloud:          "aws",
				instanceType:   "c6i.metal",
				amiID:          "ami-0f1e2d3c4b5a69788",
				region:         "eu-central-1",
				zone:           "eu-central-1b",
				engineName:     "podman",
				engineVersion:  "4.9.3",
				rootless:       "rootful",
				cgroup:         "v2",
				storage:        "overlay",
				ociRuntime:     "crun 1.14.1",
				security:       []string{"apparmor", seccompDefault},
				kernel:         "6.8.0-1018-aws",
				cpuModel:       xeon8375C,
				vcpus:          128,
				memoryBytes:    262144000 * 1024,
				tools:          installedTools(),
				hostOS:         "linux",
				hostArch:       "amd64",
			},
		},
		{
			name:         "macos with a libkrun podman machine",
			scenario:     scenarioMacPodmanMachine(t),
			engineBinary: "podman",
			want: wantFacts{
				virtualization: "apple-hypervisor-libkrun",
				executionMode:  "Virtualized host (Linux VM on macOS, libkrun on Apple Hypervisor), rootless Podman, cgroup v2",
				engineName:     "podman",
				engineVersion:  "5.8.1",
				rootless:       "rootless",
				cgroup:         "v2",
				storage:        "overlay",
				ociRuntime:     "crun 1.25.1",
				security:       []string{"rootless", seccompDefault, "selinux"},
				kernel:         "6.18.10-200.fc43.aarch64",
				cpuModel:       "Apple M2 Pro",
				vcpus:          12,
				memoryBytes:    17179869184,
				tools:          installedTools(),
				hostOS:         "darwin",
				hostArch:       "arm64",
			},
		},
		{
			name:         "generic bare-metal linux with docker",
			scenario:     bareMetal,
			engineBinary: "/usr/bin/docker",
			want: wantFacts{
				virtualization: "bare-metal",
				executionMode:  "Bare-metal host, rootful Docker Engine, cgroup v2",
				engineName:     "docker",
				engineVersion:  "27.3.1",
				rootless:       "rootful",
				cgroup:         "v2",
				storage:        "overlay2",
				ociRuntime:     "runc",
				security:       []string{"apparmor", "cgroupns", "seccomp(profile=builtin)"},
				kernel:         "6.8.0-45-generic",
				cpuModel:       "Intel(R) Xeon(R) Silver 4110 CPU @ 2.10GHz",
				vcpus:          16,
				memoryBytes:    65807976 * 1024,
				tools:          installedTools(),
				hostOS:         "linux",
				hostArch:       "amd64",
			},
		},
		{
			name:         "unknown host without dmi, engine or tools",
			scenario:     scenarioUnknownHost(),
			engineBinary: "",
			want: wantFacts{
				virtualization: "unknown",
				executionMode:  "Host of unknown virtualization, no container engine detected",
				rootless:       "unknown",
				vcpus:          4,
				tools:          allToolsAbsent(),
				hostOS:         "linux",
				hostArch:       "riscv64",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.scenario.build(t)
			meta := DetectWith(context.Background(), Options{
				Version:      "0.9.0-test",
				EngineBinary: tc.engineBinary,
				Pack:         "cis",
				PackID:       "PACK-CONUNIT-HARDENING",
				Platform:     "linux/amd64",
				ImageSource:  "local",
				ProbeWindow:  3 * time.Second,
				Flags:        []string{"--engine", "auto"},
			}, be.env)

			checkFacts(t, meta, tc.want)

			if meta.ConUnitVersion != "0.9.0-test" || meta.Pack != "cis" || meta.PackID != "PACK-CONUNIT-HARDENING" ||
				meta.Platform != "linux/amd64" || meta.ImageSource != "local" || meta.ProbeWindowMs != 3000 {
				t.Errorf("options not propagated: %+v", meta)
			}
			if !reflect.DeepEqual(meta.Flags, []string{"--engine", "auto"}) {
				t.Errorf("Flags = %v", meta.Flags)
			}
			if meta.GoVersion == "" {
				t.Errorf("GoVersion must be set")
			}
			if want := time.Date(2026, 11, 14, 13, 41, 8, 0, time.UTC); !meta.StartedAt.Equal(want) {
				t.Errorf("StartedAt = %v, want %v", meta.StartedAt, want)
			}
			if !meta.FinishedAt.IsZero() {
				t.Errorf("FinishedAt must be left to the caller, got %v", meta.FinishedAt)
			}
			if be.imds != nil && !tc.imdsExpected {
				if reqs := be.imds.requested(); len(reqs) != 0 {
					t.Errorf("link-local address contacted on a non-EC2 host: %v", reqs)
				}
			}
		})
	}
}

func TestDetectIMDSv2Protocol(t *testing.T) {
	be := scenarioC6i2xlarge(t).build(t)
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, be.env)

	reqs := be.imds.requested()
	if len(reqs) != 5 {
		t.Fatalf("requests = %v, want one PUT and four GETs", reqs)
	}
	if reqs[0] != "PUT /latest/api/token" {
		t.Errorf("first request = %q, want the IMDSv2 token PUT", reqs[0])
	}
	// The fake answers 401 to any GET without the session token, so complete
	// metadata proves that every GET carried the token.
	if meta.InstanceType == "" || meta.AMIID == "" || meta.Region == "" || meta.Zone == "" {
		t.Errorf("metadata incomplete: %+v", meta)
	}
}

func TestDetectMacPodmanKernelFallsBackToMachineSSH(t *testing.T) {
	s := scenarioMacPodmanMachine(t)
	noKernel := strings.Replace(readFixture(t, "podman_info_rootless_macos_libkrun.out"), `"kernel": "6.18.10-200.fc43.aarch64",`, `"kernel": "",`, 1)
	s.cmds["podman info --format json"] = reply{stdout: noKernel}
	s.cmds["podman machine ssh uname -r"] = reply{stdout: "6.18.10-200.fc43.aarch64\n"}
	be := s.build(t)

	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, be.env)
	if meta.LinuxKernel != "6.18.10-200.fc43.aarch64" {
		t.Errorf("LinuxKernel = %q, want the VM kernel from podman machine ssh", meta.LinuxKernel)
	}
	if !be.exec.called("podman machine ssh uname -r") {
		t.Errorf("podman machine ssh was not used as fallback")
	}
}

func TestDetectMacPodmanKernelEmptyWhenUnknown(t *testing.T) {
	s := scenarioMacPodmanMachine(t)
	noKernel := strings.Replace(readFixture(t, "podman_info_rootless_macos_libkrun.out"), `"kernel": "6.18.10-200.fc43.aarch64",`, `"kernel": "",`, 1)
	s.cmds["podman info --format json"] = reply{stdout: noKernel}
	s.cmds["podman machine ssh uname -r"] = reply{stderr: "no machine", err: errExit1}
	be := s.build(t)

	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, be.env)
	if meta.LinuxKernel != "" {
		t.Errorf("LinuxKernel = %q, want empty (never assume the macOS kernel)", meta.LinuxKernel)
	}
}

func TestDetectMacProviders(t *testing.T) {
	dockerDesktop := strings.NewReplacer(
		"Ubuntu 24.04.1 LTS", "Docker Desktop",
		"6.8.0-1018-aws", "6.10.14-linuxkit",
	).Replace(readFixture(t, "docker_info_overlay2.out"))
	plainDockerVM := strings.NewReplacer(
		"Ubuntu 24.04.1 LTS", "Ubuntu 24.04 LTS",
		"6.8.0-1018-aws", "6.8.0-45-generic",
	).Replace(readFixture(t, "docker_info_overlay2.out"))

	cases := []struct {
		name         string
		engineBinary string
		cmds         map[string]reply
		want         string
		wantMode     string
	}{
		{
			name:         "podman machine with apple virtualization framework",
			engineBinary: "podman",
			cmds: map[string]reply{
				"podman info --format json":         {stdout: readFixture(t, "podman_info_rootless_macos_libkrun.out")},
				"podman machine list --format json": {stdout: `[{"Name":"m","Default":true,"Running":true,"VMType":"applehv"}]`},
			},
			want:     "apple-virtualization",
			wantMode: "Virtualized host (Linux VM on macOS, Apple Virtualization), rootless Podman, cgroup v2",
		},
		{
			name:         "podman machine with qemu",
			engineBinary: "podman",
			cmds: map[string]reply{
				"podman info --format json":         {stdout: readFixture(t, "podman_info_rootless_macos_libkrun.out")},
				"podman machine list --format json": {stdout: `[{"Name":"m","Default":true,"Running":true,"VMType":"qemu"}]`},
			},
			want:     "qemu-hvf",
			wantMode: "Virtualized host (Linux VM on macOS, QEMU with HVF), rootless Podman, cgroup v2",
		},
		{
			name:         "podman machine list unavailable",
			engineBinary: "podman",
			cmds: map[string]reply{
				"podman info --format json": {stdout: readFixture(t, "podman_info_rootless_macos_libkrun.out")},
			},
			want:     "macos-vm",
			wantMode: "Virtualized host (Linux VM on macOS, hypervisor undetermined), rootless Podman, cgroup v2",
		},
		{
			name:         "stopped podman machine does not count",
			engineBinary: "podman",
			cmds: map[string]reply{
				"podman info --format json":         {stdout: readFixture(t, "podman_info_rootless_macos_libkrun.out")},
				"podman machine list --format json": {stdout: `[{"Name":"m","Default":true,"Running":false,"VMType":"applehv"}]`},
			},
			want:     "macos-vm",
			wantMode: "Virtualized host (Linux VM on macOS, hypervisor undetermined), rootless Podman, cgroup v2",
		},
		{
			name:         "docker desktop",
			engineBinary: "docker",
			cmds:         map[string]reply{"docker info --format {{json .}}": {stdout: dockerDesktop}},
			want:         "apple-virtualization",
			wantMode:     "Virtualized host (Linux VM on macOS, Apple Virtualization), rootful Docker Engine, cgroup v2",
		},
		{
			name:         "docker with a non desktop vm",
			engineBinary: "docker",
			cmds:         map[string]reply{"docker info --format {{json .}}": {stdout: plainDockerVM}},
			want:         "macos-vm",
			wantMode:     "Virtualized host (Linux VM on macOS, hypervisor undetermined), rootful Docker Engine, cgroup v2",
		},
		{
			name:         "engine unreachable on macos",
			engineBinary: "docker",
			cmds:         map[string]reply{"docker info --format {{json .}}": {stdout: readFixture(t, "docker_info_unreachable.out"), err: errExit1}},
			want:         "unknown",
			wantMode:     "Host of unknown virtualization, Docker Engine (rootless state unknown)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario{os: "darwin", arch: "arm64", cpus: 12, cmds: tc.cmds, installed: []string{"podman", "docker"}}
			be := s.build(t)
			meta := DetectWith(context.Background(), Options{EngineBinary: tc.engineBinary}, be.env)
			if meta.Virtualization != tc.want {
				t.Errorf("Virtualization = %q, want %q", meta.Virtualization, tc.want)
			}
			if meta.ExecutionMode != tc.wantMode {
				t.Errorf("ExecutionMode = %q, want %q", meta.ExecutionMode, tc.wantMode)
			}
		})
	}
}

func TestDetectLinuxVirtualizationVariants(t *testing.T) {
	podmanFixture := readFixture(t, "podman_info_rootful_ubuntu2404.out")
	base := func(dmi fakeFS, sdv *reply) scenario {
		cmds := map[string]reply{"podman info --format json": {stdout: podmanFixture}}
		if sdv != nil {
			cmds["systemd-detect-virt --vm"] = *sdv
		}
		installed := []string{"podman"}
		if sdv != nil {
			installed = append(installed, "systemd-detect-virt")
		}
		return scenario{
			os: "linux", arch: "amd64", cpus: 4,
			files: withFiles(dmi, fakeFS{
				"/proc/sys/kernel/osrelease": "6.8.0-1018-aws\n",
				"/proc/cpuinfo":              cpuInfoX86("Intel(R) Xeon(R)", 4),
				"/proc/meminfo":              memInfo(8000000),
			}),
			cmds:      cmds,
			installed: installed,
		}
	}
	kvmDMI := fakeFS{
		"/sys/class/dmi/id/sys_vendor":   "QEMU\n",
		"/sys/class/dmi/id/product_name": "Standard PC (Q35 + ICH9, 2009)\n",
		"/sys/class/dmi/id/bios_vendor":  "SeaBIOS\n",
	}
	xenDMI := fakeFS{
		"/sys/class/dmi/id/sys_vendor":   "Xen\n",
		"/sys/class/dmi/id/product_name": "HVM domU\n",
		"/sys/class/dmi/id/bios_vendor":  "Xen\n",
		"/sys/class/dmi/id/bios_version": "4.11.amazon\n",
	}
	dellDMI := fakeFS{
		"/sys/class/dmi/id/sys_vendor":   "Dell Inc.\n",
		"/sys/class/dmi/id/product_name": "PowerEdge R740\n",
	}

	cases := []struct {
		name  string
		s     scenario
		want  string
		cloud string
	}{
		{"qemu guest, systemd-detect-virt says kvm", base(kvmDMI, &reply{stdout: "kvm\n"}), "kvm", ""},
		{"qemu guest, no systemd-detect-virt", base(kvmDMI, nil), "qemu", ""},
		{"dmi shows a hypervisor but systemd-detect-virt says none", base(kvmDMI, &reply{stdout: "none\n", err: errExit1}), "unknown", ""},
		{"physical dmi, no systemd-detect-virt", base(dellDMI, nil), "bare-metal", ""},
		{"no dmi, systemd-detect-virt says none", base(fakeFS{}, &reply{stdout: "none\n", err: errExit1}), "bare-metal", ""},
		{"no dmi, no systemd-detect-virt", base(fakeFS{}, nil), "unknown", ""},
		{"systemd-detect-virt garbage is ignored", base(dellDMI, &reply{stdout: "Failed to connect to bus: No such file\n", err: errExit1}), "bare-metal", ""},
		{"ec2 xen instance", base(xenDMI, &reply{stdout: "xen\n"}), "aws-xen", "aws"},
		// Captured inside the libkrun podman machine: no DMI, and systemd-detect-virt
		// sees a VM without naming the hypervisor.
		{"libkrun guest without dmi", base(fakeFS{}, &reply{stdout: "vm-other\n"}), "vm-other", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.s.build(t)
			meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, be.env)
			if meta.Virtualization != tc.want {
				t.Errorf("Virtualization = %q, want %q", meta.Virtualization, tc.want)
			}
			if meta.CloudProvider != tc.cloud {
				t.Errorf("CloudProvider = %q, want %q", meta.CloudProvider, tc.cloud)
			}
		})
	}
}

func TestDetectEC2RecognisedBySystemdWhenDMIIsUnreadable(t *testing.T) {
	s := scenarioC6i2xlarge(t)
	for k := range s.files {
		if strings.HasPrefix(k, "/sys/class/dmi/id/") {
			delete(s.files, k)
		}
	}
	be := s.build(t)
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, be.env)
	if meta.CloudProvider != "aws" || meta.InstanceType != "c6i.2xlarge" || meta.Zone != "eu-central-1b" {
		t.Errorf("systemd-detect-virt amazon must trigger the IMDS probe: %+v", meta)
	}
	if meta.Virtualization != "aws-nitro-kvm" {
		t.Errorf("Virtualization = %q, want aws-nitro-kvm", meta.Virtualization)
	}
}

func TestDetectEC2WithoutIMDS(t *testing.T) {
	cases := []struct {
		name         string
		product      string
		sdv          *reply
		wantVirt     string
		wantInstance string
	}{
		{"dmi product name gives the instance type", "c6i.2xlarge", &reply{stdout: "amazon\n"}, "aws-nitro-kvm", "c6i.2xlarge"},
		{"dmi product name of a metal instance", "c6i.metal", &reply{stdout: "none\n", err: errExit1}, "aws-nitro-metal", "c6i.metal"},
		{"metal with size suffix", "m7i.metal-24xl", &reply{stdout: "none\n", err: errExit1}, "aws-nitro-metal", "m7i.metal-24xl"},
		{"product name unusable, systemd-detect-virt none", "Unknown Product", &reply{stdout: "none\n", err: errExit1}, "aws-nitro-metal", ""},
		{"product name unusable, systemd-detect-virt amazon", "Unknown Product", &reply{stdout: "amazon\n"}, "aws-nitro-kvm", ""},
		{"product name unusable, no systemd-detect-virt", "Unknown Product", nil, "aws-nitro", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario{
				os: "linux", arch: "amd64", cpus: 8,
				files: ec2DMI(tc.product), // IMDS stays unreachable
				cmds:  map[string]reply{},
			}
			if tc.sdv != nil {
				s.cmds["systemd-detect-virt --vm"] = *tc.sdv
				s.installed = []string{"systemd-detect-virt"}
			}
			meta := DetectWith(context.Background(), Options{}, s.build(t).env)
			if meta.Virtualization != tc.wantVirt {
				t.Errorf("Virtualization = %q, want %q", meta.Virtualization, tc.wantVirt)
			}
			if meta.InstanceType != tc.wantInstance {
				t.Errorf("InstanceType = %q, want %q", meta.InstanceType, tc.wantInstance)
			}
			if meta.CloudProvider != "aws" {
				t.Errorf("CloudProvider = %q, want aws", meta.CloudProvider)
			}
			if meta.AMIID != "" || meta.Region != "" || meta.Zone != "" {
				t.Errorf("IMDS facts must stay empty without IMDS: %+v", meta)
			}
		})
	}
}

func TestDetectRemoteEngineIsNotAttributedToThisHost(t *testing.T) {
	// ConUnit runs on an EC2 host, but the engine is a remote Docker daemon.
	// DMI, CPU and cloud identity of this host must not be reported as the
	// place where the containers run.
	s := scenarioC6i2xlarge(t)
	s.cmds["docker info --format {{json .}}"] = reply{stdout: readFixture(t, "docker_info_overlay2.out")}
	s.installed = append(s.installed, "docker")
	s.environ = map[string]string{"DOCKER_HOST": "ssh://builder@10.0.0.9"}
	be := s.build(t)

	meta := DetectWith(context.Background(), Options{EngineBinary: "docker"}, be.env)
	if meta.Virtualization != "unknown" {
		t.Errorf("Virtualization = %q, want unknown for a remote engine", meta.Virtualization)
	}
	if want := "Remote container engine (host not inspected), rootful Docker Engine, cgroup v2"; meta.ExecutionMode != want {
		t.Errorf("ExecutionMode = %q, want %q", meta.ExecutionMode, want)
	}
	if meta.CloudProvider != "" || meta.InstanceType != "" || meta.CPUModel != "" {
		t.Errorf("local host identity leaked into a remote run: %+v", meta)
	}
	if meta.VCPUs != 8 || meta.MemoryBytes != 16414105600 {
		t.Errorf("vCPUs and memory must come from the engine: %d, %d", meta.VCPUs, meta.MemoryBytes)
	}
	if meta.LinuxKernel != "6.8.0-1018-aws" {
		t.Errorf("LinuxKernel = %q, want the engine kernel", meta.LinuxKernel)
	}
}

func TestDetectPodmanServiceRemoteOnLinux(t *testing.T) {
	s := scenarioC6i2xlarge(t)
	remote := strings.Replace(readFixture(t, "podman_info_rootful_ubuntu2404.out"), `"serviceIsRemote": false`, `"serviceIsRemote": true`, 1)
	s.cmds["podman info --format json"] = reply{stdout: remote}
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, s.build(t).env)
	if meta.Virtualization != "unknown" || !strings.HasPrefix(meta.ExecutionMode, "Remote container engine") {
		t.Errorf("remote podman service not recognised: %q / %q", meta.Virtualization, meta.ExecutionMode)
	}
}

func TestDetectUsesCgroupFileWhenEngineIsSilent(t *testing.T) {
	s := scenarioC6i2xlarge(t)
	delete(s.cmds, "podman info --format json")
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, s.build(t).env)
	if meta.CgroupVersion != "v2" {
		t.Errorf("CgroupVersion = %q, want v2 from /sys/fs/cgroup/cgroup.controllers", meta.CgroupVersion)
	}
	if meta.EngineName != "podman" || meta.EngineVersion != "" {
		t.Errorf("engine name must come from the binary, version stays empty: %q %q", meta.EngineName, meta.EngineVersion)
	}
	if want := "Virtualized host (AWS Nitro, KVM), Podman (rootless state unknown), cgroup v2"; meta.ExecutionMode != want {
		t.Errorf("ExecutionMode = %q, want %q", meta.ExecutionMode, want)
	}
}

func TestDetectNeverFailsWhenEveryProbeHangs(t *testing.T) {
	// Every command ignores its context and blocks forever, and IMDS never
	// answers. Detect must still return, bounded by the probe timeouts.
	s := scenarioC6i2xlarge(t)
	for key := range s.cmds {
		s.cmds[key] = reply{stuck: true}
	}
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	s.imds = &fakeIMDS{token: fakeToken, stuck: stuck}
	be := s.build(t)
	be.env.CommandTimeout = 150 * time.Millisecond
	be.env.IMDSTimeout = 100 * time.Millisecond

	start := time.Now()
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, be.env)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Fatalf("Detect took %v with hanging probes, want it bounded by the timeouts", elapsed)
	}
	if meta.EngineVersion != "" || meta.AMIID != "" || meta.Region != "" {
		t.Errorf("hanging probes must leave facts empty: %+v", meta)
	}
	// File based facts still arrive, and the missing probes degrade honestly.
	if meta.CPUModel != xeon8375C || meta.VCPUs != 8 {
		t.Errorf("file based facts lost: %q %d", meta.CPUModel, meta.VCPUs)
	}
	if meta.Virtualization != "aws-nitro-kvm" {
		t.Errorf("Virtualization = %q, want aws-nitro-kvm from the DMI product name", meta.Virtualization)
	}
	for name, v := range meta.Tools {
		want := ToolVersionUnknown // installed, but the version probe hangs
		if name == "container-structure-test" {
			want = ToolAbsent // not installed in this scenario
		}
		if v != want {
			t.Errorf("tool %s = %q, want %q", name, v, want)
		}
	}
}

func TestDetectHonorsCanceledContext(t *testing.T) {
	be := scenarioC6i2xlarge(t).build(t)
	be.env.CommandTimeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	meta := DetectWith(ctx, Options{EngineBinary: "podman"}, be.env)
	if time.Since(start) > time.Second {
		t.Errorf("Detect ignored a canceled context")
	}
	if meta.StartedAt.IsZero() || meta.HostOS == "" {
		t.Errorf("static facts must still be present: %+v", meta)
	}
}

func TestDetectDatasetSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "images.txt")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := DetectWith(context.Background(), Options{DatasetPath: path}, scenarioUnknownHost().build(t).env)
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if meta.DatasetSHA256 != abc {
		t.Errorf("DatasetSHA256 = %q, want %q", meta.DatasetSHA256, abc)
	}
	if meta.DatasetPath != path {
		t.Errorf("DatasetPath = %q", meta.DatasetPath)
	}

	missing := DetectWith(context.Background(), Options{DatasetPath: filepath.Join(t.TempDir(), "absent.txt")}, scenarioUnknownHost().build(t).env)
	if missing.DatasetSHA256 != "" {
		t.Errorf("a missing dataset must leave the hash empty, got %q", missing.DatasetSHA256)
	}
	none := DetectWith(context.Background(), Options{}, scenarioUnknownHost().build(t).env)
	if none.DatasetSHA256 != "" {
		t.Errorf("no dataset, no hash; got %q", none.DatasetSHA256)
	}
}

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	abc := filepath.Join(dir, "abc")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abc, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		empty: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		abc:   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	for path, want := range cases {
		got, err := SHA256File(path)
		if err != nil || got != want {
			t.Errorf("SHA256File(%s) = %q, %v; want %q", filepath.Base(path), got, err, want)
		}
	}
	if _, err := SHA256File(filepath.Join(dir, "absent")); err == nil {
		t.Errorf("SHA256File of a missing file must fail")
	}
}

func buildInfo(revision, modified string) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: revision},
			{Key: "vcs.modified", Value: modified},
		}}, true
	}
}

func TestBuildIdentity(t *testing.T) {
	noInfo := func() (*debug.BuildInfo, bool) { return nil, false }
	cases := []struct {
		name         string
		ldCommit     string
		ldTainted    string
		allowDirty   bool
		info         func() (*debug.BuildInfo, bool)
		wantCommit   string
		wantDirty    bool
		wantTainted  bool
		wantNoCommit bool
	}{
		{name: "ldflags commit wins over build info", ldCommit: "abc123", ldTainted: "false", info: buildInfo("fromvcs", "false"), wantCommit: "abc123"},
		{name: "ldflags commit without any build info", ldCommit: "abc123", info: noInfo, wantCommit: "abc123"},
		{name: "ldflags tainted marks commit dirty and run tainted", ldCommit: "abc123", ldTainted: "true", info: noInfo, wantCommit: "abc123", wantDirty: true, wantTainted: true},
		{name: "ldflags tainted accepts 1", ldCommit: "abc123", ldTainted: "1", info: noInfo, wantCommit: "abc123", wantDirty: true, wantTainted: true},
		{name: "ldflags commit is trimmed", ldCommit: "  abc123\n", info: noInfo, wantCommit: "abc123"},
		{name: "build info used when no ldflags", info: buildInfo("fromvcs", "false"), wantCommit: "fromvcs"},
		{name: "build info modified", info: buildInfo("fromvcs", "true"), wantCommit: "fromvcs", wantDirty: true, wantTainted: true},
		{name: "allow dirty taints a clean commit", ldCommit: "abc123", allowDirty: true, info: noInfo, wantCommit: "abc123", wantTainted: true},
		{name: "nothing known", info: noInfo, wantNoCommit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldCommit, oldTainted := BuildCommit, BuildTainted
			t.Cleanup(func() { BuildCommit, BuildTainted = oldCommit, oldTainted })
			BuildCommit, BuildTainted = tc.ldCommit, tc.ldTainted

			env := scenarioUnknownHost().build(t).env
			env.BuildInfo = tc.info
			meta := DetectWith(context.Background(), Options{AllowDirty: tc.allowDirty}, env)

			if tc.wantNoCommit {
				if meta.Commit != "" {
					t.Errorf("Commit = %q, want empty", meta.Commit)
				}
			} else if meta.Commit != tc.wantCommit {
				t.Errorf("Commit = %q, want %q", meta.Commit, tc.wantCommit)
			}
			if meta.CommitDirty != tc.wantDirty {
				t.Errorf("CommitDirty = %v, want %v", meta.CommitDirty, tc.wantDirty)
			}
			if meta.Tainted != tc.wantTainted {
				t.Errorf("Tainted = %v, want %v", meta.Tainted, tc.wantTainted)
			}
		})
	}
}

// TestLdflagsInjection checks the build identity path used by the AWS bundle,
// which has no VCS metadata. It only runs when the variables were really
// injected at link time, for example:
//
//	go test ./pkg/runenv -run TestLdflagsInjection \
//	  -ldflags "-X github.com/con-unit/con-unit/pkg/runenv.BuildCommit=0123abcd \
//	            -X github.com/con-unit/con-unit/pkg/runenv.BuildTainted=true"
func TestLdflagsInjection(t *testing.T) {
	if BuildCommit == "" {
		t.Skip("BuildCommit was not injected with -ldflags -X")
	}
	// The real build info of a test binary has no vcs.revision, and even if
	// it had, the injected value must win.
	meta := Detect(context.Background(), Options{})
	if meta.Commit != strings.TrimSpace(BuildCommit) {
		t.Errorf("Commit = %q, want the injected %q", meta.Commit, BuildCommit)
	}
	if isTruthy(BuildTainted) && (!meta.Tainted || !meta.CommitDirty) {
		t.Errorf("injected BuildTainted=%q must mark the run tainted: %+v", BuildTainted, meta)
	}
}

// TestDetectLive runs the real Detect against this machine. It is opt in
// because it executes real commands, and on EC2 hosts it contacts the
// metadata service.
func TestDetectLive(t *testing.T) {
	if os.Getenv("CONUNIT_RUNENV_LIVE") != "1" {
		t.Skip("set CONUNIT_RUNENV_LIVE=1 to probe the real host")
	}
	start := time.Now()
	meta := Detect(context.Background(), Options{Version: "live", EngineBinary: "podman", ProbeWindow: 3 * time.Second})
	t.Logf("elapsed: %v", time.Since(start))
	t.Logf("host: %s", DescribeHost(meta))
	t.Logf("virtualization: %q", meta.Virtualization)
	t.Logf("tools: %v", meta.Tools)
	if meta.HostOS == "" || meta.HostArch == "" || meta.VCPUs < 1 || meta.GoVersion == "" || meta.StartedAt.IsZero() {
		t.Fatalf("static host facts missing: %+v", meta)
	}
	if time.Since(start) > 7*time.Second {
		t.Errorf("Detect exceeded its bound: %v", time.Since(start))
	}
}
