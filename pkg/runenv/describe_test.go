package runenv

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/spec"
)

func TestDeriveExecutionMode(t *testing.T) {
	cases := []struct {
		name string
		in   modeInputs
		want string
	}{
		{"nitro vm, rootful podman", modeInputs{Virtualization: VirtAWSNitroKVM, EngineName: "podman", Rootless: boolPtr(false), Cgroup: "v2"},
			"Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2"},
		{"nitro metal, rootful podman", modeInputs{Virtualization: VirtAWSNitroMetal, EngineName: "podman", Rootless: boolPtr(false), Cgroup: "v2"},
			"Bare-metal host (AWS Nitro metal instance), rootful Podman, cgroup v2"},
		{"nitro undetermined", modeInputs{Virtualization: VirtAWSNitro, EngineName: "podman", Rootless: boolPtr(false), Cgroup: "v2"},
			"AWS Nitro host (virtual machine or metal undetermined), rootful Podman, cgroup v2"},
		{"xen", modeInputs{Virtualization: VirtAWSXen, EngineName: "docker", Rootless: boolPtr(false), Cgroup: "v1"},
			"Virtualized host (AWS, Xen), rootful Docker Engine, cgroup v1"},
		{"bare metal docker", modeInputs{Virtualization: VirtBareMetal, EngineName: "docker", Rootless: boolPtr(false), Cgroup: "v2"},
			"Bare-metal host, rootful Docker Engine, cgroup v2"},
		{"rootless podman on a generic vm", modeInputs{Virtualization: "kvm", EngineName: "podman", Rootless: boolPtr(true), Cgroup: "v2"},
			"Virtualized host (kvm), rootless Podman, cgroup v2"},
		{"vm detected but hypervisor not named", modeInputs{Virtualization: VirtVMOther, EngineName: "podman", Rootless: boolPtr(true), Cgroup: "v2"},
			"Virtualized host (hypervisor not identified), rootless Podman, cgroup v2"},
		{"rootless unknown", modeInputs{Virtualization: VirtBareMetal, EngineName: "podman", Cgroup: "v2"},
			"Bare-metal host, Podman (rootless state unknown), cgroup v2"},
		{"cgroup unknown is left out", modeInputs{Virtualization: VirtBareMetal, EngineName: "podman", Rootless: boolPtr(false)},
			"Bare-metal host, rootful Podman"},
		{"no engine", modeInputs{Virtualization: VirtUnknown},
			"Host of unknown virtualization, no container engine detected"},
		{"empty virtualization reads as unknown", modeInputs{},
			"Host of unknown virtualization, no container engine detected"},
		{"remote engine", modeInputs{Virtualization: VirtUnknown, Remote: true, EngineName: "docker", Rootless: boolPtr(false), Cgroup: "v2"},
			"Remote container engine (host not inspected), rootful Docker Engine, cgroup v2"},
		{"macos libkrun", modeInputs{Virtualization: VirtAppleHypervisorLibkrun, EngineName: "podman", Rootless: boolPtr(true), Cgroup: "v2"},
			"Virtualized host (Linux VM on macOS, libkrun on Apple Hypervisor), rootless Podman, cgroup v2"},
		{"other engine name is shown as detected", modeInputs{Virtualization: VirtBareMetal, EngineName: "nerdctl", Rootless: boolPtr(false)},
			"Bare-metal host, rootful nerdctl"},
	}
	for _, tc := range cases {
		if got := deriveExecutionMode(tc.in); got != tc.want {
			t.Errorf("%s:\n got: %q\nwant: %q", tc.name, got, tc.want)
		}
	}
}

func TestExecutionModeNeverClaimsBareMetalForVirtualizedHosts(t *testing.T) {
	// The old benchmark labelled every Linux host "Bare-Metal Linux". An EC2
	// virtual machine must never read as bare metal.
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, scenarioC6i2xlarge(t).build(t).env)
	if strings.Contains(strings.ToLower(meta.ExecutionMode), "bare") {
		t.Errorf("ExecutionMode = %q must not claim bare metal for a c6i.2xlarge", meta.ExecutionMode)
	}
	if meta.Virtualization == "bare-metal" {
		t.Errorf("Virtualization = %q for a c6i.2xlarge", meta.Virtualization)
	}
}

func TestDescribeHost(t *testing.T) {
	full := spec.RunMetadata{
		ExecutionMode:  "Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2",
		Virtualization: "aws-nitro-kvm",
		CloudProvider:  "aws", InstanceType: "c6i.2xlarge", Region: "eu-central-1", Zone: "eu-central-1b", AMIID: "ami-0f1e2d3c4b5a69788",
		HostOS: "linux", HostArch: "amd64", LinuxKernel: "6.8.0-1018-aws",
		CPUModel: xeon8375C, VCPUs: 8, MemoryBytes: 16029392 * 1024,
		EngineName: "podman", EngineVersion: "4.9.3", StorageDriver: "overlay", OCIRuntime: "crun 1.14.1",
		Commit: "0123456789abcdef0123456789abcdef01234567",
	}
	cases := []struct {
		name string
		meta spec.RunMetadata
		want string
	}{
		{
			name: "full aws host",
			meta: full,
			want: "mode: Virtualized host (AWS Nitro, KVM), rootful Podman, cgroup v2" +
				" | cloud: aws c6i.2xlarge eu-central-1b ami-0f1e2d3c4b5a69788" +
				" | os: linux/amd64 kernel 6.8.0-1018-aws" +
				" | cpu: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz, 8 vCPU, 15.3 GiB" +
				" | engine: podman 4.9.3 (overlay, crun 1.14.1)" +
				" | commit: 0123456789ab",
		},
		{
			name: "dirty commit and region fallback",
			meta: spec.RunMetadata{
				ExecutionMode: "Bare-metal host, rootful Docker Engine, cgroup v2", CloudProvider: "aws", Region: "us-east-1",
				HostOS: "linux", HostArch: "arm64", EngineName: "docker", EngineVersion: "27.3.1",
				Commit: "abc", CommitDirty: true, Tainted: true,
			},
			want: "mode: Bare-metal host, rootful Docker Engine, cgroup v2 | cloud: aws us-east-1 | os: linux/arm64 | engine: docker 27.3.1 | commit: abc (dirty)",
		},
		{
			name: "tainted but not dirty",
			meta: spec.RunMetadata{Commit: "abc", Tainted: true},
			want: "commit: abc (tainted)",
		},
		{
			name: "virtualization shown when no mode was derived",
			meta: spec.RunMetadata{Virtualization: "bare-metal", HostOS: "linux", HostArch: "amd64"},
			want: "virt: bare-metal | os: linux/amd64",
		},
		{
			name: "empty metadata",
			meta: spec.RunMetadata{},
			want: "host: unknown",
		},
	}
	for _, tc := range cases {
		got := DescribeHost(tc.meta)
		if got != tc.want {
			t.Errorf("%s:\n got: %q\nwant: %q", tc.name, got, tc.want)
		}
		if strings.Contains(got, "\n") {
			t.Errorf("%s: DescribeHost must be a single line", tc.name)
		}
	}
}

func TestDescribeHostOfDetectedScenarios(t *testing.T) {
	meta := DetectWith(context.Background(), Options{EngineBinary: "podman"}, scenarioC6i2xlarge(t).build(t).env)
	got := DescribeHost(meta)
	for _, part := range []string{"AWS Nitro, KVM", "c6i.2xlarge", "eu-central-1b", "6.8.0-1018-aws", "8 vCPU", "podman 4.9.3", "crun 1.14.1"} {
		if !strings.Contains(got, part) {
			t.Errorf("DescribeHost = %q, missing %q", got, part)
		}
	}
}

// TestBoundedRunnerAbandonsStuckCommander proves the guarantee of Env.run:
// a Commander that ignores its context cannot hold the caller past the bound.
func TestBoundedRunnerAbandonsStuckCommander(t *testing.T) {
	s := scenario{os: "linux", arch: "amd64", cpus: 1, cmds: map[string]reply{"stuck": {stuck: true}, "slow": {hang: true}}}
	be := s.build(t)
	env := be.env.withDefaults()
	env.CommandTimeout = 80 * time.Millisecond

	for _, name := range []string{"stuck", "slow"} {
		start := time.Now()
		_, err := env.run(context.Background(), name)
		if err == nil {
			t.Errorf("%s: want a deadline error", name)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("%s: run returned after %v, want about 80ms", name, elapsed)
		}
	}
}

func TestBoundedRunnerRecoversFromPanics(t *testing.T) {
	env := Env{Exec: panicExec{}}.withDefaults()
	if _, err := env.run(context.Background(), "x"); err == nil {
		t.Errorf("a panicking Commander must surface as an error")
	}
	// parallel must contain panics as well.
	ran := false
	parallel(func() { panic("boom") }, func() { ran = true })
	if !ran {
		t.Errorf("a panic in one probe must not stop the others")
	}
}

type panicExec struct{}

func (panicExec) Run(context.Context, string, ...string) (CmdResult, error) { panic("boom") }

// TestExecRunnerRealCommands exercises the real Commander with harmless shell
// builtins. It never touches the network or any engine.
func TestExecRunnerRealCommands(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	r := execRunner{}

	t.Run("stdout and stderr are separated", func(t *testing.T) {
		res, err := r.Run(context.Background(), sh, "-c", "printf out; printf err >&2")
		if err != nil || string(res.Stdout) != "out" || string(res.Stderr) != "err" {
			t.Errorf("result = %q %q, %v", res.Stdout, res.Stderr, err)
		}
	})
	t.Run("output survives a non-zero exit", func(t *testing.T) {
		res, err := r.Run(context.Background(), sh, "-c", "printf none; exit 1")
		if err == nil || string(res.Stdout) != "none" {
			t.Errorf("result = %q, %v; want output with an error", res.Stdout, err)
		}
	})
	t.Run("missing binary", func(t *testing.T) {
		if _, err := r.Run(context.Background(), "definitely-not-a-real-binary-conunit"); err == nil {
			t.Errorf("want an error for a missing binary")
		}
	})
	t.Run("a hanging command with a grandchild is cut off at the deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		start := time.Now()
		// The shell forks sleep, which keeps the output pipe open after the
		// shell is killed. WaitDelay must still release the caller.
		_, err := r.Run(ctx, sh, "-c", "sleep 30; echo late")
		if err == nil {
			t.Errorf("want an error after the deadline")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Run returned after %v, want about 150ms plus the wait delay", elapsed)
		}
	})
	t.Run("output is capped", func(t *testing.T) {
		res, err := r.Run(context.Background(), sh, "-c", "head -c 3000000 /dev/zero | tr '\\0' 'a'")
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(res.Stdout) != maxOutputBytes {
			t.Errorf("captured %d bytes, want the cap of %d", len(res.Stdout), maxOutputBytes)
		}
	})
}
