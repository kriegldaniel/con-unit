package runenv

import (
	"context"
	"testing"
)

func TestParseCPUInfo(t *testing.T) {
	arm64 := "processor\t: 0\nBogoMIPS\t: 2100.00\nFeatures\t: fp asimd evtstrm aes pmull\nCPU implementer\t: 0x41\nCPU part\t: 0xd40\n\n" +
		"processor\t: 1\nBogoMIPS\t: 2100.00\nCPU implementer\t: 0x41\nCPU part\t: 0xd40\n\n"
	armv7 := "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\n\nprocessor\t: 1\nmodel name\t: ARMv7 Processor rev 4 (v7l)\n\nHardware\t: BCM2835\n"
	armLegacy := "Processor\t: ARMv6-compatible processor rev 7 (v6l)\nprocessor\t: 0\n\nHardware\t: BCM2708\n"

	cases := []struct {
		name      string
		in        string
		wantModel string
		wantProcs int
	}{
		{"x86 eight cpus", cpuInfoX86(xeon8375C, 8), xeon8375C, 8},
		{"x86 one cpu", cpuInfoX86("AMD EPYC 7R13 Processor", 1), "AMD EPYC 7R13 Processor", 1},
		{"arm64 prints no model name", arm64, "", 2},
		{"armv7 model name", armv7, "ARMv7 Processor rev 4 (v7l)", 2},
		{"legacy arm trailer", armLegacy, "ARMv6-compatible processor rev 7 (v6l)", 1},
		{"empty", "", "", 0},
		{"no colons", "garbage without structure", "", 0},
		{"placeholder model is dropped", "processor\t: 0\nmodel name\t: -\n", "", 1},
	}
	for _, tc := range cases {
		model, procs := parseCPUInfo(tc.in)
		if model != tc.wantModel || procs != tc.wantProcs {
			t.Errorf("%s: parseCPUInfo = %q, %d; want %q, %d", tc.name, model, procs, tc.wantModel, tc.wantProcs)
		}
	}
}

func TestParseLscpuModel(t *testing.T) {
	out := "Architecture:                       aarch64\nCPU(s):                             8\nVendor ID:                          ARM\nModel name:                         Neoverse-V1\nThread(s) per core:                 1\n"
	if got := parseLscpuModel(out); got != "Neoverse-V1" {
		t.Errorf("parseLscpuModel = %q", got)
	}
	if got := parseLscpuModel("no model here"); got != "" {
		t.Errorf("parseLscpuModel of unrelated text = %q", got)
	}
	// Captured on a libkrun guest: lscpu prints a dash instead of a model.
	if got := parseLscpuModel("Architecture:  aarch64\nModel name:    -\n"); got != "" {
		t.Errorf("parseLscpuModel with a placeholder = %q, want empty", got)
	}
}

func TestParseMemTotal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int64
	}{
		{"kilobytes", "MemTotal:       16029392 kB\nMemFree: 1 kB\n", 16029392 * 1024},
		{"leading lines", "MemFree: 5 kB\nMemTotal:  2048 kB\n", 2048 * 1024},
		{"no unit", "MemTotal: 4096\n", 4096},
		{"zero", "MemTotal: 0 kB\n", 0},
		{"garbage", "MemTotal: lots kB\n", 0},
		{"missing", "MemFree: 1 kB\n", 0},
		{"empty", "", 0},
	}
	for _, tc := range cases {
		if got := parseMemTotal(tc.in); got != tc.want {
			t.Errorf("%s: parseMemTotal = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestProbeHostLinux(t *testing.T) {
	t.Run("files only", func(t *testing.T) {
		s := scenario{os: "linux", arch: "amd64", cpus: 2, files: fakeFS{
			"/proc/sys/kernel/osrelease": "6.8.0-1018-aws\n",
			"/proc/cpuinfo":              cpuInfoX86(xeon8375C, 8),
			"/proc/meminfo":              memInfo(16029392),
		}}
		h := probeHost(context.Background(), s.build(t).env.withDefaults())
		if h.Kernel != "6.8.0-1018-aws" || h.CPUModel != xeon8375C || h.MemBytes != 16029392*1024 {
			t.Errorf("host facts = %+v", h)
		}
		if h.VCPUs != 8 {
			t.Errorf("VCPUs = %d, want 8 (cpuinfo count wins over NumCPU)", h.VCPUs)
		}
	})
	t.Run("uname and lscpu fallbacks", func(t *testing.T) {
		s := scenario{os: "linux", arch: "arm64", cpus: 4,
			files: fakeFS{"/proc/cpuinfo": "processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\nprocessor\t: 3\n", "/proc/meminfo": memInfo(8000000)},
			cmds: map[string]reply{
				"uname -r": {stdout: "6.1.0-arm\n"},
				"lscpu":    {stdout: "Model name:   Neoverse-V1\n"},
			}}
		h := probeHost(context.Background(), s.build(t).env.withDefaults())
		if h.Kernel != "6.1.0-arm" || h.CPUModel != "Neoverse-V1" || h.VCPUs != 4 {
			t.Errorf("host facts = %+v", h)
		}
	})
	t.Run("nothing readable falls back to NumCPU", func(t *testing.T) {
		s := scenario{os: "linux", arch: "amd64", cpus: 3}
		h := probeHost(context.Background(), s.build(t).env.withDefaults())
		if h.Kernel != "" || h.CPUModel != "" || h.MemBytes != 0 || h.VCPUs != 3 {
			t.Errorf("host facts = %+v", h)
		}
	})
}

func TestProbeHostDarwin(t *testing.T) {
	t.Run("captured sysctl output", func(t *testing.T) {
		s := scenarioMacPodmanMachine(t)
		h := probeHost(context.Background(), s.build(t).env.withDefaults())
		if h.CPUModel != "Apple M2 Pro" || h.MemBytes != 17179869184 || h.VCPUs != 12 || h.Kernel != "" {
			t.Errorf("host facts = %+v", h)
		}
	})
	t.Run("sysctl fails", func(t *testing.T) {
		s := scenario{os: "darwin", arch: "arm64", cpus: 8, cmds: map[string]reply{
			"sysctl -n machdep.cpu.brand_string": {err: errExit1},
			"sysctl -n hw.memsize":               {stdout: "not a number\n"},
		}}
		h := probeHost(context.Background(), s.build(t).env.withDefaults())
		if h.CPUModel != "" || h.MemBytes != 0 || h.VCPUs != 8 {
			t.Errorf("host facts = %+v", h)
		}
	})
}

func TestProbeHostOtherOS(t *testing.T) {
	s := scenario{os: "windows", arch: "amd64", cpus: 6}
	h := probeHost(context.Background(), s.build(t).env.withDefaults())
	if h.VCPUs != 6 || h.CPUModel != "" || h.Kernel != "" {
		t.Errorf("host facts = %+v", h)
	}
}

func TestReadDMI(t *testing.T) {
	be := scenarioC6i2xlarge(t).build(t)
	d := readDMI(be.env.withDefaults())
	if d.SysVendor != "Amazon EC2" || d.ProductName != "c6i.2xlarge" || d.BoardVendor != "Amazon EC2" || d.BiosVendor != "Amazon EC2" || !d.Readable {
		t.Errorf("dmi = %+v", d)
	}
	none := readDMI(scenarioUnknownHost().build(t).env.withDefaults())
	if none.Readable || none.SysVendor != "" {
		t.Errorf("dmi of an unknown host = %+v", none)
	}
}

func TestParseMachineList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"captured libkrun machine", readFixture(t, "podman_machine_list_libkrun.out"), "libkrun"},
		{"running default wins", `[{"Name":"a","Default":false,"Running":true,"VMType":"qemu"},{"Name":"b","Default":true,"Running":true,"VMType":"applehv"}]`, "applehv"},
		{"running beats stopped default", `[{"Name":"a","Default":true,"Running":false,"VMType":"applehv"},{"Name":"b","Default":false,"Running":true,"VMType":"libkrun"}]`, "libkrun"},
		{"no running machine", `[{"Name":"a","Default":true,"Running":false,"VMType":"applehv"}]`, ""},
		{"vm type is lowercased", `[{"Default":true,"Running":true,"VMType":"AppleHV"}]`, "applehv"},
		{"empty list", `[]`, ""},
		{"garbage", `not json`, ""},
		{"empty input", ``, ""},
	}
	for _, tc := range cases {
		if got := parseMachineList([]byte(tc.in)).VMType; got != tc.want {
			t.Errorf("%s: VMType = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSanitizeToken(t *testing.T) {
	cases := map[string]string{
		"kvm\n":                 "kvm",
		"none":                  "none",
		"amazon\nextra line":    "amazon",
		"Microsoft":             "microsoft",
		"":                      "",
		"Failed to connect: no": "",
		"with space":            "",
		"semi;colon":            "",
	}
	for in, want := range cases {
		if got := sanitizeToken(in); got != want {
			t.Errorf("sanitizeToken(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeKernel(t *testing.T) {
	cases := map[string]string{
		"6.8.0-1018-aws\n":      "6.8.0-1018-aws",
		"6.18.10-200.fc43.x86":  "6.18.10-200.fc43.x86",
		"":                      "",
		"command not found foo": "",
	}
	for in, want := range cases {
		if got := sanitizeKernel(in); got != want {
			t.Errorf("sanitizeKernel(%q) = %q, want %q", in, got, want)
		}
	}
}
