package runenv

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

// Paths read for host facts.
const (
	pathOSRelease = "/proc/sys/kernel/osrelease"
	pathCPUInfo   = "/proc/cpuinfo"
	pathMemInfo   = "/proc/meminfo"
	dmiDir        = "/sys/class/dmi/id/"
)

// hostFacts are the facts of the machine the probes run on.
type hostFacts struct {
	Kernel   string // kernel of this host (Linux only)
	CPUModel string
	VCPUs    int
	MemBytes int64
}

// probeHost reads kernel, CPU model, vCPU count and memory of the local host.
func probeHost(ctx context.Context, env Env) hostFacts {
	switch env.OS {
	case "linux":
		return probeLinuxHost(ctx, env)
	case "darwin":
		return probeDarwinHost(ctx, env)
	}
	return hostFacts{VCPUs: env.NumCPU()}
}

func probeLinuxHost(ctx context.Context, env Env) hostFacts {
	var h hostFacts
	parallel(
		func() {
			if s, ok := env.readFile(pathOSRelease); ok {
				h.Kernel = strings.TrimSpace(s)
			}
			if h.Kernel == "" {
				if res, err := env.run(ctx, "uname", "-r"); err == nil {
					h.Kernel = strings.TrimSpace(string(res.Stdout))
				}
			}
		},
		func() {
			if s, ok := env.readFile(pathCPUInfo); ok {
				h.CPUModel, h.VCPUs = parseCPUInfo(s)
			}
			if h.CPUModel == "" {
				// ARM kernels do not print a model name in /proc/cpuinfo.
				if res, err := env.run(ctx, "lscpu"); err == nil {
					h.CPUModel = parseLscpuModel(string(res.Stdout))
				}
			}
		},
		func() {
			if s, ok := env.readFile(pathMemInfo); ok {
				h.MemBytes = parseMemTotal(s)
			}
		},
	)
	if h.VCPUs == 0 {
		h.VCPUs = env.NumCPU()
	}
	return h
}

func probeDarwinHost(ctx context.Context, env Env) hostFacts {
	h := hostFacts{VCPUs: env.NumCPU()}
	parallel(
		func() {
			if res, err := env.run(ctx, "sysctl", "-n", "machdep.cpu.brand_string"); err == nil {
				h.CPUModel = strings.TrimSpace(string(res.Stdout))
			}
		},
		func() {
			if res, err := env.run(ctx, "sysctl", "-n", "hw.memsize"); err == nil {
				if n, perr := strconv.ParseInt(strings.TrimSpace(string(res.Stdout)), 10, 64); perr == nil && n > 0 {
					h.MemBytes = n
				}
			}
		},
	)
	return h
}

// cpuModelKeys lists /proc/cpuinfo keys that carry a CPU model, in order of
// preference. x86 uses "model name". The "hardware" key names the board, so
// it comes last.
var cpuModelKeys = []string{"model name", "processor name", "cpu model", "hardware"}

// parseCPUInfo returns the first CPU model string and the number of logical
// processors listed in /proc/cpuinfo.
func parseCPUInfo(s string) (model string, procs int) {
	found := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if key == "processor" {
			// x86 and arm64 print an index. 32-bit ARM prints a model string
			// under the same key, which is kept as a model candidate.
			if _, err := strconv.Atoi(val); err == nil {
				procs++
			} else if _, seen := found["processor name"]; !seen && val != "" {
				found["processor name"] = val
			}
			continue
		}
		if _, seen := found[key]; !seen && val != "" {
			found[key] = val
		}
	}
	for _, k := range cpuModelKeys {
		if v := cleanCPUModel(found[k]); v != "" {
			return v, procs
		}
	}
	return "", procs
}

// cleanCPUModel drops placeholder strings that some virtual machines report
// instead of a model, for example "-" in lscpu on a libkrun guest.
func cleanCPUModel(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "-", "--", "unknown", "n/a", "none", "null":
		return ""
	}
	return s
}

// parseLscpuModel extracts "Model name" from lscpu output.
func parseLscpuModel(s string) string {
	for _, line := range strings.Split(s, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), "Model name") {
			return cleanCPUModel(val)
		}
	}
	return ""
}

// parseMemTotal converts the MemTotal line of /proc/meminfo to bytes.
func parseMemTotal(s string) int64 {
	for _, line := range strings.Split(s, "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || n <= 0 {
			return 0
		}
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			n *= 1024
		}
		return n
	}
	return 0
}

// dmiFacts are the DMI strings that identify the machine vendor.
type dmiFacts struct {
	SysVendor   string
	ProductName string
	BoardVendor string
	BiosVendor  string
	BiosVersion string
	Readable    bool // at least one DMI entry could be read
}

func readDMI(env Env) dmiFacts {
	var d dmiFacts
	read := func(name string) string {
		s, ok := env.readFile(dmiDir + name)
		if !ok {
			return ""
		}
		d.Readable = true
		return strings.TrimSpace(s)
	}
	d.SysVendor = read("sys_vendor")
	d.ProductName = read("product_name")
	d.BoardVendor = read("board_vendor")
	d.BiosVendor = read("bios_vendor")
	d.BiosVersion = read("bios_version")
	return d
}

// probeSystemdVirt runs `systemd-detect-virt --vm` and returns its answer:
// "" when the tool is absent or gave no answer, "none" on bare metal, or the
// detected hypervisor id. The tool exits 1 for "none", so output wins over
// the exit status.
func probeSystemdVirt(ctx context.Context, env Env) string {
	if _, err := env.LookPath("systemd-detect-virt"); err != nil {
		return ""
	}
	res, _ := env.run(ctx, "systemd-detect-virt", "--vm")
	return sanitizeToken(string(res.Stdout))
}

// sanitizeToken returns the first line of s when it is a short single word
// made of letters, digits, dots, dashes and underscores, else "".
func sanitizeToken(s string) string {
	s = strings.TrimSpace(strings.SplitN(strings.TrimSpace(s), "\n", 2)[0])
	if s == "" || len(s) > 64 {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return ""
		}
	}
	return strings.ToLower(s)
}

// machineFacts describes the podman machine VM on macOS.
type machineFacts struct {
	VMType string // applehv | libkrun | qemu | hyperv | wsl, empty if unknown
}

// probeMachine asks `podman machine list --format json` which hypervisor
// backs the running podman machine. Only running machines count, and the
// default machine wins over other running ones.
func probeMachine(ctx context.Context, env Env, binary string) machineFacts {
	res, err := env.run(ctx, binary, "machine", "list", "--format", "json")
	if err != nil && len(res.Stdout) == 0 {
		return machineFacts{}
	}
	return parseMachineList(res.Stdout)
}

func parseMachineList(data []byte) machineFacts {
	var machines []struct {
		Name    string `json:"Name"`
		Default bool   `json:"Default"`
		Running bool   `json:"Running"`
		VMType  string `json:"VMType"`
	}
	if err := json.Unmarshal(data, &machines); err != nil {
		return machineFacts{}
	}
	best, bestScore := "", -1
	for _, m := range machines {
		if !m.Running || m.VMType == "" {
			continue
		}
		score := 0
		if m.Default {
			score = 1
		}
		if score > bestScore {
			best, bestScore = m.VMType, score
		}
	}
	return machineFacts{VMType: strings.ToLower(strings.TrimSpace(best))}
}

// probeMachineKernel asks the podman machine VM for its kernel. It is the
// fallback when `podman info` did not report one.
func probeMachineKernel(ctx context.Context, env Env, binary string) string {
	res, err := env.run(ctx, binary, "machine", "ssh", "uname", "-r")
	if err != nil {
		return ""
	}
	return sanitizeKernel(string(res.Stdout))
}

// sanitizeKernel accepts a kernel release such as 6.8.0-1018-aws.
func sanitizeKernel(s string) string {
	s = strings.TrimSpace(strings.SplitN(strings.TrimSpace(s), "\n", 2)[0])
	if s == "" || len(s) > 128 || strings.ContainsAny(s, " \t") {
		return ""
	}
	return s
}
