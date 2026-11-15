package runenv

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Engine names recorded in spec.RunMetadata.EngineName.
const (
	enginePodman = "podman"
	engineDocker = "docker"
)

// StorageDriverContainerdSuffix is appended to the Docker storage driver name
// when the daemon uses the containerd image store, because image identity and
// layer handling differ from the classic graph drivers.
const StorageDriverContainerdSuffix = " (containerd image store)"

// engineFacts is what one engine probe learned.
type engineFacts struct {
	Name          string // podman | docker | basename of an unknown binary
	Version       string // server version
	Reachable     bool   // the engine answered an info request
	Rootless      *bool
	Cgroup        string // v1 | v2
	Storage       string
	Runtime       string // for example "crun 1.14.1" or "runc"
	Security      []string
	Kernel        string // kernel of the engine host (VM kernel for podman machine and Docker Desktop)
	CPUs          int    // CPUs seen by the engine
	MemBytes      int64  // memory seen by the engine
	ServiceRemote bool   // podman reports a remote service
	DockerDesktop bool   // docker daemon is Docker Desktop
}

var (
	// versionToken captures a version such as 1.55.0, v2.4.1 or 2.0.0-rc.1.
	// The prefix keeps it from matching inside go1.22.5 or a longer dotted
	// number. Go regexps have no lookbehind, so the version is group 1.
	versionToken  = regexp.MustCompile(`(?:^|[^0-9A-Za-z.])(v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.+-]+)?)`)
	podmanVersion = regexp.MustCompile(`(?i)podman version\s+(\S+)`)
)

// firstVersion returns the first version-like token of s, or "".
func firstVersion(s string) string {
	if m := versionToken.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// probeEngine asks the engine binary for its facts. Unknown facts stay empty.
func probeEngine(ctx context.Context, env Env, binary string) engineFacts {
	if strings.TrimSpace(binary) == "" {
		return engineFacts{}
	}
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(binary), ".exe"))

	kind := ""
	switch {
	case strings.Contains(base, enginePodman):
		kind = enginePodman
	case strings.Contains(base, engineDocker):
		kind = engineDocker
	default:
		// Unknown name (a wrapper or a renamed binary): ask the binary.
		if res, err := env.run(ctx, binary, "--version"); err == nil || len(res.Stdout) > 0 {
			text := strings.ToLower(string(res.Stdout) + "\n" + string(res.Stderr))
			switch {
			case strings.Contains(text, "podman"):
				kind = enginePodman
			case strings.Contains(text, "docker"):
				kind = engineDocker
			}
		}
		if kind == "" {
			return engineFacts{Name: base}
		}
	}

	var args []string
	if kind == enginePodman {
		args = []string{"info", "--format", "json"}
	} else {
		args = []string{"info", "--format", "{{json .}}"}
	}
	res, _ := env.run(ctx, binary, args...)
	if facts, ok := parseEngineInfo(res.Stdout); ok {
		return facts
	}

	// The info call failed (daemon down, machine stopped). The name is still
	// known from the binary; a podman client version is reported best effort.
	facts := engineFacts{Name: kind}
	if kind == enginePodman {
		if res, err := env.run(ctx, binary, "--version"); err == nil {
			if m := podmanVersion.FindStringSubmatch(string(res.Stdout)); m != nil {
				facts.Version = m[1]
			}
		}
	}
	return facts
}

// parseEngineInfo parses the JSON printed by `podman info --format json` or
// `docker info --format '{{json .}}'`. The shape of the document decides the
// engine, so a podman-docker shim is reported as podman.
func parseEngineInfo(data []byte) (engineFacts, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return engineFacts{}, false
	}
	_, hasHost := top["host"]
	_, hasStore := top["store"]
	_, hasServerVersion := top["ServerVersion"]
	_, hasClientInfo := top["ClientInfo"]
	_, hasDriver := top["Driver"]
	switch {
	case hasHost && hasStore:
		return parsePodmanInfo(data)
	case hasServerVersion || hasClientInfo || hasDriver:
		return parseDockerInfo(data)
	}
	return engineFacts{}, false
}

type podmanInfo struct {
	Host struct {
		CgroupVersion string `json:"cgroupVersion"`
		CPUs          int    `json:"cpus"`
		Kernel        string `json:"kernel"`
		MemTotal      int64  `json:"memTotal"`
		OS            string `json:"os"`
		OCIRuntime    struct {
			Name    string `json:"name"`
			Path    string `json:"path"`
			Version string `json:"version"`
		} `json:"ociRuntime"`
		ServiceIsRemote bool `json:"serviceIsRemote"`
		Security        struct {
			AppArmorEnabled    bool   `json:"apparmorEnabled"`
			Rootless           *bool  `json:"rootless"`
			SeccompEnabled     bool   `json:"seccompEnabled"`
			SeccompProfilePath string `json:"seccompProfilePath"`
			SELinuxEnabled     bool   `json:"selinuxEnabled"`
		} `json:"security"`
	} `json:"host"`
	Store struct {
		GraphDriverName string `json:"graphDriverName"`
	} `json:"store"`
	Version struct {
		Version string `json:"Version"`
	} `json:"version"`
}

func parsePodmanInfo(data []byte) (engineFacts, bool) {
	var info podmanInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return engineFacts{}, false
	}
	f := engineFacts{
		Name:          enginePodman,
		Version:       strings.TrimSpace(info.Version.Version),
		Reachable:     true,
		Rootless:      info.Host.Security.Rootless,
		Cgroup:        normalizeCgroup(info.Host.CgroupVersion),
		Storage:       strings.TrimSpace(info.Store.GraphDriverName),
		Runtime:       formatOCIRuntime(info.Host.OCIRuntime.Name, info.Host.OCIRuntime.Path, info.Host.OCIRuntime.Version),
		Kernel:        strings.TrimSpace(info.Host.Kernel),
		CPUs:          info.Host.CPUs,
		MemBytes:      info.Host.MemTotal,
		ServiceRemote: info.Host.ServiceIsRemote,
	}
	var sec []string
	if info.Host.Security.SeccompEnabled {
		if p := strings.TrimSpace(info.Host.Security.SeccompProfilePath); p != "" {
			sec = append(sec, "seccomp(profile="+p+")")
		} else {
			sec = append(sec, "seccomp")
		}
	}
	if info.Host.Security.AppArmorEnabled {
		sec = append(sec, "apparmor")
	}
	if info.Host.Security.SELinuxEnabled {
		sec = append(sec, "selinux")
	}
	if info.Host.Security.Rootless != nil && *info.Host.Security.Rootless {
		sec = append(sec, "rootless")
	}
	f.Security = sortedCopy(sec)
	return f, true
}

type dockerInfo struct {
	ServerVersion   string     `json:"ServerVersion"`
	Driver          string     `json:"Driver"`
	DriverStatus    [][]string `json:"DriverStatus"`
	CgroupVersion   string     `json:"CgroupVersion"`
	DefaultRuntime  string     `json:"DefaultRuntime"`
	SecurityOptions []string   `json:"SecurityOptions"`
	KernelVersion   string     `json:"KernelVersion"`
	OperatingSystem string     `json:"OperatingSystem"`
	NCPU            int        `json:"NCPU"`
	MemTotal        int64      `json:"MemTotal"`
}

func parseDockerInfo(data []byte) (engineFacts, bool) {
	var info dockerInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return engineFacts{}, false
	}
	f := engineFacts{Name: engineDocker}
	if strings.TrimSpace(info.ServerVersion) == "" {
		// Only the client section was filled in: the daemon is unreachable.
		return f, true
	}
	f.Version = strings.TrimSpace(info.ServerVersion)
	f.Reachable = true
	f.Cgroup = normalizeCgroup(info.CgroupVersion)
	f.Storage = strings.TrimSpace(info.Driver)
	if usesContainerdImageStore(info.DriverStatus) && f.Storage != "" {
		f.Storage += StorageDriverContainerdSuffix
	}
	f.Runtime = strings.TrimSpace(info.DefaultRuntime)
	f.Kernel = strings.TrimSpace(info.KernelVersion)
	f.CPUs = info.NCPU
	f.MemBytes = info.MemTotal
	f.DockerDesktop = strings.Contains(strings.ToLower(info.OperatingSystem), "docker desktop")

	if len(info.SecurityOptions) > 0 {
		rootless := false
		var sec []string
		for _, raw := range info.SecurityOptions {
			opt := normalizeDockerSecurityOption(raw)
			if opt == "" {
				continue
			}
			if opt == "rootless" {
				rootless = true
			}
			sec = append(sec, opt)
		}
		f.Security = sortedCopy(sec)
		f.Rootless = &rootless
	}
	return f, true
}

// usesContainerdImageStore reports whether `docker info` DriverStatus names
// the containerd snapshotter, which is how the containerd image store shows up.
func usesContainerdImageStore(status [][]string) bool {
	for _, kv := range status {
		if len(kv) == 2 && kv[0] == "driver-type" && strings.HasPrefix(kv[1], "io.containerd.snapshotter") {
			return true
		}
	}
	return false
}

// normalizeDockerSecurityOption turns "name=seccomp,profile=builtin" into
// "seccomp(profile=builtin)" and "name=rootless" into "rootless".
func normalizeDockerSecurityOption(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "name="))
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + "(" + strings.Join(parts[1:], ",") + ")"
}

// normalizeCgroup maps "2", "v2" and "V2" to "v2" and likewise for v1.
func normalizeCgroup(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "":
		return ""
	case "1", "v1":
		return "v1"
	case "2", "v2":
		return "v2"
	}
	return s
}

// formatOCIRuntime renders "crun 1.14.1" from the podman runtime fields. The
// version field is multi-line ("crun version 1.14.1\ncommit: ...").
func formatOCIRuntime(name, path, version string) string {
	name = strings.TrimSpace(name)
	if name == "" && path != "" {
		name = filepath.Base(strings.TrimSpace(path))
	}
	first := strings.TrimSpace(strings.SplitN(version, "\n", 2)[0])
	if m := firstVersion(first); m != "" {
		if name == "" {
			return m
		}
		return name + " " + strings.TrimPrefix(m, "v")
	}
	return name
}

// remoteURL reports whether an engine address points to another machine.
func remoteURL(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	u, err := url.Parse(addr)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "tcp", "ssh", "http", "https":
		return true
	}
	return false
}

// engineIsRemote reports whether the engine runs on a machine other than the
// one being inspected. A podman machine or Docker Desktop VM on macOS is not
// remote in this sense, it is the VM the virtualization probe describes.
func engineIsRemote(f engineFacts, goos string, getenv func(string) string) bool {
	switch f.Name {
	case engineDocker:
		return remoteURL(getenv("DOCKER_HOST"))
	case enginePodman:
		if remoteURL(getenv("CONTAINER_HOST")) {
			return true
		}
		return f.ServiceRemote && goos == "linux"
	}
	return false
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
