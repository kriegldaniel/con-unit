package runenv

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestParseEngineInfo(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		wantName string
		want     engineFacts
	}{
		{
			name:     "podman rootful on ubuntu 24.04",
			fixture:  "podman_info_rootful_ubuntu2404.out",
			wantName: "podman",
			want: engineFacts{
				Name: "podman", Version: "4.9.3", Reachable: true, Rootless: boolPtr(false),
				Cgroup: "v2", Storage: "overlay", Runtime: "crun 1.14.1",
				Security: []string{"apparmor", "seccomp(profile=/usr/share/containers/seccomp.json)"},
				Kernel:   "6.8.0-1018-aws", CPUs: 8, MemBytes: 16414105600,
			},
		},
		{
			name:     "podman rootless in a macos machine (captured)",
			fixture:  "podman_info_rootless_macos_libkrun.out",
			wantName: "podman",
			want: engineFacts{
				Name: "podman", Version: "5.8.1", Reachable: true, Rootless: boolPtr(true),
				Cgroup: "v2", Storage: "overlay", Runtime: "crun 1.25.1",
				Security: []string{"rootless", "seccomp(profile=/usr/share/containers/seccomp.json)", "selinux"},
				Kernel:   "6.18.10-200.fc43.aarch64", CPUs: 6, MemBytes: 3786420224, ServiceRemote: true,
			},
		},
		{
			name:     "docker with classic overlay2 storage",
			fixture:  "docker_info_overlay2.out",
			wantName: "docker",
			want: engineFacts{
				Name: "docker", Version: "27.3.1", Reachable: true, Rootless: boolPtr(false),
				Cgroup: "v2", Storage: "overlay2", Runtime: "runc",
				Security: []string{"apparmor", "cgroupns", "seccomp(profile=builtin)"},
				Kernel:   "6.8.0-1018-aws", CPUs: 8, MemBytes: 16414105600,
			},
		},
		{
			name:     "docker with the containerd image store",
			fixture:  "docker_info_containerd_store.out",
			wantName: "docker",
			want: engineFacts{
				Name: "docker", Version: "28.0.1", Reachable: true, Rootless: boolPtr(false),
				Cgroup: "v2", Storage: "overlayfs (containerd image store)", Runtime: "runc",
				Security: []string{"apparmor", "cgroupns", "seccomp(profile=builtin)"},
				Kernel:   "6.8.0-1018-aws", CPUs: 8, MemBytes: 16414105600,
			},
		},
		{
			name:     "rootless docker",
			fixture:  "docker_info_rootless.out",
			wantName: "docker",
			want: engineFacts{
				Name: "docker", Version: "27.3.1", Reachable: true, Rootless: boolPtr(true),
				Cgroup: "v2", Storage: "overlay2", Runtime: "runc",
				Security: []string{"cgroupns", "rootless", "seccomp(profile=builtin)"},
				Kernel:   "6.8.0-1018-aws", CPUs: 8, MemBytes: 16414105600,
			},
		},
		{
			name:     "docker daemon unreachable",
			fixture:  "docker_info_unreachable.out",
			wantName: "docker",
			want:     engineFacts{Name: "docker"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseEngineInfo([]byte(readFixture(t, tc.fixture)))
			if !ok {
				t.Fatalf("parseEngineInfo failed for %s", tc.fixture)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("facts mismatch\n got: %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}

func TestParseEngineInfoRejectsOtherDocuments(t *testing.T) {
	for _, in := range []string{"", "not json", "[]", `{"hello":"world"}`, `{"host":{}}`} {
		if _, ok := parseEngineInfo([]byte(in)); ok {
			t.Errorf("parseEngineInfo(%q) accepted a document that is not engine info", in)
		}
	}
}

func TestDockerContainerdImageStoreDetection(t *testing.T) {
	cases := []struct {
		name   string
		status [][]string
		want   bool
	}{
		{"containerd snapshotter", [][]string{{"driver-type", "io.containerd.snapshotter.v1"}}, true},
		{"classic overlay2 status", [][]string{{"Backing Filesystem", "extfs"}, {"Supports d_type", "true"}}, false},
		{"empty", nil, false},
		{"other driver type", [][]string{{"driver-type", "something.else"}}, false},
	}
	for _, tc := range cases {
		if got := usesContainerdImageStore(tc.status); got != tc.want {
			t.Errorf("%s: usesContainerdImageStore = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDockerRootlessNeedsSecurityOptions(t *testing.T) {
	// Without SecurityOptions the rootless state is unknown, not "false".
	got, ok := parseEngineInfo([]byte(`{"ServerVersion":"20.10.0","Driver":"overlay2"}`))
	if !ok || got.Rootless != nil {
		t.Fatalf("Rootless = %v (ok=%v), want nil when SecurityOptions are missing", got.Rootless, ok)
	}
}

func TestFormatOCIRuntime(t *testing.T) {
	cases := []struct {
		name, runtimeName, path, version, want string
	}{
		{"crun", "crun", "/usr/bin/crun", "crun version 1.14.1\ncommit: de537a79\nspec: 1.0.0", "crun 1.14.1"},
		{"runc", "runc", "/usr/bin/runc", "runc version 1.1.12\nspec: 1.0.2-dev\ngo: go1.21.8", "runc 1.1.12"},
		{"name from path", "", "/usr/bin/crun", "crun version 1.8", "crun 1.8"},
		{"version missing", "crun", "/usr/bin/crun", "", "crun"},
		{"version unparsable", "krun", "/usr/bin/krun", "development build", "krun"},
		{"nothing", "", "", "", ""},
	}
	for _, tc := range cases {
		if got := formatOCIRuntime(tc.runtimeName, tc.path, tc.version); got != tc.want {
			t.Errorf("%s: formatOCIRuntime = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNormalizeHelpers(t *testing.T) {
	for in, want := range map[string]string{"": "", "1": "v1", "2": "v2", "v2": "v2", " V1 ": "v1", "hybrid": "hybrid"} {
		if got := normalizeCgroup(in); got != want {
			t.Errorf("normalizeCgroup(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"name=seccomp,profile=builtin": "seccomp(profile=builtin)",
		"name=rootless":                "rootless",
		"name=cgroupns":                "cgroupns",
		"name=selinux":                 "selinux",
		"name=userns":                  "userns",
		"":                             "",
		"name=":                        "",
	} {
		if got := normalizeDockerSecurityOption(in); got != want {
			t.Errorf("normalizeDockerSecurityOption(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeEngineBinarySelection(t *testing.T) {
	podman := readFixture(t, "podman_info_rootful_ubuntu2404.out")
	docker := readFixture(t, "docker_info_overlay2.out")

	cases := []struct {
		name     string
		binary   string
		cmds     map[string]reply
		wantName string
		wantVer  string
	}{
		{"podman by name", "/usr/bin/podman", map[string]reply{"/usr/bin/podman info --format json": {stdout: podman}}, "podman", "4.9.3"},
		{"docker by name", "docker", map[string]reply{"docker info --format {{json .}}": {stdout: docker}}, "docker", "27.3.1"},
		{"exe suffix", `C:\bin\podman.exe`, map[string]reply{`C:\bin\podman.exe info --format json`: {stdout: podman}}, "podman", "4.9.3"},
		{
			name:   "podman-docker shim is reported as podman",
			binary: "/usr/bin/docker",
			cmds:   map[string]reply{"/usr/bin/docker info --format {{json .}}": {stdout: podman}},
			// The binary is called docker, the document is podman's.
			wantName: "podman", wantVer: "4.9.3",
		},
		{
			name:   "renamed binary identified by its version output",
			binary: "/opt/ctr/engine",
			cmds: map[string]reply{
				"/opt/ctr/engine --version":          {stdout: "podman version 4.9.3\n"},
				"/opt/ctr/engine info --format json": {stdout: podman},
			},
			wantName: "podman", wantVer: "4.9.3",
		},
		{
			name:     "unknown binary stays unidentified",
			binary:   "/opt/ctr/mystery",
			cmds:     map[string]reply{"/opt/ctr/mystery --version": {stdout: "mystery 1.0\n"}},
			wantName: "mystery", wantVer: "",
		},
		{
			name:     "podman info fails, client version reported",
			binary:   "podman",
			cmds:     map[string]reply{"podman info --format json": {stderr: "Cannot connect", err: errExit1}, "podman --version": {stdout: "podman version 5.2.1\n"}},
			wantName: "podman", wantVer: "5.2.1",
		},
		{
			name:     "docker info fails, client version is not the engine version",
			binary:   "docker",
			cmds:     map[string]reply{"docker info --format {{json .}}": {err: errExit1}, "docker --version": {stdout: "Docker version 27.3.1, build ce12230\n"}},
			wantName: "docker", wantVer: "",
		},
		{"empty binary", "", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scenario{os: "linux", arch: "amd64", cpus: 2, cmds: tc.cmds}
			got := probeEngine(context.Background(), s.build(t).env.withDefaults(), tc.binary)
			if got.Name != tc.wantName || got.Version != tc.wantVer {
				t.Errorf("probeEngine = %q %q, want %q %q", got.Name, got.Version, tc.wantName, tc.wantVer)
			}
		})
	}
}

func TestEngineIsRemote(t *testing.T) {
	env := func(kv map[string]string) func(string) string {
		return func(k string) string { return kv[k] }
	}
	cases := []struct {
		name  string
		facts engineFacts
		goos  string
		env   map[string]string
		want  bool
	}{
		{"docker default socket", engineFacts{Name: "docker"}, "linux", nil, false},
		{"docker unix socket", engineFacts{Name: "docker"}, "linux", map[string]string{"DOCKER_HOST": "unix:///var/run/docker.sock"}, false},
		{"docker ssh", engineFacts{Name: "docker"}, "linux", map[string]string{"DOCKER_HOST": "ssh://user@host"}, true},
		{"docker tcp on macos", engineFacts{Name: "docker"}, "darwin", map[string]string{"DOCKER_HOST": "tcp://10.0.0.5:2375"}, true},
		{"podman local", engineFacts{Name: "podman"}, "linux", nil, false},
		{"podman remote service on linux", engineFacts{Name: "podman", ServiceRemote: true}, "linux", nil, true},
		{"podman machine on macos is the VM, not remote", engineFacts{Name: "podman", ServiceRemote: true}, "darwin", nil, false},
		{"podman container host ssh", engineFacts{Name: "podman"}, "darwin", map[string]string{"CONTAINER_HOST": "ssh://root@host/run/podman/podman.sock"}, true},
		{"no engine", engineFacts{}, "linux", map[string]string{"DOCKER_HOST": "ssh://x"}, false},
	}
	for _, tc := range cases {
		if got := engineIsRemote(tc.facts, tc.goos, env(tc.env)); got != tc.want {
			t.Errorf("%s: engineIsRemote = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseEngineInfoIgnoresWarningsMixedIntoStdout(t *testing.T) {
	// podman prints warnings to stderr, never to stdout. A warning that did
	// leak into stdout makes the document unparsable and must not be guessed.
	polluted := "WARN[0000] something\n" + readFixture(t, "podman_info_rootful_ubuntu2404.out")
	if _, ok := parseEngineInfo([]byte(polluted)); ok {
		t.Errorf("polluted stdout accepted")
	}
	if !strings.Contains(polluted, "WARN") {
		t.Fatal("test setup")
	}
}
