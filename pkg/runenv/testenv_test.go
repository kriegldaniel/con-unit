package runenv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file holds the fakes that replace files, commands and HTTP in tests,
// plus the host scenarios shared by several test files. Fixtures under
// testdata are raw command output. The files named *macos_libkrun* and
// podman_machine_list_libkrun were captured from a real macOS host (podman
// 5.8.1, libkrun machine). The Ubuntu 24.04 EC2 and Docker files are modeled
// on the documented output format of the named tool versions, because no EC2
// host was available. They use the .out extension because the repository
// ignores *.json outside fixtures. No test touches the external network.

// readFixture returns the content of testdata/<name>.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

// fakeFS is an in-memory FileReader keyed by absolute path.
type fakeFS map[string]string

func (f fakeFS) ReadFile(path string) ([]byte, error) {
	if v, ok := f[path]; ok {
		return []byte(v), nil
	}
	return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
}

// reply is the canned result of one command.
type reply struct {
	stdout string
	stderr string
	err    error
	hang   bool // block until the context ends
	stuck  bool // block forever, ignoring the context
}

var errExit1 = errors.New("exit status 1")

// fakeExec is a Commander that answers from a table keyed by the full command
// line. Unknown commands fail like a missing binary.
type fakeExec struct {
	mu      sync.Mutex
	replies map[string]reply
	calls   []string
	release chan struct{} // closed at test end to free stuck goroutines
}

func newFakeExec(replies map[string]reply) *fakeExec {
	return &fakeExec{replies: replies, release: make(chan struct{})}
}

func (f *fakeExec) Run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	joined := strings.Join(args, " ")
	key := strings.TrimSpace(name + " " + joined)
	f.mu.Lock()
	f.calls = append(f.calls, key)
	r, ok := f.replies[key]
	if !ok {
		// Scenarios key replies by command name, callers may use a full path.
		r, ok = f.replies[strings.TrimSpace(filepath.Base(name)+" "+joined)]
	}
	f.mu.Unlock()
	if !ok {
		return CmdResult{}, &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	switch {
	case r.stuck:
		<-f.release
		return CmdResult{}, errors.New("released")
	case r.hang:
		<-ctx.Done()
		return CmdResult{}, ctx.Err()
	}
	return CmdResult{Stdout: []byte(r.stdout), Stderr: []byte(r.stderr)}, r.err
}

func (f *fakeExec) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// fakeIMDS is an HTTPDoer that behaves like IMDSv2.
type fakeIMDS struct {
	mu       sync.Mutex
	answers  map[string]string // meta-data path (for example "instance-type") to value
	token    string
	status   int  // status of the token PUT, default 200
	hang     bool // block until the context ends
	stuck    chan struct{}
	requests []string
}

const fakeToken = "AQAAAFAKETOKENFAKETOKENFAKETOKENFAKETOKEN0123456789=="

func (f *fakeIMDS) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req.Method+" "+req.URL.Path)
	f.mu.Unlock()
	if f.stuck != nil {
		<-f.stuck
	}
	if f.hang {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	respond := func(code int, body string) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	}
	if req.URL.Path == "/latest/api/token" {
		if req.Method != http.MethodPut || req.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			return respond(http.StatusBadRequest, "")
		}
		if f.status != 0 && f.status != http.StatusOK {
			return respond(f.status, "")
		}
		return respond(http.StatusOK, f.token)
	}
	if req.Header.Get("X-aws-ec2-metadata-token") != f.token || f.token == "" {
		return respond(http.StatusUnauthorized, "")
	}
	key := strings.TrimPrefix(req.URL.Path, "/latest/meta-data/")
	if v, ok := f.answers[key]; ok {
		return respond(http.StatusOK, v)
	}
	return respond(http.StatusNotFound, "")
}

func (f *fakeIMDS) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// scenario describes one host. build turns it into an Env.
type scenario struct {
	os        string
	arch      string
	cpus      int
	files     fakeFS
	cmds      map[string]reply
	installed []string
	imds      *fakeIMDS // nil: nothing answers on the link-local address
	environ   map[string]string
}

type builtEnv struct {
	env  Env
	exec *fakeExec
	imds *fakeIMDS
}

func (s scenario) build(t *testing.T) builtEnv {
	t.Helper()
	fe := newFakeExec(s.cmds)
	t.Cleanup(func() { close(fe.release) })

	installed := map[string]bool{}
	for _, n := range s.installed {
		installed[n] = true
	}
	env := Env{
		OS:     s.os,
		Arch:   s.arch,
		NumCPU: func() int { return s.cpus },
		Files:  s.files,
		Exec:   fe,
		LookPath: func(name string) (string, error) {
			if installed[name] {
				return "/usr/bin/" + name, nil
			}
			return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
		},
		Getenv: func(k string) string { return s.environ[k] },
		Now:    func() time.Time { return time.Date(2026, 11, 14, 13, 41, 8, 0, time.UTC) },
		// Short bounds keep timeout tests fast; real defaults are 2 s and 1 s.
		CommandTimeout: 500 * time.Millisecond,
		IMDSTimeout:    300 * time.Millisecond,
	}
	if s.imds != nil {
		env.HTTP = s.imds
	} else {
		env.HTTP = unreachableHTTP{}
	}
	return builtEnv{env: env, exec: fe, imds: s.imds}
}

// unreachableHTTP fails like a network without a route to the metadata address.
type unreachableHTTP struct{}

func (unreachableHTTP) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("connect: network is unreachable")
}

// cpuInfoX86 renders /proc/cpuinfo for n logical processors of one model.
func cpuInfoX86(model string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "processor\t: %d\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 106\nmodel name\t: %s\nstepping\t: 6\ncpu MHz\t\t: 2899.998\n\n", i, model)
	}
	return b.String()
}

func memInfo(kb int64) string {
	return fmt.Sprintf("MemTotal:       %d kB\nMemFree:         1234567 kB\nMemAvailable:    9876543 kB\n", kb)
}

const (
	xeon8375C = "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz"

	syftVersionOut     = "syft 1.55.0\n"
	grypeVersionOut    = "grype 0.120.0\n"
	hadolintVersionOut = "Haskell Dockerfile Linter 2.14.0\n"
	trivyVersionOut    = "Version: 0.57.0\nVulnerability DB:\n  Version:      2\n  UpdatedAt:    2026-11-14 06:02:11.123456789 +0000 UTC\n"
	dockleVersionOut   = "dockle version 0.4.15\n"
	cosignVersionOut   = "  ______   ______        _______. __    _______ .__   __.\n /      | /  __  \\      /       ||  |  /  _____||  \\ |  |\n|  ,----'|  |  |  |    |   (----`|  | |  |  __  |   \\|  |\n\nGitVersion:    v2.4.1\nGitCommit:     9a6b6a7\nGitTreeState:  clean\nBuildDate:     2024-10-08T20:00:00Z\nGoVersion:     go1.22.5\nCompiler:      gc\nPlatform:      linux/amd64\n"
)

// toolReplies are canned version outputs for syft, grype, hadolint, trivy,
// cosign and dockle. container-structure-test is left out, so it is absent.
func toolReplies() map[string]reply {
	return map[string]reply{
		"syft --version":     {stdout: syftVersionOut},
		"grype --version":    {stdout: grypeVersionOut},
		"hadolint --version": {stdout: hadolintVersionOut},
		"trivy --version":    {stdout: trivyVersionOut},
		"cosign version":     {stdout: cosignVersionOut, stderr: ""},
		"dockle --version":   {stdout: dockleVersionOut},
	}
}

var toolBinaries = []string{"syft", "grype", "hadolint", "trivy", "cosign", "dockle"}

func mergeReplies(parts ...map[string]reply) map[string]reply {
	out := map[string]reply{}
	for _, p := range parts {
		for k, v := range p {
			out[k] = v
		}
	}
	return out
}

func ec2DMI(product string) fakeFS {
	return fakeFS{
		"/sys/class/dmi/id/sys_vendor":   "Amazon EC2\n",
		"/sys/class/dmi/id/product_name": product + "\n",
		"/sys/class/dmi/id/board_vendor": "Amazon EC2\n",
		"/sys/class/dmi/id/bios_vendor":  "Amazon EC2\n",
		"/sys/class/dmi/id/bios_version": "1.0\n",
	}
}

func withFiles(base fakeFS, extra fakeFS) fakeFS {
	out := fakeFS{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// scenarioC6i2xlarge is an EC2 c6i.2xlarge running Ubuntu 24.04 with rootful
// Podman 4.9.3. IMDSv2 answers.
func scenarioC6i2xlarge(t *testing.T) scenario {
	return scenario{
		os: "linux", arch: "amd64", cpus: 8,
		files: withFiles(ec2DMI("c6i.2xlarge"), fakeFS{
			"/proc/sys/kernel/osrelease":        "6.8.0-1018-aws\n",
			"/proc/cpuinfo":                     cpuInfoX86(xeon8375C, 8),
			"/proc/meminfo":                     memInfo(16029392),
			"/sys/fs/cgroup/cgroup.controllers": "cpuset cpu io memory hugetlb pids rdma misc\n",
		}),
		cmds: mergeReplies(toolReplies(), map[string]reply{
			"podman info --format json": {stdout: readFixture(t, "podman_info_rootful_ubuntu2404.out")},
			"systemd-detect-virt --vm":  {stdout: "amazon\n"},
		}),
		installed: append([]string{"podman", "systemd-detect-virt"}, toolBinaries...),
		imds: &fakeIMDS{token: fakeToken, answers: map[string]string{
			"instance-type":               "c6i.2xlarge",
			"ami-id":                      "ami-0f1e2d3c4b5a69788",
			"placement/region":            "eu-central-1",
			"placement/availability-zone": "eu-central-1b",
		}},
	}
}

// scenarioC6iMetal is an EC2 c6i.metal bare-metal instance with rootful Podman.
func scenarioC6iMetal(t *testing.T) scenario {
	return scenario{
		os: "linux", arch: "amd64", cpus: 128,
		files: withFiles(ec2DMI("c6i.metal"), fakeFS{
			"/proc/sys/kernel/osrelease":        "6.8.0-1018-aws\n",
			"/proc/cpuinfo":                     cpuInfoX86(xeon8375C, 128),
			"/proc/meminfo":                     memInfo(262144000),
			"/sys/fs/cgroup/cgroup.controllers": "cpuset cpu io memory hugetlb pids rdma misc\n",
		}),
		cmds: mergeReplies(toolReplies(), map[string]reply{
			"podman info --format json": {stdout: readFixture(t, "podman_info_rootful_ubuntu2404.out")},
			// systemd-detect-virt prints "none" and exits 1 on bare metal.
			"systemd-detect-virt --vm": {stdout: "none\n", err: errExit1},
		}),
		installed: append([]string{"podman", "systemd-detect-virt"}, toolBinaries...),
		imds: &fakeIMDS{token: fakeToken, answers: map[string]string{
			"instance-type":               "c6i.metal",
			"ami-id":                      "ami-0f1e2d3c4b5a69788",
			"placement/region":            "eu-central-1",
			"placement/availability-zone": "eu-central-1b",
		}},
	}
}

// scenarioMacPodmanMachine is the author's macOS laptop: Apple M2 Pro, podman
// machine with the libkrun provider, rootless. All command outputs are
// captured from that host.
func scenarioMacPodmanMachine(t *testing.T) scenario {
	return scenario{
		os: "darwin", arch: "arm64", cpus: 12,
		cmds: mergeReplies(toolReplies(), map[string]reply{
			"sysctl -n machdep.cpu.brand_string": {stdout: "Apple M2 Pro\n"},
			"sysctl -n hw.memsize":               {stdout: "17179869184\n"},
			"podman info --format json":          {stdout: readFixture(t, "podman_info_rootless_macos_libkrun.out")},
			"podman machine list --format json":  {stdout: readFixture(t, "podman_machine_list_libkrun.out")},
		}),
		installed: append([]string{"podman"}, toolBinaries...),
	}
}

// scenarioBareMetalDocker is a physical Dell server running Docker 27 with the
// classic overlay2 driver.
func scenarioBareMetalDocker(t *testing.T) scenario {
	return scenario{
		os: "linux", arch: "amd64", cpus: 16,
		files: fakeFS{
			"/sys/class/dmi/id/sys_vendor":      "Dell Inc.\n",
			"/sys/class/dmi/id/product_name":    "PowerEdge R740\n",
			"/sys/class/dmi/id/board_vendor":    "Dell Inc.\n",
			"/sys/class/dmi/id/bios_vendor":     "Dell Inc.\n",
			"/sys/class/dmi/id/bios_version":    "2.19.1\n",
			"/proc/sys/kernel/osrelease":        "6.8.0-45-generic\n",
			"/proc/cpuinfo":                     cpuInfoX86("Intel(R) Xeon(R) Silver 4110 CPU @ 2.10GHz", 16),
			"/proc/meminfo":                     memInfo(65807976),
			"/sys/fs/cgroup/cgroup.controllers": "cpuset cpu io memory pids\n",
		},
		cmds: mergeReplies(toolReplies(), map[string]reply{
			"docker info --format {{json .}}": {stdout: readFixture(t, "docker_info_overlay2.out")},
			"systemd-detect-virt --vm":        {stdout: "none\n", err: errExit1},
		}),
		installed: append([]string{"docker", "systemd-detect-virt"}, toolBinaries...),
	}
}

// scenarioUnknownHost has no DMI, no systemd-detect-virt, no engine and no
// tools, like a stripped container on an unidentifiable machine.
func scenarioUnknownHost() scenario {
	return scenario{
		os: "linux", arch: "riscv64", cpus: 4,
		files: fakeFS{},
		cmds:  map[string]reply{},
	}
}
