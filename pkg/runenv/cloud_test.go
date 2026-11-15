package runenv

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func imdsEnv(t *testing.T, imds HTTPDoer) Env {
	t.Helper()
	env := scenarioUnknownHost().build(t).env
	env.HTTP = imds
	return env.withDefaults()
}

func goodIMDS() *fakeIMDS {
	return &fakeIMDS{token: fakeToken, answers: map[string]string{
		"instance-type":               "c6i.2xlarge",
		"ami-id":                      "ami-0f1e2d3c4b5a69788",
		"placement/region":            "eu-central-1",
		"placement/availability-zone": "eu-central-1b",
	}}
}

func TestProbeIMDS(t *testing.T) {
	cases := []struct {
		name string
		imds *fakeIMDS
		want imdsFacts
	}{
		{
			name: "complete answers",
			imds: goodIMDS(),
			want: imdsFacts{InstanceType: "c6i.2xlarge", AMIID: "ami-0f1e2d3c4b5a69788", Region: "eu-central-1", Zone: "eu-central-1b"},
		},
		{
			name: "token request refused (IMDS disabled or hop limit)",
			imds: &fakeIMDS{token: fakeToken, status: http.StatusForbidden, answers: goodIMDS().answers},
			want: imdsFacts{},
		},
		{
			name: "token request returns an empty token",
			imds: &fakeIMDS{token: "", answers: goodIMDS().answers},
			want: imdsFacts{},
		},
		{
			name: "only some paths answer",
			imds: &fakeIMDS{token: fakeToken, answers: map[string]string{"instance-type": "m7i.large", "placement/region": "us-east-1"}},
			want: imdsFacts{InstanceType: "m7i.large", Region: "us-east-1"},
		},
		{
			name: "answers with surrounding whitespace are trimmed",
			imds: &fakeIMDS{token: fakeToken, answers: map[string]string{"instance-type": " c6i.metal\n", "ami-id": "ami-0abc12345678\n"}},
			want: imdsFacts{InstanceType: "c6i.metal", AMIID: "ami-0abc12345678"},
		},
		{
			name: "values that do not look like EC2 metadata are dropped",
			imds: &fakeIMDS{token: fakeToken, answers: map[string]string{
				"instance-type":               "<html>captive portal</html>",
				"ami-id":                      "not-an-ami",
				"placement/region":            "Europe",
				"placement/availability-zone": "zone with spaces",
			}},
			want: imdsFacts{},
		},
		{
			name: "local zone and gov region",
			imds: &fakeIMDS{token: fakeToken, answers: map[string]string{"placement/region": "us-gov-west-1", "placement/availability-zone": "us-west-2-lax-1a"}},
			want: imdsFacts{Region: "us-gov-west-1", Zone: "us-west-2-lax-1a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeIMDS(context.Background(), imdsEnv(t, tc.imds))
			if got != tc.want {
				t.Errorf("probeIMDS = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestProbeIMDSRequestShape(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []*http.Request
	)
	env := imdsEnv(t, recordingDoer{mu: &mu, inner: goodIMDS(), seen: &seen})
	probeIMDS(context.Background(), env)

	if len(seen) == 0 {
		t.Fatal("no requests recorded")
	}
	put := seen[0]
	if put.Method != http.MethodPut || put.URL.String() != "http://169.254.169.254/latest/api/token" {
		t.Errorf("first request = %s %s, want PUT /latest/api/token on the link-local address", put.Method, put.URL)
	}
	if put.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
		t.Errorf("token request lacks the TTL header")
	}
	for _, r := range seen[1:] {
		if r.Method != http.MethodGet {
			t.Errorf("request %s %s should be a GET", r.Method, r.URL)
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != fakeToken {
			t.Errorf("GET %s did not carry the session token", r.URL)
		}
		if !strings.HasPrefix(r.URL.Path, "/latest/meta-data/") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
}

type recordingDoer struct {
	mu    *sync.Mutex
	inner HTTPDoer
	seen  *[]*http.Request
}

func (r recordingDoer) Do(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	*r.seen = append(*r.seen, req)
	r.mu.Unlock()
	return r.inner.Do(req)
}

// TestProbeIMDSWithRealHTTPClient runs the production HTTP client against an
// IMDSv2 double on the loopback interface. Nothing leaves the machine.
func TestProbeIMDSWithRealHTTPClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/api/token" {
			if r.Method != http.MethodPut || r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				http.Error(w, "bad token request", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, fakeToken)
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != fakeToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		answers := goodIMDS().answers
		if v, ok := answers[strings.TrimPrefix(r.URL.Path, "/latest/meta-data/")]; ok {
			fmt.Fprint(w, v)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	env := Env{IMDSBase: srv.URL + "/", IMDSTimeout: time.Second}.withDefaults()
	got := probeIMDS(context.Background(), env)
	want := imdsFacts{InstanceType: "c6i.2xlarge", AMIID: "ami-0f1e2d3c4b5a69788", Region: "eu-central-1", Zone: "eu-central-1b"}
	if got != want {
		t.Errorf("probeIMDS = %+v, want %+v", got, want)
	}
}

func TestIMDSClientIgnoresProxies(t *testing.T) {
	tr, ok := newIMDSClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type")
	}
	if tr.Proxy != nil {
		t.Errorf("the IMDS client must not use a proxy: link-local traffic never leaves the host")
	}
	if !tr.DisableKeepAlives {
		t.Errorf("the IMDS client should not keep connections open")
	}
}

func TestProbeIMDSIsBoundedToOneSecond(t *testing.T) {
	// A hanging endpoint must cost at most the IMDS timeout, and the default
	// timeout must be capped at one second.
	t.Run("hang honored through context", func(t *testing.T) {
		env := imdsEnv(t, &fakeIMDS{token: fakeToken, hang: true})
		env.IMDSTimeout = 100 * time.Millisecond
		start := time.Now()
		got := probeIMDS(context.Background(), env)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("probeIMDS took %v, want about 100ms", elapsed)
		}
		if got != (imdsFacts{}) {
			t.Errorf("hanging IMDS must give no facts, got %+v", got)
		}
	})
	t.Run("doer that ignores its context", func(t *testing.T) {
		stuck := make(chan struct{})
		t.Cleanup(func() { close(stuck) })
		env := imdsEnv(t, &fakeIMDS{token: fakeToken, stuck: stuck})
		env.IMDSTimeout = 100 * time.Millisecond
		start := time.Now()
		probeIMDS(context.Background(), env)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("probeIMDS took %v with a stuck client, want about 100ms", elapsed)
		}
	})
	t.Run("defaults are capped", func(t *testing.T) {
		env := Env{IMDSTimeout: time.Minute, CommandTimeout: time.Hour}.withDefaults()
		if env.IMDSTimeout != time.Second {
			t.Errorf("IMDSTimeout = %v, want capped at 1s", env.IMDSTimeout)
		}
		if env.CommandTimeout != 2*time.Second {
			t.Errorf("CommandTimeout = %v, want capped at 2s", env.CommandTimeout)
		}
		zero := Env{}.withDefaults()
		if zero.IMDSTimeout != time.Second || zero.CommandTimeout != 2*time.Second {
			t.Errorf("zero value defaults = %v, %v", zero.IMDSTimeout, zero.CommandTimeout)
		}
	})
}

func TestIsMetalInstance(t *testing.T) {
	cases := map[string]bool{
		"c6i.metal":        true,
		"m7i.metal-24xl":   true,
		"m7i.metal-48xl":   true,
		"u-6tb1.metal":     true,
		"mac2.metal":       true,
		"C6I.METAL":        true,
		"c6i.2xlarge":      false,
		"c6i.32xlarge":     false,
		"metal.large":      false,
		"c6i.metalic":      false,
		"":                 false,
		"c6i.xlarge.metal": true,
	}
	for in, want := range cases {
		if got := isMetalInstance(in); got != want {
			t.Errorf("isMetalInstance(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDMIInstanceType(t *testing.T) {
	cases := map[string]string{
		"c6i.2xlarge":                    "c6i.2xlarge",
		"c6i.metal":                      "c6i.metal",
		"m7i.metal-24xl":                 "m7i.metal-24xl",
		"u-6tb1.112xlarge":               "u-6tb1.112xlarge",
		"t3.micro":                       "t3.micro",
		"HVM domU":                       "",
		"Standard PC (Q35 + ICH9, 2009)": "",
		"PowerEdge R740":                 "",
		"":                               "",
	}
	for in, want := range cases {
		if got := dmiInstanceType(dmiFacts{ProductName: in}); got != want {
			t.Errorf("dmiInstanceType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAWSSuspected(t *testing.T) {
	cases := []struct {
		name string
		dmi  dmiFacts
		want bool
	}{
		{"nitro vendor strings", dmiFacts{SysVendor: "Amazon EC2", BiosVendor: "Amazon EC2"}, true},
		{"xen bios version", dmiFacts{SysVendor: "Xen", BiosVersion: "4.11.amazon"}, true},
		{"case insensitive", dmiFacts{BoardVendor: "AMAZON EC2"}, true},
		{"dell", dmiFacts{SysVendor: "Dell Inc.", ProductName: "PowerEdge R740"}, false},
		{"empty", dmiFacts{}, false},
	}
	for _, tc := range cases {
		if got := awsSuspected(tc.dmi); got != tc.want {
			t.Errorf("%s: awsSuspected = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDMIHypervisor(t *testing.T) {
	cases := []struct {
		name string
		dmi  dmiFacts
		want string
	}{
		{"qemu", dmiFacts{SysVendor: "QEMU", ProductName: "Standard PC (Q35 + ICH9, 2009)"}, "qemu"},
		{"rhel kvm", dmiFacts{SysVendor: "Red Hat", ProductName: "KVM"}, "kvm"},
		{"vmware", dmiFacts{SysVendor: "VMware, Inc.", ProductName: "VMware Virtual Platform"}, "vmware"},
		{"virtualbox", dmiFacts{SysVendor: "innotek GmbH", ProductName: "VirtualBox"}, "oracle"},
		{"hyper-v", dmiFacts{SysVendor: "Microsoft Corporation", ProductName: "Virtual Machine"}, "microsoft"},
		{"surface laptop is not hyper-v", dmiFacts{SysVendor: "Microsoft Corporation", ProductName: "Surface Laptop 5"}, ""},
		{"xen", dmiFacts{SysVendor: "Xen", ProductName: "HVM domU"}, "xen"},
		{"google", dmiFacts{SysVendor: "Google", ProductName: "Google Compute Engine"}, "google"},
		{"parallels", dmiFacts{SysVendor: "Parallels Software International Inc."}, "parallels"},
		{"physical dell", dmiFacts{SysVendor: "Dell Inc.", ProductName: "PowerEdge R740", BiosVendor: "Dell Inc."}, ""},
		{"xeon is not xen", dmiFacts{ProductName: "Xeon Workstation"}, ""},
	}
	for _, tc := range cases {
		if got := dmiHypervisor(tc.dmi); got != tc.want {
			t.Errorf("%s: dmiHypervisor = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDeriveVirtualization(t *testing.T) {
	nitro := dmiFacts{SysVendor: "Amazon EC2", BiosVendor: "Amazon EC2", Readable: true}
	reachablePodman := engineFacts{Name: "podman", Reachable: true}

	cases := []struct {
		name string
		in   virtInputs
		want string
	}{
		{"nitro vm", virtInputs{OS: "linux", DMI: nitro, InstanceType: "c6i.2xlarge"}, VirtAWSNitroKVM},
		{"nitro metal", virtInputs{OS: "linux", DMI: nitro, InstanceType: "c6i.metal"}, VirtAWSNitroMetal},
		{"nitro metal with size", virtInputs{OS: "linux", DMI: nitro, InstanceType: "m7i.metal-24xl"}, VirtAWSNitroMetal},
		{"nitro, instance type unknown, systemd says amazon", virtInputs{OS: "linux", DMI: nitro, SystemdVirt: "amazon"}, VirtAWSNitroKVM},
		{"nitro, instance type unknown, systemd says none", virtInputs{OS: "linux", DMI: nitro, SystemdVirt: "none"}, VirtAWSNitroMetal},
		{"nitro, nothing else known", virtInputs{OS: "linux", DMI: nitro}, VirtAWSNitro},
		{"xen on aws", virtInputs{OS: "linux", DMI: dmiFacts{SysVendor: "Xen", BiosVendor: "Xen", BiosVersion: "4.11.amazon"}, InstanceType: "t2.micro"}, VirtAWSXen},
		{"remote engine", virtInputs{OS: "linux", DMI: nitro, InstanceType: "c6i.2xlarge", Remote: true}, VirtUnknown},
		{"macos libkrun", virtInputs{OS: "darwin", Engine: reachablePodman, MachineVMType: "libkrun"}, VirtAppleHypervisorLibkrun},
		{"macos applehv", virtInputs{OS: "darwin", Engine: reachablePodman, MachineVMType: "applehv"}, VirtAppleVirtualization},
		{"macos qemu", virtInputs{OS: "darwin", Engine: reachablePodman, MachineVMType: "qemu"}, VirtQEMUHVF},
		{"macos unknown provider", virtInputs{OS: "darwin", Engine: reachablePodman}, VirtMacOSVM},
		{"macos docker desktop", virtInputs{OS: "darwin", Engine: engineFacts{Name: "docker", Reachable: true, DockerDesktop: true}}, VirtAppleVirtualization},
		{"macos engine unreachable", virtInputs{OS: "darwin", Engine: engineFacts{Name: "podman"}, MachineVMType: "libkrun"}, VirtUnknown},
		{"physical dmi", virtInputs{OS: "linux", DMI: dmiFacts{SysVendor: "Dell Inc.", Readable: true}}, VirtBareMetal},
		{"physical dmi confirmed by systemd", virtInputs{OS: "linux", DMI: dmiFacts{SysVendor: "Dell Inc.", Readable: true}, SystemdVirt: "none"}, VirtBareMetal},
		{"systemd none without dmi", virtInputs{OS: "linux", SystemdVirt: "none"}, VirtBareMetal},
		{"systemd names the hypervisor", virtInputs{OS: "linux", DMI: dmiFacts{SysVendor: "Dell Inc.", Readable: true}, SystemdVirt: "vmware"}, "vmware"},
		{"no evidence", virtInputs{OS: "linux"}, VirtUnknown},
		{"unsupported os", virtInputs{OS: "freebsd", DMI: nitro, InstanceType: "c6i.2xlarge"}, VirtUnknown},
	}
	for _, tc := range cases {
		if got := deriveVirtualization(tc.in); got != tc.want {
			t.Errorf("%s: deriveVirtualization = %q, want %q", tc.name, got, tc.want)
		}
	}
}
