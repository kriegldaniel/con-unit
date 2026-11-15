package runenv

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// Values written to spec.RunMetadata.Virtualization.
const (
	VirtAWSNitroKVM            = "aws-nitro-kvm"            // EC2 virtual machine on the Nitro hypervisor (KVM based)
	VirtAWSNitroMetal          = "aws-nitro-metal"          // EC2 bare-metal instance (instance type ends in .metal)
	VirtAWSNitro               = "aws-nitro"                // Nitro host, but VM or metal could not be told apart
	VirtAWSXen                 = "aws-xen"                  // EC2 instance on the legacy Xen hypervisor
	VirtAppleVirtualization    = "apple-virtualization"     // macOS, VM on Apple Virtualization (applehv, Docker Desktop)
	VirtAppleHypervisorLibkrun = "apple-hypervisor-libkrun" // macOS, podman machine with the libkrun provider
	VirtQEMUHVF                = "qemu-hvf"                 // macOS, podman machine with the qemu provider
	VirtMacOSVM                = "macos-vm"                 // macOS, a Linux VM of undetermined hypervisor
	VirtBareMetal              = "bare-metal"               // DMI and systemd-detect-virt show no hypervisor
	VirtVMOther                = "vm-other"                 // systemd-detect-virt sees a VM but cannot name the hypervisor
	VirtUnknown                = "unknown"
)

// CloudAWS is written to spec.RunMetadata.CloudProvider on EC2.
const CloudAWS = "aws"

// IMDS paths. Only IMDSv2 is used; there is no fallback to IMDSv1.
const (
	imdsTokenPath = "/latest/api/token"
	imdsTokenTTL  = "60" // seconds, the token is used immediately
	imdsTTLHeader = "X-aws-ec2-metadata-token-ttl-seconds"
	imdsTokHeader = "X-aws-ec2-metadata-token"
)

var (
	instanceTypeRE = regexp.MustCompile(`^[a-z][a-z0-9-]*[0-9][a-z0-9-]*\.[a-z0-9-]+$`)
	amiRE          = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	regionRE       = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	zoneRE         = regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+$`)
	xenRE          = regexp.MustCompile(`\bxen\b`)
	kvmRE          = regexp.MustCompile(`\bkvm\b`)
)

// imdsFacts are the values read from the instance metadata service. Every
// value is validated against the shape of a real answer, so an unrelated
// service on the link-local address cannot inject text into the metadata.
type imdsFacts struct {
	InstanceType string
	AMIID        string
	Region       string
	Zone         string
}

// probeIMDS performs the IMDSv2 exchange: a PUT for a session token, then GET
// requests for instance type, AMI, region and availability zone. The whole
// exchange shares one deadline of env.IMDSTimeout (at most 1 s).
func probeIMDS(ctx context.Context, env Env) imdsFacts {
	ctx, cancel := context.WithTimeout(ctx, env.IMDSTimeout)
	defer cancel()
	base := strings.TrimRight(env.IMDSBase, "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+imdsTokenPath, nil)
	if err != nil {
		return imdsFacts{}
	}
	req.Header.Set(imdsTTLHeader, imdsTokenTTL)
	res, err := env.do(ctx, req)
	if err != nil || res.Status != http.StatusOK {
		return imdsFacts{}
	}
	token := strings.TrimSpace(string(res.Body))
	if token == "" || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") {
		return imdsFacts{}
	}

	get := func(path string, valid *regexp.Regexp) string {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest/meta-data/"+path, nil)
		if err != nil {
			return ""
		}
		req.Header.Set(imdsTokHeader, token)
		res, err := env.do(ctx, req)
		if err != nil || res.Status != http.StatusOK {
			return ""
		}
		v := strings.TrimSpace(string(res.Body))
		if !valid.MatchString(v) {
			return ""
		}
		return v
	}

	var f imdsFacts
	parallel(
		func() { f.InstanceType = get("instance-type", instanceTypeRE) },
		func() { f.AMIID = get("ami-id", amiRE) },
		func() { f.Region = get("placement/region", regionRE) },
		func() { f.Zone = get("placement/availability-zone", zoneRE) },
	)
	return f
}

// awsSuspected reports whether the DMI strings point to EC2. Nitro hosts say
// "Amazon EC2" in the vendor fields, Xen based hosts carry "amazon" in the
// BIOS version.
func awsSuspected(d dmiFacts) bool {
	for _, s := range []string{d.SysVendor, d.ProductName, d.BoardVendor, d.BiosVendor, d.BiosVersion} {
		if strings.Contains(strings.ToLower(s), "amazon") {
			return true
		}
	}
	return false
}

// systemdVirtAmazon is what systemd-detect-virt prints on a Nitro virtual
// machine (systemd 254 and later).
const systemdVirtAmazon = "amazon"

// isAWS reports whether any collected signal says the host is EC2.
func isAWS(d dmiFacts, systemdVirt, imdsInstanceType string) bool {
	return awsSuspected(d) || systemdVirt == systemdVirtAmazon || imdsInstanceType != ""
}

// isMetalInstance reports whether an EC2 instance type is a bare-metal one,
// for example c6i.metal or m7i.metal-24xl.
func isMetalInstance(instanceType string) bool {
	t := strings.ToLower(instanceType)
	return strings.HasSuffix(t, ".metal") || strings.Contains(t, ".metal-")
}

// dmiInstanceType returns the DMI product name when it has the shape of an
// EC2 instance type. On EC2 the product name is the instance type.
func dmiInstanceType(d dmiFacts) string {
	if instanceTypeRE.MatchString(d.ProductName) {
		return d.ProductName
	}
	return ""
}

// dmiHypervisor names the hypervisor that DMI strings reveal, using the ids
// of systemd-detect-virt, or "" when the strings look like physical hardware.
func dmiHypervisor(d dmiFacts) string {
	all := strings.ToLower(strings.Join([]string{d.SysVendor, d.ProductName, d.BoardVendor, d.BiosVendor}, " "))
	switch {
	case strings.Contains(all, "vmware"):
		return "vmware"
	case strings.Contains(all, "virtualbox"), strings.Contains(all, "innotek"):
		return "oracle"
	case strings.Contains(all, "parallels"):
		return "parallels"
	case strings.Contains(all, "bochs"):
		return "bochs"
	case strings.Contains(strings.ToLower(d.SysVendor), "microsoft") && strings.Contains(strings.ToLower(d.ProductName), "virtual machine"):
		return "microsoft"
	case xenRE.MatchString(all):
		return "xen"
	case strings.Contains(all, "qemu"):
		return "qemu"
	case kvmRE.MatchString(all):
		return "kvm"
	case strings.Contains(all, "google compute engine"):
		return "google"
	}
	return ""
}

// virtInputs are the detected facts the virtualization label is derived from.
type virtInputs struct {
	OS            string
	DMI           dmiFacts
	SystemdVirt   string // "", "none" or a hypervisor id
	InstanceType  string // from IMDS, else from DMI
	Engine        engineFacts
	MachineVMType string // podman machine provider on macOS
	Remote        bool   // the engine runs on another machine
}

// deriveVirtualization maps detected facts to a Virtualization label. It
// never guesses: when the evidence is missing or contradictory the result is
// VirtUnknown.
func deriveVirtualization(in virtInputs) string {
	if in.Remote {
		return VirtUnknown
	}
	switch in.OS {
	case "darwin":
		return deriveMacVirtualization(in)
	case "linux":
		return deriveLinuxVirtualization(in)
	}
	return VirtUnknown
}

// deriveMacVirtualization: containers on macOS always run in a Linux VM. The
// label names the hypervisor when it is known and says so when it is not.
func deriveMacVirtualization(in virtInputs) string {
	if !in.Engine.Reachable {
		return VirtUnknown
	}
	if in.Engine.Name == engineDocker && in.Engine.DockerDesktop {
		return VirtAppleVirtualization
	}
	switch in.MachineVMType {
	case "applehv":
		return VirtAppleVirtualization
	case "libkrun":
		return VirtAppleHypervisorLibkrun
	case "qemu":
		return VirtQEMUHVF
	}
	return VirtMacOSVM
}

func deriveLinuxVirtualization(in virtInputs) string {
	d := in.DMI
	if isAWS(d, in.SystemdVirt, in.InstanceType) {
		return deriveAWSVirtualization(in)
	}

	sdv := in.SystemdVirt
	marker := dmiHypervisor(d)
	switch {
	case sdv != "" && sdv != "none":
		return sdv // systemd-detect-virt names the hypervisor itself
	case marker != "" && sdv == "none":
		return VirtUnknown // DMI shows a hypervisor, systemd-detect-virt shows none
	case marker != "":
		return marker
	case sdv == "none":
		return VirtBareMetal
	case d.Readable:
		return VirtBareMetal // DMI shows physical hardware and no other source objects
	}
	return VirtUnknown
}

func deriveAWSVirtualization(in virtInputs) string {
	d := in.DMI
	if strings.EqualFold(d.BiosVendor, "xen") || strings.EqualFold(d.SysVendor, "xen") {
		return VirtAWSXen
	}
	if in.InstanceType != "" {
		if isMetalInstance(in.InstanceType) {
			return VirtAWSNitroMetal
		}
		return VirtAWSNitroKVM
	}
	// Instance type unknown: let systemd-detect-virt tell VM and metal apart.
	switch in.SystemdVirt {
	case "":
		return VirtAWSNitro
	case "none":
		return VirtAWSNitroMetal
	}
	return VirtAWSNitroKVM
}
