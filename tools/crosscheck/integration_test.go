package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/con-unit/con-unit/pkg/engine"
	"github.com/con-unit/con-unit/pkg/spec"
)

// The tests of this file need a container engine and a Dockle binary, so they
// are off by default and the offline tests never depend on them. Run them with
//
//	CONUNIT_INTEGRATION=1 go test ./tools/crosscheck -run Integration -v
//
// Dockle is taken from CONUNIT_DOCKLE, or else from the PATH. The tests skip
// when podman or Dockle is missing. They build the image
// localhost/cu-crosscheck-it:<format> from files created in a temporary
// directory and remove it again.
const (
	integrationEnv   = "CONUNIT_INTEGRATION"
	integrationImage = "localhost/cu-crosscheck-it"
)

// seededContainerfile starts from scratch so that the build needs no network
// and the image holds only what the test puts into it: a duplicate user ID, an
// ENV key that names a credential, a credential file name, a volume on a
// sensitive directory and no USER instruction.
const seededContainerfile = `FROM scratch
COPY etc/passwd /etc/passwd
COPY app/id_rsa /app/id_rsa
ENV DB_PASSWORD=placeholder
VOLUME /proc
`

const seededPasswd = "root:x:0:0:root:/root:/bin/sh\nfirst:x:5:5::/home/first:/bin/sh\nsecond:x:5:5::/home/second:/bin/sh\n"

func integrationSetup(t *testing.T) (*engine.Engine, string) {
	t.Helper()
	if os.Getenv(integrationEnv) != "1" {
		t.Skipf("set %s=1 to run the tests that need an engine and Dockle", integrationEnv)
	}
	binary := os.Getenv("CONUNIT_DOCKLE")
	if binary == "" {
		p, err := exec.LookPath("dockle")
		if err != nil {
			t.Skip("dockle is not installed and CONUNIT_DOCKLE is not set")
		}
		binary = p
	}
	eng, err := engine.DetectEngine("podman")
	if err != nil {
		t.Skipf("podman is not available: %v", err)
	}
	return eng, binary
}

// buildSeeded builds the seeded image in the given format and registers its
// removal. It returns the reference and the image ID that the engine reports.
func buildSeeded(t *testing.T, eng *engine.Engine, format string) (ref, id string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"Containerfile": seededContainerfile,
		"etc/passwd":    seededPasswd,
		"app/id_rsa":    "not a key, a placeholder for the file name\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ref = integrationImage + ":" + format
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		_ = eng.Command(c, "rmi", "-f", ref).Run()
	})
	var out bytes.Buffer
	build := eng.Command(ctx, "build", "--format", format, "-t", ref, "-f", filepath.Join(dir, "Containerfile"), dir)
	build.Stdout, build.Stderr = &out, &out
	if err := build.Run(); err != nil {
		t.Fatalf("building %s failed: %v\n%s", ref, err, out.String())
	}
	got, err := eng.Command(ctx, "image", "inspect", "--format", "{{.Id}}", ref).Output()
	if err != nil {
		t.Fatalf("inspecting %s failed: %v", ref, err)
	}
	return ref, strings.TrimSpace(string(got))
}

func TestIntegrationSeededImageThroughTheRealPipeline(t *testing.T) {
	eng, binary := integrationSetup(t)

	// DOCKLE_ variables of the environment of the test must not change what
	// Dockle reports: the runner removes them. These would hide the findings
	// that the assertions below expect.
	t.Setenv("DOCKLE_IGNORES", "CIS-DI-0001,CIS-DI-0010,DKL-DI-0002")
	t.Setenv("DOCKLE_ACCEPT_FILES", "id_rsa")

	for _, format := range []string{"docker", "oci"} {
		t.Run(format, func(t *testing.T) {
			ref, id := buildSeeded(t, eng, format)
			runner := &ExecRunner{Binary: binary}
			defer runner.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			version, err := runner.Version(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if version != VerifiedDockleVersion {
				t.Logf("Dockle %s differs from %s, the version whose source fixed the schema", version, VerifiedDockleVersion)
			}

			p := &Pipeline{Exporter: &EngineExporter{Engine: eng}, Dockle: runner, Timeout: 5 * time.Minute}
			study := &spec.SuiteResult{ImageName: ref, RequestedRef: ref, ConfigDigest: id, Status: spec.StatusCompleted}
			rec := p.Process(ctx, study)
			if rec.Status != ImageOK {
				t.Fatalf("status %s: %s", rec.Status, rec.Error)
			}
			// The archive holds the image that the engine reports under this ID.
			if rec.ConfigDigestArchive != NormalizeDigest(id) {
				t.Errorf("archive config digest %s, engine image ID %s", rec.ConfigDigestArchive, NormalizeDigest(id))
			}
			if rec.Pulled {
				t.Error("a local image must not be pulled")
			}

			report, err := ParseReport([]byte(rec.DockleStdout))
			if err != nil {
				t.Fatalf("the report of the real Dockle does not parse: %v", err)
			}
			for _, want := range []struct{ code, alert string }{
				{"CIS-DI-0010", "DB_PASSWORD"},
				{"CIS-DI-0010", "id_rsa"},
				{"DKL-DI-0002", "/proc"},
				{"CIS-DI-0001", ""},
			} {
				res := report.Lookup(want.code)
				if res.State != CodeFinding {
					t.Errorf("%s: state %s, want a finding even with DOCKLE_ variables set", want.code, res.State)
					continue
				}
				if !strings.Contains(dockleAlerts(res.Entries), want.alert) {
					t.Errorf("%s: the alerts %q lack %q", want.code, dockleAlerts(res.Entries), want.alert)
				}
			}

			// The same archive against a study that holds another digest is
			// refused before Dockle runs.
			wrong := &spec.SuiteResult{ImageName: ref, RequestedRef: ref, ConfigDigest: "sha256:" + strings.Repeat("0", 64), Status: spec.StatusCompleted}
			if got := p.Process(ctx, wrong); got.Status != ImageDigestMismatch || got.DockleStdout != "" {
				t.Errorf("a wrong study digest: status %s, stdout %d bytes; want %s without a Dockle run", got.Status, len(got.DockleStdout), ImageDigestMismatch)
			}
		})
	}
}
