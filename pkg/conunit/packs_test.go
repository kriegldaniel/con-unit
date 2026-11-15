package conunit_test

import (
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
	"github.com/con-unit/con-unit/pkg/engine"
)

func TestRulePackCustomization(t *testing.T) {
	t.Run("Exempting SPEC-01 suppresses userNotRoot check", func(t *testing.T) {
		pack := conunit.ProductionHygiene().Except("SPEC-01", "SPEC-02", "SPEC-03")

		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					User: "root", // Normally violates SPEC-01
				},
			},
		}

		pack.Apply(c)

		// Check if SPEC-01 was recorded
		for _, f := range c.Failures {
			if f.RuleType == "user_not_root" {
				t.Errorf("SPEC-01 was exempted, but failure was still recorded: %s", f.Message)
			}
		}
	})

	t.Run("Distroless hardening pack properties", func(t *testing.T) {
		distro := conunit.DistrolessHardening()
		if distro.ID() != "PACK-DISTROLESS" {
			t.Errorf("Expected pack ID 'PACK-DISTROLESS', got '%s'", distro.ID())
		}
	})

	t.Run("CIS Docker Benchmark pack properties", func(t *testing.T) {
		cis := conunit.CISBenchmark()
		if cis.ID() != "PACK-CONUNIT-HARDENING" {
			t.Errorf("Expected pack ID 'PACK-CONUNIT-HARDENING', got '%s'", cis.ID())
		}
		if cis.Name() == "" {
			t.Error("Expected non-empty pack name")
		}

		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					User: "10001",
					Cmd:  []string{"sh"},
				},
			},
		}
		cis.AllowPrivilegedPorts().AllowBinaries("sh").AllowPaths("/tmp")
		cis.Apply(c)
	})

	t.Run("NIST SP 800-190 pack properties", func(t *testing.T) {
		nist := conunit.NIST_SP_800_190()
		if nist.ID() != "PACK-NIST-800-190" {
			t.Errorf("Expected pack ID 'PACK-NIST-800-190', got '%s'", nist.ID())
		}
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					User: "10001",
					Cmd:  []string{"app"},
				},
			},
		}
		nist.Apply(c)
	})

	t.Run("Kubernetes Hardened pack properties", func(t *testing.T) {
		kube := conunit.KubeHardened()
		if kube.ID() != "PACK-KUBE-HARDENED" {
			t.Errorf("Expected pack ID 'PACK-KUBE-HARDENED', got '%s'", kube.ID())
		}
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					User: "10001",
				},
			},
		}
		kube.Apply(c)
	})

	t.Run("Distroless hardening pack apply", func(t *testing.T) {
		distro := conunit.DistrolessHardening()
		c := &conunit.Container{
			Inspect: &engine.ImageInspect{
				Config: engine.ImageConfig{
					User: "10001",
				},
			},
		}
		distro.Apply(c)
	})
}

func TestCIS46RequiresHealthcheckRatherThanEntrypointOrCommand(t *testing.T) {
	onlyCIS46 := conunit.CISBenchmark().Except(
		"CIS-4.1",
		"CIS-4.8",
		"CIS-4.9",
		"CIS-4.10",
		"CIS-4.11",
		"CIS-4.3",
		"CIS-4.5",
		"CIS-5.3",
		"CIS-5.7",
		"CIS-5.10",
		"CIS-5.12",
		"CIS-5.25",
	)
	c := &conunit.Container{
		Inspect: &engine.ImageInspect{
			Config: engine.ImageConfig{
				Entrypoint: []string{"/app"},
				Cmd:        []string{"serve"},
			},
		},
	}

	onlyCIS46.Apply(c)
	if len(c.Results) != 1 {
		t.Fatalf("Expected only CIS-4.6 to run, got %d results", len(c.Results))
	}
	if c.Results[0].TestID != "CIS-4.6" {
		t.Fatalf("Expected CIS-4.6 result, got %q", c.Results[0].TestID)
	}
	if c.Results[0].Passed {
		t.Fatal("CIS-4.6 passed with ENTRYPOINT and CMD but no HEALTHCHECK metadata")
	}
}
