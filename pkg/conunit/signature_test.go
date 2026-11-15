package conunit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/con-unit/con-unit/pkg/conunit"
)

func installFakeCosign(t *testing.T, exitCode, output string) string {
	t.Helper()
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "cosign-args")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$FAKE_COSIGN_ARGS"
printf '%s\n' "$FAKE_COSIGN_OUTPUT"
exit "${FAKE_COSIGN_EXIT:-0}"
`
	if err := os.WriteFile(filepath.Join(dir, "cosign"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake Cosign executable: %v", err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FAKE_COSIGN_ARGS", argsPath)
	t.Setenv("FAKE_COSIGN_EXIT", exitCode)
	t.Setenv("FAKE_COSIGN_OUTPUT", output)
	return argsPath
}

func TestVerifyWithCosignUsesPinnedDigestAndKeyPolicy(t *testing.T) {
	argsPath := installFakeCosign(t, "0", "verified")
	imageRef := "registry.example/team/app@sha256:" + strings.Repeat("a", 64)
	policy := conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"}

	if err := conunit.VerifyWithCosign(context.Background(), imageRef, policy); err != nil {
		t.Fatalf("VerifyWithCosign returned error: %v", err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read fake Cosign arguments: %v", err)
	}
	arguments := strings.Split(strings.TrimSpace(string(args)), "\n")
	want := []string{"verify", "--key", "/keys/cosign.pub", imageRef}
	if len(arguments) != len(want) {
		t.Fatalf("Cosign arguments = %q, want %q", arguments, want)
	}
	for i := range want {
		if arguments[i] != want[i] {
			t.Errorf("Cosign argument %d = %q, want %q", i, arguments[i], want[i])
		}
	}
}

func TestVerifyWithCosignUsesKeylessIdentityPolicy(t *testing.T) {
	argsPath := installFakeCosign(t, "0", "verified")
	imageRef := "registry.example/team/app@sha256:" + strings.Repeat("b", 64)
	policy := conunit.SignatureTrustPolicy{
		CertificateIdentity: "builder@example.test",
		CertificateIssuer:   "https://issuer.example.test",
	}

	if err := conunit.VerifyWithCosign(context.Background(), imageRef, policy); err != nil {
		t.Fatalf("VerifyWithCosign returned error: %v", err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read fake Cosign arguments: %v", err)
	}
	for _, expected := range []string{"--certificate-identity\nbuilder@example.test", "--certificate-oidc-issuer\nhttps://issuer.example.test", imageRef} {
		if !strings.Contains(string(args), expected) {
			t.Errorf("Cosign arguments %q do not contain %q", args, expected)
		}
	}
}

func TestVerifyWithCosignRejectsInvalidPolicyAndMutableTag(t *testing.T) {
	if err := conunit.VerifyWithCosign(context.Background(), "registry.example/team/app:latest", conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"}); err == nil {
		t.Fatal("VerifyWithCosign accepted a mutable tag")
	}
	if err := conunit.VerifyWithCosign(context.Background(), "registry.example/team/app@sha256:"+strings.Repeat("c", 64), conunit.SignatureTrustPolicy{CertificateIdentity: "builder@example.test"}); err == nil {
		t.Fatal("VerifyWithCosign accepted an incomplete keyless policy")
	}
}

func TestVerifyWithCosignRejectsSignatureAndReportsUnavailableVerifier(t *testing.T) {
	imageRef := "registry.example/team/app@sha256:" + strings.Repeat("d", 64)
	policy := conunit.SignatureTrustPolicy{KeyPath: "/keys/cosign.pub"}
	installFakeCosign(t, "1", "no matching signatures")
	if err := conunit.VerifyWithCosign(context.Background(), imageRef, policy); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("rejected signature error = %v, want verification failure", err)
	}

	t.Setenv("PATH", t.TempDir())
	err := conunit.VerifyWithCosign(context.Background(), imageRef, policy)
	var unavailable *conunit.SignatureVerificationUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("missing Cosign error = %v, want SignatureVerificationUnavailableError", err)
	}
}
