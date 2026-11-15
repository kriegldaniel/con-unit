package conunit

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SignatureVerificationUnavailableError means the verifier could not produce
// a trustworthy decision. It must not be interpreted as a rejected signature.
type SignatureVerificationUnavailableError struct {
	Err error
}

func (e *SignatureVerificationUnavailableError) Error() string {
	return fmt.Sprintf("signature verification is unavailable: %v", e.Err)
}

func (e *SignatureVerificationUnavailableError) Unwrap() error {
	return e.Err
}

// VerifyWithCosign verifies a pinned repository digest using the installed
// Cosign CLI and the supplied key or keyless identity/issuer policy.
func VerifyWithCosign(ctx context.Context, imageRef string, policy SignatureTrustPolicy) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid signature trust policy: %w", err)
	}
	if !isImmutableDigestReference(imageRef) {
		return fmt.Errorf("signature verification requires an immutable sha256 repository digest reference")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cosignPath, err := exec.LookPath("cosign")
	if err != nil {
		return &SignatureVerificationUnavailableError{Err: err}
	}

	args := []string{"verify"}
	if strings.TrimSpace(policy.KeyPath) != "" {
		args = append(args, "--key", policy.KeyPath)
	} else {
		args = append(args,
			"--certificate-identity", policy.CertificateIdentity,
			"--certificate-oidc-issuer", policy.CertificateIssuer,
		)
	}
	args = append(args, imageRef)
	output, err := exec.CommandContext(ctx, cosignPath, args...).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return &SignatureVerificationUnavailableError{Err: ctx.Err()}
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return &SignatureVerificationUnavailableError{Err: err}
		}
		return fmt.Errorf("Cosign signature verification failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
