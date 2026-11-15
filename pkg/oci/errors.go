package oci

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// The two ways the filesystem index can exceed its limit.
const (
	// IndexLimitEntries means the number of indexed paths exceeded the cap.
	IndexLimitEntries = "entries"
	// IndexLimitMemory means the estimated memory of the index exceeded the
	// budget derived from the cap, which only happens when paths are far
	// longer than in real images.
	IndexLimitMemory = "memory"
)

// IndexTooLargeError means the filesystem index of an image would exceed the
// configured limit. The image is excluded from analysis, not failed: the limit
// is a property of the tool, not of the image. The size fields are lower
// bounds on the image, observed before indexing stopped.
type IndexTooLargeError struct {
	// Dimension is IndexLimitEntries or IndexLimitMemory.
	Dimension string
	// Limit is the configured entry cap.
	Limit int
	// ByteBudget is the estimated-memory budget derived from Limit. Zero when
	// the error was built without one.
	ByteBudget int64
	// Entries is the number of index entries counted when indexing stopped.
	Entries int
	// EstimatedBytes is the estimated index memory when indexing stopped.
	EstimatedBytes int64
	// Layer is the 1-based layer being read when indexing stopped, and Layers
	// the number of layers of the image. Zero when unknown.
	Layer  int
	Layers int
	// ScannedBytes is the content size of the regular files read before
	// indexing stopped, summed over all layers read so far.
	ScannedBytes int64
}

func (e *IndexTooLargeError) Error() string {
	message := fmt.Sprintf("filesystem index exceeds configured limit of %d entries", e.Limit)
	var detail []string
	switch e.Dimension {
	case IndexLimitMemory:
		detail = append(detail, fmt.Sprintf("estimated index memory %s exceeds the %s budget derived from the limit", FormatBytes(e.EstimatedBytes), FormatBytes(e.ByteBudget)))
		if e.Entries > 0 {
			detail = append(detail, fmt.Sprintf("after %d entries", e.Entries))
		}
	default:
		if e.Entries > 0 {
			detail = append(detail, fmt.Sprintf("%d entries counted", e.Entries))
		}
	}
	if e.Layer > 0 && e.Layers > 0 {
		detail = append(detail, fmt.Sprintf("in layer %d of %d", e.Layer, e.Layers))
	}
	if e.ScannedBytes > 0 {
		detail = append(detail, fmt.Sprintf("%s of file content read", FormatBytes(e.ScannedBytes)))
	}
	if len(detail) == 0 {
		return message
	}
	return message + " (" + strings.Join(detail, ", ") + ")"
}

// FormatBytes renders a byte count with a binary unit, for messages and logs.
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	divisor, suffix := int64(unit), "KiB"
	for _, next := range []string{"MiB", "GiB", "TiB"} {
		if n < divisor*unit {
			break
		}
		divisor *= unit
		suffix = next
	}
	return fmt.Sprintf("%.1f %s", float64(n)/float64(divisor), suffix)
}

// IdentityMismatchError means the content that was read is not provably the
// image that was requested (digest or config mismatch).
type IdentityMismatchError struct {
	Ref    string
	Detail string
}

func (e *IdentityMismatchError) Error() string {
	if e.Ref == "" {
		return "image identity mismatch: " + e.Detail
	}
	return fmt.Sprintf("image identity mismatch for %s: %s", e.Ref, e.Detail)
}

// PlatformMismatchError means the resolved image does not have the requested
// platform.
type PlatformMismatchError struct {
	Ref    string
	Detail string
}

func (e *PlatformMismatchError) Error() string {
	if e.Ref == "" {
		return "platform mismatch: " + e.Detail
	}
	return fmt.Sprintf("platform mismatch for %s: %s", e.Ref, e.Detail)
}

// NotFoundError means the registry has no such manifest, image or repository.
type NotFoundError struct {
	Ref string
	Err error
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("image %s not found in registry: %v", e.Ref, e.Err)
}

func (e *NotFoundError) Unwrap() error { return e.Err }

// RateLimitError means the registry answered HTTP 429 to ConUnit's own client.
type RateLimitError struct {
	Ref string
	Err error
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("registry rate limit hit while reading %s: %v", e.Ref, e.Err)
}

func (e *RateLimitError) Unwrap() error { return e.Err }

// RetryAfter returns the wait hint of the registry. The transport error of
// go-containerregistry does not expose response headers, so the hint is
// always absent and callers fall back to exponential backoff.
func (e *RateLimitError) RetryAfter() time.Duration { return 0 }

// classifyRemoteError maps registry transport errors to typed errors. Errors
// that are not recognized are returned unchanged.
func classifyRemoteError(ref string, err error) error {
	if err == nil {
		return nil
	}
	var transportErr *transport.Error
	if !errors.As(err, &transportErr) {
		return err
	}
	if transportErr.StatusCode == http.StatusTooManyRequests {
		return &RateLimitError{Ref: ref, Err: err}
	}
	if transportErr.StatusCode == http.StatusNotFound {
		return &NotFoundError{Ref: ref, Err: err}
	}
	for _, diagnostic := range transportErr.Errors {
		switch diagnostic.Code {
		case transport.TooManyRequestsErrorCode:
			return &RateLimitError{Ref: ref, Err: err}
		case transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode:
			return &NotFoundError{Ref: ref, Err: err}
		}
	}
	return err
}
