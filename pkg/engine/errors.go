package engine

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RateLimitError means the registry throttled a request made by the container
// engine (HTTP 429, "toomanyrequests" or "pull rate limit" in the engine's
// stderr). It is the only place where rate limiting is recognized from text:
// callers use errors.As on this type and never inspect error strings.
type RateLimitError struct {
	Op     string        // engine operation, for example "pull"
	Image  string        // image reference the operation was acting on
	After  time.Duration // server supplied wait hint, zero when absent
	Detail string        // trimmed engine output
}

func (e *RateLimitError) Error() string {
	msg := fmt.Sprintf("registry rate limit hit during engine %s of %s", e.Op, e.Image)
	if e.After > 0 {
		msg += fmt.Sprintf(" (retry after %s)", e.After)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// RetryAfter returns the wait hint supplied by the registry, if any.
func (e *RateLimitError) RetryAfter() time.Duration { return e.After }

// NotFoundError means the registry reported that the image, repository or
// manifest does not exist.
type NotFoundError struct {
	Op     string
	Image  string
	Detail string
}

func (e *NotFoundError) Error() string {
	msg := fmt.Sprintf("image %s not found during engine %s", e.Image, e.Op)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// ImageNotInStoreError means the image is absent from the engine's local
// store and the active image-source policy forbids pulling it.
type ImageNotInStoreError struct {
	Image string
}

func (e *ImageNotInStoreError) Error() string {
	return fmt.Sprintf("image %s is not present in the local engine store", e.Image)
}

var (
	rateLimitPattern = regexp.MustCompile(`(?i)toomanyrequests|too many requests|pull rate limit|(?:status|http|code)\D{0,12}\b429\b`)
	notFoundPattern  = regexp.MustCompile(`(?i)manifest unknown|name unknown|manifest .*not found|repository does not exist|no such image|image not known|not found: manifest|requested image not found`)
	retryAfterSecs   = regexp.MustCompile(`(?i)retry[- ]after[: =]+(\d+)`)
	tryAgainIn       = regexp.MustCompile(`(?i)try again in (\d+)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|h)\b`)
)

// classifyPullFailure converts a failed engine pull into a typed error when
// the engine output identifies throttling or a missing image. Any other
// failure stays a plain error that wraps the original cause. The deadline of
// ctx always wins, so callers can use errors.Is(err, context.DeadlineExceeded).
func classifyPullFailure(ctx context.Context, op, image, output string, cause error) error {
	trimmed := strings.TrimSpace(output)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("engine %s of %s interrupted: %w (%v)", op, image, ctxErr, cause)
	}
	switch {
	case rateLimitPattern.MatchString(trimmed):
		return &RateLimitError{Op: op, Image: image, After: parseRetryAfter(trimmed), Detail: trimmed}
	case notFoundPattern.MatchString(trimmed):
		return &NotFoundError{Op: op, Image: image, Detail: trimmed}
	}
	return fmt.Errorf("failed to %s image %s: %s (%w)", op, image, trimmed, cause)
}

// wrapContextError makes sure that an error caused by a finished context
// reports that context error, because exec.CommandContext only returns
// "signal: killed" when it terminates a process.
func wrapContextError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w (%v)", ctxErr, err)
	}
	return err
}

func parseRetryAfter(output string) time.Duration {
	if m := retryAfterSecs.FindStringSubmatch(output); m != nil {
		if secs, err := strconv.Atoi(m[1]); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	if m := tryAgainIn.FindStringSubmatch(output); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 0 {
			return 0
		}
		switch strings.ToLower(m[2])[0] {
		case 'h':
			return time.Duration(n) * time.Hour
		case 'm':
			return time.Duration(n) * time.Minute
		default:
			return time.Duration(n) * time.Second
		}
	}
	return 0
}
