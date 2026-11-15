// Package retry implements bounded retries with exponential backoff and
// jitter for transient registry throttling.
package retry

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Policy bounds the retry behavior. The zero value performs a single attempt.
type Policy struct {
	// MaxAttempts is the total number of attempts including the first one.
	MaxAttempts int
	// BaseDelay is the backoff before the first retry. It doubles per retry.
	BaseDelay time.Duration
	// MaxDelay caps the computed exponential backoff.
	MaxDelay time.Duration
	// MaxRetryAfter is the longest server supplied wait that is honored. A
	// larger hint means the throttle window is too long to wait out inside a
	// per-image deadline, so the operation fails immediately.
	MaxRetryAfter time.Duration
	// OnRetry is called before each wait. It may be nil.
	OnRetry func(attempt int, delay time.Duration, err error)

	// Sleep and Rand are injectable for tests. Nil selects the real clock and
	// the global random source.
	Sleep func(ctx context.Context, d time.Duration) error
	Rand  func() float64
}

// DefaultPolicy returns the policy used for registry rate limiting: five
// attempts, 2 s base delay doubling up to 60 s, and server hints up to 2 min.
func DefaultPolicy() Policy {
	return Policy{
		MaxAttempts:   5,
		BaseDelay:     2 * time.Second,
		MaxDelay:      60 * time.Second,
		MaxRetryAfter: 2 * time.Minute,
	}
}

// RetryAfterHint is implemented by errors that carry a server supplied wait.
type RetryAfterHint interface {
	RetryAfter() time.Duration
}

// ErrRetryAfterTooLong marks an operation abandoned because the server asked
// for a wait longer than Policy.MaxRetryAfter.
var ErrRetryAfterTooLong = errors.New("retry-after hint exceeds the configured maximum wait")

// Do runs op until it succeeds, fails with a non-retryable error, the policy
// is exhausted or ctx ends. It returns the last error of op, wrapped with the
// reason when retrying was abandoned early. Errors are never replaced, so
// errors.Is and errors.As keep working on the result.
func Do(ctx context.Context, policy Policy, retryable func(error) bool, op func() error) error {
	attempts := policy.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		err = op()
		if err == nil {
			return nil
		}
		if retryable == nil || !retryable(err) || attempt == attempts {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return err
		}
		delay, ok := policy.delay(attempt, err)
		if !ok {
			return fmt.Errorf("%w: %w", ErrRetryAfterTooLong, err)
		}
		if policy.OnRetry != nil {
			policy.OnRetry(attempt, delay, err)
		}
		sleep := policy.Sleep
		if sleep == nil {
			sleep = sleepContext
		}
		if sleepErr := sleep(ctx, delay); sleepErr != nil {
			return fmt.Errorf("%w (retry wait interrupted: %v)", err, sleepErr)
		}
	}
	return err
}

// delay returns the wait before retry number attempt (1 based). The second
// result is false when a server hint is longer than MaxRetryAfter.
func (p Policy) delay(attempt int, err error) (time.Duration, bool) {
	var hint RetryAfterHint
	if errors.As(err, &hint) {
		if after := hint.RetryAfter(); after > 0 {
			if p.MaxRetryAfter > 0 && after > p.MaxRetryAfter {
				return 0, false
			}
			return after, true
		}
	}
	base := p.BaseDelay
	if base <= 0 {
		base = time.Second
	}
	backoff := base
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if p.MaxDelay > 0 && backoff >= p.MaxDelay {
			backoff = p.MaxDelay
			break
		}
	}
	if p.MaxDelay > 0 && backoff > p.MaxDelay {
		backoff = p.MaxDelay
	}
	random := p.Rand
	if random == nil {
		random = rand.Float64
	}
	// Equal jitter: keep half of the backoff and randomize the other half so
	// concurrent runs do not retry in lockstep.
	half := backoff / 2
	return half + time.Duration(random()*float64(backoff-half)), true
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
