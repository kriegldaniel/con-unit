package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

type hintedError struct{ after time.Duration }

func (e *hintedError) Error() string             { return "throttled" }
func (e *hintedError) RetryAfter() time.Duration { return e.after }

func recordingPolicy(attempts int, sleeps *[]time.Duration) Policy {
	return Policy{
		MaxAttempts:   attempts,
		BaseDelay:     time.Second,
		MaxDelay:      10 * time.Second,
		MaxRetryAfter: 30 * time.Second,
		Rand:          func() float64 { return 1 }, // upper end of the jitter range
		Sleep: func(_ context.Context, d time.Duration) error {
			*sleeps = append(*sleeps, d)
			return nil
		},
	}
}

func always(error) bool { return true }

func TestDoSucceedsAfterTransientFailures(t *testing.T) {
	var sleeps []time.Duration
	calls := 0
	err := Do(context.Background(), recordingPolicy(5, &sleeps), always, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("Do = %v after %d calls, want success after 3", err, calls)
	}
	if len(sleeps) != 2 {
		t.Fatalf("sleeps = %v, want two waits", sleeps)
	}
}

func TestDoBackoffGrowsExponentiallyWithJitterBounds(t *testing.T) {
	var sleeps []time.Duration
	_ = Do(context.Background(), recordingPolicy(6, &sleeps), always, func() error { return errors.New("x") })
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second}
	// Rand returns 1, so each wait equals the full backoff, capped at MaxDelay.
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %d waits", sleeps, len(want))
	}
	for i, got := range sleeps {
		if got != want[i] {
			t.Errorf("wait %d = %s, want %s", i+1, got, want[i])
		}
	}

	var low []time.Duration
	policy := recordingPolicy(2, &low)
	policy.Rand = func() float64 { return 0 }
	_ = Do(context.Background(), policy, always, func() error { return errors.New("x") })
	if len(low) != 1 || low[0] != 500*time.Millisecond {
		t.Fatalf("lowest jittered wait = %v, want 500ms (half of the base delay)", low)
	}
}

func TestDoHonorsRetryAfterHint(t *testing.T) {
	var sleeps []time.Duration
	calls := 0
	err := Do(context.Background(), recordingPolicy(3, &sleeps), always, func() error {
		calls++
		if calls == 1 {
			return &hintedError{after: 7 * time.Second}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do = %v", err)
	}
	if len(sleeps) != 1 || sleeps[0] != 7*time.Second {
		t.Fatalf("sleeps = %v, want exactly the 7s Retry-After hint", sleeps)
	}
}

func TestDoAbandonsWhenRetryAfterExceedsMaximum(t *testing.T) {
	var sleeps []time.Duration
	calls := 0
	err := Do(context.Background(), recordingPolicy(5, &sleeps), always, func() error {
		calls++
		return &hintedError{after: time.Hour}
	})
	if !errors.Is(err, ErrRetryAfterTooLong) {
		t.Fatalf("Do = %v, want ErrRetryAfterTooLong", err)
	}
	var hinted *hintedError
	if !errors.As(err, &hinted) {
		t.Fatalf("original error must stay reachable with errors.As: %v", err)
	}
	if calls != 1 || len(sleeps) != 0 {
		t.Fatalf("calls=%d sleeps=%v, want one call and no wait", calls, sleeps)
	}
}

func TestDoDoesNotRetryNonRetryableErrors(t *testing.T) {
	calls := 0
	boom := errors.New("permanent")
	err := Do(context.Background(), recordingPolicy(5, new([]time.Duration)), func(error) bool { return false }, func() error {
		calls++
		return boom
	})
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("Do = %v after %d calls, want the permanent error after one call", err, calls)
	}
}

func TestDoStopsWhenContextEndsDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	policy := recordingPolicy(5, new([]time.Duration))
	policy.Sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}
	throttled := &hintedError{}
	calls := 0
	err := Do(ctx, policy, always, func() error {
		calls++
		return throttled
	})
	if !errors.Is(err, throttled) || calls != 1 {
		t.Fatalf("Do = %v after %d calls, want the throttle error after one call", err, calls)
	}
}

func TestDoBoundsAttempts(t *testing.T) {
	calls := 0
	err := Do(context.Background(), recordingPolicy(3, new([]time.Duration)), always, func() error {
		calls++
		return errors.New("x")
	})
	if err == nil || calls != 3 {
		t.Fatalf("Do = %v after %d calls, want failure after exactly 3 attempts", err, calls)
	}
	if err := Do(context.Background(), Policy{}, always, func() error { calls++; return errors.New("y") }); err == nil || calls != 4 {
		t.Fatalf("zero policy must perform a single attempt, calls=%d err=%v", calls, err)
	}
}

func TestOnRetryReportsAttemptAndDelay(t *testing.T) {
	var sleeps []time.Duration
	policy := recordingPolicy(3, &sleeps)
	var attempts []int
	policy.OnRetry = func(attempt int, delay time.Duration, err error) {
		attempts = append(attempts, attempt)
	}
	_ = Do(context.Background(), policy, always, func() error { return errors.New("x") })
	if len(attempts) != 2 || attempts[0] != 1 || attempts[1] != 2 {
		t.Fatalf("OnRetry attempts = %v, want [1 2]", attempts)
	}
}
