package server

import (
	"context"
	"errors"
	"time"
)

// Transient-failure retry policy for the per-chat controlplane calls an
// import makes hundreds of times in sequence. Retries are bounded so
// one slow dependency cannot consume the job budget, and only reasons
// the classifier identifies as transient are retried.
const (
	importRetryMaxAttempts = 3
	importRetryBaseDelay   = 500 * time.Millisecond
	importRetryMaxDelay    = 5 * time.Second
)

// importSleep is swapped by tests so retries do not slow the suite.
var importSleep = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isTransientImportFailure reports whether a per-chat error is worth
// retrying. It reuses the job-level classifier so retry decisions and
// the reported failure reason agree, and never string-matches messages.
func isTransientImportFailure(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	switch classifyImportFailure(ctx, err) {
	case ImportFailureRequestTimeout, ImportFailureServiceUnavailable, ImportFailureRateLimited:
		return true
	}
	return false
}

// retryTransientImportCall runs fn up to importRetryMaxAttempts times,
// backing off exponentially between transient failures. Definitive
// errors and context cancellation return immediately.
func retryTransientImportCall(ctx context.Context, fn func() error) error {
	delay := importRetryBaseDelay
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn()
		if err == nil || attempt == importRetryMaxAttempts || !isTransientImportFailure(ctx, err) {
			return err
		}
		if sleepErr := importSleep(ctx, delay); sleepErr != nil {
			return errors.Join(err, sleepErr)
		}
		delay = min(delay*2, importRetryMaxDelay)
	}
}
