package server

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	attachmentOrphanReaperInterval = time.Hour
	attachmentOrphanReaperLimit    = 500
	pendingAttachmentSweepInterval = 5 * time.Minute
	pendingAttachmentSweepLimit    = 200
)

func StartAttachmentOrphanReaper(ctx context.Context, deps Deps, logger Logger) {
	if deps.Controlplane == nil || deps.Buckets == nil || !deps.Buckets.Configured() {
		return
	}
	go func() {
		runAttachmentOrphanSweep(ctx, deps, logger)
		ticker := time.NewTicker(attachmentOrphanReaperInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAttachmentOrphanSweep(ctx, deps, logger)
			}
		}
	}()
	go func() {
		runPendingAttachmentSweep(ctx, deps, logger)
		ticker := time.NewTicker(pendingAttachmentSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runPendingAttachmentSweep(ctx, deps, logger)
			}
		}
	}()
}

func runAttachmentOrphanSweep(ctx context.Context, deps Deps, logger Logger) {
	sweepCtx, cancel := context.WithTimeout(ctx, AttachmentRequestTimeout)
	defer cancel()
	count, err := sweepAttachmentOrphans(sweepCtx, deps)
	if err != nil {
		if logger != nil {
			logger.Errorf("attachment orphan sweep failed: %v", err)
		}
		return
	}
	if count > 0 && logger != nil {
		logger.Infof("attachment orphan sweep removed %d item(s)", count)
	}
}

func sweepAttachmentOrphans(ctx context.Context, deps Deps) (int, error) {
	ids, err := deps.Controlplane.DeleteOrphanedV2Attachments(ctx, attachmentOrphanReaperLimit)
	if err != nil {
		return 0, err
	}
	swept := 0
	var deleteErrs []error
	for _, id := range ids {
		if err := deps.Buckets.Delete(ctx, id); err != nil {
			deleteErrs = append(deleteErrs, fmt.Errorf("delete bucket attachment %s: %w", id, err))
			continue
		}
		swept++
	}
	return swept, errors.Join(deleteErrs...)
}

// runPendingAttachmentSweep drains expired pending-write guard rows
// the controlplane is willing to release. CP atomically removes each
// row from the ledger as it returns it, so this enclave is the sole
// owner of the buckets cleanup for that id. A buckets delete failure
// only leaves an unreferenced ciphertext blob — no chat row points to
// it, so the cost is wasted storage rather than data corruption.
func runPendingAttachmentSweep(ctx context.Context, deps Deps, logger Logger) {
	listCtx, cancelList := context.WithTimeout(ctx, AttachmentRequestTimeout)
	rows, err := deps.Controlplane.SweepPendingAttachmentWrites(listCtx, pendingAttachmentSweepLimit)
	cancelList()
	if err != nil {
		if logger != nil {
			logger.Errorf("pending attachment sweep failed: %v", err)
		}
		return
	}
	swept := 0
	for _, row := range rows {
		// Each buckets delete gets its own deadline so a slow row
		// near the end of the batch doesn't inherit a shared budget
		// that's already been spent by earlier items. CP has already
		// removed every row in `rows` from the pending ledger, so a
		// dropped delete here is a wasted blob, not data corruption.
		deleteCtx, cancelDelete := context.WithTimeout(ctx, AttachmentRequestTimeout)
		err := deps.Buckets.Delete(deleteCtx, row.AttachmentID)
		cancelDelete()
		if err != nil {
			if logger != nil {
				logger.Errorf("pending attachment cleanup failed for %s: %v", row.AttachmentID, err)
			}
			continue
		}
		swept++
	}
	if swept > 0 && logger != nil {
		logger.Infof("pending attachment sweep removed %d item(s)", swept)
	}
}
