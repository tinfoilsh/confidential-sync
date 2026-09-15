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

func StartAttachmentOrphanReaper(ctx context.Context, deps Deps) {
	if deps.Controlplane == nil || deps.Buckets == nil || !deps.Buckets.Configured() {
		return
	}
	go func() {
		runAttachmentOrphanSweep(ctx, deps)
		ticker := time.NewTicker(attachmentOrphanReaperInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAttachmentOrphanSweep(ctx, deps)
			}
		}
	}()
	go func() {
		runPendingAttachmentSweep(ctx, deps)
		ticker := time.NewTicker(pendingAttachmentSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runPendingAttachmentSweep(ctx, deps)
			}
		}
	}()
}

func runAttachmentOrphanSweep(ctx context.Context, deps Deps) {
	sweepCtx, cancel := context.WithTimeout(ctx, AttachmentRequestTimeout)
	defer cancel()
	_, _ = sweepAttachmentOrphans(sweepCtx, deps)
}

func sweepAttachmentOrphans(ctx context.Context, deps Deps) (int, error) {
	rows, err := deps.Controlplane.DeleteOrphanedV2Attachments(ctx, attachmentOrphanReaperLimit)
	if err != nil {
		return 0, err
	}
	swept := 0
	var deleteErrs []error
	for _, row := range rows {
		if err := deps.Buckets.Delete(ctx, row.ClerkUserID, row.AttachmentID); err != nil {
			deleteErrs = append(deleteErrs, fmt.Errorf("delete bucket attachment %s: %w", row.AttachmentID, err))
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
func runPendingAttachmentSweep(ctx context.Context, deps Deps) {
	listCtx, cancelList := context.WithTimeout(ctx, AttachmentRequestTimeout)
	rows, err := deps.Controlplane.SweepPendingAttachmentWrites(listCtx, pendingAttachmentSweepLimit)
	cancelList()
	if err != nil {
		return
	}
	for _, row := range rows {
		// Each buckets delete gets its own deadline so a slow row
		// near the end of the batch doesn't inherit a shared budget
		// that's already been spent by earlier items. CP has already
		// removed every row in `rows` from the pending ledger, so a
		// dropped delete here is a wasted blob, not data corruption.
		deleteCtx, cancelDelete := context.WithTimeout(ctx, AttachmentRequestTimeout)
		_ = deps.Buckets.Delete(deleteCtx, row.ClerkUserID, row.AttachmentID)
		cancelDelete()
	}
}
