package server

import (
	"context"
	"fmt"
	"time"
)

const (
	attachmentOrphanReaperInterval = time.Hour
	attachmentOrphanReaperLimit    = 500
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
	for _, id := range ids {
		if err := deps.Buckets.Delete(ctx, id); err != nil {
			return swept, fmt.Errorf("delete bucket attachment %s: %w", id, err)
		}
		swept++
	}
	return swept, nil
}
