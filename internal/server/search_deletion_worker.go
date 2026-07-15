package server

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	searchIndexDeletionInterval  = 5 * time.Minute
	searchIndexDeletionBatchSize = 25
)

func StartSearchIndexDeletionWorker(ctx context.Context, deps Deps, logger Logger) {
	if deps.Controlplane == nil || deps.SearchBuckets == nil || !deps.SearchBuckets.Configured() {
		return
	}
	go func() {
		runSearchIndexDeletionSweep(ctx, deps, logger)
		ticker := time.NewTicker(searchIndexDeletionInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runSearchIndexDeletionSweep(ctx, deps, logger)
			}
		}
	}()
}

func runSearchIndexDeletionSweep(ctx context.Context, deps Deps, logger Logger) {
	count, err := sweepSearchIndexDeletions(ctx, deps)
	if err != nil {
		if logger != nil {
			logger.Errorf("search index deletion sweep failed: %v", err)
		}
		return
	}
	if count > 0 && logger != nil {
		logger.Infof("search index deletion sweep removed %d item(s)", count)
	}
}

func sweepSearchIndexDeletions(ctx context.Context, deps Deps) (int, error) {
	claimCtx, cancelClaim := context.WithTimeout(ctx, searchOrphanCleanupTimeout)
	claim, err := deps.Controlplane.ClaimSearchIndexDeletions(claimCtx, searchIndexDeletionBatchSize)
	cancelClaim()
	if err != nil {
		return 0, err
	}
	if len(claim.Deletions) == 0 {
		return 0, nil
	}
	if claim.ClaimToken == "" {
		return 0, errors.New("controlplane: search index deletion claim missing token")
	}

	ackIDs := make([]string, 0, len(claim.Deletions))
	var deleteErrs []error
	for _, deletion := range claim.Deletions {
		deleteCtx, cancelDelete := context.WithTimeout(ctx, searchOrphanCleanupTimeout)
		err := deps.SearchBuckets.Delete(deleteCtx, deletion.ClerkUserID, deletion.ObjectKey)
		cancelDelete()
		if err != nil {
			deleteErrs = append(deleteErrs, fmt.Errorf("delete search index %s: %w", deletion.ID, err))
			continue
		}
		ackIDs = append(ackIDs, deletion.ID)
	}
	if len(ackIDs) > 0 {
		ackCtx, cancelAck := context.WithTimeout(ctx, searchOrphanCleanupTimeout)
		err := deps.Controlplane.AckSearchIndexDeletions(ackCtx, claim.ClaimToken, ackIDs)
		cancelAck()
		if err != nil {
			return 0, errors.Join(append(deleteErrs, err)...)
		}
	}
	return len(ackIDs), errors.Join(deleteErrs...)
}
