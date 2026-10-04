package server

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	attachmentPurgeInterval       = 15 * time.Minute
	attachmentPurgeQueueBatchSize = 100
	attachmentPurgeClaimBatchSize = 25
	// attachmentPurgeClaimRounds bounds how many claim/delete/ack
	// rounds one sweep runs so a large backlog drains across ticks
	// instead of holding a single goroutine for a long time.
	attachmentPurgeClaimRounds = 20
)

// StartAttachmentPurgeWorker reclaims bucket objects for attachments
// no chat references any more.
//
// Liveness is tracked by the controlplane as a side effect of every
// chat push (see Push and X-Attachment-Refs). This worker only asks the
// controlplane to move aged-out rows into its purge queue, then claims
// queue rows under a lease, deletes the bucket object, and acks. A row
// whose delete fails or whose lease expires is reclaimed on a later
// sweep, so cleanup work is never lost between the index delete and
// the bucket delete.
func StartAttachmentPurgeWorker(ctx context.Context, deps Deps) {
	if deps.Controlplane == nil || deps.Buckets == nil || !deps.Buckets.Configured() {
		return
	}
	go func() {
		runAttachmentPurgeSweep(ctx, deps)
		ticker := time.NewTicker(attachmentPurgeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAttachmentPurgeSweep(ctx, deps)
			}
		}
	}()
}

func runAttachmentPurgeSweep(ctx context.Context, deps Deps) {
	_, _ = sweepAttachmentPurges(ctx, deps)
}

func sweepAttachmentPurges(ctx context.Context, deps Deps) (int, error) {
	purgeCtx, cancelPurge := context.WithTimeout(ctx, AttachmentRequestTimeout)
	_, err := deps.Controlplane.PurgeUnreferencedAttachments(purgeCtx, attachmentPurgeQueueBatchSize)
	cancelPurge()
	if err != nil {
		return 0, err
	}

	deleted := 0
	var errs []error
	for round := 0; round < attachmentPurgeClaimRounds; round++ {
		claimCtx, cancelClaim := context.WithTimeout(ctx, AttachmentRequestTimeout)
		claim, err := deps.Controlplane.ClaimAttachmentPurges(claimCtx, attachmentPurgeClaimBatchSize)
		cancelClaim()
		if err != nil {
			return deleted, errors.Join(append(errs, err)...)
		}
		if len(claim.Purges) == 0 {
			break
		}
		if claim.ClaimToken == "" {
			return deleted, errors.New("controlplane: attachment purge claim missing token")
		}
		leaseDeadline := time.Now().Add(attachmentPurgeLeaseBudget)
		ackIDs := make([]string, 0, len(claim.Purges))
		for _, purge := range claim.Purges {
			// Never ack past the lease: a reclaim by another enclave
			// after expiry hands out a fresh token and our ack would be
			// rejected anyway, but stopping here avoids a bucket delete
			// racing a re-upload that the controlplane has, by then,
			// allowed because it saw our claim expire.
			if time.Now().After(leaseDeadline) {
				break
			}
			deleteCtx, cancelDelete := context.WithTimeout(ctx, AttachmentRequestTimeout)
			err := deps.Buckets.Delete(deleteCtx, purge.ClerkUserID, purge.AttachmentID)
			cancelDelete()
			if err != nil {
				errs = append(errs, fmt.Errorf("delete bucket attachment %s: %w", purge.AttachmentID, err))
				continue
			}
			ackIDs = append(ackIDs, purge.AttachmentID)
		}
		if len(ackIDs) > 0 {
			ackCtx, cancelAck := context.WithTimeout(ctx, AttachmentRequestTimeout)
			err := deps.Controlplane.AckAttachmentPurges(ackCtx, claim.ClaimToken, ackIDs)
			cancelAck()
			if err != nil {
				return deleted, errors.Join(append(errs, err)...)
			}
			deleted += len(ackIDs)
		}
		if len(claim.Purges) < attachmentPurgeClaimBatchSize {
			break
		}
	}
	return deleted, errors.Join(errs...)
}

// attachmentPurgeLeaseBudget is how long after a claim the worker keeps
// deleting. It stays well inside the controlplane's lease so a slow
// batch cannot outlive the claim that authorizes it.
const attachmentPurgeLeaseBudget = 3 * time.Minute
