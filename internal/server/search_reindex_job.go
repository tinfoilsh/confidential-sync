package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"sync"
	"time"
)

// Search reindex runs as a detached background job, mirroring the
// migrate-all coordinator: the kickoff request returns immediately
// with a job id, the enclave pages through the user's chats on its
// own, and the client polls for status. This keeps a large rebuild
// (thousands of embedding calls) from depending on the webapp tab
// staying open for the whole run.
//
// Key lifetime: the job necessarily retains the caller's CEKs past
// the kickoff request, since it must decrypt chats and seal the
// rebuilt index on the caller's behalf. This is the same deliberate,
// bounded exception migrate-all makes: the keys live only in this
// process's memory, only for the job's budgeted lifetime, and are
// never persisted.

const (
	maxSearchReindexKeys = 8

	// SearchReindexJobBudget caps one rebuild run. Sized for ~10k
	// chats: ~600 embedding batches at a few hundred ms each.
	SearchReindexJobBudget = 10 * time.Minute

	// SearchReindexJobRetention keeps a finished job addressable so
	// late polls see the terminal state instead of an idle gap.
	SearchReindexJobRetention = 5 * time.Minute
)

// SearchReindexJob tracks one user's in-flight or recently-finished
// rebuild. Reuses the migration job lifecycle states.
type SearchReindexJob struct {
	ID        string
	UserID    string
	StartedAt time.Time
	// keyFP fingerprints the key set the job rebuilds under. A
	// kickoff only joins an existing job when the fingerprints match:
	// a different key set must not join an old job whose output is
	// sealed under a key the client did not ask to use.
	keyFP [sha256.Size]byte
	// cancel aborts the job's context; the coordinator uses it to
	// stop a superseded job before starting its replacement.
	cancel context.CancelFunc

	mu           sync.Mutex
	updatedAt    time.Time
	status       MigrationJobStatus
	errMsg       string
	indexed      int
	failed       int
	totalIndexed int
	partial      bool

	done chan struct{}
}

func newSearchReindexJob(userID string, keyFP [sha256.Size]byte) *SearchReindexJob {
	now := time.Now().UTC()
	return &SearchReindexJob{
		ID:        newMigrationJobID(),
		UserID:    userID,
		StartedAt: now,
		keyFP:     keyFP,
		updatedAt: now,
		status:    MigrationJobRunning,
		done:      make(chan struct{}),
	}
}

// reindexKeyFingerprint hashes the primary key for job identity.
// Failed coverage keeps a job partial and immediately retryable, while
// unused trailing-key variants cannot bypass clean-job deduplication.
func reindexKeyFingerprint(keys []PullKey) [sha256.Size]byte {
	if len(keys) == 0 {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256([]byte(keys[0].Key))
}

func (j *SearchReindexJob) reportPage(page *searchReindexPageResult) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.indexed += page.Indexed
	j.failed += page.Failed
	j.totalIndexed = page.TotalIndexed
	j.updatedAt = time.Now().UTC()
}

func (j *SearchReindexJob) markPartial() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.partial = true
	j.updatedAt = time.Now().UTC()
}

func (j *SearchReindexJob) finish(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.updatedAt = time.Now().UTC()
	if err != nil {
		j.status = MigrationJobFailed
		j.errMsg = err.Error()
	} else {
		j.status = MigrationJobCompleted
	}
	close(j.done)
}

// Done returns a channel that closes once finish has been called.
// Tests use this to wait for the job goroutine deterministically.
func (j *SearchReindexJob) Done() <-chan struct{} { return j.done }

// blocksRestart reports whether this job's lifecycle can block a
// restart: always while running, and after a clean completion when
// the current index is still healthy. Failed and partial runs never
// block because they must be re-kickable immediately.
func (j *SearchReindexJob) blocksRestart() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status == MigrationJobRunning {
		return true
	}
	return j.status == MigrationJobCompleted && !j.partial
}

func (j *SearchReindexJob) running() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.status == MigrationJobRunning
}

func (j *SearchReindexJob) statusResponse() SearchReindexStatusResponse {
	j.mu.Lock()
	defer j.mu.Unlock()
	partial := j.partial
	if j.status == MigrationJobRunning {
		partial = true
	}
	resp := SearchReindexStatusResponse{
		JobID:        j.ID,
		Status:       string(j.status),
		Indexed:      j.indexed,
		Failed:       j.failed,
		TotalIndexed: j.totalIndexed,
		Partial:      partial,
		Error:        j.errMsg,
	}
	if !j.StartedAt.IsZero() {
		resp.StartedAt = j.StartedAt.Format(time.RFC3339Nano)
	}
	if !j.updatedAt.IsZero() {
		resp.UpdatedAt = j.updatedAt.Format(time.RFC3339Nano)
	}
	return resp
}

// SearchReindexCoordinator owns the per-user reindex jobs. A kickoff
// while a job is running or while a clean success sits in its
// retention window with a healthy index returns the existing job, so
// duplicate kickoffs from multiple tabs cannot stack rebuilds —
// important here because every rebuild pays for embedding the whole
// corpus again. Failed, partial, and repair-required runs are
// re-kickable immediately.
type SearchReindexCoordinator struct {
	mu         sync.Mutex
	jobs       map[string]*SearchReindexJob
	retention  time.Duration
	budget     time.Duration
	runnerHook func(ctx context.Context, deps Deps, sess Session, req SearchReindexRequest, job *SearchReindexJob) error
}

func NewSearchReindexCoordinator() *SearchReindexCoordinator {
	return &SearchReindexCoordinator{
		jobs:       map[string]*SearchReindexJob{},
		retention:  SearchReindexJobRetention,
		budget:     SearchReindexJobBudget,
		runnerHook: runSearchReindex,
	}
}

// StartOrGet returns the user's existing job when it is running or a
// retained clean success for the same key set whose index is still
// healthy, or starts a new one in a detached goroutine. The bool is
// true when a fresh job started (handler answers 202 instead of 200).
// Failed, partial, and repair-required terminal jobs do not block: a
// query that still reports needs_reindex must be able to re-kick
// without waiting out the retention window. A kickoff with a
// different key set also never joins: the old job's output is sealed
// under a key the client did not ask to use, so the old job is
// cancelled and a fresh rebuild starts once it has wound down.
func (c *SearchReindexCoordinator) StartOrGet(parentCtx context.Context, deps Deps, sess Session, req SearchReindexRequest) (*SearchReindexJob, bool, error) {
	userID := sess.Claims.Subject
	keyFP := reindexKeyFingerprint(req.Keys)
	for {
		c.mu.Lock()
		existing := c.jobs[userID]
		if existing != nil && existing.keyFP == keyFP {
			if existing.running() {
				c.mu.Unlock()
				return existing, false, nil
			}
			if existing.blocksRestart() {
				c.mu.Unlock()
				needsReindex, err := searchIndexNeedsReindex(parentCtx, deps, sess, req.Keys[0].Key)
				if err != nil {
					return nil, false, err
				}
				c.mu.Lock()
				if c.jobs[userID] != existing {
					c.mu.Unlock()
					continue
				}
				if !needsReindex {
					c.mu.Unlock()
					return existing, false, nil
				}
			}
		}
		job := newSearchReindexJob(userID, keyFP)
		// The job's context is created here, not in run, so a successor
		// kickoff can cancel it before the goroutine is scheduled.
		// Detached from the kickoff request so a closing webapp tab
		// cannot cancel the rebuild mid-run; bounded by the job budget.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parentCtx), c.budget)
		job.cancel = cancel
		c.jobs[userID] = job
		c.mu.Unlock()

		var predecessor *SearchReindexJob
		if existing != nil && existing.running() {
			// Two rebuilds must not interleave writes to the same index
			// object: stop the superseded job and make the new one wait
			// for it to wind down before paging.
			existing.cancel()
			predecessor = existing
		}
		go c.run(ctx, deps, sess, req, job, predecessor)
		return job, true, nil
	}
}

// Status returns the tracked job for a user, or nil when none exists.
func (c *SearchReindexCoordinator) Status(userID string) *SearchReindexJob {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jobs[userID]
}

func (c *SearchReindexCoordinator) Cancel(userID string) {
	c.mu.Lock()
	job := c.jobs[userID]
	delete(c.jobs, userID)
	c.mu.Unlock()
	if job != nil && job.cancel != nil {
		job.cancel()
	}
}

func (c *SearchReindexCoordinator) run(ctx context.Context, deps Deps, sess Session, req SearchReindexRequest, job *SearchReindexJob, predecessor *SearchReindexJob) {
	defer job.cancel()
	if predecessor != nil {
		select {
		case <-predecessor.Done():
		case <-ctx.Done():
		}
	}

	deps.logInfo("search reindex job begin: user=%s job=%s budget=%s", job.UserID, job.ID, c.budget)
	err := c.runnerHook(ctx, deps, sess, req, job)
	if err != nil {
		deps.logError("search reindex job failed: user=%s job=%s err=%v", job.UserID, job.ID, err)
	}
	job.finish(err)

	retention := c.retention
	if retention <= 0 {
		c.deleteIfSame(job)
		return
	}
	time.AfterFunc(retention, func() { c.deleteIfSame(job) })
}

func (c *SearchReindexCoordinator) deleteIfSame(job *SearchReindexJob) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jobs[job.UserID] == job {
		delete(c.jobs, job.UserID)
	}
}

// runSearchReindex is the production runner: it drains the user's
// chats page by page, rebuilding the index from an empty cursor. A
// budget or cancellation mid-run leaves the job completed-but-partial;
// the partially-built index is still valid (it simply misses the
// undrained chats) and a fresh kickoff rebuilds from scratch.
func runSearchReindex(ctx context.Context, deps Deps, sess Session, req SearchReindexRequest, job *SearchReindexJob) error {
	publication, err := deps.Controlplane.GetSearchIndexState(ctx, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		if ctx.Err() != nil {
			job.markPartial()
			return nil
		}
		return err
	}
	targetSourceRevision := publication.SourceRevision
	cursor := ""
	coverageFailure := false
	for {
		if ctx.Err() != nil {
			job.markPartial()
			deps.logInfo("search reindex job stopped at budget: user=%s job=%s", job.UserID, job.ID)
			return nil
		}
		page, err := searchReindexPage(ctx, deps, sess, req.Keys, cursor, job.StartedAt, targetSourceRevision, coverageFailure)
		if err != nil {
			// A budget expiry mid-page surfaces as a context error
			// wrapped in upstream failures; report it as partial
			// rather than failed so the client re-kicks instead of
			// alarming the user.
			if ctx.Err() != nil {
				job.markPartial()
				return nil
			}
			return err
		}
		job.reportPage(page)
		if page.Failed > 0 {
			job.markPartial()
			coverageFailure = true
		}
		if page.Done {
			return nil
		}
		cursor = page.NextCursor
	}
}

// normalizeSearchReindexRequest runs synchronous shape checks before
// any coordinator state is touched, then canonicalizes and dedupes the
// bounded key set so equivalent requests share one job identity.
func normalizeSearchReindexRequest(req SearchReindexRequest) (SearchReindexRequest, error) {
	if len(req.Keys) == 0 {
		return SearchReindexRequest{}, badRequest("keys is required and must not be empty")
	}
	if len(req.Keys) > maxSearchReindexKeys {
		return SearchReindexRequest{}, badRequest("too many keys")
	}
	keys, cleanup, err := decodeKeys(req.Keys)
	if err != nil {
		return SearchReindexRequest{}, err
	}
	defer cleanup()

	normalized := make([]PullKey, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, duplicate := seen[key.KeyIDHex]; duplicate {
			continue
		}
		seen[key.KeyIDHex] = struct{}{}
		normalized = append(normalized, PullKey{
			Key:   base64.StdEncoding.EncodeToString(key.Bytes),
			KeyID: key.KeyIDHex,
		})
	}
	legacy := normalized[1:]
	sort.Slice(legacy, func(i, j int) bool {
		return legacy[i].KeyID < legacy[j].KeyID
	})
	return SearchReindexRequest{Keys: normalized}, nil
}
