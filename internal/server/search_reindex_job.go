package server

import (
	"context"
	"crypto/sha256"
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

// reindexKeyFingerprint hashes the request's key set for job
// identity. Only a digest is retained on the job, never the key
// material itself.
func reindexKeyFingerprint(keys []PullKey) [sha256.Size]byte {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k.Key))
		h.Write([]byte{0})
	}
	var fp [sha256.Size]byte
	copy(fp[:], h.Sum(nil))
	return fp
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

// blocksRestart reports whether a kickoff should return this job
// instead of starting a fresh one: while it is running, and while a
// cleanly completed run is retained (a retried or duplicate kickoff
// landing just after success must not pay for embedding the whole
// corpus again). Failed and partial runs never block, because their
// whole point of being terminal is to be re-kicked immediately.
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
// retention window returns the existing job, so duplicate kickoffs
// from multiple tabs cannot stack rebuilds — important here because
// every rebuild pays for embedding the whole corpus again. Failed and
// partial runs are re-kickable immediately.
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
// retained clean success for the same key set, or starts a new one in
// a detached goroutine. The bool is true when a fresh job started
// (handler answers 202 instead of 200). Failed and partial terminal
// jobs do not block: a query that still reports needs_reindex after
// such a run must be able to re-kick without waiting out the
// retention window. A kickoff with a different key set also never
// joins: the old job's output is sealed under a key the client did
// not ask to use, so the old job is cancelled and a fresh rebuild
// starts once it has wound down.
func (c *SearchReindexCoordinator) StartOrGet(parentCtx context.Context, deps Deps, sess Session, req SearchReindexRequest) (*SearchReindexJob, bool) {
	userID := sess.Claims.Subject
	keyFP := reindexKeyFingerprint(req.Keys)
	c.mu.Lock()
	existing := c.jobs[userID]
	if existing != nil && existing.keyFP == keyFP && existing.blocksRestart() {
		c.mu.Unlock()
		return existing, false
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
	return job, true
}

// Status returns the tracked job for a user, or nil when none exists.
func (c *SearchReindexCoordinator) Status(userID string) *SearchReindexJob {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jobs[userID]
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
	cursor := ""
	for {
		if ctx.Err() != nil {
			job.markPartial()
			deps.logInfo("search reindex job stopped at budget: user=%s job=%s", job.UserID, job.ID)
			return nil
		}
		page, err := searchReindexPage(ctx, deps, sess, req.Keys, cursor, job.StartedAt)
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
		if page.Done {
			return nil
		}
		cursor = page.NextCursor
	}
}

// validateSearchReindexRequest runs synchronous shape checks before
// any coordinator state is touched, so malformed keys surface as an
// immediate 400 instead of an async "failed" status.
func validateSearchReindexRequest(req SearchReindexRequest) error {
	if len(req.Keys) == 0 {
		return badRequest("keys is required and must not be empty")
	}
	_, cleanup, err := decodeKeys(req.Keys)
	if err != nil {
		return err
	}
	cleanup()
	return nil
}
