package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// MigrationJobBudget caps how long a detached migration job is
// allowed to run before it self-cancels. Slightly larger than
// MigrateAllBudget because the inner loop honours that budget on its
// own; the extra slack absorbs the time spent on the final scope
// report + finishing bookkeeping.
const MigrationJobBudget = MigrateAllBudget + 1*time.Minute

// MigrationJobRetention is how long a finished job stays addressable
// after completion so late polling calls still see the terminal
// state. After this window the entry is reaped and the next
// migrate-all kickoff starts a fresh job.
const MigrationJobRetention = 5 * time.Minute

// MigrationJobStatus enumerates the wire-level lifecycle states a
// migration job can be in. "idle" is reserved for the no-job case
// returned by the status endpoint when nothing is running.
type MigrationJobStatus string

const (
	MigrationJobIdle      MigrationJobStatus = "idle"
	MigrationJobRunning   MigrationJobStatus = "running"
	MigrationJobCompleted MigrationJobStatus = "completed"
	MigrationJobFailed    MigrationJobStatus = "failed"
)

// MigrationJob holds the running state for a single user's
// migrate-all run. Updates are made under mu so concurrent status
// polls observe a consistent snapshot. The job survives the HTTP
// request that kicked it off; ctx cancellation in the kickoff
// request does not propagate into the job's goroutine.
type MigrationJob struct {
	ID        string
	UserID    string
	StartedAt time.Time

	mu        sync.Mutex
	updatedAt time.Time
	status    MigrationJobStatus
	errMsg    string
	scopes    map[string]MigrateAllScopeReport
	scopeOrd  []string
	partial   bool

	done chan struct{}
}

// MigrationJobSnapshot is a thread-safe point-in-time view of a job.
// Returned by Snapshot for callers that need to render the status
// without holding the job's mutex.
type MigrationJobSnapshot struct {
	ID                 string
	UserID             string
	Status             MigrationJobStatus
	StartedAt          time.Time
	UpdatedAt          time.Time
	Migrated           int
	RetryableRemaining int
	BlockedUnmigrated  int
	Partial            bool
	Scopes             []MigrateAllScopeReport
	Error              string
}

func newMigrationJob(userID string) *MigrationJob {
	now := time.Now().UTC()
	return &MigrationJob{
		ID:        newMigrationJobID(),
		UserID:    userID,
		StartedAt: now,
		updatedAt: now,
		status:    MigrationJobRunning,
		scopes:    map[string]MigrateAllScopeReport{},
		done:      make(chan struct{}),
	}
}

func newMigrationJobID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

// Snapshot returns a defensive copy of the current job state.
func (j *MigrationJob) Snapshot() MigrationJobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.snapshotLocked()
}

func (j *MigrationJob) snapshotLocked() MigrationJobSnapshot {
	out := MigrationJobSnapshot{
		ID:        j.ID,
		UserID:    j.UserID,
		Status:    j.status,
		StartedAt: j.StartedAt,
		UpdatedAt: j.updatedAt,
		Partial:   j.partial,
		Error:     j.errMsg,
	}
	if len(j.scopeOrd) > 0 {
		out.Scopes = make([]MigrateAllScopeReport, 0, len(j.scopeOrd))
		for _, name := range j.scopeOrd {
			report := j.scopes[name]
			out.Migrated += report.Migrated
			out.RetryableRemaining += report.RetryableRemaining
			out.BlockedUnmigrated += report.BlockedUnmigrated
			out.Scopes = append(out.Scopes, report)
		}
	}
	return out
}

// reportScope is called by the migration loop as each scope makes
// progress. The latest report for a given scope replaces the
// previous one so the aggregate stays correct.
func (j *MigrationJob) reportScope(report MigrateAllScopeReport) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.scopes[report.Scope]; !ok {
		j.scopeOrd = append(j.scopeOrd, report.Scope)
	}
	j.scopes[report.Scope] = report
	j.updatedAt = time.Now().UTC()
}

// markPartial records that the run hit its wall-clock budget or had
// to bail early. The job status stays "running" until finish is
// called; partial is just a flag rolled into the snapshot.
func (j *MigrationJob) markPartial() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.partial = true
	j.updatedAt = time.Now().UTC()
}

func (j *MigrationJob) finish(resp *MigrateAllResponse, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.updatedAt = time.Now().UTC()
	if err != nil {
		j.status = MigrationJobFailed
		j.errMsg = err.Error()
	} else {
		j.status = MigrationJobCompleted
		if resp != nil {
			j.partial = resp.Partial
			// Replace per-scope state with the authoritative
			// final tally from MigrateAll so the snapshot always
			// reflects what actually landed even if a progress
			// report was missed between the last batch and
			// finish.
			j.scopes = make(map[string]MigrateAllScopeReport, len(resp.Scopes))
			j.scopeOrd = j.scopeOrd[:0]
			for _, s := range resp.Scopes {
				if _, exists := j.scopes[s.Scope]; !exists {
					j.scopeOrd = append(j.scopeOrd, s.Scope)
				}
				j.scopes[s.Scope] = s
			}
		}
	}
	close(j.done)
}

// Done returns a channel that closes once finish has been called.
// Tests use this to wait for a job goroutine to settle deterministically.
func (j *MigrationJob) Done() <-chan struct{} { return j.done }

// MigrationCoordinator owns the in-memory set of in-flight and
// recently-completed migration jobs, keyed by clerk user id. A new
// migrate-all kickoff for a user that already has a running job
// returns the existing job instead of starting a duplicate, so
// multiple tabs / devices on the same account share progress.
type MigrationCoordinator struct {
	mu         sync.Mutex
	jobs       map[string]*MigrationJob
	retention  time.Duration
	budget     time.Duration
	runnerHook func(ctx context.Context, deps Deps, sess Session, req MigrateAllRequest, job *MigrationJob) (*MigrateAllResponse, error)
}

// NewMigrationCoordinator returns a coordinator with production
// defaults. Tests use newMigrationCoordinatorWithRunner to inject a
// stub runner so they don't have to spin up a real MigrateAll.
func NewMigrationCoordinator() *MigrationCoordinator {
	return &MigrationCoordinator{
		jobs:       map[string]*MigrationJob{},
		retention:  MigrationJobRetention,
		budget:     MigrationJobBudget,
		runnerHook: defaultMigrationRunner,
	}
}

// StartOrGet is the single entrypoint for the migrate-all handler.
// It atomically (a) returns the existing job for the user — whether
// still running or already in its terminal/retention window — or
// (b) starts a new job in a detached goroutine and returns it. The
// bool return is true when a fresh job was started, which the
// handler uses to pick the HTTP status code (202 vs 200).
//
// Completed jobs are intentionally NOT cleared by this call: a
// freshly-completed job stays addressable for MigrationJobRetention
// so the webapp's polling loop, which keeps calling migrate-all to
// surface progress, sees the "completed" snapshot instead of
// triggering a brand new run on every tick. The retention reaper
// (scheduled in run()) is the sole owner of the cleanup.
func (c *MigrationCoordinator) StartOrGet(parentCtx context.Context, deps Deps, sess Session, req MigrateAllRequest) (*MigrationJob, bool) {
	userID := sess.Claims.Subject
	c.mu.Lock()
	if existing, ok := c.jobs[userID]; ok {
		c.mu.Unlock()
		return existing, false
	}

	job := newMigrationJob(userID)
	c.jobs[userID] = job
	c.mu.Unlock()

	go c.run(parentCtx, deps, sess, req, job)
	return job, true
}

// Status returns the currently-tracked job for a user, or nil when
// none exists. Callers must use Snapshot to read its state safely.
func (c *MigrationCoordinator) Status(userID string) *MigrationJob {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jobs[userID]
}

func (c *MigrationCoordinator) run(parentCtx context.Context, deps Deps, sess Session, req MigrateAllRequest, job *MigrationJob) {
	// Detach from the kickoff request: the webapp tab may close
	// mid-call, which would otherwise cancel every CP fetch in
	// flight and pollute the blocked list with fake failures.
	// WithoutCancel preserves any request-scoped values (logger
	// keys, request ids) while ignoring the parent cancellation
	// signal, then we apply our own deadline.
	ctx := context.WithoutCancel(parentCtx)
	ctx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()

	deps.logInfo("migration job begin: user=%s job=%s budget=%s", job.UserID, job.ID, c.budget)
	resp, err := c.runnerHook(ctx, deps, sess, req, job)
	if err != nil {
		deps.logError("migration job failed: user=%s job=%s err=%v", job.UserID, job.ID, err)
	} else if resp != nil {
		deps.logInfo("migration job done: user=%s job=%s migrated=%d retryable_remaining=%d blocked_unmigrated=%d partial=%t",
			job.UserID, job.ID, resp.Migrated, resp.RetryableRemaining, resp.BlockedUnmigrated, resp.Partial)
	}
	job.finish(resp, err)

	retention := c.retention
	if retention <= 0 {
		c.deleteIfSame(job)
		return
	}
	time.AfterFunc(retention, func() { c.deleteIfSame(job) })
}

func (c *MigrationCoordinator) deleteIfSame(job *MigrationJob) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jobs[job.UserID] == job {
		delete(c.jobs, job.UserID)
	}
}

// defaultMigrationRunner is the production runner: it invokes the
// real MigrateAll with the job acting as its progress reporter.
func defaultMigrationRunner(ctx context.Context, deps Deps, sess Session, req MigrateAllRequest, job *MigrationJob) (*MigrateAllResponse, error) {
	return migrateAllWithProgress(ctx, deps, sess, req, job)
}

// validateMigrateAllRequest runs the same shape checks
// migrateAllWithProgress performs internally, but synchronously and
// before any coordinator state is touched. This keeps the
// async-kickoff handler honest: clients that send a malformed key
// or an empty target still get an immediate 400 instead of being
// told "job accepted" only to discover it failed at the first batch.
func validateMigrateAllRequest(req MigrateAllRequest) error {
	if len(req.Keys) == 0 {
		return badRequest("keys is required and must not be empty")
	}
	if req.Target.Key == "" {
		return badRequest("target.key is required")
	}
	_, cleanup, err := decodeKeys(req.Keys)
	if err != nil {
		return err
	}
	cleanup()
	tgt, err := decodeKey(req.Target.Key)
	if err != nil {
		return badRequest("invalid target.key: " + err.Error())
	}
	cryptopkg.Zero(tgt)
	return nil
}

// buildMigrateAllStatusResponse maps a job snapshot onto the wire
// shape returned by both migrate-all (kickoff/poll) and
// migrate-status (poll-only). While the job is still running we
// pin Partial=true so the existing webapp's "loop until !partial"
// drain keeps polling without needing to inspect Status.
func buildMigrateAllStatusResponse(job *MigrationJob) MigrateAllStatusResponse {
	snap := job.Snapshot()
	partial := snap.Partial
	if snap.Status == MigrationJobRunning {
		partial = true
	}
	resp := MigrateAllStatusResponse{
		JobID:              snap.ID,
		Status:             string(snap.Status),
		Migrated:           snap.Migrated,
		RetryableRemaining: snap.RetryableRemaining,
		BlockedUnmigrated:  snap.BlockedUnmigrated,
		Partial:            partial,
		Scopes:             snap.Scopes,
		Error:              snap.Error,
	}
	if !snap.StartedAt.IsZero() {
		resp.StartedAt = snap.StartedAt.Format(time.RFC3339Nano)
	}
	if !snap.UpdatedAt.IsZero() {
		resp.UpdatedAt = snap.UpdatedAt.Format(time.RFC3339Nano)
	}
	return resp
}
