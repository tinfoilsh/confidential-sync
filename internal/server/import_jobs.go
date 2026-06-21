package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// ImportJobBudget caps how long a detached import job may run before it
// self-cancels, sized like the migration job budget.
const ImportJobBudget = MigrateAllBudget + 1*time.Minute

// ImportJobRetention keeps a finished job addressable for late status
// polls before it is reaped.
const ImportJobRetention = 5 * time.Minute

type ImportJobStatus string

const (
	ImportJobIdle      ImportJobStatus = "idle"
	ImportJobStaging   ImportJobStatus = "staging"
	ImportJobRunning   ImportJobStatus = "running"
	ImportJobCompleted ImportJobStatus = "completed"
	ImportJobFailed    ImportJobStatus = "failed"
)

// ImportJobState holds one user's in-flight import. Secrets (stagingKey,
// cek) live only here and are zeroed when the job leaves memory.
type ImportJobState struct {
	ID            string
	UserID        string
	UploadID      string
	Source        string
	TotalBytes    int64
	TotalChunks   int
	ArchiveSHA256 string
	StartedAt     time.Time

	mu         sync.Mutex
	stagingKey []byte
	received   map[int]string
	cek        []byte
	status     ImportJobStatus
	imported   int
	failed     int
	total      int
	errs       []string
	startedRun bool
	updatedAt  time.Time

	done chan struct{}
}

type ImportJobSnapshot struct {
	ID       string
	Status   ImportJobStatus
	Imported int
	Failed   int
	Total    int
	Errors   []string
}

func (j *ImportJobState) Snapshot() ImportJobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	errs := append([]string(nil), j.errs...)
	return ImportJobSnapshot{
		ID:       j.ID,
		Status:   j.status,
		Imported: j.imported,
		Failed:   j.failed,
		Total:    j.total,
		Errors:   errs,
	}
}

// recordChunk makes chunk staging idempotent: replaying the same index
// with the same hash succeeds; a different hash for an already-seen
// index is rejected so a flipped chunk cannot corrupt the archive.
func (j *ImportJobState) recordChunk(index int, chunkSHA string) (alreadyHave bool, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.startedRun {
		return false, fmt.Errorf("import: job already started")
	}
	if prev, ok := j.received[index]; ok {
		if prev != chunkSHA {
			return false, fmt.Errorf("import: chunk %d hash conflict", index)
		}
		return true, nil
	}
	j.received[index] = chunkSHA
	j.updatedAt = time.Now().UTC()
	return false, nil
}

func (j *ImportJobState) allChunksReceived() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.received) == j.TotalChunks
}

func (j *ImportJobState) addError(msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.errs) < MaxImportJobErrors {
		j.errs = append(j.errs, msg)
	}
	j.updatedAt = time.Now().UTC()
}

func (j *ImportJobState) setProgress(imported, failed, total int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.imported = imported
	j.failed = failed
	j.total = total
	j.updatedAt = time.Now().UTC()
}

func (j *ImportJobState) finish(status ImportJobStatus) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.status = status
	j.updatedAt = time.Now().UTC()
	cryptopkg.Zero(j.cek)
	cryptopkg.Zero(j.stagingKey)
	close(j.done)
}

func (j *ImportJobState) Done() <-chan struct{} { return j.done }

// ImportCoordinator owns the in-memory set of import jobs, one per user.
type ImportCoordinator struct {
	mu        sync.Mutex
	jobs      map[string]*ImportJobState
	retention time.Duration
	budget    time.Duration
	runner    func(ctx context.Context, deps Deps, sess Session, job *ImportJobState) error
}

func NewImportCoordinator() *ImportCoordinator {
	return &ImportCoordinator{
		jobs:      map[string]*ImportJobState{},
		retention: ImportJobRetention,
		budget:    ImportJobBudget,
		runner:    runImportJob,
	}
}

// Create allocates a fresh job for the user. It rejects a second create
// while a job is still staging or running so one user can only import
// one archive at a time; a finished job is replaced.
func (c *ImportCoordinator) Create(userID string, req ImportCreateRequest) (*ImportJobState, error) {
	if err := validateImportCreate(req); err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.jobs[userID]; ok {
		snap := existing.Snapshot()
		if snap.Status == ImportJobStaging || snap.Status == ImportJobRunning {
			return nil, &AppError{Status: 409, Code: CodeIdempotencyConflict, Message: "an import is already in progress"}
		}
	}

	stagingKey, err := cryptopkg.RandomKey()
	if err != nil {
		return nil, err
	}
	job := &ImportJobState{
		ID:            newImportID(),
		UserID:        userID,
		UploadID:      newImportID(),
		Source:        req.Source,
		TotalBytes:    req.TotalBytes,
		TotalChunks:   req.TotalChunks,
		ArchiveSHA256: req.ArchiveSHA256,
		StartedAt:     time.Now().UTC(),
		stagingKey:    stagingKey,
		received:      make(map[int]string, req.TotalChunks),
		status:        ImportJobStaging,
		updatedAt:     time.Now().UTC(),
		done:          make(chan struct{}),
	}
	c.jobs[userID] = job
	return job, nil
}

func (c *ImportCoordinator) Get(userID string) *ImportJobState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jobs[userID]
}

// Start launches the detached job goroutine. It returns false when the
// job has already been started, making start idempotent against retries.
func (c *ImportCoordinator) Start(parentCtx context.Context, deps Deps, sess Session, job *ImportJobState, cek []byte) bool {
	job.mu.Lock()
	if job.startedRun {
		job.mu.Unlock()
		cryptopkg.Zero(cek)
		return false
	}
	job.startedRun = true
	job.cek = cek
	job.status = ImportJobRunning
	job.updatedAt = time.Now().UTC()
	job.mu.Unlock()

	go c.run(parentCtx, deps, sess, job)
	return true
}

func (c *ImportCoordinator) run(parentCtx context.Context, deps Deps, sess Session, job *ImportJobState) {
	ctx := context.WithoutCancel(parentCtx)
	ctx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()

	deps.logInfo("import job begin: user=%s job=%s source=%s", job.UserID, job.ID, job.Source)
	err := c.runner(ctx, deps, sess, job)
	if err != nil {
		deps.logError("import job failed: user=%s job=%s err=%v", job.UserID, job.ID, err)
		job.addError("import failed")
		job.finish(ImportJobFailed)
	} else {
		snap := job.Snapshot()
		deps.logInfo("import job done: user=%s job=%s imported=%d failed=%d", job.UserID, job.ID, snap.Imported, snap.Failed)
		job.finish(ImportJobCompleted)
	}

	c.cleanupStaging(ctx, deps, job)

	retention := c.retention
	if retention <= 0 {
		c.deleteIfSame(job)
		return
	}
	time.AfterFunc(retention, func() { c.deleteIfSame(job) })
}

// cleanupStaging deletes every staged chunk for the job. Buckets delete
// is idempotent, so this is safe on success, failure, and timeout.
func (c *ImportCoordinator) cleanupStaging(ctx context.Context, deps Deps, job *ImportJobState) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bucketsRollbackTimeout)
	defer cancel()
	for i := 0; i < job.TotalChunks; i++ {
		_ = deps.Buckets.Delete(cleanupCtx, job.UserID, importChunkToken(job.UploadID, i))
	}
}

func (c *ImportCoordinator) deleteIfSame(job *ImportJobState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jobs[job.UserID] == job {
		delete(c.jobs, job.UserID)
	}
}

func newImportID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

func validateImportCreate(req ImportCreateRequest) error {
	switch req.Source {
	case "chatgpt", "claude", "tinfoil":
	default:
		return badRequest("invalid source")
	}
	if req.TotalBytes <= 0 || req.TotalBytes > MaxImportArchiveBytes {
		return badRequest("invalid total_bytes")
	}
	if req.TotalChunks <= 0 {
		return badRequest("invalid total_chunks")
	}
	expected := int((req.TotalBytes + MaxImportChunkBytes - 1) / MaxImportChunkBytes)
	if req.TotalChunks != expected {
		return badRequest("total_chunks does not match total_bytes")
	}
	if len(req.ArchiveSHA256) != 64 {
		return badRequest("invalid archive_sha256")
	}
	return nil
}
