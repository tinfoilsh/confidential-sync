package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// buildLegacyChatBlob seals a JSON chat row under the fixture's
// userKey using the legacy v0 envelope shape so it can be planted
// directly into the cp stub and then re-keyed by Migrate.
func buildLegacyChatBlob(t *testing.T, f *fixture, id string) *cpBlob {
	t.Helper()
	pt := []byte(`{"id":"` + id + `","title":"legacy","messages":[]}`)
	nonce, ct, err := cryptopkg.Seal(f.userKey, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"iv":   base64.StdEncoding.EncodeToString(nonce),
		"data": base64.StdEncoding.EncodeToString(ct),
	})
	return &cpBlob{ETag: 1, KeyID: "", Body: body}
}

// newTestCoordinator wires the coordinator with an injected runner
// + short retention so individual tests run in milliseconds without
// leaking goroutines or in-memory entries between cases.
func newTestCoordinator(runner func(ctx context.Context, deps Deps, sess Session, req MigrateAllRequest, job *MigrationJob) (*MigrateAllResponse, error)) *MigrationCoordinator {
	c := NewMigrationCoordinator()
	c.retention = 10 * time.Millisecond
	c.budget = 5 * time.Second
	c.runnerHook = runner
	return c
}

func testSession(userID string) Session {
	return Session{
		RawJWT: "test-jwt-" + userID,
		Claims: auth.Claims{Subject: userID},
	}
}

func TestCoordinatorDedupesConcurrentKickoffPerUser(t *testing.T) {
	t.Parallel()

	var runnerInvocations int32
	release := make(chan struct{})
	runner := func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, _ *MigrationJob) (*MigrateAllResponse, error) {
		atomic.AddInt32(&runnerInvocations, 1)
		<-release
		return &MigrateAllResponse{}, nil
	}
	c := newTestCoordinator(runner)

	sess := testSession("user_alpha")
	const callers = 16
	jobs := make([]*MigrationJob, callers)
	started := make([]bool, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		idx := i
		go func() {
			defer wg.Done()
			job, isNew := c.StartOrGet(context.Background(), Deps{}, sess, MigrateAllRequest{})
			jobs[idx] = job
			started[idx] = isNew
		}()
	}
	wg.Wait()

	uniqueIDs := map[string]struct{}{}
	startedCount := 0
	for i, j := range jobs {
		if j == nil {
			t.Fatalf("caller %d got nil job", i)
		}
		uniqueIDs[j.ID] = struct{}{}
		if started[i] {
			startedCount++
		}
	}
	if got := len(uniqueIDs); got != 1 {
		t.Fatalf("expected all callers to share one job, got %d distinct ids", got)
	}
	if startedCount != 1 {
		t.Fatalf("expected exactly one caller to receive started=true, got %d", startedCount)
	}
	close(release)
	<-jobs[0].Done()
	if got := atomic.LoadInt32(&runnerInvocations); got != 1 {
		t.Fatalf("expected runner to run exactly once, got %d", got)
	}
}

func TestCoordinatorIsolatesUsers(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	runner := func(ctx context.Context, _ Deps, sess Session, _ MigrateAllRequest, _ *MigrationJob) (*MigrateAllResponse, error) {
		<-release
		return &MigrateAllResponse{Scopes: []MigrateAllScopeReport{{Scope: "chat", Migrated: 1}}}, nil
	}
	c := newTestCoordinator(runner)

	jobA, startedA := c.StartOrGet(context.Background(), Deps{}, testSession("user_a"), MigrateAllRequest{})
	jobB, startedB := c.StartOrGet(context.Background(), Deps{}, testSession("user_b"), MigrateAllRequest{})
	if !startedA || !startedB {
		t.Fatalf("both per-user kickoffs should start fresh jobs (got %v, %v)", startedA, startedB)
	}
	if jobA.ID == jobB.ID {
		t.Fatalf("expected per-user jobs to be distinct, got %s == %s", jobA.ID, jobB.ID)
	}
	close(release)
	<-jobA.Done()
	<-jobB.Done()
}

func TestCoordinatorDetachesFromRequestContext(t *testing.T) {
	t.Parallel()

	observedCtxErr := make(chan error, 1)
	release := make(chan struct{})
	runner := func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, _ *MigrationJob) (*MigrateAllResponse, error) {
		// Wait long enough for the parent ctx cancel below to land
		// then report what our ctx looked like.
		select {
		case <-release:
		case <-ctx.Done():
		}
		observedCtxErr <- ctx.Err()
		return &MigrateAllResponse{}, nil
	}
	c := newTestCoordinator(runner)

	parent, cancel := context.WithCancel(context.Background())
	job, _ := c.StartOrGet(parent, Deps{}, testSession("user_detach"), MigrateAllRequest{})

	// Cancel the parent and wait a beat. A non-detached runner would
	// observe ctx.Err() on its own ctx; a properly detached one will
	// not.
	cancel()
	time.Sleep(20 * time.Millisecond)

	close(release)
	<-job.Done()

	select {
	case err := <-observedCtxErr:
		if err != nil {
			t.Fatalf("detached job context should not have observed parent cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not report context state")
	}
}

func TestCoordinatorReplacesAfterCompletion(t *testing.T) {
	t.Parallel()

	var invocations int32
	runner := func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, _ *MigrationJob) (*MigrateAllResponse, error) {
		atomic.AddInt32(&invocations, 1)
		return &MigrateAllResponse{}, nil
	}
	c := newTestCoordinator(runner)

	sess := testSession("user_replay")
	first, _ := c.StartOrGet(context.Background(), Deps{}, sess, MigrateAllRequest{})
	<-first.Done()
	// Give the retention timer plus a small margin to reap the job.
	time.Sleep(40 * time.Millisecond)

	second, isNew := c.StartOrGet(context.Background(), Deps{}, sess, MigrateAllRequest{})
	if !isNew {
		t.Fatalf("expected a fresh job after retention window")
	}
	if second.ID == first.ID {
		t.Fatalf("expected new job id, got same id %s", first.ID)
	}
	<-second.Done()
	if got := atomic.LoadInt32(&invocations); got != 2 {
		t.Fatalf("expected runner to run twice, got %d", got)
	}
}

func TestCoordinatorReportsProgressLive(t *testing.T) {
	t.Parallel()

	advance := make(chan struct{})
	runner := func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, job *MigrationJob) (*MigrateAllResponse, error) {
		job.reportScope(MigrateAllScopeReport{Scope: "chat", Migrated: 5, RetryableRemaining: 195})
		advance <- struct{}{}
		<-advance
		job.reportScope(MigrateAllScopeReport{Scope: "chat", Migrated: 10, RetryableRemaining: 190})
		return &MigrateAllResponse{
			Migrated:           10,
			RetryableRemaining: 190,
			Scopes:             []MigrateAllScopeReport{{Scope: "chat", Migrated: 10, RetryableRemaining: 190}},
		}, nil
	}
	c := newTestCoordinator(runner)

	job, _ := c.StartOrGet(context.Background(), Deps{}, testSession("user_progress"), MigrateAllRequest{})
	<-advance
	mid := job.Snapshot()
	if mid.Migrated != 5 {
		t.Fatalf("expected mid-job migrated=5, got %d", mid.Migrated)
	}
	if mid.Status != MigrationJobRunning {
		t.Fatalf("expected mid-job status=running, got %s", mid.Status)
	}
	advance <- struct{}{}
	<-job.Done()
	final := job.Snapshot()
	if final.Migrated != 10 {
		t.Fatalf("expected final migrated=10, got %d", final.Migrated)
	}
	if final.Status != MigrationJobCompleted {
		t.Fatalf("expected final status=completed, got %s", final.Status)
	}
}

func TestCoordinatorSurfacesRunnerFailure(t *testing.T) {
	t.Parallel()

	want := errors.New("controlplane down")
	runner := func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, _ *MigrationJob) (*MigrateAllResponse, error) {
		return nil, want
	}
	c := newTestCoordinator(runner)

	job, _ := c.StartOrGet(context.Background(), Deps{}, testSession("user_err"), MigrateAllRequest{})
	<-job.Done()
	snap := job.Snapshot()
	if snap.Status != MigrationJobFailed {
		t.Fatalf("expected status=failed, got %s", snap.Status)
	}
	if !strings.Contains(snap.Error, want.Error()) {
		t.Fatalf("expected error to contain %q, got %q", want.Error(), snap.Error)
	}
}

func TestBuildMigrateAllStatusResponseHoldsPartialWhileRunning(t *testing.T) {
	t.Parallel()

	job := newMigrationJob("user_polling")
	job.reportScope(MigrateAllScopeReport{Scope: "chat", Migrated: 3, RetryableRemaining: 7})
	resp := buildMigrateAllStatusResponse(job)
	if resp.Status != string(MigrationJobRunning) {
		t.Fatalf("expected status=running, got %s", resp.Status)
	}
	if !resp.Partial {
		t.Fatalf("expected partial=true while running so legacy webapp loop keeps polling")
	}
	if resp.Migrated != 3 || resp.RetryableRemaining != 7 {
		t.Fatalf("unexpected counts %+v", resp)
	}

	job.finish(&MigrateAllResponse{
		Migrated:           10,
		RetryableRemaining: 0,
		Scopes:             []MigrateAllScopeReport{{Scope: "chat", Migrated: 10}},
	}, nil)
	final := buildMigrateAllStatusResponse(job)
	if final.Status != string(MigrationJobCompleted) {
		t.Fatalf("expected status=completed, got %s", final.Status)
	}
	if final.Partial {
		t.Fatalf("expected partial=false after completion")
	}
	if final.Migrated != 10 || final.RetryableRemaining != 0 {
		t.Fatalf("unexpected final counts %+v", final)
	}
}

func TestMigrateAllHandlerAsyncKickoff(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	// Replace the coordinator's runner with a deterministic stub so
	// the test can observe both the running and completed wire
	// shapes without relying on real CP traffic.
	release := make(chan struct{})
	f.handler.coordinator.budget = 5 * time.Second
	f.handler.coordinator.retention = 200 * time.Millisecond
	f.handler.coordinator.runnerHook = func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, job *MigrationJob) (*MigrateAllResponse, error) {
		job.reportScope(MigrateAllScopeReport{Scope: "chat", Migrated: 2, RetryableRemaining: 8})
		<-release
		return &MigrateAllResponse{
			Migrated:           5,
			RetryableRemaining: 0,
			Scopes:             []MigrateAllScopeReport{{Scope: "chat", Migrated: 5}},
		}, nil
	}

	tok := f.jwt()
	body := MigrateAllRequest{
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: f.userKeyB64},
	}

	resp, raw := f.post("/v1/blobs/migrate-all", body, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 on kickoff, got %d %s", resp.StatusCode, raw)
	}
	var first MigrateAllStatusResponse
	if err := json.Unmarshal(raw, &first); err != nil {
		t.Fatalf("decode kickoff: %v", err)
	}
	if first.Status != string(MigrationJobRunning) {
		t.Fatalf("expected status=running, got %s", first.Status)
	}
	if !first.Partial {
		t.Fatalf("expected partial=true while running")
	}
	if first.JobID == "" {
		t.Fatalf("expected job_id to be set")
	}

	// A second kickoff while the job is still running must NOT
	// start a new job and must return 200 with the same job_id.
	resp2, raw2 := f.post("/v1/blobs/migrate-all", body, tok)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on second kickoff, got %d %s", resp2.StatusCode, raw2)
	}
	var second MigrateAllStatusResponse
	if err := json.Unmarshal(raw2, &second); err != nil {
		t.Fatalf("decode second kickoff: %v", err)
	}
	if second.JobID != first.JobID {
		t.Fatalf("expected reused job_id %s, got %s", first.JobID, second.JobID)
	}
	if second.Migrated < 2 {
		t.Fatalf("expected at least 2 migrated by mid-job, got %d", second.Migrated)
	}

	// migrate-status returns the same in-flight job state.
	resp3, raw3 := f.post("/v1/blobs/migrate-status", struct{}{}, tok)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on status, got %d %s", resp3.StatusCode, raw3)
	}
	var midStatus MigrateAllStatusResponse
	if err := json.Unmarshal(raw3, &midStatus); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if midStatus.JobID != first.JobID {
		t.Fatalf("expected status to surface same job id, got %s", midStatus.JobID)
	}

	close(release)
	<-f.handler.coordinator.Status(f.userSub).Done()

	resp4, raw4 := f.post("/v1/blobs/migrate-status", struct{}{}, tok)
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on final status, got %d %s", resp4.StatusCode, raw4)
	}
	var finalStatus MigrateAllStatusResponse
	if err := json.Unmarshal(raw4, &finalStatus); err != nil {
		t.Fatalf("decode final status: %v", err)
	}
	if finalStatus.Status != string(MigrationJobCompleted) {
		t.Fatalf("expected status=completed, got %s", finalStatus.Status)
	}
	if finalStatus.Partial {
		t.Fatalf("expected partial=false after completion")
	}
	if finalStatus.Migrated != 5 {
		t.Fatalf("expected migrated=5, got %d", finalStatus.Migrated)
	}
}

// TestMigrateLoopSkipsRemainingIDsWhenContextCancelledUpfront
// reproduces the production bug where closing the webapp tab
// mid-migration caused every remaining row in the in-flight batch
// to be marked "blocked" with a canceled fetch, polluting the
// blocked list and firing useless RecordMigrationFailure calls.
//
// The ids are passed explicitly so the list-needs CP call is
// bypassed entirely and the test exercises the inner loop's
// top-of-iteration ctx.Err() guard directly. The loop must observe
// the canceled context on the very first iteration and break
// without touching ANY id.
// TestMigrateOneTreatsConcurrentV2AsMigrated guards the phantom-failure
// fix: when a concurrent migration pass (or a user push) re-keys a row
// to v2 between our fetch and our rewrap, the rewrap CAS answers
// STALE_BLOB. migrateOne must re-read, observe the row is already v2,
// and count it migrated instead of recording a migration failure that
// burns the 24h cooldown.
func TestMigrateOneTreatsConcurrentV2AsMigrated(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	chatJSON := []byte(`{"id":"c1","title":"legacy","messages":[]}`)
	f.cp.mu.Lock()
	f.cp.currentKID = f.userKeyID
	f.cp.blobs["chat/c1"] = buildLegacyChatBlob(t, f, "c1")
	f.cp.mu.Unlock()

	v2blob, err := envelope.Encrypt(f.userKey, chatJSON, envelope.AAD{
		KeyIDHex:    f.userKeyID,
		Scope:       envelope.ScopeChat,
		ID:          "c1",
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Right before our rewrap CAS runs, swap the row to a v2 envelope
	// and bump the etag so our if_match (etag 1) mismatches and the
	// stub answers STALE_BLOB, exactly as a concurrent pass that
	// already migrated the row would.
	var swapped int32
	f.cp.captureHeaders = func(r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/api/sync/rewrap") {
			return
		}
		if !atomic.CompareAndSwapInt32(&swapped, 0, 1) {
			return
		}
		f.cp.mu.Lock()
		f.cp.blobs["chat/c1"] = &cpBlob{ETag: 2, KeyID: f.userKeyID, Body: v2blob}
		f.cp.mu.Unlock()
	}

	sess := Session{RawJWT: tok, Claims: auth.Claims{Subject: f.userSub}}
	resp, err := Migrate(context.Background(), f.handler.deps, sess, MigrateRequest{
		Scope:  "chat",
		IDs:    []string{"c1"},
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: f.userKeyB64},
	})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if resp.Migrated != 1 {
		t.Fatalf("expected migrated=1, got %d (blocked=%v)", resp.Migrated, resp.Blocked)
	}
	if len(resp.Blocked) != 0 {
		t.Fatalf("expected no blocked rows, got %v", resp.Blocked)
	}

	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	if n := f.cp.migrationFailures["chat/c1"]; n != 0 {
		t.Fatalf("phantom migration failure recorded: %d", n)
	}
}

func TestMigrateLoopSkipsRemainingIDsWhenContextCancelledUpfront(t *testing.T) {
	f := newFixture(t)

	// Seed legacy blobs so the loop would have something real to
	// migrate if it weren't for the canceled context.
	blob := buildLegacyChatBlob(t, f, "ctx_skip_1")
	f.cp.mu.Lock()
	f.cp.blobs["chat/ctx_skip_1"] = blob
	f.cp.blobs["chat/ctx_skip_2"] = blob
	f.cp.blobs["chat/ctx_skip_3"] = blob
	f.cp.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess := Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
	resp, err := Migrate(ctx, f.handler.deps, sess, MigrateRequest{
		Scope:  "chat",
		IDs:    []string{"ctx_skip_1", "ctx_skip_2", "ctx_skip_3"},
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: f.userKeyB64},
	})
	if err != nil {
		t.Fatalf("ctx-cancelled run with explicit ids should return cleanly, got err=%v", err)
	}
	if resp.Migrated != 0 {
		t.Fatalf("expected migrated=0 under canceled ctx, got %d", resp.Migrated)
	}
	if len(resp.Blocked) != 0 {
		t.Fatalf("canceled ctx must not produce blocked entries; got %v", resp.Blocked)
	}

	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	for id := range f.cp.migrationFailures {
		if strings.HasPrefix(id, "chat/ctx_skip_") {
			t.Fatalf("ctx-cancelled run recorded a migration failure for %s", id)
		}
	}
}

// TestMigrateLoopDoesNotBlockIDsCanceledMidFetch validates the
// second cancellation guard: ctx.Err() check AFTER migrateOne
// returns false. The first id is fetched successfully, then we
// cancel the parent context while the second fetch is in flight.
// migrateOne returns false (canceled fetch), the post-call ctx.Err()
// guard fires, and the loop breaks WITHOUT recording a failure or
// appending to Blocked for the canceled id.
func TestMigrateLoopDoesNotBlockIDsCanceledMidFetch(t *testing.T) {
	f := newFixture(t)

	good := buildLegacyChatBlob(t, f, "mid_cancel_1")
	f.cp.mu.Lock()
	f.cp.blobs["chat/mid_cancel_1"] = good
	f.cp.blobs["chat/mid_cancel_2"] = good
	f.cp.blobs["chat/mid_cancel_3"] = good
	f.cp.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var fetchCount int32
	hold := make(chan struct{})
	f.cp.mu.Lock()
	f.cp.captureHeaders = func(r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/api/sync/blob/chat/") {
			return
		}
		n := atomic.AddInt32(&fetchCount, 1)
		// Cancel the parent ctx while the second fetch is mid-flight;
		// the in-flight GetBlob then sees ctx.Done() and returns
		// context.Canceled. Block long enough for the cancel to land.
		if n == 2 {
			cancel()
			<-hold
		}
	}
	f.cp.mu.Unlock()

	doneCh := make(chan migrateResult, 1)
	go func() {
		sess := Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
		resp, err := Migrate(ctx, f.handler.deps, sess, MigrateRequest{
			Scope:  "chat",
			IDs:    []string{"mid_cancel_1", "mid_cancel_2", "mid_cancel_3"},
			Keys:   []PullKey{{Key: f.userKeyB64}},
			Target: MigrateTarget{Key: f.userKeyB64},
		})
		doneCh <- migrateResult{resp: resp, err: err}
	}()

	// Wait briefly for the second fetch to be parked, then release.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&fetchCount) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(hold)

	select {
	case r := <-doneCh:
		if r.err != nil {
			t.Fatalf("mid-fetch cancel should return cleanly, got err=%v", r.err)
		}
		if r.resp.Migrated != 1 {
			t.Fatalf("expected migrated=1 (only the first id finished before cancel), got %d", r.resp.Migrated)
		}
		if len(r.resp.Blocked) != 0 {
			t.Fatalf("mid-fetch cancel must not produce blocked entries; got %v", r.resp.Blocked)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Migrate did not return within 5s of cancellation")
	}

	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	for id := range f.cp.migrationFailures {
		if strings.HasPrefix(id, "chat/mid_cancel_") {
			t.Fatalf("mid-fetch cancel recorded a migration failure for %s", id)
		}
	}
}

type migrateResult struct {
	resp *MigrateResponse
	err  error
}

// TestStartOrGetReturnsCompletedJobDuringRetention pins down the
// addressability contract: completed jobs stay visible to subsequent
// migrate-all calls until the retention reaper drops them, so the
// webapp's polling loop sees a stable "completed" snapshot instead
// of triggering a brand new run on every tick.
func TestStartOrGetReturnsCompletedJobDuringRetention(t *testing.T) {
	t.Parallel()

	var invocations int32
	runner := func(ctx context.Context, _ Deps, _ Session, _ MigrateAllRequest, _ *MigrationJob) (*MigrateAllResponse, error) {
		atomic.AddInt32(&invocations, 1)
		return &MigrateAllResponse{
			Migrated:           5,
			RetryableRemaining: 0,
			Scopes:             []MigrateAllScopeReport{{Scope: "chat", Migrated: 5}},
		}, nil
	}
	c := NewMigrationCoordinator()
	c.retention = 5 * time.Second
	c.budget = 1 * time.Second
	c.runnerHook = runner

	sess := testSession("user_retention")
	first, startedA := c.StartOrGet(context.Background(), Deps{}, sess, MigrateAllRequest{})
	if !startedA {
		t.Fatalf("expected first call to start a fresh job")
	}
	<-first.Done()
	if snap := first.Snapshot(); snap.Status != MigrationJobCompleted {
		t.Fatalf("expected job to be completed before second call, got %s", snap.Status)
	}

	second, startedB := c.StartOrGet(context.Background(), Deps{}, sess, MigrateAllRequest{})
	if startedB {
		t.Fatalf("a completed-but-still-retained job must not be replaced by a new run")
	}
	if second != first {
		t.Fatalf("expected second call to surface the same completed job")
	}
	if got := atomic.LoadInt32(&invocations); got != 1 {
		t.Fatalf("expected runner to have run exactly once during retention, got %d", got)
	}
}

func TestMigrateAllHandlerRejectsMalformedKeysSynchronously(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	tok := f.jwt()

	resp, raw := f.post("/v1/blobs/migrate-all", MigrateAllRequest{
		Keys:   []PullKey{{Key: "not-base64!!!"}},
		Target: MigrateTarget{Key: f.userKeyB64},
	}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on malformed key, got %d %s", resp.StatusCode, raw)
	}

	resp2, raw2 := f.post("/v1/blobs/migrate-all", MigrateAllRequest{
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: "garbage"},
	}, tok)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on malformed target, got %d %s", resp2.StatusCode, raw2)
	}

	// The kickoff failure must NOT leave a coordinator entry behind.
	if job := f.handler.coordinator.Status(f.userSub); job != nil {
		t.Fatalf("validation failure leaked a coordinator entry: %+v", job.Snapshot())
	}
}

func TestMigrateAllRefusesWhenNoCurrentKeyRegistered(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// The fixture's controlplane stub starts with no current key
	// registered. Driving migrate-all in that state must refuse to
	// bootstrap a bundleless current key (which would strand the
	// account and hide the user's legacy passkey) and instead return a
	// precondition error.
	sess := Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
	_, err := MigrateAll(context.Background(), f.handler.deps, sess, MigrateAllRequest{
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: f.userKeyB64},
	})
	if err == nil {
		t.Fatal("expected migrate-all to fail when no current key is registered")
	}
	var appErr *AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *AppError, got %T: %v", err, err)
	}
	if appErr.Status != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", appErr.Status)
	}
	if appErr.Code != CodeUnknownKey {
		t.Fatalf("expected code %s, got %s", CodeUnknownKey, appErr.Code)
	}
	if appErr.Reason != "no_current_key" {
		t.Fatalf("expected reason no_current_key, got %q", appErr.Reason)
	}

	// The refusal must not register a key as a side effect.
	f.cp.mu.Lock()
	gotKID := f.cp.currentKID
	f.cp.mu.Unlock()
	if gotKID != "" {
		t.Fatalf("expected no current key to be registered, got %q", gotKID)
	}
}

func TestMigrateAllRefusesWhenCurrentKeyDiffersFromTarget(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// Register a current key that is NOT the migration target. Every
	// rewrap would 409 STALE_KEY on the controlplane CAS, so migrate-all
	// must fail fast instead of looping doomed rewraps against every
	// blob.
	const otherKID = "00000000000000000000000000000000"
	f.cp.mu.Lock()
	f.cp.currentKID = otherKID
	f.cp.keys[otherKID] = struct{}{}
	f.cp.mu.Unlock()

	sess := Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
	_, err := MigrateAll(context.Background(), f.handler.deps, sess, MigrateAllRequest{
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: f.userKeyB64},
	})
	if err == nil {
		t.Fatal("expected migrate-all to fail when current key differs from target")
	}
	var appErr *AppError
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *AppError, got %T: %v", err, err)
	}
	if appErr.Status != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", appErr.Status)
	}
	if appErr.Code != CodeStaleKey {
		t.Fatalf("expected code %s, got %s", CodeStaleKey, appErr.Code)
	}
	if appErr.Reason != "stale_key" {
		t.Fatalf("expected reason stale_key, got %q", appErr.Reason)
	}

	// The registered current key must be untouched by the refusal.
	f.cp.mu.Lock()
	gotKID := f.cp.currentKID
	f.cp.mu.Unlock()
	if gotKID != otherKID {
		t.Fatalf("current key changed during refusal: %q", gotKID)
	}
}

func TestMigrateStatusReturnsIdleWhenNoJob(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	resp, raw := f.post("/v1/blobs/migrate-status", struct{}{}, f.jwt())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", resp.StatusCode, raw)
	}
	var got MigrateAllStatusResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != string(MigrationJobIdle) {
		t.Fatalf("expected idle, got %s", got.Status)
	}
	if got.JobID != "" {
		t.Fatalf("expected empty job_id, got %q", got.JobID)
	}
}
