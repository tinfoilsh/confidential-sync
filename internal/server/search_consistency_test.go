package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

func (f *searchFixture) searchSession() Session {
	return Session{RawJWT: f.jwt(), Claims: auth.Claims{Subject: f.userSub}}
}

func (f *searchFixture) indexKey(t *testing.T) []byte {
	t.Helper()
	indexKey, err := cryptopkg.DeriveSearchIndexKey(f.userKey)
	if err != nil {
		t.Fatal(err)
	}
	return indexKey
}

func (f *searchFixture) runReindexJob(t *testing.T, tok string) SearchReindexStatusResponse {
	t.Helper()
	resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		t.Fatalf("reindex kickoff: status %d body %s", resp.StatusCode, body)
	}
	job := f.handler.reindexCoordinator.Status(f.userSub)
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("reindex job did not finish")
	}
	return job.statusResponse()
}

type blockingEmbedder struct {
	base    *stubEmbedder
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingEmbedder) Configured() bool { return b.base.Configured() }

func (b *blockingEmbedder) Model() string { return b.base.Model() }

func (b *blockingEmbedder) Embed(ctx context.Context, inputs []string) ([][]float32, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return b.base.Embed(ctx, inputs)
}

// TestPushAfterUnreadableIndexKeepsNeedsReindex covers the coverage-
// masking hole: a push that rebuilds on top of an unreadable index
// (wrong key, corruption) only contains that one chat, so queries
// must keep reporting needs_reindex until a rebuild has run.
func TestPushAfterUnreadableIndexKeepsNeedsReindex(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	// Corrupt the stored object and cool the cache, then push again:
	// the new index holds only the new chat.
	if err := f.handler.deps.SearchBuckets.Put(context.Background(), f.userSub, searchIndexObjectKey, []byte("garbage"), f.indexKey(t)); err != nil {
		t.Fatal(err)
	}
	f.handler.deps.SearchCache.drop(f.userSub)
	f.pushChat(t, tok, "chat_tax", "Paperwork", "tax return time")

	got := f.query(t, tok, "tax")
	if !got.NeedsReindex {
		t.Fatal("push on top of an unreadable index must not clear needs_reindex")
	}
	if len(got.Results) == 0 || got.Results[0].ID != "chat_tax" {
		t.Fatalf("fresh chat should still be searchable: %+v", got.Results)
	}

	// A completed rebuild restores coverage and clears the signal.
	status := f.runReindexJob(t, tok)
	if status.Status != string(MigrationJobCompleted) || status.Partial {
		t.Fatalf("rebuild did not complete cleanly: %+v", status)
	}
	got = f.query(t, tok, "duck")
	if got.NeedsReindex {
		t.Fatal("completed rebuild must clear needs_reindex")
	}
	if got.TotalIndexed != 2 || len(got.Results) == 0 || got.Results[0].ID != "chat_duck" {
		t.Fatalf("rebuild lost coverage: %+v", got)
	}
}

func TestPushAfterMissingIndexKeepsNeedsReindexWhenOtherChatsExist(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")
	f.pushChat(t, tok, "chat_dog", "Park", "a dog fetched a ball")

	if err := f.handler.deps.SearchBuckets.Delete(context.Background(), f.userSub, searchIndexObjectKey); err != nil {
		t.Fatal(err)
	}
	f.handler.deps.SearchCache.drop(f.userSub)
	f.pushChat(t, tok, "chat_tax", "Paperwork", "tax return time")

	got := f.query(t, tok, "tax")
	if !got.NeedsReindex {
		t.Fatal("push on top of a missing index with older chats must keep needs_reindex")
	}
	if got.TotalIndexed != 1 || len(got.Results) == 0 || got.Results[0].ID != "chat_tax" {
		t.Fatalf("fresh chat should still be searchable: %+v", got)
	}

	status := f.runReindexJob(t, tok)
	if status.Status != string(MigrationJobCompleted) || status.Partial {
		t.Fatalf("rebuild did not complete cleanly: %+v", status)
	}
	got = f.query(t, tok, "duck")
	if got.NeedsReindex || got.TotalIndexed != 3 || len(got.Results) == 0 || got.Results[0].ID != "chat_duck" {
		t.Fatalf("rebuild did not restore full coverage: %+v", got)
	}
}

func TestOversizedStoredSearchIndexNeedsReindexAndCanBeReplaced(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	oldLimit := maxIndexStoredBytes
	maxIndexStoredBytes = 4
	t.Cleanup(func() { maxIndexStoredBytes = oldLimit })

	if err := f.handler.deps.SearchBuckets.Put(context.Background(), f.userSub, searchIndexObjectKey, []byte("large"), f.indexKey(t)); err != nil {
		t.Fatal(err)
	}
	f.handler.deps.SearchCache.drop(f.userSub)
	got := f.query(t, tok, "duck")
	if !got.NeedsReindex || got.TotalIndexed != 0 || len(got.Results) != 0 {
		t.Fatalf("oversized index should be treated as unreadable: %+v", got)
	}

	f.pushChat(t, tok, "chat_tax", "Paperwork", "tax return time")
	maxIndexStoredBytes = oldLimit
	got = f.query(t, tok, "tax")
	if !got.NeedsReindex || got.TotalIndexed != 1 || len(got.Results) == 0 || got.Results[0].ID != "chat_tax" {
		t.Fatalf("push did not replace oversized index with partial searchable index: %+v", got)
	}
}

// TestReindexPreservesEntriesWrittenDuringRebuild covers the rebuild
// race: entries written by inline pushes after the job started must
// survive the fresh-start page, while entries from before the job
// (including since-deleted chats) are flushed and pulled pages must
// not clobber fresher inline updates.
func TestReindexPreservesEntriesWrittenDuringRebuild(t *testing.T) {
	f := newSearchFixture(t)
	ctx := context.Background()
	tok := f.jwt()
	sess := f.searchSession()
	keys := []PullKey{{Key: f.userKeyB64}}

	// In the control plane and index from before the job.
	f.pushChat(t, tok, "chat_old", "Pond", "a duck swam by")
	// In the index only (its chat is gone from the control plane), so
	// the rebuild must flush it.
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_deleted", chatJSON(t, "chat_deleted", "", "left over ghost"), "g1", time.Now()); err != nil {
		t.Fatal(err)
	}

	startedAt := time.Now().UTC()

	// Simulates a push whose index write lands after the job began
	// but whose chat is invisible to the job's listing snapshot.
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_racer", chatJSON(t, "chat_racer", "", "zebra crossing photos"), "g2", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Simulates a chat updated inline mid-job: the pull snapshot has
	// the old "duck" content, the index already has newer "heron"
	// content, and the rebuild must keep the newer entry.
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_old", chatJSON(t, "chat_old", "", "actually a heron flew past"), "g3", time.Now()); err != nil {
		t.Fatal(err)
	}

	cursor := ""
	for {
		page, err := searchReindexPage(ctx, f.handler.deps, sess, keys, cursor, startedAt)
		if err != nil {
			t.Fatal(err)
		}
		if page.Done {
			break
		}
		cursor = page.NextCursor
	}

	ix := f.loadIndex(t)
	if ix.Incomplete {
		t.Fatal("drained rebuild must mark the index complete")
	}
	if _, ok := ix.Chats["chat_deleted"]; ok {
		t.Fatal("rebuild kept an entry whose chat no longer exists")
	}
	if got := ix.Search(nil, []string{"zebra"}, 5); len(got) != 1 || got[0].ID != "chat_racer" {
		t.Fatalf("rebuild dropped an entry pushed mid-job: %+v", got)
	}
	if got := ix.Search(nil, []string{"heron"}, 5); len(got) != 1 || got[0].ID != "chat_old" {
		t.Fatalf("rebuild clobbered a mid-job update with the pull snapshot: %+v", got)
	}
}

// TestStaleWriteCannotClobberNewerEntry covers the slow-embed race: a
// push whose embedding finishes after a newer write for the same chat
// must not replace that newer entry.
func TestStaleWriteCannotClobberNewerEntry(t *testing.T) {
	f := newSearchFixture(t)
	ctx := context.Background()
	tok := f.jwt()
	f.pushChat(t, tok, "chat_a", "Lake", "a goose on the lake")

	// Fast-forward the stored entry so the next (in-order) write looks
	// like a straggler from an older push.
	ix := f.loadIndex(t)
	e := ix.Chats["chat_a"]
	e.UpdatedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	ix.Chats["chat_a"] = e
	if err := saveSearchIndex(ctx, f.handler.deps, f.userSub, f.indexKey(t), ix); err != nil {
		t.Fatal(err)
	}

	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_a", chatJSON(t, "chat_a", "", "a duck on the pond"), "stale", time.Now()); err != nil {
		t.Fatal(err)
	}

	after := f.loadIndex(t)
	if got := after.Search(nil, []string{"goose"}, 5); len(got) != 1 {
		t.Fatalf("newer entry was clobbered by a stale write: %+v", got)
	}
	if got := after.Search(nil, []string{"duck"}, 5); len(got) != 0 {
		t.Fatalf("stale write went through: %+v", got)
	}
}

// TestReindexRestartPolicy covers kickoff dedup: a retained clean
// success returns the same job (a duplicate or retried kickoff must
// not pay for re-embedding the corpus), while failed and partial runs
// are re-kickable immediately.
func TestReindexRestartPolicy(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	clean := f.runReindexJob(t, tok)
	if clean.Status != string(MigrationJobCompleted) || clean.Partial {
		t.Fatalf("setup: expected clean completion, got %+v", clean)
	}
	resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-kick after clean success: status %d body %s, want 200", resp.StatusCode, body)
	}
	var dedup SearchReindexStatusResponse
	if err := json.Unmarshal(body, &dedup); err != nil {
		t.Fatal(err)
	}
	if dedup.JobID != clean.JobID {
		t.Fatalf("re-kick after clean success must return the retained job: got %s want %s", dedup.JobID, clean.JobID)
	}

	fp := reindexKeyFingerprint([]PullKey{{Key: f.userKeyB64}})
	partial := newSearchReindexJob(f.userSub, fp)
	partial.markPartial()
	partial.finish(nil)
	if partial.blocksRestart() {
		t.Fatal("a completed partial job must not block a restart")
	}

	failed := newSearchReindexJob(f.userSub, fp)
	failed.finish(errors.New("boom"))
	coord := f.handler.reindexCoordinator
	coord.mu.Lock()
	coord.jobs[f.userSub] = failed
	coord.mu.Unlock()

	resp, body = f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("re-kick after failed job: status %d body %s, want 202", resp.StatusCode, body)
	}
	var restarted SearchReindexStatusResponse
	if err := json.Unmarshal(body, &restarted); err != nil {
		t.Fatal(err)
	}
	if restarted.JobID == "" || restarted.JobID == failed.ID {
		t.Fatalf("re-kick after failed job must start a fresh one: got %s", restarted.JobID)
	}
	job := f.handler.reindexCoordinator.Status(f.userSub)
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("restarted job did not finish")
	}
}

func TestRetainedReindexRestartsWhenIndexNeedsRepair(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	clean := f.runReindexJob(t, tok)
	if clean.Status != string(MigrationJobCompleted) || clean.Partial {
		t.Fatalf("setup: expected clean completion, got %+v", clean)
	}
	if err := f.handler.deps.SearchBuckets.Delete(context.Background(), f.userSub, searchIndexObjectKey); err != nil {
		t.Fatal(err)
	}
	resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("repair kickoff: status %d body %s, want 202", resp.StatusCode, body)
	}
	var repair SearchReindexStatusResponse
	if err := json.Unmarshal(body, &repair); err != nil {
		t.Fatal(err)
	}
	if repair.JobID == "" || repair.JobID == clean.JobID {
		t.Fatalf("repair must start a fresh job: got %s after %s", repair.JobID, clean.JobID)
	}
	job := f.handler.reindexCoordinator.Status(f.userSub)
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("repair job did not finish")
	}
	if status := job.statusResponse(); status.Status != string(MigrationJobCompleted) || status.Partial || status.Failed != 0 {
		t.Fatalf("repair did not complete cleanly: %+v", status)
	}
	if got := f.query(t, tok, "duck"); got.NeedsReindex || got.TotalIndexed != 1 || len(got.Results) == 0 || got.Results[0].ID != "chat_duck" {
		t.Fatalf("repair did not restore search coverage: %+v", got)
	}
}

// TestDeleteAlreadyGoneStillCleansSearchIndex covers the idempotent
// replay path: when the blob is already gone but a stale index entry
// survived, the delete must still remove the entry.
func TestDeleteAlreadyGoneStillCleansSearchIndex(t *testing.T) {
	f := newSearchFixture(t)
	ctx := context.Background()
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	del := func(idem string) {
		t.Helper()
		resp, body := f.post("/v1/sync/delete", DeleteRequest{
			Scope:          "chat",
			ID:             "chat_duck",
			Key:            f.userKeyB64,
			IdempotencyKey: idem,
		}, tok)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("delete: status %d body %s", resp.StatusCode, body)
		}
	}
	del("idem-gone-1")

	// Recreate the index entry as if an earlier delete had crashed
	// between the blob removal and the search cleanup.
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_duck", chatJSON(t, "chat_duck", "", "a duck swam by"), "ghost", time.Now()); err != nil {
		t.Fatal(err)
	}
	del("idem-gone-2")

	if _, ok := f.loadIndex(t).Chats["chat_duck"]; ok {
		t.Fatal("already-gone delete left the search index entry behind")
	}
}

func TestDelayedPushIndexingDoesNotResurrectDeletedChat(t *testing.T) {
	f := newSearchFixture(t)
	ctx := context.Background()
	tok := f.jwt()

	searchBuckets := f.handler.deps.SearchBuckets
	f.handler.deps.SearchBuckets = nil
	out := f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")
	f.handler.deps.SearchBuckets = searchBuckets

	resp, body := f.post("/v1/sync/delete", DeleteRequest{
		Scope:          "chat",
		ID:             "chat_duck",
		Key:            f.userKeyB64,
		IdempotencyKey: "idem-delete-before-index",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: status %d body %s", resp.StatusCode, body)
	}

	if err := indexCurrentChatForSearch(ctx, f.handler.deps, f.searchSession(), f.userKey, "chat_duck", chatJSON(t, "chat_duck", "", "a duck swam by"), out.ETag, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := f.query(t, tok, "duck")
	if got.TotalIndexed != 0 || len(got.Results) != 0 {
		t.Fatalf("deleted chat was resurrected in search: %+v", got)
	}
}

func TestReindexDoesNotResurrectChatDeletedDuringEmbedding(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()

	searchBuckets := f.handler.deps.SearchBuckets
	f.handler.deps.SearchBuckets = nil
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")
	f.handler.deps.SearchBuckets = searchBuckets

	blocker := &blockingEmbedder{
		base:    f.embedder,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	f.handler.deps.Embedder = blocker

	done := make(chan error, 1)
	go func() {
		_, err := searchReindexPage(context.Background(), f.handler.deps, f.searchSession(), []PullKey{{Key: f.userKeyB64}}, "", time.Now().UTC())
		done <- err
	}()
	select {
	case <-blocker.started:
	case <-time.After(10 * time.Second):
		t.Fatal("reindex did not reach embedding")
	}

	resp, body := f.post("/v1/sync/delete", DeleteRequest{
		Scope:          "chat",
		ID:             "chat_duck",
		Key:            f.userKeyB64,
		IdempotencyKey: "idem-delete-during-reindex",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: status %d body %s", resp.StatusCode, body)
	}
	close(blocker.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reindex page did not finish")
	}

	got := f.query(t, tok, "duck")
	if got.TotalIndexed != 0 || len(got.Results) != 0 {
		t.Fatalf("deleted chat was resurrected by reindex: %+v", got)
	}
}

// TestPushResponseEmitsSearchIndexedFalse pins the wire shape: the
// failure signal must survive JSON encoding rather than being dropped
// by omitempty.
func TestPushResponseEmitsSearchIndexedFalse(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()

	pushRaw := func(id string) string {
		t.Helper()
		plaintext := chatJSON(t, id, "Pond", "a duck swam by")
		resp, body := f.post("/v1/sync/push", PushRequest{
			Scope:          "chat",
			ID:             id,
			Key:            f.userKeyB64,
			Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
			IdempotencyKey: "idem-" + id,
		}, tok)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("push %s: status %d body %s", id, resp.StatusCode, body)
		}
		return string(body)
	}

	if body := pushRaw("chat_ok"); !strings.Contains(body, `"search_indexed":true`) {
		t.Fatalf(`expected "search_indexed":true in push response, got %s`, body)
	}
	f.embedder.setFailEmbed(errors.New("inference down"))
	if body := pushRaw("chat_fail"); !strings.Contains(body, `"search_indexed":false`) {
		t.Fatalf(`expected "search_indexed":false in push response, got %s`, body)
	}
}

// TestReindexDifferentKeyReplacesRunningJob covers a different key
// set racing a rebuild: a kickoff with a different key set must not
// join the old job (its output is sealed under a key the client did
// not ask to use); it cancels the old job and starts a fresh rebuild.
func TestReindexDifferentKeyReplacesRunningJob(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	coord := f.handler.reindexCoordinator
	var calls atomic.Int32
	coord.runnerHook = func(ctx context.Context, deps Deps, sess Session, req SearchReindexRequest, job *SearchReindexJob) error {
		if calls.Add(1) == 1 {
			<-ctx.Done()
		}
		return nil
	}

	kick := func(key string) (int, SearchReindexStatusResponse) {
		t.Helper()
		resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: key}}}, tok)
		var status SearchReindexStatusResponse
		if err := json.Unmarshal(body, &status); err != nil {
			t.Fatalf("kickoff body %s: %v", body, err)
		}
		return resp.StatusCode, status
	}

	code, first := kick(f.userKeyB64)
	if code != http.StatusAccepted {
		t.Fatalf("first kickoff: status %d, want 202", code)
	}
	oldJob := coord.Status(f.userSub)

	if code, again := kick(f.userKeyB64); code != http.StatusOK || again.JobID != first.JobID {
		t.Fatalf("same-key kickoff must join the running job: status %d job %s", code, again.JobID)
	}

	differentKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	code, second := kick(differentKey)
	if code != http.StatusAccepted || second.JobID == first.JobID {
		t.Fatalf("different-key kickoff must start a fresh job: status %d job %s", code, second.JobID)
	}
	select {
	case <-oldJob.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("superseded job was not cancelled")
	}
	newJob := coord.Status(f.userSub)
	if newJob.ID != second.JobID {
		t.Fatalf("coordinator tracks %s, want %s", newJob.ID, second.JobID)
	}
	select {
	case <-newJob.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("replacement job did not finish")
	}

	// A retained clean success only blocks kickoffs for the same key
	// set; another key set must restart immediately.
	differentKeyAgain := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if code, third := kick(differentKeyAgain); code != http.StatusAccepted || third.JobID == second.JobID {
		t.Fatalf("different key after retained success must restart: status %d job %s", code, third.JobID)
	}
	select {
	case <-coord.Status(f.userSub).Done():
	case <-time.After(10 * time.Second):
		t.Fatal("third job did not finish")
	}
}

// TestGenerationOrderBeatsTimestamp pins the write-ordering token:
// when both etags are numeric CAS generations, the higher generation
// wins regardless of local commit timestamps, so a delayed response
// cannot let an older blob version overwrite a newer entry.
func TestGenerationOrderBeatsTimestamp(t *testing.T) {
	f := newSearchFixture(t)
	ctx := context.Background()

	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_a", chatJSON(t, "chat_a", "", "a goose on the lake"), "5", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Older generation, later local timestamp: must be skipped.
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_a", chatJSON(t, "chat_a", "", "a duck on the pond"), "3", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ix := f.loadIndex(t)
	if got := ix.Search(nil, []string{"goose"}, 5); len(got) != 1 {
		t.Fatalf("older generation clobbered newer entry: %+v", got)
	}
	if got := ix.Search(nil, []string{"duck"}, 5); len(got) != 0 {
		t.Fatalf("older generation was applied: %+v", got)
	}
	// Newer generation, earlier local timestamp: must be applied.
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_a", chatJSON(t, "chat_a", "", "a heron flew past"), "7", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ix = f.loadIndex(t)
	if got := ix.Search(nil, []string{"heron"}, 5); len(got) != 1 {
		t.Fatalf("newer generation was not applied: %+v", got)
	}
}

// TestQueryDoesNotServeUnpersistedWrites pins storage as the source
// of truth: an index mutation whose persist failed must not surface
// in query results once the failed write's cache entry is dropped.
func TestQueryDoesNotServeUnpersistedWrites(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()

	target, err := url.Parse(f.searchBk.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var failPuts atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failPuts.Load() && r.Method == http.MethodPut {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	f.handler.deps.SearchBuckets = buckets.NewClient(srv.URL, testBucketName, nil)

	f.pushChat(t, tok, "chat_a", "Pond", "a duck swam by")

	failPuts.Store(true)
	out := f.pushChat(t, tok, "chat_b", "Lake", "a goose honked")
	if out.SearchIndexed == nil || *out.SearchIndexed {
		t.Fatal("push must report search_indexed=false when the index write fails")
	}
	failPuts.Store(false)

	got := f.query(t, tok, "goose")
	if got.TotalIndexed != 1 {
		t.Fatalf("unpersisted write counted in the index: total=%d", got.TotalIndexed)
	}
	for _, r := range got.Results {
		if r.ID == "chat_b" {
			t.Fatalf("query served an index write that never persisted: %+v", got.Results)
		}
	}
	got = f.query(t, tok, "duck")
	if len(got.Results) == 0 || got.Results[0].ID != "chat_a" {
		t.Fatalf("persisted entry lost: %+v", got.Results)
	}
}
