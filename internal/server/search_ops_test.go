package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/fnv"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/searchindex"
)

// stubEmbedder produces deterministic bag-of-words hash vectors with
// a tiny synonym table, so "animal" lands near "duck" and "dog" the
// way a real embedding model would, without any network dependency.
type stubEmbedder struct {
	mu        sync.Mutex
	model     string
	failEmbed error
	calls     int
}

func (s *stubEmbedder) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *stubEmbedder) setModel(model string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.model = model
}

func (s *stubEmbedder) setFailEmbed(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failEmbed = err
}

var stubSynonyms = map[string]string{
	"duck": "animal",
	"dog":  "animal",
}

func (s *stubEmbedder) Configured() bool { return true }

func (s *stubEmbedder) Model() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model
}

func (s *stubEmbedder) Embed(_ context.Context, inputs []string) ([][]float32, error) {
	s.mu.Lock()
	s.calls++
	failEmbed := s.failEmbed
	s.mu.Unlock()
	if failEmbed != nil {
		return nil, failEmbed
	}
	out := make([][]float32, len(inputs))
	for i, in := range inputs {
		text := strings.TrimPrefix(strings.TrimPrefix(in, searchDocPrefix), searchQueryPrefix)
		vec := make([]float32, 16)
		for _, tok := range strings.Fields(strings.ToLower(text)) {
			tok = strings.Trim(tok, ".,!?;:")
			if canon, ok := stubSynonyms[tok]; ok {
				tok = canon
			}
			h := fnv.New64a()
			h.Write([]byte(tok))
			seed := h.Sum64()
			for d := range vec {
				seed = seed*6364136223846793005 + 1442695040888963407
				vec[d] += float32(int64(seed>>33)%1000) / 1000
			}
		}
		var norm float64
		for _, v := range vec {
			norm += float64(v) * float64(v)
		}
		if norm > 0 {
			n := float32(math.Sqrt(norm))
			for d := range vec {
				vec[d] /= n
			}
		}
		out[i] = vec
	}
	return out, nil
}

type searchFixture struct {
	*fixture
	searchBk *bucketsStub
	embedder *stubEmbedder
}

func newSearchFixture(t *testing.T) *searchFixture {
	t.Helper()
	f := newFixture(t)
	sbk := newBucketsStub(t)
	emb := &stubEmbedder{model: "test-embed"}
	f.handler.deps.SearchBuckets = buckets.NewClient(sbk.server.URL, testBucketName, nil)
	f.handler.deps.Embedder = emb
	return &searchFixture{fixture: f, searchBk: sbk, embedder: emb}
}

func (f *searchFixture) pushChat(t *testing.T, tok, id, title, content string) PushResponse {
	t.Helper()
	chat := map[string]any{
		"id":    id,
		"title": title,
		"messages": []map[string]any{
			{"role": "user", "content": content},
		},
	}
	plaintext, _ := json.Marshal(chat)
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
	var out PushResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *searchFixture) query(t *testing.T, tok, q string) SearchQueryResponse {
	t.Helper()
	resp, body := f.post("/v1/search/query", SearchQueryRequest{
		Key:   f.userKeyB64,
		Query: q,
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query %q: status %d body %s", q, resp.StatusCode, body)
	}
	var out SearchQueryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPushIndexesChatAndSemanticSearchFinds(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()

	if out := f.pushChat(t, tok, "chat_duck", "Pond visit", "I saw a duck at the pond today"); !out.SearchIndexed {
		t.Fatal("push did not report search_indexed")
	}
	f.pushChat(t, tok, "chat_tax", "Paperwork", "filing my tax return before the deadline")

	if !f.searchBk.has(searchIndexObjectKey) {
		t.Fatal("search index object not stored in search bucket")
	}
	if f.bk.has(searchIndexObjectKey) {
		t.Fatal("search index leaked into the attachments bucket")
	}
	if item, ok := f.searchBk.item(searchIndexObjectKey); !ok || len(item.Value) < 2 || item.Value[0] != 0x1f || item.Value[1] != 0x8b {
		t.Fatal("stored index is not gzip-compressed")
	}

	got := f.query(t, tok, "animal")
	if got.TotalIndexed != 2 {
		t.Fatalf("total_indexed = %d, want 2", got.TotalIndexed)
	}
	if got.NeedsReindex {
		t.Fatal("unexpected needs_reindex")
	}
	if len(got.Results) == 0 || got.Results[0].ID != "chat_duck" {
		t.Fatalf("expected chat_duck first for 'animal', got %+v", got.Results)
	}

	// Lexical path: an exact keyword should surface the tax chat first.
	kw := f.query(t, tok, "tax deadline")
	if len(kw.Results) == 0 || kw.Results[0].ID != "chat_tax" {
		t.Fatalf("expected chat_tax first for 'tax deadline', got %+v", kw.Results)
	}
}

func (f *searchFixture) loadIndex(t *testing.T) *searchindex.Index {
	t.Helper()
	indexKey, err := cryptopkg.DeriveSearchIndexKey(f.userKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.handler.deps.SearchBuckets.Get(context.Background(), f.userSub, searchIndexObjectKey, indexKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := gunzipIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := searchindex.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return ix
}

func TestLongChatIsChunkedAndFindableByLatePassage(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()

	// The duck passage sits past the first chunk boundary; a single
	// truncated embedding would dilute or drop it entirely.
	filler := strings.Repeat("meeting notes budget report quarterly planning ", 70)
	if len(filler) <= searchChunkChars {
		t.Fatalf("filler too short to force chunking: %d", len(filler))
	}
	chat := map[string]any{
		"id":    "chat_long",
		"title": "Weekly sync",
		"messages": []map[string]any{
			{"role": "user", "content": filler},
			{"role": "user", "content": "afterwards we watched a duck at the pond"},
		},
	}
	plaintext, _ := json.Marshal(chat)
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope:          "chat",
		ID:             "chat_long",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IdempotencyKey: "idem-chat_long",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: status %d body %s", resp.StatusCode, body)
	}
	f.pushChat(t, tok, "chat_tax", "Paperwork", "tax return time")

	entry := f.loadIndex(t).Chats["chat_long"]
	if len(entry.Vectors) < 2 {
		t.Fatalf("expected multiple chunk vectors, got %d", len(entry.Vectors))
	}

	got := f.query(t, tok, "animal")
	if len(got.Results) == 0 || got.Results[0].ID != "chat_long" {
		t.Fatalf("late passage not found via semantic chunk: %+v", got.Results)
	}
}

func TestSearchQueryReportsNeedsReindexWithoutIndex(t *testing.T) {
	f := newSearchFixture(t)
	got := f.query(t, f.jwt(), "anything")
	if !got.NeedsReindex || got.TotalIndexed != 0 || len(got.Results) != 0 {
		t.Fatalf("expected empty needs_reindex response, got %+v", got)
	}
	if f.embedder.callCount() != 0 {
		t.Fatal("query on empty index should not call the embedder")
	}
}

func TestDeleteRemovesChatFromIndex(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	resp, body := f.post("/v1/sync/delete", DeleteRequest{
		Scope:          "chat",
		ID:             "chat_duck",
		Key:            f.userKeyB64,
		IdempotencyKey: "idem-del",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: status %d body %s", resp.StatusCode, body)
	}

	got := f.query(t, tok, "duck")
	if got.TotalIndexed != 0 || len(got.Results) != 0 {
		t.Fatalf("expected empty index after delete, got %+v", got)
	}
}

func TestSearchReindexRebuildsIndex(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")
	f.pushChat(t, tok, "chat_dog", "Walk", "walked the dog in the park")
	f.pushChat(t, tok, "chat_tax", "Paperwork", "tax return time")

	// Simulate a lost index (e.g. CEK rotation or bucket wipe).
	if err := f.handler.deps.SearchBuckets.Delete(context.Background(), f.userSub, searchIndexObjectKey); err != nil {
		t.Fatal(err)
	}
	if got := f.query(t, tok, "animal"); !got.NeedsReindex {
		t.Fatal("expected needs_reindex after index loss")
	}

	// No job yet: status reports idle.
	resp, body := f.post("/v1/search/reindex-status", struct{}{}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	var idle SearchReindexStatusResponse
	if err := json.Unmarshal(body, &idle); err != nil {
		t.Fatal(err)
	}
	if idle.Status != string(MigrationJobIdle) {
		t.Fatalf("expected idle status, got %+v", idle)
	}

	req := SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}
	resp, body = f.post("/v1/search/reindex", req, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("kickoff: status %d body %s", resp.StatusCode, body)
	}
	var kicked SearchReindexStatusResponse
	if err := json.Unmarshal(body, &kicked); err != nil {
		t.Fatal(err)
	}
	if kicked.JobID == "" {
		t.Fatal("kickoff did not return a job id")
	}

	// A duplicate kickoff must join the existing job, not stack a
	// second full re-embed.
	resp, body = f.post("/v1/search/reindex", req, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second kickoff: status %d body %s", resp.StatusCode, body)
	}
	var joined SearchReindexStatusResponse
	if err := json.Unmarshal(body, &joined); err != nil {
		t.Fatal(err)
	}
	if joined.JobID != kicked.JobID {
		t.Fatalf("duplicate kickoff started a new job: %s != %s", joined.JobID, kicked.JobID)
	}

	job := f.handler.reindexCoordinator.Status(f.userSub)
	if job == nil {
		t.Fatal("no job tracked after kickoff")
	}
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("reindex job did not finish")
	}

	resp, body = f.post("/v1/search/reindex-status", struct{}{}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after run: %d %s", resp.StatusCode, body)
	}
	var final SearchReindexStatusResponse
	if err := json.Unmarshal(body, &final); err != nil {
		t.Fatal(err)
	}
	if final.Status != string(MigrationJobCompleted) || final.Partial {
		t.Fatalf("unexpected terminal status: %+v", final)
	}
	if final.Indexed != 3 || final.TotalIndexed != 3 {
		t.Fatalf("reindexed %d chats (total %d), want 3", final.Indexed, final.TotalIndexed)
	}

	got := f.query(t, tok, "animal")
	if got.NeedsReindex || got.TotalIndexed != 3 {
		t.Fatalf("unexpected post-reindex state: %+v", got)
	}
	if len(got.Results) < 2 || got.Results[0].ID == "chat_tax" || got.Results[1].ID == "chat_tax" {
		t.Fatalf("expected duck/dog chats to lead for 'animal', got %+v", got.Results)
	}
}

func TestPushSucceedsWhenEmbeddingFails(t *testing.T) {
	f := newSearchFixture(t)
	f.embedder.setFailEmbed(errors.New("embedding backend down"))
	tok := f.jwt()

	out := f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")
	if out.SearchIndexed {
		t.Fatal("push should not report search_indexed when embedding fails")
	}
	if !out.OK {
		t.Fatal("push should still succeed")
	}

	// The lexical-only entry still makes the chat findable by keyword.
	f.embedder.setFailEmbed(nil)
	got := f.query(t, tok, "duck")
	if len(got.Results) != 1 || got.Results[0].ID != "chat_duck" {
		t.Fatalf("expected lexical hit for 'duck', got %+v", got.Results)
	}
}

func TestSearchRoutesReturn503WithoutBackend(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	resp, _ := f.post("/v1/search/query", SearchQueryRequest{Key: f.userKeyB64, Query: "x"}, tok)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("query without backend: status %d, want 503", resp.StatusCode)
	}
	resp, _ = f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("reindex without backend: status %d, want 503", resp.StatusCode)
	}
}

func TestSearchQueryRequiresAuthAndValidInput(t *testing.T) {
	f := newSearchFixture(t)
	resp, _ := f.post("/v1/search/query", SearchQueryRequest{Key: f.userKeyB64, Query: "x"}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated query: status %d, want 401", resp.StatusCode)
	}
	tok := f.jwt()
	resp, _ = f.post("/v1/search/query", SearchQueryRequest{Key: f.userKeyB64, Query: "   "}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty query: status %d, want 400", resp.StatusCode)
	}
	resp, _ = f.post("/v1/search/query", SearchQueryRequest{Key: "not-base64!", Query: "x"}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad key: status %d, want 400", resp.StatusCode)
	}
}
