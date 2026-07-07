package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/searchindex"
)

func chatJSON(t *testing.T, id, title string, contents ...string) []byte {
	t.Helper()
	msgs := make([]map[string]any, 0, len(contents))
	for _, c := range contents {
		msgs = append(msgs, map[string]any{"role": "user", "content": c})
	}
	out, err := json.Marshal(map[string]any{"id": id, "title": title, "messages": msgs})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestChatSearchChunksEdgeCases(t *testing.T) {
	if got := chatSearchChunks([]byte("not json")); got != nil {
		t.Fatalf("non-JSON blob produced chunks: %v", got)
	}
	if got := chatSearchChunks([]byte(`{"id":"x"}`)); got != nil {
		t.Fatalf("empty chat produced chunks: %v", got)
	}
	if got := chatSearchChunks(chatJSON(t, "x", "", "   ", "\n\t")); got != nil {
		t.Fatalf("whitespace-only content produced chunks: %v", got)
	}
	if got := chatSearchChunks(chatJSON(t, "x", "Title only")); len(got) != 1 || got[0] != "Title only" {
		t.Fatalf("title-only chat: %v", got)
	}

	// One oversized message must be split mid-message with no text
	// lost and no chunk over the target size.
	big := strings.Repeat("a", searchChunkChars*2+500)
	chunks := chatSearchChunks(chatJSON(t, "x", "", big))
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > searchChunkChars {
			t.Fatalf("chunk %d exceeds target: %d bytes", i, len(c))
		}
	}
	if strings.Join(chunks, "") != big {
		t.Fatal("splitting an oversized message lost text")
	}

	// Multibyte runes must never be split across a chunk boundary.
	euros := strings.Repeat("\u20ac", searchChunkChars) // 3 bytes each
	uniChunks := chatSearchChunks(chatJSON(t, "x", "", euros))
	for i, c := range uniChunks {
		if !utf8.ValidString(c) {
			t.Fatalf("chunk %d contains a split rune", i)
		}
	}
	if strings.Join(uniChunks, "") != euros {
		t.Fatal("multibyte splitting lost text")
	}

	// Total coverage is capped at MaxChunksPerChat.
	var contents []string
	for i := 0; i < 30; i++ {
		contents = append(contents, strings.Repeat("b", searchChunkChars))
	}
	capped := chatSearchChunks(chatJSON(t, "x", "", contents...))
	if len(capped) > searchindex.MaxChunksPerChat {
		t.Fatalf("chunk cap exceeded: %d", len(capped))
	}
}

func TestTruncateUTF8(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"h\u00e9llo", 2, "h"}, // cutting into the 2-byte é backs off
		{"h\u00e9llo", 3, "h\u00e9"},
		{"\u20ac\u20ac", 4, "\u20ac"}, // 3-byte runes
		{"\u20ac", 2, ""},
	}
	for _, c := range cases {
		if got := truncateUTF8(c.in, c.n); got != c.want {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
		if !utf8.ValidString(truncateUTF8(c.in, c.n)) {
			t.Errorf("truncateUTF8(%q, %d) produced invalid UTF-8", c.in, c.n)
		}
	}
}

// TestConcurrentPushesAllIndexed drives parallel pushes through the
// real HTTP stack: the per-user index lock must serialize the
// read-modify-write cycles so no entry is lost to a stale overwrite.
func TestConcurrentPushesAllIndexed(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	const n = 12

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("chat_%d", i)
			plaintext := chatJSON(t, id, "Note", fmt.Sprintf("unique token uniq%d here", i))
			body, _ := json.Marshal(PushRequest{
				Scope:          "chat",
				ID:             id,
				Key:            f.userKeyB64,
				Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
				IdempotencyKey: "idem-" + id,
			})
			req, _ := http.NewRequest(http.MethodPost, f.server.URL+"/v1/sync/push", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("push %s: status %d", id, resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	ix := f.loadIndex(t)
	if len(ix.Chats) != n {
		t.Fatalf("concurrent pushes lost entries: %d of %d indexed", len(ix.Chats), n)
	}
	for i := 0; i < n; i++ {
		got := f.query(t, tok, fmt.Sprintf("uniq%d", i))
		if len(got.Results) == 0 || got.Results[0].ID != fmt.Sprintf("chat_%d", i) {
			t.Fatalf("chat_%d not findable after concurrent push: %+v", i, got.Results)
		}
	}
}

// TestReindexUpdateReplacesEntry exercises the update path directly:
// re-indexing the same chat id must supersede the old tokens, not
// accumulate them.
func TestReindexUpdateReplacesEntry(t *testing.T) {
	f := newSearchFixture(t)
	ctx := context.Background()
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_a", chatJSON(t, "chat_a", "", "a duck on the pond"), "1"); err != nil {
		t.Fatal(err)
	}
	if err := indexChatForSearch(ctx, f.handler.deps, f.userSub, f.userKey, "chat_a", chatJSON(t, "chat_a", "", "a goose on the lake"), "2"); err != nil {
		t.Fatal(err)
	}
	tok := f.jwt()
	if got := f.query(t, tok, "goose"); len(got.Results) != 1 || got.Results[0].ID != "chat_a" {
		t.Fatalf("updated content not findable: %+v", got.Results)
	}
	if got := f.query(t, tok, "goose"); got.TotalIndexed != 1 {
		t.Fatalf("update duplicated the entry: total=%d", got.TotalIndexed)
	}
	// The semantic tier ranks every chat by nearest vector, so the
	// stale-token check must interrogate the lexical tier alone.
	ix := f.loadIndex(t)
	if got := ix.Search(nil, []string{"duck"}, 5); len(got) != 0 {
		t.Fatalf("stale token still lexically findable: %+v", got)
	}
	if got := ix.Search(nil, []string{"goose"}, 5); len(got) != 1 || got[0].ID != "chat_a" {
		t.Fatalf("new token not lexically findable: %+v", got)
	}
}

func TestQueryWithWrongKeyReportsNeedsReindex(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	otherKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	resp, body := f.post("/v1/search/query", SearchQueryRequest{Key: otherKey, Query: "duck"}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query: status %d body %s", resp.StatusCode, body)
	}
	var out SearchQueryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !out.NeedsReindex || len(out.Results) != 0 {
		t.Fatalf("wrong key must yield needs_reindex and no results: %+v", out)
	}
}

func TestQueryAfterModelChangeReportsNeedsReindex(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	f.embedder.setModel("test-embed-v2")
	got := f.query(t, tok, "duck")
	if !got.NeedsReindex || got.TotalIndexed != 0 {
		t.Fatalf("model change must invalidate the index: %+v", got)
	}
}

// TestCorruptedIndexObjectsTriggerReindex overwrites the stored
// object with every corruption class and verifies each degrades to
// needs_reindex instead of an error (or worse, a crash).
func TestCorruptedIndexObjectsTriggerReindex(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	indexKey, err := cryptopkg.DeriveSearchIndexKey(f.userKey)
	if err != nil {
		t.Fatal(err)
	}
	gz := func(s string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte(s))
		zw.Close()
		return buf.Bytes()
	}
	corruptions := map[string][]byte{
		"not gzip":               []byte("garbage bytes"),
		"gzip of non-JSON":       gz("not json at all"),
		"gzip of wrong version":  gz(`{"version":99,"chats":{}}`),
		"gzip of hostile slots":  gz(`{"version":1,"slots":["a"],"chats":{"a":{"slot":9}},"postings":{}}`),
		"gzip of truncated json": gz(`{"version":1,"chats":{`),
	}
	for name, blob := range corruptions {
		if err := f.handler.deps.SearchBuckets.Put(context.Background(), f.userSub, searchIndexObjectKey, blob, indexKey); err != nil {
			t.Fatalf("%s: seed corruption: %v", name, err)
		}
		// Out-of-band corruption is invisible while the cache is warm;
		// drop it to model hitting the poisoned object cold.
		f.handler.deps.SearchCache.drop(f.userSub)
		got := f.query(t, tok, "duck")
		if !got.NeedsReindex {
			t.Fatalf("%s: expected needs_reindex", name)
		}
		if len(got.Results) != 0 || got.TotalIndexed != 0 {
			t.Fatalf("%s: corrupted index served results: %+v", name, got)
		}
	}
}

func TestQueryEmbedFailureReturns502(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	f.embedder.setFailEmbed(errors.New("inference down"))
	resp, body := f.post("/v1/search/query", SearchQueryRequest{Key: f.userKeyB64, Query: "duck"}, tok)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 when embedding fails, got %d %s", resp.StatusCode, body)
	}
}

// TestPushSucceedsWhenSearchBucketDown kills the search sidecar
// entirely: chat saving must be unaffected, only search_indexed flips.
func TestPushSucceedsWhenSearchBucketDown(t *testing.T) {
	f := newSearchFixture(t)
	f.searchBk.server.Close()
	tok := f.jwt()

	out := f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")
	if !out.OK {
		t.Fatal("push failed when search bucket was down")
	}
	if out.SearchIndexed {
		t.Fatal("push claimed search_indexed with the bucket down")
	}
}

func TestDeleteChatWhenIndexObjectMissing(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	if err := f.handler.deps.SearchBuckets.Delete(context.Background(), f.userSub, searchIndexObjectKey); err != nil {
		t.Fatal(err)
	}
	resp, body := f.post("/v1/sync/delete", DeleteRequest{
		Scope:          "chat",
		ID:             "chat_duck",
		Key:            f.userKeyB64,
		IdempotencyKey: "idem-del-noindex",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete with missing index: status %d body %s", resp.StatusCode, body)
	}
}

func TestQueryLimitOutOfRangeIsClamped(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	for _, limit := range []int{-3, 0, maxSearchLimit + 1000} {
		resp, body := f.post("/v1/search/query", SearchQueryRequest{Key: f.userKeyB64, Query: "duck", Limit: limit}, tok)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("limit %d: status %d body %s", limit, resp.StatusCode, body)
		}
		var out SearchQueryResponse
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Results) > maxSearchLimit {
			t.Fatalf("limit %d: %d results exceeds cap", limit, len(out.Results))
		}
	}
}

func TestReindexJobFailsWhenEmbeddingDown(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	f.embedder.setFailEmbed(errors.New("inference down"))
	resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("kickoff: status %d body %s", resp.StatusCode, body)
	}
	job := f.handler.reindexCoordinator.Status(f.userSub)
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("job did not finish")
	}
	status := job.statusResponse()
	if status.Status != string(MigrationJobFailed) || status.Error == "" {
		t.Fatalf("expected failed status with error, got %+v", status)
	}
}

func TestReindexJobPartialWhenBudgetExhausted(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	f.handler.reindexCoordinator.budget = -time.Second
	resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("kickoff: status %d body %s", resp.StatusCode, body)
	}
	job := f.handler.reindexCoordinator.Status(f.userSub)
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("job did not finish")
	}
	status := job.statusResponse()
	if status.Status != string(MigrationJobCompleted) || !status.Partial {
		t.Fatalf("expected completed+partial on exhausted budget, got %+v", status)
	}
	if status.Indexed != 0 {
		t.Fatalf("expired budget should index nothing, got %d", status.Indexed)
	}
}

func TestReindexKickoffValidation(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()

	resp, _ := f.post("/v1/search/reindex", SearchReindexRequest{}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty keys: status %d, want 400", resp.StatusCode)
	}
	resp, _ = f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: "!!not-base64!!"}}}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed key: status %d, want 400", resp.StatusCode)
	}
	if job := f.handler.reindexCoordinator.Status(f.userSub); job != nil {
		t.Fatal("validation failure leaked a coordinator job")
	}
	resp, _ = f.post("/v1/search/reindex-status", struct{}{}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status poll: status %d, want 401", resp.StatusCode)
	}
}

func TestReindexJobReapedAfterRetention(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	f.handler.reindexCoordinator.retention = 0
	resp, body := f.post("/v1/search/reindex", SearchReindexRequest{Keys: []PullKey{{Key: f.userKeyB64}}}, tok)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("kickoff: status %d body %s", resp.StatusCode, body)
	}
	job := f.handler.reindexCoordinator.Status(f.userSub)
	select {
	case <-job.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("job did not finish")
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.handler.reindexCoordinator.Status(f.userSub) != nil {
		if time.Now().After(deadline) {
			t.Fatal("finished job was never reaped")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
