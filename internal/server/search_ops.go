package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/searchindex"
)

// Chat search. The enclave maintains one encrypted index object per
// user in a dedicated search bucket (via a second buckets sidecar),
// sealed under a key derived from the user's CEK. Chats are indexed
// inline on push: the enclave already holds the plaintext and the
// CEK for the lifetime of the request, embeds the chat text via the
// Tinfoil confidential inference service, and merges the entry into
// the index before the plaintext is zeroed. Queries embed the query
// string the same way and rank the whole index in-enclave.

const (
	// searchIndexObjectKey is the buckets object key for a user's
	// index. The per-user tenant prefix is applied by the buckets
	// client, so a fixed key is unique per user. Version-tagged so a
	// future format change can migrate side by side.
	searchIndexObjectKey = "search-index-v1"

	// searchDocPrefix / searchQueryPrefix are the task-instruction
	// prefixes the nomic-embed-text family requires for asymmetric
	// retrieval; document and query embeddings live in different
	// subspaces and must be tagged accordingly.
	searchDocPrefix   = "search_document: "
	searchQueryPrefix = "search_query: "

	// searchChunkChars is the target size of one embedding chunk.
	// Chunks are cut on message boundaries where possible; ~2000
	// chars is ~500 tokens, small enough that one topic dominates
	// the chunk's vector.
	searchChunkChars = 2000

	// maxSearchTextChars caps how much chat text is tokenized and
	// chunked overall (searchindex.MaxChunksPerChat chunks of
	// searchChunkChars each).
	maxSearchTextChars = searchChunkChars * searchindex.MaxChunksPerChat

	// searchEmbedBatch is how many chunk texts one Embed call
	// carries. Stays under the inference client's batch cap.
	searchEmbedBatch = 32

	maxSearchQueryChars = 1000

	defaultSearchLimit = 20
	maxSearchLimit     = 100

	// reindexPageSize is how many chats one reindex page pulls and
	// embeds. Bounded by the embedder's batch limit.
	reindexPageSize = 16
)

// Embedder is the embedding backend the search feature uses. In
// production it is inference.Client; tests supply a stub.
type Embedder interface {
	Configured() bool
	Model() string
	Embed(ctx context.Context, inputs []string) ([][]float32, error)
}

// searchConfigured reports whether both halves of the search backend
// (the dedicated buckets sidecar and the embedding service) are wired
// up. When false, search routes return 503 and the push/delete hooks
// are no-ops.
func searchConfigured(deps Deps) bool {
	return deps.SearchBuckets != nil && deps.SearchBuckets.Configured() &&
		deps.Embedder != nil && deps.Embedder.Configured()
}

func searchUnavailable() *AppError {
	return &AppError{Status: http.StatusServiceUnavailable, Code: CodeInternal, Message: "search backend not configured"}
}

// searchIndexLocks serializes read-modify-write cycles on one user's
// index object within this process. The buckets sidecar has no CAS,
// so without this two concurrent pushes could each read the same
// index generation and the second write would drop the first entry.
// Readers (queries) take the shared side: cached indices are mutated
// in place by writers, so an unlocked concurrent Search would race.
var searchIndexLocks sync.Map

func lockSearchIndex(user string) func() {
	mu := searchIndexLock(user)
	mu.Lock()
	return mu.Unlock
}

func rlockSearchIndex(user string) func() {
	mu := searchIndexLock(user)
	mu.RLock()
	return mu.RUnlock
}

func searchIndexLock(user string) *sync.RWMutex {
	v, _ := searchIndexLocks.LoadOrStore(user, &sync.RWMutex{})
	return v.(*sync.RWMutex)
}

// maxIndexDecompressedBytes caps the inflated index JSON so a
// corrupted or hostile stored object cannot balloon enclave memory.
// Sized for searchindex.MaxChats entries at the worst-case per-entry
// footprint with ample margin.
const maxIndexDecompressedBytes = 512 << 20

// maxIndexStoredBytes caps the gzipped object read from the sidecar
// before decompression. It is slightly above the decoded cap to allow
// gzip framing overhead while rejecting arbitrarily large bucket
// bodies before they can exhaust memory.
var maxIndexStoredBytes int64 = maxIndexDecompressedBytes + (1 << 20)

// searchLoadState reports how loadSearchIndex obtained its result.
// Missing and unreadable both mean "no usable previous index" (the
// caller gets a fresh empty one), but they differ in what they imply
// about coverage: missing may simply be a user who never had an
// index, while unreadable means an index existed and its contents
// were lost (wrong key, corruption, model change), so anything
// built on top of it is known-incomplete.
type searchLoadState int

const (
	searchLoadOK searchLoadState = iota
	searchLoadMissing
	searchLoadUnreadable
)

// loadSearchIndex returns the user's decoded index, from the
// in-memory cache when possible and from the sidecar otherwise. A
// missing object, an index sealed under a different key, an unknown
// format, or a model change all yield a fresh empty index with a
// degraded load state so callers can surface "rebuild me" to the
// client instead of failing; those degraded results are never cached.
// Callers must hold the per-user lock (shared for reads, exclusive
// for mutation) since cached indices are shared across requests.
func loadSearchIndex(ctx context.Context, deps Deps, owner string, indexKey []byte) (*searchindex.Index, searchLoadState, error) {
	model := deps.Embedder.Model()
	keyHash := sha256.Sum256(indexKey)
	if ix, ok := deps.SearchCache.get(owner, keyHash); ok {
		if ix.Compatible(model) {
			return ix, searchLoadOK, nil
		}
		deps.SearchCache.drop(owner)
	}
	raw, err := deps.SearchBuckets.GetLimited(ctx, owner, searchIndexObjectKey, indexKey, maxIndexStoredBytes)
	switch {
	case errors.Is(err, buckets.ErrNotFound):
		return searchindex.New(model), searchLoadMissing, nil
	case errors.Is(err, buckets.ErrForbidden), errors.Is(err, buckets.ErrTooLarge):
		return searchindex.New(model), searchLoadUnreadable, nil
	case err != nil:
		return nil, searchLoadUnreadable, err
	}
	encoded, err := gunzipIndex(raw)
	if err != nil {
		return searchindex.New(model), searchLoadUnreadable, nil
	}
	ix, err := searchindex.Decode(encoded)
	if err != nil {
		return searchindex.New(model), searchLoadUnreadable, nil
	}
	if !ix.Compatible(model) {
		return searchindex.New(model), searchLoadUnreadable, nil
	}
	deps.SearchCache.put(owner, keyHash, ix, len(encoded))
	return ix, searchLoadOK, nil
}

func searchIndexNeedsReindex(ctx context.Context, deps Deps, owner, key string) (bool, error) {
	cek, err := decodeKey(key)
	if err != nil {
		return false, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)
	indexKey, err := cryptopkg.DeriveSearchIndexKey(cek)
	if err != nil {
		return false, err
	}
	defer cryptopkg.Zero(indexKey)

	runlock := rlockSearchIndex(owner)
	defer runlock()
	deps.SearchCache.drop(owner)
	ix, state, err := loadSearchIndex(ctx, deps, owner, indexKey)
	if err != nil {
		return false, err
	}
	return state != searchLoadOK || ix.Incomplete, nil
}

// searchEntryTime parses an entry's UpdatedAt for ordering decisions.
// Unparseable or absent timestamps sort as oldest, so legacy entries
// lose to anything freshly written.
func searchEntryTime(e searchindex.Entry) time.Time {
	t, err := time.Parse(time.RFC3339Nano, e.UpdatedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// searchEtagGeneration parses a controlplane CAS token as the blob's
// version counter. The controlplane issues per-blob incrementing
// numeric etags; ok is false for any other shape so callers can fall
// back to timestamp ordering rather than misorder opaque tokens.
func searchEtagGeneration(etag string) (int64, bool) {
	g, err := strconv.ParseInt(etag, 10, 64)
	return g, err == nil
}

// searchEntrySupersedes reports whether the existing index entry is a
// strictly newer blob generation than a candidate write carrying
// etag/committedAt. Generation numbers are the durable order (they
// come from the CAS chain, immune to response reordering); local
// commit-boundary timestamps are the fallback when either token is
// not numeric.
func searchEntrySupersedes(existing searchindex.Entry, etag string, committedAt time.Time) bool {
	if eg, ok := searchEtagGeneration(existing.ETag); ok {
		if cg, ok := searchEtagGeneration(etag); ok {
			return eg > cg
		}
	}
	return searchEntryTime(existing).After(committedAt)
}

type searchSnapshotState int

const (
	searchSnapshotCurrent searchSnapshotState = iota
	searchSnapshotStale
	searchSnapshotDeleted
)

func searchChatSnapshotState(ctx context.Context, deps Deps, sess Session, chatID, etag string) (searchSnapshotState, error) {
	scope := string(envelope.ScopeChat)
	meta, err := deps.Controlplane.HeadBlob(ctx, scope, chatID, sess.RawJWT, sess.Claims.Subject)
	if err == nil {
		if meta.ETag != etag {
			return searchSnapshotStale, nil
		}
		return searchSnapshotCurrent, nil
	}
	// This check runs under the search-index lock, so HEAD keeps the
	// critical section from downloading whole ciphertexts. A failed
	// HEAD is ambiguous, though: a controlplane that does not route
	// HEAD answers 404/405 for live blobs, and treating that as
	// deleted would silently drop the chat from the index. Confirm
	// with a full GET before acting on the miss.
	blob, gerr := deps.Controlplane.GetBlob(ctx, scope, chatID, sess.RawJWT, sess.Claims.Subject)
	if gerr != nil {
		var cpe *controlplane.Error
		if errors.As(gerr, &cpe) && cpe.StatusCode == http.StatusNotFound {
			return searchSnapshotDeleted, nil
		}
		return searchSnapshotStale, gerr
	}
	if blob.ETag != etag {
		return searchSnapshotStale, nil
	}
	return searchSnapshotCurrent, nil
}

func missingSearchIndexNeedsReindex(ctx context.Context, deps Deps, sess Session, chatID string) bool {
	list, err := deps.Controlplane.ListStatus(ctx, string(envelope.ScopeChat), "", 2, sess.RawJWT, sess.Claims.Subject, "", "")
	if err != nil {
		deps.logError("search coverage check failed: user=%s id=%s err=%v", sess.Claims.Subject, chatID, err)
		return true
	}
	if list.NextCursor != "" || len(list.Updates) != 1 {
		return true
	}
	return list.Updates[0].ID != chatID
}

type searchWriteHook func(ctx context.Context, ix *searchindex.Index, state searchLoadState) (cont bool, mutated bool, err error)

// saveSearchIndex gzips the index JSON before handing it to the
// sidecar: token text compresses well, and compression must happen
// before the sidecar encrypts since ciphertext does not compress.
// Writes through to the cache on success; a failed write drops the
// cache entry so the next operation reloads the last durable state
// instead of serving mutations that were never persisted.
func saveSearchIndex(ctx context.Context, deps Deps, owner string, indexKey []byte, ix *searchindex.Index) error {
	encoded, err := ix.Encode()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(encoded); err != nil {
		_ = zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := deps.SearchBuckets.Put(ctx, owner, searchIndexObjectKey, buf.Bytes(), indexKey); err != nil {
		deps.SearchCache.drop(owner)
		return err
	}
	deps.SearchCache.put(owner, sha256.Sum256(indexKey), ix, len(encoded))
	return nil
}

func gunzipIndex(compressed []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxIndexDecompressedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxIndexDecompressedBytes {
		return nil, errors.New("search index exceeds decompressed size limit")
	}
	return out, nil
}

// chatSearchDoc is the subset of the StoredChat JSON shape the
// indexer reads. Unknown fields are ignored so client-side schema
// additions never break indexing.
type chatSearchDoc struct {
	Title    string `json:"title"`
	Messages []struct {
		Content string `json:"content"`
	} `json:"messages"`
}

// chatSearchChunks extracts the indexable text from a chat blob as
// embedding-sized chunks: the title plus message bodies, packed into
// chunks of ~searchChunkChars cut on message boundaries where
// possible (an oversized single message is split mid-message). Total
// coverage is capped at MaxChunksPerChat chunks. Returns nil when the
// blob is not chat-shaped JSON or has no text.
func chatSearchChunks(plaintext []byte) []string {
	var doc chatSearchDoc
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		return nil
	}
	parts := make([]string, 0, len(doc.Messages)+1)
	if title := strings.TrimSpace(doc.Title); title != "" {
		parts = append(parts, title)
	}
	for _, m := range doc.Messages {
		if content := strings.TrimSpace(m.Content); content != "" {
			parts = append(parts, content)
		}
	}
	var chunks []string
	var cur strings.Builder
	flush := func() bool {
		if cur.Len() == 0 {
			return true
		}
		chunks = append(chunks, cur.String())
		cur.Reset()
		return len(chunks) < searchindex.MaxChunksPerChat
	}
	for _, part := range parts {
		for len(part) > 0 {
			if cur.Len() > 0 && len(part)+1 <= searchChunkChars-cur.Len() {
				cur.WriteByte('\n')
				cur.WriteString(part)
				break
			}
			if cur.Len() > 0 && len(part) <= searchChunkChars {
				if !flush() {
					return chunks
				}
				continue
			}
			available := searchChunkChars - cur.Len()
			if cur.Len() > 0 {
				available--
			}
			piece := truncateUTF8(part, available)
			if piece == "" {
				// Less room left than the next rune needs; close the
				// chunk and retry with a fresh one.
				if !flush() {
					return chunks
				}
				continue
			}
			if cur.Len() > 0 {
				cur.WriteByte('\n')
			}
			cur.WriteString(piece)
			part = part[len(piece):]
			if len(part) > 0 && !flush() {
				return chunks
			}
		}
	}
	flush()
	return chunks
}

// embedChunks prefixes every chunk with the model's task instruction
// and embeds them in batches sized for the inference client.
func embedChunks(ctx context.Context, embedder Embedder, prefix string, chunks []string) ([][]float32, error) {
	out := make([][]float32, 0, len(chunks))
	for start := 0; start < len(chunks); start += searchEmbedBatch {
		end := start + searchEmbedBatch
		if end > len(chunks) {
			end = len(chunks)
		}
		batch := make([]string, 0, end-start)
		for _, c := range chunks[start:end] {
			batch = append(batch, prefix+c)
		}
		vecs, err := embedder.Embed(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, vecs...)
	}
	return out, nil
}

func quantizeAll(vecs [][]float32) []searchindex.Vector {
	if len(vecs) == 0 {
		return nil
	}
	out := make([]searchindex.Vector, len(vecs))
	for i, v := range vecs {
		out[i] = searchindex.Quantize(v)
	}
	return out
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}

// indexChatForSearch embeds one chat and merges it into the user's
// index. committedAt is captured at the blob commit boundary
// (immediately after the CAS write returned) and orders this entry
// against concurrent writes for the same chat, well before the
// embedding round trip can reshuffle completion order.
func indexChatForSearch(ctx context.Context, deps Deps, owner string, cek []byte, chatID string, plaintext []byte, etag string, committedAt time.Time) error {
	return indexChatForSearchWithHook(ctx, deps, owner, cek, chatID, plaintext, etag, committedAt, nil)
}

func indexCurrentChatForSearch(ctx context.Context, deps Deps, sess Session, cek []byte, chatID string, plaintext []byte, etag string, committedAt time.Time) error {
	hook := func(ctx context.Context, ix *searchindex.Index, state searchLoadState) (bool, bool, error) {
		snapshotState, err := searchChatSnapshotState(ctx, deps, sess, chatID, etag)
		if err != nil {
			return false, false, err
		}
		switch snapshotState {
		case searchSnapshotCurrent:
			mutated := false
			if state == searchLoadMissing && missingSearchIndexNeedsReindex(ctx, deps, sess, chatID) {
				ix.Incomplete = true
				mutated = true
			}
			return true, mutated, nil
		case searchSnapshotDeleted:
			mutated := false
			if _, ok := ix.Chats[chatID]; ok {
				ix.Remove(chatID)
				mutated = true
			}
			return false, mutated, nil
		default:
			return false, false, nil
		}
	}
	return indexChatForSearchWithHook(ctx, deps, sess.Claims.Subject, cek, chatID, plaintext, etag, committedAt, hook)
}

func indexChatForSearchWithHook(ctx context.Context, deps Deps, owner string, cek []byte, chatID string, plaintext []byte, etag string, committedAt time.Time, hook searchWriteHook) error {
	indexKey, err := cryptopkg.DeriveSearchIndexKey(cek)
	if err != nil {
		return err
	}
	defer cryptopkg.Zero(indexKey)

	chunks := chatSearchChunks(plaintext)
	entry := searchindex.Entry{
		ETag:      etag,
		UpdatedAt: committedAt.UTC().Format(time.RFC3339Nano),
	}
	tokens := searchindex.Tokenize(strings.Join(chunks, "\n"))
	var embedErr error
	if len(chunks) > 0 {
		vecs, err := embedChunks(ctx, deps.Embedder, searchDocPrefix, chunks)
		if err != nil {
			// Keep the lexical entry so the chat is still findable by
			// keyword; surface the error so the caller logs the
			// degraded state.
			embedErr = err
		} else {
			entry.Vectors = quantizeAll(vecs)
		}
	}

	unlock := lockSearchIndex(owner)
	defer unlock()
	ix, state, err := loadSearchIndex(ctx, deps, owner, indexKey)
	if err != nil {
		return err
	}
	if hook != nil {
		cont, mutated, err := hook(ctx, ix, state)
		if err != nil {
			return err
		}
		if !cont {
			if mutated {
				return saveSearchIndex(ctx, deps, owner, indexKey, ix)
			}
			return nil
		}
	}
	// A slower push must not clobber the entry a newer push (or a
	// rebuild) already wrote for this chat. Ordering comes from the
	// blob's CAS generation whenever the etags are numeric; the
	// commit-boundary timestamp is only the fallback for opaque
	// tokens, valid because this process is the sole index writer and
	// two generations of the same chat commit at least a client round
	// trip apart.
	if existing, ok := ix.Chats[chatID]; ok && searchEntrySupersedes(existing, etag, committedAt) {
		deps.logInfo("push search index skipped stale write: user=%s id=%s", owner, chatID)
		return nil
	}
	// Building on top of an unreadable index means every previously
	// indexed chat is absent from the new generation. Persist that so
	// queries keep reporting needs_reindex instead of the first push
	// after an unreadable load masking the lost coverage.
	if state == searchLoadUnreadable {
		ix.Incomplete = true
	}
	if err := ix.Upsert(chatID, entry, tokens); err != nil {
		return err
	}
	if err := saveSearchIndex(ctx, deps, owner, indexKey, ix); err != nil {
		return err
	}
	if embedErr != nil {
		return fmt.Errorf("indexed lexical-only, embedding failed: %w", embedErr)
	}
	return nil
}

// removeChatFromSearch drops one chat from the user's index after a
// successful delete. Best-effort: a missing or unreadable index means
// there is nothing to remove.
func removeChatFromSearch(ctx context.Context, deps Deps, owner string, cek []byte, chatID string) error {
	indexKey, err := cryptopkg.DeriveSearchIndexKey(cek)
	if err != nil {
		return err
	}
	defer cryptopkg.Zero(indexKey)

	unlock := lockSearchIndex(owner)
	defer unlock()
	ix, state, err := loadSearchIndex(ctx, deps, owner, indexKey)
	if err != nil {
		return err
	}
	if state != searchLoadOK {
		return nil
	}
	if _, exists := ix.Chats[chatID]; !exists {
		return nil
	}
	ix.Remove(chatID)
	return saveSearchIndex(ctx, deps, owner, indexKey, ix)
}

// dropChatFromSearch is the best-effort delete-side hook: a stale
// entry only means a deleted chat can still surface in results until
// the next reindex, so failures are logged and swallowed.
func dropChatFromSearch(ctx context.Context, deps Deps, sess Session, scope envelope.Scope, chatID string, cek []byte) {
	if scope != envelope.ScopeChat || !searchConfigured(deps) {
		return
	}
	if err := removeChatFromSearch(ctx, deps, sess.Claims.Subject, cek, chatID); err != nil {
		deps.logError("delete search index cleanup failed: user=%s id=%s err=%v",
			sess.Claims.Subject, chatID, err)
	}
}

// SearchQuery embeds the query, loads the caller's index, and returns
// the top-ranked chat ids. Results carry ids and scores only; the
// client already syncs chat contents through pull.
func SearchQuery(ctx context.Context, deps Deps, sess Session, req SearchQueryRequest) (*SearchQueryResponse, error) {
	if !searchConfigured(deps) {
		return nil, searchUnavailable()
	}
	query := strings.TrimSpace(req.Query)
	if query == "" {
		return nil, badRequest("query is required")
	}
	if len(query) > maxSearchQueryChars {
		return nil, badRequest("query is too long")
	}
	if req.Limit <= 0 || req.Limit > maxSearchLimit {
		req.Limit = defaultSearchLimit
	}
	cek, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)
	indexKey, err := cryptopkg.DeriveSearchIndexKey(cek)
	if err != nil {
		return nil, err
	}
	defer cryptopkg.Zero(indexKey)

	runlock := rlockSearchIndex(sess.Claims.Subject)
	ix, state, err := loadSearchIndex(ctx, deps, sess.Claims.Subject, indexKey)
	if err != nil {
		runlock()
		deps.logError("search query index load failed: user=%s err=%v", sess.Claims.Subject, err)
		return nil, err
	}
	if len(ix.Chats) == 0 {
		resp := &SearchQueryResponse{
			Results:      []SearchQueryResult{},
			NeedsReindex: state != searchLoadOK || ix.Incomplete,
		}
		runlock()
		return resp, nil
	}
	runlock()

	// Embed outside the lock: it is a network round trip and must not
	// serialize against this user's pushes.
	vecs, err := deps.Embedder.Embed(ctx, []string{searchQueryPrefix + query})
	if err != nil {
		deps.logError("search query embed failed: user=%s err=%v", sess.Claims.Subject, err)
		return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "embedding service failed"}
	}

	// Reload for the search itself instead of reusing the pointer
	// from before the embedding gap: a stale pointer could observe
	// (and serve) an in-place mutation whose persist failed, whereas
	// a fresh load is a cache hit on the hot path and reflects only
	// persisted state.
	runlock = rlockSearchIndex(sess.Claims.Subject)
	ix, state, err = loadSearchIndex(ctx, deps, sess.Claims.Subject, indexKey)
	if err != nil {
		runlock()
		deps.logError("search query index load failed: user=%s err=%v", sess.Claims.Subject, err)
		return nil, err
	}
	resp := &SearchQueryResponse{
		Results:      []SearchQueryResult{},
		TotalIndexed: len(ix.Chats),
		NeedsReindex: state != searchLoadOK || ix.Incomplete,
	}
	results := ix.Search(vecs[0], searchindex.Tokenize(query), req.Limit)
	runlock()
	for _, r := range results {
		resp.Results = append(resp.Results, SearchQueryResult{ID: r.ID, Score: r.Score})
	}
	deps.logInfo("search query ok: user=%s indexed=%d results=%d",
		sess.Claims.Subject, resp.TotalIndexed, len(resp.Results))
	return resp, nil
}

// searchReindexPageResult reports one page of a rebuild. NextCursor
// feeds the next page; Done means the chat listing is drained.
type searchReindexPageResult struct {
	Indexed      int
	Failed       int
	NextCursor   string
	Done         bool
	TotalIndexed int
}

// searchReindexPage rebuilds one page of the caller's index from the
// stored chat blobs. An empty cursor starts a rebuild, dropping index
// entries from before startedAt (which also flushes entries for
// since-deleted chats) while preserving entries that inline pushes
// wrote after the job began. Driven by the reindex job runner.
func searchReindexPage(ctx context.Context, deps Deps, sess Session, keys []PullKey, cursor string, startedAt time.Time) (*searchReindexPageResult, error) {
	cek, err := decodeKey(keys[0].Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)
	indexKey, err := cryptopkg.DeriveSearchIndexKey(cek)
	if err != nil {
		return nil, err
	}
	defer cryptopkg.Zero(indexKey)

	pull, err := Pull(ctx, deps, sess, PullRequest{
		Scope:  string(envelope.ScopeChat),
		All:    true,
		Cursor: cursor,
		Limit:  reindexPageSize,
		Keys:   keys,
	})
	if err != nil {
		return nil, err
	}

	type pending struct {
		id     string
		etag   string
		chunks []string
	}
	var page []pending
	failed := 0
	var texts []string
	for _, item := range pull.Items {
		if !item.OK {
			failed++
			continue
		}
		plaintext, err := base64.StdEncoding.DecodeString(item.Plaintext)
		if err != nil {
			failed++
			continue
		}
		chunks := chatSearchChunks(plaintext)
		cryptopkg.Zero(plaintext)
		page = append(page, pending{id: item.ID, etag: item.ETag, chunks: chunks})
		texts = append(texts, chunks...)
	}

	var vectors [][]float32
	if len(texts) > 0 {
		vectors, err = embedChunks(ctx, deps.Embedder, searchDocPrefix, texts)
		if err != nil {
			deps.logError("search reindex embed failed: user=%s err=%v", sess.Claims.Subject, err)
			return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "embedding service failed"}
		}
	}

	unlock := lockSearchIndex(sess.Claims.Subject)
	defer unlock()
	ix, _, err := loadSearchIndex(ctx, deps, sess.Claims.Subject, indexKey)
	if err != nil {
		return nil, err
	}
	if cursor == "" {
		// Fresh rebuild: flush every entry from before the job
		// started (deleted chats, stale generations) but keep entries
		// written since. An inline push that raced the first page's
		// pull+embed window would otherwise be silently dropped, and
		// its chat may sort into a listing page this rebuild has
		// already drained. Degraded loads (wrong key, corruption,
		// model change) yield a fresh empty index here, which prunes
		// to the same clean slate the old start-from-empty gave.
		var stale []string
		for id, e := range ix.Chats {
			if searchEntryTime(e).Before(startedAt) {
				stale = append(stale, id)
			}
		}
		for _, id := range stale {
			ix.Remove(id)
		}
	}
	indexed := 0
	vecIdx := 0
	for _, p := range page {
		vecs := vectors[vecIdx : vecIdx+len(p.chunks)]
		vecIdx += len(p.chunks)
		snapshotState, err := searchChatSnapshotState(ctx, deps, sess, p.id, p.etag)
		if err != nil {
			return nil, err
		}
		if snapshotState == searchSnapshotDeleted {
			ix.Remove(p.id)
			continue
		}
		if snapshotState == searchSnapshotStale {
			if existing, ok := ix.Chats[p.id]; ok && searchEntrySupersedes(existing, p.etag, startedAt) {
				indexed++
			}
			continue
		}
		// Keep an existing entry that is a newer blob generation than
		// this job's pull snapshot (an inline push landed mid-job);
		// the timestamp fallback keeps anything written since the job
		// started.
		if existing, ok := ix.Chats[p.id]; ok && searchEntrySupersedes(existing, p.etag, startedAt) {
			indexed++
			continue
		}
		entry := searchindex.Entry{
			ETag:      p.etag,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Vectors:   quantizeAll(vecs),
		}
		if err := ix.Upsert(p.id, entry, searchindex.Tokenize(strings.Join(p.chunks, "\n"))); err != nil {
			failed++
			continue
		}
		indexed++
	}
	// The index is complete only once the listing is drained; until
	// then (and after a budget-truncated run) queries must keep
	// steering the client back to reindex. Per-chat failures
	// deliberately do not keep the flag set: they are permanent with
	// respect to the supplied key set (undecryptable or corrupt
	// blobs), so advertising needs_reindex for them would trap the
	// client in a rebuild loop that re-embeds the whole corpus each
	// round without ever converging. The job status reports the
	// failed count instead.
	ix.Incomplete = pull.NextCursor != ""
	if err := saveSearchIndex(ctx, deps, sess.Claims.Subject, indexKey, ix); err != nil {
		return nil, err
	}
	resp := &searchReindexPageResult{
		Indexed:      indexed,
		Failed:       failed,
		NextCursor:   pull.NextCursor,
		Done:         pull.NextCursor == "",
		TotalIndexed: len(ix.Chats),
	}
	deps.logInfo("search reindex page ok: user=%s indexed=%d failed=%d done=%t total=%d",
		sess.Claims.Subject, indexed, failed, resp.Done, resp.TotalIndexed)
	return resp, nil
}
