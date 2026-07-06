package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
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

	// maxSearchTextChars caps how much chat text is embedded and
	// tokenized. Sized to stay inside the embedding model's 8192-token
	// context with margin.
	maxSearchTextChars = 24000

	maxSearchQueryChars = 1000

	defaultSearchLimit = 20
	maxSearchLimit     = 100

	// defaultReindexPageSize is how many chats one reindex call pulls
	// and embeds. Bounded by the embedder's batch limit.
	defaultReindexPageSize = 16
	maxReindexPageSize     = 64

	// SearchReindexRequestTimeout gives one reindex page room for the
	// controlplane pulls plus a batch embedding round trip.
	SearchReindexRequestTimeout = 2 * time.Minute
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
var searchIndexLocks sync.Map

func lockSearchIndex(user string) func() {
	v, _ := searchIndexLocks.LoadOrStore(user, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// maxIndexDecompressedBytes caps the inflated index JSON so a
// corrupted or hostile stored object cannot balloon enclave memory.
// Sized for searchindex.MaxChats entries at the worst-case per-entry
// footprint with ample margin.
const maxIndexDecompressedBytes = 512 << 20

// loadSearchIndex fetches and decodes the user's index. A missing
// object, an index sealed under a different (rotated) CEK, an unknown
// format, or a model change all yield a fresh empty index with
// needsReindex=true so callers can surface "rebuild me" to the client
// instead of failing.
func loadSearchIndex(ctx context.Context, deps Deps, owner string, indexKey []byte) (*searchindex.Index, bool, error) {
	model := deps.Embedder.Model()
	raw, err := deps.SearchBuckets.Get(ctx, owner, searchIndexObjectKey, indexKey)
	switch {
	case errors.Is(err, buckets.ErrNotFound):
		return searchindex.New(model), true, nil
	case errors.Is(err, buckets.ErrForbidden):
		return searchindex.New(model), true, nil
	case err != nil:
		return nil, false, err
	}
	encoded, err := gunzipIndex(raw)
	if err != nil {
		return searchindex.New(model), true, nil
	}
	ix, err := searchindex.Decode(encoded)
	if err != nil {
		return searchindex.New(model), true, nil
	}
	if !ix.Compatible(model) {
		return searchindex.New(model), true, nil
	}
	return ix, false, nil
}

// saveSearchIndex gzips the index JSON before handing it to the
// sidecar: token text compresses well, and compression must happen
// before the sidecar encrypts since ciphertext does not compress.
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
	return deps.SearchBuckets.Put(ctx, owner, searchIndexObjectKey, buf.Bytes(), indexKey)
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

// chatSearchText extracts the indexable text from a chat blob: the
// title plus every message body, truncated to maxSearchTextChars.
// Returns "" when the blob is not chat-shaped JSON or has no text.
func chatSearchText(plaintext []byte) string {
	var doc chatSearchDoc
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		return ""
	}
	var b strings.Builder
	appendPart := func(s string) bool {
		s = strings.TrimSpace(s)
		if s == "" {
			return true
		}
		remaining := maxSearchTextChars - b.Len()
		if remaining <= 0 {
			return false
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
			remaining--
		}
		if len(s) > remaining {
			s = truncateUTF8(s, remaining)
		}
		b.WriteString(s)
		return b.Len() < maxSearchTextChars
	}
	if !appendPart(doc.Title) {
		return b.String()
	}
	for _, m := range doc.Messages {
		if !appendPart(m.Content) {
			break
		}
	}
	return b.String()
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
// index. Called inline from Push after the blob write succeeds; the
// caller treats failures as best-effort (the blob is already stored)
// and logs them.
func indexChatForSearch(ctx context.Context, deps Deps, owner string, cek []byte, chatID string, plaintext []byte, etag string) error {
	indexKey, err := cryptopkg.DeriveSearchIndexKey(cek)
	if err != nil {
		return err
	}
	defer cryptopkg.Zero(indexKey)

	text := chatSearchText(plaintext)
	entry := searchindex.Entry{
		ETag:      etag,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Tokens:    searchindex.Tokenize(text),
	}
	var embedErr error
	if text != "" {
		vecs, err := deps.Embedder.Embed(ctx, []string{searchDocPrefix + text})
		if err != nil {
			// Keep the lexical entry so the chat is still findable by
			// keyword; surface the error so the caller logs the
			// degraded state.
			embedErr = err
		} else {
			entry.Vector = searchindex.Quantize(vecs[0])
		}
	}

	unlock := lockSearchIndex(owner)
	defer unlock()
	ix, _, err := loadSearchIndex(ctx, deps, owner, indexKey)
	if err != nil {
		return err
	}
	if err := ix.Upsert(chatID, entry); err != nil {
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
	ix, needsReindex, err := loadSearchIndex(ctx, deps, owner, indexKey)
	if err != nil {
		return err
	}
	if needsReindex {
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

	ix, needsReindex, err := loadSearchIndex(ctx, deps, sess.Claims.Subject, indexKey)
	if err != nil {
		deps.logError("search query index load failed: user=%s err=%v", sess.Claims.Subject, err)
		return nil, err
	}
	resp := &SearchQueryResponse{
		Results:      []SearchQueryResult{},
		TotalIndexed: len(ix.Chats),
		NeedsReindex: needsReindex,
	}
	if len(ix.Chats) == 0 {
		return resp, nil
	}
	vecs, err := deps.Embedder.Embed(ctx, []string{searchQueryPrefix + query})
	if err != nil {
		deps.logError("search query embed failed: user=%s err=%v", sess.Claims.Subject, err)
		return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "embedding service failed"}
	}
	for _, r := range ix.Search(vecs[0], searchindex.Tokenize(query), req.Limit) {
		resp.Results = append(resp.Results, SearchQueryResult{ID: r.ID, Score: r.Score})
	}
	deps.logInfo("search query ok: user=%s indexed=%d results=%d",
		sess.Claims.Subject, resp.TotalIndexed, len(resp.Results))
	return resp, nil
}

// SearchReindex rebuilds one page of the caller's index from the
// stored chat blobs. The client drives pagination: an empty cursor
// starts a rebuild (dropping the previous index generation, which
// also flushes entries for since-deleted chats), and each response's
// next_cursor feeds the following call until done=true.
func SearchReindex(ctx context.Context, deps Deps, sess Session, req SearchReindexRequest) (*SearchReindexResponse, error) {
	if !searchConfigured(deps) {
		return nil, searchUnavailable()
	}
	if len(req.Keys) == 0 {
		return nil, badRequest("keys is required and must not be empty")
	}
	if req.Limit <= 0 || req.Limit > maxReindexPageSize {
		req.Limit = defaultReindexPageSize
	}
	cek, err := decodeKey(req.Keys[0].Key)
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
		Cursor: req.Cursor,
		Limit:  req.Limit,
		Keys:   req.Keys,
	})
	if err != nil {
		return nil, err
	}

	type pending struct {
		id    string
		etag  string
		text  string
		embed bool
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
		text := chatSearchText(plaintext)
		cryptopkg.Zero(plaintext)
		p := pending{id: item.ID, etag: item.ETag, text: text, embed: text != ""}
		if p.embed {
			texts = append(texts, searchDocPrefix+text)
		}
		page = append(page, p)
	}

	var vectors [][]float32
	if len(texts) > 0 {
		vectors, err = deps.Embedder.Embed(ctx, texts)
		if err != nil {
			deps.logError("search reindex embed failed: user=%s err=%v", sess.Claims.Subject, err)
			return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "embedding service failed"}
		}
	}

	unlock := lockSearchIndex(sess.Claims.Subject)
	defer unlock()
	var ix *searchindex.Index
	if req.Cursor == "" {
		ix = searchindex.New(deps.Embedder.Model())
	} else {
		ix, _, err = loadSearchIndex(ctx, deps, sess.Claims.Subject, indexKey)
		if err != nil {
			return nil, err
		}
	}
	indexed := 0
	vecIdx := 0
	for _, p := range page {
		entry := searchindex.Entry{
			ETag:      p.etag,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Tokens:    searchindex.Tokenize(p.text),
		}
		if p.embed {
			entry.Vector = searchindex.Quantize(vectors[vecIdx])
			vecIdx++
		}
		if err := ix.Upsert(p.id, entry); err != nil {
			failed++
			continue
		}
		indexed++
	}
	if err := saveSearchIndex(ctx, deps, sess.Claims.Subject, indexKey, ix); err != nil {
		return nil, err
	}
	resp := &SearchReindexResponse{
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
