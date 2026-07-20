// Package searchindex implements the per-user chat search index the
// sync enclave maintains, modeled on what E2EE messengers build
// client-side (SQLite FTS5 style): an inverted index from token to
// posting list for exact keyword search, plus a handful of quantized
// chunk-embedding vectors per chat for semantic ranking as a bonus
// signal.
//
// The whole index is one object fetched into memory from the buckets
// sidecar, so the format is optimized to stay small: each token
// string is stored once (as a postings key) no matter how many chats
// contain it, posting lists hold small integer slots instead of chat
// ids, and vectors are int8-quantized. Queries resolve keywords by
// O(query tokens) posting-list lookups; only the semantic pass scans
// per-chat vectors, which stays cheap at per-user corpus sizes.
//
// The index is serialized to JSON, gzipped, and stored sealed under a
// key derived from the user's CEK (crypto.DeriveSearchIndexKey).
// Plaintext index contents exist only inside the enclave for the
// lifetime of a request.
package searchindex

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	// FormatVersion tags the serialized index shape. Decode rejects
	// anything else so an older enclave never silently corrupts an
	// index written by a newer one; a version bump simply forces a
	// client-driven reindex.
	FormatVersion = 1

	// MaxChats bounds how many entries one index holds, which in turn
	// bounds the object size and per-query cost.
	MaxChats = 50000

	// MaxTokensPerChat caps how many tokens one chat contributes to
	// the postings.
	MaxTokensPerChat = 512

	// MaxChunksPerChat caps how many embedding vectors one chat may
	// store. Chunked embeddings keep long chats searchable (one
	// vector over a whole conversation dilutes everything), while the
	// cap bounds the dominant per-chat size cost; typical short chats
	// carry a single chunk.
	MaxChunksPerChat = 8

	// minTokenLen drops single-character noise tokens.
	minTokenLen = 2

	// maxTokenLen drops pathological fragment tokens (base64 blobs,
	// hashes) that bloat the index without helping keyword search.
	maxTokenLen = 40

	// maxIdentifierLen is the longer cap for whole identifiers
	// (emails, URLs) kept intact for exact matching.
	maxIdentifierLen = 64

	// compactionMinDead avoids rewriting postings for trivial amounts
	// of garbage; compaction only fires once at least this many dead
	// slots exist and they outnumber the live entries.
	compactionMinDead = 64

	// rrfK is the standard reciprocal-rank-fusion smoothing constant.
	rrfK = 60

	// rrfCandidateDepth truncates each ranked list before fusion so a
	// huge corpus doesn't drag thousands of near-zero-signal entries
	// into the fused scoring.
	rrfCandidateDepth = 128

	// maxReindexCursorLength bounds the opaque controlplane cursor
	// persisted in a partial index between resumable rebuild runs.
	maxReindexCursorLength = 4096

	// maxSerializedSlots admits the tombstones Upsert can leave
	// between compactions while rejecting slot tables this package
	// could never produce.
	maxSerializedSlots = MaxChats * 2

	// lexicalRRFWeight / semanticRRFWeight bias fusion toward keyword
	// hits: exact keyword search is the reliable tier, semantic
	// similarity the bonus tier.
	lexicalRRFWeight  = 1.0
	semanticRRFWeight = 0.5
)

var (
	ErrFormat   = errors.New("searchindex: unsupported index format")
	ErrTooLarge = errors.New("searchindex: index is full")
)

// Vector is an int8-quantized embedding vector that serializes as
// base64, keeping a 768-dim vector at ~1 KiB on the wire instead of
// the ~15 KiB a float JSON array would take. Cosine similarity is
// invariant under per-vector positive scaling, and cosine is the only
// operation performed on stored vectors, so symmetric max-abs
// quantization needs no stored scale factor and costs ranking quality
// only through the (small) rounding error.
type Vector []int8

// Quantize maps a float vector onto the int8 range via symmetric
// max-abs scaling.
func Quantize(v []float32) Vector {
	if len(v) == 0 {
		return nil
	}
	var maxAbs float64
	for _, f := range v {
		if a := math.Abs(float64(f)); a > maxAbs {
			maxAbs = a
		}
	}
	out := make(Vector, len(v))
	// NaN/Inf cannot arrive via well-formed JSON embeddings, but a
	// non-finite value here would make the int8 conversion below
	// implementation-defined; a zero vector is the safe degradation.
	if maxAbs == 0 || math.IsInf(maxAbs, 0) || math.IsNaN(maxAbs) {
		return out
	}
	scale := 127 / maxAbs
	for i, f := range v {
		q := math.Round(float64(f) * scale)
		if math.IsNaN(q) {
			continue
		}
		out[i] = int8(q)
	}
	return out
}

func (v Vector) MarshalJSON() ([]byte, error) {
	buf := make([]byte, len(v))
	for i, q := range v {
		buf[i] = byte(q)
	}
	return []byte(`"` + base64.StdEncoding.EncodeToString(buf) + `"`), nil
}

func (v *Vector) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("searchindex: vector must be a base64 string")
	}
	raw, err := base64.StdEncoding.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return fmt.Errorf("searchindex: decode vector: %w", err)
	}
	out := make(Vector, len(raw))
	for i, b := range raw {
		out[i] = int8(b)
	}
	*v = out
	return nil
}

// Entry is one chat's index record. Its tokens live in the shared
// postings, referenced by Slot, not on the entry itself.
type Entry struct {
	// Slot is the chat's position in the Slots table; posting lists
	// reference chats by slot. Assigned by Upsert.
	Slot int `json:"slot"`
	// ETag is the sync blob etag the entry was built from, so callers
	// can skip re-embedding chats that have not changed.
	ETag           string `json:"etag,omitempty"`
	SourceRevision int64  `json:"source_revision,omitempty"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	// Vectors holds one quantized embedding per text chunk; the
	// semantic score for the chat is the max similarity over them.
	Vectors          []Vector `json:"vectors,omitempty"`
	EmbeddingPending bool     `json:"embedding_pending,omitempty"`
}

// ReindexProgress checkpoints a clean page boundary for a partial
// rebuild. It lives inside the encrypted index object so a later job
// can resume after an enclave restart without retaining key material
// or progress in a separate plaintext store.
type ReindexProgress struct {
	NextCursor           string `json:"next_cursor"`
	TargetSourceRevision int64  `json:"target_source_revision"`
	StartedAt            string `json:"started_at"`
}

// Index is the serialized per-user search index.
type Index struct {
	Version int `json:"version"`
	// Model and Dims pin the embedding space. Vectors from different
	// models are not comparable, so a model change forces a rebuild.
	Model string `json:"model,omitempty"`
	Dims  int    `json:"dims,omitempty"`
	// Incomplete marks an index known not to cover the full corpus:
	// set when an inline push had to start over on top of an
	// unreadable previous index (wrong key, corruption, model change)
	// and while a rebuild is mid-flight. Queries surface it as
	// needs_reindex; a completed rebuild clears it.
	Incomplete bool `json:"incomplete,omitempty"`
	// Reindex is present only after a clean, non-final rebuild page.
	// Failures clear it so the next run starts over and retries gaps.
	Reindex *ReindexProgress `json:"reindex,omitempty"`
	// Slots maps slot -> chat id. An updated or removed chat leaves a
	// tombstone ("" at its old slot) instead of eagerly rewriting
	// every posting list; queries skip dead slots and compaction
	// reclaims them once they outnumber live entries.
	Slots []string `json:"slots,omitempty"`
	// Chats maps chat id -> entry.
	Chats map[string]Entry `json:"chats"`
	// Postings is the inverted index: token -> ascending slot list.
	Postings map[string][]int `json:"postings,omitempty"`

	// dead counts tombstoned slots; recomputed on decode, maintained
	// on mutation, never serialized.
	dead int
}

func New(model string) *Index {
	return &Index{
		Version:  FormatVersion,
		Model:    model,
		Chats:    map[string]Entry{},
		Postings: map[string][]int{},
	}
}

// Decode parses a serialized index and validates its shape. Slot
// references are checked so a corrupted object surfaces as a decode
// error (which callers treat as "rebuild") instead of a panic later.
func Decode(data []byte) (*Index, error) {
	var ix Index
	if err := json.Unmarshal(data, &ix); err != nil {
		return nil, fmt.Errorf("searchindex: decode: %w", err)
	}
	if ix.Version != FormatVersion {
		return nil, ErrFormat
	}
	if ix.Chats == nil {
		ix.Chats = map[string]Entry{}
	}
	if ix.Postings == nil {
		ix.Postings = map[string][]int{}
	}
	if len(ix.Slots) > maxSerializedSlots {
		return nil, fmt.Errorf("searchindex: %d slots exceeds limit %d", len(ix.Slots), maxSerializedSlots)
	}
	live := 0
	for _, id := range ix.Slots {
		if id == "" {
			ix.dead++
			continue
		}
		live++
		e, ok := ix.Chats[id]
		if !ok || e.Slot < 0 || e.Slot >= len(ix.Slots) || id != ix.Slots[e.Slot] {
			return nil, errors.New("searchindex: slot table does not match entries")
		}
	}
	if live != len(ix.Chats) {
		return nil, errors.New("searchindex: slot table does not match entries")
	}
	if ix.dead >= compactionMinDead && ix.dead > live {
		return nil, errors.New("searchindex: tombstones exceed compaction invariant")
	}
	// Enforce the same bounds Upsert does, so a corrupt stored object
	// cannot smuggle in an index far more expensive to search than
	// anything this code could have built. Rejecting it makes the
	// load path treat it as unreadable, which routes the client to a
	// rebuild instead of serving the oversized index.
	if len(ix.Chats) > MaxChats {
		return nil, fmt.Errorf("searchindex: %d chats exceeds limit %d", len(ix.Chats), MaxChats)
	}
	if ix.Reindex != nil {
		if !ix.Incomplete {
			return nil, errors.New("searchindex: complete index has reindex progress")
		}
		if ix.Reindex.NextCursor == "" || len(ix.Reindex.NextCursor) > maxReindexCursorLength {
			return nil, errors.New("searchindex: reindex cursor is invalid")
		}
		if ix.Reindex.TargetSourceRevision < 0 {
			return nil, errors.New("searchindex: reindex source revision is negative")
		}
		if _, err := time.Parse(time.RFC3339Nano, ix.Reindex.StartedAt); err != nil {
			return nil, errors.New("searchindex: reindex start time is invalid")
		}
	}
	for _, e := range ix.Chats {
		if e.SourceRevision < 0 {
			return nil, errors.New("searchindex: entry source revision is negative")
		}
		if len(e.Vectors) > MaxChunksPerChat {
			return nil, fmt.Errorf("searchindex: %d chunk vectors exceeds limit %d", len(e.Vectors), MaxChunksPerChat)
		}
		for _, v := range e.Vectors {
			if len(v) == 0 || len(v) != ix.Dims {
				return nil, errors.New("searchindex: entry vector does not match index dims")
			}
		}
	}
	maxPostings := len(ix.Slots) * MaxTokensPerChat
	totalPostings := 0
	postedSlots := make([]bool, len(ix.Slots))
	for tok, slots := range ix.Postings {
		if !validPostingToken(tok) {
			return nil, errors.New("searchindex: posting token is invalid")
		}
		if len(slots) == 0 {
			return nil, errors.New("searchindex: posting list is empty")
		}
		if len(slots) > len(ix.Slots) {
			return nil, errors.New("searchindex: posting list exceeds slot table")
		}
		prev := -1
		for _, s := range slots {
			if s < 0 || s >= len(ix.Slots) {
				return nil, errors.New("searchindex: posting references unknown slot")
			}
			if s <= prev {
				return nil, errors.New("searchindex: posting list is not strictly ordered")
			}
			prev = s
			postedSlots[s] = true
			totalPostings++
			if totalPostings > maxPostings {
				return nil, errors.New("searchindex: postings exceed token limit")
			}
		}
	}
	for id, entry := range ix.Chats {
		if len(entry.Vectors) == 0 && postedSlots[entry.Slot] {
			entry.EmbeddingPending = true
			ix.Chats[id] = entry
		}
	}
	return &ix, nil
}

func (ix *Index) Encode() ([]byte, error) {
	return json.Marshal(ix)
}

func validPostingToken(tok string) bool {
	return len(tok) >= minTokenLen && len(tok) <= maxIdentifierLen
}

// Upsert records or replaces one chat's entry and its postings. The
// previous generation of an updated chat is tombstoned rather than
// scrubbed from every posting list; compaction reclaims tombstones in
// bulk. The first vector to land in an empty index pins Dims; later
// vectors must match.
func (ix *Index) Upsert(id string, e Entry, tokens []string) error {
	if id == "" {
		return errors.New("searchindex: id is required")
	}
	if e.SourceRevision < 0 {
		return errors.New("searchindex: entry source revision is negative")
	}
	if len(e.Vectors) > MaxChunksPerChat {
		return fmt.Errorf("searchindex: %d chunk vectors exceeds limit %d", len(e.Vectors), MaxChunksPerChat)
	}
	dims := ix.Dims
	for _, v := range e.Vectors {
		if len(v) == 0 {
			return errors.New("searchindex: empty chunk vector")
		}
		if dims == 0 {
			dims = len(v)
		} else if len(v) != dims {
			return fmt.Errorf("searchindex: vector has %d dims, index has %d", len(v), dims)
		}
	}
	if _, exists := ix.Chats[id]; !exists && len(ix.Chats) >= MaxChats {
		return ErrTooLarge
	}
	ix.Dims = dims
	if old, exists := ix.Chats[id]; exists {
		ix.Slots[old.Slot] = ""
		ix.dead++
	}
	e.Slot = len(ix.Slots)
	ix.Slots = append(ix.Slots, id)
	ix.Chats[id] = e
	// Tokenize already dedupes, but Upsert must not trust its caller:
	// a duplicated token would double-count the chat in that token's
	// IDF and score.
	seen := make(map[string]struct{}, len(tokens))
	for _, tok := range tokens {
		if !validPostingToken(tok) {
			continue
		}
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		ix.Postings[tok] = append(ix.Postings[tok], e.Slot)
		if len(seen) >= MaxTokensPerChat {
			break
		}
	}
	ix.maybeCompact()
	return nil
}

// Remove drops one chat, leaving a tombstone slot behind.
func (ix *Index) Remove(id string) {
	e, ok := ix.Chats[id]
	if !ok {
		return
	}
	ix.Slots[e.Slot] = ""
	ix.dead++
	delete(ix.Chats, id)
	ix.maybeCompact()
}

// maybeCompact rewrites the slot table and postings once tombstones
// outnumber live entries. Amortized this keeps mutations O(tokens per
// chat) while bounding the garbage a churn-heavy user accumulates.
func (ix *Index) maybeCompact() {
	if ix.dead < compactionMinDead || ix.dead <= len(ix.Chats) {
		return
	}
	remap := make(map[int]int, len(ix.Chats))
	newSlots := make([]string, 0, len(ix.Chats))
	for oldSlot, id := range ix.Slots {
		if id == "" {
			continue
		}
		remap[oldSlot] = len(newSlots)
		newSlots = append(newSlots, id)
	}
	for id, e := range ix.Chats {
		e.Slot = remap[e.Slot]
		ix.Chats[id] = e
	}
	for tok, slots := range ix.Postings {
		kept := slots[:0]
		for _, s := range slots {
			if n, ok := remap[s]; ok {
				kept = append(kept, n)
			}
		}
		if len(kept) == 0 {
			delete(ix.Postings, tok)
			continue
		}
		sort.Ints(kept)
		ix.Postings[tok] = kept
	}
	ix.Slots = newSlots
	ix.dead = 0
}

// Compatible reports whether the index can serve queries embedded
// with the given model.
func (ix *Index) Compatible(model string) bool {
	return ix.Model == model
}

// NeedsEmbeddingRepair reports whether any lexically indexed entry is
// still waiting for semantic vectors.
func (ix *Index) NeedsEmbeddingRepair() bool {
	for _, entry := range ix.Chats {
		if entry.EmbeddingPending {
			return true
		}
	}
	return false
}

// identifierPattern matches whole emails and URLs in lowercased text.
// These are kept intact as single tokens (alongside their fragments)
// so a query for an exact identifier like "sacha@gmail.com" matches
// the whole token decisively instead of relying on fragment
// coincidence.
var identifierPattern = regexp.MustCompile(`https?://[^\s<>"']+|www\.[^\s<>"']+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)

// Tokenize lowercases text and returns its deduplicated token set:
// whole email/URL identifiers first (so the cap can never evict
// them), then fragments split on non-letter/non-digit runes.
func Tokenize(text string) []string {
	lower := strings.ToLower(text)
	seen := make(map[string]struct{})
	var out []string
	add := func(tok string, maxLen int) bool {
		if len(tok) < minTokenLen || len(tok) > maxLen {
			return true
		}
		if _, dup := seen[tok]; dup {
			return true
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
		return len(out) < MaxTokensPerChat
	}
	for _, ident := range identifierPattern.FindAllString(lower, -1) {
		if !add(strings.Trim(ident, ".,;:!?"), maxIdentifierLen) {
			return out
		}
	}
	fields := strings.FieldsFunc(lower, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	for _, f := range fields {
		if !add(f, maxTokenLen) {
			return out
		}
	}
	return out
}

// Result is one ranked search hit.
type Result struct {
	ID    string
	Score float64
}

// Search answers a query in two strict tiers:
//
//   - Lexical: posting-list lookups scored by summed IDF, so rare
//     query tokens ("sacha") dominate ubiquitous ones ("com"). This
//     is the reliable tier and every hit ranks before semantic-only
//     results.
//   - Semantic: cosine over per-chat quantized vectors, the bonus
//     tier that refines lexical ordering and then surfaces
//     "animal" -> duck/dog chats without keyword matches.
//
// Weighted reciprocal-rank fusion orders results within those tiers
// without comparing incompatible cosine and IDF scales. Returned
// scores are meaningful for ordering, not calibrated for anything
// else.
func (ix *Index) Search(queryVec []float32, queryTokens []string, limit int) []Result {
	if limit <= 0 || len(ix.Chats) == 0 {
		return nil
	}
	fused := map[int]float64{}
	lexical := map[int]struct{}{}
	for rank, slot := range ix.lexicalRanked(queryTokens) {
		lexical[slot] = struct{}{}
		fused[slot] += lexicalRRFWeight / float64(rrfK+rank+1)
	}
	for rank, slot := range ix.semanticRanked(queryVec) {
		fused[slot] += semanticRRFWeight / float64(rrfK+rank+1)
	}
	results := make([]Result, 0, len(fused))
	for slot, score := range fused {
		results = append(results, Result{ID: ix.Slots[slot], Score: score})
	}
	sort.Slice(results, func(i, j int) bool {
		_, iLexical := lexical[ix.Chats[results[i].ID].Slot]
		_, jLexical := lexical[ix.Chats[results[j].ID].Slot]
		if iLexical != jLexical {
			return iLexical
		}
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].ID < results[j].ID
	})
	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

// lexicalRanked returns live slots ordered by summed IDF over the
// matched query tokens, truncated to rrfCandidateDepth.
func (ix *Index) lexicalRanked(queryTokens []string) []int {
	n := len(ix.Chats)
	scores := map[int]float64{}
	seen := map[string]struct{}{}
	for _, tok := range queryTokens {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		live := ix.livePostings(tok)
		if len(live) == 0 {
			continue
		}
		// BM25-style IDF: a token in every chat scores ~0, a token in
		// one chat scores ~log(N).
		idf := math.Log(1 + (float64(n)-float64(len(live))+0.5)/(float64(len(live))+0.5))
		for _, slot := range live {
			scores[slot] += idf
		}
	}
	return rankSlots(scores, func(a, b int) bool { return ix.Slots[a] < ix.Slots[b] })
}

// semanticRanked returns live slots ordered by the best cosine
// similarity between the query vector and any of the chat's chunk
// vectors, truncated to rrfCandidateDepth. Max-sim over chunks means
// a long chat matches on its most relevant passage instead of an
// average washed out by the rest of the conversation.
func (ix *Index) semanticRanked(queryVec []float32) []int {
	if len(queryVec) == 0 {
		return nil
	}
	scores := map[int]float64{}
	for _, e := range ix.Chats {
		best := math.Inf(-1)
		for _, v := range e.Vectors {
			if len(v) != len(queryVec) {
				continue
			}
			if c := cosine(queryVec, v); c > best {
				best = c
			}
		}
		if !math.IsInf(best, -1) {
			scores[e.Slot] = best
		}
	}
	return rankSlots(scores, func(a, b int) bool { return ix.Slots[a] < ix.Slots[b] })
}

// livePostings returns the token's posting list with tombstoned and
// superseded slots filtered out.
func (ix *Index) livePostings(tok string) []int {
	slots := ix.Postings[tok]
	live := make([]int, 0, len(slots))
	for _, s := range slots {
		if ix.Slots[s] == "" {
			continue
		}
		live = append(live, s)
	}
	return live
}

func rankSlots(scores map[int]float64, tieBreak func(a, b int) bool) []int {
	ranked := make([]int, 0, len(scores))
	for slot := range scores {
		ranked = append(ranked, slot)
	}
	sort.Slice(ranked, func(i, j int) bool {
		si, sj := scores[ranked[i]], scores[ranked[j]]
		if si != sj {
			return si > sj
		}
		return tieBreak(ranked[i], ranked[j])
	})
	if len(ranked) > rrfCandidateDepth {
		ranked = ranked[:rrfCandidateDepth]
	}
	return ranked
}

func cosine(a []float32, b Vector) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
