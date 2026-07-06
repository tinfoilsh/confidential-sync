// Package searchindex implements the per-user chat search index the
// sync enclave maintains. The index maps each chat id to a lexical
// token set plus a semantic embedding vector; queries are answered by
// brute-force cosine similarity over every entry, combined with a
// lexical-overlap boost. Brute force is deliberate: per-user chat
// counts are small (hundreds to a few thousand), and scanning the
// whole index inside the enclave leaks no per-query access pattern
// the way a disk-resident ANN structure would.
//
// The index is serialized to JSON and stored as a single object
// through the buckets sidecar, sealed under a key derived from the
// user's CEK (crypto.DeriveSearchIndexKey). Plaintext index contents
// exist only inside the enclave for the lifetime of a request.
package searchindex

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
)

const (
	// FormatVersion tags the serialized index shape. Decode rejects
	// anything newer so an older enclave never silently corrupts an
	// index written by a newer one.
	FormatVersion = 1

	// MaxChats bounds how many entries one index holds, which in turn
	// bounds the object size and per-query scan cost.
	MaxChats = 50000

	// MaxTokensPerChat caps the stored lexical token set per chat.
	MaxTokensPerChat = 512

	// minTokenLen drops single-character noise tokens.
	minTokenLen = 2

	// maxTokenLen drops pathological tokens (base64 blobs, hashes)
	// that bloat the index without helping lexical match.
	maxTokenLen = 40

	// lexicalBoostWeight is how much a full lexical overlap adds on
	// top of the cosine score. Cosine dominates ranking; the boost
	// promotes exact keyword hits among semantically similar chats.
	lexicalBoostWeight = 0.3
)

var (
	ErrFormat   = errors.New("searchindex: unsupported index format")
	ErrTooLarge = errors.New("searchindex: index is full")
)

// Vector is an embedding vector that serializes as base64 of
// little-endian float32 bytes instead of a JSON number array, which
// keeps a 768-dim vector at ~4 KiB on the wire instead of ~15 KiB.
type Vector []float32

func (v Vector) MarshalJSON() ([]byte, error) {
	buf := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
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
	if len(raw)%4 != 0 {
		return errors.New("searchindex: vector byte length not a multiple of 4")
	}
	out := make(Vector, len(raw)/4)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
	}
	*v = out
	return nil
}

// Entry is one chat's index record.
type Entry struct {
	// ETag is the sync blob etag the entry was built from, so callers
	// can skip re-embedding chats that have not changed.
	ETag      string   `json:"etag,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
	Tokens    []string `json:"tokens,omitempty"`
	Vector    Vector   `json:"vector,omitempty"`
}

// Index is the serialized per-user search index.
type Index struct {
	Version int `json:"version"`
	// Model and Dims pin the embedding space. Vectors from different
	// models are not comparable, so a model change forces a rebuild.
	Model string           `json:"model,omitempty"`
	Dims  int              `json:"dims,omitempty"`
	Chats map[string]Entry `json:"chats"`
}

func New(model string) *Index {
	return &Index{
		Version: FormatVersion,
		Model:   model,
		Chats:   map[string]Entry{},
	}
}

// Decode parses a serialized index and validates its version.
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
	return &ix, nil
}

func (ix *Index) Encode() ([]byte, error) {
	return json.Marshal(ix)
}

// Upsert records or replaces one chat's entry. The first vector to
// land in an empty index pins Dims; later vectors must match.
func (ix *Index) Upsert(id string, e Entry) error {
	if id == "" {
		return errors.New("searchindex: id is required")
	}
	if _, exists := ix.Chats[id]; !exists && len(ix.Chats) >= MaxChats {
		return ErrTooLarge
	}
	if len(e.Vector) > 0 {
		if ix.Dims == 0 {
			ix.Dims = len(e.Vector)
		} else if len(e.Vector) != ix.Dims {
			return fmt.Errorf("searchindex: vector has %d dims, index has %d", len(e.Vector), ix.Dims)
		}
	}
	ix.Chats[id] = e
	return nil
}

func (ix *Index) Remove(id string) {
	delete(ix.Chats, id)
}

// Compatible reports whether the index can serve queries embedded
// with the given model.
func (ix *Index) Compatible(model string) bool {
	return ix.Model == model
}

// Tokenize lowercases text, splits on non-letter/non-digit runes, and
// returns the deduplicated token set (capped at MaxTokensPerChat).
// Order is sorted so serialized indexes are deterministic.
func Tokenize(text string) []string {
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < minTokenLen || len(f) > maxTokenLen {
			continue
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
		if len(out) >= MaxTokensPerChat {
			break
		}
	}
	sort.Strings(out)
	return out
}

// Result is one ranked search hit.
type Result struct {
	ID    string
	Score float64
}

// Search ranks every entry against the query embedding and token set
// and returns the top `limit` results, best first. Entries without a
// vector (or with mismatched dims) are ranked by lexical overlap
// alone, so a partially indexed corpus still returns keyword hits.
func (ix *Index) Search(queryVec []float32, queryTokens []string, limit int) []Result {
	if limit <= 0 {
		return nil
	}
	querySet := make(map[string]struct{}, len(queryTokens))
	for _, t := range queryTokens {
		querySet[t] = struct{}{}
	}
	results := make([]Result, 0, len(ix.Chats))
	for id, e := range ix.Chats {
		score := 0.0
		scored := false
		if len(queryVec) > 0 && len(e.Vector) == len(queryVec) {
			score = cosine(queryVec, e.Vector)
			scored = true
		}
		if len(querySet) > 0 {
			overlap := lexicalOverlap(querySet, e.Tokens)
			score += lexicalBoostWeight * overlap
			scored = scored || overlap > 0
		}
		if !scored {
			continue
		}
		results = append(results, Result{ID: id, Score: score})
	}
	sort.Slice(results, func(i, j int) bool {
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

// lexicalOverlap is the fraction of query tokens present in the
// entry's token set.
func lexicalOverlap(querySet map[string]struct{}, tokens []string) float64 {
	if len(querySet) == 0 || len(tokens) == 0 {
		return 0
	}
	hits := 0
	for _, t := range tokens {
		if _, ok := querySet[t]; ok {
			hits++
		}
	}
	return float64(hits) / float64(len(querySet))
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
