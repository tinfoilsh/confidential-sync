package searchindex

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func mustUpsert(t *testing.T, ix *Index, id string, e Entry, tokens []string) {
	t.Helper()
	if err := ix.Upsert(id, e, tokens); err != nil {
		t.Fatal(err)
	}
}

func resultIDs(results []Result) []string {
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids
}

func TestTokenizeNormalizesAndDedupes(t *testing.T) {
	got := Tokenize("The DUCK swam; the duck quacked! 42 x " + strings.Repeat("y", 50))
	want := []string{"the", "duck", "swam", "quacked", "42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tokenize = %v, want %v", got, want)
	}
}

func TestTokenizeKeepsIdentifiersWhole(t *testing.T) {
	got := Tokenize("Email me at Sacha@Gmail.com or see https://tinfoil.sh/docs.")
	set := map[string]struct{}{}
	for _, tok := range got {
		set[tok] = struct{}{}
	}
	for _, want := range []string{"sacha@gmail.com", "https://tinfoil.sh/docs", "sacha", "gmail", "com", "email"} {
		if _, ok := set[want]; !ok {
			t.Fatalf("missing token %q in %v", want, got)
		}
	}
}

func TestVectorJSONRoundtripAndQuantize(t *testing.T) {
	q := Quantize([]float32{0.5, -0.25, 0, 1.0})
	if want := (Vector{64, -32, 0, 127}); !reflect.DeepEqual(q, want) {
		t.Fatalf("Quantize = %v, want %v", q, want)
	}
	if got := Quantize(nil); got != nil {
		t.Fatalf("Quantize(nil) = %v, want nil", got)
	}

	ix := New("test-model")
	mustUpsert(t, ix, "chat_1", Entry{Vectors: []Vector{{25, -100, 127}, {1, 2, 3}}}, []string{"duck", "pond"})
	encoded, err := ix.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	e := decoded.Chats["chat_1"]
	if !reflect.DeepEqual(e.Vectors, []Vector{{25, -100, 127}, {1, 2, 3}}) {
		t.Fatalf("vectors roundtrip mismatch: %v", e.Vectors)
	}
	if decoded.Dims != 3 || !decoded.Compatible("test-model") {
		t.Fatalf("dims/model mismatch: dims=%d model=%q", decoded.Dims, decoded.Model)
	}
	if got := decoded.livePostings("duck"); len(got) != 1 || decoded.Slots[got[0]] != "chat_1" {
		t.Fatalf("postings roundtrip mismatch: %v", got)
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	if _, err := Decode([]byte(`{"version":99,"chats":{}}`)); err != ErrFormat {
		t.Fatalf("expected ErrFormat, got %v", err)
	}
	if _, err := Decode([]byte(`not json`)); err == nil {
		t.Fatal("expected decode error for malformed input")
	}
	// Posting referencing a slot that does not exist.
	if _, err := Decode([]byte(`{"version":1,"slots":["a"],"chats":{"a":{"slot":0}},"postings":{"x":[7]}}`)); err == nil {
		t.Fatal("expected error for out-of-range posting slot")
	}
	// Slot table naming a chat that has no entry.
	if _, err := Decode([]byte(`{"version":1,"slots":["a","b"],"chats":{"a":{"slot":0}},"postings":{}}`)); err == nil {
		t.Fatal("expected error for slot/entry mismatch")
	}
}

func TestUpsertValidatesVectors(t *testing.T) {
	ix := New("m")
	before, err := ix.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.Upsert("invalid", Entry{Vectors: []Vector{{1, 0}, {}}}, nil); err == nil {
		t.Fatal("expected empty vector error")
	}
	after, err := ix.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("rejected upsert mutated the index")
	}

	mustUpsert(t, ix, "a", Entry{Vectors: []Vector{{1, 0}}}, nil)
	if err := ix.Upsert("b", Entry{Vectors: []Vector{{1, 0, 0}}}, nil); err == nil {
		t.Fatal("expected dim mismatch error")
	}
	tooMany := make([]Vector, MaxChunksPerChat+1)
	for i := range tooMany {
		tooMany[i] = Vector{1, 0}
	}
	if err := ix.Upsert("c", Entry{Vectors: tooMany}, nil); err == nil {
		t.Fatal("expected chunk-count error")
	}
}

func TestUpsertReplaceSupersedesOldPostings(t *testing.T) {
	ix := New("m")
	mustUpsert(t, ix, "a", Entry{}, []string{"duck"})
	mustUpsert(t, ix, "a", Entry{}, []string{"goose"})

	if got := ix.Search(nil, []string{"duck"}, 5); len(got) != 0 {
		t.Fatalf("stale posting still matches: %+v", got)
	}
	got := ix.Search(nil, []string{"goose"}, 5)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("expected replacement to match, got %+v", got)
	}
	if len(ix.Chats) != 1 {
		t.Fatalf("expected 1 chat, got %d", len(ix.Chats))
	}
}

func TestRemoveAndCompaction(t *testing.T) {
	ix := New("m")
	total := compactionMinDead * 3
	for i := 0; i < total; i++ {
		mustUpsert(t, ix, fmt.Sprintf("chat_%d", i), Entry{}, []string{"common", fmt.Sprintf("uniq%d", i)})
	}
	for i := 0; i < total-2; i++ {
		ix.Remove(fmt.Sprintf("chat_%d", i))
	}
	if len(ix.Slots) >= total {
		t.Fatalf("compaction did not shrink slot table: %d slots for %d chats", len(ix.Slots), len(ix.Chats))
	}
	if _, ok := ix.Postings["uniq0"]; ok {
		t.Fatal("compaction kept posting for removed chat")
	}
	got := ix.Search(nil, []string{"common"}, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 survivors, got %+v", got)
	}
	// Survivors must still round-trip through the strict decoder.
	encoded, err := ix.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("compacted index fails decode: %v", err)
	}
}

func TestIDFWeightsRareTokensOverCommonOnes(t *testing.T) {
	ix := New("m")
	// "com" is everywhere; "sacha" appears in exactly one chat.
	for i := 0; i < 20; i++ {
		mustUpsert(t, ix, fmt.Sprintf("noise_%d", i), Entry{}, []string{"com", "example"})
	}
	mustUpsert(t, ix, "target", Entry{}, []string{"com", "gmail", "sacha", "sacha@gmail.com"})

	got := ix.Search(nil, Tokenize("sacha@gmail.com"), 5)
	if len(got) == 0 || got[0].ID != "target" {
		t.Fatalf("expected target chat first, got %+v", resultIDs(got))
	}
	// Every noise chat matches "com", but the rare-token chat must
	// outrank them decisively rather than by tie-break.
	if len(got) > 1 && got[0].Score <= got[1].Score {
		t.Fatalf("rare-token match did not dominate: %+v", got)
	}
}

func TestSearchFusesLexicalAndSemantic(t *testing.T) {
	ix := New("m")
	mustUpsert(t, ix, "ducks", Entry{Vectors: []Vector{Quantize([]float32{1, 0})}}, []string{"duck", "pond"})
	mustUpsert(t, ix, "dogs", Entry{Vectors: []Vector{Quantize([]float32{0.9, 0.44})}}, []string{"dog", "walk"})
	mustUpsert(t, ix, "taxes", Entry{Vectors: []Vector{Quantize([]float32{0, 1})}}, []string{"tax", "return"})

	// Semantic-only query: no token matches, ranking is pure cosine.
	sem := ix.Search([]float32{1, 0}, []string{"animal"}, 3)
	if ids := resultIDs(sem); ids[0] != "ducks" || ids[1] != "dogs" {
		t.Fatalf("semantic ranking wrong: %v", ids)
	}

	// Keyword hit on a semantically distant chat must win: lexical is
	// the dominant fusion tier.
	kw := ix.Search([]float32{1, 0}, []string{"tax"}, 3)
	if ids := resultIDs(kw); ids[0] != "taxes" {
		t.Fatalf("lexical hit did not lead: %v", ids)
	}
}

func TestSemanticMaxSimOverChunks(t *testing.T) {
	ix := New("m")
	// "long" matches on its second chunk; "short" is uniformly mediocre.
	mustUpsert(t, ix, "long", Entry{Vectors: []Vector{Quantize([]float32{0, 1}), Quantize([]float32{1, 0.05})}}, nil)
	mustUpsert(t, ix, "short", Entry{Vectors: []Vector{Quantize([]float32{0.7, 0.7})}}, nil)

	got := ix.Search([]float32{1, 0}, nil, 2)
	if ids := resultIDs(got); ids[0] != "long" {
		t.Fatalf("max-sim did not surface best chunk: %v", ids)
	}
}

func TestSearchLexicalOnlyWhenNoVectors(t *testing.T) {
	ix := New("m")
	mustUpsert(t, ix, "keyword-only", Entry{}, []string{"invoice", "duck"})
	results := ix.Search(nil, []string{"invoice"}, 5)
	if len(results) != 1 || results[0].ID != "keyword-only" {
		t.Fatalf("expected lexical-only hit, got %+v", results)
	}
	if none := ix.Search(nil, []string{"unrelated"}, 5); len(none) != 0 {
		t.Fatalf("expected no hits, got %+v", none)
	}
}
