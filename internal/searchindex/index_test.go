package searchindex

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestTokenizeNormalizesAndDedupes(t *testing.T) {
	got := Tokenize("The DUCK swam; the duck quacked! 42 x " + strings.Repeat("y", 50))
	want := []string{"42", "duck", "quacked", "swam", "the"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Tokenize = %v, want %v", got, want)
	}
}

func TestVectorAndTokensJSONRoundtrip(t *testing.T) {
	ix := New("test-model")
	if err := ix.Upsert("chat_1", Entry{Vector: Vector{25, -100, 127}, Tokens: TokenSet{"duck", "pond"}}); err != nil {
		t.Fatal(err)
	}
	encoded, err := ix.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"duck pond"`) {
		t.Fatalf("tokens not packed as one string: %s", encoded)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	e := decoded.Chats["chat_1"]
	if !reflect.DeepEqual(e.Vector, Vector{25, -100, 127}) {
		t.Fatalf("vector roundtrip mismatch: %v", e.Vector)
	}
	if !reflect.DeepEqual(e.Tokens, TokenSet{"duck", "pond"}) {
		t.Fatalf("tokens roundtrip mismatch: %v", e.Tokens)
	}
	if decoded.Dims != 3 || !decoded.Compatible("test-model") {
		t.Fatalf("dims/model mismatch: dims=%d model=%q", decoded.Dims, decoded.Model)
	}
}

func TestQuantizePreservesDirection(t *testing.T) {
	q := Quantize([]float32{0.5, -0.25, 0, 1.0})
	want := Vector{64, -32, 0, 127}
	if !reflect.DeepEqual(q, want) {
		t.Fatalf("Quantize = %v, want %v", q, want)
	}
	if got := Quantize(nil); got != nil {
		t.Fatalf("Quantize(nil) = %v, want nil", got)
	}
	if got := Quantize([]float32{0, 0}); !reflect.DeepEqual(got, Vector{0, 0}) {
		t.Fatalf("Quantize(zero) = %v", got)
	}

	// Cosine ranking survives quantization: a near-duplicate of the
	// query must stay ahead of an orthogonal vector.
	ix := New("m")
	if err := ix.Upsert("close", Entry{Vector: Quantize([]float32{0.99, 0.14})}); err != nil {
		t.Fatal(err)
	}
	if err := ix.Upsert("far", Entry{Vector: Quantize([]float32{0.01, 0.99})}); err != nil {
		t.Fatal(err)
	}
	results := ix.Search([]float32{1, 0}, nil, 2)
	if len(results) != 2 || results[0].ID != "close" {
		t.Fatalf("quantized ranking broken: %+v", results)
	}
}

func TestDecodeRejectsUnknownVersion(t *testing.T) {
	if _, err := Decode([]byte(`{"version":99,"chats":{}}`)); err != ErrFormat {
		t.Fatalf("expected ErrFormat, got %v", err)
	}
	if _, err := Decode([]byte(`not json`)); err == nil {
		t.Fatal("expected decode error for malformed input")
	}
}

func TestUpsertRejectsMismatchedDims(t *testing.T) {
	ix := New("m")
	if err := ix.Upsert("a", Entry{Vector: Vector{1, 0}}); err != nil {
		t.Fatal(err)
	}
	if err := ix.Upsert("b", Entry{Vector: Vector{1, 0, 0}}); err == nil {
		t.Fatal("expected dim mismatch error")
	}
}

func TestSearchRanksBySimilarityWithLexicalBoost(t *testing.T) {
	ix := New("m")
	mustUpsert := func(id string, e Entry) {
		t.Helper()
		if err := ix.Upsert(id, e); err != nil {
			t.Fatal(err)
		}
	}
	mustUpsert("ducks", Entry{Vector: Quantize([]float32{1, 0}), Tokens: TokenSet{"duck", "pond"}})
	mustUpsert("dogs", Entry{Vector: Quantize([]float32{0.9, float32(math.Sqrt(1 - 0.81))}), Tokens: TokenSet{"dog", "walk"}})
	mustUpsert("taxes", Entry{Vector: Quantize([]float32{0, 1}), Tokens: TokenSet{"tax", "return"}})

	results := ix.Search([]float32{1, 0}, []string{"animal"}, 2)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].ID != "ducks" || results[1].ID != "dogs" {
		t.Fatalf("unexpected ranking: %+v", results)
	}
	if results[0].Score <= results[1].Score {
		t.Fatalf("scores not descending: %+v", results)
	}

	// A lexical hit boosts an otherwise semantically distant entry.
	boosted := ix.Search([]float32{1, 0}, []string{"tax"}, 3)
	var taxScore, dogScore float64
	for _, r := range boosted {
		switch r.ID {
		case "taxes":
			taxScore = r.Score
		case "dogs":
			dogScore = r.Score
		}
	}
	plain := ix.Search([]float32{1, 0}, nil, 3)
	for _, r := range plain {
		if r.ID == "taxes" && taxScore <= r.Score {
			t.Fatalf("lexical boost did not raise tax score: boosted=%f plain=%f", taxScore, r.Score)
		}
	}
	if dogScore == 0 {
		t.Fatal("semantic-only entry missing from boosted results")
	}
}

func TestSearchLexicalOnlyWhenNoVector(t *testing.T) {
	ix := New("m")
	if err := ix.Upsert("keyword-only", Entry{Tokens: TokenSet{"invoice", "duck"}}); err != nil {
		t.Fatal(err)
	}
	results := ix.Search(nil, []string{"invoice"}, 5)
	if len(results) != 1 || results[0].ID != "keyword-only" {
		t.Fatalf("expected lexical-only hit, got %+v", results)
	}
	if none := ix.Search(nil, []string{"unrelated"}, 5); len(none) != 0 {
		t.Fatalf("expected no hits, got %+v", none)
	}
}
