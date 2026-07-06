package searchindex

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

func b64Vec(n int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, n))
}

// TestDecodeHostileInputsDoNotPanic feeds Decode the corruption
// classes an attacker (or bit rot) could produce in the stored
// object. Every one must come back as an error; a panic here would
// crash the enclave on a poisoned index.
func TestDecodeHostileInputsDoNotPanic(t *testing.T) {
	cases := map[string]string{
		"entry slot out of range": `{"version":1,"slots":["a"],"chats":{"a":{"slot":5}},"postings":{}}`,
		"entry slot negative":     `{"version":1,"slots":["a"],"chats":{"a":{"slot":-1}},"postings":{}}`,
		"posting slot negative":   `{"version":1,"slots":["a"],"chats":{"a":{"slot":0}},"postings":{"x":[-2]}}`,
		"posting slot too large":  `{"version":1,"slots":["a"],"chats":{"a":{"slot":0}},"postings":{"x":[1]}}`,
		"slot id without entry":   `{"version":1,"slots":["a","b"],"chats":{"a":{"slot":0}},"postings":{}}`,
		"entry without slot row":  `{"version":1,"slots":["a"],"chats":{"a":{"slot":0},"b":{"slot":0}},"postings":{}}`,
		"two ids sharing a slot":  `{"version":1,"slots":["a","b"],"chats":{"a":{"slot":0},"b":{"slot":0}},"postings":{}}`,
		"vector dims mismatch":    `{"version":1,"dims":2,"slots":["a"],"chats":{"a":{"slot":0,"vectors":["` + b64Vec(3) + `"]}},"postings":{}}`,
		"vector without dims":     `{"version":1,"slots":["a"],"chats":{"a":{"slot":0,"vectors":["` + b64Vec(3) + `"]}},"postings":{}}`,
		"empty vector":            `{"version":1,"dims":2,"slots":["a"],"chats":{"a":{"slot":0,"vectors":[""]}},"postings":{}}`,
		"null vector":             `{"version":1,"slots":["a"],"chats":{"a":{"slot":0,"vectors":[null]}},"postings":{}}`,
		"vector not a string":     `{"version":1,"slots":["a"],"chats":{"a":{"slot":0,"vectors":[[1,2]]}},"postings":{}}`,
		"vector invalid base64":   `{"version":1,"slots":["a"],"chats":{"a":{"slot":0,"vectors":["%%%"]}},"postings":{}}`,
		"future version":          `{"version":2,"chats":{}}`,
		"zero version":            `{"version":0,"chats":{}}`,
		"not an object":           `[1,2,3]`,
		"truncated json":          `{"version":1,"chats":{`,
	}
	for name, raw := range cases {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Errorf("%s: expected decode error, got none", name)
		}
	}
}

func TestDecodeAcceptsTombstonesAndEmptyIndex(t *testing.T) {
	empty, err := Decode([]byte(`{"version":1,"chats":{}}`))
	if err != nil {
		t.Fatalf("empty index rejected: %v", err)
	}
	if got := empty.Search(nil, []string{"anything"}, 5); len(got) != 0 {
		t.Fatalf("empty index returned results: %+v", got)
	}
	withDead, err := Decode([]byte(`{"version":1,"slots":["","a",""],"chats":{"a":{"slot":1}},"postings":{"duck":[0,1,2]}}`))
	if err != nil {
		t.Fatalf("tombstoned index rejected: %v", err)
	}
	got := withDead.Search(nil, []string{"duck"}, 5)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("tombstone filtering broken: %+v", got)
	}
}

func TestUpsertDedupesAndIgnoresEmptyTokens(t *testing.T) {
	ix := New("m")
	mustUpsert(t, ix, "a", Entry{}, []string{"duck", "duck", "", "duck", "pond"})
	if got := ix.Postings["duck"]; len(got) != 1 {
		t.Fatalf("duplicate tokens inflated postings: %v", got)
	}
	if _, ok := ix.Postings[""]; ok {
		t.Fatal("empty token stored in postings")
	}
	// Both chats must surface for the shared token regardless of the
	// duplicated input.
	mustUpsert(t, ix, "b", Entry{}, []string{"duck"})
	got := ix.Search(nil, []string{"duck"}, 5)
	if len(got) != 2 {
		t.Fatalf("expected both matches, got %+v", got)
	}
}

func TestUpsertRejectsEmptyID(t *testing.T) {
	if err := New("m").Upsert("", Entry{}, nil); err == nil {
		t.Fatal("expected error for empty id")
	}
}

func TestQuantizeHandlesNonFiniteAndExtremes(t *testing.T) {
	nan := float32(math.NaN())
	inf := float32(math.Inf(1))

	if got := Quantize([]float32{inf, 1}); got[0] != 0 || got[1] != 0 {
		t.Fatalf("Inf input must degrade to zeros, got %v", got)
	}
	if got := Quantize([]float32{nan, 1}); got[0] != 0 || got[1] != 127 {
		t.Fatalf("NaN element must quantize to 0, got %v", got)
	}
	if got := Quantize([]float32{0, 0}); got[0] != 0 || got[1] != 0 {
		t.Fatalf("zero vector: %v", got)
	}
	if got := Quantize([]float32{-1, 1}); got[0] != -127 || got[1] != 127 {
		t.Fatalf("extremes must hit the int8 rails exactly: %v", got)
	}
	// Tiny magnitudes still normalize to full scale (max-abs scaling).
	if got := Quantize([]float32{1e-30, -1e-30}); got[0] != 127 || got[1] != -127 {
		t.Fatalf("tiny vector scaling broken: %v", got)
	}
}

func TestVectorRoundtripFullInt8Range(t *testing.T) {
	v := Vector{-128, -1, 0, 1, 127}
	data, err := v.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Vector
	if err := back.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	for i := range v {
		if v[i] != back[i] {
			t.Fatalf("roundtrip mismatch at %d: %v vs %v", i, v, back)
		}
	}
}

func TestIndexCapEnforced(t *testing.T) {
	ix := New("m")
	for i := 0; i < MaxChats; i++ {
		if err := ix.Upsert(fmt.Sprintf("c%d", i), Entry{}, nil); err != nil {
			t.Fatalf("upsert %d under cap failed: %v", i, err)
		}
	}
	if err := ix.Upsert("one-too-many", Entry{}, nil); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	// Updating an existing chat at the cap must still be allowed.
	if err := ix.Upsert("c0", Entry{}, []string{"updated"}); err != nil {
		t.Fatalf("update at cap rejected: %v", err)
	}
	// And removal must reopen room.
	ix.Remove("c1")
	if err := ix.Upsert("replacement", Entry{}, nil); err != nil {
		t.Fatalf("insert after removal at cap rejected: %v", err)
	}
}

func TestRemoveNonexistentIsNoop(t *testing.T) {
	ix := New("m")
	mustUpsert(t, ix, "a", Entry{}, []string{"duck"})
	before, _ := ix.Encode()
	ix.Remove("never-existed")
	after, _ := ix.Encode()
	if string(before) != string(after) {
		t.Fatal("removing a nonexistent chat mutated the index")
	}
}

func TestSearchEdgeInputs(t *testing.T) {
	ix := New("m")
	for i := 0; i < 5; i++ {
		mustUpsert(t, ix, fmt.Sprintf("c%d", i), Entry{}, []string{"shared"})
	}
	if got := ix.Search(nil, []string{"shared"}, 0); got != nil {
		t.Fatalf("limit 0 must return nil, got %+v", got)
	}
	if got := ix.Search(nil, nil, 10); len(got) != 0 {
		t.Fatalf("no query signal must return nothing, got %+v", got)
	}
	if got := ix.Search(nil, []string{"absent"}, 10); len(got) != 0 {
		t.Fatalf("unmatched token returned results: %+v", got)
	}
	got := ix.Search(nil, []string{"shared"}, 2)
	if len(got) != 2 {
		t.Fatalf("limit not applied: %+v", got)
	}
	// Ordering must be deterministic across runs despite Go's random
	// map iteration (ties break on chat id inside the ranking).
	full := ix.Search(nil, []string{"shared"}, 10)
	for run := 0; run < 5; run++ {
		again := ix.Search(nil, []string{"shared"}, 10)
		for i := range full {
			if full[i] != again[i] {
				t.Fatalf("nondeterministic ordering: %+v vs %+v", full, again)
			}
		}
	}
	// Duplicate query tokens must not double-score.
	dup := ix.Search(nil, []string{"shared", "shared"}, 10)
	if dup[0].Score != full[0].Score {
		t.Fatalf("duplicate query token changed scoring: %v vs %v", dup[0].Score, full[0].Score)
	}
}

func TestSearchSkipsMismatchedQueryVectorDims(t *testing.T) {
	ix := New("m")
	mustUpsert(t, ix, "a", Entry{Vectors: []Vector{{1, 0}}}, []string{"duck"})
	// A query vector with the wrong dimensionality must not panic and
	// must fall back to lexical-only signal.
	got := ix.Search([]float32{1, 0, 0, 0}, []string{"duck"}, 5)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("lexical fallback broken under dims mismatch: %+v", got)
	}
}

func TestTokenizeFiltersAndCaps(t *testing.T) {
	longWord := strings.Repeat("x", maxTokenLen+1)
	okWord := strings.Repeat("y", maxTokenLen)
	toks := Tokenize("a " + longWord + " " + okWord)
	set := map[string]struct{}{}
	for _, tok := range toks {
		set[tok] = struct{}{}
	}
	if _, ok := set["a"]; ok {
		t.Fatal("single-char token not dropped")
	}
	if _, ok := set[longWord]; ok {
		t.Fatal("overlong token not dropped")
	}
	if _, ok := set[okWord]; !ok {
		t.Fatal("max-length token dropped")
	}

	longEmail := strings.Repeat("u", maxIdentifierLen-len("@gmail.com")) + "@gmail.com"
	tooLongEmail := strings.Repeat("u", maxIdentifierLen) + "@gmail.com"
	identToks := Tokenize(longEmail + " " + tooLongEmail)
	identSet := map[string]struct{}{}
	for _, tok := range identToks {
		identSet[tok] = struct{}{}
	}
	if _, ok := identSet[longEmail]; !ok {
		t.Fatal("identifier within cap dropped")
	}
	if _, ok := identSet[tooLongEmail]; ok {
		t.Fatal("overlong identifier kept")
	}

	// Identifiers are extracted before fragments, so the per-chat cap
	// can never evict them even in a huge chat.
	var sb strings.Builder
	for i := 0; i < MaxTokensPerChat+100; i++ {
		fmt.Fprintf(&sb, "word%04d ", i)
	}
	sb.WriteString(" contact sacha@gmail.com")
	capped := Tokenize(sb.String())
	if len(capped) > MaxTokensPerChat {
		t.Fatalf("token cap exceeded: %d", len(capped))
	}
	found := false
	for _, tok := range capped {
		if tok == "sacha@gmail.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("cap evicted the identifier token")
	}

	if got := Tokenize(""); len(got) != 0 {
		t.Fatalf("empty text produced tokens: %v", got)
	}
	if got := Tokenize("!!! ,,, ..."); len(got) != 0 {
		t.Fatalf("punctuation-only text produced tokens: %v", got)
	}
}

// TestChurnCompactionKeepsIndexConsistent hammers a small set of
// chats with repeated updates so compaction fires many times, then
// verifies only the latest generation is findable, the encoded form
// still satisfies the strict decoder, and tombstones stayed bounded.
func TestChurnCompactionKeepsIndexConsistent(t *testing.T) {
	ix := New("m")
	const chats = 10
	const rounds = 150
	for round := 0; round < rounds; round++ {
		for i := 0; i < chats; i++ {
			id := fmt.Sprintf("chat_%d", i)
			mustUpsert(t, ix, id, Entry{}, []string{fmt.Sprintf("gen%d", round), fmt.Sprintf("gen%d_%s", round, id), "common"})
		}
	}
	if len(ix.Chats) != chats {
		t.Fatalf("chat count drifted: %d", len(ix.Chats))
	}
	// Tombstones are bounded by the compaction trigger.
	if len(ix.Slots) > chats+compactionMinDead+1 {
		t.Fatalf("slot table not being compacted: %d slots for %d chats", len(ix.Slots), chats)
	}
	last := rounds - 1
	for i := 0; i < chats; i++ {
		id := fmt.Sprintf("chat_%d", i)
		got := ix.Search(nil, []string{fmt.Sprintf("gen%d_%s", last, id)}, 5)
		if len(got) != 1 || got[0].ID != id {
			t.Fatalf("latest generation of %s not findable: %+v", id, got)
		}
	}
	if got := ix.Search(nil, []string{fmt.Sprintf("gen%d", last-1)}, chats+1); len(got) != 0 {
		t.Fatalf("stale generation still findable: %+v", got)
	}
	encoded, err := ix.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatalf("churned index fails strict decode: %v", err)
	}
}

// TestRandomizedOperationsMaintainInvariants runs a seeded random
// mix of upserts (with and without vectors) and removals, checking
// after every batch that the index round-trips through the strict
// decoder and that search agrees exactly with a naive model of what
// should be live.
func TestRandomizedOperationsMaintainInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	ix := New("m")
	latest := map[string]int{} // live chat id -> current generation
	gen := 0

	randomVec := func() []Vector {
		if rng.Intn(2) == 0 {
			return nil
		}
		v := make([]float32, 4)
		for i := range v {
			v[i] = rng.Float32()*2 - 1
		}
		return []Vector{Quantize(v)}
	}

	verify := func() {
		t.Helper()
		encoded, err := ix.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("random state fails strict decode: %v", err)
		}
		if len(decoded.Chats) != len(latest) {
			t.Fatalf("live count mismatch: index %d, model %d", len(decoded.Chats), len(latest))
		}
		for id, g := range latest {
			tok := fmt.Sprintf("g%d_%s", g, id)
			got := decoded.Search(nil, []string{tok}, 3)
			if len(got) != 1 || got[0].ID != id {
				t.Fatalf("live chat %s (gen %d) not findable after roundtrip: %+v", id, g, got)
			}
			if g > 0 {
				stale := fmt.Sprintf("g%d_%s", g-1, id)
				if got := decoded.Search(nil, []string{stale}, 3); len(got) != 0 {
					t.Fatalf("stale generation of %s findable: %+v", id, got)
				}
			}
		}
	}

	for op := 0; op < 3000; op++ {
		id := fmt.Sprintf("chat_%d", rng.Intn(200))
		if rng.Intn(10) < 7 {
			gen++
			mustUpsert(t, ix, id, Entry{Vectors: randomVec()}, []string{fmt.Sprintf("g%d_%s", gen, id), "common"})
			latest[id] = gen
		} else {
			ix.Remove(id)
			delete(latest, id)
		}
		if op%500 == 499 {
			verify()
		}
	}
	verify()
}
