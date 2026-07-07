package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/searchindex"
)

// rawPost is a goroutine-safe request helper: unlike fixture.post it
// reports failures as errors instead of calling t.Fatal, which must
// not happen off the test goroutine.
func rawPost(f *searchFixture, tok, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, f.server.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	return nil
}

func rawPush(f *searchFixture, tok, id, content string) error {
	plaintext, err := json.Marshal(map[string]any{
		"id": id, "title": "Note",
		"messages": []map[string]any{{"role": "user", "content": content}},
	})
	if err != nil {
		return err
	}
	return rawPost(f, tok, "/v1/sync/push", PushRequest{
		Scope:          "chat",
		ID:             id,
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IdempotencyKey: "idem-" + id,
	})
}

func rawQuery(f *searchFixture, tok, q string) error {
	return rawPost(f, tok, "/v1/search/query", SearchQueryRequest{Key: f.userKeyB64, Query: q})
}

func cacheKeyHash(b byte) [sha256.Size]byte {
	return sha256.Sum256([]byte{b})
}

func TestSearchCacheHitMissAndKeyRotation(t *testing.T) {
	c := newSearchIndexCache(1 << 20)
	ix := searchindex.New("m")
	c.put("alice", cacheKeyHash(1), ix, 100)

	if got, ok := c.get("alice", cacheKeyHash(1)); !ok || got != ix {
		t.Fatal("expected cache hit with matching key")
	}
	if _, ok := c.get("bob", cacheKeyHash(1)); ok {
		t.Fatal("unexpected hit for uncached owner")
	}
	// A different key hash means the CEK rotated: miss, and the stale
	// entry must be gone entirely.
	if _, ok := c.get("alice", cacheKeyHash(2)); ok {
		t.Fatal("rotated key must not hit")
	}
	if _, ok := c.get("alice", cacheKeyHash(1)); ok {
		t.Fatal("stale entry must be evicted after key mismatch")
	}
	if entries, total := c.stats(); entries != 0 || total != 0 {
		t.Fatalf("accounting leak: entries=%d total=%d", entries, total)
	}
}

func TestSearchCacheLRUEviction(t *testing.T) {
	c := newSearchIndexCache(300)
	for i := 0; i < 3; i++ {
		c.put(fmt.Sprintf("user%d", i), cacheKeyHash(1), searchindex.New("m"), 100)
	}
	// Touch user0 so user1 is the least recently used.
	if _, ok := c.get("user0", cacheKeyHash(1)); !ok {
		t.Fatal("user0 should be cached")
	}
	c.put("user3", cacheKeyHash(1), searchindex.New("m"), 100)
	if _, ok := c.get("user1", cacheKeyHash(1)); ok {
		t.Fatal("LRU entry should have been evicted")
	}
	for _, u := range []string{"user0", "user2", "user3"} {
		if _, ok := c.get(u, cacheKeyHash(1)); !ok {
			t.Fatalf("%s should have survived eviction", u)
		}
	}
	if entries, total := c.stats(); entries != 3 || total != 300 {
		t.Fatalf("accounting drift: entries=%d total=%d", entries, total)
	}
}

func TestSearchCacheOversizedAndUpdates(t *testing.T) {
	c := newSearchIndexCache(300)
	c.put("whale", cacheKeyHash(1), searchindex.New("m"), 301)
	if _, ok := c.get("whale", cacheKeyHash(1)); ok {
		t.Fatal("entry above the whole budget must not be cached")
	}

	c.put("alice", cacheKeyHash(1), searchindex.New("m"), 100)
	c.put("alice", cacheKeyHash(1), searchindex.New("m"), 250)
	if entries, total := c.stats(); entries != 1 || total != 250 {
		t.Fatalf("update must replace accounting: entries=%d total=%d", entries, total)
	}
	// Updating an entry to an oversized footprint removes it rather
	// than blowing the budget.
	c.put("alice", cacheKeyHash(1), searchindex.New("m"), 301)
	if entries, total := c.stats(); entries != 0 || total != 0 {
		t.Fatalf("oversized update must evict: entries=%d total=%d", entries, total)
	}

	c.put("alice", cacheKeyHash(1), searchindex.New("m"), 100)
	c.drop("alice")
	c.drop("alice")
	if entries, total := c.stats(); entries != 0 || total != 0 {
		t.Fatalf("drop leak: entries=%d total=%d", entries, total)
	}
}

func TestSearchCacheNilReceiverIsDisabled(t *testing.T) {
	var c *searchIndexCache
	c.put("alice", cacheKeyHash(1), searchindex.New("m"), 100)
	if _, ok := c.get("alice", cacheKeyHash(1)); ok {
		t.Fatal("nil cache must never hit")
	}
	c.drop("alice")
	if entries, total := c.stats(); entries != 0 || total != 0 {
		t.Fatal("nil cache stats must be zero")
	}
}

// TestQueryServedFromCacheWhenBucketDown is the proof the cache
// works: after one push warms it, queries keep succeeding with the
// search sidecar hard down, since nothing needs to be fetched.
func TestQueryServedFromCacheWhenBucketDown(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	f.searchBk.server.Close()

	got := f.query(t, tok, "duck")
	if got.NeedsReindex || got.TotalIndexed != 1 {
		t.Fatalf("cached query degraded: %+v", got)
	}
	if len(got.Results) == 0 || got.Results[0].ID != "chat_duck" {
		t.Fatalf("cached query lost results: %+v", got.Results)
	}
}

// TestCacheNotPoisonedByWrongKeyQuery interleaves queries under a
// rotated key with queries under the real key: the wrong key must
// consistently report needs_reindex, and must not evict or corrupt
// the good state permanently.
func TestCacheNotPoisonedByWrongKeyQuery(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_duck", "Pond", "a duck swam by")

	otherKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	for i := 0; i < 2; i++ {
		resp, body := f.post("/v1/search/query", SearchQueryRequest{Key: otherKey, Query: "duck"}, tok)
		if resp.StatusCode != 200 {
			t.Fatalf("wrong-key query: %d %s", resp.StatusCode, body)
		}
		good := f.query(t, tok, "duck")
		if good.NeedsReindex || good.TotalIndexed != 1 || len(good.Results) == 0 {
			t.Fatalf("wrong-key query poisoned the real key's state: %+v", good)
		}
	}
}

// TestConcurrentPushesAndQueries races readers against writers on the
// shared cached index; run under -race this verifies the RW locking
// around in-place mutation.
func TestConcurrentPushesAndQueries(t *testing.T) {
	f := newSearchFixture(t)
	tok := f.jwt()
	f.pushChat(t, tok, "chat_seed", "Pond", "a duck swam by")

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := rawPush(f, tok, fmt.Sprintf("chat_%d", i), fmt.Sprintf("duck number %d", i)); err != nil {
				errs <- err
			}
		}(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rawQuery(f, tok, "duck"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := f.query(t, tok, "duck"); got.TotalIndexed != n+1 {
		t.Fatalf("lost entries under concurrent load: total=%d", got.TotalIndexed)
	}
}
