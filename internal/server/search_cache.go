package server

import (
	"container/list"
	"crypto/sha256"
	"sync"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/searchindex"
)

// searchCacheBudgetBytes bounds the decoded-index cache. Accounting
// uses the encoded JSON size of each index as the footprint proxy;
// the in-memory structures run a small constant factor (~2-3x)
// larger, so 4 GiB of accounting is on the order of 10 GiB resident
// in the worst case, comfortable for a 32 GiB enclave. In practice indices
// are a few MB, so effectively every active user stays cached and
// eviction only kicks in under extreme aggregate load.
const searchCacheBudgetBytes = 4 << 30

type searchCacheEntry struct {
	owner   string
	ix      *searchindex.Index
	keyHash [sha256.Size]byte
	size    int
}

// searchIndexCache keeps decoded search indices in memory between
// requests so the hot path skips the sidecar GET, gunzip, and decode
// on every operation. LRU-evicted under a byte budget.
//
// Coherence model: this process is the only writer of index objects
// (per-user RW locks serialize all mutations), so a cached index can
// only go stale if the stored object is changed out-of-band. Entries
// are bound to a hash of the encryption key they were loaded under,
// so a CEK rotation is detected as a mismatch and falls through to
// storage. All methods are safe on a nil receiver (cache disabled).
type searchIndexCache struct {
	mu      sync.Mutex
	budget  int
	total   int
	lru     *list.List // front = most recently used
	byOwner map[string]*list.Element
}

func newSearchIndexCache(budget int) *searchIndexCache {
	return &searchIndexCache{
		budget:  budget,
		lru:     list.New(),
		byOwner: make(map[string]*list.Element),
	}
}

// get returns the cached index for owner if it was cached under the
// same key. A key-hash mismatch means the CEK rotated: the stale
// entry is dropped and the caller falls through to storage.
func (c *searchIndexCache) get(owner string, keyHash [sha256.Size]byte) (*searchindex.Index, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byOwner[owner]
	if !ok {
		return nil, false
	}
	ent := el.Value.(*searchCacheEntry)
	if ent.keyHash != keyHash {
		c.removeLocked(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return ent.ix, true
}

func (c *searchIndexCache) put(owner string, keyHash [sha256.Size]byte, ix *searchindex.Index, size int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byOwner[owner]; ok {
		c.removeLocked(el)
	}
	if size > c.budget {
		return
	}
	ent := &searchCacheEntry{owner: owner, ix: ix, keyHash: keyHash, size: size}
	c.byOwner[owner] = c.lru.PushFront(ent)
	c.total += size
	for c.total > c.budget {
		c.removeLocked(c.lru.Back())
	}
}

func (c *searchIndexCache) drop(owner string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byOwner[owner]; ok {
		c.removeLocked(el)
	}
}

func (c *searchIndexCache) removeLocked(el *list.Element) {
	ent := c.lru.Remove(el).(*searchCacheEntry)
	delete(c.byOwner, ent.owner)
	c.total -= ent.size
}

func (c *searchIndexCache) stats() (entries, totalBytes int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byOwner), c.total
}
