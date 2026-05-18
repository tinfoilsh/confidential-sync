//go:build smoke

package smoke

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

// T08: §16.6 — `Delete(if_match=null)` retries on a concurrent push.
//
// This regression-tests the P1 fix landed in commit `8cfbc8c`. Without
// the retry loop, a one-shot delete from the UI can be silently
// dropped: the enclave does GetBlob to learn the current etag, then
// DeleteBlob with that etag; if a push from another tab lands
// between those two calls, the DELETE returns STALE_BLOB and the
// user's "delete this chat" intent vanishes.
//
// The fix: the enclave's Delete loops up to N times on STALE_BLOB
// when the caller passed if_match=null, refetching the current etag
// each iteration.
//
// Adversary model: a malicious or buggy concurrent writer races
// the enclave's GET-then-DELETE sequence.
//
// How we drive the race: the stub controlplane exposes a one-shot
// hook `OnFirstGet(scope, id, fn)` that fires while holding the
// stub's mutex during the GET. The hook does a concurrent push
// (bumping etag); the enclave's subsequent DELETE sees a stale
// if_match, retries, succeeds.
//
// Regression caught: removing the retry loop, or shrinking
// retryMax below 1, would make this test fail because the FIRST
// DELETE returns STALE_BLOB and is propagated to the client.
func TestT08_DeleteNullIfMatchRetriesOnRace(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// Push the row at etag=1.
	if status, resp := f.push("chat", "D1", []byte(`{"v":"orig"}`), nil, "T08-init"); status != http.StatusOK || !resp.OK {
		t.Fatalf("init push failed: status=%d body=%s", status, resp.Raw)
	}

	// Wire up the race: when the stub receives the FIRST DELETE for
	// chat/D1 — i.e. after the enclave has already done its GetBlob
	// (which read etag=1) and is now sending DeleteBlob with
	// if_match=1 — race in a concurrent push that bumps the etag to
	// 2. The stub then evaluates if_match=1 vs current=2 and returns
	// STALE_BLOB. The enclave's retry loop MUST re-fetch and try
	// again with the new etag.
	var hookFired sync.WaitGroup
	hookFired.Add(1)
	f.stack.CP.OnFirstDelete("chat", "D1", func() {
		defer hookFired.Done()
		etag1 := "1"
		if status, resp := f.push("chat", "D1", []byte(`{"v":"raced"}`), &etag1, "T08-race"); status != http.StatusOK || !resp.OK {
			t.Errorf("racing push failed: status=%d body=%s", status, resp.Raw)
		}
	})

	// Issue the delete with if_match=null. The retry loop must
	// survive the one race and ultimately succeed.
	status, body := f.deleteRow("chat", "D1", nil, "T08-del")
	hookFired.Wait()
	if status != http.StatusOK {
		t.Fatalf("delete(if_match=null) was dropped by a single concurrent push (§16.6 retry regression). status=%d body=%s", status, body)
	}
	var ok struct {
		OK bool `json:"ok"`
	}
	_ = json.Unmarshal(body, &ok)
	if !ok.OK {
		t.Fatalf("delete returned non-ok body: %s", body)
	}

	// Sanity: the row is actually gone.
	if blob := f.stack.CP.PeekBlob("chat", "D1"); blob != nil {
		t.Fatalf("delete reported ok but blob is still present: %+v", blob)
	}
}
