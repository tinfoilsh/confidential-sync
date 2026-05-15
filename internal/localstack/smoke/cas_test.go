//go:build smoke

package smoke

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// T06: CAS protects against lost updates.
//
// Adversary model: two browser tabs / two devices push divergent
// edits to the same chat. Without CAS, the later push silently
// overwrites the earlier one and the earlier edit is lost.
//
// Invariant: enclave forwards `if_match` to the controlplane.
// When if_match is stale, controlplane returns 412 STALE_BLOB and
// the enclave (with conflict_policy=reject) propagates that
// upward — never silently overwrites.
//
// Regression caught: a change that strips if_match before forwarding,
// or that suppresses 412 responses, would surface as a silent
// overwrite.
func TestT06_CASPreventsConcurrentOverwrite(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// First push creates the row at etag=1.
	if status, resp := f.push("chat", "C1", []byte(`{"v":"first"}`), nil, "T06-init", ""); status != http.StatusOK || !resp.OK {
		t.Fatalf("init push failed: status=%d body=%s", status, resp.Raw)
	}

	// Second push lands successfully with if_match="1", advancing to etag=2.
	etag1 := "1"
	if status, resp := f.push("chat", "C1", []byte(`{"v":"second"}`), &etag1, "T06-second", ""); status != http.StatusOK || !resp.OK {
		t.Fatalf("second push failed: status=%d body=%s", status, resp.Raw)
	}

	// Third push tries to use the stale etag=1, with conflict_policy=reject.
	// Must NOT silently overwrite. The enclave surfaces STALE_BLOB.
	status, resp := f.push("chat", "C1", []byte(`{"v":"third-stale"}`), &etag1, "T06-stale", "reject")
	if status == http.StatusOK && resp.OK {
		t.Fatalf("CAS broken: stale-etag push succeeded. resp=%s", resp.Raw)
	}
	if !strings.Contains(string(resp.Raw), "STALE_BLOB") {
		t.Fatalf("expected STALE_BLOB in response, got: %s", resp.Raw)
	}

	// Sanity: the row's plaintext is still "second", not "third-stale".
	_, item := f.pullOne("chat", "C1", "")
	if !item.OK {
		t.Fatalf("post-CAS pull failed: %+v", item)
	}
	pt, _ := base64.StdEncoding.DecodeString(item.Plaintext)
	if string(pt) != `{"v":"second"}` {
		t.Fatalf("CAS broken: stored plaintext is %q, expected %q", pt, `{"v":"second"}`)
	}
}

// T07: conflict_policy=replace_remote intentionally overwrites the
// current row regardless of etag.
//
// Why this is a useful test: §16.6 documents the policy semantics
// explicitly. A regression where replace_remote silently degrades
// into reject (e.g. the policy field is dropped before reaching the
// CAS path) would prevent the "I know what I'm doing, overwrite it"
// flow from working.
//
// Adversary model: this is NOT an attack — replace_remote is a
// legitimate user-initiated action. The test asserts the plumbing
// works.
func TestT07_ReplaceRemoteOverwrites(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// Create + bump to etag=2.
	if status, _ := f.push("chat", "C2", []byte(`{"v":"first"}`), nil, "T07-init", ""); status != http.StatusOK {
		t.Fatalf("init push: %d", status)
	}
	etag1 := "1"
	if status, resp := f.push("chat", "C2", []byte(`{"v":"second"}`), &etag1, "T07-second", ""); status != http.StatusOK || !resp.OK {
		t.Fatalf("second push: %s", resp.Raw)
	}

	// Third push with stale etag=1 BUT conflict_policy=replace_remote.
	// Must succeed and overwrite.
	status, resp := f.push("chat", "C2", []byte(`{"v":"third-forced"}`), &etag1, "T07-forced", "replace_remote")
	if status != http.StatusOK || !resp.OK {
		t.Fatalf("replace_remote push failed: status=%d body=%s", status, resp.Raw)
	}

	_, item := f.pullOne("chat", "C2", "")
	if !item.OK {
		t.Fatalf("post-replace pull failed: %+v", item)
	}
	pt, _ := base64.StdEncoding.DecodeString(item.Plaintext)
	if string(pt) != `{"v":"third-forced"}` {
		t.Fatalf("replace_remote did not overwrite: stored plaintext is %q", pt)
	}
}
