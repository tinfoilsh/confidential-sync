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
// Invariant: the enclave forwards `if_match` to the controlplane.
// When if_match is stale, the controlplane returns 412 STALE_BLOB
// and the enclave surfaces 409 SYNC_CONFLICT to the caller. The
// enclave never merges and never silently overwrites — conflict
// resolution is a client-UI decision (keep mine / keep theirs /
// discard local).
//
// Regression caught: a change that strips if_match before forwarding,
// suppresses the 412, or re-introduces a server-side merge would
// surface as a silent overwrite here.
func TestT06_CASPreventsConcurrentOverwrite(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// First push creates the row at etag=1.
	if status, resp := f.push("chat", "C1", []byte(`{"v":"first"}`), nil, "T06-init"); status != http.StatusOK || !resp.OK {
		t.Fatalf("init push failed: status=%d body=%s", status, resp.Raw)
	}

	// Second push lands successfully with if_match="1", advancing to etag=2.
	etag1 := "1"
	if status, resp := f.push("chat", "C1", []byte(`{"v":"second"}`), &etag1, "T06-second"); status != http.StatusOK || !resp.OK {
		t.Fatalf("second push failed: status=%d body=%s", status, resp.Raw)
	}

	// Third push tries to use the stale etag=1. The enclave surfaces
	// 409 SYNC_CONFLICT — it must NOT silently overwrite.
	status, resp := f.push("chat", "C1", []byte(`{"v":"third-stale"}`), &etag1, "T06-stale")
	if status == http.StatusOK && resp.OK {
		t.Fatalf("CAS broken: stale-etag push succeeded. resp=%s", resp.Raw)
	}
	if status != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", status, resp.Raw)
	}
	if !strings.Contains(string(resp.Raw), "SYNC_CONFLICT") {
		t.Fatalf("expected SYNC_CONFLICT in response, got: %s", resp.Raw)
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
