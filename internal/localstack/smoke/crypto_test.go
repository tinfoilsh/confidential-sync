//go:build smoke

package smoke

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"
)

// T01: ciphertext at rest reveals nothing about plaintext.
//
// Adversary model: an attacker with read access to the controlplane's
// blob storage (e.g. compromised DB read replica) tries to recover
// plaintext by grepping the stored bytes for known substrings.
//
// Invariant: the v2 envelope's `ct` field is AES-GCM ciphertext, so
// the plaintext substring MUST NOT appear anywhere in the stored
// blob body.
//
// Regression caught: a change that, say, accidentally JSON-encoded the
// plaintext alongside the envelope (debug logging, "metadata" leakage)
// would surface as the substring appearing in the stored bytes.
func TestT01_CiphertextHidesPlaintext(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// A high-entropy needle that, if it appears in the stored blob,
	// can only have come from the plaintext (collision probability
	// across random bytes is negligible at 32 chars).
	needle := []byte("MARKER_d3a8f1c92b704e6c8a55_NEEDLE")
	plaintext := []byte(`{"id":"chat_1","title":"hi","body":"` + string(needle) + `"}`)

	if status, resp := f.push("chat", "chat_1", plaintext, nil, "T01-push"); status != http.StatusOK || !resp.OK {
		t.Fatalf("push failed: status=%d body=%s", status, resp.Raw)
	}

	stored := f.stack.CP.PeekBlob("chat", "chat_1")
	if stored == nil {
		t.Fatal("stub did not record blob")
	}
	if bytes.Contains(stored.Body, needle) {
		t.Fatalf("stored ciphertext contains plaintext needle %q; bytes=%q", needle, stored.Body)
	}
	// Sanity: also ensure the stored body is shaped like a v2 envelope.
	if !bytes.HasPrefix(bytes.TrimSpace(stored.Body), []byte("{")) {
		t.Fatalf("stored body is not JSON: %q", stored.Body)
	}
	if !bytes.Contains(stored.Body, []byte(`"v":2`)) {
		t.Fatalf("stored body is not a v2 envelope: %q", stored.Body)
	}
}

// T02: AEAD integrity — any single-byte mutation of stored ciphertext
// makes the pull fail; the enclave never returns garbage plaintext.
//
// Adversary model: an attacker with WRITE access to the controlplane's
// blob storage tries to subtly mutate a stored envelope (e.g. flip
// one bit in the ciphertext to change "approved":true to "approved":false).
//
// Invariant: AES-GCM authenticates the ciphertext + AAD; any
// modification → Open fails → pull returns ok:false.
//
// This test mutates each byte of the stored body in turn and asserts
// the pull never succeeds. Doing the full body (not just `ct`) also
// catches a regression where the enclave was sloppy parsing the
// envelope JSON and ignored unauthenticated fields it shouldn't.
func TestT02_TamperedCiphertextRejected(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	plaintext := []byte(`{"id":"chat_2","title":"original"}`)
	if status, resp := f.push("chat", "chat_2", plaintext, nil, "T02-push"); status != http.StatusOK || !resp.OK {
		t.Fatalf("push failed: status=%d body=%s", status, resp.Raw)
	}

	original := f.stack.CP.PeekBlob("chat", "chat_2")
	if original == nil {
		t.Fatal("stub did not record blob")
	}

	// Confirm the unmodified blob round-trips.
	if status, item := f.pullOne("chat", "chat_2", ""); status != http.StatusOK || !item.OK {
		t.Fatalf("unmodified pull failed: status=%d item=%+v", status, item)
	}

	// Mutate every byte and assert the pull rejects each variant.
	// Sample step >1 keeps runtime bounded for large bodies; for
	// typical 200-byte envelopes this exhaustively checks all bytes.
	step := 1
	if len(original.Body) > 512 {
		step = len(original.Body) / 256 // ~256 samples
	}
	leaked := 0
	for i := 0; i < len(original.Body); i += step {
		mutated := append([]byte(nil), original.Body...)
		mutated[i] ^= 0x01

		f.stack.CP.SetBlob("chat", "chat_2", original.KeyID, mutated)

		_, item := f.pullOne("chat", "chat_2", "")
		if item.OK {
			leaked++
			// If decoding succeeded, the plaintext MUST not be the
			// original — but even returning a different plaintext
			// would be a catastrophic AEAD bypass, so just record.
			pt, _ := base64.StdEncoding.DecodeString(item.Plaintext)
			t.Errorf("AEAD bypass at byte %d: enclave returned plaintext %q after tampering original byte 0x%02x", i, pt, original.Body[i])
		}
	}
	if leaked > 0 {
		t.Fatalf("AEAD integrity broken: %d byte-mutations decrypted successfully", leaked)
	}
}
