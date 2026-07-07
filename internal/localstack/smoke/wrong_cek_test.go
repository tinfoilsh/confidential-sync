//go:build smoke

package smoke

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// T14: pulling with a wrong CEK MUST return ok:false with no
// plaintext field — never a panic, never a 5xx, never partial bytes.
//
// Adversary model: a buggy or malicious client supplies the wrong
// CEK (e.g. a stale key, or a random 32 bytes).
//
// Invariants:
// 1. No 5xx — the enclave handles wrong-key gracefully.
// 2. ok:false at the item level (200 at HTTP, ok:false in body).
// 3. No plaintext field present — even partial bytes from a failed
//    GCM Open would be a catastrophic info leak.
// 4. The error code (if present) is informative but does NOT include
//    sensitive material like the ciphertext or expected KID.
//
// Regression caught: a refactor that surfaces the raw AEAD error
// path with `item.Plaintext = base64(partialBytes)` (which is what
// happens with naive cipher.Stream constructs that have no AEAD
// integrity check) would set Plaintext to garbage. Or a wrong-key
// regression that 500s instead of returning ok:false would surface
// here.
func TestT14_PullWrongCEKReturnsOKFalseNoPlaintext(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	plaintext := []byte(`{"secret":"sealed under fixture CEK"}`)
	if status, resp := f.push("chat", "W1", plaintext, nil, "T14-push"); status != http.StatusOK || !resp.OK {
		t.Fatalf("push failed: status=%d body=%s", status, resp.Raw)
	}

	// Sanity: the legitimate pull works.
	if status, item := f.pullOne("chat", "W1", ""); status != http.StatusOK || !item.OK {
		t.Fatalf("legitimate pull failed: status=%d item=%+v", status, item)
	}

	// Adversary path: 100 random CEKs in a row. None should leak
	// plaintext, none should 500, none should panic the enclave.
	successCount := 0
	for i := 0; i < 100; i++ {
		wrong := make([]byte, crypto.KeySize)
		if _, err := rand.Read(wrong); err != nil {
			t.Fatalf("rand: %v", err)
		}
		wrongB64 := base64.StdEncoding.EncodeToString(wrong)

		status, item := f.pullOne("chat", "W1", wrongB64)
		if status >= 500 {
			t.Fatalf("wrong-CEK pull caused 5xx: status=%d", status)
		}
		if status != http.StatusOK {
			t.Fatalf("wrong-CEK pull unexpected status: %d", status)
		}
		if item.OK {
			successCount++
			t.Errorf("wrong-CEK pull #%d returned OK with plaintext=%q (AEAD bypass)", i, item.Plaintext)
		}
		if item.Plaintext != "" {
			t.Errorf("wrong-CEK pull #%d returned plaintext field %q despite ok=false", i, item.Plaintext)
		}
	}
	if successCount > 0 {
		t.Fatalf("AEAD broken: %d/100 random CEKs unsealed the ciphertext", successCount)
	}
}
