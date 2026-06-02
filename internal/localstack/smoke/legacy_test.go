//go:build smoke

package smoke

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// injectV0 injects a legacy v0 envelope into the stub at (scope, id),
// sealed under the fixture's CEK with NO AAD (legacy semantics).
// Returns the plaintext so the test can compare round-trip.
func injectV0(t *testing.T, f *fixture, scope, id string, plaintext []byte) {
	t.Helper()
	nonce, ct, err := crypto.Seal(f.cek, plaintext, nil)
	if err != nil {
		t.Fatalf("seal v0: %v", err)
	}
	envBody, err := json.Marshal(map[string]string{
		"iv":   base64.StdEncoding.EncodeToString(nonce),
		"data": base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		t.Fatalf("marshal v0: %v", err)
	}
	f.stack.CP.SetBlob(scope, id, f.cekKID, envBody)
}

// T12: pulling a legacy v0 blob returns plaintext and promotes the
// row to v2 inline. This is the v2-path's "I can read it and make
// future reads use authenticated AAD" path — NOT a silent failure,
// NOT a fake "Encrypted" placeholder.
//
// Adversary model: not strictly an attack — this is the user-journey
// where a pre-cutover blob still lives in the controlplane and the
// post-cutover client needs to read it without crashing.
//
// Invariant: the enclave's Pull path delegates to DecryptLegacy on
// non-v2 envelope shapes; success returns plaintext and, when the
// controlplane rewrap succeeds, needs_rewrap=false.
//
// Regression caught: removing the DecryptLegacy fallback (e.g.
// because someone "cleaned up" v0/v1 support) would surface as
// ok:false for users who haven't yet migrated; losing inline rewrap
// would leave needs_rewrap=true.
func TestT12_LegacyV0BlobInlineRewrapsOnPull(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	plaintext := []byte(`{"id":"legacy_1","title":"old format"}`)
	injectV0(t, f, "chat", "legacy_1", plaintext)

	status, item := f.pullOne("chat", "legacy_1", "")
	if status != http.StatusOK {
		t.Fatalf("unexpected HTTP status: %d", status)
	}
	if !item.OK {
		t.Fatalf("legacy v0 pull failed: %+v", item)
	}
	if item.NeedsRewrap {
		t.Fatalf("legacy v0 pull should inline-rewrap, got %+v", item)
	}
	gotPT, err := base64.StdEncoding.DecodeString(item.Plaintext)
	if err != nil {
		t.Fatalf("decode pt: %v", err)
	}
	if string(gotPT) != string(plaintext) {
		t.Fatalf("plaintext round-trip mismatch: got %q want %q", gotPT, plaintext)
	}

	// `needs_rewrap=false` alone does not prove the row was actually
	// promoted — the field is also false on a hypothetical future
	// regression that suppresses the flag without rewriting the
	// blob. Verify the stored bytes are now a v2 envelope so the
	// next pull skips the legacy decrypt path entirely.
	stored := f.stack.CP.PeekBlob("chat", "legacy_1")
	if stored == nil {
		t.Fatalf("blob disappeared after legacy pull")
	}
	res, err := envelope.DecryptV2(stored.Body, []envelope.Key{{Bytes: f.cek, KeyIDHex: f.cekKID}}, envelope.AAD{
		Scope:       envelope.ScopeChat,
		ID:          "legacy_1",
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatalf("expected promoted blob to be a valid v2 envelope: %v; body=%s", err, stored.Body)
	}
	if string(res.Plaintext) != string(plaintext) {
		t.Fatalf("promoted v2 plaintext mismatch: got %q want %q", res.Plaintext, plaintext)
	}
}

// T13: migrate transforms a legacy v0 blob into a v2 envelope under
// a target CEK without altering the plaintext.
//
// Adversary model: not an attack — this is the migration user
// journey, but a corruption regression would surface as different
// plaintext after migration.
//
// Invariant: the enclave reads the v0 blob using the source key,
// re-seals it with the target key + scope/id/user-bound AAD, and
// writes it back via /api/sync/rewrap. The plaintext is unchanged.
//
// Regression caught: a refactor that, say, double-seals or
// re-encodes the plaintext as JSON instead of preserving raw bytes
// would surface here.
func TestT13_MigrateLegacyToV2Roundtrip(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	original := []byte(`{"id":"legacy_2","title":"migrate me","unicode":"héllo"}`)
	injectV0(t, f, "chat", "legacy_2", original)

	// Mint a fresh target CEK to migrate under. The migrate flow
	// re-seals using this key + new AAD.
	targetKey := make([]byte, crypto.KeySize)
	if _, err := rand.Read(targetKey); err != nil {
		t.Fatalf("rand target key: %v", err)
	}
	targetB64 := base64.StdEncoding.EncodeToString(targetKey)

	status, body := f.migrate("chat", []string{"legacy_2"}, targetB64)
	if status != http.StatusOK {
		t.Fatalf("migrate failed: status=%d body=%s", status, body)
	}
	var mresp struct {
		Migrated          int      `json:"migrated"`
		BlockedUnmigrated int      `json:"blocked_unmigrated"`
		Blocked           []string `json:"blocked"`
	}
	if err := json.Unmarshal(body, &mresp); err != nil {
		t.Fatalf("decode migrate response: %v", err)
	}
	if mresp.Migrated != 1 {
		t.Fatalf("expected migrated=1, got %+v body=%s", mresp, body)
	}

	// Sanity: the stored blob is now a v2 envelope, not a v0 object.
	stored := f.stack.CP.PeekBlob("chat", "legacy_2")
	if stored == nil {
		t.Fatal("blob disappeared after migrate")
	}
	if !contains(stored.Body, []byte(`"v":2`)) {
		t.Fatalf("after migrate, stored blob is not a v2 envelope: %s", stored.Body)
	}

	// Pull with the target key (NOT the fixture's CEK) — the
	// re-seal targeted the new key.
	status, item := f.pullOne("chat", "legacy_2", targetB64)
	if status != http.StatusOK || !item.OK {
		t.Fatalf("post-migrate pull failed: status=%d item=%+v", status, item)
	}
	if item.NeedsRewrap {
		t.Fatalf("post-migrate pull should NOT need rewrap, got %+v", item)
	}
	gotPT, err := base64.StdEncoding.DecodeString(item.Plaintext)
	if err != nil {
		t.Fatalf("decode pt: %v", err)
	}
	if string(gotPT) != string(original) {
		t.Fatalf("plaintext NOT preserved across migrate: got %q want %q", gotPT, original)
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
