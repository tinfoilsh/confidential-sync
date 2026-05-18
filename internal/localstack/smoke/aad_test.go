//go:build smoke

package smoke

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// T03: AAD binds to scope — a chat envelope cannot be unsealed when
// presented as a project envelope.
//
// Adversary model: a controlplane bug (or attacker with write
// access) moves a sealed envelope between scope slots, hoping the
// enclave will unseal it under the new scope's identity.
//
// Invariant: AAD includes `scope` (see envelope/aad.go), so
// chat/X envelope at project/X slot → AAD mismatch on unseal →
// AEAD fail.
//
// Regression caught: a change that drops `scope` from CanonicalAAD,
// or accidentally builds the AAD with the wrong scope on the read
// path.
func TestT03_AADBindsScope(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	plaintext := []byte(`{"secret":"chat-only"}`)
	if status, resp := f.push("chat", "X1", plaintext, nil, "T03-push"); status != http.StatusOK || !resp.OK {
		t.Fatalf("push failed: status=%d body=%s", status, resp.Raw)
	}

	// Confirm the chat read works on the legitimate path.
	if status, item := f.pullOne("chat", "X1", ""); status != http.StatusOK || !item.OK {
		t.Fatalf("legitimate pull failed: status=%d item=%+v", status, item)
	}

	// Adversary: copy the chat envelope into the project slot.
	if !f.stack.CP.CopyBlob("chat", "X1", "project", "X1") {
		t.Fatal("copy blob failed")
	}

	// Pull at scope=project must fail — AAD binds to scope.
	status, item := f.pullOne("project", "X1", "")
	if status != http.StatusOK {
		// The enclave returns 200 with item.ok=false on decrypt
		// failure (so a single batch pull can have mixed
		// success/failure). A 5xx here would also be a bug, but
		// our contract is item.ok=false.
		t.Fatalf("unexpected HTTP status: %d", status)
	}
	if item.OK {
		t.Fatalf("AAD scope binding broken: project pull succeeded for a chat envelope. item=%+v", item)
	}
	if item.Plaintext != "" {
		t.Fatalf("AAD scope binding broken: project pull returned plaintext %q for a chat envelope", item.Plaintext)
	}
}

// T04: AAD binds to clerk_user_id — even if user B steals user A's
// CEK and JWT *for user B*, they cannot unseal user A's data.
//
// Adversary model: user B obtains user A's CEK (via a key bundle
// leak, malware, etc.) but only has their own valid JWT. They
// attempt to pull user A's chats.
//
// Invariant: AAD includes `clerk_user_id` (the JWT's `sub` claim).
// Open's AAD on unseal is built from the calling JWT's sub, so
// user B's call to unseal user A's envelope → AAD mismatch.
//
// Regression caught: a change that builds AAD from a request field
// (e.g. metadata.user_id) instead of the verified JWT sub, allowing
// cross-user impersonation if the field is attacker-controlled.
func TestT04_AADBindsUserSub(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// User A (default fixture user) pushes a chat.
	plaintext := []byte(`{"secret":"user-A-only"}`)
	if status, resp := f.push("chat", "X2", plaintext, nil, "T04-push"); status != http.StatusOK || !resp.OK {
		t.Fatalf("user A push failed: status=%d body=%s", status, resp.Raw)
	}

	// Mint user B's JWT with the same stub-CP backing (so user B's
	// pull successfully reaches the stored bytes — the stub does
	// not partition by sub). With AAD binding, the unseal still
	// fails because user B's `sub` is encoded in the AAD that
	// Open will compute.
	tokB, err := f.stack.MintJWT("user_attacker", time.Minute)
	if err != nil {
		t.Fatalf("mint user B jwt: %v", err)
	}

	status, body := f.post("/v1/sync/pull", map[string]any{
		"scope": "chat",
		"ids":   []string{"X2"},
		"keys":  []map[string]any{{"key": f.cekB64}},
	}, tokB)
	if status != http.StatusOK {
		t.Fatalf("unexpected HTTP status: %d body=%s", status, body)
	}
	var resp pullResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if len(resp.Items) == 0 {
		t.Fatalf("no items in pull response: %s", body)
	}
	item := resp.Items[0]
	if item.OK || item.Plaintext != "" {
		t.Fatalf("AAD user-sub binding broken: user B unsealed user A's envelope. item=%+v", item)
	}
}

// T05: AAD binds to id — chat_X envelope cannot be unsealed as
// chat_Y even within the same scope and same user.
//
// Adversary model: a controlplane bug (or attacker with write
// access) swaps two blobs' storage slots, hoping the enclave will
// happily unseal X's bytes when asked for Y.
//
// Invariant: AAD includes `id`, so the swap is detected at unseal
// time.
//
// Regression caught: a change that drops `id` from CanonicalAAD,
// or that uses the storage key (not the canonical id) when
// computing AAD on the read path.
func TestT05_AADBindsID(t *testing.T) {
	t.Helper()
	f := newFixture(t)

	// Push two different chats with distinguishable plaintexts.
	plaintextX := []byte(`{"secret":"X-only"}`)
	plaintextY := []byte(`{"secret":"Y-only"}`)
	if status, _ := f.push("chat", "X3", plaintextX, nil, "T05-pushX"); status != http.StatusOK {
		t.Fatalf("push X failed: %d", status)
	}
	if status, _ := f.push("chat", "Y3", plaintextY, nil, "T05-pushY"); status != http.StatusOK {
		t.Fatalf("push Y failed: %d", status)
	}

	// Adversary swap: overwrite Y's slot with X's bytes.
	xBlob := f.stack.CP.PeekBlob("chat", "X3")
	if xBlob == nil {
		t.Fatal("X blob missing")
	}
	f.stack.CP.SetBlob("chat", "Y3", xBlob.KeyID, xBlob.Body)

	// Pull Y. The bytes are X's envelope, but the AAD will be built
	// for id=Y. Open MUST fail.
	status, item := f.pullOne("chat", "Y3", "")
	if status != http.StatusOK {
		t.Fatalf("unexpected HTTP status: %d", status)
	}
	if item.OK || item.Plaintext != "" {
		t.Fatalf("AAD id binding broken: pulling chat/Y3 returned plaintext after a swap from X3. item=%+v", item)
	}
}


