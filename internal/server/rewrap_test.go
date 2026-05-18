package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// sealLegacyChatBlob emits the v0 envelope shape (`{iv, data}` JSON)
// that the enclave's DecryptLegacy path accepts. Mirrors the legacy
// webapp serializer.
func sealLegacyChatBlob(t *testing.T, key, pt []byte) []byte {
	t.Helper()
	nonce, ct, err := cryptopkg.Seal(key, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"iv":   base64.StdEncoding.EncodeToString(nonce),
		"data": base64.StdEncoding.EncodeToString(ct),
	})
	return body
}

// encryptAttachmentLegacy mirrors the webapp's encryptAttachment:
// [12-byte IV || AES-GCM(ct||tag)], no AAD.
func encryptAttachmentLegacy(t *testing.T, key, pt []byte) []byte {
	t.Helper()
	iv := make([]byte, attachmentIVLen)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, iv, pt, nil)
	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out
}

// TestPullRewrapsLegacyBareChat exercises the inline rewrap path:
// pulling a v0 chat with no attachments should return plaintext +
// needs_rewrap=false, and the controlplane row should be a v2
// envelope afterwards. No opt-in flags — the enclave always rewraps
// when it can.
func TestPullRewrapsLegacyBareChat(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	chatJSON := []byte(`{"id":"c1","messages":[]}`)
	f.cp.mu.Lock()
	f.cp.blobs["chat/c1"] = &cpBlob{ETag: 1, Body: sealLegacyChatBlob(t, f.userKey, chatJSON)}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/sync/pull", PullRequest{
		Scope: "chat",
		IDs:   []string{"c1"},
		Keys:  []PullKey{{Key: f.userKeyB64}},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull: %d %s", resp.StatusCode, body)
	}
	var pr PullResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatal(err)
	}
	if len(pr.Items) != 1 || !pr.Items[0].OK {
		t.Fatalf("items: %+v", pr.Items)
	}
	if pr.Items[0].NeedsRewrap {
		t.Fatalf("expected needs_rewrap=false after auto-rewrap")
	}
	got, err := base64.StdEncoding.DecodeString(pr.Items[0].Plaintext)
	if err != nil || string(got) != string(chatJSON) {
		t.Fatalf("plaintext mismatch: %s err=%v", got, err)
	}

	f.cp.mu.Lock()
	after := f.cp.blobs["chat/c1"].Body
	f.cp.mu.Unlock()
	if envelope.Detect(after) != envelope.VersionV2 {
		t.Fatalf("blob still legacy after auto-rewrap: %s", after)
	}
}

// TestPullRewrapsAttachmentCascade exercises the lazy attachment
// migration: a v1 chat whose plaintext references a legacy attachment
// (with an embedded `encryptionKey`) should, after pull, produce a
// buckets entry under the CEK-derived token AND a v2 chat envelope
// whose plaintext no longer carries the encryption key.
func TestPullRewrapsAttachmentCascade(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	// Plant a legacy attachment ciphertext in the cp stub.
	attID := "att_abc"
	attKey := make([]byte, 32)
	if _, err := rand.Read(attKey); err != nil {
		t.Fatal(err)
	}
	attPT := []byte("a tiny image's bytes")
	f.cp.mu.Lock()
	f.cp.legacyAttachments = map[string][]byte{
		attID: encryptAttachmentLegacy(t, attKey, attPT),
	}
	f.cp.mu.Unlock()

	// Plant a v0 chat that references the attachment.
	chat := map[string]any{
		"id": "c1",
		"messages": []any{
			map[string]any{
				"id":   "m1",
				"role": "user",
				"attachments": []any{
					map[string]any{
						"id":            attID,
						"type":          "image",
						"encryptionKey": base64.StdEncoding.EncodeToString(attKey),
					},
				},
			},
		},
	}
	chatBytes, _ := json.Marshal(chat)
	f.cp.mu.Lock()
	f.cp.blobs["chat/c1"] = &cpBlob{ETag: 1, Body: sealLegacyChatBlob(t, f.userKey, chatBytes)}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/sync/pull", PullRequest{
		Scope: "chat", IDs: []string{"c1"},
		Keys: []PullKey{{Key: f.userKeyB64}},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull: %d %s", resp.StatusCode, body)
	}
	var pr PullResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatal(err)
	}
	if pr.Items[0].NeedsRewrap {
		t.Fatalf("expected needs_rewrap=false")
	}

	// Buckets should now hold an entry under the attachment id.
	if !f.bk.has(attID) {
		t.Fatalf("attachment was not uploaded to buckets under id %q", attID)
	}

	// Controlplane should know the attachment is v2-owned now.
	f.cp.mu.Lock()
	cid, registered := f.cp.attachmentIndex[attID]
	_, legacyStill := f.cp.legacyAttachments[attID]
	f.cp.mu.Unlock()
	if !registered || cid != "c1" {
		t.Fatalf("attachment index not updated: %v %q", registered, cid)
	}
	if legacyStill {
		t.Fatalf("legacy attachment row should be cleared")
	}

	// The stored v2 envelope must decrypt to a plaintext that no
	// longer carries encryptionKey on the migrated attachment, so
	// future reads through the v2 path won't fall back into the
	// legacy branch on the webapp.
	f.cp.mu.Lock()
	afterBlob := append([]byte(nil), f.cp.blobs["chat/c1"].Body...)
	f.cp.mu.Unlock()
	if envelope.Detect(afterBlob) != envelope.VersionV2 {
		t.Fatalf("stored row not v2: %s", afterBlob)
	}
	dec, err := envelope.DecryptV2(afterBlob, []envelope.Key{{Bytes: f.userKey, KeyIDHex: f.userKeyID}}, func(kid string) ([]byte, error) {
		return envelope.CanonicalAAD(envelope.AAD{
			KeyIDHex:    kid,
			Scope:       envelope.ScopeChat,
			ID:          "c1",
			ClerkUserID: f.userSub,
		})
	})
	if err != nil {
		t.Fatalf("decrypt stored v2: %v", err)
	}
	var newChat map[string]any
	if err := json.Unmarshal(dec.Plaintext, &newChat); err != nil {
		t.Fatal(err)
	}
	msg := newChat["messages"].([]any)[0].(map[string]any)
	att := msg["attachments"].([]any)[0].(map[string]any)
	if _, has := att["encryptionKey"]; has {
		t.Fatalf("encryptionKey was not stripped after cascade: %#v", att)
	}
}

// TestDeleteChatCascadesAttachmentsToBuckets confirms that deleting a
// v2 chat through the enclave wipes the attachment objects from
// buckets before the controlplane row is dropped. The controlplane's
// own cascade is unit-tested separately; here we only verify the
// enclave-side half.
func TestDeleteChatCascadesAttachmentsToBuckets(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	// Build a v2 chat plaintext that names a v2 attachment.
	attID := "att_v2"
	chat := map[string]any{
		"id": "c2",
		"messages": []any{
			map[string]any{
				"id":   "m1",
				"role": "user",
				"attachments": []any{
					map[string]any{
						"id":   attID,
						"type": "image",
					},
				},
			},
		},
	}
	chatBytes, _ := json.Marshal(chat)
	aad, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    f.userKeyID,
		Scope:       envelope.ScopeChat,
		ID:          "c2",
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatal(err)
	}
	v2blob, err := envelope.Encrypt(f.userKey, chatBytes, aad, f.userKeyID)
	if err != nil {
		t.Fatal(err)
	}
	f.cp.mu.Lock()
	f.cp.blobs["chat/c2"] = &cpBlob{ETag: 1, KeyID: f.userKeyID, Body: v2blob}
	f.cp.mu.Unlock()

	// Pre-seed the buckets entry the cascade should remove. With
	// the v2 attachment model the path is just the attachment id
	// and the slot key is the published sentinel.
	f.bk.mu.Lock()
	f.bk.items[attID] = bucketsItem{Value: []byte("payload"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{0}, 32)}}
	f.bk.mu.Unlock()
	if !f.bk.has(attID) {
		t.Fatalf("precondition: bucket not seeded")
	}

	cekB64 := base64.StdEncoding.EncodeToString(f.userKey)
	resp, body := f.post("/v1/sync/delete", DeleteRequest{
		Scope: "chat", ID: "c2",
		Key:            cekB64,
		IdempotencyKey: "del-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
	if f.bk.has(attID) {
		t.Fatalf("buckets entry should be gone after chat delete")
	}
}


