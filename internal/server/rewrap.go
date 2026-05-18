package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// attachmentIVLen mirrors the webapp's IV size for legacy per-attachment
// AES-GCM ciphertexts. Older `encryptAttachment` builds emitted
// [12B IV || AES-GCM(ct||tag)], no AAD.
const attachmentIVLen = 12

// rewrapBlob re-seals a blob under targetKey/targetKIDHex and writes
// it back to controlplane with Rewrap=true. When scope=chat, also
// performs the lazy attachment cascade: any attachment with an
// embedded per-attachment encryptionKey (v0/v1) is fetched from the
// legacy /api/storage/attachment endpoint, decrypted in-enclave, and
// re-uploaded through buckets under the attachment id using the
// existing per-attachment key as the buckets slot key. The chat
// JSON's `attachments[i].encryptionKey` is preserved verbatim so
// future reads (and shares) can address the buckets entry directly
// without the enclave having to look up any per-attachment state.
//
// Returns the new etag on success. Plaintext is zeroed by the caller.
func rewrapBlob(
	ctx context.Context,
	deps Deps,
	sess Session,
	scope envelope.Scope,
	id string,
	plaintext []byte,
	priorETag string,
	targetKey []byte,
	targetKIDHex string,
) (string, error) {
	finalPlaintext := plaintext
	if scope == envelope.ScopeChat {
		mutated, err := rewrapChatAttachments(ctx, deps, sess, id, plaintext)
		if err != nil {
			return "", err
		}
		if mutated != nil {
			finalPlaintext = mutated
			defer cryptopkg.Zero(mutated)
		}
	}

	aadBytes, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    targetKIDHex,
		Scope:       scope,
		ID:          id,
		ClerkUserID: sess.Claims.Subject,
	})
	if err != nil {
		return "", err
	}
	envBlob, err := envelope.Encrypt(targetKey, finalPlaintext, aadBytes, targetKIDHex)
	if err != nil {
		return "", err
	}
	idem := "rewrap:" + targetKIDHex + ":" + id + ":" + priorETag
	rewrapReq := controlplane.PutBlobRequest{
		Scope:          string(scope),
		ID:             id,
		JWT:            sess.RawJWT,
		KeyIDHex:       targetKIDHex,
		IfMatch:        priorETag,
		IdempotencyKey: idem,
		Rewrap:         true,
		Ciphertext:     envBlob,
	}
	opKey, err := cryptopkg.DeriveOpHashKey(targetKey)
	if err != nil {
		return "", err
	}
	defer cryptopkg.Zero(opKey)
	hashBody, err := stableBlobOperationBody(string(scope), id, finalPlaintext, nil)
	if err != nil {
		return "", err
	}
	rewrapReq.OperationHash = cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         http.MethodPost,
		Path:           controlplane.RewrapPath,
		KeyIDHex:       targetKIDHex,
		IfMatch:        priorETag,
		IdempotencyKey: idem,
		Body:           hashBody,
	})
	resp, err := deps.Controlplane.PutBlob(ctx, rewrapReq)
	if err != nil {
		return "", err
	}
	return resp.ETag, nil
}

// rewrapChatAttachments walks the chat plaintext, finds any
// attachments with an embedded encryptionKey (legacy v0/v1 image
// rows), and promotes them to buckets-backed v2 storage. The
// per-attachment key is reused as the buckets slot key, so the
// chat JSON itself never has to change — the same `encryptionKey`
// that used to unlock the controlplane BYTEA now unlocks the buckets
// blob. Returns (nil, nil) when the plaintext doesn't parse as a
// chat envelope or contains no legacy attachments — letting the
// rewrap proceed as a pure re-seal.
//
// We swallow per-attachment failures: an attachment whose legacy row
// is already gone (e.g. 404), or whose buckets PUT fails transiently,
// must not block the chat rewrap. The chat is still readable; the
// missing attachment was already going to render as a broken image.
func rewrapChatAttachments(
	ctx context.Context,
	deps Deps,
	sess Session,
	chatID string,
	plaintext []byte,
) ([]byte, error) {
	var parsed map[string]any
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return nil, nil
	}
	rawMessages, ok := parsed["messages"].([]any)
	if !ok {
		return nil, nil
	}

	for _, m := range rawMessages {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		rawAtts, ok := msg["attachments"].([]any)
		if !ok {
			continue
		}
		for _, a := range rawAtts {
			att, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if att["type"] != "image" {
				continue
			}
			rawID, _ := att["id"].(string)
			rawKey, _ := att["encryptionKey"].(string)
			if rawID == "" || rawKey == "" {
				continue
			}
			_ = promoteOneAttachment(ctx, deps, sess, chatID, rawID, rawKey)
		}
	}

	// Plaintext is never mutated; the per-attachment encryptionKey
	// stays as-is so the same value addresses the buckets entry
	// after promotion as addressed the controlplane BYTEA before it.
	return nil, nil
}

// promoteOneAttachment fetches one legacy ciphertext, decrypts it
// with the embedded per-attachment key, re-uploads the plaintext
// through buckets under the attachment id (reusing the same
// per-attachment key as the buckets slot key), and registers the
// new v2 row with controlplane. Returns true iff the cascade fully
// succeeded. The chat JSON's `encryptionKey` field is preserved
// verbatim so the same key now addresses the buckets entry that
// previously addressed the legacy BYTEA row.
func promoteOneAttachment(
	ctx context.Context,
	deps Deps,
	sess Session,
	chatID, attID, legacyKeyB64 string,
) bool {
	if !deps.Buckets.Configured() {
		return false
	}
	ciphertext, err := deps.Controlplane.GetLegacyAttachment(ctx, sess.RawJWT, attID)
	if err != nil {
		if errors.Is(err, controlplane.ErrLegacyAttachmentNotFound) {
			// already migrated by a concurrent pass, or the row was
			// dropped — there is nothing to promote.
			return true
		}
		return false
	}
	legacyKey, err := base64.StdEncoding.DecodeString(legacyKeyB64)
	if err != nil || len(legacyKey) != 32 {
		return false
	}
	plaintext, err := decryptLegacyAttachment(ciphertext, legacyKey)
	if err != nil {
		return false
	}
	defer cryptopkg.Zero(plaintext)
	defer cryptopkg.Zero(legacyKey)

	if err := deps.Buckets.Put(ctx, attID, plaintext, legacyKey); err != nil {
		return false
	}
	if err := deps.Controlplane.RegisterAttachmentIndex(ctx, sess.RawJWT, attID, chatID); err != nil {
		// buckets PUT succeeded but index update failed — the bytes
		// are present, controlplane just hasn't been told they're
		// v2 yet. A subsequent rewrap pass will retry the register
		// (Put is idempotent on the same id+key).
		return false
	}
	return true
}

// deleteChatAttachmentsBestEffort fetches the chat, decrypts with the
// CEK the caller provided to the Delete op, parses out attachment
// ids, and tells buckets to drop each one. Any failure aborts the
// cascade silently — the caller's chat-delete must still proceed,
// and orphans in buckets are unaddressable to anyone else because
// the per-attachment slot key lives only inside the (now-deleted)
// chat envelope.
func deleteChatAttachmentsBestEffort(
	ctx context.Context,
	deps Deps,
	sess Session,
	chatID string,
	cek []byte,
) {
	if !deps.Buckets.Configured() {
		return
	}
	blob, err := deps.Controlplane.GetBlob(ctx, string(envelope.ScopeChat), chatID, sess.RawJWT)
	if err != nil {
		return
	}
	cekIDBytes, err := cryptopkg.DeriveKeyID(cek)
	if err != nil {
		return
	}
	cekKIDHex := cryptopkg.KeyIDHex(cekIDBytes)
	var plaintext []byte
	switch envelope.Detect(blob.Ciphertext) {
	case envelope.VersionV2:
		dec, err := envelope.DecryptV2(blob.Ciphertext, []envelope.Key{{Bytes: cek, KeyIDHex: cekKIDHex}}, func(kid string) ([]byte, error) {
			return envelope.CanonicalAAD(envelope.AAD{
				KeyIDHex:    kid,
				Scope:       envelope.ScopeChat,
				ID:          chatID,
				ClerkUserID: sess.Claims.Subject,
			})
		})
		if err != nil {
			return
		}
		defer cryptopkg.Zero(dec.Plaintext)
		plaintext = dec.Plaintext
	case envelope.VersionV0, envelope.VersionV1:
		// Legacy chats can't have v2 attachments yet, so there's
		// nothing in buckets to clean up. The controlplane row drop
		// alone suffices.
		return
	default:
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return
	}
	rawMessages, ok := parsed["messages"].([]any)
	if !ok {
		return
	}
	for _, m := range rawMessages {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		rawAtts, ok := msg["attachments"].([]any)
		if !ok {
			continue
		}
		for _, a := range rawAtts {
			att, ok := a.(map[string]any)
			if !ok {
				continue
			}
			if att["type"] != "image" {
				continue
			}
			attID, _ := att["id"].(string)
			if attID == "" {
				continue
			}
			// Buckets Delete is idempotent on 404 (legacy v1
			// rows that were never promoted to buckets simply
			// aren't there). Issuing the call is cheaper than
			// figuring out per-attachment which generation
			// it's on.
			_ = deps.Buckets.Delete(ctx, attID)
		}
	}
}

// decryptLegacyAttachment reverses the webapp's encryptAttachment
// format: [12-byte IV || AES-GCM(ciphertext||tag)], no AAD.
func decryptLegacyAttachment(blob, key []byte) ([]byte, error) {
	if len(blob) < attachmentIVLen {
		return nil, errors.New("rewrap: attachment ciphertext too short")
	}
	iv := blob[:attachmentIVLen]
	ct := blob[attachmentIVLen:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ct, nil)
}
