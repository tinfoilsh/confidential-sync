package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// attachmentIVLen mirrors the webapp's IV size for legacy per-attachment
// AES-GCM ciphertexts. Older `encryptAttachment` builds emitted
// [12B IV || AES-GCM(ct||tag)], no AAD.
const attachmentIVLen = 12

const bucketsDeleteCleanupTimeout = 30 * time.Second

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
	deps.logInfo("rewrap begin: user=%s scope=%s id=%s target_kid=%s prior_etag=%s",
		sess.Claims.Subject, scope, id, targetKIDHex, priorETag)

	finalPlaintext := plaintext
	if scope == envelope.ScopeChat {
		mutated, err := rewrapChatAttachments(ctx, deps, sess, id, plaintext)
		if err != nil {
			deps.logError("rewrap chat attachments failed: user=%s id=%s err=%v",
				sess.Claims.Subject, id, err)
			return "", err
		}
		if mutated != nil {
			finalPlaintext = mutated
			defer cryptopkg.Zero(mutated)
		}
	}

	// Profile blobs are keyed by clerk_user_id on the controlplane,
	// so CP's needs-migration list returns the user id as the row id.
	// The crypto envelope, however, pins the AAD id to the canonical
	// profile-singleton constant; if we forwarded CP's storage id we
	// would build an AAD the next read could never reproduce.
	aadID := id
	if scope == envelope.ScopeProfile {
		aadID = envelope.ProfileSingletonID
	}
	aadBytes, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    targetKIDHex,
		Scope:       scope,
		ID:          aadID,
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
	rewrapReq.OperationHash = cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         http.MethodPost,
		Path:           controlplane.RewrapPath,
		KeyIDHex:       targetKIDHex,
		IfMatch:        priorETag,
		IdempotencyKey: idem,
		Body:           finalPlaintext,
		AAD:            aadBytes,
	})
	resp, err := deps.Controlplane.PutBlob(ctx, rewrapReq)
	if err != nil {
		deps.logError("rewrap put failed: user=%s scope=%s id=%s target_kid=%s err=%v",
			sess.Claims.Subject, scope, id, targetKIDHex, err)
		return "", err
	}
	deps.logInfo("rewrap ok: user=%s scope=%s id=%s target_kid=%s new_etag=%s",
		sess.Claims.Subject, scope, id, targetKIDHex, resp.ETag)
	return resp.ETag, nil
}

// rewrapChatAttachments walks the chat plaintext, finds any
// attachments with an embedded encryptionKey (legacy v0/v1 image
// rows), and promotes them to buckets-backed v2 storage. The
// per-attachment key is reused as the buckets slot key, and legacy
// attachment ids are preserved as the buckets ids.
//
// Older clients stored the per-attachment key under `att.key`
// instead of `att.encryptionKey`. When such a row is promoted the
// function also sets `att.encryptionKey` to the same value so that
// post-rewrap reads address the buckets entry directly. The
// original `att.key` field is left in place so clients that still
// only know the legacy field name can keep reading via the legacy
// route until they update.
//
// Returns the mutated plaintext when any `att.key` row had to be
// normalized; returns (nil, nil) when the plaintext doesn't parse
// as a chat envelope or no field renames were needed, letting the
// rewrap proceed as a pure re-seal.
func rewrapChatAttachments(
	ctx context.Context,
	deps Deps,
	sess Session,
	chatID string,
	plaintext []byte,
) ([]byte, error) {
	// UseNumber preserves JSON numbers as json.Number (a
	// string-backed type) instead of float64. Without it, large
	// int64 fields (file sizes, Unix-ms timestamps) silently lose
	// precision on the re-marshal below, and 1.0 becomes 1, which
	// would silently rewrite chat plaintext bytes whenever this
	// cascade fires.
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.UseNumber()
	var parsed map[string]any
	if err := dec.Decode(&parsed); err != nil {
		return nil, nil
	}
	rawMessages, ok := parsed["messages"].([]any)
	if !ok {
		return nil, nil
	}

	// Attempt every attachment in the chat even when one fails so the
	// next rewrap pass starts from a smaller backlog; the chat-level
	// re-seal still aborts as soon as any single promotion errors out,
	// because returning a clean etag while the chat plaintext still
	// embeds a legacy attachment would record migration success that
	// the next read can no longer satisfy.
	var promoteErrs []error
	fieldNormalized := false
	candidates := 0
	promoted := 0
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
			keyFromLegacyField := false
			if rawKey == "" {
				rawKey, _ = att["key"].(string)
				keyFromLegacyField = rawKey != ""
			}
			if rawID == "" || rawKey == "" {
				continue
			}
			candidates++
			if err := promoteOneAttachment(ctx, deps, sess, chatID, rawID, rawKey); err != nil {
				deps.logError("rewrap attachment promote failed: user=%s chat=%s att=%s legacy_field=%t err=%v",
					sess.Claims.Subject, chatID, rawID, keyFromLegacyField, err)
				promoteErrs = append(promoteErrs, err)
				continue
			}
			promoted++
			if keyFromLegacyField {
				att["encryptionKey"] = rawKey
				fieldNormalized = true
			}
		}
	}

	if candidates > 0 {
		deps.logInfo("rewrap attachments scanned: user=%s chat=%s candidates=%d promoted=%d errors=%d field_normalized=%t",
			sess.Claims.Subject, chatID, candidates, promoted, len(promoteErrs), fieldNormalized)
	}

	if len(promoteErrs) > 0 {
		return nil, errors.Join(promoteErrs...)
	}
	if fieldNormalized {
		return json.Marshal(parsed)
	}
	return nil, nil
}

// promoteOneAttachment fetches one legacy ciphertext, decrypts it
// with the embedded per-attachment key, re-uploads the plaintext
// through buckets under the same attachment id (reusing the same
// per-attachment key as the buckets slot key), and registers the new
// v2 row with controlplane. The chat JSON's
// `encryptionKey` field is preserved verbatim so the same key now
// addresses the buckets entry that previously addressed the legacy
// BYTEA row.
func promoteOneAttachment(
	ctx context.Context,
	deps Deps,
	sess Session,
	chatID, attID, legacyKeyB64 string,
) error {
	if !deps.Buckets.Configured() {
		return errors.New("rewrap: buckets backend not configured")
	}
	deps.logInfo("attachment promote begin: user=%s chat=%s att=%s",
		sess.Claims.Subject, chatID, attID)
	resp, err := deps.Controlplane.GetLegacyAttachment(ctx, sess.RawJWT, attID)
	if err != nil {
		if errors.Is(err, controlplane.ErrLegacyAttachmentNotFound) {
			deps.logInfo("attachment promote skip not-found: user=%s chat=%s att=%s",
				sess.Claims.Subject, chatID, attID)
			return nil
		}
		return fmt.Errorf("rewrap: fetch legacy attachment %s: %w", attID, err)
	}
	if err := verifyLegacyAttachmentClaim(
		deps.SyncEnclaveSecret,
		resp.Claim,
		sess.Claims.Subject,
		attID,
		resp.Ciphertext,
	); err != nil {
		return fmt.Errorf("rewrap: legacy claim rejected for %s: %w", attID, err)
	}
	legacyKey, err := base64.StdEncoding.DecodeString(legacyKeyB64)
	if err != nil || len(legacyKey) != 32 {
		return fmt.Errorf("rewrap: invalid legacy attachment key for %s", attID)
	}
	defer cryptopkg.Zero(legacyKey)
	plaintext, err := decryptLegacyAttachment(resp.Ciphertext, legacyKey)
	if err != nil {
		return fmt.Errorf("rewrap: decrypt legacy attachment %s: %w", attID, err)
	}
	defer cryptopkg.Zero(plaintext)
	deps.logInfo("attachment promote decrypted: user=%s chat=%s att=%s ciphertext_bytes=%d plaintext_bytes=%d",
		sess.Claims.Subject, chatID, attID, len(resp.Ciphertext), len(plaintext))

	if err := deps.Buckets.Put(ctx, attID, plaintext, legacyKey); err != nil {
		return fmt.Errorf("rewrap: promote attachment %s to buckets: %w", attID, err)
	}
	if err := deps.Controlplane.RegisterAttachmentIndex(ctx, sess.RawJWT, attID, chatID); err != nil {
		// buckets PUT succeeded but index update failed — the bytes
		// are present, controlplane just hasn't been told they're
		// v2 yet. A subsequent rewrap pass will retry the register
		// (Put is idempotent on the same id+key).
		return fmt.Errorf("rewrap: register attachment index %s: %w", attID, err)
	}
	deps.logInfo("attachment promote ok: user=%s chat=%s att=%s",
		sess.Claims.Subject, chatID, attID)
	return nil
}

// deleteBucketAttachments fires off best-effort Delete calls for each
// attachment id supplied by the controlplane's chat-delete response.
// The ids MUST come from the controlplane (via
// `DeleteBlobResponse.WipedV2Attachments`), never from the
// user-controlled chat plaintext: buckets has no per-user ownership
// check, so trusting JSON ids would let a crafted chat delete an
// unrelated victim's attachment whose id the attacker happened to
// know. Failures are swallowed; an orphan in buckets is
// unaddressable without the per-attachment slot key, which lived in
// the (now-deleted) chat envelope.
func deleteBucketAttachments(ctx context.Context, deps Deps, ids []string) {
	if !deps.Buckets.Configured() {
		return
	}
	if len(ids) == 0 {
		return
	}
	deps.logInfo("buckets cleanup begin: count=%d", len(ids))
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bucketsDeleteCleanupTimeout)
	defer cancel()
	deleted := 0
	for _, attID := range ids {
		if err := deps.Buckets.Delete(cleanupCtx, attID); err != nil {
			deps.logError("buckets cleanup failed: att=%s err=%v", attID, err)
			continue
		}
		deleted++
	}
	deps.logInfo("buckets cleanup done: requested=%d deleted=%d", len(ids), deleted)
}

// legacyAttachmentClaimPayload is the canonical JSON the enclave HMACs
// to reproduce the X-Legacy-Claim header CP stamped on the response.
// Fields are alphabetical (json.Marshal preserves struct order, and the
// CP side declares them in the same order) so both sides serialize to
// identical bytes.
type legacyAttachmentClaimPayload struct {
	ClerkUserID string `json:"clerk_user_id"`
	ID          string `json:"id"`
	Scope       string `json:"scope"`
	SHA256      string `json:"sha256"`
}

// verifyLegacyAttachmentClaim recomputes the CP-signed claim from the
// authenticated user, the attachment id we asked for, and the bytes we
// just received, and compares it to the value CP sent in X-Legacy-Claim.
// A blank secret bypasses verification (only used by the unit-test
// fixtures, where the CP stub doesn't stamp the header); production
// always configures SYNC_ENCLAVE_SECRET.
func verifyLegacyAttachmentClaim(
	secret, providedClaim, clerkUserID, attID string,
	ciphertext []byte,
) error {
	if secret == "" {
		return nil
	}
	if providedClaim == "" {
		return errors.New("missing X-Legacy-Claim header")
	}
	digest := sha256.Sum256(ciphertext)
	payload, err := json.Marshal(legacyAttachmentClaimPayload{
		ClerkUserID: clerkUserID,
		ID:          attID,
		Scope:       "attachment",
		SHA256:      hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return fmt.Errorf("marshal claim: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	provided, err := hex.DecodeString(providedClaim)
	if err != nil {
		return fmt.Errorf("malformed claim signature: %w", err)
	}
	if !hmac.Equal(provided, expected) {
		return errors.New("claim signature mismatch")
	}
	return nil
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
