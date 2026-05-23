package server

import (
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
		return "", err
	}
	return resp.ETag, nil
}

// rewrapChatAttachments walks the chat plaintext, finds any
// attachments with an embedded encryptionKey (legacy v0/v1 image
// rows), and promotes them to buckets-backed v2 storage. The
// per-attachment key is reused as the buckets slot key, and legacy
// attachment ids are preserved as the buckets ids. The chat plaintext
// itself is not rewritten, so inline thumbnail/base64 fields remain
// exactly as the client stored them.
// Returns (nil, nil) when the plaintext doesn't parse as a chat
// envelope — letting the rewrap proceed as a pure re-seal.
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
	resp, err := deps.Controlplane.GetLegacyAttachment(ctx, sess.RawJWT, attID)
	if err != nil {
		if errors.Is(err, controlplane.ErrLegacyAttachmentNotFound) {
			// already migrated by a concurrent pass, or the row was
			// dropped — there is nothing to promote.
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
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bucketsDeleteCleanupTimeout)
	defer cancel()
	for _, attID := range ids {
		// Buckets Delete is idempotent on 404 (legacy v1 rows that
		// were never promoted to buckets simply aren't there).
		// Issuing the call is cheaper than figuring out
		// per-attachment which generation it's on.
		_ = deps.Buckets.Delete(cleanupCtx, attID)
	}
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
