package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// attKeySize is the length of the per-attachment AES-256 key the
// enclave mints on upload and hands to the webapp. Matches buckets'
// required slot key size.
const attKeySize = 32

// AttachmentPutRequest carries a single attachment upload. The
// plaintext lives on the wire only on the webapp↔enclave hop; the
// enclave mints a fresh per-attachment AES-256 key, hands the
// plaintext + that key to buckets (buckets seals natively under its
// v1 envelope), registers ownership with the controlplane, and
// returns the key to the webapp so it can be embedded in the chat
// JSON under `attachments[i].encryptionKey`.
//
// The webapp never picks the attachment id: the enclave mints a
// fresh 128-bit random id per upload and returns it. This keeps the
// global buckets path namespace under enclave control, so the only
// party that can write to both buckets and the controlplane's
// chat_attachments table is also the only party that decides what id
// a new row gets. No CEK material flows on this request — the
// per-attachment key is what protects the buckets bytes, and the
// chat envelope (sealed under CEK) is what protects the
// per-attachment key.
type AttachmentPutRequest struct {
	ChatID    string `json:"chat_id"`
	Plaintext string `json:"plaintext"` // base64 attachment bytes
}

// AttachmentPutResponse confirms the bucket write + index
// registration and surfaces the enclave-minted attachment id plus
// the per-attachment key the caller must embed in the chat JSON so
// future reads can unlock the bucket entry.
type AttachmentPutResponse struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id"`
	AttKey string `json:"att_key"` // base64 32-byte AES-256 key
}

// newAttachmentID mints a fresh 128-bit random attachment id encoded
// as 32 lowercase hex characters. We use hex (not UUIDv4 dashes) so
// the id is a clean buckets-path-safe string with no
// version-bit/encoding ambiguity.
func newAttachmentID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// AttachmentGetRequest carries an attachment fetch. The webapp
// pulls the per-attachment key out of the chat JSON (where it
// lives in `attachments[i].encryptionKey`) and supplies it here;
// the enclave forwards it to buckets as the slot key.
type AttachmentGetRequest struct {
	ID     string `json:"id"`
	AttKey string `json:"att_key"` // base64 32-byte AES-256 key
}

// AttachmentGetResponse returns base64 plaintext.
type AttachmentGetResponse struct {
	OK        bool   `json:"ok"`
	Plaintext string `json:"plaintext"`
}

// AttachmentDeleteRequest removes the buckets entry. Carries no key
// because the buckets path is the attachment id and deletion only
// needs addressing — buckets verifies the request against the
// enclave's Tinfoil API key, which is sufficient since the path is
// inside the enclave's tenant.
type AttachmentDeleteRequest struct {
	ID string `json:"id"`
}

// AttachmentPut uploads an attachment plaintext to buckets under a
// fresh per-attachment key. The key is returned so the caller can
// embed it in the chat JSON; nothing about the key is persisted by
// the enclave itself.
func AttachmentPut(ctx context.Context, deps Deps, sess Session, req AttachmentPutRequest) (*AttachmentPutResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ChatID == "" {
		return nil, badRequest("chat_id is required")
	}

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, badRequest("invalid plaintext base64")
	}
	defer cryptopkg.Zero(plaintext)

	id, err := newAttachmentID()
	if err != nil {
		return nil, &AppError{Status: 500, Code: CodeInternal, Message: "mint attachment id: " + err.Error()}
	}

	attKey := make([]byte, attKeySize)
	if _, err := rand.Read(attKey); err != nil {
		return nil, &AppError{Status: 500, Code: CodeInternal, Message: "mint attachment key: " + err.Error()}
	}
	defer cryptopkg.Zero(attKey)

	if err := deps.Buckets.Put(ctx, id, plaintext, attKey); err != nil {
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets put failed: " + err.Error()}
	}
	if err := deps.Controlplane.RegisterAttachmentIndex(ctx, sess.RawJWT, id, req.ChatID); err != nil {
		// Best-effort buckets rollback. If this fails the orphan
		// will be swept by the janitor — the controlplane row is
		// still the source of truth for ownership, so a missing
		// index row means the user effectively has no claim on the
		// bucket entry anyway.
		_ = deps.Buckets.Delete(ctx, id)
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "controlplane index failed: " + err.Error()}
	}
	return &AttachmentPutResponse{
		OK:     true,
		ID:     id,
		AttKey: base64.StdEncoding.EncodeToString(attKey),
	}, nil
}

// AttachmentGet fetches an attachment by id using the per-attachment
// key the caller supplies. A buckets 404 surfaces as a 404 to the
// webapp so the legacy fallback path can run. A buckets 403 (slot key
// mismatch) surfaces as a 400 — the caller has the wrong key for the
// id, which is unrecoverable without a fresh chat pull.
//
// AttachmentGet is intentionally session-agnostic: knowing the
// attachment id + the per-attachment key is the access proof. The
// same handler runs for the owner (authenticated `/v1/attachment/get`)
// and for share recipients (unauthenticated `/v1/attachment/get-public`)
// because the trust model is identical in both cases — the bucket
// entry's slot key is the only credential, and it lives in the
// chat/share JSON the caller already holds.
func AttachmentGet(ctx context.Context, deps Deps, req AttachmentGetRequest) (*AttachmentGetResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	attKey, err := base64.StdEncoding.DecodeString(req.AttKey)
	if err != nil {
		return nil, badRequest("invalid att_key base64")
	}
	if len(attKey) != attKeySize {
		return nil, badRequest("att_key must be 32 bytes")
	}
	defer cryptopkg.Zero(attKey)

	plaintext, err := deps.Buckets.Get(ctx, req.ID, attKey)
	if err != nil {
		if errors.Is(err, buckets.ErrNotFound) {
			return nil, &AppError{Status: 404, Code: CodeNotFound, Message: "attachment not found"}
		}
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets get failed: " + err.Error()}
	}
	defer cryptopkg.Zero(plaintext)
	return &AttachmentGetResponse{
		OK:        true,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

// AttachmentDelete removes the buckets entry for a single attachment.
// Called when the enclave walks a chat's attachments at delete time
// and when the start-fresh wipe drains the user's bucket footprint.
func AttachmentDelete(ctx context.Context, deps Deps, _ Session, req AttachmentDeleteRequest) (*OKResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	if err := deps.Buckets.Delete(ctx, req.ID); err != nil {
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets delete failed: " + err.Error()}
	}
	return &OKResponse{OK: true}, nil
}
