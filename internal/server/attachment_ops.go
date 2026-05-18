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

// AttachmentPutRequest carries a single attachment upload. The
// plaintext lives on the wire only on the webapp↔enclave hop; the
// enclave seals it under the user's CEK with an AAD that binds
// `clerk_user_id || chat_id || attachment_id`, then PUTs the sealed
// envelope to buckets.tinfoil.sh under the attachment id and records
// ownership with the controlplane.
//
// The webapp never picks the attachment id: the enclave mints a
// fresh 128-bit random id per upload and returns it. This keeps the
// global buckets path namespace under enclave control, so the only
// party that can write to both buckets and the controlplane's
// chat_attachments table is also the only party that decides what id
// a new row gets.
type AttachmentPutRequest struct {
	ChatID    string `json:"chat_id"`
	Key       string `json:"key"`       // base64 32-byte CEK
	Plaintext string `json:"plaintext"` // base64 attachment bytes
}

// AttachmentPutResponse confirms the bucket write + index
// registration and surfaces the enclave-minted attachment id so the
// caller can embed it in the chat JSON before pushing.
type AttachmentPutResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
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

// AttachmentGetRequest carries an attachment fetch. The plaintext
// flows back inline because the webapp consumes it as a blob URL.
type AttachmentGetRequest struct {
	ID     string `json:"id"`
	ChatID string `json:"chat_id"`
	Key    string `json:"key"` // base64 32-byte CEK
}

// AttachmentGetResponse returns base64 plaintext.
type AttachmentGetResponse struct {
	OK        bool   `json:"ok"`
	Plaintext string `json:"plaintext"`
}

// AttachmentDeleteRequest removes the buckets entry. Carries no CEK
// because the buckets path is the attachment id and the
// controlplane's `chat_attachments` row is the source of truth for
// ownership; deletion is pure addressing.
type AttachmentDeleteRequest struct {
	ID string `json:"id"`
}

// AttachmentPut seals an attachment for storage in buckets.tinfoil.sh.
// The enclave never stores any per-attachment state itself: the AAD
// is derived from session + request fields and the buckets path is
// the freshly minted attachment id, which is also returned to the
// caller so it can be embedded in the chat JSON on the subsequent
// push.
func AttachmentPut(ctx context.Context, deps Deps, sess Session, req AttachmentPutRequest) (*AttachmentPutResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ChatID == "" {
		return nil, badRequest("chat_id is required")
	}
	cek, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, badRequest("invalid plaintext base64")
	}
	defer cryptopkg.Zero(plaintext)

	id, err := newAttachmentID()
	if err != nil {
		return nil, &AppError{Status: 500, Code: CodeInternal, Message: "mint attachment id: " + err.Error()}
	}

	aad, err := cryptopkg.AttachmentAAD(sess.Claims.Subject, req.ChatID, id)
	if err != nil {
		return nil, err
	}
	envelope, err := cryptopkg.SealAttachment(cek, plaintext, aad)
	if err != nil {
		return nil, err
	}

	if err := deps.Buckets.Put(ctx, id, envelope, buckets.SentinelSlotKey); err != nil {
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
	return &AttachmentPutResponse{OK: true, ID: id}, nil
}

// AttachmentGet fetches a v2 attachment by id. A buckets 404 surfaces
// as a 404 to the webapp so the legacy fallback path can run. Tamper
// (AAD mismatch, truncated envelope) surfaces as 400 so the caller
// can stop retrying.
func AttachmentGet(ctx context.Context, deps Deps, sess Session, req AttachmentGetRequest) (*AttachmentGetResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	if req.ChatID == "" {
		return nil, badRequest("chat_id is required")
	}
	cek, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)

	envelope, err := deps.Buckets.Get(ctx, req.ID, buckets.SentinelSlotKey)
	if err != nil {
		if errors.Is(err, buckets.ErrNotFound) {
			return nil, &AppError{Status: 404, Code: CodeNotFound, Message: "attachment not found"}
		}
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets get failed: " + err.Error()}
	}
	aad, err := cryptopkg.AttachmentAAD(sess.Claims.Subject, req.ChatID, req.ID)
	if err != nil {
		return nil, err
	}
	plaintext, err := cryptopkg.OpenAttachment(cek, envelope, aad)
	if err != nil {
		return nil, &AppError{Status: 400, Code: CodeBadRequest, Message: "attachment ciphertext failed authentication"}
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
