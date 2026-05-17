package server

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

// AttachmentPutRequest carries a single attachment upload. The
// plaintext lives on the wire only on the webapp↔enclave hop; the
// enclave derives a per-attachment AES key and a per-attachment
// access token from the user's CEK and the attachment id, then PUTs
// the value to buckets.tinfoil.sh and records ownership with the
// controlplane.
type AttachmentPutRequest struct {
	ID        string `json:"id"`
	ChatID    string `json:"chat_id"`
	Key       string `json:"key"`       // base64 32-byte CEK
	Plaintext string `json:"plaintext"` // base64 attachment bytes
}

// AttachmentPutResponse confirms the bucket write + index registration.
type AttachmentPutResponse struct {
	OK bool `json:"ok"`
}

// AttachmentGetRequest carries an attachment fetch. The plaintext
// flows back inline because the webapp consumes it as a blob URL.
type AttachmentGetRequest struct {
	ID  string `json:"id"`
	Key string `json:"key"` // base64 32-byte CEK
}

// AttachmentGetResponse returns base64 plaintext.
type AttachmentGetResponse struct {
	OK        bool   `json:"ok"`
	Plaintext string `json:"plaintext"`
}

// AttachmentDeleteRequest removes the buckets entry. Index cleanup
// happens via the chat-delete path on controlplane (cascade rows).
type AttachmentDeleteRequest struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// AttachmentPut seals an attachment for storage in buckets.tinfoil.sh.
// The enclave never stores any per-attachment state itself; both the
// AES key and the access token are derived deterministically so a
// reader with the user's CEK can fetch the bytes again later.
func AttachmentPut(ctx context.Context, deps Deps, sess Session, req AttachmentPutRequest) (*AttachmentPutResponse, error) {
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

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, badRequest("invalid plaintext base64")
	}
	defer cryptopkg.Zero(plaintext)

	attachmentKey, err := cryptopkg.DeriveAttachmentKey(cek, req.ID)
	if err != nil {
		return nil, err
	}
	defer cryptopkg.Zero(attachmentKey)

	token, err := cryptopkg.DeriveAttachmentToken(cek, req.ID)
	if err != nil {
		return nil, err
	}

	if err := deps.Buckets.Put(ctx, token, plaintext, attachmentKey); err != nil {
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets put failed: " + err.Error()}
	}
	if err := deps.Controlplane.RegisterAttachmentIndex(ctx, sess.RawJWT, req.ID, req.ChatID); err != nil {
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "controlplane index failed: " + err.Error()}
	}
	return &AttachmentPutResponse{OK: true}, nil
}

// AttachmentGet fetches a v2 attachment by id. A buckets 404 surfaces
// as a 404 to the webapp so the legacy fallback path can run.
func AttachmentGet(ctx context.Context, deps Deps, sess Session, req AttachmentGetRequest) (*AttachmentGetResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	cek, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)

	attachmentKey, err := cryptopkg.DeriveAttachmentKey(cek, req.ID)
	if err != nil {
		return nil, err
	}
	defer cryptopkg.Zero(attachmentKey)

	token, err := cryptopkg.DeriveAttachmentToken(cek, req.ID)
	if err != nil {
		return nil, err
	}

	plaintext, err := deps.Buckets.Get(ctx, token, attachmentKey)
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
// Called when the enclave walks a chat's attachments at delete time.
func AttachmentDelete(ctx context.Context, deps Deps, sess Session, req AttachmentDeleteRequest) (*OKResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	cek, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(cek)

	token, err := cryptopkg.DeriveAttachmentToken(cek, req.ID)
	if err != nil {
		return nil, err
	}
	if err := deps.Buckets.Delete(ctx, token); err != nil {
		return nil, &AppError{Status: 502, Code: CodeUpstream, Message: "buckets delete failed: " + err.Error()}
	}
	return &OKResponse{OK: true}, nil
}
