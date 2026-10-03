package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// maxAttachmentGCDeletes bounds how many unreferenced blobs one
// request removes. The controlplane caps the delete batch at the same
// size; a chat with more orphans than this is cleaned over several
// calls, each of which makes progress.
const maxAttachmentGCDeletes = 500

// AttachmentGCRequest asks the enclave to remove every attachment blob
// registered under a chat that the chat's current content no longer
// references. The controlplane cannot compute this itself because the
// chat ciphertext is opaque to it; the enclave unseals the chat with
// the caller's key, reads the attachment ids out of it, and diffs
// those against the controlplane's index.
type AttachmentGCRequest struct {
	ChatID string `json:"chat_id"`
	Key    string `json:"key"` // base64 CEK, same as /v1/sync/push
}

// AttachmentGCResponse reports what the pass found. Remaining is the
// number of unreferenced ids left after the per-request delete cap,
// so a caller can loop until it reaches zero.
type AttachmentGCResponse struct {
	OK         bool `json:"ok"`
	Referenced int  `json:"referenced"`
	Indexed    int  `json:"indexed"`
	Deleted    int  `json:"deleted"`
	Remaining  int  `json:"remaining"`
}

// AttachmentGC deletes attachment blobs under a chat that the chat no
// longer references. Only ids absent from the decrypted chat are
// candidates; the controlplane then enforces ownership and chat scope
// on every id and returns the subset it actually removed, and only
// those are wiped from buckets. The index row goes first so a
// half-finished pass can never leave a readable blob the index no
// longer accounts for.
func AttachmentGC(ctx context.Context, deps Deps, sess Session, req AttachmentGCRequest) (*AttachmentGCResponse, error) {
	if req.ChatID == "" {
		return nil, badRequest("chat_id is required")
	}
	key, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(key)
	kidBytes, err := cryptopkg.DeriveKeyID(key)
	if err != nil {
		return nil, err
	}
	envKey := envelope.Key{Bytes: key, KeyIDHex: cryptopkg.KeyIDHex(kidBytes)}

	blob, err := deps.Controlplane.GetBlob(ctx, string(envelope.ScopeChat), req.ChatID, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		var cpe *controlplane.Error
		if errors.As(err, &cpe) && cpe.StatusCode == http.StatusNotFound {
			// A missing chat is the orphan reaper's job: it already
			// deletes every index row whose chat is gone.
			return nil, &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "chat not found"}
		}
		return nil, err
	}
	plaintext, ok := decryptAnyVersion(blob.Ciphertext, []envelope.Key{envKey}, envelope.ScopeChat, req.ChatID, sess.Claims.Subject)
	if !ok {
		return nil, &AppError{Status: http.StatusConflict, Code: CodeUnknownKey, Reason: "chat_not_decryptable"}
	}
	defer cryptopkg.Zero(plaintext)

	referenced, err := referencedAttachmentIDs(plaintext)
	if err != nil {
		return nil, badRequest("chat is not a valid chat document")
	}

	indexed, err := deps.Controlplane.ListAttachmentIndex(ctx, sess.RawJWT, sess.Claims.Subject, req.ChatID)
	if err != nil {
		return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "controlplane attachment index list failed: " + err.Error()}
	}

	var unreferenced []string
	for _, id := range indexed {
		if _, ok := referenced[id]; !ok {
			unreferenced = append(unreferenced, id)
		}
	}
	resp := &AttachmentGCResponse{
		OK:         true,
		Referenced: len(referenced),
		Indexed:    len(indexed),
	}
	if len(unreferenced) == 0 {
		return resp, nil
	}
	batch := unreferenced
	if len(batch) > maxAttachmentGCDeletes {
		batch = batch[:maxAttachmentGCDeletes]
	}
	resp.Remaining = len(unreferenced) - len(batch)

	deleted, err := deps.Controlplane.DeleteAttachmentIndexBatch(ctx, sess.RawJWT, sess.Claims.Subject, req.ChatID, batch)
	if err != nil {
		return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "controlplane attachment index delete failed: " + err.Error()}
	}
	resp.Deleted = len(deleted)
	if deps.Buckets != nil && deps.Buckets.Configured() {
		for _, id := range deleted {
			// The index row is already gone, so a failed bucket wipe
			// leaves an unaddressable object rather than a readable
			// one; the caller retries and Delete is idempotent on 404.
			if err := deps.Buckets.Delete(ctx, sess.Claims.Subject, id); err != nil {
				return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "buckets attachment delete failed: " + err.Error()}
			}
		}
	}
	return resp, nil
}

// referencedAttachmentIDs collects every attachment id in the chat
// that carries a server key, which is what marks it as a buckets
// backed blob rather than a client-local reference. Attachments
// without a key have never been uploaded and so cannot be indexed.
func referencedAttachmentIDs(plaintext []byte) (map[string]struct{}, error) {
	var chat nativeChatPayload
	if err := json.Unmarshal(plaintext, &chat); err != nil {
		return nil, err
	}
	ids := make(map[string]struct{})
	for _, message := range chat.Messages {
		for _, attachment := range message.Attachments {
			if attachment.ID == "" || attachmentServerKey(attachment.Raw) == "" {
				continue
			}
			ids[attachment.ID] = struct{}{}
		}
	}
	return ids, nil
}
