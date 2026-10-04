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

// AttachmentGCRequest asks for a read-only comparison of the current
// chat references with the age-filtered attachment index.
type AttachmentGCRequest struct {
	ChatID string `json:"chat_id"`
	Key    string `json:"key"` // base64 CEK, same as /v1/sync/push
}

// AttachmentGCResponse reports a diagnostic snapshot, never a deletion
// authorization. Disabled takes precedence over Remaining and RetryAfter:
// callers must retain pending work without starting a timed retry loop.
type AttachmentGCResponse struct {
	OK         bool   `json:"ok"`
	Referenced int    `json:"referenced"`
	Indexed    int    `json:"indexed"`
	Deleted    int    `json:"deleted"`
	Remaining  int    `json:"remaining"`
	Code       string `json:"code"`
	Disabled   bool   `json:"disabled"`
	Deferred   int64  `json:"deferred"`
	RetryAfter int64  `json:"retry_after"`
}

// AttachmentGC is non-destructive because chat commits do not fence
// references to collected attachments, and bucket deletes are not bound
// to an immutable upload generation. A chat revision check alone cannot
// protect references published after the check by an offline client.
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

	var unreferenced int
	for _, id := range indexed.IDs {
		if _, ok := referenced[id]; !ok {
			unreferenced++
		}
	}
	return &AttachmentGCResponse{
		Code:       CodeAttachmentGCDisabled,
		Disabled:   true,
		Referenced: len(referenced),
		Indexed:    len(indexed.IDs),
		Remaining:  unreferenced,
		Deferred:   indexed.Deferred,
		RetryAfter: indexed.RetryAfter,
	}, nil
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
