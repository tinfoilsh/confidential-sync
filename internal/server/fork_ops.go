package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

const (
	// maxForkAttachments bounds how many image blobs one fork may copy
	// so a single request cannot pin the buckets hop for an unbounded
	// number of round trips.
	maxForkAttachments = 200
	// maxForkAttachmentBytes caps a single copied image. Uploads are
	// only bounded by the request body limit, so anything stored must
	// fit under it; the cap exists to fail fast on a corrupt object
	// rather than to enforce a tighter policy than upload does.
	maxForkAttachmentBytes = MaxRequestBytes
	// maxForkTitleBytes bounds the caller-supplied title so a fork
	// cannot smuggle an oversized field into the sealed chat JSON.
	maxForkTitleBytes = 4096
	// forkTitleState marks the fork's title as user-chosen so the
	// webapp never overwrites it with a generated one.
	forkTitleState = "manual"
	// jsTimeLayout is the ISO-8601 shape a browser Date serializes to;
	// the fork's createdAt/updatedAt use it so the row is byte-compatible
	// with client-written chats.
	jsTimeLayout = "2006-01-02T15:04:05.000Z"
)

// forkStrippedFields are per-row bookkeeping the webapp stamps on a
// stored chat. None of it is meaningful for a new row: sync/clock
// state must start fresh, recovery envelopes are scoped to the source
// turn, and the code-execution token gates a per-chat sandbox the
// client mints lazily.
var forkStrippedFields = []string{
	"clock", "clockVersion", "codeExecutionAccessToken", "dataCorrupted", "decryptionFailed",
	"formatVersion", "isBlankChat", "isMetadataOnly", "isTemporary", "lastAccessedAt", "loadedAt",
	"locallyModified", "messageCount", "pendingRecoveries", "pendingSave", "pendingUpload",
	"projectLocallyModified", "syncPending", "syncUserId", "syncedAt", "syncVersion", "version", "writer",
}

// Fork creates a new chat row holding the first MessageCount messages
// of the source chat. Image attachments are copied to fresh buckets
// objects registered under the target chat id, so deleting either chat
// only cascades to its own blobs. The write is create-only: a target id
// that already exists surfaces as SYNC_CONFLICT.
func Fork(ctx context.Context, deps Deps, sess Session, req ForkRequest) (*ForkResponse, error) {
	if req.SourceID == "" {
		return nil, badRequest("source_id is required")
	}
	if req.TargetID == "" {
		return nil, badRequest("target_id is required")
	}
	if req.SourceID == req.TargetID {
		return nil, badRequest("target_id must differ from source_id")
	}
	if req.MessageCount < 1 {
		return nil, badRequest("message_count must be at least 1")
	}
	if len(req.Title) > maxForkTitleBytes {
		return nil, badRequest("title is too long")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, req.CreatedAt)
	if err != nil {
		return nil, badRequest("created_at must be an RFC 3339 timestamp")
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
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
	kidHex := cryptopkg.KeyIDHex(kidBytes)

	// Sealing under a key that is not the registered current key would
	// strand the fork behind a CAS the client can never satisfy.
	if err := ensureCurrentKeyRegistered(ctx, deps, sess, req.Key); err != nil {
		return nil, err
	}

	source, projectID, err := readForkSource(ctx, deps, sess, req.SourceID, envelope.Key{Bytes: key, KeyIDHex: kidHex})
	if err != nil {
		return nil, err
	}
	defer cryptopkg.Zero(source)

	var chat nativeChatPayload
	if err := json.Unmarshal(source, &chat); err != nil {
		return nil, badRequest("source chat is not a valid chat document")
	}
	if req.MessageCount > len(chat.Messages) {
		return nil, badRequest(fmt.Sprintf("message_count %d exceeds source message count %d", req.MessageCount, len(chat.Messages)))
	}

	plaintext, attachmentIDs, err := buildForkPayload(ctx, deps, sess, req, chat, createdAt, projectID)
	if err != nil {
		cleanupNativeAttachments(ctx, deps, sess, attachmentIDs)
		return nil, err
	}

	metadata := map[string]any{"messageCount": req.MessageCount}
	if projectID != "" {
		metadata["projectId"] = projectID
	}
	pushResp, err := Push(ctx, deps, sess, PushRequest{
		Scope:          "chat",
		ID:             req.TargetID,
		Key:            req.Key,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IfMatch:        nil,
		IdempotencyKey: req.IdempotencyKey,
		Metadata:       metadata,
	})
	if err != nil {
		// Only a definitive rejection proves the row was not written.
		// An ambiguous outcome may have committed a chat that still
		// references these blobs, so that case is left to the orphan
		// reaper. Retries re-derive the same blob ids, so cleaning up
		// after a definitive failure never strands a later replay.
		var outcomeUnknown *controlplane.PutBlobOutcomeUnknownError
		if !errors.As(err, &outcomeUnknown) {
			cleanupNativeAttachments(ctx, deps, sess, attachmentIDs)
		}
		return nil, err
	}
	return &ForkResponse{
		OK:            true,
		ID:            req.TargetID,
		ETag:          pushResp.ETag,
		KeyID:         pushResp.KeyID,
		SearchIndexed: pushResp.SearchIndexed,
	}, nil
}

// readForkSource fetches and unseals the source chat, returning the
// plaintext and the project the controlplane has the chat filed under
// (empty when unassigned). The controlplane column is authoritative
// for project membership because moves update it without re-sealing
// the row. The caller owns the returned plaintext and must zeroize it.
func readForkSource(ctx context.Context, deps Deps, sess Session, sourceID string, key envelope.Key) ([]byte, string, error) {
	blob, err := deps.Controlplane.GetBlob(ctx, string(envelope.ScopeChat), sourceID, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		var cpe *controlplane.Error
		if errors.As(err, &cpe) && cpe.StatusCode == http.StatusNotFound {
			return nil, "", &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "source chat not found"}
		}
		return nil, "", err
	}
	plaintext, ok := decryptAnyVersion(blob.Ciphertext, []envelope.Key{key}, envelope.ScopeChat, sourceID, sess.Claims.Subject)
	if !ok {
		return nil, "", &AppError{Status: http.StatusConflict, Code: CodeUnknownKey, Reason: "source_not_decryptable"}
	}
	projectID := ""
	if blob.ProjectIDSet && blob.ProjectID != nil {
		projectID = *blob.ProjectID
	}
	return plaintext, projectID, nil
}

// buildForkPayload assembles the fork's chat JSON from the source. Every
// image attachment with a server key is re-uploaded under the target
// chat id so the fork gets its own (id, key) pair; unknown fields on the
// chat, messages, and attachments are carried through untouched. The
// returned attachment ids are the fork's freshly created blobs, which
// the caller must clean up if the fork does not commit.
func buildForkPayload(ctx context.Context, deps Deps, sess Session, req ForkRequest, chat nativeChatPayload, createdAt time.Time, projectID string) ([]byte, []string, error) {
	messages := make([]map[string]json.RawMessage, 0, req.MessageCount)
	var attachmentIDs []string
	copied := 0
	for _, message := range chat.Messages[:req.MessageCount] {
		out := cloneRawMap(message.Raw)
		if len(message.Attachments) == 0 {
			messages = append(messages, out)
			continue
		}
		attachments := make([]map[string]json.RawMessage, 0, len(message.Attachments))
		for _, attachment := range message.Attachments {
			stored := cloneRawMap(attachment.Raw)
			sourceKey := attachmentServerKey(attachment.Raw)
			if attachment.Type != importer.AttachmentImage || attachment.ID == "" || sourceKey == "" {
				attachments = append(attachments, stored)
				continue
			}
			if copied >= maxForkAttachments {
				return nil, attachmentIDs, badRequest("fork: attachment limit exceeded")
			}
			putResp, err := copyForkAttachment(ctx, deps, sess, req, attachment.ID, sourceKey, copied)
			if err != nil {
				return nil, attachmentIDs, err
			}
			copied++
			attachmentIDs = append(attachmentIDs, putResp.ID)
			delete(stored, "key")
			setRawString(stored, "id", putResp.ID)
			setRawString(stored, "encryptionKey", putResp.AttKey)
			attachments = append(attachments, stored)
		}
		if err := setRawJSON(out, "attachments", attachments); err != nil {
			return nil, attachmentIDs, err
		}
		messages = append(messages, out)
	}

	payload := cloneRawMap(chat.Raw)
	for _, field := range forkStrippedFields {
		delete(payload, field)
	}
	timestamp := createdAt.UTC().Format(jsTimeLayout)
	setRawString(payload, "id", req.TargetID)
	setRawString(payload, "title", req.Title)
	setRawString(payload, "titleState", forkTitleState)
	setRawString(payload, "createdAt", timestamp)
	setRawString(payload, "updatedAt", timestamp)
	payload["isLocalOnly"] = json.RawMessage("false")
	if projectID != "" {
		setRawString(payload, "projectId", projectID)
	} else {
		delete(payload, "projectId")
	}
	if err := setRawJSON(payload, "messages", messages); err != nil {
		return nil, attachmentIDs, err
	}
	body, err := json.Marshal(payload)
	return body, attachmentIDs, err
}

// copyForkAttachment reads one source image with its per-attachment key
// and stores the bytes as a new attachment owned by the target chat.
func copyForkAttachment(ctx context.Context, deps Deps, sess Session, req ForkRequest, sourceAttachmentID, sourceKeyB64 string, index int) (*AttachmentPutResponse, error) {
	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return nil, &AppError{Status: http.StatusServiceUnavailable, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	sourceKey, err := base64.StdEncoding.DecodeString(sourceKeyB64)
	if err != nil || len(sourceKey) != attKeySize {
		return nil, badRequest("fork: source attachment key is invalid")
	}
	defer cryptopkg.Zero(sourceKey)

	plaintext, err := deps.Buckets.GetLimited(ctx, sess.Claims.Subject, sourceAttachmentID, sourceKey, maxForkAttachmentBytes)
	if err != nil {
		if errors.Is(err, buckets.ErrNotFound) {
			return nil, &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "source attachment not found"}
		}
		if errors.Is(err, buckets.ErrForbidden) {
			return nil, badRequest("fork: source attachment key does not match")
		}
		if errors.Is(err, buckets.ErrTooLarge) {
			return nil, badRequest("fork: source attachment too large")
		}
		return nil, &AppError{Status: http.StatusBadGateway, Code: CodeUpstream, Message: "buckets get failed: " + err.Error()}
	}
	defer cryptopkg.Zero(plaintext)

	return AttachmentPut(ctx, deps, sess, AttachmentPutRequest{
		ChatID:         req.TargetID,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IdempotencyKey: forkAttachmentIdemKey(req.IdempotencyKey, sourceAttachmentID, index),
	})
}

// attachmentServerKey returns the per-attachment key stored on the
// attachment, accepting the legacy `key` field name alongside
// `encryptionKey`.
func attachmentServerKey(raw map[string]json.RawMessage) string {
	for _, field := range []string{"encryptionKey", "key"} {
		var value string
		if json.Unmarshal(raw[field], &value) == nil && value != "" {
			return value
		}
	}
	return ""
}

// forkAttachmentIdemKey derives a stable per-attachment idempotency key
// from the fork's own key so a retried fork re-derives the same blob
// ids instead of orphaning a second copy.
func forkAttachmentIdemKey(forkIdemKey, sourceAttachmentID string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("fork-att:%s:%s:%d", forkIdemKey, sourceAttachmentID, index)))
	return hex.EncodeToString(sum[:16])
}
