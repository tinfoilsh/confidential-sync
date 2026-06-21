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
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
)

// maxReverseTimestamp mirrors the webapp's reverse-id family so imported
// chats sort into the sidebar alongside natively-created ones.
const maxReverseTimestamp int64 = 9999999999999

// runImportJob is the detached job body: validate the CEK, open the
// staged archive safely, stream-parse conversations, seal each chat and
// its attachments under the CEK, and notify the controlplane on finish.
func runImportJob(ctx context.Context, deps Deps, sess Session, job *ImportJobState) error {
	cekB64 := base64.StdEncoding.EncodeToString(job.cek)

	// The CEK must already be the user's registered current key; sealing
	// chats under an unregistered key would strand them.
	if err := ensureCurrentKeyRegistered(ctx, deps, sess, cekB64); err != nil {
		return err
	}

	arch, err := openStagedArchive(ctx, deps, sess.Claims.Subject, job)
	if err != nil {
		return err
	}

	conversationsJSON, err := arch.readConversations()
	if err != nil {
		return err
	}

	opts := importer.Options{
		Index: arch.entryIndex(),
		GenerateID: func(stableKey string, createdAt time.Time) string {
			return deterministicChatID(importer.Source(job.Source), stableKey, createdAt)
		},
	}

	var imported, failed, conversations, attachments int
	emit := func(chat *importer.Chat) error {
		conversations++
		if conversations > MaxImportConversations {
			return errors.New("import: conversation limit exceeded")
		}
		if err := sealImportedChat(ctx, deps, sess, arch, chat, cekB64, job, &attachments); err != nil {
			if isAlreadyImported(err) {
				imported++
			} else {
				failed++
				job.addError("chat failed")
			}
		} else {
			imported++
		}
		job.setProgress(imported, failed, conversations)
		return nil
	}

	if _, err := importer.ParseEach(importer.Source(job.Source), conversationsJSON, opts, emit); err != nil {
		return err
	}

	job.setProgress(imported, failed, conversations)
	notifyImportComplete(ctx, deps, sess.Claims.Subject, job.ID, job.Source, imported, failed)
	return nil
}

// sealImportedChat uploads each binary attachment, seals the chat under
// the CEK, and pushes it to the controlplane. Per-attachment failures
// are recorded as warnings and drop only that attachment.
func sealImportedChat(
	ctx context.Context,
	deps Deps,
	sess Session,
	arch *importArchive,
	chat *importer.Chat,
	cekB64 string,
	job *ImportJobState,
	attachments *int,
) error {
	attIndex := 0
	for mi := range chat.Messages {
		msg := &chat.Messages[mi]
		kept := make([]importer.Attachment, 0, len(msg.Attachments))
		for _, att := range msg.Attachments {
			if att.BinaryRef == "" {
				kept = append(kept, att)
				continue
			}
			idx := attIndex
			attIndex++

			data, err := arch.openBinary(att.BinaryRef)
			if err != nil {
				job.addError("attachment skipped")
				continue
			}
			contentType := http.DetectContentType(data)
			if !allowedImageMIME(contentType) {
				job.addError("attachment type rejected")
				continue
			}
			if *attachments >= MaxImportAttachments {
				return errors.New("import: attachment limit exceeded")
			}

			idem := attachmentIdemKey(chat.ID, att.BinaryRef, idx)
			putResp, err := AttachmentPut(ctx, deps, sess, AttachmentPutRequest{
				ChatID:         chat.ID,
				Plaintext:      base64.StdEncoding.EncodeToString(data),
				IdempotencyKey: idem,
			})
			if err != nil {
				job.addError("attachment upload failed")
				continue
			}
			att.ID = putResp.ID
			att.EncryptionKey = putResp.AttKey
			att.MimeType = contentType
			att.BinaryRef = ""
			kept = append(kept, att)
			*attachments++
		}
		msg.Attachments = kept
	}

	plaintext, err := json.Marshal(chat)
	if err != nil {
		return fmt.Errorf("import: marshal chat: %w", err)
	}

	metadata := map[string]any{"messageCount": len(chat.Messages)}
	if chat.ProjectID != "" {
		metadata["projectId"] = chat.ProjectID
	}

	_, err = Push(ctx, deps, sess, PushRequest{
		Scope:          "chat",
		ID:             chat.ID,
		Key:            cekB64,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IfMatch:        nil,
		IdempotencyKey: chatIdemKey(chat.ID),
		Metadata:       metadata,
	})
	return err
}

// isAlreadyImported reports whether a push error means the chat row
// already exists from a prior run — a safe, idempotent re-import.
func isAlreadyImported(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == CodeSyncConflict || appErr.Code == CodeStaleBlob
	}
	return controlplane.IsCode(err, controlplane.StatusStaleBlob)
}

// allowedImageMIME gates which sniffed content types v1 import accepts
// as binary attachments.
func allowedImageMIME(contentType string) bool {
	base := contentType
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = base[:i]
	}
	switch strings.TrimSpace(base) {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp":
		return true
	default:
		return false
	}
}

func deterministicChatID(source importer.Source, stableKey string, createdAt time.Time) string {
	ms := int64(0)
	if !createdAt.IsZero() {
		ms = createdAt.UnixMilli()
	}
	rev := maxReverseTimestamp - ms
	if rev < 0 {
		rev = 0
	}
	sum := sha256.Sum256([]byte("import-id:" + string(source) + ":" + stableKey))
	h := hex.EncodeToString(sum[:])
	uuidish := fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
	return fmt.Sprintf("%013d_%s", rev, uuidish)
}

func chatIdemKey(chatID string) string {
	sum := sha256.Sum256([]byte("import-chat:" + chatID))
	return hex.EncodeToString(sum[:16])
}

func attachmentIdemKey(chatID, ref string, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("import-att:%s:%s:%d", chatID, ref, index)))
	return hex.EncodeToString(sum[:16])
}

// notifyImportComplete tells the controlplane to email the user. It is
// best-effort: a failure is logged but never fails the job.
func notifyImportComplete(ctx context.Context, deps Deps, clerkUserID, jobID, source string, imported, failed int) {
	if deps.Controlplane == nil {
		return
	}
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := deps.Controlplane.NotifyImportComplete(notifyCtx, clerkUserID, jobID, source, imported, failed); err != nil {
		deps.logError("import notify failed: user=%s job=%s err=%v", clerkUserID, jobID, err)
	}
}

func cekFromImportStart(req ImportStartRequest) ([]byte, error) {
	key, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	return key, nil
}

// stageImportChunk validates and persists one archive chunk into the
// encrypted buckets staging area. It is idempotent on identical replays.
func stageImportChunk(ctx context.Context, deps Deps, owner string, job *ImportJobState, req ImportUploadRequest) error {
	if req.ChunkIndex < 0 || req.ChunkIndex >= job.TotalChunks {
		return badRequest("chunk_index out of range")
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return badRequest("invalid chunk data base64")
	}
	if len(data) == 0 || len(data) > MaxImportChunkBytes {
		return badRequest("invalid chunk size")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), req.ChunkSHA256) {
		return badRequest("chunk hash mismatch")
	}

	alreadyHave, err := job.recordChunk(req.ChunkIndex, strings.ToLower(req.ChunkSHA256))
	if err != nil {
		return badRequest(err.Error())
	}
	if alreadyHave {
		return nil
	}

	job.mu.Lock()
	stagingKey := append([]byte(nil), job.stagingKey...)
	job.mu.Unlock()
	defer cryptopkg.Zero(stagingKey)

	if deps.Buckets == nil || !deps.Buckets.Configured() {
		return &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if err := deps.Buckets.Put(ctx, owner, importChunkToken(job.UploadID, req.ChunkIndex), data, stagingKey); err != nil {
		return &AppError{Status: 502, Code: CodeUpstream, Message: "stage chunk failed: " + err.Error()}
	}
	return nil
}
