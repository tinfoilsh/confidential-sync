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
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/importer"
	"golang.org/x/sync/errgroup"
)

// maxReverseTimestamp mirrors the webapp's reverse-id family so imported
// chats sort into the sidebar alongside natively-created ones.
const maxReverseTimestamp int64 = 9999999999999

// importChatConcurrency is how many chats a legacy import seals and
// pushes at once. Each chat costs a few sequential controlplane round
// trips, so a serial loop is latency-bound; a small pool hides that
// latency without letting one import monopolize the controlplane's
// per-user write lock or the staged-chunk cache.
const importChatConcurrency = 4

// runImportJob is the detached job body: validate the CEK, open the
// staged archive safely, stream-parse conversations, seal each chat and
// its attachments under the CEK, and notify the controlplane on finish.
func runImportJob(ctx context.Context, deps Deps, sess Session, job *ImportJobState) error {
	cekB64 := base64.StdEncoding.EncodeToString(job.cek)
	job.setPhase("validating")

	// The CEK must already be the user's registered current key; sealing
	// chats under an unregistered key would strand them.
	if err := ensureCurrentKeyRegistered(ctx, deps, sess, cekB64); err != nil {
		return err
	}

	arch, err := openStagedArchive(ctx, deps, sess.Claims.Subject, job)
	if err != nil {
		return err
	}
	if job.Source == string(importer.SourceTinfoilBackup) {
		return runNativeBackupImport(ctx, deps, sess, job, arch, cekB64)
	}

	conversationsJSON, err := arch.readConversations()
	if err != nil {
		return err
	}
	job.setPhase("chats")

	priorIDs := make(map[string]string)
	opts := importer.Options{
		Index: arch.entryIndex(),
		GenerateID: func(stableKey string, createdAt time.Time) string {
			id := deterministicChatID(sess.Claims.Subject, importer.Source(job.Source), stableKey, createdAt)
			priorIDs[id] = priorDeterministicChatID(importer.Source(job.Source), stableKey, createdAt)
			return id
		},
	}

	// The parser runs on this goroutine and owns the archive-wide
	// limits; each emitted chat is handed to the pool for its network
	// round trips. Counters are shared between workers, so the tally
	// guards them, and the parser stops handing out work once any
	// worker reports a definitive failure.
	tally := &importChatTally{job: job}
	workers, workCtx := errgroup.WithContext(ctx)
	workers.SetLimit(importChatConcurrency)
	var conversations, messages, parsedAttachments int
	emit := func(chat *importer.Chat) error {
		if err := workCtx.Err(); err != nil {
			return err
		}
		conversations++
		if conversations > MaxImportConversations {
			return limitExceededErr("import: conversation limit exceeded")
		}
		messages += len(chat.Messages)
		if messages > maxImportMessages {
			return limitExceededErr("import: message limit exceeded")
		}
		for _, msg := range chat.Messages {
			parsedAttachments += len(msg.Attachments)
		}
		if parsedAttachments > MaxImportAttachments {
			return limitExceededErr("import: attachment limit exceeded")
		}
		chat.Restore = &importer.RestoreMarker{
			Format: "legacy-import-v1", SourceBackupID: job.Source,
			Kind: "chat", SourceID: chat.StableKey, Generation: 0,
		}
		priorID := priorIDs[chat.ID]
		tally.setTotal(conversations)
		workers.Go(func() (err error) {
			// runGuarded only covers the parser goroutine; a panic on a
			// worker would otherwise unwind past the job entirely.
			defer func() {
				if r := recover(); r != nil {
					err = importFailure(ImportFailureWorker, errors.New("import worker stopped unexpectedly"))
				}
			}()
			return importOneChat(workCtx, deps, sess, arch, chat, priorID, cekB64, job, tally)
		})
		return nil
	}

	_, parseErr := importer.ParseEach(importer.Source(job.Source), conversationsJSON, opts, emit)
	workErr := workers.Wait()
	if workErr != nil {
		return workErr
	}
	if parseErr != nil {
		return classifyParseFailure(parseErr)
	}

	imported, _, failed := tally.counts()
	job.setPhase("complete")
	notifyImportComplete(ctx, deps, sess.Claims.Subject, job.ID, job.Source, imported, failed)
	return nil
}

// importChatTally is the shared outcome counter for the legacy import
// pool. It publishes job progress after every change so the status
// endpoint and the stall watchdog see each chat as it completes.
type importChatTally struct {
	job *ImportJobState

	mu                  sync.Mutex
	imported            int
	skipped             int
	failed              int
	total               int
	uploadedAttachments int
}

func (t *importChatTally) setTotal(total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total = total
	t.publishLocked()
}

func (t *importChatTally) recordImported() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.imported++
	t.publishLocked()
}

func (t *importChatTally) recordSkipped() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.skipped++
	t.publishLocked()
}

func (t *importChatTally) recordFailed(msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failed++
	t.job.addError(msg)
	t.publishLocked()
}

// reserveAttachment claims one slot against MaxImportAttachments and
// reports whether the cap was already reached. A slot whose upload then
// fails is handed back with releaseAttachment so the cap counts stored
// attachments only.
func (t *importChatTally) reserveAttachment() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.uploadedAttachments >= MaxImportAttachments {
		return false
	}
	t.uploadedAttachments++
	return true
}

func (t *importChatTally) releaseAttachment() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.uploadedAttachments--
}

func (t *importChatTally) counts() (imported, skipped, failed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.imported, t.skipped, t.failed
}

func (t *importChatTally) publishLocked() {
	t.job.setProgress(t.imported, t.failed, t.total)
	t.job.setKindCount("chat", ImportKindCounts{Imported: t.imported, Skipped: t.skipped, Failed: t.failed})
}

// importOneChat is the pool body for one parsed chat: probe for a
// pre-release import of the same conversation, then seal and push. A
// per-chat failure is tallied and returns nil so the rest of the
// archive proceeds; only definitive errors abort the job.
func importOneChat(ctx context.Context, deps Deps, sess Session, arch *importArchive, chat *importer.Chat, priorID, cekB64 string, job *ImportJobState, tally *importChatTally) error {
	// The probe looks up the pre-release id family, which differs
	// from the id the push writes under, so the push's idempotency
	// cannot dedupe against a legacy row. If the probe is still
	// unavailable after retries, count this chat as failed and move
	// on rather than risk a duplicate; a re-run picks it up once the
	// probe recovers. Definitive probe errors still abort the job.
	priorImport, err := priorImportedChatExistsWithRetry(ctx, deps, sess, cekB64, priorID)
	if err != nil {
		if ctx.Err() != nil || !isTransientImportFailure(ctx, err) {
			return err
		}
		tally.recordFailed("chat skipped: prior import check unavailable")
		return nil
	}
	if priorImport {
		tally.recordSkipped()
		return nil
	}
	if err := sealImportedChat(ctx, deps, sess, arch, chat, cekB64, job, tally); err != nil {
		if errors.Is(err, errImportAttachmentLimit) {
			return err
		}
		tally.recordFailed("chat failed")
		return nil
	}
	tally.recordImported()
	return nil
}

// errImportAttachmentLimit is the only sealImportedChat failure that
// ends the whole job rather than just the current chat.
var errImportAttachmentLimit = limitExceededErr("import: attachment limit exceeded")

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
	tally *importChatTally,
) error {
	attIndex := 0
	for mi := range chat.Messages {
		msg := &chat.Messages[mi]
		kept := make([]importer.Attachment, 0, len(msg.Attachments))
		for _, att := range msg.Attachments {
			if att.Type == importer.AttachmentDocument && att.BinaryRef == "" && strings.TrimSpace(att.TextContent) == "" {
				job.addWarning("document attachment without content skipped")
				continue
			}
			if att.BinaryRef == "" {
				if att.Type == importer.AttachmentImage && (att.ID == "" || att.EncryptionKey == "") {
					job.addWarning("image attachment skipped")
					continue
				}
				kept = append(kept, att)
				continue
			}
			if att.Type != importer.AttachmentImage {
				job.addWarning("binary document skipped")
				continue
			}
			idx := attIndex
			attIndex++

			data, err := arch.openBinary(att.BinaryRef)
			if err != nil {
				job.addWarning("attachment skipped")
				continue
			}
			contentType := http.DetectContentType(data)
			if !allowedImageMIME(contentType) {
				job.addWarning("attachment type rejected")
				continue
			}
			if !tally.reserveAttachment() {
				return errImportAttachmentLimit
			}

			idem := attachmentIdemKey(chat.ID, att.BinaryRef, idx)
			putResp, err := AttachmentPut(ctx, deps, sess, AttachmentPutRequest{
				ChatID:         chat.ID,
				Plaintext:      base64.StdEncoding.EncodeToString(data),
				IdempotencyKey: idem,
			})
			if err != nil {
				tally.releaseAttachment()
				job.addWarning("attachment upload failed")
				continue
			}
			att.ID = putResp.ID
			att.EncryptionKey = putResp.AttKey
			att.MimeType = contentType
			att.BinaryRef = ""
			kept = append(kept, att)
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

	// The push carries a stable idempotency key and operation hash, so a
	// retry after a lost response replays instead of duplicating.
	err = retryTransientImportCall(ctx, func() error {
		_, pushErr := Push(ctx, deps, sess, PushRequest{
			Scope:          "chat",
			ID:             chat.ID,
			Key:            cekB64,
			Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
			IfMatch:        nil,
			IdempotencyKey: chatIdemKey(chat.ID),
			Metadata:       metadata,
		})
		return pushErr
	})
	if err != nil && isAlreadyImported(err) && chat.Restore != nil {
		match, _, verifyErr := inspectRestoreCandidate(ctx, deps, sess, cekB64, "chat", chat.ID, *chat.Restore)
		if verifyErr == nil && match {
			return nil
		}
	}
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

func deterministicChatID(userID string, source importer.Source, stableKey string, createdAt time.Time) string {
	return formattedDeterministicChatID("import-id:"+userID+":"+string(source)+":"+stableKey, createdAt)
}

func priorDeterministicChatID(source importer.Source, stableKey string, createdAt time.Time) string {
	return formattedDeterministicChatID("import-id:"+string(source)+":"+stableKey, createdAt)
}

func formattedDeterministicChatID(hashInput string, createdAt time.Time) string {
	ms := int64(0)
	if !createdAt.IsZero() {
		ms = createdAt.UnixMilli()
	}
	rev := maxReverseTimestamp - ms
	if rev < 0 {
		rev = 0
	}
	sum := sha256.Sum256([]byte(hashInput))
	h := hex.EncodeToString(sum[:])
	uuidish := fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
	return fmt.Sprintf("%013d_%s", rev, uuidish)
}

// priorImportedChatExistsWithRetry retries the read-only probe on
// transient failures. A definitive answer or a non-transient error
// returns immediately.
func priorImportedChatExistsWithRetry(ctx context.Context, deps Deps, sess Session, cekB64, id string) (bool, error) {
	var exists bool
	err := retryTransientImportCall(ctx, func() error {
		var probeErr error
		exists, probeErr = priorImportedChatExists(ctx, deps, sess, cekB64, id)
		return probeErr
	})
	return exists, err
}

func priorImportedChatExists(ctx context.Context, deps Deps, sess Session, cekB64, id string) (bool, error) {
	resp, err := Pull(ctx, deps, sess, PullRequest{Scope: "chat", IDs: []string{id}, Keys: []PullKey{{Key: cekB64}}})
	if err != nil {
		return false, importFailure(ImportFailureExistingChatCheck, err)
	}
	if len(resp.Items) != 1 {
		return false, importFailure(ImportFailureExistingChatCheck, errors.New("import: invalid prior import probe response"))
	}
	item := resp.Items[0]
	if item.OK {
		return true, nil
	}
	if item.Code == "NOT_FOUND" {
		return false, nil
	}
	if item.cause != nil {
		return false, importFailure(ImportFailureExistingChatCheck, item.cause)
	}
	return false, importFailure(ImportFailureExistingChatCheck, &AppError{Code: item.Code})
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
// best-effort: a failure never fails the job.
func notifyImportComplete(ctx context.Context, deps Deps, clerkUserID, jobID, source string, imported, failed int) {
	notifyImportOutcome(ctx, deps, controlplane.ImportOutcome{
		ClerkUserID: clerkUserID, JobID: jobID, Source: source,
		Status: controlplane.ImportOutcomeCompleted, Imported: imported, Failed: failed,
	})
}

// notifyImportFailed tells the controlplane why the job did not finish
// so the user is emailed instead of left polling a job that has gone.
func notifyImportFailed(ctx context.Context, deps Deps, clerkUserID, jobID, source string, imported, failed int, reason ImportFailureReason) {
	notifyImportOutcome(ctx, deps, controlplane.ImportOutcome{
		ClerkUserID: clerkUserID, JobID: jobID, Source: source,
		Status: controlplane.ImportOutcomeFailed, Imported: imported, Failed: failed,
		FailureReason: string(reason),
	})
}

func notifyImportOutcome(ctx context.Context, deps Deps, outcome controlplane.ImportOutcome) {
	if deps.Controlplane == nil {
		return
	}
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), importNotifyTimeout)
	defer cancel()
	// Notification is best-effort: the job outcome is already recorded
	// in the status response, and a missed email is not a data loss.
	_ = deps.Controlplane.NotifyImportOutcome(notifyCtx, outcome)
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

	expectedChunkBytes := MaxImportChunkBytes
	if req.ChunkIndex == job.TotalChunks-1 {
		expectedChunkBytes = int(job.TotalBytes - int64(req.ChunkIndex)*int64(MaxImportChunkBytes))
	}
	if len(data) != expectedChunkBytes {
		return badRequest("chunk size does not match expected range")
	}

	chunkSHA := strings.ToLower(req.ChunkSHA256)
	alreadyHave, err := job.beginChunk(req.ChunkIndex, chunkSHA)
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
		job.clearPendingChunk(req.ChunkIndex, chunkSHA)
		return &AppError{Status: 503, Code: CodeInternal, Message: "buckets backend not configured"}
	}
	if err := deps.Buckets.Put(ctx, owner, importChunkToken(job.UploadID, req.ChunkIndex), data, stagingKey); err != nil {
		job.clearPendingChunk(req.ChunkIndex, chunkSHA)
		return &AppError{Status: 502, Code: CodeUpstream, Message: "stage chunk failed: " + err.Error()}
	}
	job.finishChunk(req.ChunkIndex, chunkSHA)
	return nil
}
