package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// Deps bundles everything operations need from the surrounding process.
type Deps struct {
	Controlplane *controlplane.Client
	Buckets      *buckets.Client
	// SearchBuckets talks to the dedicated search-index sidecar,
	// backed by its own S3 bucket. Optional: when unconfigured the
	// search routes return 503 and push/delete skip index upkeep.
	SearchBuckets *buckets.Client
	// Embedder generates embedding vectors via the Tinfoil inference
	// service. Optional, gated together with SearchBuckets.
	Embedder Embedder
	// SearchCache holds decoded search indices between requests.
	// Populated by NewHandler; nil disables caching.
	SearchCache *searchIndexCache
	searchGate  *searchInferenceGate
	GitSHA      string
	// SyncEnclaveSecret is the shared secret used to verify the
	// X-Legacy-Claim header CP stamps on legacy attachment reads.
	// Empty in test fixtures, where the legacy-claim guard is
	// bypassed.
	SyncEnclaveSecret string
	// Logger is optional; when nil, logInfo/logError become no-ops.
	// Tests leave this unset so verbose sync/migration logging stays
	// out of test output.
	Logger Logger
}

func (d Deps) logInfo(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Infof(format, args...)
	}
}

func (d Deps) logError(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Errorf(format, args...)
	}
}

// Session is the per-request authenticated context: the bearer token (to
// forward to the controlplane) and the claims (for AAD construction).
type Session struct {
	RawJWT string
	Claims auth.Claims
}

const (
	// createIfMatchSentinel is the wire value the controlplane uses
	// to mean "create-only" when a caller doesn't have an etag yet.
	// Must match controlplane/handlers/sync_blob_handler.go
	// (createIfMatch = "0").
	createIfMatchSentinel = "0"
)

// Push encrypts plaintext into a v2 envelope and uploads it to the
// controlplane with idempotent CAS semantics. On 412 STALE_BLOB the
// enclave surfaces 409 SYNC_CONFLICT with the controlplane's
// current_etag; conflict resolution is a client-UI decision (keep
// local, keep remote, or discard local edits). The enclave never
// merges, never silently overwrites.
func Push(ctx context.Context, deps Deps, sess Session, req PushRequest) (*PushResponse, error) {
	scope := envelope.Scope(req.Scope)
	if !scope.Valid() {
		return nil, badRequest("invalid scope")
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}

	key, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(key)

	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return nil, badRequest("invalid plaintext base64")
	}
	defer cryptopkg.Zero(plaintext)

	kidBytes, err := cryptopkg.DeriveKeyID(key)
	if err != nil {
		return nil, err
	}
	kidHex := cryptopkg.KeyIDHex(kidBytes)

	aad := envelope.AAD{
		KeyIDHex:    kidHex,
		Scope:       scope,
		ID:          req.ID,
		ClerkUserID: sess.Claims.Subject,
	}
	payloadAAD, err := envelope.CanonicalPayloadAAD(aad)
	if err != nil {
		return nil, badRequest("invalid envelope inputs: " + err.Error())
	}

	envBlob, err := envelope.Encrypt(key, plaintext, aad)
	if err != nil {
		return nil, err
	}

	ifMatch := createIfMatchSentinel
	if req.IfMatch != nil {
		ifMatch = *req.IfMatch
	}
	opHash, err := operationHashForBlob(key, http.MethodPut, req.Scope, req.ID, kidHex, ifMatch, req.IdempotencyKey, payloadAAD, plaintext)
	if err != nil {
		return nil, err
	}

	// messageCount is metadata-only (the chat-list UI uses it for the
	// "empty chat" predicate). It is NOT mixed into the op-hash: the
	// controlplane is the authority on that column and could tamper
	// with it post-write regardless. Mixing it in would only force
	// retries to recompute the hash without changing the threat
	// model. The same reasoning applies to projectId — it surfaces
	// in list-status so cross-project moves propagate without
	// decrypting the row.
	projectIDSet, projectID := projectIDFromMetadata(req.Scope, req.Metadata)
	deps.logInfo("push begin: user=%s scope=%s id=%s kid=%s if_match=%s plaintext_bytes=%d",
		sess.Claims.Subject, scope, req.ID, kidHex, ifMatch, len(plaintext))

	resp, err := deps.Controlplane.PutBlob(ctx, controlplane.PutBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		ClerkUserID:    sess.Claims.Subject,
		KeyIDHex:       kidHex,
		IfMatch:        ifMatch,
		IdempotencyKey: req.IdempotencyKey,
		OperationHash:  opHash,
		Ciphertext:     envBlob,
		MessageCount:   messageCountFromMetadata(req.Scope, req.Metadata),
		ProjectIDSet:   projectIDSet,
		ProjectID:      projectID,
	})
	if err == nil {
		committedAt := time.Now()
		deps.logInfo("push ok: user=%s scope=%s id=%s kid=%s new_etag=%s",
			sess.Claims.Subject, scope, req.ID, kidHex, resp.ETag)
		// Search indexing is inline (the plaintext and CEK only exist
		// for this request) but best-effort: the blob write already
		// succeeded, so an indexing failure degrades search instead
		// of failing the push. The reindex path repairs any gap.
		var searchIndexed *bool
		if scope == envelope.ScopeChat && searchConfigured(deps) {
			indexed := true
			if idxErr := indexCurrentChatForSearch(ctx, deps, sess, key, req.ID, plaintext, resp.ETag, committedAt, resp.SourceRevision); idxErr != nil {
				deps.logError("push search index failed: user=%s id=%s err=%v",
					sess.Claims.Subject, req.ID, idxErr)
				indexed = false
			}
			searchIndexed = &indexed
		}
		return &PushResponse{OK: true, ETag: resp.ETag, KeyID: resp.KeyID, SearchIndexed: searchIndexed}, nil
	}

	if controlplane.IsCode(err, controlplane.StatusStaleBlob) {
		var cpe *controlplane.Error
		currentETag := ""
		if errors.As(err, &cpe) {
			currentETag = cpe.CurrentETag
		}
		deps.logInfo("push stale blob: user=%s scope=%s id=%s current_etag=%s",
			sess.Claims.Subject, scope, req.ID, currentETag)
		return nil, &AppError{
			Status:      http.StatusConflict,
			Code:        CodeSyncConflict,
			Reason:      "stale_blob",
			CurrentETag: currentETag,
		}
	}
	deps.logError("push failed: user=%s scope=%s id=%s err=%v",
		sess.Claims.Subject, scope, req.ID, err)
	return nil, err
}

// operationHashForBlob derives X-Operation-Hash for a blob mutation
// according to syncplan.md §7.0. The MAC covers the logical plaintext
// plus stable request metadata, not the randomized v2 envelope bytes,
// so a retry with the same idempotency key can replay after a lost
// response instead of tripping IDEMPOTENCY_CONFLICT on a fresh nonce.
func operationHashForBlob(cek []byte, method, scope, id, keyIDHex, ifMatch, idempotencyKey string, aad, plaintext []byte) (string, error) {
	path, err := controlplane.PathFor(scope, id)
	if err != nil {
		return "", err
	}
	opKey, err := cryptopkg.DeriveOpHashKey(cek)
	if err != nil {
		return "", err
	}
	defer cryptopkg.Zero(opKey)
	return cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         method,
		Path:           path,
		KeyIDHex:       keyIDHex,
		IfMatch:        ifMatch,
		IdempotencyKey: idempotencyKey,
		Body:           plaintext,
		AAD:            aad,
	}), nil
}

// Pull fetches one or more blobs and decrypts them. Each item is
// independent: a single bad blob does not fail the batch.
func Pull(ctx context.Context, deps Deps, sess Session, req PullRequest) (*PullResponse, error) {
	scope := envelope.Scope(req.Scope)
	if !scope.Valid() {
		return nil, badRequest("invalid scope")
	}
	if len(req.Keys) == 0 {
		return nil, badRequest("keys is required and must not be empty")
	}

	keys, cleanup, err := decodeKeys(req.Keys)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}

	var ids []string
	var nextCursor string

	switch {
	case len(req.IDs) > 0:
		ids = req.IDs
	case req.All:
		list, err := deps.Controlplane.ListStatus(ctx, req.Scope, req.Cursor, req.Limit, sess.RawJWT, sess.Claims.Subject, "", "")
		if err != nil {
			return nil, err
		}
		nextCursor = list.NextCursor
		for _, u := range list.Updates {
			ids = append(ids, u.ID)
		}
	default:
		return nil, badRequest("either ids[] or all=true is required")
	}

	// keys[0] is the caller's current primary CEK by convention
	// (see cek-encoding.ts on the webapp). We use it as the rewrap
	// target so legacy rows get promoted to v2 inline on first pull
	// without the caller having to opt in. Deriving the key-id once
	// keeps the per-item loop cheap.
	targetKey := keys[0].Bytes
	targetKIDBytes, err := cryptopkg.DeriveKeyID(targetKey)
	if err != nil {
		return nil, err
	}
	targetKIDHex := cryptopkg.KeyIDHex(targetKIDBytes)

	deps.logInfo("pull begin: user=%s scope=%s candidate_keys=%d target_kid=%s ids=%d all=%t",
		sess.Claims.Subject, scope, len(keys), targetKIDHex, len(ids), req.All)

	// Inline rewrap promotes legacy rows to v2 on first read, but the
	// controlplane gates every rewrap CAS on the user's registered
	// current key. When the pull target is not that key (none
	// registered yet, or a mismatch the user must reconcile via
	// recovery) every rewrap returns STALE_KEY. Probe once per pull and
	// skip the inline rewrap in that case: the rows still decrypt and
	// render via the candidate keys, and we avoid a doomed per-blob 409
	// storm on every sync.
	canRewrap := currentPrimaryKeyIs(ctx, deps, sess, targetKIDHex)

	out := &PullResponse{NextCursor: nextCursor}
	var okCount, failCount, legacyCount int
	for _, id := range ids {
		item := pullOne(ctx, deps, sess, scope, id, keys, targetKey, targetKIDHex, canRewrap)
		out.Items = append(out.Items, item)
		switch {
		case !item.OK:
			failCount++
		case item.NeedsRewrap:
			legacyCount++
			okCount++
		default:
			okCount++
		}
	}
	deps.logInfo("pull done: user=%s scope=%s ok=%d failed=%d legacy_needs_rewrap=%d",
		sess.Claims.Subject, scope, okCount, failCount, legacyCount)
	return out, nil
}

func pullOne(
	ctx context.Context,
	deps Deps,
	sess Session,
	scope envelope.Scope,
	id string,
	keys []envelope.Key,
	targetKey []byte,
	targetKIDHex string,
	canRewrap bool,
) PullItem {
	blob, err := deps.Controlplane.GetBlob(ctx, string(scope), id, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		var cpe *controlplane.Error
		if errors.As(err, &cpe) && cpe.StatusCode == http.StatusNotFound {
			return PullItem{ID: id, OK: false, Code: "NOT_FOUND"}
		}
		if controlplane.IsCode(err, controlplane.StatusLegacyBlobNotMigrated) {
			return PullItem{ID: id, OK: false, Code: CodeLegacyBlobNotMigrated}
		}
		return PullItem{ID: id, OK: false, Code: CodeNetwork, Reason: err.Error()}
	}

	switch envelope.Detect(blob.Ciphertext) {
	case envelope.VersionV2:
		dec, err := envelope.DecryptV2(blob.Ciphertext, keys, envelope.AAD{
			Scope:       scope,
			ID:          aadIDForScope(scope, id),
			ClerkUserID: sess.Claims.Subject,
		})
		if err != nil {
			if errors.Is(err, envelope.ErrNoMatchingKey) {
				return PullItem{ID: id, OK: false, Code: CodeUnknownKey, KeyID: dec.KeyIDHex}
			}
			return PullItem{ID: id, OK: false, Code: CodeBadRequest, Reason: err.Error()}
		}
		defer cryptopkg.Zero(dec.Plaintext)
		return PullItem{
			ID: id, OK: true,
			Plaintext:   base64.StdEncoding.EncodeToString(dec.Plaintext),
			KeyID:       dec.KeyIDHex,
			ETag:        blob.ETag,
			NeedsRewrap: false,
		}
	case envelope.VersionV0, envelope.VersionV1:
		deps.logInfo("pull legacy detected: user=%s scope=%s id=%s",
			sess.Claims.Subject, scope, id)
		dec, err := envelope.DecryptLegacy(blob.Ciphertext, keys)
		if err != nil {
			deps.logError("pull legacy decrypt failed: user=%s scope=%s id=%s err=%v",
				sess.Claims.Subject, scope, id, err)
			return PullItem{ID: id, OK: false, Code: CodeUnknownKey, Reason: "no_key_decrypted_legacy"}
		}
		defer cryptopkg.Zero(dec.Plaintext)
		if canRewrap {
			if newETag, rewrapErr := rewrapBlob(ctx, deps, sess, scope, id, dec.Plaintext, blob.ETag, targetKey, targetKIDHex); rewrapErr == nil {
				return PullItem{
					ID: id, OK: true,
					Plaintext:   base64.StdEncoding.EncodeToString(dec.Plaintext),
					KeyID:       targetKIDHex,
					ETag:        newETag,
					NeedsRewrap: false,
				}
			} else {
				deps.logError("pull lazy rewrap failed: user=%s scope=%s id=%s err=%v",
					sess.Claims.Subject, scope, id, rewrapErr)
			}
		}
		// rewrap is best-effort: if the controlplane PUT loses a CAS
		// race or the buckets-cascade trips, surface the legacy
		// plaintext so the caller can still render the row. The
		// /v1/blobs/migrate endpoint stays available for a backstop
		// pass that retries failed rewraps.
		return PullItem{
			ID: id, OK: true,
			Plaintext:   base64.StdEncoding.EncodeToString(dec.Plaintext),
			KeyID:       dec.KeyIDHex,
			ETag:        blob.ETag,
			NeedsRewrap: true,
		}
	default:
		return PullItem{ID: id, OK: false, Code: CodeBadRequest, Reason: "unknown_envelope_format"}
	}
}

func ListStatus(ctx context.Context, deps Deps, sess Session, req ListStatusRequest) (*ListStatusResponse, error) {
	if !envelope.Scope(req.Scope).Valid() {
		return nil, badRequest("invalid scope")
	}
	if req.ProjectID != "" && envelope.Scope(req.Scope) != envelope.ScopeChat {
		return nil, badRequest("project_id filter is only valid for chat scope")
	}
	if req.Direction != "" && req.Direction != "asc" && req.Direction != "desc" {
		return nil, badRequest("invalid direction (must be 'asc' or 'desc')")
	}
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}
	deps.logInfo("list-status begin: user=%s scope=%s limit=%d project=%s direction=%q cursor=%q",
		sess.Claims.Subject, req.Scope, req.Limit, req.ProjectID, req.Direction, req.Cursor)
	resp, err := deps.Controlplane.ListStatus(ctx, req.Scope, req.Cursor, req.Limit, sess.RawJWT, sess.Claims.Subject, req.ProjectID, req.Direction)
	if err != nil {
		deps.logError("list-status failed: user=%s scope=%s err=%v",
			sess.Claims.Subject, req.Scope, err)
		return nil, err
	}
	deps.logInfo("list-status ok: user=%s scope=%s updates=%d deletes=%d next_cursor=%q",
		sess.Claims.Subject, req.Scope, len(resp.Updates), len(resp.Deletes), resp.NextCursor)
	out := &ListStatusResponse{NextCursor: resp.NextCursor}
	for _, u := range resp.Updates {
		update := ListStatusUpdate{
			ID:        u.ID,
			ETag:      u.ETag,
			KeyID:     u.KeyID,
			UpdatedAt: u.UpdatedAt.UTC().Format(time.RFC3339Nano),
			Cursor:    u.Cursor,
		}
		if u.ProjectID != nil {
			pid := *u.ProjectID
			update.ProjectID = &pid
		}
		out.Updates = append(out.Updates, update)
	}
	for _, d := range resp.Deletes {
		out.Deletes = append(out.Deletes, ListStatusDelete{
			ID:        d.ID,
			Scope:     d.Scope,
			DeletedAt: d.DeletedAt.UTC().Format(time.RFC3339Nano),
			Cursor:    d.Cursor,
		})
	}
	return out, nil
}

func Delete(ctx context.Context, deps Deps, sess Session, req DeleteRequest) (*OKResponse, error) {
	scope := envelope.Scope(req.Scope)
	if !scope.Valid() {
		return nil, badRequest("invalid scope")
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}
	if req.ID == "" {
		return nil, badRequest("id is required")
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

	deps.logInfo("delete begin: user=%s scope=%s id=%s kid=%s if_match=%v",
		sess.Claims.Subject, scope, req.ID, kidHex, req.IfMatch)

	// If the caller passed a concrete ifMatch, run a single CAS-delete
	// against that etag — a STALE_BLOB surfaces to the caller because
	// they explicitly chose to race the etag they had.
	if req.IfMatch != nil && *req.IfMatch != "" {
		resp, cpResp, err := deleteOnce(ctx, deps, sess, req, key, kidHex, *req.IfMatch)
		if err != nil {
			deps.logError("delete (explicit if_match) failed: user=%s scope=%s id=%s err=%v",
				sess.Claims.Subject, scope, req.ID, err)
			return nil, err
		}
		sourceRevision := int64(0)
		if cpResp != nil {
			sourceRevision = cpResp.SourceRevision
			if scope == envelope.ScopeChat {
				deleteBucketAttachments(ctx, deps, sess.Claims.Subject, cpResp.WipedV2Attachments)
			}
		}
		dropChatFromSearch(ctx, deps, sess, scope, req.ID, key, sourceRevision)
		deps.logInfo("delete ok: user=%s scope=%s id=%s", sess.Claims.Subject, scope, req.ID)
		return resp, nil
	}

	// Otherwise the caller asked us to "just delete it" (`ifMatch=null`).
	// Loop: fetch current etag, CAS-delete with it, retry on STALE_BLOB
	// up to deleteMaxRetries times so a concurrent push from another
	// tab can't strand the user's delete intent. The idempotency key
	// is augmented with the retry counter so each attempt's cache row
	// is independent — otherwise a replay of attempt 1 would echo
	// "OK" even after attempt 2 actually deleted the row.
	for attempt := 0; attempt < deleteMaxRetries; attempt++ {
		blob, err := deps.Controlplane.GetBlob(ctx, req.Scope, req.ID, sess.RawJWT, sess.Claims.Subject)
		if err != nil {
			var cpe *controlplane.Error
			if errors.As(err, &cpe) && cpe.StatusCode == http.StatusNotFound {
				// The blob may be gone while its index entry survived
				// (an earlier delete that failed after the blob write,
				// or a crash between the two); the idempotent replay
				// must still finish the search cleanup.
				dropChatFromSearch(ctx, deps, sess, scope, req.ID, key, 0)
				deps.logInfo("delete already-gone: user=%s scope=%s id=%s",
					sess.Claims.Subject, scope, req.ID)
				return &OKResponse{OK: true}, nil
			}
			deps.logError("delete fetch-etag failed: user=%s scope=%s id=%s attempt=%d err=%v",
				sess.Claims.Subject, scope, req.ID, attempt, err)
			return nil, err
		}
		attemptReq := req
		idem := req.IdempotencyKey
		if attempt > 0 {
			idem = fmt.Sprintf("%s:retry:%d", req.IdempotencyKey, attempt)
		}
		attemptReq.IdempotencyKey = idem
		resp, cpResp, err := deleteOnce(ctx, deps, sess, attemptReq, key, kidHex, blob.ETag)
		if err == nil {
			sourceRevision := int64(0)
			if scope == envelope.ScopeChat && cpResp != nil {
				// cpResp.WipedV2Attachments is the controlplane's
				// authoritative list of v2 attachment ids that
				// belonged to this (user, chat); the SQL that
				// produces it (DeleteChatAttachmentsByChatReturningV2)
				// filters on (clerk_user_id, chat_id) so the enclave
				// can trust it the same way every other write path
				// trusts controlplane authority over ownership.
				deleteBucketAttachments(ctx, deps, sess.Claims.Subject, cpResp.WipedV2Attachments)
			}
			if cpResp != nil {
				sourceRevision = cpResp.SourceRevision
			}
			dropChatFromSearch(ctx, deps, sess, scope, req.ID, key, sourceRevision)
			deps.logInfo("delete ok: user=%s scope=%s id=%s attempt=%d",
				sess.Claims.Subject, scope, req.ID, attempt)
			return resp, nil
		}
		if controlplane.IsCode(err, controlplane.StatusStaleBlob) {
			deps.logInfo("delete stale, retrying: user=%s scope=%s id=%s attempt=%d",
				sess.Claims.Subject, scope, req.ID, attempt)
			continue
		}
		deps.logError("delete attempt failed: user=%s scope=%s id=%s attempt=%d err=%v",
			sess.Claims.Subject, scope, req.ID, attempt, err)
		return nil, err
	}
	deps.logError("delete exhausted retries: user=%s scope=%s id=%s",
		sess.Claims.Subject, scope, req.ID)
	return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "delete_exhausted_retries"}
}

const deleteMaxRetries = 3

func deleteOnce(ctx context.Context, deps Deps, sess Session, req DeleteRequest, key []byte, kidHex, ifMatch string) (*OKResponse, *controlplane.DeleteBlobResponse, error) {
	opHash, err := operationHashForBlob(key, http.MethodDelete, req.Scope, req.ID, kidHex, ifMatch, req.IdempotencyKey, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	cpResp, err := deps.Controlplane.DeleteBlob(ctx, controlplane.DeleteBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		ClerkUserID:    sess.Claims.Subject,
		IfMatch:        ifMatch,
		IdempotencyKey: req.IdempotencyKey,
		OperationHash:  opHash,
	})
	if err != nil {
		return nil, nil, err
	}
	return &OKResponse{OK: true}, cpResp, nil
}

func RegisterKey(ctx context.Context, deps Deps, sess Session, req KeyRegisterRequest) (*KeyRegisterResponse, error) {
	switch req.CreatedVia {
	case "passkey", "manual", "recovery", "start_fresh":
	default:
		return nil, badRequest("invalid created_via")
	}
	if req.IfMatch == "" {
		return nil, badRequest("if_match is required (use \"*\" to mean no current key)")
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

	var bundle *controlplane.RegisterKeyBundle
	if req.InitialBundle != nil {
		if req.InitialBundle.CredentialID == "" {
			return nil, badRequest("initial_bundle.credential_id is required when initial_bundle is set")
		}
		if err := validateCanonicalBundleShape(
			req.InitialBundle.KEKIV,
			req.InitialBundle.EncryptedKeys,
		); err != nil {
			return nil, err
		}
		bundle = &controlplane.RegisterKeyBundle{
			CredentialID:  req.InitialBundle.CredentialID,
			KEKIV:         req.InitialBundle.KEKIV,
			EncryptedKeys: req.InitialBundle.EncryptedKeys,
		}
	}
	cpReq := controlplane.RegisterKeyRequest{
		JWT:            sess.RawJWT,
		ClerkUserID:    sess.Claims.Subject,
		KeyIDHex:       kidHex,
		IfMatch:        req.IfMatch,
		CreatedVia:     req.CreatedVia,
		IdempotencyKey: req.IdempotencyKey,
		InitialBundle:  bundle,
	}
	body, err := controlplane.RegisterKeyBody(cpReq)
	if err != nil {
		return nil, err
	}
	opKey, err := cryptopkg.DeriveOpHashKey(key)
	if err != nil {
		return nil, err
	}
	defer cryptopkg.Zero(opKey)
	cpReq.OperationHash = cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         http.MethodPost,
		Path:           controlplane.RegisterKeyPath,
		KeyIDHex:       kidHex,
		IfMatch:        req.IfMatch,
		IdempotencyKey: req.IdempotencyKey,
		Body:           body,
	})

	deps.logInfo("key register begin: user=%s kid=%s created_via=%s if_match=%s bundle=%t",
		sess.Claims.Subject, kidHex, req.CreatedVia, req.IfMatch, req.InitialBundle != nil)
	cpResp, err := deps.Controlplane.RegisterKey(ctx, cpReq)
	if err != nil {
		deps.logError("key register failed: user=%s kid=%s err=%v",
			sess.Claims.Subject, kidHex, err)
		return nil, err
	}
	deps.logInfo("key register ok: user=%s kid=%s wiped_attachments=%d",
		sess.Claims.Subject, kidHex, len(cpResp.WipedV2Attachments))
	// Drain the buckets blobs the controlplane wiped under the
	// start-fresh bypass. The controlplane already committed its
	// half of the wipe; failures here only leave orphaned buckets
	// entries (unreachable to anyone without the old CEK + AAD),
	// so the cascade is fire-and-forget per-id and never fails the
	// register-key call.
	deleteBucketAttachments(ctx, deps, sess.Claims.Subject, cpResp.WipedV2Attachments)
	return &KeyRegisterResponse{OK: true, KeyID: kidHex}, nil
}

func AddBundle(ctx context.Context, deps Deps, sess Session, req AddBundleRequest) (*OKResponse, error) {
	if len(req.KeyID) != 32 || !isLowerHex(req.KeyID) {
		return nil, badRequest("invalid key_id")
	}
	if req.CredentialID == "" || req.KEKIV == "" || req.EncryptedKeys == "" {
		return nil, badRequest("credential_id, kek_iv, encrypted_keys are required")
	}
	if err := validateCanonicalBundleShape(req.KEKIV, req.EncryptedKeys); err != nil {
		return nil, err
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}
	cpReq := controlplane.AddBundleRequest{
		JWT:            sess.RawJWT,
		ClerkUserID:    sess.Claims.Subject,
		KeyIDHex:       req.KeyID,
		CredentialID:   req.CredentialID,
		KEKIV:          req.KEKIV,
		EncryptedKeys:  req.EncryptedKeys,
		IdempotencyKey: req.IdempotencyKey,
	}
	body, err := controlplane.AddBundleBody(cpReq)
	if err != nil {
		return nil, err
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
	if kidHex := cryptopkg.KeyIDHex(kidBytes); kidHex != req.KeyID {
		return nil, badRequest("key does not match key_id")
	}
	opHash, err := operationHashForKey(key, http.MethodPost, controlplane.AddBundlePath(req.KeyID), req.KeyID, req.IdempotencyKey, body)
	if err != nil {
		return nil, err
	}
	cpReq.OperationHash = opHash
	deps.logInfo("key add-bundle begin: user=%s kid=%s credential=%s",
		sess.Claims.Subject, req.KeyID, req.CredentialID)
	err = deps.Controlplane.AddBundle(ctx, cpReq)
	if err != nil {
		deps.logError("key add-bundle failed: user=%s kid=%s credential=%s err=%v",
			sess.Claims.Subject, req.KeyID, req.CredentialID, err)
		return nil, err
	}
	deps.logInfo("key add-bundle ok: user=%s kid=%s credential=%s",
		sess.Claims.Subject, req.KeyID, req.CredentialID)
	return &OKResponse{OK: true}, nil
}

func RemoveBundle(ctx context.Context, deps Deps, sess Session, req RemoveBundleRequest) (*OKResponse, error) {
	if len(req.KeyID) != 32 || !isLowerHex(req.KeyID) {
		return nil, badRequest("invalid key_id")
	}
	if req.CredentialID == "" {
		return nil, badRequest("credential_id is required")
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}
	cpReq := controlplane.RemoveBundleRequest{
		JWT:            sess.RawJWT,
		ClerkUserID:    sess.Claims.Subject,
		KeyIDHex:       req.KeyID,
		CredentialID:   req.CredentialID,
		IdempotencyKey: req.IdempotencyKey,
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
	if kidHex := cryptopkg.KeyIDHex(kidBytes); kidHex != req.KeyID {
		return nil, badRequest("key does not match key_id")
	}
	opHash, err := operationHashForKey(key, http.MethodDelete, controlplane.RemoveBundlePath(req.KeyID, req.CredentialID), req.KeyID, req.IdempotencyKey, nil)
	if err != nil {
		return nil, err
	}
	cpReq.OperationHash = opHash
	deps.logInfo("key remove-bundle begin: user=%s kid=%s credential=%s",
		sess.Claims.Subject, req.KeyID, req.CredentialID)
	err = deps.Controlplane.RemoveBundle(ctx, cpReq)
	if err != nil {
		deps.logError("key remove-bundle failed: user=%s kid=%s credential=%s err=%v",
			sess.Claims.Subject, req.KeyID, req.CredentialID, err)
		return nil, err
	}
	deps.logInfo("key remove-bundle ok: user=%s kid=%s credential=%s",
		sess.Claims.Subject, req.KeyID, req.CredentialID)
	return &OKResponse{OK: true}, nil
}

func operationHashForKey(cek []byte, method, path, keyIDHex, idempotencyKey string, body []byte) (string, error) {
	opKey, err := cryptopkg.DeriveOpHashKey(cek)
	if err != nil {
		return "", err
	}
	defer cryptopkg.Zero(opKey)
	return cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         method,
		Path:           path,
		KeyIDHex:       keyIDHex,
		IfMatch:        "",
		IdempotencyKey: idempotencyKey,
		Body:           body,
	}), nil
}

// KeyCurrent fetches the user's current KeyID + bundles from the
// controlplane and re-shapes the response into the webapp's
// expected envelope. Per the webapp SDK convention, a missing key
// surfaces as KeyID=nil + empty bundles via a 404 from the
// controlplane; we re-emit that 404 here.
func KeyCurrent(ctx context.Context, deps Deps, sess Session, _ KeyCurrentRequest) (*KeyCurrentResponse, error) {
	deps.logInfo("key current begin: user=%s", sess.Claims.Subject)
	resp, err := deps.Controlplane.GetCurrentKey(ctx, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		deps.logError("key current failed: user=%s err=%v", sess.Claims.Subject, err)
		return nil, err
	}
	// No registered key. Older controlplanes answer with a 404 (resp ==
	// nil); newer ones return 200 with an empty key_id plus has_data.
	// Either way, surface the null-key shape with has_data so the client
	// can tell a brand-new user apart from a legacy user whose blobs
	// predate the key registry.
	if resp == nil || resp.KeyID == "" {
		hasData := false
		if resp != nil {
			hasData = resp.HasData
		}
		deps.logInfo("key current absent: user=%s has_data=%t", sess.Claims.Subject, hasData)
		return &KeyCurrentResponse{
			KeyID:   nil,
			Bundles: map[string]KeyCurrentBundle{},
			HasData: hasData,
		}, nil
	}
	deps.logInfo("key current ok: user=%s kid=%s bundles=%d created_via=%s",
		sess.Claims.Subject, resp.KeyID, len(resp.Bundles), resp.CreatedVia)
	out := &KeyCurrentResponse{
		KeyID:      &resp.KeyID,
		ETag:       resp.ETag,
		CreatedVia: resp.CreatedVia,
		Bundles:    make(map[string]KeyCurrentBundle, len(resp.Bundles)),
		HasData:    resp.HasData,
	}
	if resp.CreatedAt != "" {
		out.CreatedAt = resp.CreatedAt
	}
	for cid, b := range resp.Bundles {
		out.Bundles[cid] = KeyCurrentBundle{
			CredentialID:  b.CredentialID,
			KEKIV:         b.KEKIV,
			EncryptedKeys: b.EncryptedKeys,
		}
		if b.RegisteredAt != "" {
			ent := out.Bundles[cid]
			ent.CreatedAt = b.RegisteredAt
			ent.UpdatedAt = b.RegisteredAt
			out.Bundles[cid] = ent
		}
	}
	return out, nil
}

func Migrate(ctx context.Context, deps Deps, sess Session, req MigrateRequest) (*MigrateResponse, error) {
	scope := envelope.Scope(req.Scope)
	if !scope.Valid() {
		return nil, badRequest("invalid scope")
	}
	if len(req.Keys) == 0 {
		return nil, badRequest("keys is required and must not be empty")
	}
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 50
	}
	targetKey, err := decodeKey(req.Target.Key)
	if err != nil {
		return nil, badRequest("invalid target.key: " + err.Error())
	}
	defer cryptopkg.Zero(targetKey)

	targetKIDBytes, err := cryptopkg.DeriveKeyID(targetKey)
	if err != nil {
		return nil, err
	}
	targetKIDHex := cryptopkg.KeyIDHex(targetKIDBytes)

	keys, cleanup, err := decodeKeys(req.Keys)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	deps.logInfo("migrate begin: user=%s scope=%s target_kid=%s candidate_keys=%d limit=%d explicit_ids=%d",
		sess.Claims.Subject, scope, targetKIDHex, len(keys), req.Limit, len(req.IDs))

	var ids []string
	var retryableRemaining, blockedUnmigrated int

	if len(req.IDs) > 0 {
		ids = req.IDs
	} else {
		list, err := deps.Controlplane.ListNeedsMigration(ctx, req.Scope, req.Limit, sess.RawJWT, sess.Claims.Subject)
		if err != nil {
			deps.logError("migrate list-needs failed: user=%s scope=%s err=%v",
				sess.Claims.Subject, scope, err)
			return nil, err
		}
		ids = list.IDs
		retryableRemaining = list.RetryableRemaining
		blockedUnmigrated = list.BlockedUnmigrated
		deps.logInfo("migrate list-needs: user=%s scope=%s ids=%d retryable_remaining=%d blocked_unmigrated=%d",
			sess.Claims.Subject, scope, len(ids), retryableRemaining, blockedUnmigrated)
	}

	out := &MigrateResponse{}
	for _, id := range ids {
		// Bail before touching CP if the run is being torn down (the
		// detached migration job hit its budget, the enclave is
		// shutting down, etc). Without this guard the loop would
		// stamp every remaining id as "blocked" with a canceled
		// fetch, burning the 24h cooldown on rows we never actually
		// attempted.
		if ctxErr := ctx.Err(); ctxErr != nil {
			deps.logInfo("migrate cancellation observed: user=%s scope=%s processed=%d remaining=%d err=%v",
				sess.Claims.Subject, scope, out.Migrated+len(out.Blocked), len(ids)-(out.Migrated+len(out.Blocked)), ctxErr)
			break
		}
		ok := migrateOne(ctx, deps, sess, scope, id, keys, targetKey, targetKIDHex)
		if ok {
			out.Migrated++
			continue
		}
		// migrateOne returned false. If that was because ctx was
		// cancelled mid-fetch (rather than a real decrypt/rewrap
		// failure), don't record a migration failure or count the
		// row as blocked — the row stays retryable.
		if ctxErr := ctx.Err(); ctxErr != nil {
			deps.logInfo("migrate cancellation observed mid-item: user=%s scope=%s id=%s err=%v",
				sess.Claims.Subject, scope, id, ctxErr)
			break
		}
		out.Blocked = append(out.Blocked, id)
		if err := deps.Controlplane.RecordMigrationFailure(ctx, req.Scope, id, sess.RawJWT, sess.Claims.Subject); err != nil {
			deps.logError("migrate record-failure failed: user=%s scope=%s id=%s err=%v",
				sess.Claims.Subject, scope, id, err)
		}
	}

	if len(req.IDs) == 0 {
		out.RetryableRemaining = retryableRemaining - out.Migrated
		if out.RetryableRemaining < 0 {
			out.RetryableRemaining = 0
		}
		out.BlockedUnmigrated = blockedUnmigrated
	} else {
		out.RetryableRemaining = 0
		out.BlockedUnmigrated = len(out.Blocked)
	}

	deps.logInfo("migrate done: user=%s scope=%s migrated=%d blocked=%d retryable_remaining=%d blocked_unmigrated=%d",
		sess.Claims.Subject, scope, out.Migrated, len(out.Blocked), out.RetryableRemaining, out.BlockedUnmigrated)

	return out, nil
}

// MigrateAll drains every scope until empty or the wall-clock budget
// is hit, then returns an aggregate report. Callers do not paginate:
// the enclave loops internally so the client-side migration code is a
// single one-shot call. We cap each call at MigrateAllBudget so the
// HTTP write-timeout can never trip mid-stream; if work remains, the
// response sets Partial=true and the client schedules a follow-up.
//
// Why scopes run sequentially instead of in parallel: every scope
// targets the same set of user keys, and the controlplane Rewrap
// query already CAS-protects each row. Sequential keeps the cost
// profile predictable and avoids contention against a single user's
// row set, which the controlplane indexes as one btree per scope.
const (
	MigrateAllBudget         = 10 * time.Minute
	MigrateAllRequestTimeout = MigrateAllBudget + 2*time.Minute
	migrateAllScopeMaxBatch  = 200
)

// migrationProgressReporter is the seam between MigrateAll and the
// background MigrationJob. The job snapshots state for HTTP polling
// from these callbacks; passing nil disables reporting (used by
// tests and the legacy synchronous MigrateAll entrypoint).
type migrationProgressReporter interface {
	reportScope(MigrateAllScopeReport)
	markPartial()
}

// MigrateAll preserves the legacy synchronous signature for tests
// and any direct callers; production traffic goes through the
// background coordinator, which calls migrateAllWithProgress.
func MigrateAll(ctx context.Context, deps Deps, sess Session, req MigrateAllRequest) (*MigrateAllResponse, error) {
	return migrateAllWithProgress(ctx, deps, sess, req, nil)
}

func migrateAllWithProgress(ctx context.Context, deps Deps, sess Session, req MigrateAllRequest, progress migrationProgressReporter) (*MigrateAllResponse, error) {
	if len(req.Keys) == 0 {
		return nil, badRequest("keys is required and must not be empty")
	}
	if req.Target.Key == "" {
		return nil, badRequest("target.key is required")
	}

	if err := ensureCurrentKeyRegistered(ctx, deps, sess, req.Target.Key); err != nil {
		deps.logError("migrate-all bootstrap current-key failed: user=%s err=%v",
			sess.Claims.Subject, err)
		return nil, err
	}

	deadline := time.Now().Add(MigrateAllBudget)
	scopes := []envelope.Scope{
		envelope.ScopeProfile,
		envelope.ScopeChat,
		envelope.ScopeProject,
		envelope.ScopeProjectDocument,
	}

	deps.logInfo("migrate-all begin: user=%s scopes=%d budget=%s candidate_keys=%d",
		sess.Claims.Subject, len(scopes), MigrateAllBudget, len(req.Keys))

	out := &MigrateAllResponse{Scopes: make([]MigrateAllScopeReport, 0, len(scopes))}

	for _, scope := range scopes {
		report := MigrateAllScopeReport{Scope: string(scope)}
		pages := 0

		for {
			if ctxErr := ctx.Err(); ctxErr != nil {
				out.Partial = true
				if progress != nil {
					progress.markPartial()
				}
				deps.logInfo("migrate-all context done: user=%s scope=%s pages=%d err=%v",
					sess.Claims.Subject, scope, pages, ctxErr)
				break
			}
			if time.Now().After(deadline) {
				out.Partial = true
				if progress != nil {
					progress.markPartial()
				}
				deps.logInfo("migrate-all budget exhausted: user=%s scope=%s pages=%d",
					sess.Claims.Subject, scope, pages)
				break
			}
			budgetLeft := time.Until(deadline)
			if budgetLeft <= 0 {
				out.Partial = true
				if progress != nil {
					progress.markPartial()
				}
				deps.logInfo("migrate-all budget exhausted: user=%s scope=%s pages=%d",
					sess.Claims.Subject, scope, pages)
				break
			}

			subCtx, cancel := context.WithTimeout(ctx, budgetLeft)
			page, err := Migrate(subCtx, deps, sess, MigrateRequest{
				Scope:  string(scope),
				Limit:  migrateAllScopeMaxBatch,
				Keys:   req.Keys,
				Target: req.Target,
			})
			cancel()
			if err != nil {
				// Auth-layer failures (user JWT expired without
				// service-auth fallback, missing enclave secret,
				// wrong keys) will hit every subsequent call
				// the same way. Surface Partial=true so the
				// client retries with a fresh token instead of
				// burning the loop on a thousand 401s.
				if isAuthError(err) {
					deps.logError("migrate-all auth failed mid-loop, aborting: user=%s scope=%s page=%d err=%v",
						sess.Claims.Subject, scope, pages, err)
					out.Partial = true
					if progress != nil {
						progress.markPartial()
					}
					break
				}
				deps.logError("migrate-all page failed: user=%s scope=%s page=%d err=%v",
					sess.Claims.Subject, scope, pages, err)
				return nil, err
			}
			pages++

			report.Migrated += page.Migrated
			if len(page.Blocked) > 0 {
				report.Blocked = append(report.Blocked, page.Blocked...)
			}
			report.RetryableRemaining = page.RetryableRemaining
			report.BlockedUnmigrated = page.BlockedUnmigrated
			if progress != nil {
				progress.reportScope(cloneScopeReport(report))
			}

			if page.Migrated == 0 || page.RetryableRemaining == 0 {
				break
			}
		}

		deps.logInfo("migrate-all scope done: user=%s scope=%s pages=%d migrated=%d blocked=%d retryable_remaining=%d blocked_unmigrated=%d",
			sess.Claims.Subject, scope, pages, report.Migrated, len(report.Blocked), report.RetryableRemaining, report.BlockedUnmigrated)

		out.Migrated += report.Migrated
		out.RetryableRemaining += report.RetryableRemaining
		out.BlockedUnmigrated += report.BlockedUnmigrated
		out.Scopes = append(out.Scopes, report)

		if out.Partial {
			break
		}
	}

	deps.logInfo("migrate-all done: user=%s migrated=%d retryable_remaining=%d blocked_unmigrated=%d partial=%t",
		sess.Claims.Subject, out.Migrated, out.RetryableRemaining, out.BlockedUnmigrated, out.Partial)

	return out, nil
}

func cloneScopeReport(in MigrateAllScopeReport) MigrateAllScopeReport {
	out := in
	if len(in.Blocked) > 0 {
		out.Blocked = append([]string(nil), in.Blocked...)
	}
	return out
}

// ensureCurrentKeyRegistered guarantees the user has a primary key on
// the controlplane before the migration loop runs. Without it, every
// rewrap returns STALE_KEY because controlplane gates the CAS update
// on current_key_id, and a freshly-arrived v2 user whose `user_keys`
// row was never written would burn the whole migration on 409s.
//
// Idempotent when the registered current key already matches the
// target. When a current key exists but differs from the target, the
// call fails fast with STALE_KEY instead of letting the migration loop
// fire a doomed rewrap against every blob — those all return STALE_KEY
// from the controlplane CAS and only produce a 409 storm. The client
// must reconcile the key (recovery / key change) before retrying.
func ensureCurrentKeyRegistered(
	ctx context.Context,
	deps Deps,
	sess Session,
	targetKeyB64 string,
) error {
	current, err := deps.Controlplane.GetCurrentKey(ctx, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		return fmt.Errorf("inspect current key: %w", err)
	}

	targetBytes, err := decodeKey(targetKeyB64)
	if err != nil {
		return badRequest("invalid target.key: " + err.Error())
	}
	defer cryptopkg.Zero(targetBytes)

	targetKIDBytes, err := cryptopkg.DeriveKeyID(targetBytes)
	if err != nil {
		return err
	}
	targetKIDHex := cryptopkg.KeyIDHex(targetKIDBytes)

	if current != nil && current.KeyID != "" {
		if current.KeyID != targetKIDHex {
			deps.logError("migrate-all bootstrap: user=%s target kid=%s != current kid=%s; refusing to migrate",
				sess.Claims.Subject, targetKIDHex, current.KeyID)
			return &AppError{
				Status:  http.StatusConflict,
				Code:    CodeStaleKey,
				Reason:  "stale_key",
				Message: "migration target is not the registered current key",
			}
		}
		deps.logInfo("migrate-all bootstrap: user=%s current_kid=%s target_kid=%s",
			sess.Claims.Subject, current.KeyID, targetKIDHex)
		return nil
	}

	// No current key is registered. Do NOT bootstrap one here: the
	// register-key path (passkey / manual / start-fresh) is the only
	// place that also persists a key bundle. Registering a bundleless
	// current key strands the account — a key_id with no bundle hides
	// the user's legacy passkey and forces manual recovery. The client
	// must register the primary key (with its bundle) before driving
	// migration, so surface a precondition error instead of stamping a
	// key the user can never unlock.
	deps.logError("migrate-all bootstrap: user=%s no current key registered; refusing to migrate target kid=%s",
		sess.Claims.Subject, targetKIDHex)
	return &AppError{
		Status:  http.StatusConflict,
		Code:    CodeUnknownKey,
		Reason:  "no_current_key",
		Message: "no current key registered; register the primary key before migrating",
	}
}

// currentPrimaryKeyIs reports whether the user's registered current key
// is exactly targetKIDHex. Every rewrap CAS on the controlplane is
// gated on the current key id, so a rewrap toward any other key (none
// registered yet, or a key the user must still reconcile) is guaranteed
// to return STALE_KEY. Read paths probe this once per batch to skip a
// doomed per-blob rewrap. A probe failure returns false so we err
// toward not rewrapping rather than storming.
func currentPrimaryKeyIs(ctx context.Context, deps Deps, sess Session, targetKIDHex string) bool {
	current, err := deps.Controlplane.GetCurrentKey(ctx, sess.RawJWT, sess.Claims.Subject)
	if err != nil {
		deps.logError("current-key probe failed: user=%s target_kid=%s err=%v",
			sess.Claims.Subject, targetKIDHex, err)
		return false
	}
	return current != nil && current.KeyID == targetKIDHex
}

// isAuthError reports whether err originates from a 401/403 from
// controlplane. Used to abort the migrate-all loop cleanly instead of
// hammering CP once the auth chain has broken (expired user JWT,
// missing service secret, wrong keys).
func isAuthError(err error) bool {
	var cpe *controlplane.Error
	if !errors.As(err, &cpe) {
		return false
	}
	return cpe.StatusCode == http.StatusUnauthorized || cpe.StatusCode == http.StatusForbidden
}

func migrateOne(
	ctx context.Context,
	deps Deps,
	sess Session,
	scope envelope.Scope,
	id string,
	keys []envelope.Key,
	targetKey []byte,
	targetKIDHex string,
) bool {
	// Loop: fetch the current row, decrypt the bytes we actually see,
	// and rewrap them to v2. On STALE_BLOB the row moved under us
	// (typically a concurrent migration pass, or a user push that
	// already sealed it under the current key); re-fetch and
	// re-evaluate instead of stamping a phantom failure that burns the
	// 24h cooldown. Re-reading each attempt also means we never rewrap
	// stale plaintext over newer bytes.
	for attempt := 0; attempt < migrateRewrapMaxRetries; attempt++ {
		blob, err := deps.Controlplane.GetBlob(ctx, string(scope), id, sess.RawJWT, sess.Claims.Subject)
		if err != nil {
			deps.logError("migrate item fetch failed: user=%s scope=%s id=%s err=%v",
				sess.Claims.Subject, scope, id, err)
			return false
		}
		version := envelope.Detect(blob.Ciphertext)
		if version == envelope.VersionV2 && blob.KeyID == targetKIDHex {
			// Already sealed under the target key by a concurrent
			// migration pass or a user push. The row is in the desired
			// end state, so count it migrated rather than re-sealing it
			// or recording a failure. A v2 row under a different key
			// still falls through to the rewrap below.
			deps.logInfo("migrate item already at target: user=%s scope=%s id=%s attempt=%d",
				sess.Claims.Subject, scope, id, attempt)
			return true
		}
		plaintext, ok := decryptAnyVersion(blob.Ciphertext, keys, scope, id, sess.Claims.Subject)
		if !ok {
			deps.logError("migrate item decrypt failed: user=%s scope=%s id=%s version=%v",
				sess.Claims.Subject, scope, id, version)
			return false
		}
		newETag, rerr := rewrapBlob(ctx, deps, sess, scope, id, plaintext, blob.ETag, targetKey, targetKIDHex)
		cryptopkg.Zero(plaintext)
		if rerr == nil {
			deps.logInfo("migrate item ok: user=%s scope=%s id=%s version=%v target_kid=%s new_etag=%s",
				sess.Claims.Subject, scope, id, version, targetKIDHex, newETag)
			return true
		}
		if controlplane.IsCode(rerr, controlplane.StatusStaleBlob) {
			deps.logInfo("migrate item stale, retrying: user=%s scope=%s id=%s attempt=%d",
				sess.Claims.Subject, scope, id, attempt)
			continue
		}
		deps.logError("migrate item rewrap failed: user=%s scope=%s id=%s version=%v err=%v",
			sess.Claims.Subject, scope, id, version, rerr)
		return false
	}
	deps.logError("migrate item exhausted retries: user=%s scope=%s id=%s",
		sess.Claims.Subject, scope, id)
	return false
}

const migrateRewrapMaxRetries = 3

// projectIDFromMetadata pulls the optional `projectId` field out of
// a chat push's metadata. Returns (false, nil) for non-chat scopes,
// for chat pushes that don't mention projectId at all, and for
// malformed values. A `projectId` set to nil or the empty string is
// treated as an explicit clear (the row becomes unassigned).
func projectIDFromMetadata(scope string, metadata map[string]any) (set bool, value *string) {
	if scope != string(envelope.ScopeChat) {
		return false, nil
	}
	raw, ok := metadata["projectId"]
	if !ok {
		return false, nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return true, nil
		}
		copy := v
		return true, &copy
	case nil:
		return true, nil
	default:
		return false, nil
	}
}

// messageCountFromMetadata pulls the optional `messageCount` field
// out of a chat push's metadata map. Returns nil for non-chat scopes
// or when the metadata is missing/malformed; the controlplane treats
// a missing X-Message-Count as "don't change the column" on update
// and "0" on insert.
func messageCountFromMetadata(scope string, metadata map[string]any) *int {
	if scope != string(envelope.ScopeChat) {
		return nil
	}
	raw, ok := metadata["messageCount"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case float64:
		if v < 0 {
			return nil
		}
		n := int(v)
		return &n
	case int:
		if v < 0 {
			return nil
		}
		return &v
	default:
		return nil
	}
}

// aadIDForScope maps a controlplane storage id to the canonical
// envelope AAD id. Profile is the only scope where the two differ: the
// controlplane keys a user's profile row by clerk_user_id, so its list
// and needs-migration endpoints return the user id as the row id, while
// the envelope pins the profile AAD id to a fixed singleton. Every
// internal path that builds a v2 AAD from a controlplane-supplied id —
// the migration read, the inline pull read, and the rewrap write — must
// run the id through here, or the read and write AADs disagree for
// profiles and the row can never be decrypted again.
//
// The client-facing Push path deliberately does not use this: it keeps
// the fail-closed AAD guard so a client that forgets to send the
// profile singleton id gets a loud error instead of a silent normalize.
func aadIDForScope(scope envelope.Scope, storageID string) string {
	if scope == envelope.ScopeProfile {
		return envelope.ProfileSingletonID
	}
	return storageID
}

// decryptAnyVersion picks the right decrypt path for whichever
// envelope version the ciphertext is in. Returns the plaintext (caller
// owns the buffer and must zeroize) and ok=true on success.
func decryptAnyVersion(ciphertext []byte, keys []envelope.Key, scope envelope.Scope, id, clerkUserID string) ([]byte, bool) {
	switch envelope.Detect(ciphertext) {
	case envelope.VersionV2:
		dec, err := envelope.DecryptV2(ciphertext, keys, envelope.AAD{
			Scope:       scope,
			ID:          aadIDForScope(scope, id),
			ClerkUserID: clerkUserID,
		})
		if err != nil {
			return nil, false
		}
		return dec.Plaintext, true
	case envelope.VersionV0, envelope.VersionV1:
		dec, err := envelope.DecryptLegacy(ciphertext, keys)
		if err != nil {
			return nil, false
		}
		return dec.Plaintext, true
	default:
		return nil, false
	}
}

func Health(deps Deps) HealthResponse {
	return HealthResponse{Status: "ok", GitSHA: deps.GitSHA}
}

// ---- decoding helpers --------------------------------------------------

func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("missing key")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != cryptopkg.KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", cryptopkg.KeySize, len(b))
	}
	return b, nil
}

func decodeKeys(in []PullKey) ([]envelope.Key, func(), error) {
	out := make([]envelope.Key, 0, len(in))
	for i, k := range in {
		raw, err := decodeKey(k.Key)
		if err != nil {
			for _, prev := range out {
				cryptopkg.Zero(prev.Bytes)
			}
			return nil, nil, badRequest(fmt.Sprintf("keys[%d]: %v", i, err))
		}
		kidBytes, err := cryptopkg.DeriveKeyID(raw)
		if err != nil {
			for _, prev := range out {
				cryptopkg.Zero(prev.Bytes)
			}
			cryptopkg.Zero(raw)
			return nil, nil, err
		}
		kidHex := cryptopkg.KeyIDHex(kidBytes)
		if k.KeyID != "" && k.KeyID != kidHex {
			for _, prev := range out {
				cryptopkg.Zero(prev.Bytes)
			}
			cryptopkg.Zero(raw)
			return nil, nil, badRequest(fmt.Sprintf("keys[%d]: key_id mismatch (claimed %s, derived %s)", i, k.KeyID, kidHex))
		}
		out = append(out, envelope.Key{Bytes: raw, KeyIDHex: kidHex})
	}
	cleanup := func() {
		for _, k := range out {
			cryptopkg.Zero(k.Bytes)
		}
	}
	return out, cleanup, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Bundle wire shape. A canonical passkey bundle is AES-256-GCM over
// the user's raw 32-byte CEK with a 12-byte random IV. AES-GCM
// produces a 16-byte authentication tag appended to the ciphertext,
// so the wrapped payload is always (32 + 16) = 48 bytes -> 96 hex
// chars; the IV is 12 bytes -> 24 hex chars. Validating these on
// write keeps non-canonical legacy envelope blobs from being
// silently registered by future clients while leaving read paths
// fully back-compatible for existing rows.
const (
	canonicalBundleKEKIVHexLen         = 24
	canonicalBundleEncryptedKeysHexLen = 96
)

func validateCanonicalBundleShape(kekIV, encryptedKeys string) error {
	if len(kekIV) != canonicalBundleKEKIVHexLen || !isLowerHex(kekIV) {
		return badRequest("kek_iv must be 24 lower-hex characters (12 raw bytes)")
	}
	if len(encryptedKeys) != canonicalBundleEncryptedKeysHexLen ||
		!isLowerHex(encryptedKeys) {
		return badRequest("encrypted_keys must be 96 lower-hex characters (raw CEK wrapped with AES-GCM)")
	}
	return nil
}
