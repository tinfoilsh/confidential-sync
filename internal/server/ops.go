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
	"github.com/tinfoilsh/confidential-sync-enclave/internal/resolver"
)

// Deps bundles everything operations need from the surrounding process.
type Deps struct {
	Controlplane *controlplane.Client
	Buckets      *buckets.Client
	GitSHA       string
}

// Session is the per-request authenticated context: the bearer token (to
// forward to the controlplane) and the claims (for AAD construction).
type Session struct {
	RawJWT string
	Claims auth.Claims
}

const (
	conflictPolicyAutoMerge     = "auto_merge"
	conflictPolicyReject        = "reject"
	conflictPolicyReplaceRemote = "replace_remote"

	// createIfMatchSentinel is the wire value the controlplane uses
	// to mean "create-only" when a caller doesn't have an etag yet.
	// Must match controlplane/handlers/sync_blob_handler.go
	// (createIfMatch = "0").
	createIfMatchSentinel = "0"
)

// Push encrypts plaintext into a v2 envelope and uploads it to the
// controlplane with idempotent CAS semantics. On 412 STALE_BLOB it can
// optionally invoke the per-scope resolver and retry once.
func Push(ctx context.Context, deps Deps, sess Session, req PushRequest) (*PushResponse, error) {
	scope := envelope.Scope(req.Scope)
	if !scope.Valid() {
		return nil, badRequest("invalid scope")
	}
	if scope != envelope.ScopeProfile && req.ID == "" {
		return nil, badRequest("id is required for scope " + req.Scope)
	}
	if scope == envelope.ScopeProfile && req.ID == "" {
		req.ID = "profile"
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}
	if req.ConflictPolicy == "" {
		req.ConflictPolicy = conflictPolicyAutoMerge
	}
	switch req.ConflictPolicy {
	case conflictPolicyAutoMerge, conflictPolicyReject, conflictPolicyReplaceRemote:
	default:
		return nil, badRequest("invalid conflict_policy")
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

	metaHash, err := envelope.MetadataHash(req.Metadata)
	if err != nil {
		return nil, badRequest("invalid metadata: " + err.Error())
	}
	aadBytes, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    kidHex,
		Scope:       scope,
		ID:          req.ID,
		ClerkUserID: sess.Claims.Subject,
	})
	if err != nil {
		return nil, badRequest("invalid envelope inputs: " + err.Error())
	}

	envBlob, err := envelope.Encrypt(key, plaintext, aadBytes, kidHex)
	if err != nil {
		return nil, err
	}

	ifMatch := createIfMatchSentinel
	if req.IfMatch != nil {
		ifMatch = *req.IfMatch
	}
	opHash, err := operationHashForBlob(key, http.MethodPut, req.Scope, req.ID, kidHex, ifMatch, req.IdempotencyKey, envBlob)
	if err != nil {
		return nil, err
	}
	// metaHash is no longer mixed into the op-hash directly: it travels
	// inside the AAD and therefore inside the encrypted envelope, which
	// is itself the BODY of the canonical tuple.
	_ = metaHash

	// messageCount is metadata-only (the chat-list UI uses it for the
	// "empty chat" predicate). It is NOT mixed into the op-hash: the
	// controlplane is the authority on that column and could tamper
	// with it post-write regardless. Mixing it in would only force
	// retries to recompute the hash without changing the threat
	// model. The same reasoning applies to projectId — it surfaces
	// in list-status so cross-project moves propagate without
	// decrypting the row.
	projectIDSet, projectID := projectIDFromMetadata(req.Scope, req.Metadata)
	resp, err := deps.Controlplane.PutBlob(ctx, controlplane.PutBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
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
		return &PushResponse{OK: true, ETag: resp.ETag, KeyID: resp.KeyID}, nil
	}

	if controlplane.IsCode(err, controlplane.StatusStaleBlob) && req.ConflictPolicy != conflictPolicyReject {
		merged, mergedErr := autoResolve(ctx, deps, sess, req, key, plaintext, aadBytes)
		if mergedErr != nil {
			return nil, mergedErr
		}
		return merged, nil
	}
	return nil, err
}

func autoResolve(
	ctx context.Context,
	deps Deps,
	sess Session,
	req PushRequest,
	key, plaintext, _ []byte,
) (*PushResponse, error) {
	remote, err := deps.Controlplane.GetBlob(ctx, req.Scope, req.ID, sess.RawJWT)
	if err != nil {
		return nil, err
	}
	remoteKey := envelope.Key{Bytes: key, KeyIDHex: ""}
	kidBytes, _ := cryptopkg.DeriveKeyID(key)
	remoteKey.KeyIDHex = cryptopkg.KeyIDHex(kidBytes)

	var remotePT []byte
	switch envelope.Detect(remote.Ciphertext) {
	case envelope.VersionV2:
		dec, err := envelope.DecryptV2(remote.Ciphertext, []envelope.Key{remoteKey}, func(kid string) ([]byte, error) {
			return envelope.CanonicalAAD(envelope.AAD{
				KeyIDHex:    kid,
				Scope:       envelope.Scope(req.Scope),
				ID:          req.ID,
				ClerkUserID: sess.Claims.Subject,
			})
		})
		if err != nil {
			return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "remote_envelope_decrypt_failed"}
		}
		remotePT = dec.Plaintext
		defer cryptopkg.Zero(remotePT)
	case envelope.VersionV0, envelope.VersionV1:
		dec, err := envelope.DecryptLegacy(remote.Ciphertext, []envelope.Key{remoteKey})
		if err != nil {
			return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "remote_legacy_decrypt_failed"}
		}
		remotePT = dec.Plaintext
		defer cryptopkg.Zero(remotePT)
	default:
		return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "remote_unknown_format"}
	}

	var mergedPT []byte
	if req.ConflictPolicy == conflictPolicyReplaceRemote {
		mergedPT = plaintext
	} else {
		r, err := resolver.For(req.Scope)
		if err != nil {
			return nil, err
		}
		out, err := r.Merge(plaintext, remotePT)
		if err != nil {
			return nil, err
		}
		mergedPT = out.Plaintext
		defer cryptopkg.Zero(mergedPT)
	}

	kidHex := remoteKey.KeyIDHex
	metaHash, _ := envelope.MetadataHash(req.Metadata)
	aadBytes, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    kidHex,
		Scope:       envelope.Scope(req.Scope),
		ID:          req.ID,
		ClerkUserID: sess.Claims.Subject,
	})
	if err != nil {
		return nil, err
	}
	envBlob, err := envelope.Encrypt(key, mergedPT, aadBytes, kidHex)
	if err != nil {
		return nil, err
	}
	retryReq := req
	newIfMatch := remote.ETag
	if newIfMatch == "" {
		newIfMatch = createIfMatchSentinel
	}
	retryReq.IfMatch = &newIfMatch
	retryReq.IdempotencyKey = req.IdempotencyKey + ":resolved"
	_ = metaHash
	opHash, err := operationHashForBlob(key, http.MethodPut, req.Scope, req.ID, kidHex, newIfMatch, retryReq.IdempotencyKey, envBlob)
	if err != nil {
		return nil, err
	}

	projectIDSet, projectID := projectIDFromMetadata(req.Scope, req.Metadata)
	resp, err := deps.Controlplane.PutBlob(ctx, controlplane.PutBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		KeyIDHex:       kidHex,
		IfMatch:        newIfMatch,
		IdempotencyKey: retryReq.IdempotencyKey,
		OperationHash:  opHash,
		Ciphertext:     envBlob,
		MessageCount:   messageCountFromMetadata(req.Scope, req.Metadata),
		ProjectIDSet:   projectIDSet,
		ProjectID:      projectID,
	})
	if err != nil {
		if controlplane.IsCode(err, controlplane.StatusStaleBlob) {
			return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "rerace_after_resolve"}
		}
		return nil, err
	}
	return &PushResponse{OK: true, ETag: resp.ETag, KeyID: resp.KeyID}, nil
}

// operationHashForBlob derives X-Operation-Hash for a blob mutation
// according to syncplan.md §7.0. The canonical tuple matches exactly
// what the controlplane will see on the wire (METHOD, PATH, KEY_ID,
// IF_MATCH, IDEMPOTENCY_KEY, BODY).
func operationHashForBlob(cek []byte, method, scope, id, keyIDHex, ifMatch, idempotencyKey string, body []byte) (string, error) {
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
		Body:           body,
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
		list, err := deps.Controlplane.ListStatus(ctx, req.Scope, req.Cursor, req.Limit, sess.RawJWT)
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

	out := &PullResponse{NextCursor: nextCursor}
	for _, id := range ids {
		item := pullOne(ctx, deps, sess, scope, id, keys)
		out.Items = append(out.Items, item)
	}
	return out, nil
}

func pullOne(ctx context.Context, deps Deps, sess Session, scope envelope.Scope, id string, keys []envelope.Key) PullItem {
	blob, err := deps.Controlplane.GetBlob(ctx, string(scope), id, sess.RawJWT)
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
		dec, err := envelope.DecryptV2(blob.Ciphertext, keys, func(kid string) ([]byte, error) {
			return envelope.CanonicalAAD(envelope.AAD{
				KeyIDHex:    kid,
				Scope:       scope,
				ID:          id,
				ClerkUserID: sess.Claims.Subject,
			})
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
		dec, err := envelope.DecryptLegacy(blob.Ciphertext, keys)
		if err != nil {
			return PullItem{ID: id, OK: false, Code: CodeUnknownKey, Reason: "no_key_decrypted_legacy"}
		}
		defer cryptopkg.Zero(dec.Plaintext)
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
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 100
	}
	resp, err := deps.Controlplane.ListStatus(ctx, req.Scope, req.Cursor, req.Limit, sess.RawJWT)
	if err != nil {
		return nil, err
	}
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
	if scope == envelope.ScopeProfile && req.ID == "" {
		req.ID = "profile"
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

	// If the caller passed a concrete ifMatch, run a single CAS-delete
	// against that etag — a STALE_BLOB surfaces to the caller because
	// they explicitly chose to race the etag they had.
	if req.IfMatch != nil && *req.IfMatch != "" {
		return deleteOnce(ctx, deps, sess, req, key, kidHex, *req.IfMatch)
	}

	// Otherwise the caller asked us to "just delete it" (`ifMatch=null`).
	// Loop: fetch current etag, CAS-delete with it, retry on STALE_BLOB
	// up to deleteMaxRetries times so a concurrent push from another
	// tab can't strand the user's delete intent. The idempotency key
	// is augmented with the retry counter so each attempt's cache row
	// is independent — otherwise a replay of attempt 1 would echo
	// "OK" even after attempt 2 actually deleted the row.
	for attempt := 0; attempt < deleteMaxRetries; attempt++ {
		blob, err := deps.Controlplane.GetBlob(ctx, req.Scope, req.ID, sess.RawJWT)
		if err != nil {
			var cpe *controlplane.Error
			if errors.As(err, &cpe) && cpe.StatusCode == http.StatusNotFound {
				return &OKResponse{OK: true}, nil
			}
			return nil, err
		}
		attemptReq := req
		idem := req.IdempotencyKey
		if attempt > 0 {
			idem = fmt.Sprintf("%s:retry:%d", req.IdempotencyKey, attempt)
		}
		attemptReq.IdempotencyKey = idem
		resp, err := deleteOnce(ctx, deps, sess, attemptReq, key, kidHex, blob.ETag)
		if err == nil {
			return resp, nil
		}
		if controlplane.IsCode(err, controlplane.StatusStaleBlob) {
			continue
		}
		return nil, err
	}
	return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "delete_exhausted_retries"}
}

const deleteMaxRetries = 3

func deleteOnce(ctx context.Context, deps Deps, sess Session, req DeleteRequest, key []byte, kidHex, ifMatch string) (*OKResponse, error) {
	opHash, err := operationHashForBlob(key, http.MethodDelete, req.Scope, req.ID, kidHex, ifMatch, req.IdempotencyKey, nil)
	if err != nil {
		return nil, err
	}
	if err := deps.Controlplane.DeleteBlob(ctx, controlplane.DeleteBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		IfMatch:        ifMatch,
		IdempotencyKey: req.IdempotencyKey,
		OperationHash:  opHash,
	}); err != nil {
		return nil, err
	}
	return &OKResponse{OK: true}, nil
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
		bundle = &controlplane.RegisterKeyBundle{
			CredentialID:  req.InitialBundle.CredentialID,
			KEKIV:         req.InitialBundle.KEKIV,
			EncryptedKeys: req.InitialBundle.EncryptedKeys,
		}
	}
	cpReq := controlplane.RegisterKeyRequest{
		JWT:            sess.RawJWT,
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

	if err := deps.Controlplane.RegisterKey(ctx, cpReq); err != nil {
		return nil, err
	}
	return &KeyRegisterResponse{OK: true, KeyID: kidHex}, nil
}

func AddBundle(ctx context.Context, deps Deps, sess Session, req AddBundleRequest) (*OKResponse, error) {
	if len(req.KeyID) != 32 || !isLowerHex(req.KeyID) {
		return nil, badRequest("invalid key_id")
	}
	if req.CredentialID == "" || req.KEKIV == "" || req.EncryptedKeys == "" {
		return nil, badRequest("credential_id, kek_iv, encrypted_keys are required")
	}
	if req.IdempotencyKey == "" {
		return nil, badRequest("idempotency_key is required")
	}
	cpReq := controlplane.AddBundleRequest{
		JWT:            sess.RawJWT,
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
	opHash, err := operationHashForKey(key, http.MethodPost, controlplane.AddBundlePath(req.KeyID), req.KeyID, req.IdempotencyKey, body)
	if err != nil {
		return nil, err
	}
	cpReq.OperationHash = opHash
	err = deps.Controlplane.AddBundle(ctx, cpReq)
	if err != nil {
		return nil, err
	}
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
		KeyIDHex:       req.KeyID,
		CredentialID:   req.CredentialID,
		IdempotencyKey: req.IdempotencyKey,
	}
	key, err := decodeKey(req.Key)
	if err != nil {
		return nil, badRequest("invalid key: " + err.Error())
	}
	defer cryptopkg.Zero(key)
	opHash, err := operationHashForKey(key, http.MethodDelete, controlplane.RemoveBundlePath(req.KeyID, req.CredentialID), req.KeyID, req.IdempotencyKey, nil)
	if err != nil {
		return nil, err
	}
	cpReq.OperationHash = opHash
	err = deps.Controlplane.RemoveBundle(ctx, cpReq)
	if err != nil {
		return nil, err
	}
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
	resp, err := deps.Controlplane.GetCurrentKey(ctx, sess.RawJWT)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "no current key"}
	}
	out := &KeyCurrentResponse{
		KeyID:      &resp.KeyID,
		CreatedVia: resp.CreatedVia,
		Bundles:    make(map[string]KeyCurrentBundle, len(resp.Bundles)),
	}
	if !resp.CreatedAt.IsZero() {
		out.CreatedAt = resp.CreatedAt.Format("2006-01-02T15:04:05.000Z")
	}
	for cid, b := range resp.Bundles {
		out.Bundles[cid] = KeyCurrentBundle{
			CredentialID:  b.CredentialID,
			KEKIV:         b.KEKIV,
			EncryptedKeys: b.EncryptedKeys,
		}
		if !b.RegisteredAt.IsZero() {
			ent := out.Bundles[cid]
			ent.UpdatedAt = b.RegisteredAt.Format("2006-01-02T15:04:05.000Z")
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

	var ids []string
	var retryableRemaining, blockedUnmigrated int

	if len(req.IDs) > 0 {
		ids = req.IDs
	} else {
		list, err := deps.Controlplane.ListNeedsMigration(ctx, req.Scope, req.Limit, sess.RawJWT)
		if err != nil {
			return nil, err
		}
		ids = list.IDs
		retryableRemaining = list.RetryableRemaining
		blockedUnmigrated = list.BlockedUnmigrated
	}

	out := &MigrateResponse{}
	for _, id := range ids {
		ok := migrateOne(ctx, deps, sess, scope, id, keys, targetKey, targetKIDHex)
		if ok {
			out.Migrated++
		} else {
			out.Blocked = append(out.Blocked, id)
			_ = deps.Controlplane.RecordMigrationFailure(ctx, req.Scope, id, sess.RawJWT)
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
	MigrateAllBudget        = 4 * time.Minute
	migrateAllScopeMaxBatch = 200
)

func MigrateAll(ctx context.Context, deps Deps, sess Session, req MigrateAllRequest) (*MigrateAllResponse, error) {
	if len(req.Keys) == 0 {
		return nil, badRequest("keys is required and must not be empty")
	}
	if req.Target.Key == "" {
		return nil, badRequest("target.key is required")
	}

	deadline := time.Now().Add(MigrateAllBudget)
	scopes := []envelope.Scope{
		envelope.ScopeProfile,
		envelope.ScopeChat,
		envelope.ScopeProject,
		envelope.ScopeProjectDocument,
	}

	out := &MigrateAllResponse{Scopes: make([]MigrateAllScopeReport, 0, len(scopes))}

	for _, scope := range scopes {
		report := MigrateAllScopeReport{Scope: string(scope)}

		for {
			if time.Now().After(deadline) {
				out.Partial = true
				break
			}
			budgetLeft := time.Until(deadline)
			if budgetLeft <= 0 {
				out.Partial = true
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
				return nil, err
			}

			report.Migrated += page.Migrated
			if len(page.Blocked) > 0 {
				report.Blocked = append(report.Blocked, page.Blocked...)
			}
			report.RetryableRemaining = page.RetryableRemaining
			report.BlockedUnmigrated = page.BlockedUnmigrated

			// Stop draining this scope when nothing migrated and nothing
			// retryable is left. RetryableRemaining can plateau if every
			// remaining row keeps failing — page.Migrated == 0 catches
			// that and lets the loop fall through to the next scope.
			if page.Migrated == 0 || page.RetryableRemaining == 0 {
				break
			}
		}

		out.Migrated += report.Migrated
		out.RetryableRemaining += report.RetryableRemaining
		out.BlockedUnmigrated += report.BlockedUnmigrated
		out.Scopes = append(out.Scopes, report)

		if out.Partial {
			break
		}
	}

	return out, nil
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
	blob, err := deps.Controlplane.GetBlob(ctx, string(scope), id, sess.RawJWT)
	if err != nil {
		return false
	}
	// ListNeedsMigration only returns rows with key_id IS NULL, so we
	// re-seal and rewrap every row we see here — even V2 ones that
	// decrypt cleanly today — so the controlplane's key_id column
	// gets stamped and the row leaves the "needs migration" set
	// permanently. Returning early on V2 (the old behavior) left
	// key_id NULL forever, blocking future key rotation via
	// HasAnyUserData.
	plaintext, ok := decryptAnyVersion(blob.Ciphertext, keys, scope, id, sess.Claims.Subject)
	if !ok {
		return false
	}
	defer cryptopkg.Zero(plaintext)

	aadBytes, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    targetKIDHex,
		Scope:       scope,
		ID:          id,
		ClerkUserID: sess.Claims.Subject,
	})
	if err != nil {
		return false
	}
	envBlob, err := envelope.Encrypt(targetKey, plaintext, aadBytes, targetKIDHex)
	if err != nil {
		return false
	}
	idem := "migrate:" + targetKIDHex + ":" + id + ":" + blob.ETag
	rewrapReq := controlplane.PutBlobRequest{
		Scope:          string(scope),
		ID:             id,
		JWT:            sess.RawJWT,
		KeyIDHex:       targetKIDHex,
		IfMatch:        blob.ETag,
		IdempotencyKey: idem,
		Rewrap:         true,
		Ciphertext:     envBlob,
	}
	rewrapBody, err := controlplane.RewrapBody(rewrapReq)
	if err != nil {
		return false
	}
	opKey, err := cryptopkg.DeriveOpHashKey(targetKey)
	if err != nil {
		return false
	}
	defer cryptopkg.Zero(opKey)
	rewrapReq.OperationHash = cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         http.MethodPost,
		Path:           controlplane.RewrapPath,
		KeyIDHex:       targetKIDHex,
		IfMatch:        blob.ETag,
		IdempotencyKey: idem,
		Body:           rewrapBody,
	})
	_, err = deps.Controlplane.PutBlob(ctx, rewrapReq)
	return err == nil
}

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

// decryptAnyVersion picks the right decrypt path for whichever
// envelope version the ciphertext is in. Returns the plaintext (caller
// owns the buffer and must zeroize) and ok=true on success.
func decryptAnyVersion(ciphertext []byte, keys []envelope.Key, scope envelope.Scope, id, clerkUserID string) ([]byte, bool) {
	switch envelope.Detect(ciphertext) {
	case envelope.VersionV2:
		dec, err := envelope.DecryptV2(ciphertext, keys, func(kid string) ([]byte, error) {
			return envelope.CanonicalAAD(envelope.AAD{
				KeyIDHex:    kid,
				Scope:       scope,
				ID:          id,
				ClerkUserID: clerkUserID,
			})
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
