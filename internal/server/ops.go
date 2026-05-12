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

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/resolver"
)

// Deps bundles everything operations need from the surrounding process.
type Deps struct {
	Controlplane *controlplane.Client
	GitSHA       string
}

// Session is the per-request authenticated context: the bearer token (to
// forward to the controlplane) and the claims (for AAD construction).
type Session struct {
	RawJWT string
	Claims auth.Claims
}

const (
	conflictPolicyAutoMerge      = "auto_merge"
	conflictPolicyReject         = "reject"
	conflictPolicyReplaceRemote  = "replace_remote"
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

	ifMatch := ""
	if req.IfMatch != nil {
		ifMatch = *req.IfMatch
	}
	opHash := operationHashPush(req, kidHex, metaHash)

	resp, err := deps.Controlplane.PutBlob(ctx, controlplane.PutBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		KeyIDHex:       kidHex,
		IfMatch:        ifMatch,
		IdempotencyKey: req.IdempotencyKey,
		OperationHash:  opHash,
		Ciphertext:     envBlob,
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
	retryReq.IfMatch = &newIfMatch
	retryReq.IdempotencyKey = req.IdempotencyKey + ":resolved"
	opHash := operationHashPush(retryReq, kidHex, metaHash)

	resp, err := deps.Controlplane.PutBlob(ctx, controlplane.PutBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		KeyIDHex:       kidHex,
		IfMatch:        newIfMatch,
		IdempotencyKey: retryReq.IdempotencyKey,
		OperationHash:  opHash,
		Ciphertext:     envBlob,
	})
	if err != nil {
		if controlplane.IsCode(err, controlplane.StatusStaleBlob) {
			return nil, &AppError{Status: http.StatusConflict, Code: CodeSyncConflict, Reason: "rerace_after_resolve"}
		}
		return nil, err
	}
	return &PushResponse{OK: true, ETag: resp.ETag, KeyID: resp.KeyID}, nil
}

func operationHashPush(req PushRequest, kid, metaHash string) string {
	canon := map[string]any{
		"op":              "push",
		"scope":           req.Scope,
		"id":              req.ID,
		"kid":             kid,
		"if_match":        nullableString(req.IfMatch),
		"plaintext_sha":   plaintextHashFromBase64(req.Plaintext),
		"metadata_sha":    metaHash,
		"conflict_policy": req.ConflictPolicy,
		"idempotency":     req.IdempotencyKey,
	}
	b, _ := json.Marshal(canon)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func plaintextHashFromBase64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
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
		out.Updates = append(out.Updates, ListStatusUpdate{
			ID:        u.ID,
			ETag:      u.ETag,
			KeyID:     u.KeyID,
			UpdatedAt: u.UpdatedAt.Format("2006-01-02T15:04:05.000Z"),
			Cursor:    u.Cursor,
		})
	}
	for _, d := range resp.Deletes {
		out.Deletes = append(out.Deletes, ListStatusDelete{
			ID:        d.ID,
			Scope:     d.Scope,
			DeletedAt: d.DeletedAt.Format("2006-01-02T15:04:05.000Z"),
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

	ifMatch := ""
	if req.IfMatch != nil {
		ifMatch = *req.IfMatch
	}

	opHash := operationHashDelete(req)
	err := deps.Controlplane.DeleteBlob(ctx, controlplane.DeleteBlobRequest{
		Scope:          req.Scope,
		ID:             req.ID,
		JWT:            sess.RawJWT,
		IfMatch:        ifMatch,
		IdempotencyKey: req.IdempotencyKey,
		OperationHash:  opHash,
	})
	if err != nil {
		return nil, err
	}
	return &OKResponse{OK: true}, nil
}

func operationHashDelete(req DeleteRequest) string {
	canon := map[string]any{
		"op":          "delete",
		"scope":       req.Scope,
		"id":          req.ID,
		"if_match":    nullableString(req.IfMatch),
		"idempotency": req.IdempotencyKey,
	}
	b, _ := json.Marshal(canon)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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
	opHash := operationHashRegisterKey(req, kidHex)
	err = deps.Controlplane.RegisterKey(ctx, controlplane.RegisterKeyRequest{
		JWT:            sess.RawJWT,
		KeyIDHex:       kidHex,
		IfMatch:        req.IfMatch,
		CreatedVia:     req.CreatedVia,
		IdempotencyKey: req.IdempotencyKey,
		OperationHash:  opHash,
		InitialBundle:  bundle,
	})
	if err != nil {
		return nil, err
	}
	return &KeyRegisterResponse{OK: true, KeyID: kidHex}, nil
}

func operationHashRegisterKey(req KeyRegisterRequest, kid string) string {
	bundleDigest := ""
	if req.InitialBundle != nil {
		b, _ := json.Marshal(req.InitialBundle)
		h := sha256.Sum256(b)
		bundleDigest = hex.EncodeToString(h[:])
	}
	canon := map[string]any{
		"op":           "register_key",
		"kid":          kid,
		"if_match":     req.IfMatch,
		"created_via":  req.CreatedVia,
		"bundle_sha":   bundleDigest,
		"idempotency":  req.IdempotencyKey,
	}
	b, _ := json.Marshal(canon)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func AddBundle(ctx context.Context, deps Deps, sess Session, req AddBundleRequest) (*OKResponse, error) {
	if len(req.KeyID) != 32 || !isLowerHex(req.KeyID) {
		return nil, badRequest("invalid key_id")
	}
	if req.CredentialID == "" || req.KEKIV == "" || req.EncryptedKeys == "" {
		return nil, badRequest("credential_id, kek_iv, encrypted_keys are required")
	}
	err := deps.Controlplane.AddBundle(ctx, controlplane.AddBundleRequest{
		JWT:           sess.RawJWT,
		KeyIDHex:      req.KeyID,
		CredentialID:  req.CredentialID,
		KEKIV:         req.KEKIV,
		EncryptedKeys: req.EncryptedKeys,
	})
	if err != nil {
		return nil, err
	}
	return &OKResponse{OK: true}, nil
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
	if envelope.Detect(blob.Ciphertext) == envelope.VersionV2 {
		return true
	}
	dec, err := envelope.DecryptLegacy(blob.Ciphertext, keys)
	if err != nil {
		return false
	}
	defer cryptopkg.Zero(dec.Plaintext)

	aadBytes, err := envelope.CanonicalAAD(envelope.AAD{
		KeyIDHex:    targetKIDHex,
		Scope:       scope,
		ID:          id,
		ClerkUserID: sess.Claims.Subject,
	})
	if err != nil {
		return false
	}
	envBlob, err := envelope.Encrypt(targetKey, dec.Plaintext, aadBytes, targetKIDHex)
	if err != nil {
		return false
	}
	opHashBuf := sha256.Sum256(envBlob)
	opHash := hex.EncodeToString(opHashBuf[:])
	_, err = deps.Controlplane.PutBlob(ctx, controlplane.PutBlobRequest{
		Scope:          string(scope),
		ID:             id,
		JWT:            sess.RawJWT,
		KeyIDHex:       targetKIDHex,
		IfMatch:        blob.ETag,
		IdempotencyKey: "migrate:" + targetKIDHex + ":" + id + ":" + blob.ETag,
		OperationHash:  opHash,
		Rewrap:         true,
		Ciphertext:     envBlob,
	})
	return err == nil
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
