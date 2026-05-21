// Package localstack brings up an in-process stack — fake JWKS issuer,
// stub controlplane, real enclave handler — on real TCP listeners so
// both the local-stack daemon (`cmd/local-stack`) and the smoke test
// suite (`internal/localstack/smoke`) drive the same stack.
//
// The stub controlplane mirrors the real controlplane's HTTP shape on
// /api/sync/* with enough fidelity that the enclave
// handler exercises every real code path. It is NOT a faithful
// reimplementation: it has no Postgres, no idempotency table, and no
// op-hash verification. Tests that need those concerns belong in the
// controlplane repo.
package localstack

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/bucketstub"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

// StubBlob is a stored ciphertext envelope on the stub.
type StubBlob struct {
	ETag      int64
	KeyID     string
	Body      []byte
	UpdatedAt time.Time
}

// StubCP is the in-memory controlplane. Its methods are safe for
// concurrent use; tests can call PeekBlob / SetBlob / CopyBlob /
// InjectLegacyV0 / OnFirstGet directly to drive adversarial
// scenarios.
type StubCP struct {
	mu         sync.Mutex
	mux        *http.ServeMux
	blobs      map[string]*StubBlob
	keys       map[string]struct{}
	currentKID string
	bundles    map[string]map[string]controlplane.CurrentKeyBundle
	deletes    map[string]time.Time

	buckets           *bucketstub.Store
	legacyAttachments map[string][]byte
	attachmentIndex   map[string]string

	// onFirstDelete maps "scope/id" to a callback that fires exactly
	// once, at the very start of the first DELETE handled for that
	// key. The callback runs with the stub's mutex RELEASED so it
	// can perform its own stub-mutating calls (e.g. a racing PUT
	// that bumps the etag). The DELETE that triggered the hook
	// then proceeds — if the hook bumped the etag, the caller's
	// if_match is stale and STALE_BLOB is returned. Used by T08
	// to drive the §16.6 retry loop test.
	onFirstDelete map[string]func()
}

// NewStubCP returns a stub controlplane ready to serve.
func NewStubCP() *StubCP {
	s := &StubCP{
		blobs:             map[string]*StubBlob{},
		keys:              map[string]struct{}{},
		bundles:           map[string]map[string]controlplane.CurrentKeyBundle{},
		deletes:           map[string]time.Time{},
		buckets:           bucketstub.NewStore(BucketsStubAPIKey),
		legacyAttachments: map[string][]byte{},
		attachmentIndex:   map[string]string{},
		onFirstDelete:     map[string]func(){},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/sync/blob/chat/{id}", s.putBlob("chat"))
	mux.HandleFunc("PUT /api/sync/blob/profile", s.putBlob("profile"))
	mux.HandleFunc("PUT /api/sync/blob/project/{id}", s.putBlob("project"))
	mux.HandleFunc("PUT /api/sync/blob/project_document/{pid}/{did}", s.putBlob("project_document"))
	mux.HandleFunc("GET /api/sync/blob/chat/{id}", s.getBlob("chat"))
	mux.HandleFunc("GET /api/sync/blob/profile", s.getBlob("profile"))
	mux.HandleFunc("GET /api/sync/blob/project/{id}", s.getBlob("project"))
	mux.HandleFunc("GET /api/sync/blob/project_document/{pid}/{did}", s.getBlob("project_document"))
	mux.HandleFunc("DELETE /api/sync/blob/chat/{id}", s.delBlob("chat"))
	mux.HandleFunc("DELETE /api/sync/blob/profile", s.delBlob("profile"))
	mux.HandleFunc("DELETE /api/sync/blob/project/{id}", s.delBlob("project"))
	mux.HandleFunc("DELETE /api/sync/blob/project_document/{pid}/{did}", s.delBlob("project_document"))
	mux.HandleFunc("GET /api/sync/list-status", s.listStatus)
	mux.HandleFunc("GET /api/sync/needs-migration", s.needsMigration)
	mux.HandleFunc("POST /api/sync/migration-failure", s.migrationFailure)
	mux.HandleFunc("POST /api/sync/rewrap", s.rewrap)
	mux.HandleFunc("POST /api/sync/keys", s.registerKey)
	mux.HandleFunc("GET /api/sync/keys/current", s.currentKey)
	mux.HandleFunc("POST /api/sync/keys/{kid}/bundles", s.addBundle)
	mux.HandleFunc("DELETE /api/sync/keys/{kid}/bundles/{cid}", s.removeBundle)
	mux.HandleFunc("GET /api/storage/attachment/{aid}", s.getLegacyAttachment)
	mux.HandleFunc("POST /api/sync/attachment-index/{aid}", s.registerAttachmentIndex)
	mux.HandleFunc("DELETE /api/sync/attachment-index/{aid}", s.deleteAttachmentIndex)
	mux.HandleFunc("POST /put", s.buckets.Handle)
	mux.HandleFunc("POST /get", s.buckets.Handle)
	mux.HandleFunc("POST /delete", s.buckets.Handle)
	s.mux = mux
	return s
}

func (s *StubCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/sync/") && r.Header.Get(controlplane.HeaderServiceSecret) != LocalStackSyncEnclaveSecret {
		http.Error(w, "sync enclave credential is required", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// BucketsStubAPIKey is the static credential the buckets stub
// expects on every buckets call. Smoke tests configure the
// enclave's buckets.Client with this same value; tightening the
// check here catches missing-Authorization regressions that the
// real buckets backend would surface as 401. Exported so the
// stack wiring uses the same constant.
const BucketsStubAPIKey = "local-stack-buckets-key"

const LocalStackSyncEnclaveSecret = "local-stack-sync-enclave-secret"

// -----------------------------------------------------------------------------
// Test-facing poke API. Holding the stub's mutex while calling these is
// intentional so concurrent enclave requests see the same atomic state.
// -----------------------------------------------------------------------------

// PeekBlob returns a copy of the stored blob at (scope, id), or nil if
// the slot is empty. Useful for asserting that what was stored is NOT
// the plaintext.
func (s *StubCP) PeekBlob(scope, id string) *StubBlob {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.blobs[blobKey(scope, id)]
	if b == nil {
		return nil
	}
	cp := *b
	cp.Body = append([]byte(nil), b.Body...)
	return &cp
}

// SetBlob overwrites the stored blob at (scope, id) with raw bytes.
// Bumps etag. Used by T02 (tamper) to flip bytes in a stored
// ciphertext, and by T12 (legacy v0 read) to inject a legacy envelope.
func (s *StubCP) SetBlob(scope, id, keyID string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := blobKey(scope, id)
	var next int64 = 1
	if existing := s.blobs[key]; existing != nil {
		next = existing.ETag + 1
	}
	s.blobs[key] = &StubBlob{
		ETag:      next,
		KeyID:     keyID,
		Body:      append([]byte(nil), body...),
		UpdatedAt: time.Now().UTC(),
	}
	delete(s.deletes, key)
}

// CopyBlob copies the ciphertext at src into dst, preserving key_id.
// Used by T03 / T05 to attempt to read a chat envelope as a project
// envelope (or chat_Y as chat_X). The AAD binding makes the read fail.
func (s *StubCP) CopyBlob(srcScope, srcID, dstScope, dstID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.blobs[blobKey(srcScope, srcID)]
	if src == nil {
		return false
	}
	dstKey := blobKey(dstScope, dstID)
	var next int64 = 1
	if existing := s.blobs[dstKey]; existing != nil {
		next = existing.ETag + 1
	}
	s.blobs[dstKey] = &StubBlob{
		ETag:      next,
		KeyID:     src.KeyID,
		Body:      append([]byte(nil), src.Body...),
		UpdatedAt: time.Now().UTC(),
	}
	return true
}

func (s *StubCP) SetLegacyAttachment(id string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.legacyAttachments[id] = append([]byte(nil), body...)
}

// OnFirstDelete registers a callback to fire exactly once, at the
// start of the first DELETE that lands at (scope, id) AFTER this
// call. The callback runs with the stub's mutex RELEASED so it can
// make its own stub-mutating calls (e.g. a PUT that bumps the etag).
// After the callback returns, the DELETE proceeds against the
// (possibly mutated) state. This is precisely the race window
// §16.6's retry loop is designed to absorb.
func (s *StubCP) OnFirstDelete(scope, id string, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onFirstDelete[blobKey(scope, id)] = fn
}

// -----------------------------------------------------------------------------
// HTTP handlers.
// -----------------------------------------------------------------------------

func blobKey(scope, id string) string { return scope + "/" + id }

func (s *StubCP) extractID(scope string, r *http.Request) string {
	switch scope {
	case "chat", "project":
		return r.PathValue("id")
	case "profile":
		return "profile"
	case "project_document":
		return r.PathValue("pid") + "/" + r.PathValue("did")
	}
	return ""
}

func (s *StubCP) putBlob(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		id := s.extractID(scope, r)
		key := blobKey(scope, id)
		ifMatch := r.Header.Get("If-Match")
		blob := s.blobs[key]
		if blob != nil && ifMatch != "" && ifMatch != "*" {
			if ifMatch != formatETag(blob.ETag) {
				w.WriteHeader(http.StatusPreconditionFailed)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"code":         controlplane.StatusStaleBlob,
					"current_etag": formatETag(blob.ETag),
				})
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		var next int64 = 1
		if blob != nil {
			next = blob.ETag + 1
		}
		s.blobs[key] = &StubBlob{
			ETag:      next,
			KeyID:     r.Header.Get("X-Key-Id"),
			Body:      body,
			UpdatedAt: time.Now().UTC(),
		}
		delete(s.deletes, key)
		w.Header().Set("ETag", formatETag(next))
		w.Header().Set("X-Key-Id", r.Header.Get("X-Key-Id"))
		_ = json.NewEncoder(w).Encode(map[string]string{"etag": formatETag(next)})
	}
}

func (s *StubCP) getBlob(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		id := s.extractID(scope, r)
		blob, ok := s.blobs[blobKey(scope, id)]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", formatETag(blob.ETag))
		w.Header().Set("X-Key-Id", blob.KeyID)
		_, _ = w.Write(blob.Body)
	}
}

func (s *StubCP) delBlob(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		id := s.extractID(scope, r)
		key := blobKey(scope, id)
		// One-shot pre-delete hook (T08): release the mutex around
		// the callback so it can drive concurrent stub mutations
		// (e.g. a racing push that bumps the etag). After the hook
		// returns, the delete proceeds against the post-hook state
		// — which may now reject the caller's stale if_match.
		if fn, ok := s.onFirstDelete[key]; ok {
			delete(s.onFirstDelete, key)
			s.mu.Unlock()
			fn()
			s.mu.Lock()
		}
		defer s.mu.Unlock()
		ifMatch := r.Header.Get("If-Match")
		blob := s.blobs[key]
		if blob != nil && ifMatch != "" && ifMatch != "*" && ifMatch != formatETag(blob.ETag) {
			w.WriteHeader(http.StatusPreconditionFailed)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"code":         controlplane.StatusStaleBlob,
				"current_etag": formatETag(blob.ETag),
			})
			return
		}
		delete(s.blobs, key)
		s.deletes[key] = time.Now().UTC()
		wipedV2 := []string{}
		if scope == "chat" {
			for aid, cid := range s.attachmentIndex {
				if cid == id {
					wipedV2 = append(wipedV2, aid)
					delete(s.attachmentIndex, aid)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                   true,
			"wiped_v2_attachments": wipedV2,
		})
	}
}

func (s *StubCP) listStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := r.URL.Query().Get("scope")
	updates := []controlplane.BlobMeta{}
	deletes := []controlplane.BlobDelete{}
	for k, blob := range s.blobs {
		parts := strings.SplitN(k, "/", 2)
		if parts[0] != scope {
			continue
		}
		updates = append(updates, controlplane.BlobMeta{
			ID:        parts[1],
			ETag:      formatETag(blob.ETag),
			KeyID:     blob.KeyID,
			UpdatedAt: blob.UpdatedAt,
		})
	}
	for k, ts := range s.deletes {
		parts := strings.SplitN(k, "/", 2)
		if parts[0] != scope {
			continue
		}
		deletes = append(deletes, controlplane.BlobDelete{
			ID:        parts[1],
			Scope:     scope,
			DeletedAt: ts,
		})
	}
	_ = json.NewEncoder(w).Encode(controlplane.ListStatusResponse{Updates: updates, Deletes: deletes})
}

func (s *StubCP) needsMigration(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scope := r.URL.Query().Get("scope")
	ids := []string{}
	for k, b := range s.blobs {
		parts := strings.SplitN(k, "/", 2)
		if parts[0] != scope {
			continue
		}
		// Legacy blobs are identified by an absent or non-v2 envelope
		// shape. The stub trusts test code to set them up via
		// SetBlob with a v0/v1 body; here we just surface anything
		// in this scope whose body does not start with `{"v":2`.
		if !strings.HasPrefix(string(b.Body), `{"v":2`) && !strings.HasPrefix(string(b.Body), `{"v": 2`) {
			ids = append(ids, parts[1])
		}
	}
	_ = json.NewEncoder(w).Encode(controlplane.ListNeedsMigrationResponse{
		IDs:                ids,
		RetryableRemaining: len(ids),
	})
}

func (s *StubCP) migrationFailure(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *StubCP) rewrap(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var req struct {
		Scope         string `json:"scope"`
		ID            string `json:"id"`
		KeyID         string `json:"key_id"`
		IfMatch       string `json:"if_match"`
		CiphertextB64 string `json:"ciphertext_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.CiphertextB64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id := req.ID
	if req.Scope == "profile" {
		id = "profile"
	}
	key := blobKey(req.Scope, id)
	blob, ok := s.blobs[key]
	if !ok {
		w.WriteHeader(http.StatusPreconditionFailed)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": controlplane.StatusStaleBlob, "current_etag": "0"})
		return
	}
	if req.IfMatch != formatETag(blob.ETag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": controlplane.StatusStaleBlob, "current_etag": formatETag(blob.ETag)})
		return
	}
	next := blob.ETag + 1
	s.blobs[key] = &StubBlob{ETag: next, KeyID: req.KeyID, Body: ct, UpdatedAt: time.Now().UTC()}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "etag": formatETag(next), "key_id": req.KeyID})
}

func (s *StubCP) getLegacyAttachment(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, ok := s.legacyAttachments[r.PathValue("aid")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

func (s *StubCP) registerAttachmentIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aid := r.PathValue("aid")
	var body struct {
		ChatID string `json:"chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if body.ChatID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.attachmentIndex[aid] = body.ChatID
	delete(s.legacyAttachments, aid)
	w.WriteHeader(http.StatusNoContent)
}

func (s *StubCP) deleteAttachmentIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aid := r.PathValue("aid")
	if _, ok := s.attachmentIndex[aid]; !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	delete(s.attachmentIndex, aid)
	w.WriteHeader(http.StatusNoContent)
}

func (s *StubCP) registerKey(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var body struct {
		KeyID         string                         `json:"key_id"`
		CreatedVia    string                         `json:"created_via"`
		InitialBundle *controlplane.CurrentKeyBundle `json:"initial_bundle,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if ifMatch != "*" && ifMatch != s.currentKID {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": controlplane.StatusStaleKey, "current_key_id": s.currentKID})
		return
	}
	wipedAttachments := []string{}
	if body.CreatedVia == "start_fresh" {
		// Mirror the controlplane's atomic wipe: drop every blob
		// for the user before swapping the primary key, and
		// report every bucket-backed attachment id back to the
		// enclave so its cleanup cascade can drop them too.
		for k, b := range s.blobs {
			if b.KeyID != body.KeyID {
				delete(s.blobs, k)
			}
		}
		for aid := range s.attachmentIndex {
			wipedAttachments = append(wipedAttachments, aid)
			delete(s.attachmentIndex, aid)
		}
		for aid := range s.legacyAttachments {
			delete(s.legacyAttachments, aid)
		}
	} else {
		for _, b := range s.blobs {
			if b.KeyID != "" && b.KeyID != body.KeyID {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": controlplane.StatusExistingDataUnderOtherKey, "current_key_id": s.currentKID})
				return
			}
		}
	}
	s.keys[body.KeyID] = struct{}{}
	s.currentKID = body.KeyID
	if body.InitialBundle != nil {
		if _, ok := s.bundles[body.KeyID]; !ok {
			s.bundles[body.KeyID] = map[string]controlplane.CurrentKeyBundle{}
		}
		s.bundles[body.KeyID][body.InitialBundle.CredentialID] = *body.InitialBundle
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                   true,
		"key_id":               body.KeyID,
		"etag":                 "1",
		"wiped_v2_attachments": wipedAttachments,
	})
}

func (s *StubCP) currentKey(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentKID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(controlplane.CurrentKeyResponse{
		KeyID:   s.currentKID,
		Bundles: s.bundles[s.currentKID],
	})
}

func (s *StubCP) addBundle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kid := r.PathValue("kid")
	var body controlplane.CurrentKeyBundle
	_ = json.NewDecoder(r.Body).Decode(&body)
	if _, ok := s.bundles[kid]; !ok {
		s.bundles[kid] = map[string]controlplane.CurrentKeyBundle{}
	}
	s.bundles[kid][body.CredentialID] = body
	w.WriteHeader(http.StatusNoContent)
}

func (s *StubCP) removeBundle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kid := r.PathValue("kid")
	cid := r.PathValue("cid")
	if m, ok := s.bundles[kid]; ok {
		delete(m, cid)
	}
	w.WriteHeader(http.StatusNoContent)
}

func formatETag(n int64) string { return strconv.FormatInt(n, 10) }
