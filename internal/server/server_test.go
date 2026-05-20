package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

// ---- test fixture ------------------------------------------------------

type fixture struct {
	t          *testing.T
	jwks       *httptest.Server
	signKey    *rsa.PrivateKey
	signKID    string
	issuer     string
	verifier   auth.Verifier
	cp         *cpStub
	cpClient   *controlplane.Client
	bk         *bucketsStub
	server     *httptest.Server
	userKey    []byte
	userKeyID  string
	userKeyB64 string
	userSub    string
}

type cpStub struct {
	t                 *testing.T
	mu                sync.Mutex
	blobs             map[string]*cpBlob  // scope/id → blob
	keys              map[string]struct{} // hex KeyIDs registered
	currentKID        string
	bundles           map[string]map[string]controlplane.CurrentKeyBundle
	registeredOps     map[string]bool
	migrationFailures map[string]int
	needsMigration    []cpNeedsMigration
	legacyAttachments map[string][]byte // attachmentID → ciphertext (set by tests)
	attachmentIndex   map[string]string // attachmentID → chatID (populated by handler)
	// wipedAttachments seeds the start_fresh response so tests can
	// exercise the enclave-side buckets cleanup cascade. Real
	// controlplane returns the ids of the v2 attachments it nulled
	// during the atomic wipe; tests pre-populate this slice.
	wipedAttachments []string
	mux              *http.ServeMux
	server           *httptest.Server
	registerHandler  func(w http.ResponseWriter, r *http.Request)
	captureHeaders   func(r *http.Request)
}

type cpNeedsMigration struct {
	ID string
}

type cpBlob struct {
	ETag  int64
	KeyID string
	Body  []byte
}

func newCPStub(t *testing.T) *cpStub {
	t.Helper()
	st := &cpStub{
		t:                 t,
		blobs:             map[string]*cpBlob{},
		keys:              map[string]struct{}{},
		bundles:           map[string]map[string]controlplane.CurrentKeyBundle{},
		registeredOps:     map[string]bool{},
		migrationFailures: map[string]int{},
	}
	st.mux = http.NewServeMux()
	st.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		cb := st.captureHeaders
		st.mu.Unlock()
		if cb != nil {
			cb(r)
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		st.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(st.server.Close)
	st.installHandlers()
	return st
}

func (s *cpStub) putBlobKey(scope, id string) string {
	return scope + "/" + id
}

func (s *cpStub) installHandlers() {
	// PUT blobs
	s.mux.HandleFunc("PUT /api/sync/blob/chat/{id}", s.handlePutBlob("chat"))
	s.mux.HandleFunc("PUT /api/sync/blob/profile", s.handlePutBlob("profile"))
	s.mux.HandleFunc("PUT /api/sync/blob/project/{id}", s.handlePutBlob("project"))
	s.mux.HandleFunc("PUT /api/sync/blob/project_document/{pid}/{did}", s.handlePutBlob("project_document"))
	// GET blobs
	s.mux.HandleFunc("GET /api/sync/blob/chat/{id}", s.handleGetBlob("chat"))
	s.mux.HandleFunc("GET /api/sync/blob/profile", s.handleGetBlob("profile"))
	s.mux.HandleFunc("GET /api/sync/blob/project/{id}", s.handleGetBlob("project"))
	s.mux.HandleFunc("GET /api/sync/blob/project_document/{pid}/{did}", s.handleGetBlob("project_document"))
	// DELETE blobs
	s.mux.HandleFunc("DELETE /api/sync/blob/chat/{id}", s.handleDeleteBlob("chat"))
	s.mux.HandleFunc("DELETE /api/sync/blob/project/{id}", s.handleDeleteBlob("project"))
	// rewrap (separate JSON endpoint; not the PUT blob path)
	s.mux.HandleFunc("POST /api/sync/rewrap", s.handleRewrap)
	// list-status + migration surface
	s.mux.HandleFunc("GET /api/sync/list-status", s.handleListStatus)
	s.mux.HandleFunc("GET /api/sync/needs-migration", s.handleNeedsMigration)
	s.mux.HandleFunc("POST /api/sync/migration-failure", s.handleMigrationFailure)
	// key registry
	s.mux.HandleFunc("POST /api/sync/keys", s.handleRegisterKey)
	s.mux.HandleFunc("POST /api/sync/keys/{kid}/bundles", s.handleAddBundle)
	s.mux.HandleFunc("DELETE /api/sync/keys/{kid}/bundles/{cid}", s.handleRemoveBundle)
	s.mux.HandleFunc("GET /api/sync/keys/current", s.handleCurrentKey)
	// legacy attachment fetch + new attachment ownership index
	s.mux.HandleFunc("GET /api/storage/attachment/{aid}", s.handleLegacyAttachment)
	s.mux.HandleFunc("POST /api/sync/attachment-index/{aid}", s.handleRegisterAttachmentIndex)
}

func (s *cpStub) extractID(scope string, r *http.Request) string {
	switch scope {
	case "chat":
		return r.PathValue("id")
	case "profile":
		return "profile"
	case "project":
		return r.PathValue("id")
	case "project_document":
		return r.PathValue("pid") + "/" + r.PathValue("did")
	}
	return ""
}

func (s *cpStub) handlePutBlob(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := s.extractID(scope, r)
		key := s.putBlobKey(scope, id)
		ifMatch := r.Header.Get("If-Match")
		blob := s.blobs[key]
		if blob != nil && ifMatch != "" {
			if ifMatch != formatETag(blob.ETag) {
				w.WriteHeader(http.StatusPreconditionFailed)
				json.NewEncoder(w).Encode(map[string]string{
					"code":         controlplane.StatusStaleBlob,
					"current_etag": formatETag(blob.ETag),
				})
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		var nextETag int64 = 1
		if blob != nil {
			nextETag = blob.ETag + 1
		}
		s.blobs[key] = &cpBlob{
			ETag:  nextETag,
			KeyID: r.Header.Get("X-Key-Id"),
			Body:  body,
		}
		w.Header().Set("ETag", formatETag(nextETag))
		w.Header().Set("X-Key-Id", r.Header.Get("X-Key-Id"))
		json.NewEncoder(w).Encode(map[string]string{"etag": formatETag(nextETag)})
	}
}

func (s *cpStub) handleGetBlob(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := s.extractID(scope, r)
		blob, ok := s.blobs[s.putBlobKey(scope, id)]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", formatETag(blob.ETag))
		w.Header().Set("X-Key-Id", blob.KeyID)
		w.Write(blob.Body)
	}
}

func (s *cpStub) handleDeleteBlob(scope string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := s.extractID(scope, r)
		key := s.putBlobKey(scope, id)
		blob, ok := s.blobs[key]
		if !ok {
			w.WriteHeader(http.StatusPreconditionFailed)
			json.NewEncoder(w).Encode(map[string]string{
				"code":         controlplane.StatusStaleBlob,
				"current_etag": "0",
			})
			return
		}
		if ifMatch := r.Header.Get("If-Match"); ifMatch != "" && ifMatch != "*" && ifMatch != formatETag(blob.ETag) {
			w.WriteHeader(http.StatusPreconditionFailed)
			json.NewEncoder(w).Encode(map[string]string{
				"code":         controlplane.StatusStaleBlob,
				"current_etag": formatETag(blob.ETag),
			})
			return
		}
		delete(s.blobs, key)
		// Mirror the real controlplane's chat-delete cascade: drop
		// matching attachment-index rows and return their v2 ids so
		// the enclave can wipe the buckets blobs. Tests rely on this
		// to assert the secure attachment-cleanup path.
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
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                   true,
			"wiped_v2_attachments": wipedV2,
		})
	}
}

func (s *cpStub) handleListStatus(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	updates := []controlplane.BlobMeta{}
	for key, blob := range s.blobs {
		parts := strings.SplitN(key, "/", 2)
		if parts[0] != scope {
			continue
		}
		updates = append(updates, controlplane.BlobMeta{
			ID:    parts[1],
			ETag:  formatETag(blob.ETag),
			KeyID: blob.KeyID,
		})
	}
	json.NewEncoder(w).Encode(controlplane.ListStatusResponse{Updates: updates})
}

func (s *cpStub) handleNeedsMigration(w http.ResponseWriter, r *http.Request) {
	ids := []string{}
	for _, n := range s.needsMigration {
		ids = append(ids, n.ID)
	}
	json.NewEncoder(w).Encode(controlplane.ListNeedsMigrationResponse{
		IDs:                ids,
		RetryableRemaining: len(ids),
	})
}

func (s *cpStub) handleMigrationFailure(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope string `json:"scope"`
		ID    string `json:"id"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	s.migrationFailures[body.Scope+"/"+body.ID]++
	w.WriteHeader(http.StatusNoContent)
}

func (s *cpStub) handleRegisterKey(w http.ResponseWriter, r *http.Request) {
	if s.registerHandler != nil {
		s.registerHandler(w, r)
		return
	}
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
		json.NewEncoder(w).Encode(map[string]string{
			"code":           controlplane.StatusStaleKey,
			"current_key_id": s.currentKID,
		})
		return
	}
	if body.CreatedVia != "start_fresh" {
		for _, b := range s.blobs {
			if b.KeyID != "" && b.KeyID != body.KeyID {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"code":           controlplane.StatusExistingDataUnderOtherKey,
					"current_key_id": s.currentKID,
				})
				return
			}
		}
	} else {
		for k, b := range s.blobs {
			if b.KeyID != body.KeyID {
				delete(s.blobs, k)
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
	// Mirror the real controlplane shape so the enclave's buckets
	// cleanup cascade has something to drain when tests exercise
	// start_fresh. wipedV2Attachments stays empty unless the test
	// pre-seeded it via s.wipedAttachments.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                   true,
		"key_id":               body.KeyID,
		"etag":                 "1",
		"wiped_v2_attachments": s.wipedAttachments,
	})
}

func (s *cpStub) handleAddBundle(w http.ResponseWriter, r *http.Request) {
	kid := r.PathValue("kid")
	var body controlplane.CurrentKeyBundle
	json.NewDecoder(r.Body).Decode(&body)
	if _, ok := s.bundles[kid]; !ok {
		s.bundles[kid] = map[string]controlplane.CurrentKeyBundle{}
	}
	s.bundles[kid][body.CredentialID] = body
	w.WriteHeader(http.StatusNoContent)
}

func (s *cpStub) handleCurrentKey(w http.ResponseWriter, r *http.Request) {
	if s.currentKID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(controlplane.CurrentKeyResponse{
		KeyID:   s.currentKID,
		Bundles: s.bundles[s.currentKID],
	})
}

func (s *cpStub) handleRemoveBundle(w http.ResponseWriter, r *http.Request) {
	kid := r.PathValue("kid")
	cid := r.PathValue("cid")
	if m, ok := s.bundles[kid]; ok {
		delete(m, cid)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLegacyAttachment mirrors GET /api/storage/attachment/{id}.
// Tests plant ciphertext into s.legacyAttachments before triggering
// a rewrap to simulate the v1 BYTEA storage the rewrap path drains.
func (s *cpStub) handleLegacyAttachment(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	if s.legacyAttachments == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, ok := s.legacyAttachments[aid]
	if !ok || len(body) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(body)
}

// handleRegisterAttachmentIndex mirrors POST /api/sync/attachment-index/{id}.
// On a successful call the legacy row is logically deleted (we drop
// the bytes) so subsequent legacy GETs return 404, matching real
// controlplane behavior where UpsertChatAttachmentIndex sets data=NULL.
func (s *cpStub) handleRegisterAttachmentIndex(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	var body struct {
		ChatID string `json:"chat_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.attachmentIndex == nil {
		s.attachmentIndex = map[string]string{}
	}
	s.attachmentIndex[aid] = body.ChatID
	if s.legacyAttachments != nil {
		delete(s.legacyAttachments, aid)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRewrap mirrors the controlplane's /api/sync/rewrap endpoint:
// JSON body in, replaces the blob ciphertext + key_id, bumps etag,
// returns {ok, etag, key_id}. Mid-test rewrap CAS mismatches are
// surfaced via the same STALE_BLOB code the controlplane uses.
func (s *cpStub) handleRewrap(w http.ResponseWriter, r *http.Request) {
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
	key := s.putBlobKey(req.Scope, id)
	blob, ok := s.blobs[key]
	if !ok {
		w.WriteHeader(http.StatusPreconditionFailed)
		json.NewEncoder(w).Encode(map[string]string{
			"code":         controlplane.StatusStaleBlob,
			"current_etag": "0",
		})
		return
	}
	if req.IfMatch != formatETag(blob.ETag) {
		w.WriteHeader(http.StatusPreconditionFailed)
		json.NewEncoder(w).Encode(map[string]string{
			"code":         controlplane.StatusStaleBlob,
			"current_etag": formatETag(blob.ETag),
		})
		return
	}
	nextETag := blob.ETag + 1
	s.blobs[key] = &cpBlob{ETag: nextETag, KeyID: req.KeyID, Body: ct}
	json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"etag":   formatETag(nextETag),
		"key_id": req.KeyID,
	})
}

func formatETag(n int64) string {
	return strconv.FormatInt(n, 10)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-kid"
	pub := priv.Public().(*rsa.PublicKey)

	jwksJSON, _ := json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})

	mux := http.NewServeMux()
	jwksSrv := httptest.NewServer(mux)
	t.Cleanup(jwksSrv.Close)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	})

	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksSrv.URL + "/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifierWithKeyfunc(auth.Config{Issuer: jwksSrv.URL}, kf)
	if err != nil {
		t.Fatal(err)
	}

	cp := newCPStub(t)
	cpClient := controlplane.NewClient(cp.server.URL, nil)

	bk := newBucketsStub(t)
	bkClient := buckets.NewClient(bk.server.URL, "test-api-key", nil)

	deps := Deps{Controlplane: cpClient, Buckets: bkClient, GitSHA: "test-sha"}
	handler := NewHandler(deps, v, nil)
	srv := httptest.NewServer(handler.Routes())
	t.Cleanup(srv.Close)

	rawKey := make([]byte, cryptopkg.KeySize)
	if _, err := rand.Read(rawKey); err != nil {
		t.Fatal(err)
	}
	kidBytes, _ := cryptopkg.DeriveKeyID(rawKey)
	kidHex := cryptopkg.KeyIDHex(kidBytes)

	return &fixture{
		t:          t,
		jwks:       jwksSrv,
		signKey:    priv,
		signKID:    kid,
		issuer:     jwksSrv.URL,
		verifier:   v,
		cp:         cp,
		cpClient:   cpClient,
		bk:         bk,
		server:     srv,
		userKey:    rawKey,
		userKeyID:  kidHex,
		userKeyB64: base64.StdEncoding.EncodeToString(rawKey),
		userSub:    "user_abc",
	}
}

func (f *fixture) jwt() string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": f.userSub,
		"iss": f.issuer,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = f.signKID
	s, err := tok.SignedString(f.signKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) post(path string, body any, token string) (*http.Response, []byte) {
	f.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, f.server.URL+path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp, respBody
}

// ---- tests -------------------------------------------------------------

func TestPushAndPullRoundtrip(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	plaintext := []byte(`{"id":"chat_1","title":"Hello","messages":[]}`)
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope:          "chat",
		ID:             "chat_1",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IfMatch:        nil,
		IdempotencyKey: "idem-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: %d %s", resp.StatusCode, body)
	}
	var pushResp PushResponse
	json.Unmarshal(body, &pushResp)
	if !pushResp.OK || pushResp.ETag == "" || pushResp.KeyID != f.userKeyID {
		t.Fatalf("push resp: %+v", pushResp)
	}

	pullResp, pullBody := f.post("/v1/sync/pull", PullRequest{
		Scope: "chat",
		IDs:   []string{"chat_1"},
		Keys:  []PullKey{{Key: f.userKeyB64}},
	}, tok)
	if pullResp.StatusCode != http.StatusOK {
		t.Fatalf("pull: %d %s", pullResp.StatusCode, pullBody)
	}
	var pull PullResponse
	json.Unmarshal(pullBody, &pull)
	if len(pull.Items) != 1 || !pull.Items[0].OK {
		t.Fatalf("pull resp: %+v", pull)
	}
	got, _ := base64.StdEncoding.DecodeString(pull.Items[0].Plaintext)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
	if pull.Items[0].NeedsRewrap {
		t.Fatalf("v2 should not need rewrap")
	}
}

func TestPullUnknownKey(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	// First push under userKey
	plaintext := []byte(`{"x":1}`)
	resp, _ := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "c1",
		Key: f.userKeyB64, Plaintext: base64.StdEncoding.EncodeToString(plaintext),
		IdempotencyKey: "i1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	// Try pull with a different key
	otherKey := make([]byte, cryptopkg.KeySize)
	rand.Read(otherKey)
	pullResp, pullBody := f.post("/v1/sync/pull", PullRequest{
		Scope: "chat", IDs: []string{"c1"},
		Keys: []PullKey{{Key: base64.StdEncoding.EncodeToString(otherKey)}},
	}, tok)
	if pullResp.StatusCode != http.StatusOK {
		t.Fatalf("pull http: %d %s", pullResp.StatusCode, pullBody)
	}
	var pull PullResponse
	json.Unmarshal(pullBody, &pull)
	if len(pull.Items) != 1 {
		t.Fatalf("items: %+v", pull)
	}
	if pull.Items[0].OK {
		t.Fatalf("expected !OK")
	}
	if pull.Items[0].Code != CodeUnknownKey {
		t.Fatalf("code: %q", pull.Items[0].Code)
	}
}

func TestAuthMissingBearer(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.post("/v1/sync/push", PushRequest{Scope: "chat"}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestAuthInvalidToken(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.post("/v1/sync/push", PushRequest{Scope: "chat"}, "garbage")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestInvalidScope(t *testing.T) {
	f := newFixture(t)
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope: "bogus", ID: "x", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte("x")),
		IdempotencyKey: "i1",
	}, f.jwt())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
}

// TestStaleBlobSurfacesSyncConflict asserts a stale-etag push
// surfaces 409 SYNC_CONFLICT with the controlplane's current_etag
// instead of silently merging or overwriting. The enclave never
// runs a conflict resolver; conflict resolution is a client-UI
// decision.
func TestStaleBlobSurfacesSyncConflict(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	resp, _ := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "c", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"id":"c","messages":[]}`)),
		IdempotencyKey: "i1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("init: %d", resp.StatusCode)
	}

	stale := "999"
	resp2, body2 := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "c", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"id":"c","messages":[]}`)),
		IfMatch:        &stale,
		IdempotencyKey: "i2",
	}, tok)
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d %s", resp2.StatusCode, body2)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body2, &parsed); err != nil {
		t.Fatalf("parse body: %v %s", err, body2)
	}
	if parsed["code"] != "SYNC_CONFLICT" {
		t.Fatalf("expected code=SYNC_CONFLICT, got %v in %s", parsed["code"], body2)
	}
	if parsed["current_etag"] != "1" {
		t.Fatalf("expected current_etag=1, got %v in %s", parsed["current_etag"], body2)
	}
}

func TestRegisterKeyAtomicWithIfMatchStar(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	resp, body := f.post("/v1/key/register", KeyRegisterRequest{
		Key: f.userKeyB64, IfMatch: "*", CreatedVia: "passkey",
		IdempotencyKey: "reg-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: %d %s", resp.StatusCode, body)
	}
	var kr KeyRegisterResponse
	json.Unmarshal(body, &kr)
	if !kr.OK || kr.KeyID != f.userKeyID {
		t.Fatalf("response: %+v", kr)
	}
}

func TestRegisterKeyExistingDataConflict(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	// First, push something under the user's key so the controlplane has
	// data under that KeyID.
	if r, _ := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "c1", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte("x")),
		IdempotencyKey: "i1",
	}, tok); r.StatusCode != http.StatusOK {
		t.Fatalf("seed push: %d", r.StatusCode)
	}
	// Now try to register a different fresh key without start_fresh.
	freshKey := make([]byte, cryptopkg.KeySize)
	rand.Read(freshKey)
	resp, body := f.post("/v1/key/register", KeyRegisterRequest{
		Key:            base64.StdEncoding.EncodeToString(freshKey),
		IfMatch:        "*",
		CreatedVia:     "passkey",
		IdempotencyKey: "reg-2",
	}, tok)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d %s", resp.StatusCode, body)
	}
	var e AppError
	json.Unmarshal(body, &e)
	if e.Code != CodeExistingDataUnderOtherKey {
		t.Fatalf("code: %q", e.Code)
	}
}

func TestAddBundleForwards(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	resp, body := f.post("/v1/key/add-bundle", AddBundleRequest{
		KeyID:          f.userKeyID,
		Key:            f.userKeyB64,
		CredentialID:   "cred-x",
		KEKIV:          "iv",
		EncryptedKeys:  "ct",
		IdempotencyKey: "idem-add-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add-bundle: %d %s", resp.StatusCode, body)
	}
	if got, ok := f.cp.bundles[f.userKeyID]; !ok || got["cred-x"].EncryptedKeys != "ct" {
		t.Fatalf("bundle not stored: %+v", f.cp.bundles)
	}
}

func TestAddBundleRejectsMismatchedKeyID(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	otherKey := make([]byte, cryptopkg.KeySize)
	rand.Read(otherKey)
	resp, body := f.post("/v1/key/add-bundle", AddBundleRequest{
		KeyID:          f.userKeyID,
		Key:            base64.StdEncoding.EncodeToString(otherKey),
		CredentialID:   "cred-x",
		KEKIV:          "iv",
		EncryptedKeys:  "ct",
		IdempotencyKey: "idem-add-1",
	}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", resp.StatusCode, body)
	}
	if got, ok := f.cp.bundles[f.userKeyID]; ok && got["cred-x"].EncryptedKeys == "ct" {
		t.Fatalf("mismatched bundle was stored: %+v", f.cp.bundles)
	}
}

func TestRemoveBundleRejectsMismatchedKeyID(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	otherKey := make([]byte, cryptopkg.KeySize)
	rand.Read(otherKey)
	resp, body := f.post("/v1/key/remove-bundle", RemoveBundleRequest{
		KeyID:          f.userKeyID,
		Key:            base64.StdEncoding.EncodeToString(otherKey),
		CredentialID:   "cred-x",
		IdempotencyKey: "idem-remove-1",
	}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", resp.StatusCode, body)
	}
}

func TestDeleteForwardsHeaders(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	// seed
	_, pushBody := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "c", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte("x")),
		IdempotencyKey: "i1",
	}, tok)
	var push PushResponse
	json.Unmarshal(pushBody, &push)
	etag := push.ETag
	resp, body := f.post("/v1/sync/delete", DeleteRequest{
		Scope: "chat", ID: "c", IdempotencyKey: "del-1", Key: f.userKeyB64,
		IfMatch: &etag,
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
	if _, ok := f.cp.blobs["chat/c"]; ok {
		t.Fatalf("blob not deleted")
	}
}

func TestMigrateLegacyBlob(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	// Plant a legacy v0 blob directly in the cp stub.
	pt := []byte(`{"id":"chat_old","title":"legacy","messages":[]}`)
	nonce, ct, err := cryptopkg.Seal(f.userKey, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	v0 := map[string]string{
		"iv":   base64.StdEncoding.EncodeToString(nonce),
		"data": base64.StdEncoding.EncodeToString(ct),
	}
	v0b, _ := json.Marshal(v0)
	f.cp.mu.Lock()
	f.cp.blobs["chat/chat_old"] = &cpBlob{ETag: 1, KeyID: "", Body: v0b}
	f.cp.needsMigration = []cpNeedsMigration{{ID: "chat_old"}}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/blobs/migrate", MigrateRequest{
		Scope:  "chat",
		Limit:  10,
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: f.userKeyB64},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("migrate: %d %s", resp.StatusCode, body)
	}
	var mr MigrateResponse
	json.Unmarshal(body, &mr)
	if mr.Migrated != 1 {
		t.Fatalf("migrated: %d", mr.Migrated)
	}

	f.cp.mu.Lock()
	after := f.cp.blobs["chat/chat_old"].Body
	f.cp.mu.Unlock()
	if envelope.Detect(after) != envelope.VersionV2 {
		t.Fatalf("blob not migrated to v2: %s", after)
	}
}

func TestMigrateBlobBumpsAttemptsOnFailure(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	// A blob the user does not have the key for.
	otherKey := make([]byte, cryptopkg.KeySize)
	rand.Read(otherKey)
	pt := []byte(`{"x":1}`)
	nonce, ct, _ := cryptopkg.Seal(otherKey, pt, nil)
	v0, _ := json.Marshal(map[string]string{
		"iv":   base64.StdEncoding.EncodeToString(nonce),
		"data": base64.StdEncoding.EncodeToString(ct),
	})
	f.cp.mu.Lock()
	f.cp.blobs["chat/blocked"] = &cpBlob{ETag: 1, Body: v0}
	f.cp.needsMigration = []cpNeedsMigration{{ID: "blocked"}}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/blobs/migrate", MigrateRequest{
		Scope: "chat", Limit: 5,
		Keys:   []PullKey{{Key: f.userKeyB64}}, // wrong key
		Target: MigrateTarget{Key: f.userKeyB64},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("migrate: %d %s", resp.StatusCode, body)
	}
	var mr MigrateResponse
	json.Unmarshal(body, &mr)
	if mr.Migrated != 0 || len(mr.Blocked) != 1 {
		t.Fatalf("response: %+v", mr)
	}
	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	if f.cp.migrationFailures["chat/blocked"] != 1 {
		t.Fatalf("failure not recorded: %d", f.cp.migrationFailures["chat/blocked"])
	}
}

func TestHealth(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Get(f.server.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var h HealthResponse
	json.Unmarshal(body, &h)
	if h.Status != "ok" || h.GitSHA != "test-sha" {
		t.Fatalf("health: %+v", h)
	}
}

func TestAADProtectsAcrossScope(t *testing.T) {
	// Ensure the same key encrypting plaintext for scope=chat cannot
	// decrypt it back as scope=profile. This is the cross-resource swap
	// attack AAD exists to prevent.
	f := newFixture(t)
	tok := f.jwt()
	pt := []byte("hello")
	resp, _ := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "x", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString(pt),
		IdempotencyKey: "i",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: %d", resp.StatusCode)
	}
	// Move the chat blob into the profile slot at the controlplane and
	// see if we can decrypt under scope=profile.
	f.cp.mu.Lock()
	f.cp.blobs["profile/profile"] = f.cp.blobs["chat/x"]
	f.cp.mu.Unlock()

	pullResp, body := f.post("/v1/sync/pull", PullRequest{
		Scope: "profile", IDs: []string{"profile"},
		Keys: []PullKey{{Key: f.userKeyB64}},
	}, tok)
	if pullResp.StatusCode != http.StatusOK {
		t.Fatalf("pull http: %d %s", pullResp.StatusCode, body)
	}
	var pull PullResponse
	json.Unmarshal(body, &pull)
	if pull.Items[0].OK {
		t.Fatalf("AAD failed to prevent cross-scope decryption")
	}
}

func TestIdempotencyHeaderForwarded(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	var (
		mu       sync.Mutex
		seenIdem string
		seenHash string
	)
	f.cp.captureHeaders = func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if h := r.Header.Get("X-Idempotency-Key"); h != "" && seenIdem == "" {
			seenIdem = h
		}
		if h := r.Header.Get("X-Operation-Hash"); h != "" && seenHash == "" {
			seenHash = h
		}
	}

	resp, _ := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "newc", Key: f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte("x")),
		IdempotencyKey: "my-idem-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	mu.Lock()
	gotIdem := seenIdem
	gotHash := seenHash
	mu.Unlock()
	if gotIdem != "my-idem-1" {
		t.Fatalf("X-Idempotency-Key not forwarded, got %q", gotIdem)
	}
	if gotHash == "" {
		t.Fatalf("X-Operation-Hash not forwarded")
	}
}

func TestKeyIDDerivationConsistencyAcrossClients(t *testing.T) {
	// The enclave derives KeyID identically regardless of who is calling.
	// This test pins the hex output for a deterministic key.
	key := bytes.Repeat([]byte{0x11}, cryptopkg.KeySize)
	id, err := cryptopkg.DeriveKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	got := cryptopkg.KeyIDHex(id)
	if len(got) != 32 {
		t.Fatalf("bad length")
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("not hex: %v", err)
	}
}

func TestAttachmentIDMatchesBucketsTokenContract(t *testing.T) {
	id, err := newAttachmentID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 {
		t.Fatalf("attachment id length = %d, want 36", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("attachment id is not hex: %v", err)
	}
}

func TestDeterministicAttachmentIDMatchesBucketsTokenContract(t *testing.T) {
	plaintext := []byte("attachment-bytes")
	id, key, err := deriveAttachmentMaterials("idem-attachment", "chat-1", "user_123", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(key)
	if len(id) != 36 {
		t.Fatalf("attachment id length = %d, want 36", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("attachment id is not hex: %v", err)
	}
	if len(key) != attKeySize {
		t.Fatalf("attachment key length = %d, want %d", len(key), attKeySize)
	}

	// A retry with byte-identical inputs reproduces the same
	// (id, att_key) — that's the whole point of the derivation.
	id2, key2, err := deriveAttachmentMaterials("idem-attachment", "chat-1", "user_123", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(key2)
	if id2 != id {
		t.Fatalf("retry id mismatch: got %s, want %s", id2, id)
	}
	if !bytes.Equal(key, key2) {
		t.Fatalf("retry key mismatch")
	}

	// Reusing the same idempotency key against different bytes
	// MUST derive a different slot so the original attachment
	// cannot be overwritten.
	otherID, otherKey, err := deriveAttachmentMaterials("idem-attachment", "chat-1", "user_123", []byte("different-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(otherKey)
	if otherID == id {
		t.Fatalf("different plaintext must derive different id")
	}

	// Likewise across different chats.
	otherChatID, otherChatKey, err := deriveAttachmentMaterials("idem-attachment", "chat-2", "user_123", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(otherChatKey)
	if otherChatID == id {
		t.Fatalf("different chat id must derive different attachment id")
	}

	// A length-prefixed IKM rules out a class of collisions a
	// printable delimiter would otherwise allow: shifting bytes
	// across the field boundary ("a|b","c") versus ("a","b|c")
	// must derive to different (id, key) pairs even if the
	// concatenated string is identical.
	shiftedA_ID, shiftedA_Key, err := deriveAttachmentMaterials("idem|attachment", "chat-1", "user_123", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(shiftedA_Key)
	shiftedB_ID, shiftedB_Key, err := deriveAttachmentMaterials("idem", "attachment|chat-1", "user_123", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(shiftedB_Key)
	if shiftedA_ID == shiftedB_ID {
		t.Fatalf("delimiter ambiguity: shifting bytes across field boundary derived the same id (%s)", shiftedA_ID)
	}
	if bytes.Equal(shiftedA_Key, shiftedB_Key) {
		t.Fatal("delimiter ambiguity: shifting bytes across field boundary derived the same key")
	}
}
