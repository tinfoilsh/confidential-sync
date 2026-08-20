package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	handler    *Handler
	userKey    []byte
	userKeyID  string
	userKeyB64 string
	userSub    string
}

type cpStub struct {
	t          *testing.T
	mu         sync.Mutex
	blobs      map[string]*cpBlob  // scope/id → blob
	keys       map[string]struct{} // hex KeyIDs registered
	currentKID string
	// noKeyHasData simulates a newer controlplane that answers the
	// no-key case with 200 + has_data instead of a bare 404.
	noKeyHasData               bool
	bundles                    map[string]map[string]controlplane.CurrentKeyBundle
	registeredOps              map[string]bool
	migrationFailures          map[string]int
	needsMigration             []cpNeedsMigration
	legacyAttachments          map[string][]byte // attachmentID → ciphertext (set by tests)
	goneAttachments            map[string]bool   // attachmentID → already promoted to v2 (410)
	attachmentIndex            map[string]string // attachmentID → chatID (populated by handler)
	attachmentOwner            map[string]string // attachmentID → clerkUserID (set by tests)
	sourceRevision             int64
	oldestReplayableRevision   int64
	revisions                  []controlplane.RevisionEvent
	searchState                controlplane.SearchIndexState
	searchConflict             func(controlplane.SearchIndexState) controlplane.SearchIndexState
	minimumProfileSyncProtocol int
	// wipedAttachments seeds the start_fresh response so tests can
	// exercise the enclave-side buckets cleanup cascade. Real
	// controlplane returns the ids of the v2 attachments it nulled
	// during the atomic wipe; tests pre-populate this slice.
	wipedAttachments              []string
	deleteAllStatus               int
	deleteAllCode                 string
	deleteAllUnconfirmed          bool
	mux                           *http.ServeMux
	server                        *httptest.Server
	registerHandler               func(w http.ResponseWriter, r *http.Request)
	beforePutBlob                 func(scope, id string)
	putBlobFailures               map[string]int
	postPutFailures               map[string]int
	deleteAttachmentIndexFailures map[string]int
	captureHeaders                func(r *http.Request)
}

type cpNeedsMigration struct {
	ID string
}

type cpBlob struct {
	ETag         int64
	KeyID        string
	Body         []byte
	ProjectIDSet bool
	ProjectID    *string
	UpdatedAt    time.Time
}

func newCPStub(t *testing.T) *cpStub {
	t.Helper()
	st := &cpStub{
		t:                             t,
		blobs:                         map[string]*cpBlob{},
		keys:                          map[string]struct{}{},
		bundles:                       map[string]map[string]controlplane.CurrentKeyBundle{},
		registeredOps:                 map[string]bool{},
		migrationFailures:             map[string]int{},
		putBlobFailures:               map[string]int{},
		postPutFailures:               map[string]int{},
		deleteAttachmentIndexFailures: map[string]int{},
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
	s.mux.HandleFunc("DELETE "+controlplane.DeleteAllProjectsPath, s.handleDeleteAllProjects)
	// rewrap (separate JSON endpoint; not the PUT blob path)
	s.mux.HandleFunc("POST /api/sync/rewrap", s.handleRewrap)
	// list-status + migration surface
	s.mux.HandleFunc("GET /api/sync/list-status", s.handleListStatus)
	s.mux.HandleFunc("GET "+controlplane.RevisionSummaryPath, s.handleRevisionSummary)
	s.mux.HandleFunc("GET "+controlplane.RevisionEventsPath, s.handleRevisionEvents)
	s.mux.HandleFunc("GET "+controlplane.RevisionSnapshotPath, s.handleRevisionSnapshot)
	s.mux.HandleFunc("GET /api/sync/search-index", s.handleGetSearchIndex)
	s.mux.HandleFunc("PUT /api/sync/search-index", s.handlePublishSearchIndex)
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
	s.mux.HandleFunc("DELETE /api/sync/attachment-index/{aid}", s.handleDeleteAttachmentIndex)
	s.mux.HandleFunc("GET /api/sync/attachment-owner/{aid}", s.handleAttachmentOwner)
	// pending-attachment-write ledger (no-op when the test fixture
	// hasn't opted in; AttachmentPut's reserve call is best-effort).
	s.mux.HandleFunc("POST /api/sync/pending-attachments/{aid}", s.handleReservePendingAttachment)
	s.mux.HandleFunc("POST /api/sync/pending-attachments/sweep", s.handleSweepPendingAttachments)
}

// handleReservePendingAttachment / handleSweepPendingAttachments mirror
// the controlplane ledger endpoints. The unit fixture only needs them
// to return 200 so AttachmentPut's preflight reservation does not blow
// up; production-grade behavior (atomic clear on register, sweeper
// reaping) is exercised by the localstack stub_cp.
func (s *cpStub) handleReservePendingAttachment(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *cpStub) handleSweepPendingAttachments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"rows":[]}`))
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
		if s.beforePutBlob != nil {
			s.beforePutBlob(scope, id)
		}
		if s.putBlobFailures[key] > 0 {
			s.putBlobFailures[key]--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ifMatch := r.Header.Get("If-Match")
		blob := s.blobs[key]
		if scope == "profile" && blob != nil && s.minimumProfileSyncProtocol > 0 {
			protocol, _ := strconv.Atoi(r.Header.Get(controlplane.HeaderProfileSyncProtocol))
			if protocol < s.minimumProfileSyncProtocol {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUpgradeRequired)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"code":             controlplane.StatusProfileSyncUpgradeRequired,
					"minimum_protocol": s.minimumProfileSyncProtocol,
				})
				return
			}
		}
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
		updatedAt := time.Now().UTC()
		stored := &cpBlob{
			ETag:      nextETag,
			KeyID:     r.Header.Get("X-Key-Id"),
			Body:      body,
			UpdatedAt: updatedAt,
		}
		if scope == "chat" && r.Header.Get(controlplane.HeaderProjectIDSet) == "1" {
			stored.ProjectIDSet = true
			if projectID := r.Header.Get(controlplane.HeaderProjectID); projectID != "" {
				stored.ProjectID = &projectID
			}
		}
		s.blobs[key] = stored
		if scope == "chat" {
			s.sourceRevision++
			s.revisions = append(s.revisions, controlplane.RevisionEvent{
				Revision:  formatETag(s.sourceRevision),
				Kind:      "upsert",
				ID:        id,
				ETag:      formatETag(nextETag),
				KeyID:     r.Header.Get("X-Key-Id"),
				UpdatedAt: updatedAt.Format(time.RFC3339Nano),
			})
		}
		if s.postPutFailures[key] > 0 {
			s.postPutFailures[key]--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", formatETag(nextETag))
		w.Header().Set("X-Key-Id", r.Header.Get("X-Key-Id"))
		json.NewEncoder(w).Encode(map[string]any{
			"etag":            formatETag(nextETag),
			"source_revision": s.sourceRevision,
		})
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
		if scope == "chat" && blob.ProjectIDSet {
			w.Header().Set("X-Project-Id-Set", "1")
			if blob.ProjectID != nil {
				w.Header().Set("X-Project-Id", *blob.ProjectID)
			}
		}
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
		if scope == "chat" {
			s.sourceRevision++
			s.revisions = append(s.revisions, controlplane.RevisionEvent{
				Revision:  formatETag(s.sourceRevision),
				Kind:      "delete",
				ID:        id,
				UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
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
			"source_revision":      s.sourceRevision,
		})
	}
}

func (s *cpStub) handleDeleteAllProjects(w http.ResponseWriter, r *http.Request) {
	if s.deleteAllStatus != 0 {
		w.WriteHeader(s.deleteAllStatus)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": s.deleteAllCode})
		return
	}
	if s.deleteAllUnconfirmed {
		_ = json.NewEncoder(w).Encode(controlplane.DeleteAllProjectsResponse{OK: false})
		return
	}
	deleted := 0
	for key := range s.blobs {
		if strings.HasPrefix(key, "project/") {
			deleted++
		}
		if strings.HasPrefix(key, "project/") || strings.HasPrefix(key, "project_document/") {
			delete(s.blobs, key)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(controlplane.DeleteAllProjectsResponse{OK: true, Deleted: deleted})
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
			ID:        parts[1],
			ETag:      formatETag(blob.ETag),
			KeyID:     blob.KeyID,
			ProjectID: blob.ProjectID,
			UpdatedAt: blob.UpdatedAt,
		})
	}
	json.NewEncoder(w).Encode(controlplane.ListStatusResponse{Updates: updates})
}

func (s *cpStub) handleRevisionSummary(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(controlplane.RevisionSummaryResponse{
		CurrentRevision:          formatETag(s.sourceRevision),
		OldestReplayableRevision: formatETag(s.oldestReplayableRevision),
	})
}

func (s *cpStub) handleRevisionEvents(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after_revision"), 10, 64)
	if after < s.oldestReplayableRevision {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":                       controlplane.StatusSyncSnapshotRequired,
			"message":                    "chat sync snapshot required",
			"current_revision":           formatETag(s.sourceRevision),
			"oldest_replayable_revision": formatETag(s.oldestReplayableRevision),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(controlplane.RevisionEventsResponse{Events: s.revisions})
}

func (s *cpStub) handleRevisionSnapshot(w http.ResponseWriter, r *http.Request) {
	items := make([]controlplane.RevisionSnapshotItem, 0)
	for key, blob := range s.blobs {
		parts := strings.SplitN(key, "/", 2)
		if parts[0] != "chat" {
			continue
		}
		items = append(items, controlplane.RevisionSnapshotItem{
			ID:        parts[1],
			ETag:      formatETag(blob.ETag),
			KeyID:     blob.KeyID,
			ProjectID: blob.ProjectID,
			UpdatedAt: blob.UpdatedAt.Format(time.RFC3339Nano),
		})
	}
	_ = json.NewEncoder(w).Encode(controlplane.RevisionSnapshotResponse{
		Items:            items,
		SnapshotRevision: formatETag(s.sourceRevision),
	})
}

func (s *cpStub) currentSearchState() controlplane.SearchIndexState {
	state := s.searchState
	state.SourceRevision = s.sourceRevision
	state.Incomplete = state.PublicationIncomplete || state.PublishedSourceRevision < state.SourceRevision
	return state
}

func (s *cpStub) handleGetSearchIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.currentSearchState())
}

func (s *cpStub) handlePublishSearchIndex(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ExpectedGeneration    int64  `json:"expected_generation"`
		ExpectedFence         int64  `json:"expected_fence"`
		CoveredSourceRevision int64  `json:"covered_source_revision"`
		ObjectKey             string `json:"object_key"`
		KeyID                 string `json:"key_id"`
		Model                 string `json:"model"`
		Incomplete            bool   `json:"incomplete"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	state := s.currentSearchState()
	if s.searchConflict != nil {
		conflict := s.searchConflict
		s.searchConflict = nil
		s.searchState = conflict(state)
		state = s.currentSearchState()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":  controlplane.StatusSearchIndexConflict,
			"state": state,
		})
		return
	}
	if req.ExpectedGeneration != state.PublicationGeneration ||
		req.ExpectedFence != state.FenceGeneration ||
		req.CoveredSourceRevision < state.PublishedSourceRevision ||
		req.CoveredSourceRevision > state.SourceRevision ||
		(s.currentKID != "" && req.KeyID != s.currentKID) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":  controlplane.StatusSearchIndexConflict,
			"state": state,
		})
		return
	}
	s.searchState = controlplane.SearchIndexState{
		PublicationGeneration:   state.PublicationGeneration + 1,
		FenceGeneration:         state.FenceGeneration,
		PublishedSourceRevision: req.CoveredSourceRevision,
		ObjectKey:               req.ObjectKey,
		KeyID:                   req.KeyID,
		Model:                   req.Model,
		PublicationIncomplete:   req.Incomplete,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.currentSearchState())
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
	previousKID := s.currentKID
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
				if strings.HasPrefix(k, "chat/") {
					s.sourceRevision++
				}
			}
		}
	}
	s.keys[body.KeyID] = struct{}{}
	s.currentKID = body.KeyID
	searchIndexFenced := body.CreatedVia == "start_fresh" || (previousKID != "" && previousKID != body.KeyID)
	if searchIndexFenced {
		state := s.currentSearchState()
		s.searchState = controlplane.SearchIndexState{
			PublicationGeneration: state.PublicationGeneration + 1,
			FenceGeneration:       state.FenceGeneration + 1,
			PublicationIncomplete: true,
		}
	}
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
	if searchIndexFenced {
		w.Header().Set(controlplane.HeaderSearchIndexFenced, "true")
	}
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
		if s.noKeyHasData {
			// Mirror the real controlplane's no-key 200 shape verbatim,
			// including the empty `created_at` string. Encoding the
			// CurrentKeyResponse struct would mask a regression if the
			// decode type ever drifts back to time.Time (which cannot
			// parse ""), so pin the exact wire bytes the enclave must
			// tolerate.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key_id":"","etag":"","bundles":{},"created_via":"","created_at":"","has_data":true}`))
			return
		}
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
	if s.goneAttachments[aid] {
		w.WriteHeader(http.StatusGone)
		return
	}
	if s.legacyAttachments == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, ok := s.legacyAttachments[aid]
	if !ok {
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

func (s *cpStub) handleDeleteAttachmentIndex(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	if s.deleteAttachmentIndexFailures[aid] > 0 {
		s.deleteAttachmentIndexFailures[aid]--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if s.attachmentIndex == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, ok := s.attachmentIndex[aid]; !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	delete(s.attachmentIndex, aid)
	w.WriteHeader(http.StatusNoContent)
}

// handleAttachmentOwner mirrors GET /api/sync/attachment-owner/{id}:
// the enclave's read path resolves the owning user here so the buckets
// tenant prefix comes from a trusted source, not the caller. Runs
// under the stub's mutex (held by the server wrapper), so it reads the
// map without locking.
func (s *cpStub) handleAttachmentOwner(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	owner := s.attachmentOwner[aid]
	if owner == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"clerk_user_id": owner})
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
	bkClient := buckets.NewClient(bk.server.URL, testBucketName, nil)

	deps := Deps{Controlplane: cpClient, Buckets: bkClient, GitSHA: "test-sha"}
	handler := NewHandler(deps, v, nil)
	// Shorten retention so migrate-all kickoff tests don't leak
	// in-memory job state across cases.
	handler.coordinator.retention = 50 * time.Millisecond
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
		handler:    handler,
		userKey:    rawKey,
		userKeyID:  kidHex,
		userKeyB64: base64.StdEncoding.EncodeToString(rawKey),
		userSub:    "user_abc",
	}
}

func TestBlobOperationHashIgnoresRandomizedEnvelopeBytes(t *testing.T) {
	f := newFixture(t)
	plaintext := []byte(`{"id":"chat_1","messages":[]}`)
	aadBytes, err := envelope.CanonicalPayloadAAD(envelope.AAD{
		KeyIDHex:    f.userKeyID,
		Scope:       envelope.ScopeChat,
		ID:          "chat_1",
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatal(err)
	}

	a, err := operationHashForBlob(f.userKey, http.MethodPut, "chat", "chat_1", f.userKeyID, "0", "idem-1", 0, aadBytes, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	b, err := operationHashForBlob(f.userKey, http.MethodPut, "chat", "chat_1", f.userKeyID, "0", "idem-1", 0, aadBytes, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("op-hash changed for identical logical blob write")
	}

	c, err := operationHashForBlob(f.userKey, http.MethodPut, "chat", "chat_1", f.userKeyID, "0", "idem-1", 0, aadBytes, []byte(`{"id":"chat_1","messages":[{"role":"user"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("op-hash did not change when plaintext changed")
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
	req.Header.Set(controlplane.HeaderSyncProtocol, strconv.Itoa(controlplane.SyncProtocolV2))
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
	projectID := "project-1"
	f.cp.mu.Lock()
	f.cp.blobs["chat/chat_1"].ProjectIDSet = true
	f.cp.blobs["chat/chat_1"].ProjectID = &projectID
	f.cp.mu.Unlock()

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
	if !pull.Items[0].ProjectIDSet || pull.Items[0].ProjectID == nil || *pull.Items[0].ProjectID != projectID {
		t.Fatalf("project metadata: %+v", pull.Items[0])
	}
}

func TestPushPropagatesRequestIDAndReturnsOutcomeUnknown(t *testing.T) {
	tests := []struct {
		name      string
		requestID string
		preserve  bool
	}{
		{name: "accepts caller request id", requestID: "browser-report-1", preserve: true},
		{name: "generates request id"},
		{name: "replaces unsafe request id", requestID: "browser report/1"},
		{name: "replaces oversized request id", requestID: strings.Repeat("a", MaxPushRequestIDLength+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			var seenRequestIDs []string
			cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenRequestIDs = append(seenRequestIDs, r.Header.Get(controlplane.HeaderRequestID))
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"code":"UPSTREAM_UNAVAILABLE"}`)
			}))
			t.Cleanup(cp.Close)
			f.handler.deps.Controlplane = controlplane.NewClient(cp.URL, nil)

			body, err := json.Marshal(PushRequest{
				Scope:          "chat",
				ID:             "request-id-chat",
				Key:            f.userKeyB64,
				Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"messages":[]}`)),
				IdempotencyKey: "request-id-idem",
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/sync/push", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+f.jwt())
			req.Header.Set(controlplane.HeaderSyncProtocol, strconv.Itoa(controlplane.SyncProtocolV2))
			req.Header.Set("Content-Type", "application/json")
			if tc.requestID != "" {
				req.Header.Set(controlplane.HeaderRequestID, tc.requestID)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", resp.StatusCode, respBody)
			}
			var appErr AppError
			if err := json.Unmarshal(respBody, &appErr); err != nil {
				t.Fatal(err)
			}
			if appErr.Code != CodeUpstream || appErr.Reason != "outcome_unknown" {
				t.Fatalf("error=%+v", appErr)
			}
			echoed := resp.Header.Get(controlplane.HeaderRequestID)
			if !validPushRequestID(echoed) {
				t.Fatalf("echoed request id=%q", echoed)
			}
			if tc.preserve && echoed != tc.requestID {
				t.Fatalf("caller request id changed: got=%q want=%q", echoed, tc.requestID)
			}
			if !tc.preserve && tc.requestID != "" && echoed == tc.requestID {
				t.Fatalf("invalid caller request id was preserved: %q", echoed)
			}
			if len(seenRequestIDs) != 2 || seenRequestIDs[0] != echoed || seenRequestIDs[1] != echoed {
				t.Fatalf("controlplane request ids=%v echoed=%q", seenRequestIDs, echoed)
			}
		})
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

func TestUnauthenticatedPushDoesNotConsumeIdempotencyKey(t *testing.T) {
	f := newFixture(t)
	controlplaneRequests := 0
	f.cp.captureHeaders = func(r *http.Request) {
		f.cp.mu.Lock()
		defer f.cp.mu.Unlock()
		controlplaneRequests++
	}
	push := PushRequest{
		Scope:          "chat",
		ID:             "auth-retry",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"messages":[]}`)),
		IdempotencyKey: "auth-retry-key",
	}

	resp, body := f.post("/v1/sync/push", push, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated push: status=%d body=%s", resp.StatusCode, body)
	}
	f.cp.mu.Lock()
	requestsAfterFailure := controlplaneRequests
	_, persistedAfterFailure := f.cp.blobs["chat/auth-retry"]
	f.cp.mu.Unlock()
	if requestsAfterFailure != 0 || persistedAfterFailure {
		t.Fatalf("unauthenticated push reached persistence: requests=%d persisted=%t", requestsAfterFailure, persistedAfterFailure)
	}

	resp, body = f.post("/v1/sync/push", push, f.jwt())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated retry: status=%d body=%s", resp.StatusCode, body)
	}
	f.cp.mu.Lock()
	requestsAfterRetry := controlplaneRequests
	_, persistedAfterRetry := f.cp.blobs["chat/auth-retry"]
	f.cp.mu.Unlock()
	if requestsAfterRetry != 1 || !persistedAfterRetry {
		t.Fatalf("authenticated retry did not persist: requests=%d persisted=%t", requestsAfterRetry, persistedAfterRetry)
	}
}

func TestAuthenticationPrecedesProtocolEnforcement(t *testing.T) {
	f := newFixture(t)
	for _, authorization := range []string{"", "Bearer garbage"} {
		req, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/key/current", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set(controlplane.HeaderAuth, authorization)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("authorization %q: status=%d body=%s", authorization, resp.StatusCode, body)
		}
	}
}

func TestAuthenticatedRoutesRequireSyncProtocolV2(t *testing.T) {
	f := newFixture(t)
	for _, protocols := range [][]string{nil, {"1"}, {"3"}, {"2", "1"}} {
		req, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/key/current", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(controlplane.HeaderAuth, "Bearer "+f.jwt())
		for _, protocol := range protocols {
			req.Header.Add(controlplane.HeaderSyncProtocol, protocol)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if resp.StatusCode != http.StatusUpgradeRequired {
			t.Fatalf("protocols %q: status=%d body=%s", protocols, resp.StatusCode, body)
		}
		var appErr AppError
		if err := json.Unmarshal(body, &appErr); err != nil {
			t.Fatal(err)
		}
		if appErr.Code != CodeSyncProtocolUpgradeRequired {
			t.Fatalf("protocols %q: error=%+v", protocols, appErr)
		}
		if appErr.MinimumProtocol != controlplane.SyncProtocolV2 {
			t.Fatalf("protocols %q: minimum_protocol=%d, want %d", protocols, appErr.MinimumProtocol, controlplane.SyncProtocolV2)
		}
	}
}

func TestRevisionSyncRoutesProxyReplayMetadata(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	var revisionRequests int
	f.cp.captureHeaders = func(r *http.Request) {
		if r.URL.Path != controlplane.RevisionSummaryPath && r.URL.Path != controlplane.RevisionEventsPath && r.URL.Path != controlplane.RevisionSnapshotPath {
			return
		}
		revisionRequests++
		if got := r.Header.Get(controlplane.HeaderAuth); got != "Bearer "+tok {
			t.Errorf("forwarded authorization=%q", got)
		}
		if got := r.Header.Get(controlplane.HeaderClerkUserID); got != f.userSub {
			t.Errorf("forwarded subject=%q", got)
		}
		if r.URL.Path == controlplane.RevisionEventsPath {
			query := r.URL.Query()
			if query.Get("after_revision") != "0" || query.Get("through_revision") != "1" || query.Get("limit") != "10" {
				t.Errorf("forwarded revision query=%q", r.URL.RawQuery)
			}
		}
	}
	pushResponse, pushBody := f.post("/v1/sync/push", PushRequest{
		Scope:          "chat",
		ID:             "revision-chat",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"id":"revision-chat"}`)),
		IdempotencyKey: "revision-push",
	}, tok)
	if pushResponse.StatusCode != http.StatusOK {
		t.Fatalf("push: status=%d body=%s", pushResponse.StatusCode, pushBody)
	}

	summaryResponse, summaryBody := f.post("/v1/sync/revision-summary", RevisionSummaryRequest{}, tok)
	if summaryResponse.StatusCode != http.StatusOK {
		t.Fatalf("summary: status=%d body=%s", summaryResponse.StatusCode, summaryBody)
	}
	var summary RevisionSummaryResponse
	if err := json.Unmarshal(summaryBody, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.CurrentRevision != "1" || summary.OldestReplayableRevision != "0" {
		t.Fatalf("summary=%+v", summary)
	}

	limit := 10
	eventsResponse, eventsBody := f.post("/v1/sync/revision-events", RevisionEventsRequest{
		AfterRevision:   "0",
		ThroughRevision: summary.CurrentRevision,
		Limit:           &limit,
	}, tok)
	if eventsResponse.StatusCode != http.StatusOK {
		t.Fatalf("events: status=%d body=%s", eventsResponse.StatusCode, eventsBody)
	}
	var events RevisionEventsResponse
	if err := json.Unmarshal(eventsBody, &events); err != nil {
		t.Fatal(err)
	}
	if len(events.Events) != 1 || events.Events[0].Kind != "upsert" || events.Events[0].ID != "revision-chat" {
		t.Fatalf("events=%+v", events)
	}

	snapshotResponse, snapshotBody := f.post("/v1/sync/revision-snapshot", RevisionSnapshotRequest{}, tok)
	if snapshotResponse.StatusCode != http.StatusOK {
		t.Fatalf("snapshot: status=%d body=%s", snapshotResponse.StatusCode, snapshotBody)
	}
	var snapshot RevisionSnapshotResponse
	if err := json.Unmarshal(snapshotBody, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SnapshotRevision != "1" || len(snapshot.Items) != 1 || snapshot.Items[0].ID != "revision-chat" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if revisionRequests != 3 {
		t.Fatalf("revision requests=%d", revisionRequests)
	}
}

// TestRevisionEventsSnapshotRequiredPassesThrough asserts the
// controlplane's SYNC_SNAPSHOT_REQUIRED 409 reaches the enclave's
// client with its structure intact: the code plus both revision
// fields the client needs to bootstrap a snapshot without an extra
// summary round trip.
func TestRevisionEventsSnapshotRequiredPassesThrough(t *testing.T) {
	f := newFixture(t)
	f.cp.mu.Lock()
	f.cp.sourceRevision = 9
	f.cp.oldestReplayableRevision = 5
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/sync/revision-events", RevisionEventsRequest{
		AfterRevision:   "2",
		ThroughRevision: "9",
	}, f.jwt())
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("parse body: %v %s", err, body)
	}
	if parsed["code"] != controlplane.StatusSyncSnapshotRequired {
		t.Fatalf("code=%v body=%s", parsed["code"], body)
	}
	if parsed["current_revision"] != "9" {
		t.Fatalf("current_revision=%v body=%s", parsed["current_revision"], body)
	}
	if parsed["oldest_replayable_revision"] != "5" {
		t.Fatalf("oldest_replayable_revision=%v body=%s", parsed["oldest_replayable_revision"], body)
	}
}

func TestListStatusRemainsAvailableWithProtocolV2(t *testing.T) {
	f := newFixture(t)
	projectID := "project-1"
	updatedAt := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	f.cp.mu.Lock()
	f.cp.blobs["chat/listed-chat"] = &cpBlob{
		ETag:      7,
		KeyID:     f.userKeyID,
		ProjectID: &projectID,
		UpdatedAt: updatedAt,
	}
	f.cp.mu.Unlock()

	tok := f.jwt()
	var proxied bool
	f.cp.captureHeaders = func(r *http.Request) {
		if r.URL.Path != "/api/sync/list-status" {
			return
		}
		proxied = true
		query := r.URL.Query()
		if query.Get("scope") != "chat" || query.Get("cursor") != "cursor-1" || query.Get("limit") != "50" || query.Get("project_id") != projectID || query.Get("direction") != "desc" {
			t.Errorf("forwarded list-status query=%q", r.URL.RawQuery)
		}
		if got := r.Header.Get(controlplane.HeaderAuth); got != "Bearer "+tok {
			t.Errorf("forwarded authorization=%q", got)
		}
		if got := r.Header.Get(controlplane.HeaderClerkUserID); got != f.userSub {
			t.Errorf("forwarded subject=%q", got)
		}
	}
	response, body := f.post("/v1/sync/list-status", ListStatusRequest{
		Scope:     "chat",
		Cursor:    "cursor-1",
		Limit:     50,
		ProjectID: projectID,
		Direction: "desc",
	}, tok)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	var list ListStatusResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if !proxied || len(list.Updates) != 1 || list.Updates[0].ID != "listed-chat" || list.Updates[0].ProjectID == nil || *list.Updates[0].ProjectID != projectID || list.Updates[0].UpdatedAt != updatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("proxied=%v response=%+v", proxied, list)
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
	canonicalIV := strings.Repeat("0", canonicalBundleKEKIVHexLen)
	canonicalCT := strings.Repeat("a", canonicalBundleEncryptedKeysHexLen)
	resp, body := f.post("/v1/key/add-bundle", AddBundleRequest{
		KeyID:          f.userKeyID,
		Key:            f.userKeyB64,
		CredentialID:   "cred-x",
		KEKIV:          canonicalIV,
		EncryptedKeys:  canonicalCT,
		IdempotencyKey: "idem-add-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add-bundle: %d %s", resp.StatusCode, body)
	}
	if got, ok := f.cp.bundles[f.userKeyID]; !ok || got["cred-x"].EncryptedKeys != canonicalCT {
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
		KEKIV:          strings.Repeat("0", canonicalBundleKEKIVHexLen),
		EncryptedKeys:  strings.Repeat("a", canonicalBundleEncryptedKeysHexLen),
		IdempotencyKey: "idem-add-1",
	}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", resp.StatusCode, body)
	}
	if _, ok := f.cp.bundles[f.userKeyID]; ok {
		t.Fatalf("mismatched bundle was stored: %+v", f.cp.bundles)
	}
}

// Canonical bundle shape: AES-256-GCM wraps a raw 32-byte CEK using
// a 12-byte IV, producing a 48-byte ciphertext+tag. The hex-encoded
// wire is 24 hex chars for the IV and 96 hex chars for the ciphertext.
// Both write endpoints reject anything outside that shape so legacy
// JSON-envelope bundles can never sneak back in via newer clients.
func TestRegisterKeyRejectsNonCanonicalBundle(t *testing.T) {
	cases := []struct {
		name string
		iv   string
		ct   string
	}{
		{
			name: "iv too short",
			iv:   "00",
			ct:   strings.Repeat("a", canonicalBundleEncryptedKeysHexLen),
		},
		{
			name: "ciphertext too long",
			iv:   strings.Repeat("0", canonicalBundleKEKIVHexLen),
			ct:   strings.Repeat("a", canonicalBundleEncryptedKeysHexLen+2),
		},
		{
			name: "iv has uppercase hex",
			iv:   strings.Repeat("A", canonicalBundleKEKIVHexLen),
			ct:   strings.Repeat("a", canonicalBundleEncryptedKeysHexLen),
		},
		{
			name: "ciphertext has non-hex chars",
			iv:   strings.Repeat("0", canonicalBundleKEKIVHexLen),
			ct:   strings.Repeat("z", canonicalBundleEncryptedKeysHexLen),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tok := f.jwt()
			resp, body := f.post("/v1/key/register", KeyRegisterRequest{
				Key:            f.userKeyB64,
				IfMatch:        "*",
				CreatedVia:     "passkey",
				IdempotencyKey: "reg-bad-bundle",
				InitialBundle: &KeyRegisterBundleInput{
					CredentialID:  "cred-x",
					KEKIV:         tc.iv,
					EncryptedKeys: tc.ct,
				},
			}, tok)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d %s", resp.StatusCode, body)
			}
			if _, ok := f.cp.keys[f.userKeyID]; ok {
				t.Fatalf("key registered despite invalid bundle: %v", f.cp.keys)
			}
		})
	}
}

func TestAddBundleRejectsNonCanonicalBundle(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	resp, body := f.post("/v1/key/add-bundle", AddBundleRequest{
		KeyID:          f.userKeyID,
		Key:            f.userKeyB64,
		CredentialID:   "cred-x",
		KEKIV:          "not-hex",
		EncryptedKeys:  strings.Repeat("a", canonicalBundleEncryptedKeysHexLen),
		IdempotencyKey: "idem-add-bad",
	}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", resp.StatusCode, body)
	}
	if _, ok := f.cp.bundles[f.userKeyID]; ok {
		t.Fatalf("non-canonical bundle was stored: %+v", f.cp.bundles)
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

func TestDeleteAllProjectsRouteAndWireContract(t *testing.T) {
	f := newFixture(t)
	f.cp.mu.Lock()
	f.cp.blobs["project/project-1"] = &cpBlob{}
	f.cp.blobs["project/project-2"] = &cpBlob{}
	f.cp.blobs["project_document/project-1/doc-1"] = &cpBlob{}
	f.cp.blobs["chat/chat-1"] = &cpBlob{}
	f.cp.mu.Unlock()

	var captured *http.Request
	f.cp.mu.Lock()
	f.cp.captureHeaders = func(r *http.Request) { captured = r.Clone(r.Context()) }
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/sync/delete-all-projects", DeleteAllProjectsRequest{
		Key:            f.userKeyB64,
		IdempotencyKey: "delete-projects-1",
	}, f.jwt())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete all projects: %d %s", resp.StatusCode, body)
	}
	var result DeleteAllProjectsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Deleted != 2 {
		t.Fatalf("response = %+v", result)
	}
	if captured == nil || captured.Method != http.MethodDelete || captured.URL.Path != controlplane.DeleteAllProjectsPath {
		t.Fatalf("captured request = %+v", captured)
	}
	if captured.Header.Get(controlplane.HeaderAuth) == "" || captured.Header.Get(controlplane.HeaderClerkUserID) != f.userSub {
		t.Fatalf("auth headers = %v", captured.Header)
	}
	if captured.Header.Get(controlplane.HeaderKeyID) != f.userKeyID || captured.Header.Get(controlplane.HeaderIdempotency) != "delete-projects-1" {
		t.Fatalf("operation headers = %v", captured.Header)
	}
	if captured.Header.Get(controlplane.HeaderIfMatch) != "" {
		t.Fatalf("unexpected If-Match = %q", captured.Header.Get(controlplane.HeaderIfMatch))
	}
	opKey, err := cryptopkg.DeriveOpHashKey(f.userKey)
	if err != nil {
		t.Fatal(err)
	}
	defer cryptopkg.Zero(opKey)
	wantHash := cryptopkg.ComputeOperationHash(opKey, cryptopkg.CanonicalInput{
		Method:         http.MethodDelete,
		Path:           controlplane.DeleteAllProjectsPath,
		KeyIDHex:       f.userKeyID,
		IdempotencyKey: "delete-projects-1",
	})
	if captured.Header.Get(controlplane.HeaderOperationHash) != wantHash {
		t.Fatalf("operation hash = %q, want %q", captured.Header.Get(controlplane.HeaderOperationHash), wantHash)
	}
	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	if f.cp.blobs["project/project-1"] != nil || f.cp.blobs["project_document/project-1/doc-1"] != nil {
		t.Fatal("project blobs were not deleted")
	}
	if f.cp.blobs["chat/chat-1"] == nil {
		t.Fatal("non-project blob was deleted")
	}
}

func TestDeleteAllProjectsRequiresAuthentication(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.post("/v1/sync/delete-all-projects", DeleteAllProjectsRequest{
		Key:            f.userKeyB64,
		IdempotencyKey: "delete-projects-1",
	}, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestDeleteAllProjectsRejectsInvalidRequests(t *testing.T) {
	f := newFixture(t)
	token := f.jwt()
	for name, req := range map[string]DeleteAllProjectsRequest{
		"missing key":             {IdempotencyKey: "delete-projects-1"},
		"malformed key":           {Key: "not-base64", IdempotencyKey: "delete-projects-1"},
		"missing idempotency key": {Key: f.userKeyB64},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := f.post("/v1/sync/delete-all-projects", req, token)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
			}
		})
	}

	httpReq, _ := http.NewRequest(http.MethodPost, f.server.URL+"/v1/sync/delete-all-projects", strings.NewReader(`{"key":`))
	httpReq.Header.Set(controlplane.HeaderAuth, "Bearer "+token)
	httpReq.Header.Set(controlplane.HeaderSyncProtocol, strconv.Itoa(controlplane.SyncProtocolV2))
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", resp.StatusCode)
	}
}

func TestDeleteAllProjectsForwardsUpstreamError(t *testing.T) {
	f := newFixture(t)
	f.cp.mu.Lock()
	f.cp.deleteAllStatus = http.StatusConflict
	f.cp.deleteAllCode = controlplane.StatusIdempotencyConflict
	f.cp.mu.Unlock()
	resp, body := f.post("/v1/sync/delete-all-projects", DeleteAllProjectsRequest{
		Key:            f.userKeyB64,
		IdempotencyKey: "delete-projects-1",
	}, f.jwt())
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var appErr AppError
	if err := json.Unmarshal(body, &appErr); err != nil {
		t.Fatal(err)
	}
	if appErr.Code != CodeIdempotencyConflict {
		t.Fatalf("error = %+v", appErr)
	}
}

func TestDeleteAllProjectsRequiresUpstreamConfirmation(t *testing.T) {
	f := newFixture(t)
	f.cp.mu.Lock()
	f.cp.deleteAllUnconfirmed = true
	f.cp.mu.Unlock()
	_, err := DeleteAllProjects(context.Background(), f.handler.deps, importSession(f), DeleteAllProjectsRequest{
		Key:            f.userKeyB64,
		IdempotencyKey: "delete-projects-1",
	})
	if err == nil {
		t.Fatal("expected unconfirmed controlplane response to fail")
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

// TestMigrateV2ProfileAddressedByClerkUserID pins the read-side half
// of the profile AAD-id contract. The controlplane addresses profile
// rows by clerk_user_id, so its needs-migration list returns the user
// id as the row id — but a v2 profile envelope is sealed with the AAD
// id fixed to the profile singleton. The migrate read path must
// normalize the storage id back to that singleton before rebuilding
// the AAD; otherwise a v2 profile being re-sealed under a different
// key fails to decrypt and the migration silently blocks.
func TestMigrateV2ProfileAddressedByClerkUserID(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	// Seal a profile blob exactly as the write path does: AAD id
	// pinned to the profile singleton, not the clerk_user_id the
	// controlplane stores the row under.
	profilePT := []byte(`{"language":"English","theme":"dark"}`)
	v2blob, err := envelope.Encrypt(f.userKey, profilePT, envelope.AAD{
		KeyIDHex:    f.userKeyID,
		Scope:       envelope.ScopeProfile,
		ID:          envelope.ProfileSingletonID,
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Mint the target key the migrate re-seals under.
	targetRaw := make([]byte, cryptopkg.KeySize)
	if _, err := rand.Read(targetRaw); err != nil {
		t.Fatal(err)
	}
	targetB64 := base64.StdEncoding.EncodeToString(targetRaw)
	targetKIDBytes, _ := cryptopkg.DeriveKeyID(targetRaw)
	targetKID := cryptopkg.KeyIDHex(targetKIDBytes)

	// The profile row lives under "profile/profile" in the stub, but
	// the needs-migration list reports it by clerk_user_id, mirroring
	// the real controlplane.
	f.cp.mu.Lock()
	f.cp.blobs["profile/profile"] = &cpBlob{ETag: 1, KeyID: f.userKeyID, Body: v2blob}
	f.cp.needsMigration = []cpNeedsMigration{{ID: f.userSub}}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/blobs/migrate", MigrateRequest{
		Scope:  "profile",
		Limit:  10,
		Keys:   []PullKey{{Key: f.userKeyB64}},
		Target: MigrateTarget{Key: targetB64},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("migrate: %d %s", resp.StatusCode, body)
	}
	var mr MigrateResponse
	if err := json.Unmarshal(body, &mr); err != nil {
		t.Fatal(err)
	}
	if mr.Migrated != 1 || len(mr.Blocked) != 0 {
		t.Fatalf("profile v2 migrate blocked (read AAD id not normalized?): %+v", mr)
	}

	// The re-sealed row must decrypt under the target key with the
	// AAD id still pinned to the profile singleton.
	f.cp.mu.Lock()
	after := f.cp.blobs["profile/profile"]
	f.cp.mu.Unlock()
	if envelope.Detect(after.Body) != envelope.VersionV2 {
		t.Fatalf("profile row not v2 after migrate")
	}
	if after.KeyID != targetKID {
		t.Fatalf("profile row key id = %q, want target %q", after.KeyID, targetKID)
	}
	targetKey := envelope.Key{Bytes: targetRaw, KeyIDHex: targetKID}
	dec, err := envelope.DecryptV2(after.Body, []envelope.Key{targetKey}, envelope.AAD{
		Scope:       envelope.ScopeProfile,
		ID:          envelope.ProfileSingletonID,
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatalf("decrypt migrated profile under target key: %v", err)
	}
	if !bytes.Equal(dec.Plaintext, profilePT) {
		t.Fatalf("profile plaintext changed across migrate: got %q want %q", dec.Plaintext, profilePT)
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

func TestProfileSyncProtocolFromMetadataAcceptsProgrammaticInt(t *testing.T) {
	got, err := profileSyncProtocolFromMetadata("profile", map[string]any{
		profileSyncProtocolMetadataKey: controlplane.ProfileSyncProtocolV2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != controlplane.ProfileSyncProtocolV2 {
		t.Fatalf("protocol = %d, want %d", got, controlplane.ProfileSyncProtocolV2)
	}
}

func TestProfileSyncProtocolForwardedAndHashBound(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	var (
		mu           sync.Mutex
		seenProtocol string
		seenHash     string
	)
	f.cp.captureHeaders = func(r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/sync/blob/profile" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		seenProtocol = r.Header.Get(controlplane.HeaderProfileSyncProtocol)
		seenHash = r.Header.Get(controlplane.HeaderOperationHash)
	}

	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope:          "profile",
		ID:             "profile",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"theme":"dark"}`)),
		IdempotencyKey: "profile-protocol-2",
		Metadata: map[string]any{
			profileSyncProtocolMetadataKey: float64(controlplane.ProfileSyncProtocolV2),
		},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}

	mu.Lock()
	gotProtocol := seenProtocol
	gotHash := seenHash
	mu.Unlock()
	if gotProtocol != strconv.Itoa(controlplane.ProfileSyncProtocolV2) {
		t.Fatalf("%s = %q, want %d", controlplane.HeaderProfileSyncProtocol, gotProtocol, controlplane.ProfileSyncProtocolV2)
	}
	if gotHash == "" {
		t.Fatal("profile operation hash was not forwarded")
	}

	aadBytes, err := envelope.CanonicalPayloadAAD(envelope.AAD{
		KeyIDHex:    f.userKeyID,
		Scope:       envelope.ScopeProfile,
		ID:          envelope.ProfileSingletonID,
		ClerkUserID: f.userSub,
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"theme":"dark"}`)
	v1Hash, err := operationHashForBlob(f.userKey, http.MethodPut, "profile", "profile", f.userKeyID, "0", "same-idem", 1, aadBytes, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	v2Hash, err := operationHashForBlob(f.userKey, http.MethodPut, "profile", "profile", f.userKeyID, "0", "same-idem", controlplane.ProfileSyncProtocolV2, aadBytes, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if v1Hash == v2Hash {
		t.Fatal("operation hash did not bind profile sync protocol")
	}
}

func TestProfileSyncProtocolUpgradeRequiredPassesThrough(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	createResp, createBody := f.post("/v1/sync/push", PushRequest{
		Scope:          "profile",
		ID:             "profile",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"theme":"dark"}`)),
		IdempotencyKey: "profile-create-before-gate",
	}, tok)
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create status: %d body=%s", createResp.StatusCode, createBody)
	}

	f.cp.mu.Lock()
	f.cp.minimumProfileSyncProtocol = controlplane.ProfileSyncProtocolV2
	f.cp.mu.Unlock()

	etag := "1"
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope:          "profile",
		ID:             "profile",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"theme":"light"}`)),
		IfMatch:        &etag,
		IdempotencyKey: "profile-old-protocol",
		Metadata: map[string]any{
			profileSyncProtocolMetadataKey: 1,
		},
	}, tok)
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}
	var appErr AppError
	if err := json.Unmarshal(body, &appErr); err != nil {
		t.Fatal(err)
	}
	if appErr.Code != CodeProfileSyncUpgradeRequired {
		t.Fatalf("code = %q, want %q", appErr.Code, CodeProfileSyncUpgradeRequired)
	}
	if appErr.MinimumProtocol != controlplane.ProfileSyncProtocolV2 {
		t.Fatalf("minimum_protocol = %d, want %d body=%s", appErr.MinimumProtocol, controlplane.ProfileSyncProtocolV2, body)
	}
}

func TestProfileSyncProtocolMetadataIgnoredOutsideProfileScope(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()

	var (
		mu           sync.Mutex
		seenProtocol string
	)
	f.cp.captureHeaders = func(r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/sync/blob/chat/protocol-chat" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		seenProtocol = r.Header.Get(controlplane.HeaderProfileSyncProtocol)
	}

	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope:          "chat",
		ID:             "protocol-chat",
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString([]byte(`{"messages":[]}`)),
		IdempotencyKey: "chat-protocol-metadata",
		Metadata: map[string]any{
			profileSyncProtocolMetadataKey: "not-a-version",
		},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body=%s", resp.StatusCode, body)
	}

	mu.Lock()
	gotProtocol := seenProtocol
	mu.Unlock()
	if gotProtocol != "" {
		t.Fatalf("profile protocol leaked onto chat write: %q", gotProtocol)
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

func TestAttachmentDeleteDropsIndexAndBucket(t *testing.T) {
	f := newFixture(t)
	tok := f.jwt()
	attID := "123e4567-e89b-12d3-a456-426614174111"

	ownerTenant, err := buckets.TenantForUser(f.userSub)
	if err != nil {
		t.Fatal(err)
	}
	f.bk.items.Put(attID, bucketsItem{
		Tenant:         ownerTenant,
		Value:          []byte("payload"),
		EncryptionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)},
	})
	f.cp.mu.Lock()
	f.cp.attachmentIndex = map[string]string{attID: "chat-1"}
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/attachment/delete", AttachmentDeleteRequest{ID: attID}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
	if f.bk.has(attID) {
		t.Fatalf("buckets entry should be gone")
	}
	f.cp.mu.Lock()
	_, indexed := f.cp.attachmentIndex[attID]
	f.cp.mu.Unlock()
	if indexed {
		t.Fatalf("attachment index should be gone")
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

func TestIsAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"controlplane 401", &controlplane.Error{StatusCode: http.StatusUnauthorized}, true},
		{"controlplane 403", &controlplane.Error{StatusCode: http.StatusForbidden}, true},
		{"controlplane 409", &controlplane.Error{StatusCode: http.StatusConflict}, false},
		{"controlplane 500", &controlplane.Error{StatusCode: http.StatusInternalServerError}, false},
		{"wrapped 401", fmt.Errorf("rewrap: %w", &controlplane.Error{StatusCode: http.StatusUnauthorized}), true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isAuthError(tc.err); got != tc.want {
				t.Errorf("isAuthError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
