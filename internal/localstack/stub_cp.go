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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/bucketstub"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

// StubBlob is a stored ciphertext envelope on the stub.
type StubBlob struct {
	ETag         int64
	KeyID        string
	Body         []byte
	ProjectIDSet bool
	ProjectID    *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// StubCP is the in-memory controlplane. Its methods are safe for
// concurrent use; tests can call PeekBlob / SetBlob / CopyBlob /
// InjectLegacyV0 / OnFirstGet directly to drive adversarial
// scenarios.
type StubCP struct {
	mu                       sync.Mutex
	mux                      *http.ServeMux
	blobs                    map[string]*StubBlob
	keys                     map[string]struct{}
	currentKID               string
	bundles                  map[string]map[string]controlplane.CurrentKeyBundle
	deletes                  map[string]stubDelete
	sourceRev                int64
	oldestReplayableRevision int64
	revisions                []controlplane.RevisionEvent
	search                   controlplane.SearchIndexState

	buckets             *bucketstub.Store
	legacyAttachments   map[string][]byte
	attachmentIndex     map[string]attachmentMeta
	pendingAttachments  map[string]pendingAttachment
	pendingExpiryWindow time.Duration

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

// stubDelete mirrors a sync_tombstones row. Production's
// tombstone-on-delete trigger copies the deleted chat's project_id
// onto the tombstone so project-scoped list-status queries return
// the project's deletes as well.
type stubDelete struct {
	deletedAt time.Time
	projectID *string
}

// pendingAttachment mirrors the pending_attachment_writes ledger so
// smoke tests can assert the enclave's two-phase upload flow ends up
// in the right state without needing a real Postgres.
type pendingAttachment struct {
	chatID      string
	clerkUserID string
	createdAt   time.Time
}

// attachmentMeta mirrors the chat_attachments index row the stub needs
// to answer ownership queries: which chat an attachment belongs to and
// which user owns it.
type attachmentMeta struct {
	chatID      string
	clerkUserID string
}

// NewStubCP returns a stub controlplane ready to serve.
func NewStubCP() *StubCP {
	s := &StubCP{
		blobs:               map[string]*StubBlob{},
		keys:                map[string]struct{}{},
		bundles:             map[string]map[string]controlplane.CurrentKeyBundle{},
		deletes:             map[string]stubDelete{},
		buckets:             bucketstub.NewStore(),
		legacyAttachments:   map[string][]byte{},
		attachmentIndex:     map[string]attachmentMeta{},
		pendingAttachments:  map[string]pendingAttachment{},
		pendingExpiryWindow: 15 * time.Minute,
		onFirstDelete:       map[string]func(){},
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
	mux.HandleFunc("DELETE "+controlplane.DeleteAllProjectsPath, s.deleteAllProjects)
	mux.HandleFunc("GET /api/sync/list-status", s.listStatus)
	mux.HandleFunc("GET "+controlplane.BackupInventoryPath, s.backupInventory)
	mux.HandleFunc("GET "+controlplane.RevisionSummaryPath, s.revisionSummary)
	mux.HandleFunc("GET "+controlplane.RevisionEventsPath, s.revisionEvents)
	mux.HandleFunc("GET "+controlplane.RevisionSnapshotPath, s.revisionSnapshot)
	mux.HandleFunc("GET /api/sync/search-index", s.getSearchIndex)
	mux.HandleFunc("PUT /api/sync/search-index", s.publishSearchIndex)
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
	mux.HandleFunc("GET /api/sync/attachment-owner/{aid}", s.attachmentOwner)
	mux.HandleFunc("POST /api/sync/pending-attachments/{aid}", s.reservePendingAttachment)
	mux.HandleFunc("POST /api/sync/pending-attachments/sweep", s.sweepPendingAttachments)
	mux.HandleFunc("/"+LocalStackBucketsBucket+"/{key}", s.buckets.Handle)
	mux.HandleFunc("/"+LocalStackBucketsBucket, s.buckets.Handle)
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

const LocalStackSyncEnclaveSecret = "local-stack-sync-enclave-secret"

// Pagination bounds mirroring the production controlplane's
// constants (SyncRevisionDefaultPageLimit / SyncRevisionMaxPageLimit
// in controlplane/constants/limits.go). The cap also keeps
// offset+limit arithmetic far away from integer overflow.
const (
	defaultRevisionPageLimit = 100
	maxRevisionPageLimit     = 500
)

// LocalStackBucketsBucket is the bucket name the stubbed sidecar
// serves and the enclave's buckets client is configured with.
const LocalStackBucketsBucket = "local-stack-bucket"

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
		CreatedAt: time.Now().UTC(),
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
		ETag:         next,
		KeyID:        src.KeyID,
		Body:         append([]byte(nil), src.Body...),
		ProjectIDSet: src.ProjectIDSet,
		ProjectID:    src.ProjectID,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
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
		updatedAt := time.Now().UTC()
		createdAt := updatedAt
		if blob != nil {
			createdAt = blob.CreatedAt
			if createdAt.IsZero() {
				createdAt = blob.UpdatedAt
			}
		}
		nextBlob := &StubBlob{
			ETag:      next,
			KeyID:     r.Header.Get("X-Key-Id"),
			Body:      body,
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		}
		if blob != nil {
			nextBlob.ProjectIDSet = blob.ProjectIDSet
			nextBlob.ProjectID = blob.ProjectID
		}
		if scope == "chat" && r.Header.Get(controlplane.HeaderProjectIDSet) == "1" {
			nextBlob.ProjectIDSet = true
			nextBlob.ProjectID = nil
			if projectID := r.Header.Get(controlplane.HeaderProjectID); projectID != "" {
				nextBlob.ProjectID = &projectID
			}
		}
		s.blobs[key] = nextBlob
		if scope == "chat" {
			s.sourceRev++
			s.revisions = append(s.revisions, controlplane.RevisionEvent{
				Revision:  formatETag(s.sourceRev),
				Kind:      "upsert",
				ID:        id,
				ETag:      formatETag(next),
				KeyID:     r.Header.Get("X-Key-Id"),
				ProjectID: nextBlob.ProjectID,
				UpdatedAt: updatedAt.Format(time.RFC3339Nano),
			})
		}
		delete(s.deletes, key)
		w.Header().Set("ETag", formatETag(next))
		w.Header().Set("X-Key-Id", r.Header.Get("X-Key-Id"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"etag":            formatETag(next),
			"source_revision": s.sourceRev,
		})
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
		if scope == "chat" && blob.ProjectIDSet {
			w.Header().Set(controlplane.HeaderProjectIDSet, "1")
			if blob.ProjectID != nil {
				w.Header().Set(controlplane.HeaderProjectID, *blob.ProjectID)
			}
		}
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
		if scope == "chat" && blob != nil {
			s.sourceRev++
			s.revisions = append(s.revisions, controlplane.RevisionEvent{
				Revision:  formatETag(s.sourceRev),
				Kind:      "delete",
				ID:        id,
				UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
		}
		// Mirror the tombstone-on-delete trigger: the deleted row's
		// project_id rides along on the tombstone.
		tombstone := stubDelete{deletedAt: time.Now().UTC()}
		if blob != nil {
			tombstone.projectID = blob.ProjectID
		}
		s.deletes[key] = tombstone
		wipedV2 := []string{}
		if scope == "chat" {
			for aid, meta := range s.attachmentIndex {
				if meta.chatID == id {
					wipedV2 = append(wipedV2, aid)
					delete(s.attachmentIndex, aid)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                   true,
			"wiped_v2_attachments": wipedV2,
			"source_revision":      s.sourceRev,
		})
	}
}

func (s *StubCP) deleteAllProjects(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for key, blob := range s.blobs {
		if !strings.HasPrefix(key, "project/") && !strings.HasPrefix(key, "project_document/") {
			continue
		}
		if strings.HasPrefix(key, "project/") {
			deleted++
		}
		delete(s.blobs, key)
		s.deletes[key] = stubDelete{deletedAt: time.Now().UTC(), projectID: blob.ProjectID}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(controlplane.DeleteAllProjectsResponse{OK: true, Deleted: deleted})
}

// listStatusRow is one entry in the merged update/delete timeline the
// stub paginates over, mirroring the production controlplane's
// keyset pagination on (updated_at, id).
type listStatusRow struct {
	ts     time.Time
	id     string
	update *controlplane.BlobMeta
	del    *controlplane.BlobDelete
}

// listStatusCursor is the opaque page token: the (updated_at, id)
// position of the last row emitted. Base64 raw-URL JSON like the
// revision-snapshot cursor so tests treat it as opaque.
type listStatusCursor struct {
	UpdatedAt string `json:"updated_at"`
	ID        string `json:"id"`
}

func encodeListStatusCursor(ts time.Time, id string) string {
	raw, _ := json.Marshal(listStatusCursor{
		UpdatedAt: ts.UTC().Format(time.RFC3339Nano),
		ID:        id,
	})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeListStatusCursor(raw string) (time.Time, string, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", false
	}
	var cursor listStatusCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.ID == "" {
		return time.Time{}, "", false
	}
	ts, err := time.Parse(time.RFC3339Nano, cursor.UpdatedAt)
	if err != nil {
		return time.Time{}, "", false
	}
	return ts, cursor.ID, true
}

// listStatusRowLess orders the merged timeline oldest-first with id
// as the tie-breaker, matching the controlplane's keyset order.
func listStatusRowLess(a, b listStatusRow) bool {
	if !a.ts.Equal(b.ts) {
		return a.ts.Before(b.ts)
	}
	return a.id < b.id
}

func (s *StubCP) listStatus(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	scope := query.Get("scope")
	projectID := query.Get("project_id")
	direction := query.Get("direction")
	if direction != "" && direction != "asc" && direction != "desc" {
		http.Error(w, "invalid direction", http.StatusBadRequest)
		return
	}
	limit := 100
	if rawLimit := query.Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	var afterTS time.Time
	afterID := ""
	hasCursor := false
	if rawCursor := query.Get("cursor"); rawCursor != "" {
		ts, id, ok := decodeListStatusCursor(rawCursor)
		if !ok {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		afterTS, afterID, hasCursor = ts, id, true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]listStatusRow, 0)
	for k, blob := range s.blobs {
		parts := strings.SplitN(k, "/", 2)
		if parts[0] != scope {
			continue
		}
		if projectID != "" && (blob.ProjectID == nil || *blob.ProjectID != projectID) {
			continue
		}
		rows = append(rows, listStatusRow{
			ts: blob.UpdatedAt,
			id: parts[1],
			update: &controlplane.BlobMeta{
				ID:        parts[1],
				ETag:      formatETag(blob.ETag),
				KeyID:     blob.KeyID,
				ProjectID: blob.ProjectID,
				UpdatedAt: blob.UpdatedAt,
			},
		})
	}
	// Tombstones carry the deleted row's project_id (production's
	// tombstone-on-delete trigger copies it), so a project-scoped
	// query returns the project's deletes too.
	for k, tombstone := range s.deletes {
		parts := strings.SplitN(k, "/", 2)
		if parts[0] != scope {
			continue
		}
		if projectID != "" && (tombstone.projectID == nil || *tombstone.projectID != projectID) {
			continue
		}
		rows = append(rows, listStatusRow{
			ts: tombstone.deletedAt,
			id: parts[1],
			del: &controlplane.BlobDelete{
				ID:        parts[1],
				Scope:     scope,
				DeletedAt: tombstone.deletedAt,
			},
		})
	}
	sort.Slice(rows, func(i, j int) bool { return listStatusRowLess(rows[i], rows[j]) })
	if direction == "desc" {
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
	}
	if hasCursor {
		cursorRow := listStatusRow{ts: afterTS, id: afterID}
		start := 0
		for start < len(rows) {
			row := rows[start]
			// Skip everything at or before the cursor position in
			// traversal order (strictly-after keyset resume).
			atOrBefore := row.ts.Equal(cursorRow.ts) && row.id == cursorRow.id
			if direction == "desc" {
				atOrBefore = atOrBefore || listStatusRowLess(cursorRow, row)
			} else {
				atOrBefore = atOrBefore || listStatusRowLess(row, cursorRow)
			}
			if !atOrBefore {
				break
			}
			start++
		}
		rows = rows[start:]
	}
	nextCursor := ""
	if len(rows) > limit {
		last := rows[limit-1]
		nextCursor = encodeListStatusCursor(last.ts, last.id)
		rows = rows[:limit]
	}
	updates := []controlplane.BlobMeta{}
	deletes := []controlplane.BlobDelete{}
	for _, row := range rows {
		rowCursor := encodeListStatusCursor(row.ts, row.id)
		if row.update != nil {
			update := *row.update
			update.Cursor = rowCursor
			updates = append(updates, update)
			continue
		}
		del := *row.del
		del.Cursor = rowCursor
		deletes = append(deletes, del)
	}
	_ = json.NewEncoder(w).Encode(controlplane.ListStatusResponse{
		Updates:    updates,
		Deletes:    deletes,
		NextCursor: nextCursor,
	})
}

func (s *StubCP) backupInventory(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]controlplane.BackupInventoryItem, 0, len(s.blobs))
	for key, blob := range s.blobs {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 || parts[0] == "profile" {
			continue
		}
		createdAt := blob.CreatedAt
		if createdAt.IsZero() {
			createdAt = blob.UpdatedAt
		}
		item := controlplane.BackupInventoryItem{
			Scope:     parts[0],
			ID:        parts[1],
			ETag:      formatETag(blob.ETag),
			ProjectID: blob.ProjectID,
			CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
			UpdatedAt: blob.UpdatedAt.UTC().Format(time.RFC3339Nano),
		}
		if parts[0] == "project_document" {
			projectID, documentID, found := strings.Cut(parts[1], "/")
			if found {
				item.ID = documentID
				item.ProjectID = &projectID
			}
		}
		if parts[0] == "project" {
			item.ProjectID = nil
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Scope != items[j].Scope {
			return items[i].Scope < items[j].Scope
		}
		return items[i].ID < items[j].ID
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(controlplane.BackupInventoryResponse{
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		TotalItems: len(items),
		Items:      items,
	})
}

func (s *StubCP) revisionSummary(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(controlplane.RevisionSummaryResponse{
		CurrentRevision:          formatETag(s.sourceRev),
		OldestReplayableRevision: formatETag(s.oldestReplayableRevision),
	})
}

func (s *StubCP) revisionEvents(w http.ResponseWriter, r *http.Request) {
	after, err := strconv.ParseInt(r.URL.Query().Get("after_revision"), 10, 64)
	if err != nil || after < 0 {
		http.Error(w, "invalid after_revision", http.StatusBadRequest)
		return
	}
	through, err := strconv.ParseInt(r.URL.Query().Get("through_revision"), 10, 64)
	if err != nil || through < after {
		http.Error(w, "invalid through_revision", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if after < s.oldestReplayableRevision {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":                       controlplane.StatusSyncSnapshotRequired,
			"message":                    "chat sync snapshot required",
			"current_revision":           formatETag(s.sourceRev),
			"oldest_replayable_revision": formatETag(s.oldestReplayableRevision),
		})
		return
	}
	offset, limit, ok := revisionPage(r)
	if !ok {
		http.Error(w, "invalid pagination", http.StatusBadRequest)
		return
	}
	filtered := make([]controlplane.RevisionEvent, 0)
	for _, event := range s.revisions {
		revision, _ := strconv.ParseInt(event.Revision, 10, 64)
		if revision > after && revision <= through {
			filtered = append(filtered, event)
		}
	}
	// Clamp the offset before adding the limit so a huge cursor value
	// cannot overflow offset+limit into a negative slice bound.
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := min(offset+limit, len(filtered))
	response := controlplane.RevisionEventsResponse{Events: filtered[offset:end]}
	if end < len(filtered) {
		response.NextCursor = strconv.Itoa(end)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *StubCP) revisionSnapshot(w http.ResponseWriter, r *http.Request) {
	afterID, snapshotRevision, limit, ok := revisionSnapshotPage(r)
	if !ok {
		http.Error(w, "invalid pagination", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
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
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	start := sort.Search(len(items), func(i int) bool { return items[i].ID > afterID })
	end := min(start+limit, len(items))
	if snapshotRevision == "" {
		snapshotRevision = formatETag(s.sourceRev)
	}
	response := controlplane.RevisionSnapshotResponse{
		Items:            items[start:end],
		SnapshotRevision: snapshotRevision,
	}
	if end < len(items) {
		response.NextCursor = encodeRevisionSnapshotCursor(items[end-1].ID, snapshotRevision)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

type revisionSnapshotCursor struct {
	AfterID          string `json:"id"`
	SnapshotRevision string `json:"revision"`
}

func revisionSnapshotPage(r *http.Request) (string, string, int, bool) {
	afterID := ""
	snapshotRevision := ""
	if rawCursor := r.URL.Query().Get("cursor"); rawCursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(rawCursor)
		if err != nil {
			return "", "", 0, false
		}
		var cursor revisionSnapshotCursor
		if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.AfterID == "" {
			return "", "", 0, false
		}
		revision, err := strconv.ParseInt(cursor.SnapshotRevision, 10, 64)
		if err != nil || revision < 0 {
			return "", "", 0, false
		}
		afterID = cursor.AfterID
		snapshotRevision = cursor.SnapshotRevision
	}
	limit, ok := revisionLimit(r)
	return afterID, snapshotRevision, limit, ok
}

func encodeRevisionSnapshotCursor(afterID, snapshotRevision string) string {
	raw, _ := json.Marshal(revisionSnapshotCursor{
		AfterID:          afterID,
		SnapshotRevision: snapshotRevision,
	})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func revisionPage(r *http.Request) (int, int, bool) {
	offset := 0
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil || parsed < 0 {
			return 0, 0, false
		}
		offset = parsed
	}
	limit, ok := revisionLimit(r)
	return offset, limit, ok
}

func revisionLimit(r *http.Request) (int, bool) {
	limit := defaultRevisionPageLimit
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 || parsed > maxRevisionPageLimit {
			return 0, false
		}
		limit = parsed
	}
	return limit, true
}

func (s *StubCP) currentSearchIndex() controlplane.SearchIndexState {
	state := s.search
	state.SourceRevision = s.sourceRev
	state.Incomplete = state.PublicationIncomplete || state.PublishedSourceRevision < state.SourceRevision
	return state
}

func (s *StubCP) getSearchIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.currentSearchIndex())
}

func (s *StubCP) publishSearchIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	state := s.currentSearchIndex()
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
	s.search = controlplane.SearchIndexState{
		PublicationGeneration:   state.PublicationGeneration + 1,
		FenceGeneration:         state.FenceGeneration,
		PublishedSourceRevision: req.CoveredSourceRevision,
		ObjectKey:               req.ObjectKey,
		KeyID:                   req.KeyID,
		Model:                   req.Model,
		PublicationIncomplete:   req.Incomplete,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.currentSearchIndex())
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
	s.blobs[key] = &StubBlob{ETag: next, KeyID: req.KeyID, Body: ct, CreatedAt: blob.CreatedAt, UpdatedAt: time.Now().UTC()}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "etag": formatETag(next), "key_id": req.KeyID})
}

func (s *StubCP) getLegacyAttachment(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	aid := r.PathValue("aid")
	body, ok := s.legacyAttachments[aid]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	subject := stubClerkUserIDFromAuth(r.Header.Get("Authorization"))
	claim, err := stubSignLegacyClaim(LocalStackSyncEnclaveSecret, subject, aid, body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(controlplane.HeaderLegacyClaim, claim)
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

// stubClerkUserIDFromAuth pulls the JWT subject out of the bearer token
// the enclave forwards. Real CP runs middleware that validates the JWT
// and populates `userID = clerk.user.id`; the stub is happy to read the
// `sub` claim directly because smoke fixtures mint signed JWTs whose
// subject the test harness already controls.
func stubClerkUserIDFromAuth(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	token := authHeader[len(prefix):]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

func stubSignLegacyClaim(secret, clerkUserID, attID string, ciphertext []byte) (string, error) {
	digest := sha256.Sum256(ciphertext)
	payload, err := json.Marshal(struct {
		ClerkUserID string `json:"clerk_user_id"`
		ID          string `json:"id"`
		Scope       string `json:"scope"`
		SHA256      string `json:"sha256"`
	}{
		ClerkUserID: clerkUserID,
		ID:          attID,
		Scope:       "attachment",
		SHA256:      hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
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
	s.attachmentIndex[aid] = attachmentMeta{
		chatID:      body.ChatID,
		clerkUserID: stubClerkUserIDFromAuth(r.Header.Get("Authorization")),
	}
	delete(s.legacyAttachments, aid)
	delete(s.pendingAttachments, aid)
	w.WriteHeader(http.StatusNoContent)
}

// attachmentOwner answers the enclave's ResolveAttachmentOwner lookup
// so the read path can derive the buckets tenant prefix from a trusted
// source instead of the caller. Service-secret gated like the rest of
// /api/sync/*.
func (s *StubCP) attachmentOwner(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	aid := r.PathValue("aid")
	meta, ok := s.attachmentIndex[aid]
	if !ok || meta.clerkUserID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"clerk_user_id": meta.clerkUserID})
}

func (s *StubCP) reservePendingAttachment(w http.ResponseWriter, r *http.Request) {
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
	if _, exists := s.pendingAttachments[aid]; !exists {
		s.pendingAttachments[aid] = pendingAttachment{
			chatID:      body.ChatID,
			clerkUserID: stubClerkUserIDFromAuth(r.Header.Get("Authorization")),
			createdAt:   time.Now(),
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *StubCP) sweepPendingAttachments(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	now := time.Now()
	type pendingRow struct {
		AttachmentID string `json:"attachment_id"`
		ChatID       string `json:"chat_id"`
		ClerkUserID  string `json:"clerk_user_id"`
	}
	s.mu.Lock()
	rows := make([]pendingRow, 0)
	for aid, pa := range s.pendingAttachments {
		if now.Sub(pa.createdAt) < s.pendingExpiryWindow {
			continue
		}
		rows = append(rows, pendingRow{
			AttachmentID: aid,
			ChatID:       pa.chatID,
			ClerkUserID:  pa.clerkUserID,
		})
		delete(s.pendingAttachments, aid)
		if len(rows) >= limit {
			break
		}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"rows": rows})
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
	previousKID := s.currentKID
	wipedAttachments := []string{}
	if body.CreatedVia == "start_fresh" {
		// Mirror the controlplane's atomic wipe: drop every blob
		// for the user before swapping the primary key, and
		// report every bucket-backed attachment id back to the
		// enclave so its cleanup cascade can drop them too.
		for k, blob := range s.blobs {
			deletedAt := time.Now().UTC()
			delete(s.blobs, k)
			s.deletes[k] = stubDelete{deletedAt: deletedAt, projectID: blob.ProjectID}
			if strings.HasPrefix(k, "chat/") {
				s.sourceRev++
				s.revisions = append(s.revisions, controlplane.RevisionEvent{
					Revision:  formatETag(s.sourceRev),
					Kind:      "delete",
					ID:        strings.TrimPrefix(k, "chat/"),
					UpdatedAt: deletedAt.Format(time.RFC3339Nano),
				})
			}
		}
		s.revisions = nil
		s.oldestReplayableRevision = s.sourceRev
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
	searchIndexFenced := body.CreatedVia == "start_fresh" || (previousKID != "" && previousKID != body.KeyID)
	if searchIndexFenced {
		state := s.currentSearchIndex()
		s.search = controlplane.SearchIndexState{
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
	w.Header().Set("Content-Type", "application/json")
	if searchIndexFenced {
		w.Header().Set(controlplane.HeaderSearchIndexFenced, "true")
	}
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
