package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
)

// MaxRequestBytes caps decoded JSON bodies. Plaintext blobs upload via the
// base64 plaintext field; 64 MiB after base64 expansion is roughly 48 MiB
// of decoded data, which exceeds any reasonable chat or document size.
const MaxRequestBytes = 64 << 20

// AttachmentRequestTimeout is the deadline for attachment + share
// transfers. The default 30s auth timeout is fine for sync blobs but
// can prematurely cancel large bucket uploads/downloads on slow
// network paths; this gives the buckets hop room to breathe while
// still bounding worst-case latency.
const AttachmentRequestTimeout = 5 * time.Minute

type Handler struct {
	deps              Deps
	verifier          auth.Verifier
	logger            Logger
	coordinator       *MigrationCoordinator
	importCoordinator *ImportCoordinator
}

type Logger interface {
	Errorf(format string, args ...any)
	Infof(format string, args ...any)
}

func NewHandler(deps Deps, verifier auth.Verifier, logger Logger) *Handler {
	return &Handler{
		deps:              deps,
		verifier:          verifier,
		logger:            logger,
		coordinator:       NewMigrationCoordinator(),
		importCoordinator: NewImportCoordinator(),
	}
}

// routeSpec ties one HTTP route's wire-level path to the handler
// that serves it. Centralising the routes here lets us derive both
// the mux registration and the canonical path list for shim-config
// drift checks from a single source.
type routeSpec struct {
	method  string
	path    string
	handler func(*Handler) http.Handler
}

func (h *Handler) routeSpecs() []routeSpec {
	return []routeSpec{
		{"POST", "/v1/sync/push", func(h *Handler) http.Handler { return h.authMiddleware(h.push) }},
		{"POST", "/v1/sync/pull", func(h *Handler) http.Handler { return h.authMiddleware(h.pull) }},
		{"POST", "/v1/sync/list-status", func(h *Handler) http.Handler { return h.authMiddleware(h.listStatus) }},
		{"POST", "/v1/sync/delete", func(h *Handler) http.Handler { return h.authMiddleware(h.delete) }},

		{"POST", "/v1/key/register", func(h *Handler) http.Handler { return h.authMiddleware(h.registerKey) }},
		{"POST", "/v1/key/add-bundle", func(h *Handler) http.Handler { return h.authMiddleware(h.addBundle) }},
		{"POST", "/v1/key/remove-bundle", func(h *Handler) http.Handler { return h.authMiddleware(h.removeBundle) }},
		{"POST", "/v1/key/current", func(h *Handler) http.Handler { return h.authMiddleware(h.keyCurrent) }},

		{"POST", "/v1/blobs/migrate", func(h *Handler) http.Handler { return h.authMiddleware(h.migrate) }},
		// Migrate-all kicks off a detached background job and
		// returns immediately so the webapp tab closing mid-call
		// can no longer kill the loop. The handler runs under the
		// regular auth timeout because it only mutates in-memory
		// coordinator state before returning.
		{"POST", "/v1/blobs/migrate-all", func(h *Handler) http.Handler { return h.authMiddleware(h.migrateAll) }},
		{"POST", "/v1/blobs/migrate-status", func(h *Handler) http.Handler { return h.authMiddleware(h.migrateStatus) }},

		{"POST", "/v1/attachment/put", func(h *Handler) http.Handler {
			return h.authMiddlewareWithTimeout(h.attachmentPut, AttachmentRequestTimeout)
		}},
		{"POST", "/v1/attachment/get", func(h *Handler) http.Handler {
			return h.authMiddlewareWithTimeout(h.attachmentGet, AttachmentRequestTimeout)
		}},
		{"POST", "/v1/attachment/delete", func(h *Handler) http.Handler {
			return h.authMiddlewareWithTimeout(h.attachmentDelete, AttachmentRequestTimeout)
		}},
		// /v1/attachment/get-public is intentionally unauthenticated.
		// Knowing the attachment id + per-attachment key is the access
		// proof — the same trust model the legacy public attachment
		// endpoint uses, and the only way share recipients can read v2
		// attachments without holding the owner's JWT. Wrapped in a
		// request timeout so the missing authMiddleware doesn't also
		// drop the per-request deadline.
		{"POST", "/v1/attachment/get-public", func(h *Handler) http.Handler {
			return withRequestTimeout(http.HandlerFunc(h.attachmentGetPublic), AttachmentRequestTimeout)
		}},

		// Off-device chat import. create/start/status only touch
		// in-memory coordinator state and return quickly; upload
		// streams an 8 MiB chunk to the buckets staging area, so it
		// gets the longer attachment-style timeout.
		{"POST", "/v1/import/create", func(h *Handler) http.Handler { return h.authMiddleware(h.importCreate) }},
		{"POST", "/v1/import/upload", func(h *Handler) http.Handler {
			return h.authMiddlewareWithTimeout(h.importUpload, AttachmentRequestTimeout)
		}},
		{"POST", "/v1/import/start", func(h *Handler) http.Handler { return h.authMiddleware(h.importStart) }},
		{"POST", "/v1/import/status", func(h *Handler) http.Handler { return h.authMiddleware(h.importStatus) }},

		{"POST", "/v1/share/seal", func(h *Handler) http.Handler { return h.authMiddleware(h.shareSeal) }},
		// /v1/share/open is intentionally unauthenticated. Knowing the
		// share key in the URL fragment is the access proof — the same
		// trust model the legacy in-browser share path uses today.
		//
		// No context timeout wrapper here: the work is pure in-memory
		// CPU (AES-GCM Open + gzip inflate), neither of which observes
		// context cancellation in Go's stdlib, so a wall-clock deadline
		// would fire without doing anything. DoS protection comes from
		// the bounded input — MaxRequestBytes caps the ciphertext on
		// the wire and shareMaxPlaintextBytes caps the post-decompress
		// plaintext — which makes worst-case work O(MiB), not O(time).
		{"POST", "/v1/share/open", func(h *Handler) http.Handler { return http.HandlerFunc(h.shareOpen) }},

		{"GET", "/v1/health", func(h *Handler) http.Handler { return http.HandlerFunc(h.health) }},
		{"GET", "/health", func(h *Handler) http.Handler { return http.HandlerFunc(h.health) }},
	}
}

// ExternalRoutePaths returns the canonical list of HTTP paths the
// enclave exposes. The Tinfoil CVM shim hard-blocks any path not on
// its allowlist, so this slice must stay in lockstep with
// `tinfoil-config.yml#shim.paths`. The list is derived from the
// same routeSpecs() table that powers Routes(), so adding a handler
// to the mux automatically adds it here — TestShimPathsMatchRoutes
// then forces the YAML to be updated in the same commit.
func ExternalRoutePaths() []string {
	specs := (&Handler{}).routeSpecs()
	seen := make(map[string]struct{}, len(specs))
	paths := make([]string, 0, len(specs))
	for _, s := range specs {
		if _, ok := seen[s.path]; ok {
			continue
		}
		seen[s.path] = struct{}{}
		paths = append(paths, s.path)
	}
	return paths
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	for _, spec := range h.routeSpecs() {
		mux.Handle(spec.method+" "+spec.path, spec.handler(h))
	}
	return h.commonMiddleware(mux)
}

// authMiddleware extracts and verifies the JWT, then attaches a Session to
// the request context. Unauthenticated requests get a uniform 401.
func (h *Handler) authMiddleware(fn func(http.ResponseWriter, *http.Request, Session)) http.Handler {
	return h.authMiddlewareWithTimeout(fn, 30*time.Second)
}

func (h *Handler) authMiddlewareWithTimeout(fn func(http.ResponseWriter, *http.Request, Session), timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := auth.BearerToken(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, unauthorized("missing bearer token"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		claims, err := h.verifier.Verify(ctx, tok)
		if err != nil {
			writeError(w, unauthorized("invalid token"))
			return
		}
		fn(w, r.WithContext(ctx), Session{RawJWT: tok, Claims: claims})
	})
}

// withRequestTimeout attaches a context deadline to the request so
// unauthenticated handlers (which don't run through authMiddleware)
// still get a bounded per-request lifetime.
func withRequestTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// commonMiddleware wraps every request in panic recovery and a request-size
// limit so a malformed body cannot OOM the enclave.
func (h *Handler) commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if h.logger != nil {
					h.logger.Errorf("panic in handler: %v", rec)
				}
				writeError(w, &AppError{Status: http.StatusInternalServerError, Code: CodeInternal, Message: "internal error"})
			}
		}()
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

func decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return badRequest("empty body")
		}
		return badRequest("invalid json: " + err.Error())
	}
	return nil
}

func encode(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) push(w http.ResponseWriter, r *http.Request, sess Session) {
	var req PushRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := Push(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) pull(w http.ResponseWriter, r *http.Request, sess Session) {
	var req PullRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := Pull(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) listStatus(w http.ResponseWriter, r *http.Request, sess Session) {
	var req ListStatusRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := ListStatus(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request, sess Session) {
	var req DeleteRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := Delete(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) registerKey(w http.ResponseWriter, r *http.Request, sess Session) {
	var req KeyRegisterRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := RegisterKey(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) addBundle(w http.ResponseWriter, r *http.Request, sess Session) {
	var req AddBundleRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := AddBundle(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) removeBundle(w http.ResponseWriter, r *http.Request, sess Session) {
	var req RemoveBundleRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := RemoveBundle(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) keyCurrent(w http.ResponseWriter, r *http.Request, sess Session) {
	var req KeyCurrentRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := KeyCurrent(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) migrate(w http.ResponseWriter, r *http.Request, sess Session) {
	var req MigrateRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := Migrate(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) migrateAll(w http.ResponseWriter, r *http.Request, sess Session) {
	var req MigrateAllRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	// Synchronous validation: the kickoff returns 202/200 with an
	// async job id, so anything that would have failed the legacy
	// synchronous handler — empty/malformed keys, wrong key length —
	// has to surface as a 400 here rather than ten seconds later as
	// a "failed" status payload nobody is polling for yet.
	if err := validateMigrateAllRequest(req); err != nil {
		writeError(w, err)
		return
	}

	job, started := h.coordinator.StartOrGet(r.Context(), h.deps, sess, req)
	resp := buildMigrateAllStatusResponse(job)
	status := http.StatusOK
	if started {
		status = http.StatusAccepted
	}
	encode(w, status, resp)
}

func (h *Handler) migrateStatus(w http.ResponseWriter, r *http.Request, sess Session) {
	job := h.coordinator.Status(sess.Claims.Subject)
	if job == nil {
		encode(w, http.StatusOK, MigrateAllStatusResponse{Status: string(MigrationJobIdle)})
		return
	}
	encode(w, http.StatusOK, buildMigrateAllStatusResponse(job))
}

func (h *Handler) attachmentPut(w http.ResponseWriter, r *http.Request, sess Session) {
	var req AttachmentPutRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := AttachmentPut(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) attachmentGet(w http.ResponseWriter, r *http.Request, _ Session) {
	var req AttachmentGetRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := AttachmentGet(r.Context(), h.deps, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) attachmentGetPublic(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	var req AttachmentGetRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := AttachmentGet(r.Context(), h.deps, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) attachmentDelete(w http.ResponseWriter, r *http.Request, sess Session) {
	var req AttachmentDeleteRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := AttachmentDelete(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) importCreate(w http.ResponseWriter, r *http.Request, sess Session) {
	var req ImportCreateRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	job, err := h.importCoordinator.Create(sess.Claims.Subject, req)
	if err != nil {
		writeError(w, err)
		return
	}
	h.importCoordinator.ScheduleStagingCleanup(r.Context(), h.deps, job)
	encode(w, http.StatusOK, ImportCreateResponse{JobID: job.ID, UploadID: job.UploadID})
}

func (h *Handler) importUpload(w http.ResponseWriter, r *http.Request, sess Session) {
	var req ImportUploadRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	job := h.importCoordinator.Get(sess.Claims.Subject)
	if job == nil || job.UploadID != req.UploadID {
		writeError(w, &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "import upload not found"})
		return
	}
	if err := stageImportChunk(r.Context(), h.deps, sess.Claims.Subject, job, req); err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) importStart(w http.ResponseWriter, r *http.Request, sess Session) {
	var req ImportStartRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	job := h.importCoordinator.Get(sess.Claims.Subject)
	if job == nil || job.ID != req.JobID {
		writeError(w, &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "import job not found"})
		return
	}
	if !job.allChunksReceived() {
		writeError(w, badRequest("not all chunks uploaded"))
		return
	}
	cek, err := cekFromImportStart(req)
	if err != nil {
		writeError(w, err)
		return
	}
	if !h.importCoordinator.Start(r.Context(), h.deps, sess, job, cek) {
		snap := job.Snapshot()
		if snap.Status == ImportJobRunning || snap.Status == ImportJobCompleted || snap.Status == ImportJobFailed {
			encode(w, http.StatusAccepted, importStatusResponse(snap))
			return
		}
		writeError(w, &AppError{Status: http.StatusConflict, Code: CodeIdempotencyConflict, Message: "import job is not startable"})
		return
	}
	snap := job.Snapshot()
	encode(w, http.StatusAccepted, importStatusResponse(snap))
}

func (h *Handler) importStatus(w http.ResponseWriter, r *http.Request, sess Session) {
	var req ImportStatusRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.JobID == "" {
		writeError(w, badRequest("job_id is required"))
		return
	}
	job := h.importCoordinator.Get(sess.Claims.Subject)
	if job == nil || job.ID != req.JobID {
		writeError(w, &AppError{Status: http.StatusNotFound, Code: CodeNotFound, Message: "import job not found"})
		return
	}
	encode(w, http.StatusOK, importStatusResponse(job.Snapshot()))
}

func importStatusResponse(snap ImportJobSnapshot) ImportStatusResponse {
	return ImportStatusResponse{
		Status:   string(snap.Status),
		Imported: snap.Imported,
		Failed:   snap.Failed,
		Total:    snap.Total,
		Errors:   snap.Errors,
		JobID:    snap.ID,
	}
}

func (h *Handler) shareSeal(w http.ResponseWriter, r *http.Request, sess Session) {
	var req ShareSealRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := ShareSeal(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) shareOpen(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	var req ShareOpenRequest
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := ShareOpen(r.Context(), h.deps, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	encode(w, http.StatusOK, Health(h.deps))
}
