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

// attachmentRequestTimeout is the deadline for attachment + share
// transfers. The default 30s auth timeout is fine for sync blobs but
// can prematurely cancel large bucket uploads/downloads on slow
// network paths; this gives the buckets hop room to breathe while
// still bounding worst-case latency.
const attachmentRequestTimeout = 5 * time.Minute

type Handler struct {
	deps     Deps
	verifier auth.Verifier
	logger   Logger
}

type Logger interface {
	Errorf(format string, args ...any)
	Infof(format string, args ...any)
}

func NewHandler(deps Deps, verifier auth.Verifier, logger Logger) *Handler {
	return &Handler{deps: deps, verifier: verifier, logger: logger}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("POST /v1/sync/push", h.authMiddleware(h.push))
	mux.Handle("POST /v1/sync/pull", h.authMiddleware(h.pull))
	mux.Handle("POST /v1/sync/list-status", h.authMiddleware(h.listStatus))
	mux.Handle("POST /v1/sync/delete", h.authMiddleware(h.delete))

	mux.Handle("POST /v1/key/register", h.authMiddleware(h.registerKey))
	mux.Handle("POST /v1/key/add-bundle", h.authMiddleware(h.addBundle))
	mux.Handle("POST /v1/key/remove-bundle", h.authMiddleware(h.removeBundle))
	mux.Handle("POST /v1/key/current", h.authMiddleware(h.keyCurrent))

	mux.Handle("POST /v1/blobs/migrate", h.authMiddleware(h.migrate))
	mux.Handle("POST /v1/blobs/migrate-all", h.authMiddlewareWithTimeout(h.migrateAll, MigrateAllBudget+time.Minute))

	mux.Handle("POST /v1/attachment/put", h.authMiddlewareWithTimeout(h.attachmentPut, attachmentRequestTimeout))
	mux.Handle("POST /v1/attachment/get", h.authMiddlewareWithTimeout(h.attachmentGet, attachmentRequestTimeout))
	// /v1/attachment/get-public is intentionally unauthenticated.
	// Knowing the attachment id + per-attachment key is the access
	// proof — the same trust model the legacy public attachment
	// endpoint uses, and the only way share recipients can read v2
	// attachments without holding the owner's JWT. Wrapped in a
	// request timeout so the missing authMiddleware doesn't also
	// drop the per-request deadline.
	mux.Handle("POST /v1/attachment/get-public", withRequestTimeout(http.HandlerFunc(h.attachmentGetPublic), attachmentRequestTimeout))

	mux.Handle("POST /v1/share/seal", h.authMiddleware(h.shareSeal))
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
	mux.Handle("POST /v1/share/open", http.HandlerFunc(h.shareOpen))

	mux.HandleFunc("GET /v1/health", h.health)
	mux.HandleFunc("GET /health", h.health)

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
	resp, err := MigrateAll(r.Context(), h.deps, sess, req)
	if err != nil {
		writeError(w, err)
		return
	}
	encode(w, http.StatusOK, resp)
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
