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

	mux.Handle("POST /v1/blobs/migrate", h.authMiddleware(h.migrate))
	mux.Handle("POST /v1/blobs/migrate-all", h.authMiddleware(h.migrateAll))

	mux.HandleFunc("GET /v1/health", h.health)
	mux.HandleFunc("GET /health", h.health)

	return h.commonMiddleware(mux)
}

// authMiddleware extracts and verifies the JWT, then attaches a Session to
// the request context. Unauthenticated requests get a uniform 401.
func (h *Handler) authMiddleware(fn func(http.ResponseWriter, *http.Request, Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := auth.BearerToken(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, unauthorized("missing bearer token"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		claims, err := h.verifier.Verify(ctx, tok)
		if err != nil {
			writeError(w, unauthorized("invalid token"))
			return
		}
		fn(w, r.WithContext(ctx), Session{RawJWT: tok, Claims: claims})
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

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	encode(w, http.StatusOK, Health(h.deps))
}
