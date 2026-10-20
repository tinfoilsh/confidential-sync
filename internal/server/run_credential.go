package server

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
	cryptopkg "github.com/tinfoilsh/confidential-sync-enclave/internal/crypto"
)

const (
	runCredentialPrefix     = "sync_run_"
	runCredentialIssuer     = "tinfoil-sync"
	runCredentialAudience   = "chat-run"
	runCredentialKeyPurpose = "tinfoil-sync/run-credential/v1"
	runCredentialLifetime   = time.Hour
	maxRunResourceID        = 256
)

type runCredential struct {
	jwt.RegisteredClaims
	Operation string `json:"operation,omitempty"`
	ChatID    string `json:"chat_id"`
	ProjectID string `json:"project_id,omitempty"`
	KeyID     string `json:"key_id"`
}

type operationCredentialRequest struct {
	Operation string `json:"operation"`
	Key       string `json:"key"`
	ProjectID string `json:"project_id,omitempty"`
}

func (h *Handler) authorizeOperation(w http.ResponseWriter, r *http.Request, sess Session) {
	var in operationCredentialRequest
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if in.Operation != "import" && in.Operation != "export" && in.Operation != "project-upload" {
		writeError(w, badRequest("invalid storage operation"))
		return
	}
	if in.Operation == "project-upload" && !runIDValid(in.ProjectID) {
		writeError(w, badRequest("invalid project id"))
		return
	}
	kid, err := runKeyID(in.Key)
	if err != nil {
		writeError(w, err)
		return
	}
	h.writeStorageCredential(w, runCredential{RegisteredClaims: jwt.RegisteredClaims{Subject: sess.Claims.Subject}, Operation: in.Operation, ProjectID: in.ProjectID, KeyID: kid})
}

type authorizeRunRequest struct {
	ThreadID  string `json:"thread_id"`
	ProjectID string `json:"project_id,omitempty"`
	Key       string `json:"key"`
}

func runSigningKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("run credentials are not configured")
	}
	return hkdf.Key(sha256.New, []byte(secret), nil, runCredentialKeyPurpose, sha256.Size)
}

func runKeyID(encoded string) (string, error) {
	key, err := decodeKey(encoded)
	if err != nil {
		return "", badRequest("invalid key")
	}
	defer cryptopkg.Zero(key)
	id, err := cryptopkg.DeriveKeyID(key)
	return cryptopkg.KeyIDHex(id), err
}

func runIDValid(id string) bool {
	return id != "" && id != "." && id != ".." && len(id) <= maxRunResourceID && !strings.ContainsAny(id, "/\x00")
}

func (grant *runCredential) ownsDocument(id string) bool {
	if grant.ProjectID == "" {
		return false
	}
	document, ok := strings.CutPrefix(id, grant.ProjectID+"/")
	return ok && runIDValid(document)
}

func (h *Handler) authorizeRun(w http.ResponseWriter, r *http.Request, sess Session) {
	var in authorizeRunRequest
	if err := decode(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if !runIDValid(in.ThreadID) || in.ProjectID != "" && !runIDValid(in.ProjectID) {
		writeError(w, badRequest("invalid chat or project id"))
		return
	}
	kid, err := runKeyID(in.Key)
	if err != nil {
		writeError(w, err)
		return
	}
	// Existing chats determine their own project, including a move that only
	// changed storage metadata. A new chat names its initial project.
	pulled, err := Pull(r.Context(), h.deps, sess, PullRequest{Scope: "chat", IDs: []string{in.ThreadID}, Keys: []PullKey{{Key: in.Key}}})
	if err != nil {
		writeError(w, err)
		return
	}
	for _, item := range pulled.Items {
		if !item.OK {
			if item.Code != CodeNotFound {
				writeError(w, &AppError{Status: http.StatusConflict, Code: item.Code, Message: "chat cannot be opened"})
				return
			}
			continue
		}
		if item.ProjectIDSet {
			in.ProjectID = ""
			if item.ProjectID != nil {
				in.ProjectID = *item.ProjectID
			}
		} else {
			plain, decodeErr := base64.StdEncoding.DecodeString(item.Plaintext)
			if decodeErr != nil {
				writeError(w, badRequest("invalid chat"))
				return
			}
			var chat struct {
				ProjectID string `json:"projectId"`
			}
			decodeErr = json.Unmarshal(plain, &chat)
			cryptopkg.Zero(plain)
			if decodeErr != nil {
				writeError(w, badRequest("invalid chat"))
				return
			}
			in.ProjectID = chat.ProjectID
		}
	}
	if in.ProjectID != "" && !runIDValid(in.ProjectID) {
		writeError(w, badRequest("invalid project id"))
		return
	}
	h.writeStorageCredential(w, runCredential{RegisteredClaims: jwt.RegisteredClaims{Subject: sess.Claims.Subject}, ChatID: in.ThreadID, ProjectID: in.ProjectID, KeyID: kid})
}

func (h *Handler) writeStorageCredential(w http.ResponseWriter, claims runCredential) {
	key, err := runSigningKey(h.deps.SyncEnclaveSecret)
	if err != nil {
		writeError(w, &AppError{Status: http.StatusServiceUnavailable, Code: CodeInternal, Message: "run credentials are unavailable"})
		return
	}
	defer cryptopkg.Zero(key)
	now := time.Now()
	claims.Issuer, claims.Audience = runCredentialIssuer, jwt.ClaimStrings{runCredentialAudience}
	claims.IssuedAt, claims.ExpiresAt = jwt.NewNumericDate(now), jwt.NewNumericDate(now.Add(runCredentialLifetime))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	encode(w, http.StatusOK, struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{runCredentialPrefix + token, claims.ExpiresAt.Time})
}

func (h *Handler) verifyRunCredential(token string) (Session, error) {
	key, err := runSigningKey(h.deps.SyncEnclaveSecret)
	if err != nil {
		return Session{}, err
	}
	defer cryptopkg.Zero(key)
	var claims runCredential
	parsed, err := jwt.ParseWithClaims(strings.TrimPrefix(token, runCredentialPrefix), &claims, func(*jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(runCredentialIssuer), jwt.WithAudience(runCredentialAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(auth.ClockSkewLeeway))
	validScope := claims.Operation == "" && runIDValid(claims.ChatID) || claims.Operation == "import" || claims.Operation == "export" || claims.Operation == "project-upload" && runIDValid(claims.ProjectID)
	if err != nil || !parsed.Valid || claims.Subject == "" || !validScope || claims.KeyID == "" {
		return Session{}, errors.New("invalid run credential")
	}
	return Session{Claims: auth.Claims{Subject: claims.Subject, ExpiresAt: claims.ExpiresAt.Time}, Run: &claims}, nil
}

func (grant *runCredential) routeAllowed(path string) bool {
	if grant.Operation == "project-upload" {
		return path == "/v1/sync/pull" || path == "/v1/sync/push"
	}
	if grant.Operation == "import" {
		return path == "/v1/import/create" || path == "/v1/import/upload" || path == "/v1/import/start" || path == "/v1/import/status"
	}
	if grant.Operation == "export" {
		return path == "/v1/sync/pull" || path == "/v1/sync/list-status" || path == "/v1/attachment/get"
	}
	switch path {
	case "/v1/sync/push", "/v1/sync/pull", "/v1/sync/list-status", "/v1/attachment/put", "/v1/attachment/get":
		return true
	}
	return false
}

func runScopeRefused() error {
	return &AppError{Status: http.StatusForbidden, Code: "RUN_SCOPE_REFUSED", Message: "operation is outside this run's storage scope"}
}

func (grant *runCredential) keyMatches(key string) bool {
	id, err := runKeyID(key)
	return err == nil && id == grant.KeyID
}

func (grant *runCredential) permitsPull(req PullRequest) bool {
	if len(req.Keys) == 0 {
		return false
	}
	for _, key := range req.Keys {
		if !grant.keyMatches(key.Key) {
			return false
		}
	}
	if grant.Operation == "export" {
		return req.Scope == "chat" || req.Scope == "profile" || req.Scope == "project" || req.Scope == "project_document"
	}
	if req.All || len(req.IDs) == 0 {
		return false
	}
	if grant.Operation == "project-upload" {
		for _, id := range req.IDs {
			if req.Scope == "project" && id == grant.ProjectID {
				continue
			}
			if req.Scope == "project_document" && grant.ownsDocument(id) {
				continue
			}
			return false
		}
		return true
	}
	for _, id := range req.IDs {
		switch req.Scope {
		case "chat":
			if id != grant.ChatID {
				return false
			}
		case "profile":
			if id != "profile" {
				return false
			}
		case "project":
			if grant.ProjectID == "" || id != grant.ProjectID {
				return false
			}
		case "project_document":
			if !grant.ownsDocument(id) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (grant *runCredential) permitsPush(req PushRequest) bool {
	if !grant.keyMatches(req.Key) {
		return false
	}
	if grant.Operation == "project-upload" {
		return req.Scope == "project_document" && grant.ownsDocument(req.ID) && req.IfMatch == nil && req.Metadata["projectId"] == grant.ProjectID
	}
	// The grant owns the chat, including its metadata. ProjectID limits
	// context reads; the user can move the chat while a reply is running.
	return grant.Operation == "" && req.Scope == "chat" && req.ID == grant.ChatID
}
