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
	ChatID    string `json:"chat_id"`
	ProjectID string `json:"project_id,omitempty"`
	KeyID     string `json:"key_id"`
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
	return id != "" && len(id) <= maxRunResourceID && !strings.ContainsAny(id, "/\x00")
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
	key, err := runSigningKey(h.deps.SyncEnclaveSecret)
	if err != nil {
		writeError(w, &AppError{Status: http.StatusServiceUnavailable, Code: CodeInternal, Message: "run credentials are unavailable"})
		return
	}
	defer cryptopkg.Zero(key)
	now := time.Now()
	claims := runCredential{RegisteredClaims: jwt.RegisteredClaims{Issuer: runCredentialIssuer, Subject: sess.Claims.Subject, Audience: jwt.ClaimStrings{runCredentialAudience}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(runCredentialLifetime))}, ChatID: in.ThreadID, ProjectID: in.ProjectID, KeyID: kid}
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
	if err != nil || !parsed.Valid || claims.Subject == "" || !runIDValid(claims.ChatID) || claims.KeyID == "" {
		return Session{}, errors.New("invalid run credential")
	}
	return Session{Claims: auth.Claims{Subject: claims.Subject, ExpiresAt: claims.ExpiresAt.Time}, Run: &claims}, nil
}

func runRouteAllowed(path string) bool {
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
	if req.All || len(req.IDs) == 0 || len(req.Keys) == 0 {
		return false
	}
	for _, key := range req.Keys {
		if !grant.keyMatches(key.Key) {
			return false
		}
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
			if grant.ProjectID == "" || !strings.HasPrefix(id, grant.ProjectID+"/") {
				return false
			}
		default:
			return false
		}
	}
	return true
}
