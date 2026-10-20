package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/auth"
)

func TestRunCredentialSavesAfterClerkExpiresAndCannotEscapeItsChat(t *testing.T) {
	f := newFixture(t)
	f.handler.deps.SyncEnclaveSecret = "test-run-credential-secret"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{f.issuer + "/.well-known/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	f.handler.verifier, err = auth.NewVerifierWithKeyfunc(auth.Config{Issuer: f.issuer, Clock: func() time.Time { return time.Unix(clock.Load(), 0) }}, kf)
	if err != nil {
		t.Fatal(err)
	}
	clerk := f.jwt()
	response, body := f.post("/v1/runs/authorize", authorizeRunRequest{ThreadID: "target", ProjectID: "project", Key: f.userKeyB64}, clerk)
	var granted struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &granted) != nil || !strings.HasPrefix(granted.Token, runCredentialPrefix) || response.Header.Get("Cache-Control") != "no-store" || time.Until(granted.ExpiresAt) > runCredentialLifetime {
		t.Fatalf("grant: %d %s", response.StatusCode, body)
	}
	clock.Add(int64((10 * time.Minute) / time.Second))
	// The capability works on another instance with the same signing secret.
	other := httptest.NewServer(NewHandler(f.handler.deps, f.handler.verifier).Routes())
	t.Cleanup(other.Close)
	f.server = other
	plaintext := `{"id":"target","messages":[{"role":"assistant","content":"Finished after login expiry","createdAt":"2026-10-20T01:00:00Z"}]}`
	push := PushRequest{Scope: "chat", ID: "target", Key: f.userKeyB64, Plaintext: base64.StdEncoding.EncodeToString([]byte(plaintext)), IdempotencyKey: "save"}
	if response, _ := f.post("/v1/sync/push", push, clerk); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("expired Clerk token still authorizes storage")
	}
	response, body = f.post("/v1/sync/push", push, granted.Token)
	if response.StatusCode != 200 {
		t.Fatalf("delegated save: %d %s", response.StatusCode, body)
	}
	response, body = f.post("/v1/sync/pull", PullRequest{Scope: "chat", IDs: []string{"target"}, Keys: []PullKey{{Key: f.userKeyB64}}}, granted.Token)
	var pulled PullResponse
	if response.StatusCode != 200 || json.Unmarshal(body, &pulled) != nil || len(pulled.Items) != 1 || !pulled.Items[0].OK || pulled.Items[0].Plaintext != push.Plaintext {
		t.Fatalf("saved reply: %d %s", response.StatusCode, body)
	}
	for _, tc := range []struct {
		path string
		body any
	}{
		{"/v1/sync/push", PushRequest{Scope: "chat", ID: "other", Key: f.userKeyB64, Plaintext: push.Plaintext}},
		{"/v1/sync/push", PushRequest{Scope: "profile", ID: "profile", Key: f.userKeyB64, Plaintext: push.Plaintext}},
		{"/v1/sync/push", PushRequest{Scope: "chat", ID: "target", Key: base64.StdEncoding.EncodeToString(make([]byte, 32)), Plaintext: push.Plaintext}},
		{"/v1/sync/pull", PullRequest{Scope: "chat", IDs: []string{"other"}, Keys: []PullKey{{Key: f.userKeyB64}}}},
		{"/v1/sync/pull", PullRequest{Scope: "chat", All: true, Keys: []PullKey{{Key: f.userKeyB64}}}},
		{"/v1/sync/pull", PullRequest{Scope: "project_document", IDs: []string{"other/doc"}, Keys: []PullKey{{Key: f.userKeyB64}}}},
		{"/v1/sync/list-status", ListStatusRequest{Scope: "chat"}},
		{"/v1/attachment/put", AttachmentPutRequest{ChatID: "other", Plaintext: "aW1hZ2U=", IdempotencyKey: "other"}},
		{"/v1/sync/delete", DeleteRequest{Scope: "chat", ID: "target", Key: f.userKeyB64}},
		{"/v1/key/current", map[string]any{}},
		{"/v1/import/create", map[string]any{}},
		{"/v1/runs/authorize", authorizeRunRequest{ThreadID: "other", Key: f.userKeyB64}},
	} {
		response, body := f.post(tc.path, tc.body, granted.Token)
		if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
			t.Errorf("grant escaped at %s: %d %s", tc.path, response.StatusCode, body)
		}
	}
	// The denied delete must leave the saved reply intact.
	_, body = f.post("/v1/sync/pull", PullRequest{Scope: "chat", IDs: []string{"target"}, Keys: []PullKey{{Key: f.userKeyB64}}}, granted.Token)
	json.Unmarshal(body, &pulled)
	if len(pulled.Items) != 1 || !pulled.Items[0].OK || pulled.Items[0].Plaintext != push.Plaintext {
		t.Fatalf("denied operations changed the chat: %s", body)
	}
}

func TestRunCredentialRequiresItsSignatureAudienceAndExpiry(t *testing.T) {
	f := newFixture(t)
	secret := "test-run-credential-secret"
	f.handler.deps.SyncEnclaveSecret = secret
	key, err := runSigningKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	base := runCredential{RegisteredClaims: jwt.RegisteredClaims{Issuer: runCredentialIssuer, Subject: f.userSub, Audience: jwt.ClaimStrings{runCredentialAudience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, ChatID: "target", KeyID: f.userKeyID}
	for _, variant := range []string{"wrong-key", "expired", "wrong-audience", "wrong-algorithm", "missing-expiry", "wrong-issuer", "empty-subject"} {
		claims := base
		method := jwt.SigningMethodHS256
		signingKey := key
		switch variant {
		case "wrong-key":
			signingKey = []byte(secret)
		case "expired":
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		case "wrong-audience":
			claims.Audience = jwt.ClaimStrings{"other"}
		case "wrong-algorithm":
			method = jwt.SigningMethodHS512
		case "missing-expiry":
			claims.ExpiresAt = nil
		case "wrong-issuer":
			claims.Issuer = "other"
		case "empty-subject":
			claims.Subject = ""
		}
		token, err := jwt.NewWithClaims(method, claims).SignedString(signingKey)
		if err != nil {
			t.Fatal(err)
		}
		response, body := f.post("/v1/sync/pull", PullRequest{Scope: "chat", IDs: []string{"target"}, Keys: []PullKey{{Key: f.userKeyB64}}}, runCredentialPrefix+token)
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", variant, response.StatusCode, body)
		}
	}
}
