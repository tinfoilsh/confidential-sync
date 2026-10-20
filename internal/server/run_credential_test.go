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

func TestArchiveCredentialsSeparateReadsFromImportWrites(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	f.handler.deps.SyncEnclaveSecret = "test-archive-credential-secret"
	clerk := f.jwt()
	plain := []byte(`{"id":"existing","title":"Keep this","messages":[]}`)
	response, body := f.post("/v1/sync/push", PushRequest{Scope: "chat", ID: "existing", Key: f.userKeyB64, Plaintext: base64.StdEncoding.EncodeToString(plain), IdempotencyKey: "existing"}, clerk)
	if response.StatusCode != 200 {
		t.Fatalf("seed: %d %s", response.StatusCode, body)
	}
	grant := func(operation string) string {
		t.Helper()
		response, body := f.post("/v1/operations/authorize", operationCredentialRequest{Operation: operation, Key: f.userKeyB64}, clerk)
		var value struct {
			Token string `json:"token"`
		}
		if response.StatusCode != 200 || json.Unmarshal(body, &value) != nil || value.Token == "" {
			t.Fatalf("%s grant: %d %s", operation, response.StatusCode, body)
		}
		return value.Token
	}
	export, imported := grant("export"), grant("import")
	read := PullRequest{Scope: "chat", IDs: []string{"existing"}, Keys: []PullKey{{Key: f.userKeyB64}}}
	response, body = f.post("/v1/sync/pull", read, export)
	var rows PullResponse
	if response.StatusCode != 200 || json.Unmarshal(body, &rows) != nil || len(rows.Items) != 1 || rows.Items[0].Plaintext != base64.StdEncoding.EncodeToString(plain) {
		t.Fatalf("export read: %d %s", response.StatusCode, body)
	}
	for _, tc := range []struct {
		token, path string
		body        any
	}{
		{export, "/v1/sync/push", PushRequest{Scope: "chat", ID: "other", Key: f.userKeyB64, Plaintext: base64.StdEncoding.EncodeToString(plain), IdempotencyKey: "forbidden"}},
		{export, "/v1/import/create", map[string]any{}},
		{imported, "/v1/sync/pull", read},
		{imported, "/v1/sync/push", PushRequest{Scope: "chat", ID: "other", Key: f.userKeyB64, Plaintext: base64.StdEncoding.EncodeToString(plain), IdempotencyKey: "forbidden"}},
		{imported, "/v1/key/current", map[string]any{}},
		{imported, "/v1/operations/authorize", operationCredentialRequest{Operation: "export", Key: f.userKeyB64}},
	} {
		if response, body := f.post(tc.path, tc.body, tc.token); response.StatusCode != http.StatusUnauthorized {
			t.Errorf("scope escaped: %s %d %s", tc.path, response.StatusCode, body)
		}
	}
	archive := nativeTestArchive(t, "delegated", []nativeTestEntity{{kind: "chat", sourceID: "source", path: "entities/chat.json", payload: []byte(`{"title":"Imported with scoped access","messages":[{"role":"user","content":"Archive content","timestamp":"2026-01-01T00:00:00Z"}],"createdAt":"2026-01-01T00:00:00Z","isLocalOnly":false}`)}}, nil, nil)
	response, body = f.post("/v1/import/create", ImportCreateRequest{Source: "tinfoil_backup", TotalBytes: int64(len(archive)), TotalChunks: 1, ArchiveSHA256: hashOf(archive)}, imported)
	var created ImportCreateResponse
	if response.StatusCode != 200 || json.Unmarshal(body, &created) != nil || created.JobID == "" {
		t.Fatalf("create: %d %s", response.StatusCode, body)
	}
	response, body = f.post("/v1/import/upload", ImportUploadRequest{UploadID: created.UploadID, ChunkIndex: 0, ChunkSHA256: hashOf(archive), Data: base64.StdEncoding.EncodeToString(archive)}, imported)
	if response.StatusCode != 200 {
		t.Fatalf("upload: %d %s", response.StatusCode, body)
	}
	response, body = f.post("/v1/import/start", ImportStartRequest{JobID: created.JobID, Key: base64.StdEncoding.EncodeToString(make([]byte, 32))}, imported)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong key: %d %s", response.StatusCode, body)
	}
	response, body = f.post("/v1/import/start", ImportStartRequest{JobID: created.JobID, Key: f.userKeyB64}, imported)
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("start: %d %s", response.StatusCode, body)
	}
	job := f.handler.importCoordinator.Get(f.userSub)
	select {
	case <-job.done:
	case <-time.After(5 * time.Second):
		t.Fatal("import did not finish")
	}
	if snapshot := job.Snapshot(); snapshot.Imported != 1 || snapshot.Failed != 0 {
		t.Fatalf("import result: %+v", snapshot)
	}
}

func TestProjectUploadCredentialCanOnlyAddDocumentsToItsProject(t *testing.T) {
	f := newFixture(t)
	f.handler.deps.SyncEnclaveSecret = "test-project-upload-secret"
	if response, body := f.post("/v1/sync/push", PushRequest{Scope: "project", ID: "project", Key: f.userKeyB64, Plaintext: base64.StdEncoding.EncodeToString([]byte(`{"name":"House"}`)), IdempotencyKey: "seed-project"}, f.jwt()); response.StatusCode != 200 {
		t.Fatalf("project: %d %s", response.StatusCode, body)
	}
	response, body := f.post("/v1/operations/authorize", operationCredentialRequest{Operation: "project-upload", ProjectID: "project", Key: f.userKeyB64}, f.jwt())
	var grant struct {
		Token string `json:"token"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &grant) != nil || grant.Token == "" {
		t.Fatalf("grant: %d %s", response.StatusCode, body)
	}
	data := base64.StdEncoding.EncodeToString([]byte(`{"projectId":"project","filename":"photo.png","content":"Image description"}`))
	request := PushRequest{Scope: "project_document", ID: "project/doc", Key: f.userKeyB64, Plaintext: data, IdempotencyKey: "new-document", Metadata: map[string]any{"projectId": "project"}}
	response, body = f.post("/v1/sync/push", request, grant.Token)
	if response.StatusCode != 200 {
		t.Fatalf("save document: %d %s", response.StatusCode, body)
	}
	var saved PushResponse
	json.Unmarshal(body, &saved)
	for _, change := range []func(*PushRequest){
		func(r *PushRequest) { r.ID = "other/doc" },
		func(r *PushRequest) { r.ID = "project/../other/doc" },
		func(r *PushRequest) { r.ID = "project/.." },
		func(r *PushRequest) { r.Scope = "chat" },
		func(r *PushRequest) { r.IfMatch = &saved.ETag },
		func(r *PushRequest) { r.Metadata = map[string]any{"projectId": "other"} },
	} {
		modified := request
		change(&modified)
		if response, body := f.post("/v1/sync/push", modified, grant.Token); response.StatusCode != http.StatusForbidden {
			t.Errorf("scope escaped: %d %s", response.StatusCode, body)
		}
	}
	response, body = f.post("/v1/sync/pull", PullRequest{Scope: "project_document", IDs: []string{"project/doc"}, Keys: []PullKey{{Key: f.userKeyB64}}}, grant.Token)
	var pulled PullResponse
	if response.StatusCode != 200 || json.Unmarshal(body, &pulled) != nil || len(pulled.Items) != 1 || !pulled.Items[0].OK || pulled.Items[0].Plaintext != data {
		t.Fatalf("document was changed: %d %s", response.StatusCode, body)
	}
}
