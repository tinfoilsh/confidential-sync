package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

// TestPushReportsServerKeyedAttachmentRefs: every chat push carries the
// exact set of buckets-backed attachment ids the plaintext references,
// de-duplicated, excluding attachments that have never been uploaded
// (no server key). Non-chat scopes never send the header.
func TestPushReportsServerKeyedAttachmentRefs(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()

	var captured []string
	var seen bool
	f.cp.captureHeaders = func(r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasPrefix(r.URL.Path, "/api/sync/blob/chat/") {
			return
		}
		f.cp.mu.Lock()
		defer f.cp.mu.Unlock()
		raw, present := r.Header[controlplane.HeaderAttachmentRefs]
		seen = present
		if present && raw[0] != "" {
			captured = strings.Split(raw[0], ",")
		} else {
			captured = []string{}
		}
	}

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	chat := map[string]any{
		"id": "chat-refs", "title": "Refs", "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z",
		"messages": []any{
			map[string]any{"role": "user", "content": "a", "timestamp": "2026-01-01T00:00:00.000Z", "attachments": []any{
				map[string]any{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "type": "image", "fileName": "a.png", "encryptionKey": key},
				map[string]any{"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "type": "document", "fileName": "b.pdf", "key": key},
				map[string]any{"id": "local-only", "type": "image", "fileName": "c.png", "base64": "AQID"},
			}},
			map[string]any{"role": "assistant", "content": "b", "timestamp": "2026-01-01T00:00:01.000Z", "attachments": []any{
				map[string]any{"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "type": "image", "fileName": "a.png", "encryptionKey": key},
			}},
		},
	}
	plaintext, _ := json.Marshal(chat)
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "chat-refs", Key: f.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext), IdempotencyKey: "idem-refs",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: %d %s", resp.StatusCode, body)
	}
	if !seen {
		t.Fatal("chat push did not send X-Attachment-Refs")
	}
	want := []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	if strings.Join(captured, ",") != strings.Join(want, ",") {
		t.Fatalf("refs = %v, want %v", captured, want)
	}

	// A chat with no uploaded attachments still sends the header, empty:
	// that is what tells the controlplane every blob under it is dead.
	seen, captured = false, nil
	empty, _ := json.Marshal(map[string]any{"id": "chat-empty", "messages": []any{}})
	resp, body = f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "chat-empty", Key: f.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString(empty), IdempotencyKey: "idem-empty",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty push: %d %s", resp.StatusCode, body)
	}
	if !seen || len(captured) != 0 {
		t.Fatalf("empty chat: seen=%v refs=%v", seen, captured)
	}

	// Profile scope: no header.
	seen = false
	f.cp.captureHeaders = func(r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/sync/blob/profile") {
			_, seen = r.Header[controlplane.HeaderAttachmentRefs]
		}
	}
	resp, body = f.post("/v1/sync/push", PushRequest{
		Scope: "profile", ID: "profile", Key: f.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString([]byte(`{"settings":{}}`)), IdempotencyKey: "idem-profile",
		Metadata: map[string]any{"profileSyncProtocol": 2},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("profile push: %d %s", resp.StatusCode, body)
	}
	if seen {
		t.Fatal("profile push must not send X-Attachment-Refs")
	}
}

// TestPushSurfacesMissingAttachment: the controlplane's MISSING_ATTACHMENT
// rejection reaches the client as a 409 with the ids to re-upload.
func TestPushSurfacesMissingAttachment(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/sync/blob/chat/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":               "chat references attachments the server does not hold",
				"code":                controlplane.StatusMissingAttachment,
				"missing_attachments": []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			})
			return
		}
		f.cp.server.Config.Handler.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	f.handler.deps.Controlplane = controlplane.NewClient(proxy.URL, nil)

	plaintext, _ := json.Marshal(map[string]any{"id": "chat-missing", "messages": []any{}})
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "chat-missing", Key: f.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext), IdempotencyKey: "idem-missing",
	}, tok)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	var out AppError
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Code != CodeMissingAttachment || len(out.MissingAttachments) != 1 || out.MissingAttachments[0] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("unexpected error: %+v", out)
	}
}

// TestAttachmentPurgeSweepDeletesThenAcks: the worker asks the
// controlplane to queue aged rows, claims, deletes the bucket object,
// and acks only what it deleted. A failed delete is left queued.
func TestAttachmentPurgeSweepDeletesThenAcks(t *testing.T) {
	f := newFixture(t)
	tenant, err := buckets.TenantForUser(f.userSub)
	if err != nil {
		t.Fatal(err)
	}
	const okID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const failID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	f.bk.items.Put(okID, bucketsItem{Tenant: tenant, Value: []byte("x"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)}})
	f.bk.items.Put(failID, bucketsItem{Tenant: tenant, Value: []byte("y"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{2}, 32)}})
	f.cp.mu.Lock()
	f.cp.purgeQueue = map[string]controlplane.AttachmentPurge{
		okID:   {AttachmentID: okID, ClerkUserID: f.userSub, ChatID: "chat-1"},
		failID: {AttachmentID: failID, ClerkUserID: f.userSub, ChatID: "chat-1"},
	}
	f.cp.mu.Unlock()

	// The bucket stub resolves the object key from the mux pattern, so
	// the failure injector must sit in front of a mux that routes the
	// same way the fixture's server does.
	passthrough := http.NewServeMux()
	passthrough.HandleFunc("/"+testBucketName+"/{key}", f.bk.items.Handle)
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, failID) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		passthrough.ServeHTTP(w, r)
	}))
	defer failing.Close()
	f.handler.deps.Buckets = buckets.NewClient(failing.URL, testBucketName, nil)

	deleted, sweepErr := sweepAttachmentPurges(t.Context(), f.handler.deps)
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1 (err %v)", deleted, sweepErr)
	}
	if sweepErr == nil {
		t.Fatal("expected the failed bucket delete to be reported")
	}
	if f.bk.items.Has(okID) {
		t.Fatal("acked attachment still in buckets")
	}
	if !f.bk.items.Has(failID) {
		t.Fatal("failed delete must leave the object")
	}
	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	if f.cp.purgeRequests != 1 {
		t.Fatalf("purge requests = %d", f.cp.purgeRequests)
	}
	if _, stillQueued := f.cp.purgeQueue[okID]; stillQueued {
		t.Fatal("acked purge still queued")
	}
	if _, stillQueued := f.cp.purgeQueue[failID]; !stillQueued {
		t.Fatal("failed purge must stay queued for the next sweep")
	}
}
