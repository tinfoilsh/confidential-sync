package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

func TestAttachmentGCRetriesPreserveUnreferencedStorage(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	const chatID = "gc-pending-chat"
	seedForkSource(t, f, tok, chatID)
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tenant, err := buckets.TenantForUser(f.userSub)
	if err != nil {
		t.Fatal(err)
	}
	f.cp.mu.Lock()
	f.cp.attachmentIndex[id] = chatID
	f.cp.mu.Unlock()
	f.bk.items.Put(id, bucketsItem{Tenant: tenant, Value: []byte("pending upload"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)}})
	var bucketDeletes atomic.Int32
	failingBuckets := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			bucketDeletes.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		f.bk.items.Handle(w, r)
	}))
	defer failingBuckets.Close()
	f.handler.deps.Buckets = buckets.NewClient(failingBuckets.URL, testBucketName, nil)
	for range 2 {
		resp, body := f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: chatID, Key: f.userKeyB64}, tok)
		f.cp.mu.Lock()
		indexed := f.cp.attachmentIndex[id] == chatID
		f.cp.mu.Unlock()
		if !indexed || !f.bk.has(id) {
			t.Fatalf("GC lost pending storage: indexed=%v bucket=%v (response %d %s)", indexed, f.bk.has(id), resp.StatusCode, body)
		}
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("GC must report disabled: %d %s", resp.StatusCode, body)
		}
	}
	if bucketDeletes.Load() != 0 {
		t.Fatal("disabled GC attempted a bucket delete")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AttachmentGC(ctx, f.handler.deps, importSession(f), AttachmentGCRequest{ChatID: chatID, Key: f.userKeyB64}); err == nil {
		t.Fatal("canceled diagnostic request must report its read failure")
	}
	f.cp.mu.Lock()
	indexed := f.cp.attachmentIndex[id] == chatID
	f.cp.mu.Unlock()
	if !indexed || !f.bk.has(id) {
		t.Fatal("canceled GC discarded storage")
	}
	if bucketDeletes.Load() != 0 {
		t.Fatal("canceled GC attempted a bucket delete")
	}
}

func TestAttachmentGCForwardsDeferredWorkAndCannotBeEnabledByControlplane(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	const chatID = "gc-young-chat"
	seedForkSource(t, f, tok, chatID)
	const retryAfter = 900
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/sync/attachment-index" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(controlplane.AttachmentIndex{
				IDs: []string{}, Deferred: 2, RetryAfter: retryAfter, Disabled: false,
			})
			return
		}
		f.cp.server.Config.Handler.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	f.handler.deps.Controlplane = controlplane.NewClient(proxy.URL, nil)
	resp, body := f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: chatID, Key: f.userKeyB64}, tok)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("GC must remain disabled: %d %s", resp.StatusCode, body)
	}
	var out AttachmentGCResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.OK || !out.Disabled || out.Code != CodeAttachmentGCDisabled || out.Deferred != 2 || out.RetryAfter != retryAfter || out.Remaining != 0 || out.Indexed != 0 || out.Deleted != 0 {
		t.Fatalf("empty listing incorrectly reported completion: %+v", out)
	}
}
