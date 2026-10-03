package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
)

// TestAttachmentGCRemovesOnlyUnreferencedBlobs seeds a chat whose
// stored content references one image, then registers three further
// index rows under the same chat (the shape a client re-uploading the
// same bytes on every failed sync cycle leaves behind), one row under
// a different chat, and runs a GC pass.
func TestAttachmentGCRemovesOnlyUnreferencedBlobs(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	const chatID = "chat-gc"
	src := seedForkSource(t, f, tok, chatID)

	tenant, err := buckets.TenantForUser(f.userSub)
	if err != nil {
		t.Fatal(err)
	}
	orphans := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"cccccccccccccccccccccccccccccccccccc",
	}
	const otherChatAttachment = "dddddddddddddddddddddddddddddddddddd"
	f.cp.mu.Lock()
	for _, id := range orphans {
		f.cp.attachmentIndex[id] = chatID
		f.bk.items.Put(id, bucketsItem{Tenant: tenant, Value: []byte("stale"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{1}, 32)}})
	}
	f.cp.attachmentIndex[otherChatAttachment] = "chat-other"
	f.bk.items.Put(otherChatAttachment, bucketsItem{Tenant: tenant, Value: []byte("other"), EncryptionKeys: [][]byte{bytes.Repeat([]byte{2}, 32)}})
	f.cp.mu.Unlock()

	resp, body := f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: chatID, Key: f.userKeyB64}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gc: %d %s", resp.StatusCode, body)
	}
	var out AttachmentGCResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Referenced != 1 || out.Indexed != 4 || out.Deleted != 3 || out.Remaining != 0 {
		t.Fatalf("unexpected gc summary: %+v", out)
	}

	f.cp.mu.Lock()
	defer f.cp.mu.Unlock()
	if _, ok := f.cp.attachmentIndex[src.attachmentID]; !ok {
		t.Fatalf("referenced attachment index row was removed")
	}
	if !f.bk.items.Has(src.attachmentID) {
		t.Fatalf("referenced attachment blob was removed")
	}
	for _, id := range orphans {
		if _, ok := f.cp.attachmentIndex[id]; ok {
			t.Fatalf("orphan %s still indexed", id)
		}
		if f.bk.items.Has(id) {
			t.Fatalf("orphan %s still in buckets", id)
		}
	}
	if _, ok := f.cp.attachmentIndex[otherChatAttachment]; !ok {
		t.Fatalf("attachment under another chat was removed")
	}
	if !f.bk.items.Has(otherChatAttachment) {
		t.Fatalf("blob under another chat was removed")
	}
}

func TestAttachmentGCIsNoOpWhenIndexMatchesChat(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	const chatID = "chat-gc-clean"
	seedForkSource(t, f, tok, chatID)

	resp, body := f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: chatID, Key: f.userKeyB64}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gc: %d %s", resp.StatusCode, body)
	}
	var out AttachmentGCResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Referenced != 1 || out.Indexed != 1 || out.Deleted != 0 || out.Remaining != 0 {
		t.Fatalf("unexpected gc summary: %+v", out)
	}
}

func TestAttachmentGCRejectsMissingChatAndBadKey(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()

	resp, _ := f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: "", Key: f.userKeyB64}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing chat_id: %d", resp.StatusCode)
	}
	resp, _ = f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: "nope", Key: f.userKeyB64}, tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown chat: %d", resp.StatusCode)
	}
}
