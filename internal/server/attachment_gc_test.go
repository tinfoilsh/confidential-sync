package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
)

// The legacy controlplane stub permits deletes, so this also checks
// that the enclave's safety gate is independent of controlplane rollout.
func TestAttachmentGCReportsCandidatesWithoutDeleting(t *testing.T) {
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
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("gc: %d %s", resp.StatusCode, body)
	}
	var out AttachmentGCResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.OK || !out.Disabled || out.Code != CodeAttachmentGCDisabled || out.Referenced != 1 || out.Indexed != 4 || out.Deleted != 0 || out.Remaining != 3 {
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
		if _, ok := f.cp.attachmentIndex[id]; !ok {
			t.Fatalf("candidate %s lost its index row", id)
		}
		if !f.bk.items.Has(id) {
			t.Fatalf("candidate %s lost its bucket object", id)
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
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("gc: %d %s", resp.StatusCode, body)
	}
	var out AttachmentGCResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.OK || !out.Disabled || out.Code != CodeAttachmentGCDisabled || out.Referenced != 1 || out.Indexed != 1 || out.Deleted != 0 || out.Remaining != 0 {
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
	resp, _ = f.post("/v1/attachment/gc", AttachmentGCRequest{ChatID: "nope", Key: "not-base64!"}, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed key: %d", resp.StatusCode)
	}
}
