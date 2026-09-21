package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/buckets"
	"github.com/tinfoilsh/confidential-sync-enclave/internal/envelope"
)

type forkTestSource struct {
	attachmentID  string
	attachmentKey []byte
	imageBytes    []byte
}

// seedForkSource stores a three-message chat (user with an image, an
// assistant reply, and a trailing user turn) under sourceID, with the
// image blob living in buckets under the source's own attachment id.
func seedForkSource(t *testing.T, f *fixture, tok, sourceID string) forkTestSource {
	t.Helper()
	src := forkTestSource{
		attachmentID:  "0123456789abcdef0123456789abcdef0123",
		attachmentKey: bytes.Repeat([]byte{7}, 32),
		imageBytes:    []byte("png-bytes"),
	}
	tenant, err := buckets.TenantForUser(f.userSub)
	if err != nil {
		t.Fatal(err)
	}
	f.bk.items.Put(src.attachmentID, bucketsItem{
		Tenant:         tenant,
		Value:          src.imageBytes,
		EncryptionKeys: [][]byte{src.attachmentKey},
	})
	f.cp.mu.Lock()
	f.cp.attachmentIndex = map[string]string{src.attachmentID: sourceID}
	f.cp.mu.Unlock()

	chat := map[string]any{
		"id":                       sourceID,
		"title":                    "Trip planning",
		"titleState":               "generated",
		"model":                    "gpt-oss-120b",
		"presetId":                 "preset-1",
		"projectId":                "project-1",
		"webSearchEnabled":         true,
		"createdAt":                "2026-01-01T00:00:00.000Z",
		"updatedAt":                "2026-01-02T00:00:00.000Z",
		"syncVersion":              7,
		"clock":                    3,
		"codeExecutionAccessToken": "secret-token",
		"pendingRecoveries":        []any{map[string]any{"turnId": "t1"}},
		"customField":              "kept",
		"messages": []any{
			map[string]any{
				"role": "user", "content": "Here is a photo", "turnId": "t1",
				"timestamp": "2026-01-01T00:00:00.000Z",
				"attachments": []any{
					map[string]any{
						"id": src.attachmentID, "type": "image", "fileName": "a.png",
						"encryptionKey":    base64.StdEncoding.EncodeToString(src.attachmentKey),
						"storagePayloadId": sourceID + ":" + src.attachmentID,
					},
					map[string]any{
						"id": "doc-1", "type": "document", "fileName": "notes.txt", "textContent": "hello",
					},
				},
			},
			map[string]any{"role": "assistant", "content": "Nice photo", "turnId": "t1", "timestamp": "2026-01-01T00:00:01.000Z"},
			map[string]any{"role": "user", "content": "Second question", "turnId": "t2", "timestamp": "2026-01-01T00:00:02.000Z"},
		},
	}
	plaintext, err := json.Marshal(chat)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := f.post("/v1/sync/push", PushRequest{
		Scope:          "chat",
		ID:             sourceID,
		Key:            f.userKeyB64,
		Plaintext:      base64.StdEncoding.EncodeToString(plaintext),
		IdempotencyKey: "idem-source",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed push: %d %s", resp.StatusCode, body)
	}
	return src
}

func pullChatJSON(t *testing.T, f *fixture, tok, id string) map[string]any {
	t.Helper()
	resp, body := f.post("/v1/sync/pull", PullRequest{
		Scope: "chat",
		IDs:   []string{id},
		Keys:  []PullKey{{Key: f.userKeyB64}},
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull: %d %s", resp.StatusCode, body)
	}
	var pull PullResponse
	if err := json.Unmarshal(body, &pull); err != nil {
		t.Fatal(err)
	}
	if len(pull.Items) != 1 || !pull.Items[0].OK {
		t.Fatalf("pull item: %+v", pull.Items)
	}
	raw, err := base64.StdEncoding.DecodeString(pull.Items[0].Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestForkCopiesPrefixAndReuploadsAttachments(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	src := seedForkSource(t, f, tok, "chat_source")

	resp, body := f.post("/v1/sync/fork", ForkRequest{
		SourceID:       "chat_source",
		TargetID:       "chat_fork",
		Key:            f.userKeyB64,
		MessageCount:   2,
		Title:          "Trip planning (fork)",
		CreatedAt:      "2026-03-04T05:06:07.123Z",
		IdempotencyKey: "idem-fork",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fork: %d %s", resp.StatusCode, body)
	}
	var forkResp ForkResponse
	if err := json.Unmarshal(body, &forkResp); err != nil {
		t.Fatal(err)
	}
	if !forkResp.OK || forkResp.ID != "chat_fork" || forkResp.ETag == "" || forkResp.KeyID != f.userKeyID {
		t.Fatalf("fork resp: %+v", forkResp)
	}

	fork := pullChatJSON(t, f, tok, "chat_fork")
	if fork["id"] != "chat_fork" || fork["title"] != "Trip planning (fork)" || fork["titleState"] != "manual" {
		t.Fatalf("fork identity: id=%v title=%v titleState=%v", fork["id"], fork["title"], fork["titleState"])
	}
	for _, field := range []string{"model", "presetId", "projectId", "webSearchEnabled", "customField"} {
		if fork[field] == nil {
			t.Fatalf("fork dropped %s", field)
		}
	}
	for _, field := range forkStrippedFields {
		if _, present := fork[field]; present {
			t.Fatalf("fork kept bookkeeping field %s", field)
		}
	}
	if fork["createdAt"] != "2026-03-04T05:06:07.123Z" || fork["updatedAt"] != "2026-03-04T05:06:07.123Z" {
		t.Fatalf("fork timestamps: createdAt=%v updatedAt=%v", fork["createdAt"], fork["updatedAt"])
	}
	if fork["isLocalOnly"] != false {
		t.Fatalf("fork isLocalOnly = %v", fork["isLocalOnly"])
	}

	messages, _ := fork["messages"].([]any)
	if len(messages) != 2 {
		t.Fatalf("fork message count = %d, want 2", len(messages))
	}
	first := messages[0].(map[string]any)
	if first["turnId"] != "t1" {
		t.Fatalf("message fields not carried through: %+v", first)
	}
	attachments, _ := first["attachments"].([]any)
	if len(attachments) != 2 {
		t.Fatalf("attachment count = %d, want 2", len(attachments))
	}
	image := attachments[0].(map[string]any)
	newID, _ := image["id"].(string)
	newKeyB64, _ := image["encryptionKey"].(string)
	if newID == "" || newID == src.attachmentID {
		t.Fatalf("image id not rewritten: %v", newID)
	}
	newKey, err := base64.StdEncoding.DecodeString(newKeyB64)
	if err != nil || bytes.Equal(newKey, src.attachmentKey) {
		t.Fatalf("image key not rewritten: %v %v", newKeyB64, err)
	}
	if image["fileName"] != "a.png" || image["storagePayloadId"] == nil {
		t.Fatalf("image metadata not carried through: %+v", image)
	}
	document := attachments[1].(map[string]any)
	if document["id"] != "doc-1" || document["textContent"] != "hello" {
		t.Fatalf("document attachment changed: %+v", document)
	}

	item, ok := f.bk.item(newID)
	if !ok {
		t.Fatalf("fork blob %s missing from buckets", newID)
	}
	if !bytes.Equal(item.Value, src.imageBytes) {
		t.Fatalf("fork blob bytes = %q, want %q", item.Value, src.imageBytes)
	}
	if len(item.EncryptionKeys) != 1 || !bytes.Equal(item.EncryptionKeys[0], newKey) {
		t.Fatalf("fork blob sealed under wrong key")
	}
	if !f.bk.has(src.attachmentID) {
		t.Fatalf("source blob must remain untouched")
	}
	f.cp.mu.Lock()
	indexedChat := f.cp.attachmentIndex[newID]
	sourceIndexedChat := f.cp.attachmentIndex[src.attachmentID]
	f.cp.mu.Unlock()
	if indexedChat != "chat_fork" {
		t.Fatalf("fork blob indexed under %q, want chat_fork", indexedChat)
	}
	if sourceIndexedChat != "chat_source" {
		t.Fatalf("source blob index changed to %q", sourceIndexedChat)
	}

	source := pullChatJSON(t, f, tok, "chat_source")
	if sourceMessages, _ := source["messages"].([]any); len(sourceMessages) != 3 {
		t.Fatalf("source message count changed to %d", len(sourceMessages))
	}
}

func TestForkSurvivesSourceDeletion(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	src := seedForkSource(t, f, tok, "chat_source")

	resp, body := f.post("/v1/sync/fork", ForkRequest{
		SourceID: "chat_source", TargetID: "chat_fork", Key: f.userKeyB64,
		MessageCount: 1, Title: "fork", CreatedAt: "2026-03-04T05:06:07Z", IdempotencyKey: "idem-fork",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fork: %d %s", resp.StatusCode, body)
	}
	fork := pullChatJSON(t, f, tok, "chat_fork")
	forkAttachment := fork["messages"].([]any)[0].(map[string]any)["attachments"].([]any)[0].(map[string]any)
	forkAttachmentID := forkAttachment["id"].(string)

	f.cp.mu.Lock()
	sourceETag := formatETag(f.cp.blobs["chat/chat_source"].ETag)
	f.cp.mu.Unlock()
	resp, body = f.post("/v1/sync/delete", DeleteRequest{
		Scope: "chat", ID: "chat_source", IfMatch: &sourceETag, IdempotencyKey: "idem-delete", Key: f.userKeyB64,
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete source: %d %s", resp.StatusCode, body)
	}
	if f.bk.has(src.attachmentID) {
		t.Fatalf("source blob should cascade on delete")
	}
	if !f.bk.has(forkAttachmentID) {
		t.Fatalf("fork blob must survive source deletion")
	}
}

func TestForkRejectsInvalidRequests(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	seedForkSource(t, f, tok, "chat_source")

	valid := ForkRequest{
		SourceID: "chat_source", TargetID: "chat_fork", Key: f.userKeyB64,
		MessageCount: 1, Title: "fork", CreatedAt: "2026-03-04T05:06:07Z", IdempotencyKey: "idem-fork",
	}
	cases := []struct {
		name   string
		mutate func(*ForkRequest)
		status int
	}{
		{"zero messages", func(r *ForkRequest) { r.MessageCount = 0 }, http.StatusBadRequest},
		{"too many messages", func(r *ForkRequest) { r.MessageCount = 4 }, http.StatusBadRequest},
		{"same id", func(r *ForkRequest) { r.TargetID = r.SourceID }, http.StatusBadRequest},
		{"missing idempotency key", func(r *ForkRequest) { r.IdempotencyKey = "" }, http.StatusBadRequest},
		{"invalid created_at", func(r *ForkRequest) { r.CreatedAt = "yesterday" }, http.StatusBadRequest},
		{"unknown source", func(r *ForkRequest) { r.SourceID = "chat_missing" }, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.mutate(&req)
			resp, body := f.post("/v1/sync/fork", req, tok)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, tc.status, body)
			}
			f.cp.mu.Lock()
			_, created := f.cp.blobs["chat/chat_fork"]
			f.cp.mu.Unlock()
			if created {
				t.Fatalf("rejected fork must not create the target row")
			}
		})
	}
}

func TestForkIsCreateOnly(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	seedForkSource(t, f, tok, "chat_source")
	req := ForkRequest{
		SourceID: "chat_source", TargetID: "chat_fork", Key: f.userKeyB64,
		MessageCount: 1, Title: "fork", CreatedAt: "2026-03-04T05:06:07Z", IdempotencyKey: "idem-fork",
	}
	if resp, body := f.post("/v1/sync/fork", req, tok); resp.StatusCode != http.StatusOK {
		t.Fatalf("first fork: %d %s", resp.StatusCode, body)
	}
	req.IdempotencyKey = "idem-fork-2"
	resp, body := f.post("/v1/sync/fork", req, tok)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second fork onto same target: %d %s", resp.StatusCode, body)
	}
	var appErr AppError
	if err := json.Unmarshal(body, &appErr); err != nil || appErr.Code != CodeSyncConflict {
		t.Fatalf("conflict code = %q (%v)", appErr.Code, err)
	}
}

// TestForkPayloadIsDeterministicForRetries proves that a retried fork
// (same request, same idempotency key) seals byte-identical plaintext
// and re-derives the same attachment ids. The controlplane's
// operation-hash check would otherwise reject the replay, and a fresh
// blob id on every attempt would orphan the earlier copy.
func TestForkPayloadIsDeterministicForRetries(t *testing.T) {
	f := newFixture(t)
	f.cp.currentKID = f.userKeyID
	tok := f.jwt()
	seedForkSource(t, f, tok, "chat_source")

	sess := Session{RawJWT: tok}
	sess.Claims.Subject = f.userSub
	req := ForkRequest{
		SourceID: "chat_source", TargetID: "chat_fork", Key: f.userKeyB64,
		MessageCount: 1, Title: "fork", CreatedAt: "2026-03-04T05:06:07Z", IdempotencyKey: "idem-fork",
	}
	createdAt, _ := time.Parse(time.RFC3339Nano, req.CreatedAt)
	key := envelope.Key{Bytes: f.userKey, KeyIDHex: f.userKeyID}

	build := func() ([]byte, []string) {
		source, err := readForkSource(context.Background(), f.handler.deps, sess, req.SourceID, key)
		if err != nil {
			t.Fatal(err)
		}
		var chat nativeChatPayload
		if err := json.Unmarshal(source, &chat); err != nil {
			t.Fatal(err)
		}
		payload, ids, err := buildForkPayload(context.Background(), f.handler.deps, sess, req, chat, createdAt)
		if err != nil {
			t.Fatal(err)
		}
		return payload, ids
	}
	first, firstIDs := build()
	second, secondIDs := build()
	if !bytes.Equal(first, second) {
		t.Fatalf("retried fork produced different plaintext:\n%s\n%s", first, second)
	}
	if len(firstIDs) != 1 || len(secondIDs) != 1 || firstIDs[0] != secondIDs[0] {
		t.Fatalf("retried fork derived different attachment ids: %v vs %v", firstIDs, secondIDs)
	}
}
