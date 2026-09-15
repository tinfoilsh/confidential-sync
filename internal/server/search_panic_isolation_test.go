package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

// panickingEmbedder simulates a defect inside the search pipeline. The
// blob write has already committed by the time embedding runs, so the
// caller must observe a normal response with search degraded, never a
// crashed request or import worker.
type panickingEmbedder struct {
	panicOnModel bool
}

func (panickingEmbedder) Configured() bool { return true }
func (e panickingEmbedder) Model() string {
	if e.panicOnModel {
		panic("embedder defect")
	}
	return "panic-embed"
}
func (panickingEmbedder) Embed(context.Context, []string) ([][]float32, error) {
	panic("embedder defect")
}

func TestPushSurvivesSearchIndexPanic(t *testing.T) {
	sf := newSearchFixture(t)
	sf.handler.deps.Embedder = panickingEmbedder{}
	sf.cp.currentKID = sf.userKeyID

	plaintext, _ := json.Marshal(map[string]any{
		"id": "chat-1", "title": "T",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	})
	resp, body := sf.post("/v1/sync/push", PushRequest{
		Scope: "chat", ID: "chat-1", Key: sf.userKeyB64,
		Plaintext: base64.StdEncoding.EncodeToString(plaintext), IdempotencyKey: "idem-1",
	}, sf.jwt())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push status=%d body=%s, want 200 with search degraded", resp.StatusCode, body)
	}
	var out PushResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.SearchIndexed == nil || *out.SearchIndexed {
		t.Fatalf("push=%+v, want ok with searchIndexed=false", out)
	}
	if _, stored := sf.cp.blobs["chat/chat-1"]; !stored {
		t.Fatal("blob was not written")
	}
}

func TestDeleteSurvivesSearchIndexPanic(t *testing.T) {
	sf := newSearchFixture(t)
	sf.cp.currentKID = sf.userKeyID
	tok := sf.jwt()
	pushed := sf.pushChat(t, tok, "chat-1", "T", "hello")

	// The delete-side hook consults the embedder model while checking
	// index publication state; a panic there must not fail the delete.
	sf.handler.deps.Embedder = panickingEmbedder{panicOnModel: true}
	resp, body := sf.post("/v1/sync/delete", DeleteRequest{
		Scope: "chat", ID: "chat-1", Key: sf.userKeyB64, IfMatch: &pushed.ETag, IdempotencyKey: "del-1",
	}, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d body=%s, want 200", resp.StatusCode, body)
	}
	if _, stored := sf.cp.blobs["chat/chat-1"]; stored {
		t.Fatal("blob was not deleted")
	}
}

func TestImportJobSurvivesSearchIndexPanic(t *testing.T) {
	sf := newSearchFixture(t)
	sf.handler.deps.Embedder = panickingEmbedder{}
	sf.cp.currentKID = sf.userKeyID
	notified := captureImportNotifications(t, sf.fixture)

	job := stageArchive(t, sf.fixture, "tinfoil", []byte(retryTestArchive))
	snap := runCoordinatorJob(t, sf.fixture, NewImportCoordinator(), job)

	if snap.Status != ImportJobCompleted || snap.Imported != 1 || snap.Failed != 0 {
		t.Fatalf("status=%s reason=%s imported=%d failed=%d, want completed/1/0", snap.Status, snap.FailureReason, snap.Imported, snap.Failed)
	}
	if len(sf.cp.blobs) != 1 {
		t.Fatalf("expected exactly one chat blob written, got %d", len(sf.cp.blobs))
	}
	for _, blob := range sf.cp.blobs {
		if len(blob.Body) == 0 || blob.KeyID != sf.userKeyID {
			t.Fatalf("imported blob is empty or sealed under the wrong key: len=%d kid=%s", len(blob.Body), blob.KeyID)
		}
	}
	if body := notified.single(t); body["status"] != "completed" {
		t.Fatalf("notification=%v, want completed", body)
	}
}
