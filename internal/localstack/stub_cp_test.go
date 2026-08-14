package localstack

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

func TestListStatusIncludesChatProjectID(t *testing.T) {
	stub := NewStubCP()
	projectID := "project-1"
	putStubBlob(t, stub, "chat", "chat-1", map[string]string{
		controlplane.HeaderProjectIDSet: "1",
		controlplane.HeaderProjectID:    projectID,
	})

	recorder := requestStub(t, stub, http.MethodGet, "/api/sync/list-status?scope=chat", "", nil)
	var response controlplane.ListStatusResponse
	decodeStubResponse(t, recorder, &response)
	if len(response.Updates) != 1 || response.Updates[0].ProjectID == nil || *response.Updates[0].ProjectID != projectID {
		t.Fatalf("updates = %+v", response.Updates)
	}
}

func TestStartFreshWipeRequiresSnapshotBeforeResetFloor(t *testing.T) {
	stub := NewStubCP()
	putStubBlob(t, stub, "chat", "chat-1", nil)
	putStubBlob(t, stub, "project", "project-1", nil)

	body := `{"key_id":"new-key","created_via":"start_fresh"}`
	recorder := requestStub(t, stub, http.MethodPost, "/api/sync/keys", body, map[string]string{
		controlplane.HeaderIfMatch: controlplane.IfMatchAnyKey,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("register status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = requestStub(t, stub, http.MethodGet, controlplane.RevisionSummaryPath, "", nil)
	var summary controlplane.RevisionSummaryResponse
	decodeStubResponse(t, recorder, &summary)
	if summary.CurrentRevision != "2" || summary.OldestReplayableRevision != "2" {
		t.Fatalf("summary = %+v", summary)
	}

	recorder = requestStub(t, stub, http.MethodGet, controlplane.RevisionEventsPath+"?after_revision=1&through_revision=2", "", nil)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("events status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var snapshotRequired map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshotRequired); err != nil {
		t.Fatalf("decode snapshot-required response: %v", err)
	}
	if snapshotRequired["code"] != controlplane.StatusSyncSnapshotRequired || snapshotRequired["current_revision"] != "2" || snapshotRequired["oldest_replayable_revision"] != "2" {
		t.Fatalf("snapshot-required response = %+v", snapshotRequired)
	}

	recorder = requestStub(t, stub, http.MethodGet, controlplane.RevisionEventsPath+"?after_revision=2&through_revision=2", "", nil)
	var events controlplane.RevisionEventsResponse
	decodeStubResponse(t, recorder, &events)
	if len(events.Events) != 0 {
		t.Fatalf("events after reset floor = %+v", events.Events)
	}

	recorder = requestStub(t, stub, http.MethodPut, "/api/sync/blob/chat/chat-2", "ciphertext", map[string]string{
		controlplane.HeaderKeyID:   "new-key",
		controlplane.HeaderIfMatch: controlplane.IfMatchCreateOnly,
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("post-reset put status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	recorder = requestStub(t, stub, http.MethodGet, controlplane.RevisionEventsPath+"?after_revision=2&through_revision=3", "", nil)
	decodeStubResponse(t, recorder, &events)
	if len(events.Events) != 1 || events.Events[0].Revision != "3" || events.Events[0].Kind != "upsert" || events.Events[0].ID != "chat-2" {
		t.Fatalf("post-reset events = %+v", events.Events)
	}

	recorder = requestStub(t, stub, http.MethodGet, "/api/sync/list-status?scope=project", "", nil)
	var status controlplane.ListStatusResponse
	decodeStubResponse(t, recorder, &status)
	if len(status.Deletes) != 1 || status.Deletes[0].ID != "project-1" {
		t.Fatalf("deletes = %+v", status.Deletes)
	}
}

func TestRevisionSnapshotPinsRevisionAndPagesByID(t *testing.T) {
	stub := NewStubCP()
	for _, id := range []string{"chat-a", "chat-b", "chat-c"} {
		putStubBlob(t, stub, "chat", id, nil)
	}

	recorder := requestStub(t, stub, http.MethodGet, controlplane.RevisionSnapshotPath+"?limit=2", "", nil)
	var first controlplane.RevisionSnapshotResponse
	decodeStubResponse(t, recorder, &first)
	if first.SnapshotRevision != "3" || len(first.Items) != 2 || first.Items[0].ID != "chat-a" || first.Items[1].ID != "chat-b" || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	putStubBlob(t, stub, "chat", "chat-aa", nil)
	recorder = requestStub(t, stub, http.MethodGet, controlplane.RevisionSnapshotPath+"?limit=2&cursor="+url.QueryEscape(first.NextCursor), "", nil)
	var second controlplane.RevisionSnapshotResponse
	decodeStubResponse(t, recorder, &second)
	if second.SnapshotRevision != first.SnapshotRevision || len(second.Items) != 1 || second.Items[0].ID != "chat-c" {
		t.Fatalf("second page = %+v", second)
	}
}

// seedStubBlob writes a blob directly with a controlled UpdatedAt so
// pagination tests get a deterministic timeline.
func seedStubBlob(stub *StubCP, scope, id string, projectID *string, updatedAt time.Time) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.blobs[blobKey(scope, id)] = &StubBlob{
		ETag:         1,
		KeyID:        "key-1",
		Body:         []byte("ciphertext"),
		ProjectIDSet: projectID != nil,
		ProjectID:    projectID,
		UpdatedAt:    updatedAt,
	}
}

func seedStubDelete(stub *StubCP, scope, id string, projectID *string, deletedAt time.Time) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.deletes[blobKey(scope, id)] = stubDelete{deletedAt: deletedAt, projectID: projectID}
}

func listStatusPage(t *testing.T, stub *StubCP, rawQuery string) controlplane.ListStatusResponse {
	t.Helper()
	recorder := requestStub(t, stub, http.MethodGet, "/api/sync/list-status?"+rawQuery, "", nil)
	var response controlplane.ListStatusResponse
	decodeStubResponse(t, recorder, &response)
	return response
}

func TestListStatusPaginatesOldestFirstWithCursor(t *testing.T) {
	stub := NewStubCP()
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	seedStubBlob(stub, "chat", "chat-b", nil, base.Add(2*time.Minute))
	seedStubBlob(stub, "chat", "chat-a", nil, base.Add(1*time.Minute))
	seedStubBlob(stub, "chat", "chat-c", nil, base.Add(3*time.Minute))

	first := listStatusPage(t, stub, "scope=chat&limit=2")
	if len(first.Updates) != 2 || first.Updates[0].ID != "chat-a" || first.Updates[1].ID != "chat-b" || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	second := listStatusPage(t, stub, "scope=chat&limit=2&cursor="+url.QueryEscape(first.NextCursor))
	if len(second.Updates) != 1 || second.Updates[0].ID != "chat-c" || second.NextCursor != "" {
		t.Fatalf("second page = %+v", second)
	}
}

func TestListStatusDescendingWalksNewestFirst(t *testing.T) {
	stub := NewStubCP()
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	seedStubBlob(stub, "chat", "chat-a", nil, base.Add(1*time.Minute))
	seedStubBlob(stub, "chat", "chat-b", nil, base.Add(2*time.Minute))
	seedStubBlob(stub, "chat", "chat-c", nil, base.Add(3*time.Minute))

	first := listStatusPage(t, stub, "scope=chat&limit=2&direction=desc")
	if len(first.Updates) != 2 || first.Updates[0].ID != "chat-c" || first.Updates[1].ID != "chat-b" || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	second := listStatusPage(t, stub, "scope=chat&limit=2&direction=desc&cursor="+url.QueryEscape(first.NextCursor))
	if len(second.Updates) != 1 || second.Updates[0].ID != "chat-a" || second.NextCursor != "" {
		t.Fatalf("second page = %+v", second)
	}
}

func TestListStatusFiltersByProjectID(t *testing.T) {
	stub := NewStubCP()
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	projectID := "project-1"
	otherProject := "project-2"
	seedStubBlob(stub, "chat", "chat-in", &projectID, base.Add(1*time.Minute))
	seedStubBlob(stub, "chat", "chat-other", &otherProject, base.Add(2*time.Minute))
	seedStubBlob(stub, "chat", "chat-none", nil, base.Add(3*time.Minute))
	seedStubDelete(stub, "chat", "chat-deleted-in", &projectID, base.Add(4*time.Minute))
	seedStubDelete(stub, "chat", "chat-deleted-other", &otherProject, base.Add(5*time.Minute))
	seedStubDelete(stub, "chat", "chat-deleted-none", nil, base.Add(6*time.Minute))

	response := listStatusPage(t, stub, "scope=chat&project_id="+projectID)
	if len(response.Updates) != 1 || response.Updates[0].ID != "chat-in" {
		t.Fatalf("updates = %+v", response.Updates)
	}
	if len(response.Deletes) != 1 || response.Deletes[0].ID != "chat-deleted-in" {
		t.Fatalf("deletes = %+v", response.Deletes)
	}
}

// TestListStatusProjectDeleteTombstoneFromLiveDelete drives a real
// DELETE through the stub (not a seeded tombstone) and asserts the
// deleted chat's project_id survives onto the tombstone, mirroring
// production's tombstone-on-delete trigger.
func TestListStatusProjectDeleteTombstoneFromLiveDelete(t *testing.T) {
	stub := NewStubCP()
	projectID := "project-1"
	putStubBlob(t, stub, "chat", "chat-1", map[string]string{
		controlplane.HeaderProjectIDSet: "1",
		controlplane.HeaderProjectID:    projectID,
	})

	recorder := requestStub(t, stub, http.MethodDelete, "/api/sync/blob/chat/chat-1", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	response := listStatusPage(t, stub, "scope=chat&project_id="+projectID)
	if len(response.Deletes) != 1 || response.Deletes[0].ID != "chat-1" || len(response.Updates) != 0 {
		t.Fatalf("response = %+v", response)
	}
}

func TestListStatusInterleavesDeletesInTimeline(t *testing.T) {
	stub := NewStubCP()
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	seedStubBlob(stub, "chat", "chat-a", nil, base.Add(1*time.Minute))
	seedStubDelete(stub, "chat", "chat-gone", nil, base.Add(2*time.Minute))
	seedStubBlob(stub, "chat", "chat-b", nil, base.Add(3*time.Minute))

	first := listStatusPage(t, stub, "scope=chat&limit=2")
	if len(first.Updates) != 1 || first.Updates[0].ID != "chat-a" || len(first.Deletes) != 1 || first.Deletes[0].ID != "chat-gone" || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}

	second := listStatusPage(t, stub, "scope=chat&limit=2&cursor="+url.QueryEscape(first.NextCursor))
	if len(second.Updates) != 1 || second.Updates[0].ID != "chat-b" || len(second.Deletes) != 0 || second.NextCursor != "" {
		t.Fatalf("second page = %+v", second)
	}
}

func TestRevisionEventsRejectsOversizedLimit(t *testing.T) {
	stub := NewStubCP()
	putStubBlob(t, stub, "chat", "chat-a", nil)

	oversized := strconv.Itoa(maxRevisionPageLimit + 1)
	recorder := requestStub(t, stub, http.MethodGet, controlplane.RevisionEventsPath+"?after_revision=0&through_revision=1&limit="+oversized, "", nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("events status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	recorder = requestStub(t, stub, http.MethodGet, controlplane.RevisionSnapshotPath+"?limit="+oversized, "", nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("snapshot status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestRevisionEventsCursorPastEndDoesNotPanic(t *testing.T) {
	stub := NewStubCP()
	putStubBlob(t, stub, "chat", "chat-a", nil)

	target := controlplane.RevisionEventsPath + "?after_revision=0&through_revision=1&limit=" + strconv.Itoa(maxRevisionPageLimit) + "&cursor=" + strconv.Itoa(math.MaxInt-1)
	recorder := requestStub(t, stub, http.MethodGet, target, "", nil)
	var events controlplane.RevisionEventsResponse
	decodeStubResponse(t, recorder, &events)
	if len(events.Events) != 0 || events.NextCursor != "" {
		t.Fatalf("events = %+v", events)
	}
}

func TestListStatusRejectsInvalidPagination(t *testing.T) {
	stub := NewStubCP()
	for name, rawQuery := range map[string]string{
		"direction": "scope=chat&direction=sideways",
		"limit":     "scope=chat&limit=0",
		"cursor":    "scope=chat&cursor=not-base64!",
	} {
		recorder := requestStub(t, stub, http.MethodGet, "/api/sync/list-status?"+rawQuery, "", nil)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, body = %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func putStubBlob(t *testing.T, stub *StubCP, scope, id string, headers map[string]string) {
	t.Helper()
	if headers == nil {
		headers = map[string]string{}
	}
	headers[controlplane.HeaderKeyID] = "key-1"
	headers[controlplane.HeaderIfMatch] = controlplane.IfMatchCreateOnly
	recorder := requestStub(t, stub, http.MethodPut, "/api/sync/blob/"+scope+"/"+id, "ciphertext", headers)
	if recorder.Code != http.StatusOK {
		t.Fatalf("put %s/%s status = %d, body = %s", scope, id, recorder.Code, recorder.Body.String())
	}
}

func requestStub(t *testing.T, stub *StubCP, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set(controlplane.HeaderServiceSecret, LocalStackSyncEnclaveSecret)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	stub.ServeHTTP(recorder, request)
	return recorder
}

func decodeStubResponse(t *testing.T, recorder *httptest.ResponseRecorder, out any) {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
