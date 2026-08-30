package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-sync-enclave/internal/controlplane"
)

func TestBackupInventoryRequiresAuthenticationAndProtocol(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name       string
		token      string
		protocol   string
		wantStatus int
	}{
		{name: "missing bearer", protocol: "2", wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer", token: "invalid", protocol: "2", wantStatus: http.StatusUnauthorized},
		{name: "missing protocol", token: f.jwt(), wantStatus: http.StatusUpgradeRequired},
		{name: "old protocol", token: f.jwt(), protocol: "1", wantStatus: http.StatusUpgradeRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, _ := postRawBackupInventory(t, f, `{}`, tc.token, tc.protocol)
			if response.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", response.StatusCode, tc.wantStatus)
			}
			if got := response.Header.Get("Cache-Control"); got != BackupInventoryCacheControl {
				t.Fatalf("Cache-Control = %q", got)
			}
		})
	}
}

func TestBackupInventoryAcceptsOnlyEmptyJSONObject(t *testing.T) {
	f := newFixture(t)
	upstreamCalls := 0
	f.cp.captureHeaders = func(r *http.Request) {
		if r.URL.Path == controlplane.BackupInventoryPath {
			upstreamCalls++
		}
	}
	for _, body := range []string{
		``, `null`, `[]`, `"{}"`, `{"unknown":true}`, `{"key":"secret"}`, `{"keys":[]}`,
		`{"plaintext":"secret"}`, `{"ciphertext":"secret"}`, `{"key_id":"secret"}`,
		`{"user_id":"secret"}`, `{"cek":"secret"}`, `{"attachment_key":"secret"}`,
	} {
		response, responseBody := postRawBackupInventory(t, f, body, f.jwt(), "2")
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %q: status=%d response=%s", body, response.StatusCode, responseBody)
		}
		if got := response.Header.Get("Cache-Control"); got != BackupInventoryCacheControl {
			t.Fatalf("body %q: Cache-Control=%q", body, got)
		}
	}
	if upstreamCalls != 0 {
		t.Fatalf("invalid requests reached controlplane %d times", upstreamCalls)
	}
}

func TestBackupInventoryUpstreamErrorsAreNoStoreAndSanitized(t *testing.T) {
	f := newFixture(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"code":"UPSTREAM","message":"inventory-id","user_id":"user-id","plaintext":"secret"}`)
	}))
	t.Cleanup(upstream.Close)
	f.handler.deps.Controlplane = controlplane.NewClient(upstream.URL, nil)

	response, body := postRawBackupInventory(t, f, `{}`, f.jwt(), "2")
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if got := response.Header.Get("Cache-Control"); got != BackupInventoryCacheControl {
		t.Fatalf("Cache-Control=%q", got)
	}
	for _, forbidden := range []string{"inventory-id", "user-id", "secret"} {
		if bytes.Contains(body, []byte(forbidden)) {
			t.Fatalf("error leaked %q: %s", forbidden, body)
		}
	}
}

func TestBackupInventorySecurityBoundaryReturnsKeyFreeNoStoreMetadata(t *testing.T) {
	f := newFixture(t)
	timestamp := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	projectID := "project-1"
	f.cp.mu.Lock()
	f.cp.blobs["project_document/project-1/doc-1"] = &cpBlob{ETag: 3, KeyID: "forbidden-key-id", ProjectID: &projectID, UpdatedAt: timestamp}
	f.cp.blobs["chat/chat-1"] = &cpBlob{ETag: 1, KeyID: "forbidden-key-id", UpdatedAt: timestamp}
	f.cp.blobs["project/project-1"] = &cpBlob{ETag: 2, KeyID: "forbidden-key-id", UpdatedAt: timestamp}
	f.cp.mu.Unlock()

	token := f.jwt()
	var upstreamRequest *http.Request
	f.cp.captureHeaders = func(r *http.Request) {
		if r.URL.Path == controlplane.BackupInventoryPath {
			upstreamRequest = r.Clone(r.Context())
		}
	}
	response, body := postRawBackupInventory(t, f, `{ }`, token, "2")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if got := response.Header.Get("Cache-Control"); got != BackupInventoryCacheControl {
		t.Fatalf("Cache-Control = %q", got)
	}
	if upstreamRequest == nil || upstreamRequest.Method != http.MethodGet || upstreamRequest.Header.Get(controlplane.HeaderAuth) != "Bearer "+token || upstreamRequest.Header.Get(controlplane.HeaderClerkUserID) != f.userSub || upstreamRequest.ContentLength != 0 {
		t.Fatalf("unexpected upstream request: %+v", upstreamRequest)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 3 || raw["captured_at"] == nil || raw["total_items"] == nil || raw["items"] == nil {
		t.Fatalf("response shape = %s", body)
	}
	var inventory BackupInventoryResponse
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.TotalItems != 3 || len(inventory.Items) != 3 || inventory.Items[0].Scope != "chat" || inventory.Items[1].Scope != "project" || inventory.Items[2].Scope != "project_document" {
		t.Fatalf("inventory = %+v", inventory)
	}
	if inventory.Items[0].ID != "chat-1" || inventory.Items[0].ProjectID != nil {
		t.Fatalf("chat item = %+v", inventory.Items[0])
	}
	if inventory.Items[1].ID != "project-1" || inventory.Items[1].ProjectID != nil {
		t.Fatalf("project item = %+v", inventory.Items[1])
	}
	if inventory.Items[2].ID != "doc-1" || inventory.Items[2].ProjectID == nil || *inventory.Items[2].ProjectID != projectID {
		t.Fatalf("project document item = %+v", inventory.Items[2])
	}
	for _, forbidden := range []string{"key_id", "user_id", "plaintext", "ciphertext", "cek", "attachment_key"} {
		if bytes.Contains(body, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("response contains forbidden field %q: %s", forbidden, body)
		}
	}
}

func postRawBackupInventory(t *testing.T, f *fixture, body, token, protocol string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.server.URL+"/v1/sync/backup-inventory", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set(controlplane.HeaderAuth, "Bearer "+token)
	}
	if protocol != "" {
		request.Header.Set(controlplane.HeaderSyncProtocol, protocol)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, responseBody
}
