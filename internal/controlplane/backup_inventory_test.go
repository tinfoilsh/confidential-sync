package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const backupInventoryTestTimestamp = "2026-08-30T12:00:00Z"

func TestBackupInventoryWireRequestAndTypedResponse(t *testing.T) {
	st := newStub(t)
	st.handle1(http.MethodGet, BackupInventoryPath, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderAuth); got != "Bearer verified-jwt" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get(HeaderClerkUserID); got != "verified-subject" {
			t.Errorf("subject = %q", got)
		}
		if got := r.Header.Get(HeaderServiceSecret); got != "service-secret" {
			t.Errorf("service secret = %q", got)
		}
		if r.ContentLength != 0 {
			t.Errorf("content length = %d", r.ContentLength)
		}
		_, _ = io.WriteString(w, `{
			"captured_at":"2026-08-30T12:00:00Z",
			"total_items":3,
			"user_id":"must-not-pass",
			"items":[
				{"scope":"project_document","id":"doc-1","etag":"3","project_id":"project-1","created_at":"2026-08-30T10:00:00Z","updated_at":"2026-08-30T11:00:00Z","key_id":"must-not-pass","ciphertext":"must-not-pass"},
				{"scope":"project","id":"project-1","etag":"2","created_at":"2026-08-30T09:00:00Z","updated_at":"2026-08-30T10:00:00Z","plaintext":"must-not-pass"},
				{"scope":"chat","id":"chat-1","etag":"1","project_id":null,"created_at":"2026-08-30T08:00:00Z","updated_at":"2026-08-30T09:00:00Z","cek":"must-not-pass","attachment_key":"must-not-pass"}
			]
		}`)
	})

	response, err := NewClient(st.server.URL, nil, WithServiceSecret("service-secret")).BackupInventory(context.Background(), "verified-jwt", "verified-subject")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 3 || response.Items[0].Scope != "chat" || response.Items[1].Scope != "project" || response.Items[2].Scope != "project_document" {
		t.Fatalf("items are not deterministic: %+v", response.Items)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"user_id", "key_id", "plaintext", "ciphertext", "cek", "attachment_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("typed response leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestBackupInventoryValidation(t *testing.T) {
	projectID := "project-1"
	validItem := BackupInventoryItem{
		Scope:     "project_document",
		ID:        "doc-1",
		ETag:      "etag-1",
		ProjectID: &projectID,
		CreatedAt: backupInventoryTestTimestamp,
		UpdatedAt: backupInventoryTestTimestamp,
	}
	tests := []struct {
		name   string
		mutate func(*BackupInventoryResponse)
	}{
		{name: "bad captured timestamp", mutate: func(v *BackupInventoryResponse) { v.CapturedAt = "not-time" }},
		{name: "nil items", mutate: func(v *BackupInventoryResponse) { v.Items = nil; v.TotalItems = 0 }},
		{name: "wrong total", mutate: func(v *BackupInventoryResponse) { v.TotalItems = 2 }},
		{name: "unknown scope", mutate: func(v *BackupInventoryResponse) { v.Items[0].Scope = "profile" }},
		{name: "empty id", mutate: func(v *BackupInventoryResponse) { v.Items[0].ID = "" }},
		{name: "empty etag", mutate: func(v *BackupInventoryResponse) { v.Items[0].ETag = "" }},
		{name: "bad created timestamp", mutate: func(v *BackupInventoryResponse) { v.Items[0].CreatedAt = "not-time" }},
		{name: "updated before created", mutate: func(v *BackupInventoryResponse) { v.Items[0].UpdatedAt = "2026-08-29T12:00:00Z" }},
		{name: "document missing project", mutate: func(v *BackupInventoryResponse) { v.Items[0].ProjectID = nil }},
		{name: "project has project", mutate: func(v *BackupInventoryResponse) { v.Items[0].Scope = "project" }},
		{name: "duplicate", mutate: func(v *BackupInventoryResponse) { v.Items = append(v.Items, v.Items[0]); v.TotalItems = 2 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := BackupInventoryResponse{CapturedAt: backupInventoryTestTimestamp, TotalItems: 1, Items: []BackupInventoryItem{validItem}}
			tc.mutate(&response)
			if err := validateBackupInventory(&response); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
}

func TestBackupInventoryAcceptsMaximumItemCount(t *testing.T) {
	items := make([]BackupInventoryItem, MaxBackupInventoryItems)
	for index := range items {
		items[index] = BackupInventoryItem{
			Scope:     "chat",
			ID:        fmt.Sprintf("chat-%06d", index),
			ETag:      "1",
			CreatedAt: backupInventoryTestTimestamp,
			UpdatedAt: backupInventoryTestTimestamp,
		}
	}
	response := BackupInventoryResponse{CapturedAt: backupInventoryTestTimestamp, TotalItems: len(items), Items: items}
	if err := validateBackupInventory(&response); err != nil {
		t.Fatal(err)
	}
	response.Items = append(response.Items, BackupInventoryItem{Scope: "chat", ID: "over-limit", ETag: "1", CreatedAt: backupInventoryTestTimestamp, UpdatedAt: backupInventoryTestTimestamp})
	response.TotalItems++
	if err := validateBackupInventory(&response); err == nil {
		t.Fatal("expected over-limit inventory to fail")
	}
}

func TestBackupInventoryRejectsOversizedResponseWithoutTruncation(t *testing.T) {
	originalLimit := maxBackupInventoryResponseBytes
	maxBackupInventoryResponseBytes = 64
	t.Cleanup(func() { maxBackupInventoryResponseBytes = originalLimit })

	st := newStub(t)
	st.handle1(http.MethodGet, BackupInventoryPath, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxBackupInventoryResponseBytes+1))
	})
	_, err := NewClient(st.server.URL, nil).BackupInventory(context.Background(), "jwt", "subject")
	if err == nil || err.Error() != "controlplane: backup inventory exceeds 64 bytes" {
		t.Fatalf("error = %v", err)
	}
}

func TestBackupInventorySanitizesUpstreamErrors(t *testing.T) {
	st := newStub(t)
	st.handle1(http.MethodGet, BackupInventoryPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"code":"FORBIDDEN","message":"user-id inventory-id","current_key_id":"key-id","plaintext":"secret"}`)
	})
	_, err := NewClient(st.server.URL, nil).BackupInventory(context.Background(), "jwt", "subject")
	var controlplaneError *Error
	if !errors.As(err, &controlplaneError) {
		t.Fatalf("error type = %T", err)
	}
	if controlplaneError.StatusCode != http.StatusForbidden || controlplaneError.Code != "FORBIDDEN" || controlplaneError.Message != "" || controlplaneError.CurrentKeyID != "" || controlplaneError.Raw != nil {
		t.Fatalf("unsanitized error = %+v", controlplaneError)
	}
}
